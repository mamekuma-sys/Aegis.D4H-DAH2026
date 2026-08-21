"""Bounded HTTP request semantics for high-confidence packet policy.

Only a complete request header already present in the packet payload is parsed. Any
truncation, malformed encoding, oversized value, or unsupported shape returns ``None``
so the caller preserves the defender's fail-open contract.
"""

from __future__ import annotations

import base64
import binascii
import json
import re
import urllib.parse
from dataclasses import dataclass


MAX_REQUEST_LINE = 1536
MAX_HEADER_LINES = 64
MAX_COOKIE_VALUE = 512
MAX_JSON_KEYS = 16
MAX_JSON_TEXT = 512
MAX_PERCENT_DECODE_ROUNDS = 3
MAX_NESTED_URL_DEPTH = 3
_METHODS = frozenset({"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"})
_BASE64_BYTES = frozenset(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/_-=")
_OBSERVED_BASE64_NOISE = frozenset(b" \t.*~")


def _normalize_scalar(value: object) -> str | None:
    if isinstance(value, bool):
        return "true" if value else "false"
    if value is None:
        return "null"
    if isinstance(value, (str, int, float)):
        text = str(value).strip().lower()
        return text if len(text) <= 64 else None
    return None


def _decode_target(raw: bytes) -> str | None:
    target = raw
    for _ in range(MAX_PERCENT_DECODE_ROUNDS):
        try:
            decoded = urllib.parse.unquote_to_bytes(target)
        except Exception:  # malformed target -> no semantic match
            return None
        if decoded == target:
            break
        target = decoded
    if len(target) > MAX_REQUEST_LINE or b"\x00" in target:
        return None
    # Raw CR/LF cannot occur inside the already-bounded request line, but percent-
    # encoded SQL whitespace decodes to these bytes.  Treat decoded controls as
    # semantic whitespace instead of turning a valid application request invisible.
    target = target.replace(b"\r", b" ").replace(b"\n", b" ")
    try:
        text = target.decode("latin-1")
    except UnicodeDecodeError:
        return None
    if text.startswith(("http://", "https://")):
        try:
            parsed = urllib.parse.urlsplit(text)
        except ValueError:
            return None
        text = parsed.path or "/"
        if parsed.query:
            text += "?" + parsed.query
    return text


def _decode_query_component(raw: str) -> str | None:
    value = raw.encode("latin-1", "replace")
    for _ in range(MAX_PERCENT_DECODE_ROUNDS):
        value = value.replace(b"+", b" ")
        try:
            decoded = urllib.parse.unquote_to_bytes(value)
        except Exception:
            return None
        if decoded == value:
            break
        value = decoded
    if len(value) > MAX_REQUEST_LINE or b"\x00" in value:
        return None
    value = value.replace(b"\r", b" ").replace(b"\n", b" ")
    return value.decode("latin-1", "replace")


def _query_pairs(query: str) -> tuple[tuple[str, str], ...]:
    pairs = []
    for item in query.split("&"):
        if not item:
            continue
        raw_name, separator, raw_value = item.partition("=")
        name = _decode_query_component(raw_name)
        value = _decode_query_component(raw_value if separator else "")
        if name is None or value is None or not name:
            continue
        pairs.append((name.strip().lower(), value))
        if len(pairs) >= 32:
            break
    return tuple(pairs)


def _canonical_url_path(path: str) -> str:
    decoded = _decode_query_component(path) or path
    normalized = re.sub(r"/+", "/", decoded or "/")
    return normalized if normalized.startswith("/") else "/" + normalized


def _iter_url_targets(value: str, depth: int = 0):
    if depth >= MAX_NESTED_URL_DEPTH:
        return
    decoded = _decode_query_component(value)
    if decoded is None or not decoded.lower().startswith(("http://", "https://")):
        return
    try:
        parsed = urllib.parse.urlsplit(decoded)
        host = (parsed.hostname or "").rstrip(".").lower()
        port = parsed.port
    except ValueError:
        return
    if not host:
        return
    if port is None:
        port = 443 if parsed.scheme.lower() == "https" else 80
    yield host, int(port), _canonical_url_path(parsed.path or "/")
    for _, nested_value in _query_pairs(parsed.query):
        yield from _iter_url_targets(nested_value, depth + 1)


def _decode_json_cookie(value: bytes) -> tuple[tuple[str, str], ...] | None:
    value = value.strip().strip(b'"')
    if not value or len(value) > MAX_COOKIE_VALUE:
        return None
    try:
        value = urllib.parse.unquote_to_bytes(value)
        # Finals P3 captures show the protected application using a lenient Base64
        # decoder: redundant padding and a small observed set of ignored characters
        # (space, dot, asterisk, tilde) still produced an admin JSON document. Mirror
        # only that bounded alphabet before strict decoding; other bytes still fail.
        if any(
            byte not in _BASE64_BYTES and byte not in _OBSERVED_BASE64_NOISE
            for byte in value
        ):
            return None
        value = bytes(byte for byte in value if byte not in _OBSERVED_BASE64_NOISE)
        unpadded = value.rstrip(b"=")
        padded = unpadded + b"=" * ((4 - len(unpadded) % 4) % 4)
        decoded = base64.b64decode(padded, altchars=b"-_", validate=True)
    except (ValueError, binascii.Error):
        return None
    if not decoded or len(decoded) > MAX_JSON_TEXT:
        return None
    try:
        document = json.loads(decoded.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None
    if not isinstance(document, dict) or len(document) > MAX_JSON_KEYS:
        return None
    claims = []
    for key, value in document.items():
        if not isinstance(key, str) or not key or len(key) > 64:
            return None
        normalized = _normalize_scalar(value)
        if normalized is None:
            continue
        claims.append((key.strip().lower(), normalized))
    return tuple(claims)


def _looks_like_traversal_or_abs(text: str) -> bool:
    """상대 파일명만 있는 정상 조회와 LFI 시도를 구분한다."""
    stripped = text.lstrip()
    if stripped.startswith(("/", "\\")):
        return True
    low = stripped.lower().replace("\\", "/")
    if ".." in low or "%2e%2e" in low or "%c0%af" in low or "%e0%80%af" in low:
        return True
    if "....;" in stripped or "..;" in stripped or "...." in stripped:
        return True
    return False


def _collapse_local_path(raw: str) -> str | None:
    """퍼센트 재귀 디코드 후 로컬 경로를 한 형태로 접는다.

    `../`, `....//`, `..;/`, 백슬래시, 오버롱 UTF-8 슬래시(`%c0%af`) 변종을
    같은 canonical path로 모아, 바이트 나열 시그니처 없이도 LFI를 잡는다.
    """
    decoded = _decode_query_component(raw)
    if decoded is None:
        return None
    text = decoded
    for overlong, slash in (
        ("\xc0\xaf", "/"),
        ("\xc0\x2f", "/"),
        ("\xe0\x80\xaf", "/"),
    ):
        text = text.replace(overlong, slash)
    text = text.replace("\\", "/")
    # Tomcat-style path parameters: "..;/" → "../"
    text = re.sub(r";[^/]*", "", text)
    parts: list[str] = []
    for segment in text.split("/"):
        if segment in ("", "."):
            continue
        # "...." / "..." 등 점만으로 된 세그먼트는 parent 로 취급한다.
        if segment == ".." or (len(segment) >= 2 and set(segment) == {"."}):
            if parts:
                parts.pop()
            continue
        if len(segment) > 256:
            return None
        parts.append(segment)
    return "/" + "/".join(parts) if parts else "/"


@dataclass(frozen=True, slots=True)
class HttpRequestView:
    method: str
    target: str
    path: str
    query_pairs: tuple[tuple[str, str], ...]
    json_cookies: tuple[tuple[str, tuple[tuple[str, str], ...]], ...]

    def cookie_claim_matches(
        self, cookie_name: str, claim_key: str, claim_values: tuple[str, ...]
    ) -> bool:
        expected_cookie = cookie_name.lower()
        expected_key = claim_key.lower()
        for name, claims in self.json_cookies:
            if name != expected_cookie:
                continue
            for key, value in claims:
                if key == expected_key and value in claim_values:
                    return True
        return False

    def ssrf_target_matches(
        self,
        query_names: tuple[str, ...],
        target_hosts: tuple[str, ...],
        target_ports: tuple[int, ...],
        target_path: str,
    ) -> bool:
        expected_names = frozenset(name.lower() for name in query_names)
        expected_hosts = frozenset(host.rstrip(".").lower() for host in target_hosts)
        expected_ports = frozenset(int(port) for port in target_ports)
        expected_path = _canonical_url_path(target_path)
        for name, value in self.query_pairs:
            if expected_names and name not in expected_names:
                continue
            for host, port, path in _iter_url_targets(value):
                if host in expected_hosts and port in expected_ports and path == expected_path:
                    return True
        return False

    def sql_source_matches(self, query_names: tuple[str, ...], source: str) -> bool:
        expected_names = frozenset(name.lower() for name in query_names)
        expected_source = source.strip().lower()
        for name, value in self.query_pairs:
            if expected_names and name not in expected_names:
                continue
            canonical = re.sub(r"/\*.*?\*/", " ", value, flags=re.DOTALL)
            canonical = re.sub(r"\[([A-Za-z_][A-Za-z0-9_]*)\]", r"\1", canonical)
            tokens = re.findall(r"[a-z_][a-z0-9_]*", canonical.lower())
            try:
                union_at = tokens.index("union")
                select_at = tokens.index("select", union_at + 1)
                from_at = tokens.index("from", select_at + 1)
                source_at = tokens.index(expected_source, from_at + 1)
            except ValueError:
                continue
            if union_at < select_at < from_at < source_at:
                return True
        return False

    def path_traversal_target_matches(
        self,
        query_names: tuple[str, ...],
        path_basenames: tuple[str, ...],
    ) -> bool:
        expected_names = frozenset(name.lower() for name in query_names)
        expected_bases = frozenset(name.strip().lower() for name in path_basenames if name.strip())
        if not expected_bases:
            return False
        for name, value in self.query_pairs:
            if expected_names and name not in expected_names:
                continue
            decoded = _decode_query_component(value)
            if decoded is None or not _looks_like_traversal_or_abs(decoded):
                continue
            collapsed = _collapse_local_path(value)
            if collapsed is None:
                continue
            lowered = collapsed.lower()
            base = lowered.rstrip("/").rsplit("/", 1)[-1]
            if base in expected_bases:
                return True
            for marker in expected_bases:
                if lowered == f"/{marker}" or lowered.endswith(f"/{marker}"):
                    return True
        return False


def parse_http_request(payload: bytes) -> HttpRequestView | None:
    """Parse one complete bounded HTTP/1 request header, or fail open with ``None``."""
    line_end = payload.find(b"\r\n")
    header_end = payload.find(b"\r\n\r\n")
    if line_end <= 0 or line_end > MAX_REQUEST_LINE or header_end < line_end:
        return None
    parts = payload[:line_end].split(b" ", 2)
    if len(parts) != 3 or not parts[2].startswith(b"HTTP/1."):
        return None
    try:
        method = parts[0].decode("ascii").upper()
    except UnicodeDecodeError:
        return None
    if method not in _METHODS:
        return None
    target = _decode_target(parts[1])
    if target is None:
        return None
    path, separator, query = target.partition("?")
    path = path or "/"
    query_pairs = _query_pairs(query if separator else "")

    cookies = []
    header_lines = payload[line_end + 2 : header_end].split(b"\r\n")
    if len(header_lines) > MAX_HEADER_LINES:
        return None
    for line in header_lines:
        if b":" not in line:
            continue
        name, value = line.split(b":", 1)
        if name.strip().lower() != b"cookie":
            continue
        for item in value.split(b";"):
            if b"=" not in item:
                continue
            cookie_name, cookie_value = item.split(b"=", 1)
            try:
                normalized_name = cookie_name.strip().decode("ascii").lower()
            except UnicodeDecodeError:
                continue
            claims = _decode_json_cookie(cookie_value)
            if normalized_name and claims is not None:
                cookies.append((normalized_name, claims))
    return HttpRequestView(
        method=method,
        target=target,
        path=path,
        query_pairs=query_pairs,
        json_cookies=tuple(cookies),
    )
