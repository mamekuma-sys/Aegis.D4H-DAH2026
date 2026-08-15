"""Bounded HTTP request semantics for high-confidence packet policy.

Only a complete request header already present in the packet payload is parsed. Any
truncation, malformed encoding, oversized value, or unsupported shape returns ``None``
so the caller preserves the defender's fail-open contract.
"""

from __future__ import annotations

import base64
import binascii
import json
import urllib.parse
from dataclasses import dataclass


MAX_REQUEST_LINE = 1536
MAX_HEADER_LINES = 64
MAX_COOKIE_VALUE = 512
MAX_JSON_KEYS = 16
MAX_JSON_TEXT = 512
MAX_PERCENT_DECODE_ROUNDS = 2
_METHODS = frozenset({"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"})


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
    if len(target) > MAX_REQUEST_LINE or any(ch in target for ch in (b"\r", b"\n", b"\x00")):
        return None
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


def _decode_json_cookie(value: bytes) -> tuple[tuple[str, str], ...] | None:
    value = value.strip().strip(b'"')
    if not value or len(value) > MAX_COOKIE_VALUE:
        return None
    try:
        value = urllib.parse.unquote_to_bytes(value)
        padded = value + b"=" * ((4 - len(value) % 4) % 4)
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


@dataclass(frozen=True, slots=True)
class HttpRequestView:
    method: str
    target: str
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
    return HttpRequestView(method=method, target=target, json_cookies=tuple(cookies))
