"""Lossy redaction helpers used before any evidence can reach an LLM."""

from __future__ import annotations

import hashlib
import re
from urllib.parse import parse_qsl, unquote, urlsplit


REDACTED = "[REDACTED]"

_ASSIGNMENT = re.compile(
    r"(?i)\b(authorization|bearer|api[_-]?key|submit[_-]?token|token|password|passwd|"
    r"cookie|session(?:id)?|secret)\b\s*[:=]\s*([^\s,;]+)"
)
_FLAG = re.compile(r"(?i)\b(?:flag|d4h|dah)\{[^}\r\n]{1,512}\}")
_JWT = re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")
_PEM = re.compile(r"-----BEGIN [A-Z0-9 ]*(?:PRIVATE KEY|CERTIFICATE)-----")
_UUID = re.compile(r"^[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}$")
_HEX = re.compile(r"^[0-9a-fA-F]{12,}$")
_SAFE_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_.:-]{0,63}$")


def redact_text(value: str, *, limit: int = 512) -> str:
    """Redact credential-like values and cap retained text."""

    text = _ASSIGNMENT.sub(lambda m: f"{m.group(1)}={REDACTED}", value)
    text = _FLAG.sub(REDACTED, text)
    text = _JWT.sub(REDACTED, text)
    text = _PEM.sub(REDACTED, text)
    text = text.replace("\x00", "")
    return text[:limit]


def safe_label(value: object) -> str:
    """Keep only short categorical labels; fingerprint everything else."""

    text = redact_text(str(value), limit=256).strip()
    if text == REDACTED or REDACTED in text:
        return REDACTED
    if _SAFE_NAME.fullmatch(text):
        return text
    match = re.search(r"\b([A-Za-z_][A-Za-z0-9_.]*(?:Error|Exception|Timeout))\b", text)
    if match:
        return match.group(1)
    digest = hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()[:12]
    return f"template:{digest}"


def _segment_shape(segment: str) -> str:
    decoded = unquote(segment)
    if not decoded:
        return ""
    if decoded.isdigit():
        return "{num}"
    if _UUID.fullmatch(decoded):
        return "{uuid}"
    if _HEX.fullmatch(decoded):
        return "{hex}"
    if _SAFE_NAME.fullmatch(decoded):
        return decoded.lower()
    return "{value}"


def uri_shape(raw_uri: str) -> dict[str, object]:
    """Return route/query structure and attack-relevant features without values."""

    redacted = redact_text(raw_uri, limit=4096)
    lowered = unquote(redacted).lower()
    candidate = redacted if "://" in redacted else f"http://placeholder{redacted}"
    try:
        parsed = urlsplit(candidate)
        path = parsed.path
        query = parsed.query
    except ValueError:
        path, _, query = redacted.partition("?")

    shaped_segments = [_segment_shape(item) for item in path.split("/")]
    shaped_path = "/".join(shaped_segments) or "/"
    if path.startswith("/") and not shaped_path.startswith("/"):
        shaped_path = "/" + shaped_path

    query_keys: list[str] = []
    query_values: list[str] = []
    for key, value in parse_qsl(query, keep_blank_values=True, max_num_fields=64):
        query_keys.append(_segment_shape(key))
        query_values.append(value)

    feature_text = " ".join([lowered, *[unquote(item).lower() for item in query_values]])
    features: set[str] = set()
    if "../" in feature_text or "%2e" in raw_uri.lower():
        features.add("path_traversal")
    if re.search(r"\bunion\s+(?:all\s+)?select\b", feature_text):
        features.add("sql_union")
    if re.search(r"(?:127\.0\.0\.1|0\.0\.0\.0|localhost|\[?::1\]?)", feature_text):
        features.add("loopback_target")
    if any(marker in feature_text for marker in ("http://", "https://", "file://", "gopher://")):
        features.add("nested_url")
    if re.search(r"%[0-9a-f]{2}", raw_uri, re.IGNORECASE):
        features.add("percent_encoding")
    if any(marker in feature_text for marker in ("flag", "secret", "passwd", "metadata")):
        features.add("sensitive_resource_keyword")

    return {
        "path_shape": shaped_path[:512],
        "query_keys": sorted({item for item in query_keys if item})[:32],
        "features": sorted(features),
    }


def contains_forbidden_secret(value: str) -> bool:
    """Conservative detector used on LLM patches and generated artifacts."""

    if _FLAG.search(value) or _JWT.search(value) or _PEM.search(value):
        return True
    return bool(
        re.search(
            r"(?im)^\s*(?:LLM_API_KEY|SUBMIT_TOKEN|PASSWORD|API_KEY)\s*=\s*[^\s<][^\r\n]*$",
            value,
        )
    )
