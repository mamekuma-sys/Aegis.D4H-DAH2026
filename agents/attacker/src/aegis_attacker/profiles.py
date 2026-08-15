"""ObservedServiceProfile 분류와 취약 부류 우선순위 힌트.

설계 §9.6·§9.7·§7.3. 관측 증거로만 프로파일을 채우고, 취약 부류 힌트는 **우선순위
제안**일 뿐 확정이 아니다. 증거가 맞지 않으면 planner가 범용 관측으로 회귀한다.
FinalsPhaseHint는 증거가 특정 레이어를 강하게 가리킬 때만 생성한다(대부분 None).
"""

from __future__ import annotations

import hashlib
import json
import re

from .models import Endpoint, ObservedServiceProfile, VulnClass
from .observation import fingerprint, notable_headers

# 응답·배너에서 잡는 오류/스택 시그니처(다음 요청 근거).
ERROR_SIGNATURES = (
    "sqlite", "mysql", "postgres", "syntax error", "traceback", "stack trace",
    "unauthorized", "forbidden", "no such", "error near", "usage:",
)

# 배너 키워드 → 취약 부류 우선순위 힌트.
_VULN_KEYWORDS = {
    VulnClass.SSRF: ("url", "fetch", "proxy", "callback", "ssrf", "registry", "webhook"),
    VulnClass.LFI: ("file", "path", "download", "view", "read", "include", "template", "lfi"),
    VulnClass.AUTH: ("login", "admin", "session", "account", "auth", "cookie", "token", "portal", "private"),
    VulnClass.SQLI: ("product", "id=", "search", "query", "sql", "shop", "item", "user="),
}

_STRUCTURAL_PATH_RE = re.compile(r"/[A-Za-z][A-Za-z0-9_./-]{0,63}")
_STRUCTURAL_PARAM_RE = re.compile(r"[?&]([A-Za-z_][A-Za-z0-9_-]{0,63})=")
_FORM_ACTION_RE = re.compile(r"\baction\s*=\s*['\"]([^'\"]{1,128})", re.IGNORECASE)
_HTML_TAG_RE = re.compile(r"<([A-Za-z][A-Za-z0-9-]{0,31})(?:\s|>)")


def service_fingerprint(status: int, body: str, headers) -> str:
    """Return a structural service-family fingerprint, excluding team-specific values.

    The previous raw body hash split the same challenge into one family per team when a
    banner contained a team name, nonce, or timestamp.  Only observable interface shape
    is retained here: route/parameter/form/tag sets, coarse status, notable header names,
    content type, error signatures, and vulnerability markers.
    """
    text = body or ""
    low = text.lower()
    routes = sorted(set(_STRUCTURAL_PATH_RE.findall(text)))[:32]
    routes.extend(
        value for value in sorted(set(_FORM_ACTION_RE.findall(text)))[:16]
        if value not in routes
    )
    params = sorted(set(_STRUCTURAL_PARAM_RE.findall(text)))[:32]
    tags = sorted(set(tag.lower() for tag in _HTML_TAG_RE.findall(text)))[:24]
    errors = sorted(sig for sig in ERROR_SIGNATURES if sig in low)
    markers = sorted(
        vuln.value
        for vuln, keywords in _VULN_KEYWORDS.items()
        if any(keyword in low for keyword in keywords)
    )
    notable = notable_headers(headers)
    content_type = ""
    for key, value in (headers or {}).items():
        if key.lower() == "content-type":
            content_type = str(value).split(";", 1)[0].strip().lower()[:64]
            break
    material = json.dumps(
        {
            "status_class": int(status) // 100 if status else 0,
            "routes": routes,
            "params": params,
            "tags": tags,
            "errors": errors,
            "markers": markers,
            "header_names": sorted(key.lower() for key in notable),
            "content_type": content_type,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(material).hexdigest()


def latency_band(ms: float) -> str:
    if ms < 50:
        return "fast"
    if ms < 300:
        return "normal"
    return "slow"


def classify(endpoint: Endpoint, status: int, banner: str, headers,
             latency_ms: float) -> ObservedServiceProfile:
    """단일 배너 관측으로 프로파일을 만든다."""
    profile = ObservedServiceProfile(endpoint)
    profile.banner_fingerprint = fingerprint(banner)
    profile.status_codes = {status}
    profile.redacted_header_hints = notable_headers(headers)
    profile.latency_band = latency_band(latency_ms)

    low = (banner or "").lower()
    for sig in ERROR_SIGNATURES:
        if sig in low:
            profile.error_signatures.append(sig)

    text = (banner or "").strip()
    if text:
        profile.add_evidence("banner:" + text[:80])
    for key in profile.redacted_header_hints:
        profile.add_evidence("header:" + key.lower())
    if status == 0:
        profile.add_evidence("no-response")
    return profile


def merge_observation(profile: ObservedServiceProfile, status: int, body: str, headers) -> None:
    """후속 관측을 기존 프로파일에 누적한다(상태 코드·헤더·오류 시그니처)."""
    profile.status_codes.add(status)
    for k, v in notable_headers(headers).items():
        profile.redacted_header_hints.setdefault(k, v)
        profile.add_evidence("header:" + k.lower())
    low = (body or "").lower()
    for sig in ERROR_SIGNATURES:
        if sig in low and sig not in profile.error_signatures:
            profile.error_signatures.append(sig)


def suggest_vuln_classes(banner: str) -> list:
    """배너 기반 취약 부류 우선순위 힌트(확정 아님). 매칭 없으면 [OTHER]."""
    low = (banner or "").lower()
    hints = []
    for vuln, keywords in _VULN_KEYWORDS.items():
        if any(kw in low for kw in keywords):
            hints.append(vuln)
    return hints or [VulnClass.OTHER]
