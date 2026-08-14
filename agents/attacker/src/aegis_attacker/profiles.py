"""ObservedServiceProfile 분류와 취약 부류 우선순위 힌트.

설계 §9.6·§9.7·§7.3. 관측 증거로만 프로파일을 채우고, 취약 부류 힌트는 **우선순위
제안**일 뿐 확정이 아니다. 증거가 맞지 않으면 planner가 범용 관측으로 회귀한다.
FinalsPhaseHint는 증거가 특정 레이어를 강하게 가리킬 때만 생성한다(대부분 None).
"""

from __future__ import annotations

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


# 오류 시그니처 → 취약 부류 우선순위(확정 아님, 관측 근거).
_SIGNATURE_TO_VULN = {
    "sqlite": VulnClass.SQLI, "mysql": VulnClass.SQLI, "postgres": VulnClass.SQLI,
    "syntax error": VulnClass.SQLI, "error near": VulnClass.SQLI,
    "no such": VulnClass.LFI, "traceback": VulnClass.LFI, "stack trace": VulnClass.LFI,
    "unauthorized": VulnClass.AUTH, "forbidden": VulnClass.AUTH,
}


def suggest_from_profile(profile) -> list:
    """관측 프로파일(오류 시그니처·헤더 힌트)에서 취약 부류 우선순위를 도출한다.

    classify/merge_observation 로 누적한 증거를 LLM 우선순위 힌트로 승격한다. 확정이 아니라
    우선순위이며, 근거가 없으면 빈 목록(planner 가 배너 힌트로 회귀)."""
    if profile is None:
        return []
    hints = []
    for sig in getattr(profile, "error_signatures", []) or []:
        vuln = _SIGNATURE_TO_VULN.get(sig)
        if vuln and vuln not in hints:
            hints.append(vuln)
    header_keys = {k.lower() for k in (getattr(profile, "redacted_header_hints", {}) or {})}
    if header_keys & {"set-cookie", "www-authenticate", "x-role", "x-user"}:
        if VulnClass.AUTH not in hints:
            hints.append(VulnClass.AUTH)
    if "location" in header_keys and VulnClass.SSRF not in hints:
        hints.append(VulnClass.SSRF)
    return hints
