"""허용 도구 레지스트리·실행 어댑터·범위 재검증·시그니처 회피.

설계 §9.10. 도구는 실행 직전에 대상이 `TARGETS × PORTS`(+제출·LiteLLM)에 포함되는지
재검증한다(운영세칙 제11·24조). 상대 방어 에이전트는 패킷 시그니처로 DROP하는 필터이므로,
같은 exploit·경로를 유지하면서 페이로드를 재인코딩해 시그니처를 회피하는 것은 이 게임의
정당한 핵심 기법이다(스켈레톤 agent-guide). 단 rate limit 자체를 우회하는 조작은 금지(제24조 8호).
"""

from __future__ import annotations

import time
import urllib.parse

from .models import Endpoint, ExecutionPlan, Observation, Outcome, ToolResult
from .observation import fingerprint, notable_headers

_QUOTE_SAFE = "/?&=%:+@,;!*'()$-_.~"


class ScopeViolation(Exception):
    """허용 범위 밖 대상 실행 시도."""


class Scope:
    """허용된 공격 대상 집합. 실행 직전 재검증에 쓴다."""

    def __init__(self, endpoints):
        self._allowed = {(e.host, e.port) for e in endpoints}

    def contains(self, endpoint: Endpoint) -> bool:
        return (endpoint.host, endpoint.port) in self._allowed

    def check(self, endpoint: Endpoint) -> None:
        if not self.contains(endpoint):
            raise ScopeViolation(f"범위 밖 대상: {endpoint.key()}")


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


def evasion_variants(payload: str) -> list:
    """동일 의도를 유지한 회피 변형들을 우선순위 순으로 반환한다."""
    variants = []
    for fn in (url_encode_tokens, vary_keyword_case, insert_sql_comments, double_encode_tokens):
        v = fn(payload)
        if v != payload and v not in variants:
            variants.append(v)
    return variants


# ---- 실행 어댑터 ----

class ExecutionAdapter:
    """단일 HTTP 도구 실행기. 실행 직전 범위·rate 재검증."""

    def __init__(self, http, rate, scope: Scope, clock=time.monotonic):
        self._http = http
        self._rate = rate
        self._scope = scope
        self._clock = clock

    def execute(self, plan: ExecutionPlan) -> ToolResult:
        self._scope.check(plan.target)  # 범위 밖이면 예외

        method = str(plan.args.get("method", "GET")).upper()
        raw_path = plan.args.get("path", "/") or "/"
        if not raw_path.startswith("/"):
            raw_path = "/" + raw_path
        url = plan.target.base_url() + urllib.parse.quote(raw_path, safe=_QUOTE_SAFE)
        headers = plan.args.get("headers") or {}
        body = plan.args.get("body") or None

        self._rate.acquire_request()
        start = self._clock()
        resp = self._http.request(method, url, headers, body, plan.timeout)
        latency_ms = (self._clock() - start) * 1000.0

        outcome = Outcome.SUCCESS if resp.status != 0 else Outcome.TIMEOUT
        obs = Observation(
            endpoint=plan.target,
            request_fingerprint=fingerprint(f"{method} {raw_path}"),
            status=resp.status,
            header_hints=notable_headers(resp.headers),
            body_fingerprint=fingerprint(resp.body),
            latency_ms=latency_ms,
            note="no-response" if resp.status == 0 else "",
        )
        return ToolResult(plan=plan, outcome=outcome, observation=obs, body=resp.body)
