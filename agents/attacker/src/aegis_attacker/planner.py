"""가설 플래너 — 관측 증거로 다음 exploit 계획을 만든다.

설계 §9.8. 하드코딩된 S1→S2→S3 순서를 강제하지 않는다. 배너·응답 증거로 취약 부류
우선순위를 잡고, LLM 조언(비실행)을 exploit 계획으로 변환한다. LLM 출력은 그대로 실행되지
않고 반드시 범위·예산 검사를 다시 통과한다(§9.12). 증거가 없거나 진전이 없으면 중단한다.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Optional

from .models import Endpoint, ExecutionPlan, Scenario, VulnClass
from .profiles import suggest_vuln_classes

MAX_TURNS = 6

# 취약 부류 → 예선 시나리오(보고용 느슨한 대응, 실행 판단 아님).
_VULN_TO_SCENARIO = {
    VulnClass.AUTH: Scenario.S1,
    VulnClass.SQLI: Scenario.S2,
    VulnClass.LFI: Scenario.S3,
    VulnClass.SSRF: Scenario.S3,
}


def parse_exploit(content: str) -> Optional[dict]:
    """LLM 응답에서 exploit JSON을 추출·검증한다."""
    if not content:
        return None
    m = re.search(r"\{.*\}", content, re.DOTALL)
    if not m:
        return None
    try:
        obj = json.loads(m.group(0))
    except Exception:
        return None
    if not isinstance(obj, dict) or "path" not in obj:
        return None
    obj.setdefault("method", "GET")
    obj.setdefault("headers", {})
    obj.setdefault("body", "")
    obj.setdefault("vuln", "OTHER")
    obj.setdefault("reason", "")
    if not isinstance(obj.get("headers"), dict):
        obj["headers"] = {}
    method = str(obj["method"]).upper()
    obj["method"] = method if method in ("GET", "POST") else "GET"
    vuln = str(obj["vuln"]).upper()
    obj["vuln"] = vuln if vuln in ("LFI", "SSRF", "AUTH", "SQLI", "OTHER") else "OTHER"
    return obj


@dataclass
class EndpointState:
    """표적별 공격 진행 상태(라운드 한정)."""

    endpoint: Endpoint
    turn: int = 0
    no_response_streak: int = 0
    last_status: int = -1
    history: list = field(default_factory=list)  # (method, path, status) 요약


class Planner:
    """LLM 조언을 exploit 계획으로 변환한다. advisor는 조언만 제공(비실행)."""

    def __init__(self, advisor, max_turns: int = MAX_TURNS):
        self._advisor = advisor
        self._max_turns = max_turns

    def plan_next(self, endpoint: Endpoint, banner: str, feedback: str,
                  state: EndpointState, model: str = None) -> Optional[ExecutionPlan]:
        hints = suggest_vuln_classes(banner)
        exploit = self._advisor.advise_exploit(banner=banner, feedback=feedback,
                                               hints=hints, model=model)
        if not exploit:
            return None
        path = exploit.get("path")
        if not path:
            return None  # 경로 없는 조언은 실행 계획으로 만들지 않는다
        method = str(exploit.get("method", "GET")).upper()
        if method not in ("GET", "POST"):
            method = "GET"
        headers = exploit.get("headers") or {}
        if not isinstance(headers, dict):
            headers = {}
        vuln_name = str(exploit.get("vuln", "OTHER")).upper()
        vuln = VulnClass[vuln_name] if vuln_name in VulnClass.__members__ else VulnClass.OTHER
        return ExecutionPlan(
            tool="http",
            target=endpoint,
            args={
                "method": method,
                "path": path,
                "headers": headers,
                "body": exploit.get("body", "") or "",
            },
            expected_cost=1,
            timeout=6.0,
            budget_charge=1,
            scenario=_VULN_TO_SCENARIO.get(vuln),
            reason=exploit.get("reason", ""),
        )

    def should_stop(self, state: EndpointState) -> bool:
        """턴 소진 시 중단. 진전 없는 반복을 계속하지 않는다(§9.8)."""
        return state.turn >= self._max_turns
