"""수명주기 오케스트레이터 — 관측 → 계획 → 실행 → 제출.

설계 §9.4·§9.5·§9.13. 구성요소를 엮어 공정 스케줄러로 표적을 순회하고, 각 표적에서
관측 증거 기반으로 exploit을 반복한다. 상대 방어 필터에 DROP되면(무응답) 시그니처 회피
변형으로 재시도한다. 오류는 표적 단위로 격리하고 LLM 장애·예산 소진에도 결정론 경로
(관측·범위검사·제출)를 계속한다.
"""

from __future__ import annotations

import time

from .audit import AuditLogger, Redactor
from .config import AttackerConfig
from .flags import FlagPipeline, SubmitClient
from .llm_advisor import LLMAdvisor
from .models import ExecutionPlan, Outcome, RoundBudget, SubmitState
from .observation import Observer, UrllibHttp
from .phase_policy import FairScheduler
from .planner import EndpointState, Planner
from .round_report import RoundReport
from .tools import ExecutionAdapter, Scope, ScopeViolation, evasion_variants

LOOP_SLEEP = 4.0
PER_TARGET_BUDGET = 1
MAX_EVASION_VARIANTS = 3


class AttackerRuntime:
    """공격 런타임. 의존성 주입 가능(네트워크 없이 테스트)."""

    def __init__(self, config: AttackerConfig, http=None, rate=None,
                 clock=time.monotonic, sleep=time.sleep, audit=None, budget=None):
        from .rate_limit import RateLimiter

        self.config = config
        self.http = http or UrllibHttp()
        self.rate = rate or RateLimiter(clock=clock, sleep=sleep)
        self.sleep = sleep
        self.budget = budget or RoundBudget()
        self.scope = Scope(config.endpoints())
        self.observer = Observer(self.http, self.rate, clock)
        self.advisor = LLMAdvisor(self.http, config, self.budget)
        self.planner = Planner(self.advisor)
        self.adapter = ExecutionAdapter(self.http, self.rate, self.scope, clock)
        self.submit_client = SubmitClient(
            self.http, self.rate, config.submit_url, config.submit_token, sleep=sleep)
        self.pipeline = FlagPipeline(self.submit_client)
        self.report = RoundReport(budget=self.budget)
        self.audit = audit or AuditLogger(
            Redactor({config.llm_api_key, config.submit_token}))

    # ---- flag 처리 ----

    def _process_flags(self, body: str) -> bool:
        captured = False
        for fp, state in self.pipeline.process(body):
            self.report.record_submit(fp, state)
            if state == SubmitState.ACCEPTED:
                captured = True
        return captured

    # ---- 피드백 ----

    def _feedback(self, plan: ExecutionPlan, result) -> str:
        obs = result.observation
        method, path = plan.args["method"], plan.args["path"]
        if result.outcome == Outcome.TIMEOUT:
            return (f"Your request {method} {path} got NO response (dropped/timeout) though GET / "
                    "worked — an inline filter is DROPPING it by payload signature. Re-encode to evade "
                    "while keeping the SAME exploit and target path. Reply ONLY the JSON object.")
        hdrs = "; ".join(f"{k}:{v}" for k, v in obs.header_hints.items())
        return (f"Your request {method} {path} returned HTTP {obs.status}. "
                f"Notable headers: {hdrs or '-'}. Body: {result.body[:300]}. "
                "No flag yet. Craft a DIFFERENT, more specific request escalating the SAME vuln "
                "(deeper path, schema enumeration, spoofed header, internal root). Reply ONLY the JSON object.")

    # ---- 시그니처 회피 재시도 ----

    def _try_evasion(self, plan: ExecutionPlan):
        """무응답(필터 DROP) 시 동일 의도의 재인코딩 변형으로 재시도한다."""
        for variant in evasion_variants(plan.args["path"])[:MAX_EVASION_VARIANTS]:
            vplan = ExecutionPlan(
                tool=plan.tool, target=plan.target,
                args={**plan.args, "path": variant},
                timeout=plan.timeout, scenario=plan.scenario, reason="evasion:" + plan.reason,
            )
            try:
                vresult = self.adapter.execute(vplan)
            except ScopeViolation:
                return None, False
            self.report.record_request()
            if self._process_flags(vresult.body):
                return vresult, True
            if vresult.outcome == Outcome.SUCCESS:
                return vresult, False  # 필터 통과 — 이 응답으로 다음 계획
        return None, False

    # ---- 단일 표적 공격 ----

    def attack_endpoint(self, endpoint) -> bool:
        obs, resp = self.observer.observe_banner(endpoint)
        self.report.record_observation()
        self.report.record_request()
        if obs.no_response:
            self.audit.log("skip", target=endpoint.key(), reason="no-response")
            return False

        banner = (resp.body or "").strip()
        if self._process_flags(resp.body):  # 배너에 직접 flag가 있을 수도
            self.audit.log("hit", target=endpoint.key(), turn=0, path="/", reason="banner")
            return True

        state = EndpointState(endpoint)
        feedback = ""
        while not self.planner.should_stop(state):
            state.turn += 1
            plan = self.planner.plan_next(endpoint, banner, feedback, state)
            if plan is None:
                break
            try:
                result = self.adapter.execute(plan)
            except ScopeViolation:
                self.audit.log("scope-violation", target=endpoint.key())
                break
            self.report.record_request()

            if self._process_flags(result.body):
                self.audit.log("hit", target=endpoint.key(), turn=state.turn,
                               path=plan.args["path"], vuln=str(plan.scenario), reason=plan.reason)
                return True

            if result.outcome == Outcome.TIMEOUT:
                state.no_response_streak += 1
                evaded, captured = self._try_evasion(plan)
                if captured:
                    self.audit.log("hit", target=endpoint.key(), turn=state.turn,
                                   path=plan.args["path"], reason="evasion")
                    return True
                if evaded is not None:
                    result = evaded  # 필터 통과한 응답으로 피드백
            else:
                state.no_response_streak = 0

            feedback = self._feedback(plan, result)

        return False

    # ---- 라운드 루프 ----

    def run_once(self) -> RoundReport:
        """엔드포인트 전체를 공정 스케줄러로 한 번 순회한다."""
        endpoints = self.config.endpoints()
        sched = FairScheduler(endpoints, per_target_budget=PER_TARGET_BUDGET)
        while True:
            endpoint = sched.next()
            if endpoint is None:
                break
            sched.charge(endpoint)
            try:
                # 이번 패스에서 flag를 얻으면 해당 표적은 완료(재공격 불필요).
                self.attack_endpoint(endpoint)
            except Exception as exc:  # 표적 단위 격리
                self.audit.log("error", target=endpoint.key(), error=type(exc).__name__)
        return self.report

    def run_forever(self) -> None:
        self.audit.log("startup", targets=len(self.config.targets),
                       ports=len(self.config.ports), can_attack=self.config.can_attack,
                       can_submit=self.config.can_submit, model=self.config.llm_model)
        if not self.config.can_attack:
            self.audit.log("inert", reason="LLM 키 또는 표적 없음 — fail-open, 공격 없음")
            return
        if not self.config.can_submit:
            self.audit.log("warn", reason="제출 설정 없음 — flag 획득해도 제출 불가")
        while True:
            self.run_once()
            self.audit.log("round-summary", **self.report.summary())
            self.sleep(LOOP_SLEEP)
