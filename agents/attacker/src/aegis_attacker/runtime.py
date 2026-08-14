"""수명주기 오케스트레이터 — 관측 → 계획 → 실행 → 제출.

설계 §9.4·§9.5·§9.10·§9.13. 구성요소를 typed egress·Round 비밀 저장소·증거 binding으로 엮어
공정 스케줄러로 표적을 순회한다. 각 계획은 실행 직전 capability·Round·endpoint·TTL·증거·부작용을
재검증하고, 상대 방어 필터에 DROP되면 시그니처 회피 변형으로 재시도한다. 오류는 표적 단위로
격리하고, Round 종료 시 비밀 원문·증거·중복 집합을 폐기한다.
"""

from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor

from .audit import AuditLogger, Redactor
from .config import AttackerConfig
from .egress import EgressError, EgressGateway, build_allowlists
from .flags import FlagPipeline, SubmitClient
from .llm_advisor import LLMAdvisor, escalated_model
from .models import Capability, ExecutionPlan, Outcome, RoundBudget, SideEffectClass, SubmitState
from .observation import EvidenceFactory, Observer, UrllibHttp
from .phase_policy import FairScheduler
from .planner import EndpointState, Planner
from .playbook import Playbook
from .rate_limit import RateLimiter
from .recon import COMMON_PROBE_PATHS
from .round_report import RoundReport
from .secrets import KIND_LLM_KEY, KIND_SUBMIT_TOKEN, RoundSecretStore
from .tools import ExecutionAdapter, PlanBindingError, evasion_variants

LOOP_SLEEP = 4.0
PER_TARGET_BUDGET = 1
MAX_EVASION_VARIANTS = 3
PLAN_TTL = 30.0
EVIDENCE_TTL = 90.0
ROUND_DURATION = 20 * 60.0  # Round 20분 → 제출 재시도 경계


class AttackerRuntime:
    """공격 런타임. 의존성 주입 가능(네트워크 없이 테스트)."""

    def __init__(self, config: AttackerConfig, http=None, rate=None,
                 clock=time.monotonic, sleep=time.sleep, audit=None, budget=None):
        self.config = config
        self.transport = http or UrllibHttp()
        self.rate = rate or RateLimiter(clock=clock, sleep=sleep)
        self.clock = clock
        self.sleep = sleep
        self.budget = budget or RoundBudget()
        # 로그에서 제출 토큰·LLM 키를 제거(원문은 저장소로 옮기지만 config가 origin).
        self.audit = audit or AuditLogger(Redactor({config.submit_token, config.llm_api_key}))
        self._round_seq = 0
        # run_once에서 설정하는 Round 한정 컴포넌트
        self._round_id = ""
        self._secret_store = None
        self._observer = None
        self._adapter = None
        self._pipeline = None
        self._planner = None
        self._report = None
        self._playbook = None
        self._round_active = False

    # ---- Round 컨텍스트 구성 ----

    def _build_round(self) -> None:
        self._round_seq += 1
        self._round_id = f"round-{self._round_seq}"
        self.budget.reset()  # 라운드별 예산 격리 — 누적 상한/보고 왜곡 방지
        now = self.clock()
        store = RoundSecretStore(self._round_id, clock=self.clock)
        submit_handle = (store.put(KIND_SUBMIT_TOKEN, self.config.submit_token)
                         if self.config.submit_token else None)
        llm_handle = (store.put(KIND_LLM_KEY, self.config.llm_api_key)
                      if self.config.llm_api_key else None)
        self._secret_store = store

        egress = EgressGateway(self.transport, build_allowlists(self.config))
        evidence = EvidenceFactory(self._round_id, self.clock, EVIDENCE_TTL)

        self._observer = Observer(egress, self.rate, self._round_id, self.clock, evidence)
        self._adapter = ExecutionAdapter(egress, self.rate, self._round_id, self.clock, evidence)
        advisor = LLMAdvisor(egress, self.config, self.budget, store, llm_handle)
        self._planner = Planner(advisor)
        submit_client = SubmitClient(
            egress, self.rate, self.config.submit_url, submit_handle, store,
            clock=self.clock, sleep=self.sleep, round_deadline=now + ROUND_DURATION)
        self._pipeline = FlagPipeline(submit_client, store)
        self._report = RoundReport(budget=self.budget)
        self._playbook = Playbook()  # Round 한정 교차 재사용(비밀 없음)

    def start_round(self) -> RoundReport:
        """공식 Round를 연다. 이미 열려 있으면 같은 Round를 유지한다."""
        if not self._round_active:
            self._build_round()
            self._round_active = True
        return self._report

    def _finish_round(self) -> None:
        """Round 비밀을 폐기한다. 반복 호출해도 안전하다."""
        if not self._round_active:
            return
        self._secret_store.expire_all()
        self._round_active = False

    def finish_round(self) -> None:
        """공식 Round를 종료하고 비밀 원문을 폐기한다."""
        self._finish_round()

    def _bind_plan(self, plan: ExecutionPlan, endpoint, evidence_ref) -> ExecutionPlan:
        now = self.clock()
        plan.plan_id = f"plan-{self._round_id}-{endpoint.endpoint_id}-{now}"
        plan.round_id = self._round_id
        plan.endpoint_id = endpoint.endpoint_id
        plan.capability = Capability.ATTACK_TARGET
        plan.evidence_refs = [evidence_ref] if evidence_ref else []
        plan.created_at_monotonic = now
        plan.expires_at_monotonic = now + PLAN_TTL
        if plan.side_effect_class is None:
            plan.side_effect_class = SideEffectClass.READ_ONLY
        return plan

    # ---- flag 처리 ----

    def _process_flags(self, body: str) -> bool:
        captured = False
        for fp, state in self._pipeline.process(body):
            self._report.record_submit(fp, state)
            if state == SubmitState.ACCEPTED:
                captured = True
        return captured

    def _feedback(self, plan: ExecutionPlan, result) -> str:
        obs = result.observation
        method, path = plan.args["method"], plan.args["path"]
        if result.outcome == Outcome.TIMEOUT:
            return (f"Your request {method} {path} got NO response (dropped/timeout) though GET / "
                    "worked — an inline filter is DROPPING it by payload signature. Re-encode to evade "
                    "while keeping the SAME exploit and target path. Reply ONLY the JSON object.")
        hdrs = "; ".join(f"{k}:{v}" for k, v in obs.redacted_header_hints.items())
        return (f"Your request {method} {path} returned HTTP {obs.status}. "
                f"Notable headers: {hdrs or '-'}. Body: {result.body[:300]}. "
                "No flag yet. Craft a DIFFERENT, more specific request escalating the SAME vuln "
                "(deeper path, schema enumeration, spoofed header, internal root). Reply ONLY the JSON object.")

    def _try_evasion(self, plan: ExecutionPlan, evidence_ref):
        """무응답(필터 DROP) 시 동일 의도의 재인코딩 변형으로 재시도한다."""
        for variant in evasion_variants(plan.args["path"])[:MAX_EVASION_VARIANTS]:
            now = self.clock()
            vplan = ExecutionPlan(
                tool=plan.tool, target=plan.target,
                args={**plan.args, "path": variant},
                plan_id=f"{plan.plan_id}-evade",
                round_id=self._round_id, endpoint_id=plan.target.endpoint_id,
                capability=Capability.ATTACK_TARGET,
                evidence_refs=[evidence_ref] if evidence_ref else [],
                created_at_monotonic=now, expires_at_monotonic=now + PLAN_TTL,
                side_effect_class=plan.side_effect_class,
                timeout=plan.timeout, scenario=plan.scenario, reason="evasion:" + plan.reason)
            try:
                vresult = self._adapter.execute(vplan)
            except (PlanBindingError, EgressError):
                return None, False
            self._report.record_request()
            if self._process_flags(vresult.body):
                return vresult, True
            if vresult.outcome == Outcome.SUCCESS:
                return vresult, False  # 필터 통과 — 이 응답으로 다음 계획
        return None, False

    # ---- 결정론적 사전 정찰 (LLM 전, 토큰 0) ----

    def _recon(self, endpoint, evidence_ref) -> bool:
        for path in COMMON_PROBE_PATHS:
            now = self.clock()
            plan = ExecutionPlan(
                tool="http", target=endpoint, args={"method": "GET", "path": path},
                plan_id=f"recon-{self._round_id}-{endpoint.endpoint_id}-{path}",
                round_id=self._round_id, endpoint_id=endpoint.endpoint_id,
                capability=Capability.ATTACK_TARGET,
                evidence_refs=[evidence_ref] if evidence_ref else [],
                created_at_monotonic=now, expires_at_monotonic=now + PLAN_TTL,
                side_effect_class=SideEffectClass.READ_ONLY, reason="recon")
            try:
                result = self._adapter.execute(plan)
            except (PlanBindingError, EgressError):
                continue
            self._report.record_request()
            if self._process_flags(result.body):
                self.audit.log("hit", target=endpoint.key(), path=path, reason="recon")
                return True
            evidence_ref = result.observation.evidence_ref  # 다음 프로브용 신선한 증거
        return False

    def _run_bound_exploit(self, endpoint, args, evidence_ref, reason):
        """비밀 없는 exploit 형태(method·path)를 READ_ONLY 계획으로 실행한다(playbook 재사용용)."""
        now = self.clock()
        plan = ExecutionPlan(
            tool="http", target=endpoint,
            args={"method": args.get("method", "GET"), "path": args.get("path", "/"),
                  "headers": args.get("headers", {}) or {}, "body": args.get("body", "") or ""},
            plan_id=f"pb-{self._round_id}-{endpoint.endpoint_id}",
            round_id=self._round_id, endpoint_id=endpoint.endpoint_id,
            capability=Capability.ATTACK_TARGET,
            evidence_refs=[evidence_ref] if evidence_ref else [],
            created_at_monotonic=now, expires_at_monotonic=now + PLAN_TTL,
            side_effect_class=SideEffectClass.READ_ONLY, reason=reason)
        try:
            result = self._adapter.execute(plan)
        except (PlanBindingError, EgressError):
            return None, False
        self._report.record_request()
        return result, self._process_flags(result.body)

    # ---- 단일 표적 공격 ----

    def attack_endpoint(self, endpoint) -> bool:
        obs, resp = self._observer.observe_banner(endpoint)
        self._report.record_observation()
        self._report.record_request()
        if obs.no_response:
            self.audit.log("skip", target=endpoint.key(), reason="no-response")
            return False

        current_evidence = obs.evidence_ref
        banner_fp = obs.body_fingerprint
        banner = (resp.body or "").strip()
        if self._process_flags(resp.body):
            self.audit.log("hit", target=endpoint.key(), turn=0, path="/", reason="banner")
            return True

        # 결정론적 사전 정찰 — 쉬운 flag를 LLM 토큰 없이
        if self._recon(endpoint, current_evidence):
            return True

        # 라운드 내 성공 플레이북 교차 재사용 — 같은 배너의 다른 표적에 먼저 시도(LLM 전)
        known = self._playbook.lookup(banner_fp)
        if known:
            result, captured = self._run_bound_exploit(endpoint, known, current_evidence, "playbook")
            if captured:
                self.audit.log("hit", target=endpoint.key(),
                               path=known.get("path"), reason="playbook")
                return True
            if result is not None:
                current_evidence = result.observation.evidence_ref

        state = EndpointState(endpoint)
        feedback = ""
        while not self._planner.should_stop(state):
            state.turn += 1
            # cheap-first 모델, 실패가 쌓이면 승급
            model = escalated_model(self.config.llm_model, max(0, state.turn - 2))
            plan = self._planner.plan_next(endpoint, banner, feedback, state, model=model)
            if plan is None:
                break
            self._bind_plan(plan, endpoint, current_evidence)
            try:
                result = self._adapter.execute(plan)
            except (PlanBindingError, EgressError) as exc:
                self.audit.log("reject", target=endpoint.key(), turn=state.turn,
                               reason=type(exc).__name__)
                break
            self._report.record_request()

            if self._process_flags(result.body):
                self._playbook.record(banner_fp, plan.args)  # 교차 재사용용 기록(비밀 없음)
                self.audit.log("hit", target=endpoint.key(), turn=state.turn,
                               path=plan.args["path"], vuln=str(plan.scenario), reason=plan.reason)
                return True

            current_evidence = result.observation.evidence_ref
            if result.outcome == Outcome.TIMEOUT:
                state.no_response_streak += 1
                evaded, captured = self._try_evasion(plan, current_evidence)
                if captured:
                    self.audit.log("hit", target=endpoint.key(), turn=state.turn,
                                   path=plan.args["path"], reason="evasion")
                    return True
                if evaded is not None:
                    result = evaded
                    current_evidence = evaded.observation.evidence_ref
            else:
                state.no_response_streak = 0

            feedback = self._feedback(plan, result)

        return False

    # ---- 라운드 루프 ----

    def _attack_isolated(self, endpoint) -> None:
        try:
            self.attack_endpoint(endpoint)
        except Exception as exc:  # 표적 단위 격리
            self.audit.log("error", target=endpoint.key(), error=type(exc).__name__)

    def run_cycle(self) -> RoundReport:
        """열린 Round에서 엔드포인트 전체를 한 번 공격한다(병렬, 전역 rate limit 공유).

        concurrency<=1 이거나 표적이 1개면 결정론적 순차 경로를 쓴다.
        """
        if not self._round_active:
            raise RuntimeError("start_round() must be called before run_cycle()")
        endpoints = self.config.endpoints()
        workers = min(self.config.concurrency, max(1, len(endpoints)))
        if workers <= 1:
            # 순차(결정론) — 공정 스케줄러로 순회
            sched = FairScheduler(endpoints, per_target_budget=PER_TARGET_BUDGET)
            while True:
                endpoint = sched.next()
                if endpoint is None:
                    break
                sched.charge(endpoint)
                self._attack_isolated(endpoint)
        else:
            # 병렬 — 표적별 스레드가 전역 rate limit·공유 상태(락)를 공유
            with ThreadPoolExecutor(max_workers=workers) as pool:
                for fut in [pool.submit(self._attack_isolated, e) for e in endpoints]:
                    fut.result()
        return self._report

    def run_once(self) -> RoundReport:
        """독립된 한 Round를 열고 한 번의 scan cycle을 실행한다."""
        self.start_round()
        try:
            return self.run_cycle()
        finally:
            self.finish_round()

    def run_forever(self, max_cycles=None) -> None:
        self.audit.log("startup", targets=len(self.config.targets),
                       ports=len(self.config.ports), can_attack=self.config.can_attack,
                       can_submit=self.config.can_submit, model=self.config.llm_model)
        if not self.config.can_attack:
            self.audit.log("inert", reason="LLM 키 또는 표적 없음 — fail-open, 공격 없음")
            return
        if not self.config.can_submit:
            self.audit.log("warn", reason="제출 설정 없음 — flag 획득해도 제출 불가")
        self.start_round()
        try:
            cycles = 0
            while max_cycles is None or cycles < max_cycles:
                report = self.run_cycle()
                self.audit.log("round-summary", **report.summary())
                cycles += 1
                if max_cycles is None or cycles < max_cycles:
                    self.sleep(LOOP_SLEEP)
        finally:
            self.finish_round()
