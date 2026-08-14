"""수명주기 오케스트레이터 — 관측 → 계획 → 실행 → 제출.

설계 §9.4·§9.5·§9.10·§9.13. 구성요소를 typed egress·Round 비밀 저장소·증거 binding으로 엮어
공정 스케줄러로 표적을 순회한다. 각 계획은 실행 직전 capability·Round·endpoint·TTL·증거·부작용을
재검증하고, 상대 방어 필터에 DROP되면 시그니처 회피 변형으로 재시도한다. 오류는 표적 단위로
격리한다.

**Round = 컨테이너 수명.** 운영진은 20분마다 컨테이너를 새로 만든다(integration/README).
따라서 playbook·flag 중복 집합·성공/실패 메모리·비밀 저장소는 4초 루프마다 폐기하지 않고
컨테이너 수명 동안 유지한다. 이미 flag 를 딴 표적은 다시 공격하지 않고, 실패 표적은 backoff 후
재시도한다. ROUND_DURATION 은 제출 Retry-After 경계로만 쓴다.
"""

from __future__ import annotations

import threading
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
from .profiles import classify, merge_observation
from .rate_limit import RateLimiter
from .recon import COMMON_PROBE_PATHS, MAX_DISCOVERED_PATHS, discover_paths
from .round_report import RoundReport
from .secrets import KIND_LLM_KEY, KIND_SUBMIT_TOKEN, RoundSecretStore
from .tools import ExecutionAdapter, PlanBindingError, evasion_arg_variants

LOOP_SLEEP = 4.0
PER_TARGET_BUDGET = 1
MAX_EVASION_VARIANTS = 3
PLAN_TTL = 30.0
EVIDENCE_TTL = 90.0
ROUND_DURATION = 20 * 60.0  # Round(컨테이너 수명) 20분 → 제출 재시도 경계

# 실패 표적 backoff(초). 같은 요청을 매 4초 루프마다 두들기지 않는다.
BACKOFF_SCHEDULE = (0.0, 8.0, 30.0, 60.0, 120.0)


class AttackerRuntime:
    """공격 런타임. 의존성 주입 가능(네트워크 없이 테스트).

    컨테이너 수명 동안 살아있는 하나의 오퍼레이셔널 Round 로 동작한다. persistent 컴포넌트
    (playbook·flag 저장소·비밀 저장소·성공/실패 메모리)는 첫 `run_once` 에서 한 번만 만들고
    이후 pass 에서 재사용한다.
    """

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
        # 한 번만 구성하는 컨테이너 수명 컴포넌트
        self._round_built = False
        self._round_id = ""
        self._secret_store = None
        self._observer = None
        self._adapter = None
        self._pipeline = None
        self._planner = None
        self._report = None
        self._playbook = None
        self._use_llm = False
        # 표적 단위 성공/실패 메모리(컨테이너 수명 유지). 병렬 안전.
        self._mem_lock = threading.Lock()
        self._accepted = set()       # 이미 flag 를 딴 endpoint key — 재공격 안 함
        self._attempts = {}          # endpoint key -> 실패 시도 횟수
        self._next_attempt_at = {}   # endpoint key -> 다음 시도 가능 monotonic

    # ---- Round 컨텍스트 구성(컨테이너 수명 1회) ----

    def _build_round(self) -> None:
        if self._round_built:
            return
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
        self._use_llm = llm_handle is not None

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
        self._playbook = Playbook()  # 컨테이너 수명 교차 재사용(비밀 없음)
        self._round_built = True

    def shutdown(self) -> None:
        """컨테이너 종료 시 비밀 원문을 즉시 폐기한다(운영진이 컨테이너를 재생성)."""
        if self._secret_store is not None:
            self._secret_store.expire_all()

    def _bind_plan(self, plan: ExecutionPlan, endpoint, evidence_ref) -> ExecutionPlan:
        now = self.clock()
        plan.plan_id = f"plan-{self._round_id}-{endpoint.endpoint_id}-{now}"
        plan.round_id = self._round_id
        plan.endpoint_id = endpoint.endpoint_id
        plan.capability = Capability.ATTACK_TARGET
        plan.evidence_refs = [evidence_ref] if evidence_ref else []
        plan.created_at_monotonic = now
        plan.expires_at_monotonic = now + PLAN_TTL
        # POST/로그인/파라미터 변경은 신선한 증거 + 유한 flag-directed 선행조건에서만 변경 등급.
        # SLA/DoS 를 유발하지 않는 단발 요청이다(§9.10).
        if str(plan.args.get("method", "GET")).upper() == "POST" and evidence_ref is not None:
            plan.side_effect_class = SideEffectClass.BOUNDED_FLAG_DIRECTED_MUTATION
            if not plan.preconditions:
                plan.preconditions = ["fresh-evidence", "flag-directed", "single-shot-no-sla"]
        elif plan.side_effect_class is None:
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
        """무응답(필터 DROP) 시 path·query·body·headers 를 재인코딩한 변형으로 재시도한다."""
        for variant_args in evasion_arg_variants(plan.args)[:MAX_EVASION_VARIANTS]:
            now = self.clock()
            vplan = ExecutionPlan(
                tool=plan.tool, target=plan.target,
                args=variant_args,
                plan_id=f"{plan.plan_id}-evade",
                round_id=self._round_id, endpoint_id=plan.target.endpoint_id,
                capability=Capability.ATTACK_TARGET,
                evidence_refs=[evidence_ref] if evidence_ref else [],
                created_at_monotonic=now, expires_at_monotonic=now + PLAN_TTL,
                side_effect_class=plan.side_effect_class, preconditions=list(plan.preconditions),
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

    def _recon(self, endpoint, evidence_ref, banner, profile):
        """흔한 경로 + 배너/robots/오류에서 노출된 경로를 읽기 전용 GET 으로 찌른다.

        (captured, last_evidence) 를 반환한다. 발견 경로는 유한 상한(MAX_DISCOVERED_PATHS)까지만
        큐잉해 요청 예산을 아낀다. 모든 프로브는 READ_ONLY.
        """
        seen = set()
        queue = list(COMMON_PROBE_PATHS)
        for p in discover_paths(banner):  # 배너에 노출된 경로 우선 편입
            if p not in queue:
                queue.append(p)
        discovered_budget = MAX_DISCOVERED_PATHS

        i = 0
        while i < len(queue):
            path = queue[i]
            i += 1
            if path in seen:
                continue
            seen.add(path)
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
                return True, result.observation.evidence_ref
            merge_observation(profile, result.observation.status, result.body,
                              result.observation.redacted_header_hints)
            # robots/오류/인덱스 본문에서 새 경로를 발견하면 상한 안에서 큐에 추가한다.
            if discovered_budget > 0 and result.body:
                for np in discover_paths(result.body):
                    if np not in seen and np not in queue and discovered_budget > 0:
                        queue.append(np)
                        discovered_budget -= 1
            evidence_ref = result.observation.evidence_ref  # 다음 프로브용 신선한 증거
        return False, evidence_ref

    def _run_bound_exploit(self, endpoint, args, evidence_ref, reason):
        """비밀 없는 exploit 형태(method·path·headers·body)를 계획으로 실행한다(playbook 재사용)."""
        now = self.clock()
        plan = ExecutionPlan(
            tool="http", target=endpoint,
            args={"method": args.get("method", "GET"), "path": args.get("path", "/"),
                  "headers": dict(args.get("headers", {}) or {}), "body": args.get("body", "") or ""},
            plan_id=f"pb-{self._round_id}-{endpoint.endpoint_id}",
            round_id=self._round_id, endpoint_id=endpoint.endpoint_id,
            capability=Capability.ATTACK_TARGET,
            evidence_refs=[evidence_ref] if evidence_ref else [],
            created_at_monotonic=now, expires_at_monotonic=now + PLAN_TTL,
            reason=reason)
        self._bind_plan(plan, endpoint, evidence_ref)  # POST 형이면 변경 등급·선행조건 부여
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
        # 관측 프로파일: 배너로 초기화하고 recon/exploit 응답으로 누적(§9.6·§9.7).
        profile = classify(endpoint, obs.status, banner,
                           obs.redacted_header_hints, obs.latency_ms)
        if self._process_flags(resp.body):
            self.audit.log("hit", target=endpoint.key(), turn=0, path="/", reason="banner")
            return True

        # 결정론적 사전 정찰 — 쉬운 flag 를 LLM 토큰 없이(배너/robots/오류 경로 포함)
        captured, current_evidence = self._recon(endpoint, current_evidence, banner, profile)
        if captured:
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

        # LLM 키가 없으면 결정론 경로까지만(배너/recon/playbook). 여기서 종료.
        if not self._use_llm:
            return False

        state = EndpointState(endpoint)
        feedback = ""
        while not self._planner.should_stop(state):
            state.turn += 1
            # cheap-first 모델, 실패가 쌓이면 승급
            model = escalated_model(self.config.llm_model, max(0, state.turn - 2))
            plan = self._planner.plan_next(endpoint, banner, feedback, state,
                                           model=model, profile=profile)
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
                self._playbook.record(banner_fp, plan.args)  # 교차 재사용용 기록(비밀 마스크)
                self.audit.log("hit", target=endpoint.key(), turn=state.turn,
                               path=plan.args["path"], vuln=str(plan.scenario), reason=plan.reason)
                return True

            current_evidence = result.observation.evidence_ref
            merge_observation(profile, result.observation.status, result.body,
                              result.observation.redacted_header_hints)
            if result.outcome == Outcome.TIMEOUT:
                state.no_response_streak += 1
                evaded, captured = self._try_evasion(plan, current_evidence)
                if captured:
                    self._playbook.record(banner_fp, plan.args)
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

    # ---- 표적 단위 성공/실패 메모리 ----

    def _eligible(self, now: float):
        """이미 딴 표적은 제외하고, backoff 시각이 지난 표적만 공정 순서로 반환한다."""
        out = []
        with self._mem_lock:
            for e in self.config.endpoints():
                key = e.key()
                if key in self._accepted:
                    continue
                if now < self._next_attempt_at.get(key, 0.0):
                    continue  # backoff 중 — 두들기지 않는다
                out.append(e)
        return out

    def _record_result(self, endpoint, captured: bool) -> None:
        key = endpoint.key()
        now = self.clock()
        with self._mem_lock:
            if captured:
                self._accepted.add(key)  # 재공격 안 함
                self._attempts.pop(key, None)
                self._next_attempt_at.pop(key, None)
                return
            n = self._attempts.get(key, 0) + 1
            self._attempts[key] = n
            delay = BACKOFF_SCHEDULE[min(n, len(BACKOFF_SCHEDULE) - 1)]
            self._next_attempt_at[key] = now + delay

    def _attack_isolated(self, endpoint) -> None:
        try:
            captured = self.attack_endpoint(endpoint)
        except Exception as exc:  # 표적 단위 격리
            self.audit.log("error", target=endpoint.key(), error=type(exc).__name__)
            captured = False
        self._record_result(endpoint, captured)

    def run_once(self) -> RoundReport:
        """공격 대상을 한 번 순회한다(공유 작업 큐·전역 rate limit 공유).

        컨테이너 수명 Round 컴포넌트는 첫 호출에서만 구성하고 이후 pass 에서 재사용한다.
        이미 flag 를 딴 표적은 건너뛰고, 실패 표적은 backoff 후에만 재시도한다. concurrency<=1
        이거나 대상이 1개면 결정론적 순차 경로를 쓴다.
        """
        self._build_round()
        eligible = self._eligible(self.clock())
        if not eligible:
            return self._report  # 모두 성공했거나 backoff 중 — 이번 pass 는 무동작
        workers = min(self.config.concurrency, max(1, len(eligible)))
        sched = FairScheduler(eligible, per_target_budget=PER_TARGET_BUDGET)
        if workers <= 1:
            # 순차(결정론) — 공정 스케줄러로 순회
            while True:
                endpoint = sched.next_and_charge()
                if endpoint is None:
                    break
                self._attack_isolated(endpoint)
        else:
            # 병렬 — 워커가 공유 스케줄러에서 다음 표적을 원자적으로 꺼낸다(공정 + 전역 rate 공유).
            def worker():
                while True:
                    endpoint = sched.next_and_charge()
                    if endpoint is None:
                        return
                    self._attack_isolated(endpoint)
            with ThreadPoolExecutor(max_workers=workers) as pool:
                for fut in [pool.submit(worker) for _ in range(workers)]:
                    fut.result()
        return self._report

    def run_forever(self, max_passes: int = None) -> None:
        """컨테이너 수명 동안 공격 pass 를 반복한다.

        `can_run`(표적·포트 존재)로 가동하며 LLM 키 유무로 전면 inert 하지 않는다. 표적이 없으면
        무동작이되 주기적으로 재점검한다(§9.13). max_passes 는 테스트용 상한(None=무한).
        """
        self.audit.log("startup", targets=len(self.config.targets),
                       ports=len(self.config.ports), can_run=self.config.can_run,
                       can_use_llm=self.config.can_use_llm,
                       can_submit=self.config.can_submit, model=self.config.llm_model)
        if not self.config.can_submit:
            self.audit.log("warn", reason="제출 설정 없음 — flag 획득해도 제출 불가")
        if not self.config.can_use_llm:
            self.audit.log("info", reason="LLM 키 없음 — 배너/recon/playbook/제출 결정론 경로만 수행")
        passes = 0
        try:
            while max_passes is None or passes < max_passes:
                passes += 1
                if not self.config.can_run:
                    # 표적/포트 없음 → inert. LLM 키로 전면 inert 하지 않고 주기적 재점검(§9.13).
                    self.audit.log("inert", reason="표적/포트 없음 — 주기적 재점검")
                    self.sleep(LOOP_SLEEP)
                    continue
                report = self.run_once()
                self.audit.log("round-summary", **report.summary())
                self.sleep(LOOP_SLEEP)
        finally:
            self.shutdown()
