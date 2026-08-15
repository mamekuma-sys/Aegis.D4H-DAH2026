"""동기 판정 3단계 (`HotPolicy` — Gate · Sig · Score).

설계 §4.1 동기 경로 예산 분리, §6 기본 verdict 정책, §9.2~§9.4, §10.1 rule 우선순위.

기본 원칙은 **불확실하면 빠르게 `ACCEPT`, 고신뢰 증거가 있을 때만 `DROP`**이다.
§0.2의 산식 분석에 따르면 flag 1개 손실은 SLA 수십 회 실패와 맞먹으므로 조건을
충족한 고신뢰 rule을 오탐 우려로 미루지는 않는다. 다만 그 "조건"은 §6.1의 여섯
가지이고, 그것을 판단하는 주체는 런타임이 아니라 Break의 사람이다. 이 모듈은
policy file이 이미 승인한 것만 집행한다.

세 단계는 서로 다른 것을 본다(§0.4 직교 3축).

    Gate   구조 sanity            p99 25μs 이하   — 실패는 차단이 아니라 판정 포기
    Sig    payload·HTTP 의미 검사  p99 100μs 이하  — 결합 정규식 + bounded exact lookup
    Score  flow 위험도 조회        p99 25μs 이하   — snapshot 한 번 읽고 한 번 조회

soft cutoff 5ms를 넘기면 남은 분석을 포기하고 즉시 `ACCEPT`한다. 이 값은 200ms
내부 send hard cutoff, 300ms Broker deadline, 50ms socket fault timeout과 목적이
다른 별개의 값이다(§5.2).
"""

from __future__ import annotations

import time
from dataclasses import dataclass

from .metrics import (
    L_GATE,
    L_POLICY,
    L_SCORE,
    L_SIG,
    M_POLICY_CONFLICT,
    M_POLICY_EXCEPTION,
    M_RULE_CANARY_SKIP,
    M_RULE_SHADOW_HIT,
    M_VERDICT_SOFT_CUTOFF,
    Metrics,
)
from .http_semantics import parse_http_request
from .packet import ParsedPacket, ParseStatus, is_scan_flag_combination
from .protocol import FrameStatus, VERDICT_ACCEPT, VERDICT_DROP
from .rules import CompiledPolicy, EMPTY_POLICY, MatchKind, PromotionState, Rule, canary_selected
from .state import CorrelationSnapshotRef
from .stream import HttpStreamStitcher

# §5.2 — 판정 soft cutoff. PACKET 수신 시각 기준이며 큐 진입 시각 기준이 아니다.
SOFT_CUTOFF_SECONDS = 0.005

STAGE_GATE = "gate"
STAGE_SIG = "sig"
STAGE_SCORE = "score"
STAGE_CUTOFF = "cutoff"
STAGE_ERROR = "error"

# 비민감 reason code. rule 내용이나 payload를 드러내지 않으면서 로그만으로
# 오탐 분석이 가능해야 한다(§15.7).
R_ACCEPT_DEFAULT = "accept-default"
R_FRAME_STATUS = "accept-frame-status"
R_PARSE_STATUS = "accept-parse-status"
R_SOFT_CUTOFF = "accept-soft-cutoff"
R_SHADOW = "accept-shadow-hit"
R_CANARY_SKIP = "accept-canary-not-selected"
R_CONFLICT = "accept-rule-conflict"
R_POLICY_EXCEPTION = "accept-policy-exception"
R_SNAPSHOT_MISSING = "accept-snapshot-missing"


@dataclass(frozen=True, slots=True)
class RuleMatch:
    """어떤 rule이 왜 걸렸는지(§8).

    `confidence`는 숫자가 아니라 승격 상태다. LLM confidence나 합성 점수를
    확신의 근거로 쓰지 않는다는 §6.2를 타입 수준에서 강제하기 위한 선택이다.
    """

    rule_id: str
    category: str
    confidence: PromotionState
    reason_code: str
    stage: str
    evidence: str = ""


@dataclass(frozen=True, slots=True)
class VerdictDecision:
    pkt_id: int
    verdict: int
    rule_id: str
    reason_code: str
    elapsed: float
    stage: str
    match: RuleMatch | None = None
    baseline_match: bool = False

    @property
    def is_drop(self) -> bool:
        return self.verdict == VERDICT_DROP


class HotPolicy:
    """사전 승인 rule과 immutable snapshot의 bounded 조회."""

    def __init__(
        self,
        policy: CompiledPolicy | None = None,
        snapshot_ref: CorrelationSnapshotRef | None = None,
        metrics: Metrics | None = None,
        clock=time.monotonic,
        soft_cutoff: float = SOFT_CUTOFF_SECONDS,
        http_stream: HttpStreamStitcher | None = None,
    ) -> None:
        self._policy = policy or EMPTY_POLICY
        self._snapshot_ref = snapshot_ref
        self._metrics = metrics
        self._clock = clock
        self._soft_cutoff = soft_cutoff
        self._http_stream = http_stream or HttpStreamStitcher()

    @property
    def policy(self) -> CompiledPolicy:
        return self._policy

    def decide(
        self,
        pkt_id: int,
        parsed: ParsedPacket,
        received_at: float,
        frame_status: FrameStatus = FrameStatus.OK,
    ) -> VerdictDecision:
        """어떤 입력에도 verdict를 돌려준다. 예외를 밖으로 내지 않는다."""
        try:
            return self._decide(pkt_id, parsed, received_at, frame_status)
        except Exception:  # noqa: BLE001 - §6.2 policy 예외는 DROP 사유가 아니다
            if self._metrics is not None:
                self._metrics.incr(M_POLICY_EXCEPTION)
            return VerdictDecision(
                pkt_id=pkt_id,
                verdict=VERDICT_ACCEPT,
                rule_id="",
                reason_code=R_POLICY_EXCEPTION,
                elapsed=self._clock() - received_at,
                stage=STAGE_ERROR,
            )

    def _decide(
        self,
        pkt_id: int,
        parsed: ParsedPacket,
        received_at: float,
        frame_status: FrameStatus,
    ) -> VerdictDecision:
        policy_started = self._clock()

        # §11 — 함수 시작에서 정확히 한 번만 읽는다. 처리 도중 global 참조를 다시
        # 읽지 않으므로 한 판정은 언제나 한 세대의 완결된 값만 본다.
        snapshot = self._snapshot_ref.read() if self._snapshot_ref is not None else None

        # ── Gate ────────────────────────────────────────────────────────────
        gate_started = policy_started
        if frame_status is not FrameStatus.OK:
            return self._finish(
                pkt_id, VERDICT_ACCEPT, "", R_FRAME_STATUS, received_at, STAGE_GATE,
                policy_started, gate_started, None,
            )

        if not parsed.ok:
            reason = (
                R_PARSE_STATUS if parsed.status is not ParseStatus.EXCEPTION
                else R_PARSE_STATUS
            )
            return self._finish(
                pkt_id, VERDICT_ACCEPT, "", reason, received_at, STAGE_GATE,
                policy_started, gate_started, None,
            )

        baseline = self._is_baseline(parsed)
        allowed_by = self._allow_match(parsed)
        flag_decision = self._gate_flags(pkt_id, parsed, received_at, allowed_by, baseline)
        gate_elapsed = self._clock() - gate_started
        self._observe(L_GATE, gate_elapsed)
        if flag_decision is not None:
            return self._finalize(flag_decision, policy_started)

        if self._past_cutoff(received_at):
            return self._cutoff(pkt_id, received_at, policy_started, baseline)

        # ── Sig ─────────────────────────────────────────────────────────────
        sig_started = self._clock()
        sig_decision = self._sig(pkt_id, parsed, received_at, allowed_by, baseline)
        self._observe(L_SIG, self._clock() - sig_started)
        if sig_decision is not None:
            return self._finalize(sig_decision, policy_started)

        if self._past_cutoff(received_at):
            return self._cutoff(pkt_id, received_at, policy_started, baseline)

        # ── Score ───────────────────────────────────────────────────────────
        score_started = self._clock()
        score_decision = self._score(pkt_id, parsed, received_at, snapshot, allowed_by, baseline)
        self._observe(L_SCORE, self._clock() - score_started)
        if score_decision is not None:
            return self._finalize(score_decision, policy_started)

        decision = VerdictDecision(
            pkt_id=pkt_id,
            verdict=VERDICT_ACCEPT,
            rule_id="",
            reason_code=R_ACCEPT_DEFAULT,
            elapsed=self._clock() - received_at,
            stage=STAGE_SCORE,
            baseline_match=baseline,
        )
        return self._finalize(decision, policy_started)

    # ── 단계 구현 ───────────────────────────────────────────────────────────

    def _is_baseline(self, parsed: ParsedPacket) -> bool:
        """관측된 정상 profile에 속하는가(§10.3 `baseline_violation_rate`).

        분류일 뿐 허가가 아니다. 이 값은 alert-only monitor의 분모가 되며 verdict를
        바꾸지 않는다. 실제로 차단을 무르는 것은 `allow_profile` rule 쪽이다.
        """
        profile = parsed.profile
        if profile is None or not self._policy.baseline_profiles:
            return False
        return profile.scope_key() in self._policy.baseline_profiles

    def _allow_match(self, parsed: ParsedPacket) -> Rule | None:
        """검증된 정상 traffic allowlist(§10.1 우선순위 2).

        allow rule과 drop rule이 동시에 걸리면 §10.1 우선순위 5에 따라 SLA를
        보존하는 `ACCEPT`와 conflict metric으로 처리한다.
        """
        for rule in self._policy.allow_rules:
            if self._scope_allows(rule, parsed):
                return rule
        return None

    def _scope_allows(self, rule: Rule, parsed: ParsedPacket) -> bool:
        if rule.protocol != parsed.protocol:
            return False
        if rule.ports and parsed.dst_port not in rule.ports:
            return False
        if rule.profile_scope and "*" not in rule.profile_scope:
            profile = parsed.profile
            if profile is None or profile.scope_key() not in rule.profile_scope:
                return False
        return True

    def _gate_flags(
        self,
        pkt_id: int,
        parsed: ParsedPacket,
        received_at: float,
        allowed_by: Rule | None,
        baseline: bool,
    ) -> VerdictDecision | None:
        """§9.2 마지막 행 — 명시적 스캔 플래그 조합만 Gate의 `DROP` 후보다."""
        if not self._policy.flag_rules or parsed.protocol != 6:
            return None
        name = is_scan_flag_combination(parsed.tcp_flags)
        if name is None:
            return None
        for rule in self._policy.flag_rules:
            if rule.tcp_flags_name != name or not self._scope_allows(rule, parsed):
                continue
            return self._enforce(
                pkt_id, rule, parsed, received_at, STAGE_GATE, allowed_by, name, baseline
            )
        return None

    def _sig(
        self,
        pkt_id: int,
        parsed: ParsedPacket,
        received_at: float,
        allowed_by: Rule | None,
        baseline: bool,
    ) -> VerdictDecision | None:
        payload = parsed.payload
        if not payload:
            return None

        deferred_shadow: tuple[Rule, str] | None = None

        stitched = self._http_stream.feed(parsed, self._clock())
        payload_views = [payload]
        if stitched is not None and stitched != payload:
            payload_views.insert(0, stitched)

        # 포트별 matcher와 포트 무관 matcher 최대 두 번. 정규식 수십 개를 패킷마다
        # 순차 실행하지 않는 것이 §5.2 `Sig` 100μs 예산의 전제다(§9.3).
        for candidate in payload_views:
            for matcher in (
                self._policy.payload_matchers.get((parsed.protocol, parsed.dst_port)),
                self._policy.wildcard_matchers.get(parsed.protocol),
            ):
                if matcher is None:
                    continue
                found = matcher.pattern.search(candidate)
                if found is None:
                    continue
                rule = matcher.rules_by_group.get(found.lastgroup or "")
                if rule is None or not self._scope_allows(rule, parsed):
                    continue
                if rule.promotion_state is PromotionState.SHADOW:
                    if deferred_shadow is None:
                        deferred_shadow = (rule, rule.category)
                    continue
                self._http_stream.discard(parsed.flow_key)
                return self._enforce(
                    pkt_id, rule, parsed, received_at, STAGE_SIG,
                    allowed_by, rule.category, baseline,
                )

        if self._policy.http_json_rules or self._policy.http_semantic_rules:
            request = parse_http_request(stitched if stitched is not None else payload)
            if request is not None:
                rules = self._policy.http_json_rules.get(
                    (parsed.protocol, parsed.dst_port, request.method, request.path), ()
                )
                for rule in rules:
                    if not self._scope_allows(rule, parsed):
                        continue
                    if request.cookie_claim_matches(
                        rule.cookie_name, rule.claim_key, rule.claim_values
                    ):
                        if rule.promotion_state is PromotionState.SHADOW:
                            if deferred_shadow is None:
                                deferred_shadow = (rule, rule.category)
                            continue
                        return self._enforce(
                            pkt_id, rule, parsed, received_at, STAGE_SIG,
                            allowed_by, rule.category, baseline,
                        )
                semantic_rules = self._policy.http_semantic_rules.get(
                    (parsed.protocol, parsed.dst_port, request.method, request.path), ()
                )
                for rule in semantic_rules:
                    if not self._scope_allows(rule, parsed):
                        continue
                    matched = False
                    if rule.kind is MatchKind.HTTP_SSRF_TARGET:
                        matched = request.ssrf_target_matches(
                            rule.query_names,
                            rule.target_hosts,
                            rule.target_ports,
                            rule.target_path,
                        )
                    elif rule.kind is MatchKind.HTTP_SQLI_SOURCE:
                        matched = request.sql_source_matches(rule.query_names, rule.sql_source)
                    if matched:
                        if rule.promotion_state is PromotionState.SHADOW:
                            if deferred_shadow is None:
                                deferred_shadow = (rule, rule.category)
                            continue
                        self._http_stream.discard(parsed.flow_key)
                        return self._enforce(
                            pkt_id, rule, parsed, received_at, STAGE_SIG,
                            allowed_by, rule.category, baseline,
                        )
        if deferred_shadow is not None:
            rule, evidence = deferred_shadow
            return self._enforce(
                pkt_id, rule, parsed, received_at, STAGE_SIG,
                allowed_by, evidence, baseline,
            )
        return None

    def _score(
        self,
        pkt_id: int,
        parsed: ParsedPacket,
        received_at: float,
        snapshot,
        allowed_by: Rule | None,
        baseline: bool,
    ) -> VerdictDecision | None:
        """immutable snapshot 단일 조회(§9.4, §11).

        snapshot이 없거나 만료됐거나 key가 없으면 즉시 `ACCEPT`한다. stale
        snapshot의 점수를 이전 값으로 계속 쓰지 않는다.
        """
        if not self._policy.score_rules or snapshot is None or parsed.flow_key is None:
            return None
        entry = snapshot.lookup(parsed.flow_key, self._clock())
        if entry is None:
            return None
        for rule in self._policy.score_rules:
            if entry.score < rule.min_score or not self._scope_allows(rule, parsed):
                continue
            return self._enforce(
                pkt_id, rule, parsed, received_at, STAGE_SCORE, allowed_by,
                f"score={entry.score}", baseline,
            )
        return None

    # ── 집행 ────────────────────────────────────────────────────────────────

    def _enforce(
        self,
        pkt_id: int,
        rule: Rule,
        parsed: ParsedPacket,
        received_at: float,
        stage: str,
        allowed_by: Rule | None,
        evidence: str,
        baseline: bool,
    ) -> VerdictDecision:
        """승격 상태에 따라 집행한다. 런타임은 상태를 바꾸지 않는다(§10.3)."""
        match = RuleMatch(
            rule_id=rule.rule_id,
            category=rule.category,
            confidence=rule.promotion_state,
            reason_code=rule.reason_code,
            stage=stage,
            evidence=evidence,
        )

        if rule.promotion_state is PromotionState.SHADOW:
            self._count(M_RULE_SHADOW_HIT)
            return self._decision(
                pkt_id, VERDICT_ACCEPT, rule.rule_id, R_SHADOW, received_at, stage, match, baseline
            )

        if allowed_by is not None:
            # §10.1 우선순위 5 — conflict 에서는 SLA를 보존한다.
            self._count(M_POLICY_CONFLICT)
            return self._decision(
                pkt_id, VERDICT_ACCEPT, rule.rule_id, R_CONFLICT, received_at, stage, match, baseline
            )

        if rule.promotion_state is PromotionState.CANARY:
            material = parsed.flow_key.digest_material() if parsed.flow_key else b""
            if not canary_selected(rule, material):
                self._count(M_RULE_CANARY_SKIP)
                return self._decision(
                    pkt_id, VERDICT_ACCEPT, rule.rule_id, R_CANARY_SKIP, received_at, stage,
                    match, baseline,
                )

        return self._decision(
            pkt_id, VERDICT_DROP, rule.rule_id, rule.reason_code, received_at, stage, match, baseline
        )

    # ── 보조 ────────────────────────────────────────────────────────────────

    def _past_cutoff(self, received_at: float) -> bool:
        return (self._clock() - received_at) >= self._soft_cutoff

    def _cutoff(
        self, pkt_id: int, received_at: float, policy_started: float, baseline: bool = False
    ) -> VerdictDecision:
        self._count(M_VERDICT_SOFT_CUTOFF)
        decision = VerdictDecision(
            pkt_id=pkt_id,
            verdict=VERDICT_ACCEPT,
            rule_id="",
            reason_code=R_SOFT_CUTOFF,
            elapsed=self._clock() - received_at,
            stage=STAGE_CUTOFF,
            baseline_match=baseline,
        )
        return self._finalize(decision, policy_started)

    def _decision(
        self,
        pkt_id: int,
        verdict: int,
        rule_id: str,
        reason_code: str,
        received_at: float,
        stage: str,
        match: RuleMatch | None,
        baseline: bool = False,
    ) -> VerdictDecision:
        return VerdictDecision(
            pkt_id=pkt_id,
            verdict=verdict,
            rule_id=rule_id,
            reason_code=reason_code,
            elapsed=self._clock() - received_at,
            stage=stage,
            match=match,
            baseline_match=baseline,
        )

    def _finish(
        self,
        pkt_id: int,
        verdict: int,
        rule_id: str,
        reason_code: str,
        received_at: float,
        stage: str,
        policy_started: float,
        gate_started: float,
        match: RuleMatch | None,
    ) -> VerdictDecision:
        self._observe(L_GATE, self._clock() - gate_started)
        decision = self._decision(pkt_id, verdict, rule_id, reason_code, received_at, stage, match)
        return self._finalize(decision, policy_started)

    def _finalize(self, decision: VerdictDecision, policy_started: float) -> VerdictDecision:
        self._observe(L_POLICY, self._clock() - policy_started)
        return decision

    def _observe(self, name: str, seconds: float) -> None:
        if self._metrics is not None:
            self._metrics.observe(name, seconds)

    def _count(self, name: str) -> None:
        if self._metrics is not None:
            self._metrics.incr(name)
