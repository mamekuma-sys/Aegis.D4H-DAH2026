"""동기 판정 정책 테스트.

설계 §6 기본 verdict 정책, §9.2~§9.4, §10.1 rule 우선순위, §15.3.
"""

import unittest

from aegis_defender.metrics import M_POLICY_CONFLICT, M_RULE_CANARY_SKIP, M_RULE_SHADOW_HIT, Metrics
from aegis_defender.packet import ParseStatus, ParsedPacket, parse_ip
from aegis_defender.policy import (
    R_CANARY_SKIP,
    R_CONFLICT,
    R_FRAME_STATUS,
    R_PARSE_STATUS,
    R_SHADOW,
    R_SOFT_CUTOFF,
    HotPolicy,
)
from aegis_defender.protocol import FrameStatus, VERDICT_ACCEPT, VERDICT_DROP
from aegis_defender.rules import compile_bundle
from aegis_defender.state import (
    CorrelationSnapshot,
    CorrelationSnapshotRef,
    FlowScore,
)
from types import MappingProxyType

from .fakes import FakeClock, http_request, ipv4_tcp, minimal_bundle, rule_document

BASELINE = ["6/80"]


def build_policy(rules, baseline=BASELINE, snapshot_ref=None, metrics=None, clock=None):
    compiled, _ = compile_bundle(minimal_bundle(rules=rules, baseline_profiles=baseline))
    return HotPolicy(
        policy=compiled,
        snapshot_ref=snapshot_ref,
        metrics=metrics,
        clock=clock or (lambda: 0.0),
    )


class TestFastAccept(unittest.TestCase):
    """§6.2 — 이 중 어느 것도 DROP 사유가 아니다."""

    def setUp(self):
        self.policy = build_policy([rule_document("r-drop")])

    def test_frame_status_not_ok_accepts(self):
        parsed = parse_ip(ipv4_tcp(http_request("/../../etc/passwd")))
        decision = self.policy.decide(1, parsed, 0.0, FrameStatus.LENGTH_MISMATCH)
        self.assertEqual(decision.verdict, VERDICT_ACCEPT)
        self.assertEqual(decision.reason_code, R_FRAME_STATUS)

    def test_parser_failure_accepts(self):
        decision = self.policy.decide(2, ParsedPacket(ParseStatus.EXCEPTION), 0.0)
        self.assertEqual(decision.verdict, VERDICT_ACCEPT)
        self.assertEqual(decision.reason_code, R_PARSE_STATUS)

    def test_unsupported_protocol_accepts(self):
        decision = self.policy.decide(3, ParsedPacket(ParseStatus.UNSUPPORTED_PROTOCOL), 0.0)
        self.assertEqual(decision.verdict, VERDICT_ACCEPT)

    def test_empty_policy_accepts_everything(self):
        policy = build_policy([])
        parsed = parse_ip(ipv4_tcp(http_request("/../../etc/passwd")))
        self.assertEqual(policy.decide(4, parsed, 0.0).verdict, VERDICT_ACCEPT)

    def test_policy_exception_accepts(self):
        class Exploding:
            @property
            def status(self):
                raise RuntimeError("boom")

        metrics = Metrics()
        policy = build_policy([], metrics=metrics)
        decision = policy.decide(5, Exploding(), 0.0)
        self.assertEqual(decision.verdict, VERDICT_ACCEPT)
        self.assertEqual(metrics.counter("policy.exception"), 1)


class TestSignatureStage(unittest.TestCase):
    def setUp(self):
        self.metrics = Metrics()
        self.attack = parse_ip(ipv4_tcp(http_request("/a/../../etc/passwd")))
        self.normal = parse_ip(ipv4_tcp(http_request("/index.html")))

    def test_active_rule_drops(self):
        policy = build_policy([rule_document("r-active")], metrics=self.metrics)
        decision = policy.decide(1, self.attack, 0.0)
        self.assertEqual(decision.verdict, VERDICT_DROP)
        self.assertEqual(decision.rule_id, "r-active")
        self.assertEqual(decision.stage, "sig")

    def test_normal_traffic_passes_same_rule(self):
        policy = build_policy([rule_document("r-active")])
        self.assertEqual(policy.decide(2, self.normal, 0.0).verdict, VERDICT_ACCEPT)

    def test_shadow_rule_logs_but_accepts(self):
        policy = build_policy(
            [rule_document("r-shadow", promotion_state="SHADOW")], metrics=self.metrics
        )
        decision = policy.decide(3, self.attack, 0.0)
        self.assertEqual(decision.verdict, VERDICT_ACCEPT)
        self.assertEqual(decision.reason_code, R_SHADOW)
        self.assertEqual(decision.rule_id, "r-shadow")
        self.assertEqual(self.metrics.counter(M_RULE_SHADOW_HIT), 1)

    def test_source_ip_alone_does_not_change_verdict(self):
        """§15.3 — NAT source IP만 바뀌어도 verdict가 달라지지 않는다."""
        policy = build_policy([rule_document("r-active")])
        verdicts = set()
        for octet in range(1, 12):
            packet = ipv4_tcp(
                http_request("/a/../../etc/passwd"), src_ip=bytes((10, octet, 0, 4))
            )
            verdicts.add(policy.decide(1, parse_ip(packet), 0.0).verdict)
        self.assertEqual(verdicts, {VERDICT_DROP})

    def test_port_scope_limits_rule(self):
        policy = build_policy([rule_document("r-active", ports=[9999])])
        self.assertEqual(policy.decide(1, self.attack, 0.0).verdict, VERDICT_ACCEPT)

    def test_wildcard_port_rule_applies_to_any_port(self):
        policy = build_policy([rule_document("r-active", ports=[])])
        packet = parse_ip(ipv4_tcp(http_request("/a/../../etc/passwd"), dst_port=31337))
        self.assertEqual(policy.decide(1, packet, 0.0).verdict, VERDICT_DROP)

    def test_combined_matcher_reports_the_matching_rule(self):
        rules = [
            rule_document("r-traversal", pattern="\\.\\./"),
            rule_document("r-sql", pattern="union\\s+select", category="sql-injection"),
        ]
        policy = build_policy(rules)
        sql = parse_ip(ipv4_tcp(http_request("/x?q=union%20select")))
        sql_payload = parse_ip(ipv4_tcp(b"POST /x HTTP/1.1\r\n\r\nq=union select 1"))
        self.assertEqual(policy.decide(1, sql_payload, 0.0).rule_id, "r-sql")
        self.assertEqual(policy.decide(2, self.attack, 0.0).rule_id, "r-traversal")
        del sql


class TestCanary(unittest.TestCase):
    """§6.4, §10.4 — 결정론적 bucket. packet마다 다시 추첨하지 않는다."""

    def setUp(self):
        self.rule = rule_document(
            "r-canary", promotion_state="CANARY", canary_fraction=0.5, canary_seed="seed-2026"
        )
        self.policy = build_policy([self.rule], metrics=Metrics())

    def test_same_flow_always_gets_the_same_verdict(self):
        parsed = parse_ip(ipv4_tcp(http_request("/a/../../etc/passwd")))
        verdicts = {self.policy.decide(index, parsed, 0.0).verdict for index in range(50)}
        self.assertEqual(len(verdicts), 1)

    def test_bucket_is_stable_across_policy_instances(self):
        # 프로세스를 재시작해도 같은 bucket 이어야 한다. Python 의 process-randomized
        # hash() 를 쓰지 않고 blake2s 를 쓰는 이유다.
        parsed = parse_ip(ipv4_tcp(http_request("/a/../../etc/passwd")))
        first = build_policy([self.rule]).decide(1, parsed, 0.0).verdict
        second = build_policy([self.rule]).decide(1, parsed, 0.0).verdict
        self.assertEqual(first, second)

    def test_fraction_splits_flows(self):
        drops = 0
        total = 0
        for port in range(1024, 1224):
            parsed = parse_ip(
                ipv4_tcp(http_request("/a/../../etc/passwd"), src_port=port)
            )
            total += 1
            if self.policy.decide(1, parsed, 0.0).verdict == VERDICT_DROP:
                drops += 1
        # 0.5 근처. 정확한 비율이 아니라 "둘 다 발생한다"가 검증 대상이다.
        self.assertGreater(drops, 0)
        self.assertLess(drops, total)

    def test_unselected_flow_records_skip_reason(self):
        # bucket 밖의 flow 는 ACCEPT 되고 그 사실이 reason code 로 남는다. 그래야
        # "왜 이 패킷만 통과했는가"가 로그만으로 설명된다.
        metrics = Metrics()
        policy = build_policy([self.rule], metrics=metrics)
        for port in range(1024, 1124):
            parsed = parse_ip(ipv4_tcp(http_request("/a/../../etc/passwd"), src_port=port))
            decision = policy.decide(1, parsed, 0.0)
            if decision.verdict == VERDICT_ACCEPT:
                self.assertEqual(decision.reason_code, R_CANARY_SKIP)
                self.assertEqual(decision.rule_id, "r-canary")
                break
        else:
            self.fail("bucket 밖 flow 가 하나도 없었다")
        self.assertGreater(metrics.counter(M_RULE_CANARY_SKIP), 0)


class TestRuleConflict(unittest.TestCase):
    """§10.1 우선순위 5 — conflict에서는 SLA를 보존한다."""

    def test_allow_rule_overrides_drop_rule(self):
        metrics = Metrics()
        rules = [
            rule_document("r-drop"),
            rule_document("r-allow", kind="allow_profile", pattern=None, ports=[80]),
        ]
        rules[1].pop("pattern")
        policy = build_policy(rules, metrics=metrics)
        parsed = parse_ip(ipv4_tcp(http_request("/a/../../etc/passwd")))
        decision = policy.decide(1, parsed, 0.0)
        self.assertEqual(decision.verdict, VERDICT_ACCEPT)
        self.assertEqual(decision.reason_code, R_CONFLICT)
        self.assertEqual(metrics.counter(M_POLICY_CONFLICT), 1)


class TestSoftCutoff(unittest.TestCase):
    """§5.2 — 5ms soft cutoff는 PACKET 수신 시각 기준이다."""

    def test_cutoff_accepts_without_running_signatures(self):
        clock = FakeClock()
        policy = build_policy([rule_document("r-active")], clock=clock)
        parsed = parse_ip(ipv4_tcp(http_request("/a/../../etc/passwd")))
        received_at = clock.now
        clock.advance(0.006)  # 판정 시작 전에 이미 5ms 초과
        decision = policy.decide(1, parsed, received_at)
        self.assertEqual(decision.verdict, VERDICT_ACCEPT)
        self.assertEqual(decision.reason_code, R_SOFT_CUTOFF)
        self.assertEqual(decision.stage, "cutoff")

    def test_elapsed_is_measured_from_packet_receipt(self):
        clock = FakeClock()
        policy = build_policy([], clock=clock)
        received_at = clock.now
        clock.advance(0.002)
        decision = policy.decide(1, parse_ip(ipv4_tcp()), received_at)
        self.assertAlmostEqual(decision.elapsed, 0.002, places=6)


class TestScoreStage(unittest.TestCase):
    """§9.4, §11 — snapshot 단일 조회. missing·stale·miss는 즉시 ACCEPT."""

    def setUp(self):
        self.clock = FakeClock()
        self.ref = CorrelationSnapshotRef()
        self.rule = rule_document(
            "r-score", kind="flow_score", min_score=50, ports=[], pattern=None
        )
        self.rule.pop("pattern")
        self.rule["min_score"] = 50
        self.parsed = parse_ip(ipv4_tcp(http_request("/normal")))
        self.policy = build_policy(
            [self.rule], snapshot_ref=self.ref, clock=self.clock
        )

    def _publish(self, score, expires_at):
        entry = FlowScore(
            score=score, sig_hits=1, distinct_paths=1, scan_flag_hits=0,
            matched_stages=(), updated_at=self.clock.now,
        )
        self.ref.publish(CorrelationSnapshot(
            generation=1,
            published_at=self.clock.now,
            expires_at=expires_at,
            entries=MappingProxyType({self.parsed.flow_key: entry}),
        ))

    def test_missing_snapshot_accepts(self):
        self.assertEqual(self.policy.decide(1, self.parsed, 0.0).verdict, VERDICT_ACCEPT)

    def test_score_above_threshold_drops(self):
        self._publish(80, expires_at=self.clock.now + 5.0)
        self.assertEqual(self.policy.decide(1, self.parsed, 0.0).verdict, VERDICT_DROP)

    def test_score_below_threshold_accepts(self):
        self._publish(10, expires_at=self.clock.now + 5.0)
        self.assertEqual(self.policy.decide(1, self.parsed, 0.0).verdict, VERDICT_ACCEPT)

    def test_stale_snapshot_accepts(self):
        self._publish(99, expires_at=self.clock.now + 1.0)
        self.clock.advance(2.0)
        decision = self.policy.decide(1, self.parsed, self.clock.now)
        self.assertEqual(decision.verdict, VERDICT_ACCEPT)

    def test_key_miss_accepts(self):
        self._publish(99, expires_at=self.clock.now + 5.0)
        other = parse_ip(ipv4_tcp(http_request("/normal"), src_port=40000))
        self.assertEqual(self.policy.decide(1, other, 0.0).verdict, VERDICT_ACCEPT)

    def test_snapshot_read_takes_no_lock(self):
        # 참조 하나를 읽을 뿐이므로 lock 객체 자체가 없다(§11).
        self.assertFalse(hasattr(self.ref, "_lock"))
        self.assertEqual(CorrelationSnapshotRef.__slots__, ("_snapshot",))


class TestGateFlags(unittest.TestCase):
    """§9.2 — Gate에서 DROP 가능한 유일한 범주."""

    def _flag_rule(self, name, state="ACTIVE"):
        rule = rule_document(
            f"gate-{name}", kind="tcp_flags", promotion_state=state, ports=[]
        )
        rule.pop("pattern")
        rule["tcp_flags_name"] = name
        return rule

    def test_active_scan_rule_drops(self):
        policy = build_policy([self._flag_rule("tcp-null")])
        parsed = parse_ip(ipv4_tcp(flags=0x00))
        decision = policy.decide(1, parsed, 0.0)
        self.assertEqual(decision.verdict, VERDICT_DROP)
        self.assertEqual(decision.stage, "gate")

    def test_shadow_scan_rule_accepts(self):
        policy = build_policy([self._flag_rule("tcp-xmas", state="SHADOW")])
        parsed = parse_ip(ipv4_tcp(flags=0x29))
        self.assertEqual(policy.decide(1, parsed, 0.0).verdict, VERDICT_ACCEPT)

    def test_normal_flags_unaffected(self):
        policy = build_policy([self._flag_rule("tcp-null")])
        parsed = parse_ip(ipv4_tcp(http_request(), flags=0x18))
        self.assertEqual(policy.decide(1, parsed, 0.0).verdict, VERDICT_ACCEPT)


class TestBaselineClassification(unittest.TestCase):
    def test_baseline_match_is_classification_not_permission(self):
        policy = build_policy([rule_document("r-active")], baseline=["6/80"])
        parsed = parse_ip(ipv4_tcp(http_request("/a/../../etc/passwd")))
        decision = policy.decide(1, parsed, 0.0)
        self.assertTrue(decision.baseline_match)
        self.assertEqual(decision.verdict, VERDICT_DROP)


if __name__ == "__main__":
    unittest.main()
