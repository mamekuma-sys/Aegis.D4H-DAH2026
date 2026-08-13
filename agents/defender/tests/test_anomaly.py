"""alert-only anomaly monitor 테스트.

설계 §10.3 ③, §15.6 packet-derived anomaly 조작 저항 검증 — **가장 중요한 회귀
테스트다.**

공격자는 활성 signature를 반복 자극하고, 정상 형태를 replay하고, malformed 입력을
쏟아 이 지표들을 전부 임계 위로 올릴 수 있다. 그때 런타임이 rule을 자동으로
되돌리거나 전체 관찰 모드로 전환한다면, 공격자는 패킷만 보내서 우리 방어를 끄게
만들 수 있다. 그래서 여기서 검증하는 것은 "경보가 잘 뜬다"가 아니라 **"경보가
떠도 아무것도 바뀌지 않는다"**이다.
"""

import unittest

from aegis_defender.anomaly import (
    METRIC_BASELINE_VIOLATION_RATE,
    METRIC_PARSER_FAILURE_RATE,
    METRIC_PROMOTION_COHORT_CONFLICT,
    METRIC_RAW_DROP_RATE,
    METRIC_RULE_CONCENTRATION,
    AnomalyMonitor,
)
from aegis_defender.metrics import Metrics
from aegis_defender.packet import parse_ip
from aegis_defender.policy import HotPolicy
from aegis_defender.protocol import VERDICT_DROP
from aegis_defender.rules import AlertProfile, PromotionState, compile_bundle

from .fakes import FakeClock, http_request, ipv4_tcp, minimal_bundle, rule_document

BASELINE = ["6/80"]


def profile(**overrides) -> AlertProfile:
    fields = {
        "profile_id": "round-default",
        "minimum_samples": 10,
        "sustain_window_seconds": 0.0,
        "alert_thresholds": {
            METRIC_RAW_DROP_RATE: 0.05,
            METRIC_BASELINE_VIOLATION_RATE: 0.01,
            METRIC_PARSER_FAILURE_RATE: 0.2,
            METRIC_RULE_CONCENTRATION: 0.8,
            METRIC_PROMOTION_COHORT_CONFLICT: 0.01,
        },
        "reviewer_runbook": "Break 에서만 조치",
    }
    fields.update(overrides)
    return AlertProfile(**fields)


class TestMetricComputation(unittest.TestCase):
    def test_empty_monitor_reports_zeros(self):
        values = AnomalyMonitor().values()
        for metric in values.values():
            self.assertEqual(metric, 0.0)

    def test_raw_drop_rate(self):
        monitor = AnomalyMonitor()
        for index in range(10):
            monitor.record(dropped=index < 3)
        self.assertAlmostEqual(monitor.values()[METRIC_RAW_DROP_RATE], 0.3)

    def test_baseline_violation_rate_uses_baseline_denominator(self):
        monitor = AnomalyMonitor()
        for index in range(20):
            baseline = index < 10
            monitor.record(dropped=index < 2, baseline_match=baseline)
        self.assertAlmostEqual(monitor.values()[METRIC_BASELINE_VIOLATION_RATE], 0.2)

    def test_parser_failure_rate(self):
        monitor = AnomalyMonitor()
        for index in range(10):
            monitor.record(parser_failed=index < 4)
        self.assertAlmostEqual(monitor.values()[METRIC_PARSER_FAILURE_RATE], 0.4)

    def test_rule_concentration(self):
        monitor = AnomalyMonitor()
        for _ in range(9):
            monitor.record(dropped=True, rule_id="r-hot")
        monitor.record(dropped=True, rule_id="r-cold")
        self.assertAlmostEqual(monitor.values()[METRIC_RULE_CONCENTRATION], 0.9)

    def test_tracked_rule_ids_are_bounded(self):
        monitor = AnomalyMonitor()
        for index in range(500):
            monitor.record(dropped=True, rule_id=f"r{index}")
        self.assertLessEqual(len(monitor._rule_drops), 128)


class TestAlerting(unittest.TestCase):
    def test_minimum_samples_gate(self):
        monitor = AnomalyMonitor({"p": profile(minimum_samples=100)}, clock=FakeClock())
        for _ in range(20):
            monitor.record(dropped=True)
        self.assertEqual(monitor.evaluate(), ())

    def test_sustain_window_gate(self):
        clock = FakeClock()
        monitor = AnomalyMonitor({"p": profile(sustain_window_seconds=30.0)}, clock=clock)
        for _ in range(20):
            monitor.record(dropped=True)
        self.assertEqual(monitor.evaluate(clock.now), ())
        clock.advance(29.0)
        self.assertEqual(monitor.evaluate(clock.now), ())
        clock.advance(2.0)
        self.assertTrue(monitor.evaluate(clock.now))

    def test_transient_spike_resets_the_sustain_timer(self):
        clock = FakeClock()
        monitor = AnomalyMonitor({"p": profile(sustain_window_seconds=10.0)}, clock=clock)
        for _ in range(20):
            monitor.record(dropped=True)
        monitor.evaluate(clock.now)
        clock.advance(5.0)
        for _ in range(2000):
            monitor.record(dropped=False)  # 비율이 임계 아래로 내려간다
        self.assertEqual(monitor.evaluate(clock.now), ())
        clock.advance(20.0)
        self.assertEqual(monitor.evaluate(clock.now), ())

    def test_alert_carries_the_reviewer_runbook(self):
        monitor = AnomalyMonitor({"p": profile()}, clock=FakeClock())
        for _ in range(20):
            monitor.record(dropped=True, rule_id="r1")
        alerts = monitor.evaluate()
        self.assertTrue(alerts)
        self.assertTrue(all(alert.runbook for alert in alerts))
        self.assertTrue(all(alert.samples == 20 for alert in alerts))

    def test_alert_is_logged_as_no_policy_change(self):
        logged = []

        class Recorder:
            def log(self, event, **fields):
                logged.append((event, fields))

        metrics = Metrics()
        monitor = AnomalyMonitor(
            {"p": profile()}, metrics=metrics, audit=Recorder(), clock=FakeClock()
        )
        for _ in range(20):
            monitor.record(dropped=True, rule_id="r1")
        monitor.evaluate()
        self.assertTrue(logged)
        for event, fields in logged:
            self.assertEqual(event, "anomaly-alert")
            self.assertEqual(fields["action"], "alert-only-no-policy-change")
        self.assertGreater(metrics.counter("anomaly.alert"), 0)


class TestPoisonedTrafficChangesNothing(unittest.TestCase):
    """§15.6 — 지표를 전부 임계 위로 올려도 런타임 상태가 바뀌지 않는다."""

    def setUp(self):
        self.clock = FakeClock()
        rules = [
            rule_document("r-active"),
            rule_document(
                "r-canary", pattern="union\\s+select", category="sql-injection",
                promotion_state="CANARY", canary_fraction=0.3, canary_seed="seed",
            ),
            rule_document("r-shadow", pattern="<%=", category="template-injection",
                          promotion_state="SHADOW"),
        ]
        self.compiled, _ = compile_bundle(
            minimal_bundle(rules=rules, baseline_profiles=BASELINE)
        )
        self.policy = HotPolicy(policy=self.compiled, clock=self.clock)
        self.monitor = AnomalyMonitor({"p": profile()}, clock=self.clock)
        self.probe = parse_ip(ipv4_tcp(http_request("/a/../../etc/passwd")))

    def _snapshot_policy_state(self):
        return {
            rule_id: (
                rule.promotion_state,
                rule.canary_fraction,
                rule.canary_seed,
                rule.ports,
                rule.profile_scope,
                rule.min_score,
            )
            for rule_id, rule in self.compiled.rules_by_id.items()
        }

    def test_all_metrics_raised_but_nothing_changes(self):
        before_state = self._snapshot_policy_state()
        before_verdict = self.policy.decide(1, self.probe, 0.0).verdict
        self.assertEqual(before_verdict, VERDICT_DROP)

        # 공격 signature 에 일치하면서 정상 profile 형태를 흉내 내는 트래픽을 고율 주입
        attack = parse_ip(ipv4_tcp(http_request("/a/../../etc/passwd")))
        malformed = parse_ip(b"\x45\x00\x00")
        for index in range(2000):
            self.clock.advance(0.001)
            if index % 3 == 0:
                decision = self.policy.decide(index, malformed, self.clock.now)
                self.monitor.record(parser_failed=True, dropped=decision.is_drop)
            else:
                decision = self.policy.decide(index, attack, self.clock.now)
                self.monitor.record(
                    dropped=decision.is_drop,
                    baseline_match=decision.baseline_match,
                    rule_id=decision.rule_id,
                    cohort_conflict=True,
                )

        values = self.monitor.values()
        alerts = self.monitor.evaluate(self.clock.now)

        # 지표는 실제로 임계를 넘었다.
        self.assertGreater(values[METRIC_RAW_DROP_RATE], 0.05)
        self.assertGreater(values[METRIC_BASELINE_VIOLATION_RATE], 0.01)
        self.assertGreater(values[METRIC_PARSER_FAILURE_RATE], 0.2)
        self.assertGreater(values[METRIC_RULE_CONCENTRATION], 0.8)
        self.assertGreater(values[METRIC_PROMOTION_COHORT_CONFLICT], 0.01)
        self.assertTrue(alerts, "경보는 발생해야 한다")

        # 그러나 policy state 도 verdict 도 그대로다.
        self.assertEqual(self._snapshot_policy_state(), before_state)
        after_verdict = self.policy.decide(1, self.probe, self.clock.now).verdict
        self.assertEqual(after_verdict, before_verdict)
        self.assertEqual(self.compiled.bundle_id, "test-bundle")
        self.assertIs(self.policy.policy, self.compiled)

    def test_monitor_holds_no_reference_to_policy(self):
        """바꿀 대상을 손에 쥐고 있지 않으면 실수로도 바꿀 수 없다."""
        for value in vars(self.monitor).values():
            self.assertNotIsInstance(value, type(self.compiled))
            self.assertNotIsInstance(value, HotPolicy)

    def test_monitor_exposes_no_rollback_api(self):
        forbidden = (
            "rollback", "promote", "demote", "disable", "enable",
            "set_promotion_state", "apply", "observe_only_mode",
        )
        for name in forbidden:
            self.assertFalse(
                hasattr(AnomalyMonitor, name), f"AnomalyMonitor 에 {name} 이 있어서는 안 된다"
            )

    def test_shadow_rule_stays_shadow_under_pressure(self):
        for _ in range(5000):
            self.monitor.record(dropped=True, rule_id="r-shadow", baseline_match=True)
        self.monitor.evaluate(self.clock.now)
        self.assertIs(
            self.compiled.rules_by_id["r-shadow"].promotion_state, PromotionState.SHADOW
        )
        self.assertIs(
            self.compiled.rules_by_id["r-active"].promotion_state, PromotionState.ACTIVE
        )


if __name__ == "__main__":
    unittest.main()
