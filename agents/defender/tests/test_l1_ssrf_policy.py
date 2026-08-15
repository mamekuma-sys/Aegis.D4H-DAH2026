"""실측 L1 SSRF hotfix의 shipped PolicyBundle 회귀 테스트."""

import os
import unittest

from aegis_defender.packet import parse_ip
from aegis_defender.policy import HotPolicy
from aegis_defender.protocol import VERDICT_ACCEPT, VERDICT_DROP
from aegis_defender.rules import PromotionState, load_policy

from .fakes import ipv4_tcp

_POLICY_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "policy"))
_ACTIVE_WINDOW_EPOCH = 1786764000.0
_RULE_ID = "sig-l1-helper-secret-001"
_REASON = "sig-l1-helper-secret"

_POSITIVE_PATHS = (
    "/fetch?url=http://helper-box:8080/secret",
    "/fetch?url=http%3A%2F%2Fhelper-box%3A8080%2Fsecret",
    "/%66%65%74%63%68?%75%72%6C=%68%74%74%70%3A%2F%2F%68%65%6C%70%65%72%2D%62%6F%78%3A%38%30%38%30%2F%73%65%63%72%65%74",
)

_NEGATIVE_PATHS = (
    "/",
    "/fetch",
    "/fetch?url=http://127.0.0.1:5000/registry",
    "/fetch?url=http://127.0.0.1:5000/health",
    "/fetch?url=http://example.invalid/",
)


class TestShippedL1SsrfPolicy(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        compiled, report = load_policy(_POLICY_DIR, now_epoch=_ACTIVE_WINDOW_EPOCH)
        cls.compiled = compiled
        cls.report = report
        cls.policy = HotPolicy(policy=compiled, clock=lambda: 0.0)

    def _decide(self, path, dst_port=8082, pkt_id=1):
        payload = (
            f"GET {path} HTTP/1.1\r\n"
            "Host: team1.lig.internal:8082\r\n"
            "User-Agent: fixture\r\n\r\n"
        ).encode("ascii")
        parsed = parse_ip(ipv4_tcp(payload, dst_port=dst_port))
        return self.policy.decide(pkt_id, parsed, 0.0)

    def test_observed_plain_and_encoded_variants_drop(self):
        for index, path in enumerate(_POSITIVE_PATHS, start=1):
            with self.subTest(path=path):
                decision = self._decide(path, pkt_id=index)
                self.assertEqual(decision.verdict, VERDICT_DROP)
                self.assertEqual(decision.rule_id, _RULE_ID)
                self.assertEqual(decision.reason_code, _REASON)

    def test_round1_negative_and_sla_requests_accept_100_times(self):
        for index in range(100):
            path = _NEGATIVE_PATHS[index % len(_NEGATIVE_PATHS)]
            with self.subTest(index=index, path=path):
                self.assertEqual(self._decide(path, pkt_id=index).verdict, VERDICT_ACCEPT)

    def test_same_payload_on_non_l1_port_accepts(self):
        for index, path in enumerate(_POSITIVE_PATHS, start=1):
            with self.subTest(path=path):
                self.assertEqual(
                    self._decide(path, dst_port=8083, pkt_id=index).verdict,
                    VERDICT_ACCEPT,
                )

    def test_shipped_bundle_activates_only_the_l1_hotfix(self):
        self.assertEqual(self.report.source, "active")
        self.assertEqual(self.report.bundle_id, "defender-2026-08-15-l1-ssrf-hotfix")
        self.assertEqual(self.report.drop_capable_rules, 1)
        self.assertEqual(self.report.demotions, ())
        self.assertEqual(self.compiled.baseline_profiles, frozenset({"6/8082"}))
        self.assertIs(
            self.compiled.rules_by_id[_RULE_ID].promotion_state,
            PromotionState.ACTIVE,
        )
        for rule_id, rule in self.compiled.rules_by_id.items():
            if rule_id != _RULE_ID:
                self.assertIs(rule.promotion_state, PromotionState.SHADOW)


if __name__ == "__main__":
    unittest.main()
