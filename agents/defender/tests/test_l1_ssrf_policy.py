"""TEAM1 실측 L1~L3 공격에 대한 shipped PolicyBundle 회귀 테스트."""

import base64
import json
import os
import unittest

from aegis_defender.packet import parse_ip
from aegis_defender.policy import HotPolicy
from aegis_defender.protocol import VERDICT_ACCEPT, VERDICT_DROP
from aegis_defender.rules import PromotionState, load_policy

from .fakes import ipv4_tcp

_POLICY_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "policy"))
_ACTIVE_WINDOW_EPOCH = 1786764000.0
_L1_RULE_ID = "sig-l1-helper-secret-001"
_L2_ADMIN_RULE_ID = "http-l2-forged-admin-session-001"
_L2_SSRF_RULE_ID = "sig-l2-loopback-secret-001"
_L3_RULE_ID = "sig-l3-app-meta-union-001"
_L1_CANONICAL_RULE_ID = "http-l1-helper-secret-canonical-001"
_L2_CANONICAL_RULE_ID = "http-l2-loopback-secret-canonical-001"
_L3_CANONICAL_RULE_ID = "http-l3-app-meta-canonical-001"
_ACTIVE_RULES = {
    _L1_RULE_ID, _L2_ADMIN_RULE_ID, _L2_SSRF_RULE_ID, _L3_RULE_ID,
    _L1_CANONICAL_RULE_ID, _L2_CANONICAL_RULE_ID, _L3_CANONICAL_RULE_ID,
}

_POSITIVE_PATHS = (
    "/fetch?url=http://helper-box:8080/secret",
    "/fetch?url=http%3A%2F%2Fhelper-box%3A8080%2Fsecret",
    "/fetch?url=http%3A%2F%2Fhelper-box.%3A8080%2Fsecret",
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

    def _decide(self, path, dst_port=8082, pkt_id=1, headers=""):
        payload = (
            f"GET {path} HTTP/1.1\r\n"
            "Host: team1.lig.internal:8082\r\n"
            f"User-Agent: fixture\r\n{headers}\r\n"
        ).encode("ascii")
        parsed = parse_ip(ipv4_tcp(payload, dst_port=dst_port))
        return self.policy.decide(pkt_id, parsed, 0.0)

    def test_observed_plain_and_encoded_variants_drop(self):
        for index, path in enumerate(_POSITIVE_PATHS, start=1):
            with self.subTest(path=path):
                decision = self._decide(path, pkt_id=index)
                self.assertEqual(decision.verdict, VERDICT_DROP)
                self.assertEqual(decision.rule_id, _L1_RULE_ID)
                self.assertEqual(decision.reason_code, "sig-l1-helper-secret")

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

    def test_l2_observed_admin_cookie_variants_drop(self):
        documents = (
            {"user": "guest", "role": "admin"},
            {"role": "admin", "user": "operator"},
            {"authenticated": True, "role": "admin", "user": "guest"},
            {"admin": True, "is_admin": True, "role": "admin", "user": "admin"},
        )
        for index, document in enumerate(documents, start=1):
            encoded = base64.urlsafe_b64encode(
                json.dumps(document, separators=(",", ":")).encode("utf-8")
            ).decode("ascii").rstrip("=")
            for path in ("/admin", "/%61%64%6D%69%6E"):
                with self.subTest(document=document, path=path):
                    decision = self._decide(
                        path, dst_port=8083, pkt_id=index,
                        headers=f"Cookie: session = {encoded}\r\n",
                    )
                    self.assertEqual(decision.verdict, VERDICT_DROP)
                    self.assertEqual(decision.rule_id, _L2_ADMIN_RULE_ID)

    def test_l2_empty_query_admin_cookie_drops(self):
        encoded = base64.urlsafe_b64encode(b'{"user":"admin","role":"admin"}').decode("ascii")
        decision = self._decide(
            "/admin?", dst_port=8083,
            headers=f"Cookie: session={encoded}\r\n",
        )
        self.assertEqual(decision.verdict, VERDICT_DROP)
        self.assertEqual(decision.rule_id, _L2_ADMIN_RULE_ID)

    def test_l2_guest_malformed_and_cookie_free_admin_requests_accept(self):
        guest = base64.b64encode(b'{"user":"guest","role":"user"}').decode("ascii")
        cases = ("", f"Cookie: session={guest}\r\n", "Cookie: session=not-base64!\r\n")
        for index, headers in enumerate(cases):
            with self.subTest(headers=bool(headers)):
                self.assertEqual(
                    self._decide("/admin", dst_port=8083, pkt_id=index, headers=headers).verdict,
                    VERDICT_ACCEPT,
                )

    def test_l2_observed_absolute_form_loopback_secret_drops(self):
        path = "http://team1.lig.internal:8083/fetch?url=http%3A%2F%2F127.0.0.1%3A8083%2Fsecret"
        decision = self._decide(path, dst_port=8083)
        self.assertEqual(decision.verdict, VERDICT_DROP)
        self.assertEqual(decision.rule_id, _L2_SSRF_RULE_ID)

    def test_l3_observed_app_meta_union_variants_drop(self):
        paths = (
            "/product?id=-1%20UNION%20SELECT%201,k,v%20FROM%20app_meta--%20",
            "/product?id=-1+UNION+ALL+SELECT+1%2Cv%2C3+FROM+app_meta+WHERE+k%3D%27deploy_token%27",
            "/product?id=0%20UNION%20SELECT%201,group_concat(k%7C%7Cv),3%20FROM%20app_meta",
        )
        for index, path in enumerate(paths):
            with self.subTest(path=path):
                decision = self._decide(path, dst_port=8084, pkt_id=index)
                self.assertEqual(decision.verdict, VERDICT_DROP)
                self.assertEqual(decision.rule_id, _L3_RULE_ID)

    def test_r17_canonical_bypasses_drop(self):
        cases = (
            (8082, "/%66%65%74%63%68?%75%72%6C=%68%74%74%70%3A%2F%2F%68%65%6C%70%65%72%2D%62%6F%78%2E%3A%38%30%38%30%2F%73%65%63%72%65%74", _L1_CANONICAL_RULE_ID),
            (8082, "/fetch?url=http%3A%2F%2F127.0.0.1%3A8082%2Ffetch%3Furl%3Dhttp%253A%252F%252Fhelper-box%253A8080%252Fsecret", _L1_CANONICAL_RULE_ID),
            (8082, "/fetch?url=http%3A%2F%2Fhelper-box%3A08080%2Fsecret", _L1_CANONICAL_RULE_ID),
            (8084, "/product?id=-1%20UNION%0A%0ASELECT%20k%2Cv%2C3%20FROM%20app_meta", _L3_CANONICAL_RULE_ID),
            (8084, "/product?id=0%2F%2Ax%2A%2FUNION%2F%2Ax%2A%2FSELECT%2F%2Ax%2A%2F1%2Cv%2C3%2F%2Ax%2A%2FFROM%2F%2Ax%2A%2F%5Bapp_meta%5D", _L3_CANONICAL_RULE_ID),
        )
        for index, (port, path, rule_id) in enumerate(cases):
            with self.subTest(path=path):
                decision = self._decide(path, dst_port=port, pkt_id=500 + index)
                self.assertEqual(decision.verdict, VERDICT_DROP)
                self.assertEqual(decision.rule_id, rule_id)

    def test_cross_layer_and_normal_product_requests_accept(self):
        attack = "/product?id=-1%20UNION%20SELECT%201,k,v%20FROM%20app_meta"
        self.assertEqual(self._decide(attack, dst_port=8083).verdict, VERDICT_ACCEPT)
        for path in ("/product?id=1", "/product?name=app_meta", "/health"):
            self.assertEqual(self._decide(path, dst_port=8084).verdict, VERDICT_ACCEPT)

    def test_shipped_bundle_activates_only_observed_exact_rules(self):
        self.assertEqual(self.report.source, "active")
        self.assertEqual(self.report.bundle_id, "defender-2026-08-15-finals-validity")
        self.assertEqual(self.report.drop_capable_rules, 7)
        self.assertEqual(self.report.demotions, ())
        self.assertEqual(
            self.compiled.baseline_profiles, frozenset({"6/8082", "6/8083", "6/8084"})
        )
        for rule_id, rule in self.compiled.rules_by_id.items():
            expected = PromotionState.ACTIVE if rule_id in _ACTIVE_RULES else PromotionState.SHADOW
            self.assertIs(rule.promotion_state, expected)


if __name__ == "__main__":
    unittest.main()
