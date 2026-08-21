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
_L1_CONFIG_RULE_ID = "sig-l1-config-flag-traversal-001"
_L2_REGISTRY_RULE_ID = "http-l2-loopback-registry-canonical-001"
_L1_SATDIAG_TAIL_RULE_ID = "sig-l1-satdiag-tail-flag-001"
_L1_SATDIAG_EXPORT_RULE_ID = "sig-l1-satdiag-export-flag-echo-001"
_L2_GRAPHQL_RULE_ID = "sig-l2-graphql-mission-audit-001"
_L1_SVC_FLAG_RULE_ID = "sig-l1-svc-flag-gateway-001"
_L1_PORTAL_FEEDBACK_RULE_ID = "sig-l1-portal-feedback-001"
_ACTIVE_RULES = {
    _L1_RULE_ID, _L2_ADMIN_RULE_ID, _L2_SSRF_RULE_ID, _L3_RULE_ID,
    _L1_CANONICAL_RULE_ID, _L2_CANONICAL_RULE_ID, _L3_CANONICAL_RULE_ID,
    _L1_CONFIG_RULE_ID, _L2_REGISTRY_RULE_ID,
    _L1_SATDIAG_TAIL_RULE_ID, _L1_SATDIAG_EXPORT_RULE_ID,
    _L2_GRAPHQL_RULE_ID, _L1_SVC_FLAG_RULE_ID, _L1_PORTAL_FEEDBACK_RULE_ID,
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
            f"Host: team1.lig.internal:{dst_port}\r\n"
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

    def test_finals_p1_8080_observed_l1_attacks_drop(self):
        cases = (
            ("/fetch?url=http://helper-box:8080/secret", _L1_RULE_ID),
            (
                "/fetch?url=http%3A%2F%2F172.18.0.2%3A8080%2Fsecret",
                _L1_CANONICAL_RULE_ID,
            ),
            ("/config?file=../../../../flag", _L1_CONFIG_RULE_ID),
        )
        for index, (path, rule_id) in enumerate(cases, start=1):
            with self.subTest(path=path):
                decision = self._decide(path, dst_port=8080, pkt_id=50 + index)
                self.assertEqual(decision.verdict, VERDICT_DROP)
                self.assertEqual(decision.rule_id, rule_id)

    def test_finals_p1_8080_normal_requests_accept_100_times(self):
        paths = (
            "/",
            "/health",
            "/config?file=config.json",
            "/config?file=../settings.json",
            "/fetch?url=http%3A%2F%2F172.18.0.2%3A8080%2Fhealth",
        )
        for index in range(100):
            with self.subTest(index=index):
                self.assertEqual(
                    self._decide(
                        paths[index % len(paths)], dst_port=8080, pkt_id=150 + index
                    ).verdict,
                    VERDICT_ACCEPT,
                )

    def test_round1_negative_and_sla_requests_accept_100_times(self):
        for index in range(100):
            path = _NEGATIVE_PATHS[index % len(_NEGATIVE_PATHS)]
            with self.subTest(index=index, path=path):
                self.assertEqual(self._decide(path, pkt_id=index).verdict, VERDICT_ACCEPT)

    def test_same_payload_on_non_l1_port_accepts(self):
        for index, path in enumerate(_POSITIVE_PATHS, start=1):
            with self.subTest(path=path):
                self.assertEqual(
                    self._decide(path, dst_port=9090, pkt_id=index).verdict,
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
                        path, dst_port=8082, pkt_id=index,
                        headers=f"Cookie: session = {encoded}\r\n",
                    )
                    self.assertEqual(decision.verdict, VERDICT_DROP)
                    self.assertEqual(decision.rule_id, _L2_ADMIN_RULE_ID)

    def test_l2_empty_query_admin_cookie_drops(self):
        encoded = base64.urlsafe_b64encode(b'{"user":"admin","role":"admin"}').decode("ascii")
        decision = self._decide(
            "/admin?", dst_port=8082,
            headers=f"Cookie: session={encoded}\r\n",
        )
        self.assertEqual(decision.verdict, VERDICT_DROP)
        self.assertEqual(decision.rule_id, _L2_ADMIN_RULE_ID)

    def test_l2_observed_lenient_base64_admin_cookie_drops(self):
        encoded = base64.urlsafe_b64encode(
            b'{"role":"admin","user":"guest"}'
        ).decode("ascii")
        variants = (
            encoded + "==",
            encoded.rstrip("=") + "====",
            encoded[:8] + "..*~.." + encoded[8:],
            encoded[:12] + " " + encoded[12:],
        )
        for variant in variants:
            with self.subTest(length=len(variant)):
                decision = self._decide(
                    "/admin", dst_port=8082,
                    headers=f"Cookie: session={variant}\r\n",
                )
                self.assertEqual(decision.verdict, VERDICT_DROP)
                self.assertEqual(decision.rule_id, _L2_ADMIN_RULE_ID)

    def test_l2_guest_malformed_and_cookie_free_admin_requests_accept(self):
        guest = base64.b64encode(b'{"user":"guest","role":"user"}').decode("ascii")
        cases = ("", f"Cookie: session={guest}\r\n", "Cookie: session=not-base64!\r\n")
        for index, headers in enumerate(cases):
            with self.subTest(headers=bool(headers)):
                self.assertEqual(
                    self._decide("/admin", dst_port=8082, pkt_id=index, headers=headers).verdict,
                    VERDICT_ACCEPT,
                )

    def test_l2_observed_absolute_form_loopback_secret_drops(self):
        path = "http://team1.lig.internal:8082/fetch?url=http%3A%2F%2F127.0.0.1%3A8082%2Fsecret"
        decision = self._decide(path, dst_port=8082)
        self.assertEqual(decision.verdict, VERDICT_DROP)
        self.assertEqual(decision.rule_id, _L2_SSRF_RULE_ID)

    def test_full_corpus_l1_alternate_host_and_config_traversal_drop(self):
        alternate_hosts = (
            "172.18.0.2", "0xac120002", "2886860802", "[::ffff:ac12:2]",
        )
        for index, host in enumerate(alternate_hosts):
            path = f"/fetch?url=http%3A%2F%2F{host}%3A8080%2Fsecret"
            with self.subTest(host=host):
                decision = self._decide(path, pkt_id=600 + index)
                self.assertEqual(decision.verdict, VERDICT_DROP)
                self.assertEqual(decision.rule_id, _L1_CANONICAL_RULE_ID)

        traversal_paths = (
            "/config?file=../../../../flag",
            "/config?file=..%2f..%2f..%2f..%2fflag",
            "/config?file=%252e%252e%252f%252e%252e%252fflag",
        )
        for index, path in enumerate(traversal_paths):
            with self.subTest(path=path):
                decision = self._decide(path, pkt_id=610 + index)
                self.assertEqual(decision.verdict, VERDICT_DROP)
                self.assertEqual(decision.rule_id, _L1_CONFIG_RULE_ID)

    def test_full_corpus_l2_loopback_registry_drops(self):
        paths = (
            "/fetch?host=http%3A%2F%2F127.1%3A8082%2Fregistry",
            "/proxy?url=http%3A%2F%2F127.0.0.1%3A8082%2Fregistry",
        )
        for index, path in enumerate(paths):
            with self.subTest(path=path):
                decision = self._decide(path, dst_port=8082, pkt_id=620 + index)
                self.assertEqual(decision.verdict, VERDICT_DROP)
                self.assertEqual(decision.rule_id, _L2_REGISTRY_RULE_ID)

    def test_full_corpus_rule_negative_and_cross_layer_requests_accept(self):
        cases = (
            (8082, "/config?file=config.json"),
            (8082, "/config?file=../settings.json"),
            (8082, "/config?file=flag"),
            (8082, "/fetch?url=http%3A%2F%2F172.18.0.2%3A8080%2Fhealth"),
            (9090, "/fetch?url=http%3A%2F%2Fexample.invalid%3A8082%2Fregistry"),
            (9090, "/config?file=../../../../flag"),
        )
        for index in range(100):
            port, path = cases[index % len(cases)]
            with self.subTest(index=index, port=port, path=path):
                self.assertEqual(
                    self._decide(path, dst_port=port, pkt_id=700 + index).verdict,
                    VERDICT_ACCEPT,
                )

    def test_l3_observed_app_meta_union_variants_drop(self):
        paths = (
            "/product?id=-1%20UNION%20SELECT%201,k,v%20FROM%20app_meta--%20",
            "/product?id=-1+UNION+ALL+SELECT+1%2Cv%2C3+FROM+app_meta+WHERE+k%3D%27deploy_token%27",
            "/product?id=0%20UNION%20SELECT%201,group_concat(k%7C%7Cv),3%20FROM%20app_meta",
        )
        for index, path in enumerate(paths):
            with self.subTest(path=path):
                decision = self._decide(path, dst_port=9090, pkt_id=index)
                self.assertEqual(decision.verdict, VERDICT_DROP)
                self.assertEqual(decision.rule_id, _L3_RULE_ID)

    def test_r17_canonical_bypasses_drop(self):
        cases = (
            (8082, "/%66%65%74%63%68?%75%72%6C=%68%74%74%70%3A%2F%2F%68%65%6C%70%65%72%2D%62%6F%78%2E%3A%38%30%38%30%2F%73%65%63%72%65%74", _L1_CANONICAL_RULE_ID),
            (8082, "/fetch?url=http%3A%2F%2F127.0.0.1%3A8082%2Ffetch%3Furl%3Dhttp%253A%252F%252Fhelper-box%253A8080%252Fsecret", _L1_CANONICAL_RULE_ID),
            (8082, "/fetch?url=http%3A%2F%2Fhelper-box%3A08080%2Fsecret", _L1_CANONICAL_RULE_ID),
            (9090, "/product?id=-1%20UNION%0A%0ASELECT%20k%2Cv%2C3%20FROM%20app_meta", _L3_CANONICAL_RULE_ID),
            (9090, "/product?id=0%2F%2Ax%2A%2FUNION%2F%2Ax%2A%2FSELECT%2F%2Ax%2A%2F1%2Cv%2C3%2F%2Ax%2A%2FFROM%2F%2Ax%2A%2F%5Bapp_meta%5D", _L3_CANONICAL_RULE_ID),
        )
        for index, (port, path, rule_id) in enumerate(cases):
            with self.subTest(path=path):
                decision = self._decide(path, dst_port=port, pkt_id=500 + index)
                self.assertEqual(decision.verdict, VERDICT_DROP)
                self.assertEqual(decision.rule_id, rule_id)

    def test_cross_layer_and_normal_product_requests_accept(self):
        attack = "/product?id=-1%20UNION%20SELECT%201,k,v%20FROM%20app_meta"
        self.assertEqual(self._decide(attack, dst_port=8082).verdict, VERDICT_ACCEPT)
        for path in ("/product?id=1", "/product?name=app_meta", "/health"):
            self.assertEqual(self._decide(path, dst_port=9090).verdict, VERDICT_ACCEPT)

    def test_finals_p1_9000_satdiag_attacks_drop(self):
        cases = (
            (
                b":path*/satdiag.v1.SatDiag/TailDiagnosticLog\x00\x0a\x05/flag",
                _L1_SATDIAG_TAIL_RULE_ID,
                "sig-l1-satdiag-tail-flag",
            ),
            (
                b":path*/satdiag.v1.SatDiag/TailDiagnosticLog\x00\x0a\x12/proc/self/environ",
                _L1_SATDIAG_TAIL_RULE_ID,
                "sig-l1-satdiag-tail-flag",
            ),
            (
                b"\x00\x00\x00\x07\x00\x00\x00\x00\x01\x00\x00\x00\x00\x02\x0a\x05/flag",
                _L1_SATDIAG_TAIL_RULE_ID,
                "sig-l1-satdiag-tail-flag",
            ),
            (
                b":path*/satdiag.v1.SatDiag/ExportDiagnosticBundle\x00"
                b"telemetry.log;echo AegisD4H${FLAG}AegisD4H\x12\x07capture",
                _L1_SATDIAG_EXPORT_RULE_ID,
                "sig-l1-satdiag-export-flag-echo",
            ),
            (
                b":path*/satdiag.v1.SatDiag/ExportDiagnosticBundle\x00"
                b"x;cat /flag\x12\x07capture",
                _L1_SATDIAG_EXPORT_RULE_ID,
                "sig-l1-satdiag-export-flag-echo",
            ),
        )
        for index, (payload, rule_id, reason) in enumerate(cases, start=1):
            with self.subTest(rule_id=rule_id, index=index):
                parsed = parse_ip(ipv4_tcp(payload, dst_port=9000))
                decision = self.policy.decide(700 + index, parsed, 0.0)
                self.assertEqual(decision.verdict, VERDICT_DROP)
                self.assertEqual(decision.rule_id, rule_id)
                self.assertEqual(decision.reason_code, reason)

    def test_finals_p2_8082_graphql_mission_audit_drops(self):
        cases = (
            b"POST /graphql HTTP/1.1\r\nHost: team1.lig.internal:8082\r\n"
            b"Content-Type: application/json\r\n\r\n"
            b'{"query":"{ missionAudit { lastDeployment { notes } } }"}',
        )
        for index, payload in enumerate(cases, start=1):
            with self.subTest(index=index):
                parsed = parse_ip(ipv4_tcp(payload, dst_port=8082))
                decision = self.policy.decide(850 + index, parsed, 0.0)
                self.assertEqual(decision.verdict, VERDICT_DROP)
                self.assertEqual(decision.rule_id, _L2_GRAPHQL_RULE_ID)
                self.assertEqual(decision.reason_code, "sig-l2-graphql-mission-audit")

    def test_finals_p2r4_8080_svc_flag_and_portal_feedback_drop(self):
        cases = (
            (b"GET /svc/flag-8ceb780e-e860-4078-8a1c-f5348976062f/ HTTP/1.1\r\nHost: x\r\n\r\n",
             _L1_SVC_FLAG_RULE_ID, "sig-l1-svc-flag-gateway"),
            (b"GET /portal/feedback?service_id=vulncheck HTTP/1.1\r\nHost: x\r\n\r\n",
             _L1_PORTAL_FEEDBACK_RULE_ID, "sig-l1-portal-feedback"),
        )
        for index, (payload, rule_id, reason) in enumerate(cases, start=1):
            with self.subTest(rule_id=rule_id):
                parsed = parse_ip(ipv4_tcp(payload, dst_port=8080))
                decision = self.policy.decide(870 + index, parsed, 0.0)
                self.assertEqual(decision.verdict, VERDICT_DROP)
                self.assertEqual(decision.rule_id, rule_id)
                self.assertEqual(decision.reason_code, reason)

    def test_finals_p2r4_export_printf_flag_drops(self):
        payload = (
            b":path*/satdiag.v1.SatDiag/ExportDiagnosticBundle\x00"
            b"telemetry.log;printf 'M%sM' \"$FLAG\"\x12\x07capture"
        )
        parsed = parse_ip(ipv4_tcp(payload, dst_port=9000))
        decision = self.policy.decide(880, parsed, 0.0)
        self.assertEqual(decision.verdict, VERDICT_DROP)
        self.assertEqual(decision.rule_id, _L1_SATDIAG_EXPORT_RULE_ID)

    def test_finals_p2_8082_benign_graphql_accepts(self):

        bodies = (
            b'{"query":"{ __typename }"}',
            b'{"query":"{ systemConfig { mqtt broker password } }"}',
        )
        for index, body in enumerate(bodies):
            payload = (
                b"POST /graphql HTTP/1.1\r\nHost: team1.lig.internal:8082\r\n\r\n"
                + body
            )
            parsed = parse_ip(ipv4_tcp(payload, dst_port=8082))
            self.assertEqual(
                self.policy.decide(860 + index, parsed, 0.0).verdict,
                VERDICT_ACCEPT,
            )

    def test_finals_p1_9000_benign_satdiag_accepts(self):
        payloads = (
            b":path*/satdiag.v1.SatDiag/Health",
            b":path*/satdiag.v1.SatDiag/ExportDiagnosticBundle"
            b"\x12\x11diagnostic-bundle\x1a\x04gzip",
            b":path*/satdiag.v1.SatDiag/ProbeEndpoint\x0a\x09telemetry\x12\x05/ping",
        )
        for index, payload in enumerate(payloads, start=1):
            with self.subTest(index=index):
                parsed = parse_ip(ipv4_tcp(payload, dst_port=9000))
                self.assertEqual(
                    self.policy.decide(800 + index, parsed, 0.0).verdict,
                    VERDICT_ACCEPT,
                )

    def test_shipped_bundle_activates_only_observed_exact_rules(self):
        self.assertEqual(self.report.source, "active")
        self.assertEqual(
            self.report.bundle_id,
            "defender-2026-08-21-p2r4-satdiag-portal",
        )
        self.assertEqual(self.report.drop_capable_rules, 14)
        self.assertEqual(self.report.demotions, ())
        self.assertEqual(
            self.compiled.baseline_profiles,
            frozenset({"6/8080", "6/9000", "6/8082", "6/1883", "6/8554", "6/9090", "6/8410", "6/8420"}),
        )
        for rule_id, rule in self.compiled.rules_by_id.items():
            expected = PromotionState.ACTIVE if rule_id in _ACTIVE_RULES else PromotionState.SHADOW
            self.assertIs(rule.promotion_state, expected)


if __name__ == "__main__":
    unittest.main()
