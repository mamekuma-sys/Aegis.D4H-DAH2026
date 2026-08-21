"""Bounded TCP request stitching regression tests from TEAM1 P3 R17."""

import base64
import json
import os
import unittest

from aegis_defender.packet import parse_ip
from aegis_defender.policy import HotPolicy
from aegis_defender.protocol import VERDICT_ACCEPT, VERDICT_DROP
from aegis_defender.rules import load_policy
from aegis_defender.stream import HttpStreamStitcher

from .fakes import ipv4_tcp

_POLICY_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "policy"))
_ACTIVE_WINDOW_EPOCH = 1786764000.0


class TestHttpStreamStitcher(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        compiled, _ = load_policy(_POLICY_DIR, now_epoch=_ACTIVE_WINDOW_EPOCH)
        cls.compiled = compiled

    def setUp(self):
        self.policy = HotPolicy(policy=self.compiled, clock=lambda: 0.0)

    @staticmethod
    def _admin_request(role="admin", path="/admin?"):
        value = base64.urlsafe_b64encode(
            json.dumps({"user": "guest", "role": role}, separators=(",", ":")).encode()
        ).decode("ascii")
        return (
            f"GET {path} HTTP/1.1\r\nHost: team1.lig.internal:8082\r\n"
            f"Cookie: session={value}\r\n\r\n"
        ).encode("ascii")

    def test_segmented_admin_cookie_drops_completing_packet(self):
        request = self._admin_request()
        split = request.index(b"role") if b"role" in request else len(request) // 2
        # Base64 hides the word role; force a split inside the Cookie value.
        split = request.index(b"Cookie:") + 24
        first, second = request[:split], request[split:]
        parsed_first = parse_ip(ipv4_tcp(first, dst_port=8082, sequence=1000))
        parsed_second = parse_ip(ipv4_tcp(second, dst_port=8082, sequence=1000 + len(first)))
        self.assertEqual(self.policy.decide(1, parsed_first, 0.0).verdict, VERDICT_ACCEPT)
        decision = self.policy.decide(2, parsed_second, 0.0)
        self.assertEqual(decision.verdict, VERDICT_DROP)
        self.assertEqual(decision.rule_id, "http-l2-forged-admin-session-001")

    def test_segmented_guest_cookie_accepts(self):
        request = self._admin_request(role="user", path="/admin")
        split = request.index(b"Cookie:") + 20
        first, second = request[:split], request[split:]
        self.assertEqual(
            self.policy.decide(3, parse_ip(ipv4_tcp(first, dst_port=8082, sequence=2000)), 0.0).verdict,
            VERDICT_ACCEPT,
        )
        self.assertEqual(
            self.policy.decide(
                4,
                parse_ip(ipv4_tcp(second, dst_port=8082, sequence=2000 + len(first))),
                0.0,
            ).verdict,
            VERDICT_ACCEPT,
        )

    def test_segmented_portal_ssti_drops_completing_packet(self):
        request = (
            b"GET /portal%2Ffeedback?service_id=%7B%7B(lipsum%7Cattr('__globals__'))"
            b".get('__builtins__').get('open')('/flag').read()%7D%7D HTTP/1.1\r\n"
            b"Host: team1.lig.internal:8080\r\n\r\n"
        )
        split = request.index(b"__globals__") + 5
        first, second = request[:split], request[split:]
        parsed_first = parse_ip(ipv4_tcp(first, dst_port=8080, sequence=3000))
        parsed_second = parse_ip(
            ipv4_tcp(second, dst_port=8080, sequence=3000 + len(first))
        )

        self.assertEqual(self.policy.decide(5, parsed_first, 0.0).verdict, VERDICT_ACCEPT)
        decision = self.policy.decide(6, parsed_second, 0.0)
        self.assertEqual(decision.verdict, VERDICT_DROP)
        self.assertEqual(
            decision.rule_id,
            "http-l1-portal-feedback-ssti-semantic-001",
        )

    def test_gap_fails_open_and_discards_state(self):
        stitcher = HttpStreamStitcher()
        first = parse_ip(ipv4_tcp(b"GET /admin HTTP/1.1\r\n", dst_port=8082, sequence=10))
        gap = parse_ip(ipv4_tcp(b"Cookie: x=y\r\n\r\n", dst_port=8082, sequence=100))
        self.assertIsNone(stitcher.feed(first, 0.0))
        self.assertIsNone(stitcher.feed(gap, 0.1))
        self.assertEqual(stitcher.flow_count, 0)

    def test_ttl_and_capacity_evict_without_cross_flow_stitching(self):
        stitcher = HttpStreamStitcher(max_flows=1, ttl_seconds=1.0)
        first = parse_ip(ipv4_tcp(
            b"GET /admin HTTP/1.1\r\n", dst_port=8082, src_port=51001, sequence=10,
        ))
        second_flow = parse_ip(ipv4_tcp(
            b"GET /health HTTP/1.1\r\n", dst_port=8082, src_port=51002, sequence=20,
        ))
        self.assertIsNone(stitcher.feed(first, 0.0))
        self.assertIsNone(stitcher.feed(second_flow, 0.1))
        self.assertEqual(stitcher.flow_count, 1)
        expired_tail = parse_ip(ipv4_tcp(
            b"Cookie: session=x\r\n\r\n",
            dst_port=8082,
            src_port=51002,
            sequence=20 + len(b"GET /health HTTP/1.1\r\n"),
        ))
        self.assertIsNone(stitcher.feed(expired_tail, 2.0))
        self.assertEqual(stitcher.flow_count, 0)

    def test_segmented_graphql_body_drops_on_the_completing_packet(self):
        body = b'{"query":"{ missionAudit { lastDeployment { notes } } }"}'
        header = (
            b"POST /graphql HTTP/1.1\r\n"
            b"Host: team1.lig.internal:8082\r\n"
            b"Content-Type: application/json\r\n"
            + f"Content-Length: {len(body)}\r\n\r\n".encode("ascii")
        )
        first = header + body[:12]
        second = body[12:]
        first_packet = parse_ip(ipv4_tcp(first, dst_port=8082, sequence=3000))
        second_packet = parse_ip(
            ipv4_tcp(second, dst_port=8082, sequence=3000 + len(first))
        )
        self.assertEqual(
            self.policy.decide(10, first_packet, 0.0).verdict, VERDICT_ACCEPT
        )
        decision = self.policy.decide(11, second_packet, 0.0)
        self.assertEqual(decision.verdict, VERDICT_DROP)
        self.assertEqual(decision.rule_id, "sig-l2-graphql-mission-audit-001")


if __name__ == "__main__":
    unittest.main()
