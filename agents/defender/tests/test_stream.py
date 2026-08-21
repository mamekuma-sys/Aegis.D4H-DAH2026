"""Bounded TCP request stitching regression tests from TEAM1 P3 R17."""

import base64
import json
import os
import unittest

from aegis_defender.packet import TCP_FIN, TCP_RST, TCP_SYN, parse_ip
from aegis_defender.policy import HotPolicy
from aegis_defender.protocol import VERDICT_ACCEPT, VERDICT_DROP
from aegis_defender.rules import load_policy
from aegis_defender.stream import (
    MAX_EGRESS_TAIL_BYTES,
    EgressStreamStitcher,
    HttpStreamStitcher,
)

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


class TestEgressStreamStitcher(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.compiled, _ = load_policy(_POLICY_DIR, now_epoch=_ACTIVE_WINDOW_EPOCH)

    def setUp(self):
        self.policy = HotPolicy(policy=self.compiled, clock=lambda: 0.0)

    @staticmethod
    def _response(payload, sequence, *, flags=0x18, src_port=8080, dst_port=52000):
        return parse_ip(ipv4_tcp(
            payload,
            src_port=src_port,
            dst_port=dst_port,
            sequence=sequence,
            flags=flags,
        ))

    def test_flag_split_across_three_segments_drops_completing_packet(self):
        pieces = (
            b"HTTP/1.1 200 OK\r\n\r\n{{ harmless }}FLAG{",
            b"f754c99511e9caa2",
            b"6226bc372215084b}",
        )
        sequence = 1000
        for index, piece in enumerate(pieces):
            decision = self.policy.decide(
                100 + index,
                self._response(piece, sequence),
                0.0,
            )
            sequence += len(piece)
            if index < len(pieces) - 1:
                self.assertEqual(decision.verdict, VERDICT_ACCEPT)
            else:
                self.assertEqual(decision.verdict, VERDICT_DROP)
                self.assertEqual(decision.rule_id, "sig-flag-egress-001")

    def test_non_hex_split_placeholder_accepts(self):
        first = b"HTTP/1.1 200 OK\r\n\r\nFLAG{synthetic-"
        second = b"marker}"
        self.assertEqual(
            self.policy.decide(110, self._response(first, 2000), 0.0).verdict,
            VERDICT_ACCEPT,
        )
        self.assertEqual(
            self.policy.decide(
                111, self._response(second, 2000 + len(first)), 0.0
            ).verdict,
            VERDICT_ACCEPT,
        )

    def test_syn_fin_and_rst_retire_reused_tuple_state(self):
        prefix = b"FLAG{f754c99511e9caa2"
        suffix = b"6226bc372215084b}"
        for index, terminal in enumerate((TCP_SYN, TCP_FIN, TCP_RST)):
            with self.subTest(terminal=terminal):
                policy = HotPolicy(policy=self.compiled, clock=lambda: 0.0)
                base = 3000 + (index * 1000)
                self.assertEqual(
                    policy.decide(
                        120 + index * 3, self._response(prefix, base), 0.0
                    ).verdict,
                    VERDICT_ACCEPT,
                )
                self.assertEqual(
                    policy.decide(
                        121 + index * 3,
                        self._response(b"", base + len(prefix), flags=terminal),
                        0.0,
                    ).verdict,
                    VERDICT_ACCEPT,
                )
                self.assertEqual(
                    policy.decide(
                        122 + index * 3,
                        self._response(suffix, base + len(prefix) + 1),
                        0.0,
                    ).verdict,
                    VERDICT_ACCEPT,
                )

    def test_out_of_order_gap_drops_when_middle_segment_completes_marker(self):
        prefix = b"FLAG{f754c99511e9caa2"
        middle = b"6226bc37"
        suffix = b"2215084b}"
        self.assertEqual(
            self.policy.decide(140, self._response(prefix, 5000), 0.0).verdict,
            VERDICT_ACCEPT,
        )
        self.assertEqual(
            self.policy.decide(
                141,
                self._response(suffix, 5000 + len(prefix) + len(middle)),
                0.0,
            ).verdict,
            VERDICT_ACCEPT,
        )
        decision = self.policy.decide(
            142, self._response(middle, 5000 + len(prefix)), 0.0
        )
        self.assertEqual(decision.verdict, VERDICT_DROP)
        self.assertEqual(decision.rule_id, "sig-flag-egress-001")

    def test_suffix_seen_before_prefix_drops_when_prefix_arrives(self):
        prefix = b"FLAG{f754c99511e9caa2"
        suffix = b"6226bc372215084b}"
        suffix_sequence = 7000 + len(prefix)
        self.assertEqual(
            self.policy.decide(
                150, self._response(suffix, suffix_sequence), 0.0
            ).verdict,
            VERDICT_ACCEPT,
        )
        decision = self.policy.decide(151, self._response(prefix, 7000), 0.0)
        self.assertEqual(decision.verdict, VERDICT_DROP)
        self.assertEqual(decision.rule_id, "sig-flag-egress-001")

    def test_ttl_capacity_and_memory_are_bounded(self):
        stitcher = EgressStreamStitcher(max_flows=1, ttl_seconds=1.0)
        first = self._response(b"A" * 500, 10, dst_port=53001)
        second = self._response(b"B" * 500, 20, dst_port=53002)
        self.assertIsNone(stitcher.feed(first, 0.0))
        self.assertLessEqual(stitcher.buffered_bytes, MAX_EGRESS_TAIL_BYTES * 2)
        self.assertIsNone(stitcher.feed(second, 0.1))
        self.assertEqual(stitcher.flow_count, 1)
        self.assertLessEqual(stitcher.buffered_bytes, MAX_EGRESS_TAIL_BYTES * 2)
        contiguous = self._response(b"C" * 20, 20 + 500, dst_port=53002)
        self.assertIsNone(stitcher.feed(contiguous, 2.0))
        self.assertEqual(stitcher.flow_count, 1)
        self.assertLessEqual(stitcher.buffered_bytes, MAX_EGRESS_TAIL_BYTES * 2)


if __name__ == "__main__":
    unittest.main()
