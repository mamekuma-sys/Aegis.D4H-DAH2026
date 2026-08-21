"""R6 one-byte HTTP/2 DATA fragmentation regression tests."""

import os
import unittest

from aegis_defender.grpc_semantics import (
    CLIENT_PREFACE,
    EXPORT_FLAG_COMMAND,
    TAIL_SENSITIVE_FILE,
    GrpcH2StreamInspector,
)
from aegis_defender.packet import parse_ip
from aegis_defender.policy import HotPolicy
from aegis_defender.protocol import VERDICT_ACCEPT, VERDICT_DROP
from aegis_defender.rules import load_policy

from .fakes import ipv4_tcp

_POLICY_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "policy"))
_ACTIVE_WINDOW_EPOCH = 1787356800.0


def _frame(frame_type, flags, stream_id, payload=b""):
    return (
        len(payload).to_bytes(3, "big")
        + bytes((frame_type, flags))
        + stream_id.to_bytes(4, "big")
        + payload
    )


def _field(number, value):
    raw = value.encode("utf-8")
    return bytes(((number << 3) | 2, len(raw))) + raw


def _grpc_packets(message, src_port=51000, huffman_headers=True):
    envelope = b"\x00" + len(message).to_bytes(4, "big") + message
    # The header bytes deliberately do not expose the RPC in clear text.  The
    # semantic decision must depend only on the completed protobuf message.
    headers = b"\x83\x86\x44\x9a\x61\x03\x4c\x86" if huffman_headers else b"\x83\x86"
    payloads = [CLIENT_PREFACE + _frame(4, 0, 0) + _frame(1, 4, 1, headers)]
    payloads.extend(
        _frame(0, 1 if index == len(envelope) - 1 else 0, 1, bytes((byte,)))
        for index, byte in enumerate(envelope)
    )
    packets = []
    sequence = 1000
    for payload in payloads:
        packets.append(parse_ip(ipv4_tcp(
            payload, src_port=src_port, dst_port=9000, sequence=sequence
        )))
        sequence += len(payload)
    return packets


class TestGrpcH2StreamInspector(unittest.TestCase):
    def test_tail_and_export_are_detected_only_when_complete(self):
        samples = (
            (_field(1, "/flag") + b"\x10\x01", TAIL_SENSITIVE_FILE),
            (_field(1, "telemetry.log;echo ${FLAG}") + _field(2, "capture"),
             EXPORT_FLAG_COMMAND),
        )
        for offset, (message, expected) in enumerate(samples):
            with self.subTest(expected=expected):
                inspector = GrpcH2StreamInspector()
                packets = _grpc_packets(message, src_port=51000 + offset)
                for packet in packets[:-1]:
                    self.assertIsNone(inspector.feed(packet, 0.0))
                self.assertEqual(inspector.feed(packets[-1], 0.0), expected)

    def test_normal_or_gapped_stream_fails_open(self):
        inspector = GrpcH2StreamInspector()
        normal = _grpc_packets(_field(1, "diagnostic.log") + b"\x10\x01")
        self.assertTrue(all(inspector.feed(packet, 0.0) is None for packet in normal))

        inspector = GrpcH2StreamInspector()
        packets = _grpc_packets(_field(1, "/flag") + b"\x10\x01", src_port=52000)
        self.assertIsNone(inspector.feed(packets[0], 0.0))
        gap_packet = parse_ip(ipv4_tcp(
            packets[1].payload, src_port=52000, dst_port=9000,
            sequence=packets[1].tcp_sequence + 1,
        ))
        self.assertIsNone(inspector.feed(gap_packet, 0.0))
        self.assertEqual(inspector.flow_count, 0)

    def test_payloadless_new_syn_retires_reused_tuple_state(self):
        inspector = GrpcH2StreamInspector()
        packets = _grpc_packets(_field(1, "/flag") + b"\x10\x01", src_port=53000)
        self.assertIsNone(inspector.feed(packets[0], 0.0))
        syn = parse_ip(ipv4_tcp(
            b"", src_port=53000, dst_port=9000, sequence=9000, flags=0x02,
        ))
        self.assertIsNone(inspector.feed(syn, 0.1))
        self.assertEqual(inspector.flow_count, 0)


class TestGrpcSemanticPolicy(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.compiled, _ = load_policy(_POLICY_DIR, now_epoch=_ACTIVE_WINDOW_EPOCH)

    def test_fragmented_huffman_tail_drops_completing_packet(self):
        policy = HotPolicy(policy=self.compiled, clock=lambda: 0.0)
        packets = _grpc_packets(_field(1, "/flag") + b"\x10\x01")
        for packet_id, packet in enumerate(packets[:-1], start=1):
            self.assertEqual(
                policy.decide(packet_id, packet, 0.0).verdict, VERDICT_ACCEPT
            )
        decision = policy.decide(len(packets), packets[-1], 0.0)
        self.assertEqual(decision.verdict, VERDICT_DROP)
        self.assertEqual(decision.rule_id, "grpc-l1-tail-sensitive-file-001")


if __name__ == "__main__":
    unittest.main()
