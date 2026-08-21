"""R6 one-byte HTTP/2 DATA fragmentation regression tests."""

import os
import base64
import json
import unittest

from aegis_defender.grpc_semantics import (
    CLIENT_PREFACE,
    EXPORT_FLAG_COMMAND,
    L4_CALIBRATION_PICKLE_CODE,
    L4_DIAGNOSTIC_MAP_SNAPSHOT,
    L4_GET_CATALOG,
    L4_PROGRAMMING_SECRET_SOURCE,
    L4_SERVER_REFLECTION,
    TAIL_SENSITIVE_FILE,
    GrpcH2StreamInspector,
    classify_grpc_message,
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
    raw = value.encode("utf-8") if isinstance(value, str) else value
    return _varint((number << 3) | 2) + _varint(len(raw)) + raw


def _varint(value):
    encoded = bytearray()
    while value >= 0x80:
        encoded.append((value & 0x7F) | 0x80)
        value >>= 7
    encoded.append(value)
    return bytes(encoded)


def _int_field(number, value):
    return _varint(number << 3) + _varint(value)


def _l4_exchange(topic_id, type_id, sample, encoding=0):
    envelope = (
        _int_field(1, 23) + _int_field(2, 26165)
        + _int_field(3, topic_id) + _int_field(4, type_id)
        + _int_field(5, 68) + _int_field(6, 1) + _field(7, sample)
    )
    if encoding == 1:
        encoded = base64.b64encode(envelope)
    elif encoding == 2:
        encoded = json.dumps({
            "domainId": 23,
            "participantId": 26165,
            "topicId": topic_id,
            "typeId": type_id,
            "qos": 68,
            "seq": "1",
            "sample": base64.b64encode(sample).decode("ascii"),
        }, separators=(",", ":")).encode("ascii")
    else:
        encoded = envelope
    return _int_field(1, 1) + _int_field(2, 2) + _int_field(3, encoding) + _field(4, encoded)


def _grpc_packets(message, src_port=51000, huffman_headers=True, dst_port=9000):
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
            payload, src_port=src_port, dst_port=dst_port, sequence=sequence
        )))
        sequence += len(payload)
    return packets


def _headers_packets(path, dst_port=8410, src_port=54000, split_at=None):
    wire = CLIENT_PREFACE + _frame(4, 0, 0) + _frame(1, 4, 1, b"\x00" + path)
    payloads = [wire] if split_at is None else [wire[:split_at], wire[split_at:]]
    packets = []
    sequence = 4000
    for payload in payloads:
        packets.append(parse_ip(ipv4_tcp(
            payload, src_port=src_port, dst_port=dst_port, sequence=sequence
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

    def test_normal_stream_accepts_and_bounded_reordering_recovers(self):
        inspector = GrpcH2StreamInspector()
        normal = _grpc_packets(_field(1, "diagnostic.log") + b"\x10\x01")
        self.assertTrue(all(inspector.feed(packet, 0.0) is None for packet in normal))

        inspector = GrpcH2StreamInspector()
        packets = _grpc_packets(_field(1, "/flag") + b"\x10\x01", src_port=52000)
        self.assertIsNone(inspector.feed(packets[0], 0.0))
        self.assertIsNone(inspector.feed(packets[2], 0.0))
        self.assertIsNone(inspector.feed(packets[1], 0.0))
        for packet in packets[3:-1]:
            self.assertIsNone(inspector.feed(packet, 0.0))
        self.assertEqual(inspector.feed(packets[-1], 0.0), TAIL_SENSITIVE_FILE)

    def test_l4_exchange_encodings_and_exact_negative_shapes(self):
        diagnostic = _int_field(1, 4) + _field(3, b"maintenance")
        for encoding in (0, 1, 2):
            with self.subTest(encoding=encoding):
                self.assertEqual(
                    classify_grpc_message(
                        _l4_exchange(65536, 4097, diagnostic, encoding), 8410
                    ),
                    L4_DIAGNOSTIC_MAP_SNAPSHOT,
                )
        for action in (1, 2, 3):
            self.assertIsNone(classify_grpc_message(
                _l4_exchange(65536, 4097, _int_field(1, action)), 8420
            ))

    def test_l4_pickle_is_opcode_inspected_without_unpickling(self):
        dangerous = b"cos\nsystem\n(S'cat /flag'\ntR."
        benign = b"\x80\x04}\x94."
        for blob, expected in (
            (dangerous, L4_CALIBRATION_PICKLE_CODE),
            (benign, None),
        ):
            sample = (
                _int_field(1, 1) + _int_field(2, 1) + _int_field(3, 1)
                + _field(4, blob) + _int_field(5, 1)
            )
            self.assertEqual(
                classify_grpc_message(_l4_exchange(393216, 16384, sample), 8410),
                expected,
            )

    def test_l4_programming_store_requires_explicit_secret_source(self):
        def store(source):
            return (
                _int_field(1, 1) + _int_field(2, 1002) + _field(3, b"program-1")
                + _int_field(4, 1) + _int_field(5, 1) + _field(6, source)
            )

        self.assertEqual(
            classify_grpc_message(
                _l4_exchange(655360, 28672, store(b"print(open('/flag').read())")),
                8420,
            ),
            L4_PROGRAMMING_SECRET_SOURCE,
        )
        self.assertIsNone(classify_grpc_message(
            _l4_exchange(655360, 28672, store(b"print('grpc-sla-ok')")), 8420
        ))

    def test_payloadless_new_syn_retires_reused_tuple_state(self):
        inspector = GrpcH2StreamInspector()
        packets = _grpc_packets(_field(1, "/flag") + b"\x10\x01", src_port=53000)
        self.assertIsNone(inspector.feed(packets[0], 0.0))
        syn = parse_ip(ipv4_tcp(
            b"", src_port=53000, dst_port=9000, sequence=9000, flags=0x02,
        ))
        self.assertIsNone(inspector.feed(syn, 0.1))
        self.assertEqual(inspector.flow_count, 0)

    def test_l4_literal_discovery_paths_are_port_scoped(self):
        samples = (
            (b"/grpc.reflection.v1.ServerReflection/ServerReflectionInfo",
             L4_SERVER_REFLECTION),
            (b"/g2dds.v1.Layer4Service/GetCatalog", L4_GET_CATALOG),
        )
        for offset, (path, expected) in enumerate(samples):
            with self.subTest(expected=expected):
                inspector = GrpcH2StreamInspector()
                packets = _headers_packets(
                    path, dst_port=8410 + offset * 10, src_port=54000 + offset,
                    split_at=len(CLIENT_PREFACE) + 12,
                )
                self.assertIsNone(inspector.feed(packets[0], 0.0))
                self.assertEqual(inspector.feed(packets[1], 0.0), expected)

        inspector = GrpcH2StreamInspector()
        normal = _headers_packets(b"/grpc.health.v1.Health/Check", dst_port=8410)
        self.assertIsNone(inspector.feed(normal[0], 0.0))


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

    def test_fragmented_l4_map_snapshot_drops_on_both_ports(self):
        message = _l4_exchange(65536, 4097, _int_field(1, 4))
        for port in (8410, 8420):
            policy = HotPolicy(policy=self.compiled, clock=lambda: 0.0)
            packets = _grpc_packets(message, src_port=52000 + port, dst_port=port)
            for packet_id, packet in enumerate(packets[:-1], start=1):
                self.assertEqual(policy.decide(packet_id, packet, 0.0).verdict, VERDICT_ACCEPT)
            decision = policy.decide(len(packets), packets[-1], 0.0)
            self.assertEqual(decision.verdict, VERDICT_DROP)
            self.assertEqual(decision.rule_id, "grpc-l4-diagnostic-map-snapshot-001")

    def test_l4_discovery_paths_remain_shadow(self):
        policy = HotPolicy(policy=self.compiled, clock=lambda: 0.0)
        samples = (
            (b"/grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo",
             8410, "grpc-l4-server-reflection-001"),
            (b"/g2dds.v1.Layer4Service/GetCatalog",
             8420, "grpc-l4-get-catalog-001"),
        )
        for index, (path, port, rule_id) in enumerate(samples):
            decision = policy.decide(
                100 + index,
                _headers_packets(path, dst_port=port, src_port=55000 + index)[0],
                0.0,
            )
            self.assertEqual(decision.verdict, VERDICT_ACCEPT)
            self.assertEqual(decision.rule_id, rule_id)


if __name__ == "__main__":
    unittest.main()
