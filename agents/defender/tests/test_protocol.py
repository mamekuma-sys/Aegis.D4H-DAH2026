"""Broker 프레임 계약 테스트.

설계 §15.1. 고정 입력은 `contracts/fixtures/*.hex`이며, 팀 공통 계약이므로
테스트가 그 파일을 직접 읽어 우리 코덱과 대조한다.
"""

import os
import unittest

from aegis_defender.protocol import (
    HEARTBEAT_FRAME,
    MAX_PACKET_MSG_SIZE,
    MSG_HEARTBEAT,
    PACKET_HEADER_LEN,
    VERDICT_ACCEPT,
    VERDICT_DROP,
    FrameOutcome,
    FrameStatus,
    decode_frame,
    decode_verdict,
    encode_verdict,
)

_FIXTURES = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "..", "..", "contracts", "fixtures")
)


def load_fixture(name: str) -> bytes:
    with open(os.path.join(_FIXTURES, name), "r", encoding="utf-8") as handle:
        return bytes.fromhex("".join(handle.read().split()))


class TestContractFixtures(unittest.TestCase):
    def test_packet_frame_fixture(self):
        frame = decode_frame(load_fixture("packet-frame.hex"))
        self.assertIs(frame.outcome, FrameOutcome.PACKET)
        packet = frame.packet
        self.assertEqual(packet.pkt_id, 42)
        self.assertEqual(packet.declared_len, 20)
        self.assertEqual(len(packet.raw_ip), 20)
        self.assertIs(packet.status, FrameStatus.OK)
        # big-endian 해석 확인: 20바이트 IPv4 헤더의 version/IHL 과 protocol
        self.assertEqual(packet.raw_ip[0], 0x45)
        self.assertEqual(packet.raw_ip[9], 6)

    def test_accept_verdict_fixture_matches_encoder(self):
        expected = load_fixture("accept-verdict.hex")
        self.assertEqual(encode_verdict(42, VERDICT_ACCEPT), expected)
        self.assertEqual(decode_verdict(expected), (42, VERDICT_ACCEPT))

    def test_heartbeat_fixture_is_single_byte(self):
        expected = load_fixture("heartbeat.hex")
        self.assertEqual(expected, HEARTBEAT_FRAME)
        self.assertEqual(len(HEARTBEAT_FRAME), 1)
        self.assertEqual(HEARTBEAT_FRAME[0], MSG_HEARTBEAT)


class TestFrameDecoding(unittest.TestCase):
    def test_recv_buffer_covers_maximum_frame(self):
        self.assertEqual(MAX_PACKET_MSG_SIZE, 1 + 8 + 2 + 65535)

    def test_drop_verdict_byte(self):
        frame = encode_verdict(7, VERDICT_DROP)
        self.assertEqual(frame[-1], 0x01)
        self.assertEqual(decode_verdict(frame), (7, VERDICT_DROP))

    def test_invalid_verdict_value_rejected(self):
        # 계약에 없는 값을 소켓에 흘리기 전에 막는다.
        with self.assertRaises(ValueError):
            encode_verdict(1, 0x02)

    def test_unknown_message_type_is_discarded_not_fault(self):
        frame = decode_frame(bytes([0x09]) + b"\x00" * 20)
        self.assertIs(frame.outcome, FrameOutcome.UNKNOWN_TYPE)
        self.assertFalse(frame.outcome.is_session_fault)

    def test_short_packet_header_is_session_fault(self):
        # §13 — pkt_id 를 만들 수 없으므로 verdict 를 생성하지 않고 재연결한다.
        frame = decode_frame(bytes([0x01]) + b"\x00" * (PACKET_HEADER_LEN - 2))
        self.assertIs(frame.outcome, FrameOutcome.SHORT_HEADER)
        self.assertTrue(frame.outcome.is_session_fault)
        self.assertIsNone(frame.packet)

    def test_empty_frame_is_session_fault(self):
        frame = decode_frame(b"")
        self.assertIs(frame.outcome, FrameOutcome.EMPTY)
        self.assertTrue(frame.outcome.is_session_fault)

    def test_length_mismatch_keeps_packet_id(self):
        # header 가 완전하면 pkt_id 를 알 수 있으므로 그 ID 에 ACCEPT 를 보낸다.
        import struct

        data = struct.pack(">BQH", 0x01, 99, 40) + b"\xaa" * 10
        frame = decode_frame(data)
        self.assertIs(frame.outcome, FrameOutcome.PACKET)
        self.assertEqual(frame.packet.pkt_id, 99)
        self.assertIs(frame.packet.status, FrameStatus.LENGTH_MISMATCH)
        self.assertEqual(len(frame.packet.raw_ip), 10)

    def test_trailing_bytes_are_truncated_to_declared_length(self):
        import struct

        data = struct.pack(">BQH", 0x01, 100, 4) + b"\x01\x02\x03\x04" + b"\xff" * 6
        frame = decode_frame(data)
        self.assertIs(frame.packet.status, FrameStatus.TRAILING_BYTES)
        self.assertEqual(frame.packet.raw_ip, b"\x01\x02\x03\x04")

    def test_seqpacket_message_boundary_is_preserved(self):
        # 두 프레임을 각각 디코드하면 서로 섞이지 않는다. SOCK_SEQPACKET 에서
        # 짧은 프레임을 다음 프레임과 이어 붙이지 않는다는 §13 정책의 근거다.
        import struct

        first = struct.pack(">BQH", 0x01, 1, 2) + b"\x11\x22"
        second = struct.pack(">BQH", 0x01, 2, 2) + b"\x33\x44"
        self.assertEqual(decode_frame(first).packet.raw_ip, b"\x11\x22")
        self.assertEqual(decode_frame(second).packet.raw_ip, b"\x33\x44")


if __name__ == "__main__":
    unittest.main()
