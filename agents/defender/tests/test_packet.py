"""상한 있는 파서 테스트.

설계 §9.1 parser별 문서화 항목, §9.2 Gate 단계, §15.3.

핵심 회귀는 하나다 — **어떤 입력에서도 예외가 밖으로 나오지 않고, 실패는 전부
`ACCEPT` 가능한 status가 된다.** 파싱 실패를 차단으로 바꾸는 순간 공격자는
malformed 패킷만 보내서 우리가 정상 트래픽을 막게 만들 수 있다.
"""

import struct
import unittest

from aegis_defender.packet import (
    IPPROTO_ICMP,
    IPPROTO_TCP,
    IPPROTO_UDP,
    MAX_PAYLOAD_VIEW,
    TCP_ACK,
    TCP_FIN,
    TCP_PSH,
    TCP_URG,
    ParseStatus,
    is_scan_flag_combination,
    parse_ip,
)

from .fakes import http_request, ipv4_tcp, ipv4_udp


class TestIpv4Tcp(unittest.TestCase):
    def test_positive_fixture(self):
        parsed = parse_ip(ipv4_tcp(http_request("/index.html"), dst_port=8080, sequence=12345))
        self.assertIs(parsed.status, ParseStatus.OK)
        self.assertEqual(parsed.ip_version, 4)
        self.assertEqual(parsed.protocol, IPPROTO_TCP)
        self.assertEqual(parsed.dst_port, 8080)
        self.assertEqual(parsed.src_port, 51234)
        self.assertEqual(parsed.tcp_sequence, 12345)
        self.assertTrue(parsed.payload.startswith(b"GET /index.html"))
        self.assertIsNotNone(parsed.flow_key)
        self.assertEqual(parsed.flow_key.protocol, IPPROTO_TCP)

    def test_flow_key_includes_protocol(self):
        # §8 — protocol 을 포함한 5-tuple. 같은 포트의 TCP/UDP 를 한 flow 로
        # 합치면 상관분석이 서로 다른 대화를 섞는다.
        tcp = parse_ip(ipv4_tcp(dst_port=5000)).flow_key
        udp = parse_ip(ipv4_udp(dst_port=5000, src_port=51234)).flow_key
        self.assertNotEqual(tcp, udp)

    def test_payload_view_is_bounded(self):
        parsed = parse_ip(ipv4_tcp(b"A" * 5000))
        self.assertIs(parsed.status, ParseStatus.OK)
        self.assertEqual(len(parsed.payload), MAX_PAYLOAD_VIEW)
        self.assertTrue(parsed.payload_truncated)

    def test_ip_total_length_bounds_payload(self):
        # IP 총길이 뒤의 padding 은 payload 가 아니다.
        packet = ipv4_tcp(b"REAL") + b"\xff" * 32
        parsed = parse_ip(packet)
        self.assertEqual(parsed.payload, b"REAL")

    def test_source_ip_change_does_not_alter_parse(self):
        # NAT 로 source IP 가 정규화되므로(운영세칙 제12조 2항) source IP 는
        # 판단 근거가 아니다. 파싱 결과에서 src_ip 외에는 아무것도 달라지지 않는다.
        first = parse_ip(ipv4_tcp(http_request(), src_ip=bytes((10, 1, 0, 4))))
        second = parse_ip(ipv4_tcp(http_request(), src_ip=bytes((10, 9, 0, 4))))
        self.assertEqual(first.status, second.status)
        self.assertEqual(first.dst_port, second.dst_port)
        self.assertEqual(first.payload, second.payload)


class TestFallbacks(unittest.TestCase):
    def test_too_short(self):
        self.assertIs(parse_ip(b"\x45\x00\x00").status, ParseStatus.TOO_SHORT)

    def test_unsupported_version_records_observation(self):
        # §9.1 — IPv4 만 지원한다고 가정하지 않는다. 판정은 포기하되 관측은 남긴다.
        packet = bytes([0x60]) + b"\x00" * 39
        parsed = parse_ip(packet)
        self.assertIs(parsed.status, ParseStatus.UNSUPPORTED_VERSION)
        self.assertEqual(parsed.ip_version, 6)

    def test_bad_ihl(self):
        packet = bytearray(ipv4_tcp())
        packet[0] = 0x43  # IHL=3 → 12바이트, 최소 20 미만
        self.assertIs(parse_ip(bytes(packet)).status, ParseStatus.BAD_IHL)

    def test_total_length_larger_than_frame_is_truncated(self):
        packet = bytearray(ipv4_tcp(b"payload"))
        struct.pack_into(">H", packet, 2, 900)
        self.assertIs(parse_ip(bytes(packet)).status, ParseStatus.TRUNCATED)

    def test_total_length_smaller_than_header(self):
        packet = bytearray(ipv4_tcp())
        struct.pack_into(">H", packet, 2, 8)
        self.assertIs(parse_ip(bytes(packet)).status, ParseStatus.BAD_TOTAL_LENGTH)

    def test_fragment_is_not_reassembled(self):
        packet = bytearray(ipv4_tcp(b"chunk"))
        struct.pack_into(">H", packet, 6, 0x2000)  # More Fragments
        parsed = parse_ip(bytes(packet))
        self.assertIs(parsed.status, ParseStatus.FRAGMENTED)

    def test_fragment_offset_is_not_reassembled(self):
        packet = bytearray(ipv4_tcp(b"chunk"))
        struct.pack_into(">H", packet, 6, 0x0001)
        self.assertIs(parse_ip(bytes(packet)).status, ParseStatus.FRAGMENTED)

    def test_truncated_l4(self):
        packet = ipv4_tcp()[:28]  # IP 헤더 + TCP 8바이트만
        packet = bytearray(packet)
        struct.pack_into(">H", packet, 2, 28)
        self.assertIs(parse_ip(bytes(packet)).status, ParseStatus.TRUNCATED_L4)

    def test_unsupported_protocol(self):
        packet = bytearray(ipv4_tcp())
        packet[9] = IPPROTO_ICMP
        parsed = parse_ip(bytes(packet))
        self.assertIs(parsed.status, ParseStatus.UNSUPPORTED_PROTOCOL)
        self.assertEqual(parsed.protocol, IPPROTO_ICMP)

    def test_parser_never_raises(self):
        # 무작위 바이트열에서도 예외가 나오지 않아야 한다.
        samples = [
            b"",
            b"\x00",
            b"\xff" * 64,
            bytes(range(256)),
            b"\x45" + b"\xff" * 19,
            b"\x4f" + b"\x00" * 60,
        ]
        for index in range(0, 4096, 97):
            samples.append(bytes((index % 256, (index * 7) % 256)) * 20)
        for sample in samples:
            with self.subTest(size=len(sample)):
                parsed = parse_ip(sample)
                self.assertIsInstance(parsed.status, ParseStatus)


class TestUdp(unittest.TestCase):
    def test_udp_positive(self):
        parsed = parse_ip(ipv4_udp(b"hello", dst_port=5353))
        self.assertIs(parsed.status, ParseStatus.OK)
        self.assertEqual(parsed.protocol, IPPROTO_UDP)
        self.assertEqual(parsed.dst_port, 5353)
        self.assertEqual(parsed.payload, b"hello")

    def test_udp_length_field_conflict_uses_smaller_bound(self):
        packet = bytearray(ipv4_udp(b"hello"))
        struct.pack_into(">H", packet, 24, 400)  # UDP length 필드만 부풀린다
        parsed = parse_ip(bytes(packet))
        self.assertIs(parsed.status, ParseStatus.OK)
        self.assertEqual(parsed.payload, b"hello")


class TestScanFlags(unittest.TestCase):
    def test_null_scan(self):
        self.assertEqual(is_scan_flag_combination(0x00), "tcp-null")

    def test_fin_scan(self):
        self.assertEqual(is_scan_flag_combination(TCP_FIN), "tcp-fin")

    def test_xmas_scan(self):
        self.assertEqual(is_scan_flag_combination(TCP_FIN | TCP_PSH | TCP_URG), "tcp-xmas")

    def test_normal_flags_are_not_scans(self):
        for flags in (TCP_ACK, TCP_PSH | TCP_ACK, 0x02, TCP_FIN | TCP_ACK):
            with self.subTest(flags=flags):
                self.assertIsNone(is_scan_flag_combination(flags))


if __name__ == "__main__":
    unittest.main()
