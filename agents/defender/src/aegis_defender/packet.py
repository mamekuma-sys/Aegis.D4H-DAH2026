"""상한 있는 IP/L4 파서 (`PacketParser`).

설계 §9.1 parser별 문서화 항목, §9.2 Gate 단계, §8 상태와 데이터 모델.

이 모듈의 유일한 계약은 **예외를 밖으로 던지지 않는다**는 것이다. 파싱 실패는
차단 사유가 아니라 판정 포기 사유이며(§6.2), 호출자는 어떤 status를 받든
`ACCEPT`를 만들 수 있어야 한다.

**IPv4만 지원한다고 가정하지 않는다**(§9.1). 레퍼런스 구현은 `(pkt[0] >> 4) != 4`
이면 판정을 포기하고 `ACCEPT`한다. 같은 fallback을 유지하되 IPv6 관측 여부를
status로 남겨, 오리엔테이션 확인 항목(§18.2 "IPv6 패킷이 전달되는가")에 대한
실측 근거가 되게 한다.

payload는 복사가 아니라 **상한 있는 view**여야 한다(§8). 64KB 패킷이 그대로
정규식 대상이 되면 §5.2의 `Sig` 100μs 예산을 지킬 수 없기 때문이다. 여기서는
상한까지만 슬라이스해 최대 `MAX_PAYLOAD_VIEW` 바이트만 보유한다.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from enum import Enum

PARSER_VERSION = 1

# `Sig` 예산(§5.2 p99 100μs)과 §8.1 flow 재조립 버퍼 16KB 사이에서 고른 상한.
# 인바운드 HTTP 요청 헤더·경로는 대부분 첫 2KB 안에 들어간다. 이 값을 키우려면
# §15.4 부하 프로파일을 다시 측정한다.
MAX_PAYLOAD_VIEW = 2048

IPPROTO_ICMP = 1
IPPROTO_TCP = 6
IPPROTO_UDP = 17

TCP_FIN = 0x01
TCP_SYN = 0x02
TCP_RST = 0x04
TCP_PSH = 0x08
TCP_ACK = 0x10
TCP_URG = 0x20

# §9.2 마지막 행 — 정상 트래픽에 나타나지 않음이 fixture로 증명돼야 `DROP` 후보가
# 되는 조합. 여기서는 "무엇이 그 조합인가"만 정의하고, 실제 차단 여부는
# PolicyBundle의 승격 상태가 결정한다.
TCP_FLAGS_NULL = 0x00
TCP_FLAGS_FIN_ONLY = TCP_FIN
TCP_FLAGS_XMAS = TCP_FIN | TCP_PSH | TCP_URG

_PORTS = struct.Struct(">HH")
_U16 = struct.Struct(">H")

IPV4_MIN_HEADER = 20
TCP_MIN_HEADER = 20
UDP_HEADER = 8


class ParseStatus(str, Enum):
    """파싱 결과. `OK` 외에는 전부 빠른 `ACCEPT` 사유다(§9.2)."""

    OK = "ok"
    TOO_SHORT = "parse-too-short"
    UNSUPPORTED_VERSION = "parse-unsupported-version"
    BAD_IHL = "parse-bad-ihl"
    BAD_TOTAL_LENGTH = "parse-bad-total-length"
    TRUNCATED = "parse-truncated"
    FRAGMENTED = "parse-fragmented"
    TRUNCATED_L4 = "parse-truncated-l4"
    UNSUPPORTED_PROTOCOL = "parse-unsupported-protocol"
    EXCEPTION = "parse-exception"

    @property
    def ok(self) -> bool:
        return self is ParseStatus.OK


@dataclass(frozen=True, slots=True)
class FlowKey:
    """protocol을 포함한 5-tuple(§8).

    source IP는 NAT로 `10.{N}.0.4` 하나로 정규화되므로(운영세칙 제12조 2항)
    **식별자로 쓰지 않는다.** 그럼에도 key에 남기는 이유는 flow를 서로 구분하기
    위한 좌표로는 필요하기 때문이다. 신뢰 신호로 쓰지 않는다는 것과 좌표로 쓰는
    것은 다르며, `test_policy.py`가 source IP만 바꾼 fixture로 verdict 불변을
    검증한다.
    """

    src_ip: bytes
    src_port: int
    dst_ip: bytes
    dst_port: int
    protocol: int

    def digest_material(self) -> bytes:
        """`hashlib.blake2s` canary bucket 입력(§6.4, §10.4).

        프로세스를 재시작해도 같은 bucket이 나와야 하므로 Python의
        process-randomized `hash()`를 쓰지 않고 바이트열을 직접 만든다.
        """
        return b"".join((
            self.src_ip,
            self.src_port.to_bytes(2, "big"),
            self.dst_ip,
            self.dst_port.to_bytes(2, "big"),
            self.protocol.to_bytes(1, "big"),
        ))

    def scope_key(self) -> str:
        """rule의 protocol/port scope 조회 키."""
        return f"{self.protocol}/{self.dst_port}"


@dataclass(frozen=True, slots=True)
class ObservedTrafficProfile:
    """관측으로만 만들어지는 트래픽 profile(§8, §16.1).

    `dst_subnet_candidate`는 목적지 IP의 세 번째 옥텟이다. 세그먼트가
    `10.{N}.{L}.0/24`이므로 레이어와 대응할 가능성이 높지만, **Broker가 전달하는
    `raw_ip`가 포워딩 전인지 후인지 확인되지 않았다**(§16.1, §18.2). 따라서
    이름을 `layer`가 아니라 `candidate`로 두고, fixture로 일치를 증명하기 전까지
    레이어 확정에 쓰지 않는다.
    """

    protocol: int
    dst_port: int
    dst_subnet_candidate: int | None
    parser_version: int = PARSER_VERSION

    def scope_key(self) -> str:
        return f"{self.protocol}/{self.dst_port}"


@dataclass(frozen=True, slots=True)
class ParsedPacket:
    status: ParseStatus
    ip_version: int = 0
    protocol: int = -1
    src_ip: bytes = b""
    dst_ip: bytes = b""
    src_port: int = 0
    dst_port: int = 0
    tcp_flags: int = 0
    total_length: int = 0
    payload: bytes = b""
    payload_truncated: bool = False
    flow_key: FlowKey | None = None
    profile: ObservedTrafficProfile | None = None

    @property
    def ok(self) -> bool:
        return self.status.ok


_EMPTY_TOO_SHORT = ParsedPacket(ParseStatus.TOO_SHORT)


def parse_ip(raw: bytes) -> ParsedPacket:
    """raw IP 패킷을 상한 안에서 파싱한다. 절대 예외를 던지지 않는다."""
    try:
        return _parse_ip(raw)
    except Exception:  # noqa: BLE001 - §9.2 parser 예외 → ACCEPT + 예외 metric
        return ParsedPacket(ParseStatus.EXCEPTION)


def _parse_ip(raw: bytes) -> ParsedPacket:
    length = len(raw)
    if length < IPV4_MIN_HEADER:
        return _EMPTY_TOO_SHORT

    version = raw[0] >> 4
    if version != 4:
        # IPv6나 알 수 없는 version. 레퍼런스와 동일하게 판정을 포기하되 관측
        # 사실은 남긴다(§9.1).
        return ParsedPacket(ParseStatus.UNSUPPORTED_VERSION, ip_version=version)

    ihl = (raw[0] & 0x0F) * 4
    if ihl < IPV4_MIN_HEADER or length < ihl:
        return ParsedPacket(ParseStatus.BAD_IHL, ip_version=4)

    total_length = _U16.unpack_from(raw, 2)[0]
    if total_length < ihl:
        return ParsedPacket(ParseStatus.BAD_TOTAL_LENGTH, ip_version=4, total_length=total_length)
    if total_length > length:
        # 선언 총길이보다 실제가 짧다 = 잘린 패킷. 상한 밖을 읽지 않고 포기한다.
        return ParsedPacket(ParseStatus.TRUNCATED, ip_version=4, total_length=total_length)

    flags_frag = _U16.unpack_from(raw, 6)[0]
    more_fragments = bool(flags_frag & 0x2000)
    fragment_offset = flags_frag & 0x1FFF
    protocol = raw[9]
    src_ip = raw[12:16]
    dst_ip = raw[16:20]

    if more_fragments or fragment_offset:
        # 재조립은 hot path 예산 밖이다(§9.2). fragment는 차단하지 않고 포기한다.
        return ParsedPacket(
            ParseStatus.FRAGMENTED,
            ip_version=4,
            protocol=protocol,
            src_ip=src_ip,
            dst_ip=dst_ip,
            total_length=total_length,
        )

    # IP 총길이를 신뢰 경계로 삼아 trailing padding을 파싱 대상에서 제외한다.
    body_end = total_length

    if protocol == IPPROTO_TCP:
        return _parse_tcp(raw, ihl, body_end, src_ip, dst_ip, total_length)
    if protocol == IPPROTO_UDP:
        return _parse_udp(raw, ihl, body_end, src_ip, dst_ip, total_length)

    return ParsedPacket(
        ParseStatus.UNSUPPORTED_PROTOCOL,
        ip_version=4,
        protocol=protocol,
        src_ip=src_ip,
        dst_ip=dst_ip,
        total_length=total_length,
    )


def _bounded_payload(raw: bytes, start: int, end: int) -> tuple[bytes, bool]:
    if start >= end:
        return b"", False
    available = end - start
    if available > MAX_PAYLOAD_VIEW:
        return raw[start:start + MAX_PAYLOAD_VIEW], True
    return raw[start:end], False


def _make(
    status: ParseStatus,
    protocol: int,
    src_ip: bytes,
    dst_ip: bytes,
    src_port: int,
    dst_port: int,
    tcp_flags: int,
    total_length: int,
    payload: bytes,
    truncated: bool,
) -> ParsedPacket:
    flow_key = FlowKey(src_ip, src_port, dst_ip, dst_port, protocol)
    profile = ObservedTrafficProfile(
        protocol=protocol,
        dst_port=dst_port,
        dst_subnet_candidate=dst_ip[2] if len(dst_ip) == 4 else None,
    )
    return ParsedPacket(
        status=status,
        ip_version=4,
        protocol=protocol,
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        tcp_flags=tcp_flags,
        total_length=total_length,
        payload=payload,
        payload_truncated=truncated,
        flow_key=flow_key,
        profile=profile,
    )


def _parse_tcp(
    raw: bytes, ihl: int, body_end: int, src_ip: bytes, dst_ip: bytes, total_length: int
) -> ParsedPacket:
    if body_end < ihl + TCP_MIN_HEADER:
        return ParsedPacket(
            ParseStatus.TRUNCATED_L4,
            ip_version=4,
            protocol=IPPROTO_TCP,
            src_ip=src_ip,
            dst_ip=dst_ip,
            total_length=total_length,
        )

    src_port, dst_port = _PORTS.unpack_from(raw, ihl)
    data_offset = (raw[ihl + 12] >> 4) * 4
    tcp_flags = raw[ihl + 13]

    if data_offset < TCP_MIN_HEADER or body_end < ihl + data_offset:
        # options 길이가 프레임을 넘어선다. 포트와 플래그는 이미 읽었지만 payload
        # 경계를 신뢰할 수 없으므로 payload 없이 판정을 포기한다.
        return _make(
            ParseStatus.TRUNCATED_L4, IPPROTO_TCP, src_ip, dst_ip, src_port, dst_port,
            tcp_flags, total_length, b"", False,
        )

    payload, truncated = _bounded_payload(raw, ihl + data_offset, body_end)
    return _make(
        ParseStatus.OK, IPPROTO_TCP, src_ip, dst_ip, src_port, dst_port,
        tcp_flags, total_length, payload, truncated,
    )


def _parse_udp(
    raw: bytes, ihl: int, body_end: int, src_ip: bytes, dst_ip: bytes, total_length: int
) -> ParsedPacket:
    if body_end < ihl + UDP_HEADER:
        return ParsedPacket(
            ParseStatus.TRUNCATED_L4,
            ip_version=4,
            protocol=IPPROTO_UDP,
            src_ip=src_ip,
            dst_ip=dst_ip,
            total_length=total_length,
        )

    src_port, dst_port = _PORTS.unpack_from(raw, ihl)
    udp_length = _U16.unpack_from(raw, ihl + 4)[0]

    # UDP 길이 필드가 IP 총길이와 모순되면 짧은 쪽을 경계로 삼는다. 두 값을 모두
    # 신뢰하지 않고 최소값만 읽는 것이 상한 있는 파싱의 정의다.
    declared_end = ihl + udp_length if udp_length >= UDP_HEADER else body_end
    end = min(body_end, declared_end)

    payload, truncated = _bounded_payload(raw, ihl + UDP_HEADER, end)
    return _make(
        ParseStatus.OK, IPPROTO_UDP, src_ip, dst_ip, src_port, dst_port,
        0, total_length, payload, truncated,
    )


def is_scan_flag_combination(tcp_flags: int) -> str | None:
    """명시적 스캔 플래그 조합이면 그 이름을 돌려준다(§9.2 마지막 행).

    이름을 돌려줄 뿐 차단하지 않는다. 차단 여부는 PolicyBundle의 rule 승격
    상태만 결정하며, 정상 negative fixture 통과 전에는 관찰 전용이다.
    """
    if tcp_flags == TCP_FLAGS_NULL:
        return "tcp-null"
    if tcp_flags == TCP_FLAGS_FIN_ONLY:
        return "tcp-fin"
    if (tcp_flags & TCP_FLAGS_XMAS) == TCP_FLAGS_XMAS and not (tcp_flags & TCP_ACK):
        return "tcp-xmas"
    return None
