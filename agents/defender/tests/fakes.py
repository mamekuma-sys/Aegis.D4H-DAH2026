"""테스트용 fake clock·fake socket과 패킷 빌더.

설계 §15.4가 요구하는 "fake clock·fake socket 기반 송신 모델 검증"의 토대다.

실제 `AF_UNIX`/`SOCK_SEQPACKET` 소켓을 쓰지 않는다. macOS는 `AF_UNIX` 계열에서
`SOCK_SEQPACKET`을 지원하지 않고 CI는 windows-latest라, 실제 소켓으로 쓴 테스트는
개발 환경 어디에서도 돌지 않는다. 설계가 fake 기반 검증을 명시한 것도 같은 이유다.
"""

from __future__ import annotations

import struct
import threading
from collections import deque

from aegis_defender.packet import IPPROTO_TCP, IPPROTO_UDP
from aegis_defender.protocol import MSG_PACKET


class FakeClock:
    """monotonic clock 대체. 테스트가 시간을 직접 전진시킨다."""

    def __init__(self, start: float = 0.0) -> None:
        self.now = start

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> float:
        self.now += seconds
        return self.now


class FakeTransport:
    """`SocketTransport` 대체.

    `send`에 넘어온 timeout을 그대로 기록하므로 §4.2의 예산 계산식을 그대로
    검증할 수 있다. 호출한 스레드 이름도 모아 "소켓에 쓰는 주체가 정확히
    하나"임을 확인한다.
    """

    def __init__(self) -> None:
        self.sent: list[bytes] = []
        self.timeouts: list[float] = []
        self.callers: set[str] = set()
        self.inbox: deque[bytes] = deque()
        self.closed = False
        self.blocked = False
        self.error: Exception | None = None
        self.partial_by = 0
        self._idle = threading.Event()
        # `hold`를 설정하면 send가 그 이벤트가 풀릴 때까지 안에서 멈춘다. blocking
        # send 도중에 재연결이 끼어드는 경쟁 상황을 결정론적으로 재현하기 위한 것이다.
        self.hold: threading.Event | None = None
        self.entered_send = threading.Event()

    def send(self, frame: bytes, timeout: float) -> int:
        self.callers.add(threading.current_thread().name)
        self.timeouts.append(timeout)
        self.entered_send.set()
        if self.hold is not None:
            self.hold.wait(5.0)
        if self.error is not None:
            raise self.error
        if self.blocked:
            raise TimeoutError("fake blocked send")
        self.sent.append(frame)
        if self.partial_by:
            return max(0, len(frame) - self.partial_by)
        return len(frame)

    def recv(self, timeout: float) -> bytes | None:
        """`None`은 timeout, `b""`는 EOF다.

        비어 있을 때 실제로 기다리는 이유는, 즉시 `None`을 돌려주면 수신 루프가
        바쁜 대기에 빠져 writer 스레드의 실행 기회를 빼앗기 때문이다.
        """
        if self.inbox:
            return self.inbox.popleft()
        self._idle.wait(timeout)
        return None

    def close(self) -> None:
        self.closed = True

    def feed(self, frame: bytes) -> None:
        self.inbox.append(frame)


def ipv4_tcp(
    payload: bytes = b"",
    src_ip: bytes = bytes((10, 1, 0, 4)),
    dst_ip: bytes = bytes((10, 1, 1, 4)),
    src_port: int = 51234,
    dst_port: int = 80,
    flags: int = 0x18,
) -> bytes:
    """최소 IPv4+TCP 패킷. options 없음, fragment 없음."""
    tcp_header = struct.pack(
        ">HHIIBBHHH",
        src_port, dst_port,
        0, 0,
        (5 << 4), flags,
        65535, 0, 0,
    )
    total = 20 + len(tcp_header) + len(payload)
    ip_header = struct.pack(
        ">BBHHHBBH4s4s",
        0x45, 0, total,
        0, 0,
        64, IPPROTO_TCP, 0,
        src_ip, dst_ip,
    )
    return ip_header + tcp_header + payload


def ipv4_udp(
    payload: bytes = b"",
    src_ip: bytes = bytes((10, 1, 0, 4)),
    dst_ip: bytes = bytes((10, 1, 1, 4)),
    src_port: int = 51234,
    dst_port: int = 5353,
) -> bytes:
    udp_header = struct.pack(">HHHH", src_port, dst_port, 8 + len(payload), 0)
    total = 20 + len(udp_header) + len(payload)
    ip_header = struct.pack(
        ">BBHHHBBH4s4s",
        0x45, 0, total,
        0, 0,
        64, IPPROTO_UDP, 0,
        src_ip, dst_ip,
    )
    return ip_header + udp_header + payload


def packet_frame(pkt_id: int, raw_ip: bytes, declared_len: int | None = None) -> bytes:
    """`0x01` PACKET frame. `declared_len`을 따로 주면 길이 불일치를 만든다."""
    length = len(raw_ip) if declared_len is None else declared_len
    return struct.pack(">BQH", MSG_PACKET, pkt_id, length) + raw_ip


def http_request(path: str = "/index.html", method: str = "GET") -> bytes:
    return (
        f"{method} {path} HTTP/1.1\r\nHost: team1.lig.internal\r\n"
        "User-Agent: sla-check\r\n\r\n"
    ).encode("latin-1")


def minimal_bundle(rules=None, baseline_profiles=None, bundle_id="test-bundle") -> dict:
    """검증을 통과하는 최소 bundle 문서."""
    return {
        "schema_version": 1,
        "bundle_id": bundle_id,
        "generated_at": "2026-08-13T00:00:00Z",
        "baseline_profiles": list(baseline_profiles or []),
        "rules": list(rules or []),
        "alert_profiles": [],
    }


def rule_document(rule_id: str, **overrides) -> dict:
    """승인 완료 상태의 rule 문서. 테스트가 필요한 필드만 덮어쓴다."""
    document = {
        "rule_id": rule_id,
        "kind": "payload_regex",
        "category": "path-traversal",
        "reason_code": f"reason-{rule_id}",
        "protocol": "tcp",
        "ports": [80],
        "pattern": "\\.\\./",
        "promotion_state": "ACTIVE",
        "canary_fraction": 0.0,
        "canary_seed": "",
        "promotion_cohort": "test-cohort",
        "promoted_in_bundle": "test-bundle",
        "parser_version": 1,
        "profile_scope": ["*"],
        "evidence_id": "EV-1",
        "positive_fixture_id": "POS-1",
        "negative_fixture_id": "NEG-1",
        "sla_fixture_id": "SLA-1",
        "expires_at": "2099-01-01T00:00:00Z",
        "rollback_condition": "test",
        "owner_review": "approved",
        "lead_review": "approved",
    }
    document.update(overrides)
    return document
