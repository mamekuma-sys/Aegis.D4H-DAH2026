"""Broker 프레임 코덱 (`FrameCodec`).

설계 §3 근거 추적표(프레임 오프셋 `>Q`@1 `>H`@9 payload@11), §13 오류 처리,
§15.1 Broker protocol 테스트. 계약 원문은 `contracts/defender/README.md`.

    0x01 PACKET     Broker → Agent   type(1) + pkt_id(8) + pkt_len(2) + raw_ip(pkt_len)
    0x02 VERDICT    Agent → Broker   type(1) + pkt_id(8) + verdict(1)
    0x05 HEARTBEAT  Agent → Broker   type(1)

모든 정수는 big-endian이다. struct는 매 패킷 재컴파일하지 않도록 모듈 로드 시
한 번만 컴파일한다(§5.2 — frame header 검증·unpack p99 50μs 이하).

short-frame 정책은 하나로 고정돼 있다(§13). `SOCK_SEQPACKET`은 메시지 경계를
보존하므로 짧은 프레임을 다음 프레임과 이어 붙이는 것은 프로토콜 desync를 숨기는
동작이다. 따라서 11바이트 header에 못 미치면 `pkt_id`를 만들 수 없으므로 verdict를
생성하지 않고 session fault로 처리한다. 반대로 header가 완전하면 `pkt_id`를 알 수
있으므로 길이가 안 맞아도 그 ID에 `ACCEPT`를 돌려준다.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from enum import Enum

MSG_PACKET = 0x01
MSG_VERDICT = 0x02
MSG_HEARTBEAT = 0x05

VERDICT_ACCEPT = 0x00
VERDICT_DROP = 0x01

PACKET_HEADER_LEN = 11
MAX_RAW_IP_LEN = 0xFFFF

# recv 버퍼는 최대 PACKET 프레임 전체를 한 번에 담아야 한다(§15.1). SOCK_SEQPACKET에서
# 버퍼가 모자라면 메시지 뒷부분이 잘려 length mismatch로 위장되기 때문이다.
MAX_PACKET_MSG_SIZE = PACKET_HEADER_LEN + MAX_RAW_IP_LEN
VERDICT_MSG_SIZE = 1 + 8 + 1

_PKT_ID = struct.Struct(">Q")
_PKT_LEN = struct.Struct(">H")
_VERDICT = struct.Struct(">BQB")

HEARTBEAT_FRAME = bytes([MSG_HEARTBEAT])


class FrameOutcome(str, Enum):
    """수신 프레임을 어떻게 취급할지."""

    PACKET = "packet"
    UNKNOWN_TYPE = "unknown-type"
    SHORT_HEADER = "short-header"
    EMPTY = "empty"

    @property
    def is_session_fault(self) -> bool:
        """§13 — desync는 재연결로만 회복한다. 존재하지 않는 ID를 만들지 않는다."""
        return self in (FrameOutcome.SHORT_HEADER, FrameOutcome.EMPTY)


class FrameStatus(str, Enum):
    """유효한 header를 가진 PACKET 프레임의 body 상태.

    셋 다 verdict를 만들 수 있다. `OK`가 아닌 두 값은 §9.2 Gate 표에 따라
    구조 오류이므로 `DROP`이 아니라 reason code를 붙인 `ACCEPT`가 된다.
    """

    OK = "ok"
    LENGTH_MISMATCH = "frame-length-mismatch"
    TRAILING_BYTES = "frame-trailing-bytes"


@dataclass(frozen=True)
class DecodedPacket:
    pkt_id: int
    declared_len: int
    raw_ip: bytes
    status: FrameStatus


@dataclass(frozen=True)
class DecodedFrame:
    outcome: FrameOutcome
    msg_type: int
    frame_len: int
    packet: DecodedPacket | None = None


def decode_frame(data: bytes) -> DecodedFrame:
    """수신한 seqpacket 하나를 해석한다. 예외를 던지지 않는다.

    길이 불일치 두 방향을 구분해 기록한다. 선언보다 짧으면 받은 만큼만 파싱
    대상으로 삼고(`LENGTH_MISMATCH`), 길면 선언 길이까지만 자른다
    (`TRAILING_BYTES`). 어느 쪽도 `DROP` 사유가 아니다.
    """
    frame_len = len(data)
    if frame_len == 0:
        return DecodedFrame(FrameOutcome.EMPTY, -1, 0)

    msg_type = data[0]
    if msg_type != MSG_PACKET:
        return DecodedFrame(FrameOutcome.UNKNOWN_TYPE, msg_type, frame_len)

    if frame_len < PACKET_HEADER_LEN:
        return DecodedFrame(FrameOutcome.SHORT_HEADER, msg_type, frame_len)

    pkt_id = _PKT_ID.unpack_from(data, 1)[0]
    declared_len = _PKT_LEN.unpack_from(data, 9)[0]
    body = data[PACKET_HEADER_LEN:]
    actual_len = len(body)

    if actual_len == declared_len:
        status = FrameStatus.OK
        raw_ip = body
    elif actual_len < declared_len:
        status = FrameStatus.LENGTH_MISMATCH
        raw_ip = body
    else:
        status = FrameStatus.TRAILING_BYTES
        raw_ip = body[:declared_len]

    return DecodedFrame(
        FrameOutcome.PACKET,
        msg_type,
        frame_len,
        DecodedPacket(pkt_id, declared_len, raw_ip, status),
    )


def encode_verdict(pkt_id: int, verdict: int) -> bytes:
    """VERDICT 프레임을 만든다.

    `verdict`는 `0x00` ACCEPT 또는 `0x01` DROP만 허용한다. 그 외 값은 Broker가
    어떻게 해석할지 계약에 없으므로, 계약 위반 프레임을 소켓에 흘리기 전에
    여기서 막는다.
    """
    if verdict not in (VERDICT_ACCEPT, VERDICT_DROP):
        raise ValueError(f"verdict 는 0x00 또는 0x01 이어야 합니다: {verdict!r}")
    return _VERDICT.pack(MSG_VERDICT, pkt_id, verdict)


def decode_verdict(frame: bytes) -> tuple[int, int]:
    """VERDICT 프레임을 되읽는다(계약 fixture 테스트 전용)."""
    msg_type, pkt_id, verdict = _VERDICT.unpack(frame)
    if msg_type != MSG_VERDICT:
        raise ValueError(f"VERDICT 프레임이 아닙니다: 0x{msg_type:02x}")
    return pkt_id, verdict
