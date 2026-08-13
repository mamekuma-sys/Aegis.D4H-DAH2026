"""verdict 이후 event 변환과 상한 있는 큐 (`EventAdapter`, bounded queue).

설계 §8 `CorrelationEvent`, §8.1 용량 상한, §11 온라인 비동기 상관분석.

두 가지가 이 모듈의 형태를 결정한다.

1. **event는 원본을 참조하지 않는다.** `payload`·`PacketEnvelope`·`ParsedPacket`을
   그대로 큐에 넣으면 큐 용량은 1,024건이어도 실제 메모리는 패킷 크기에 비례해
   늘어난다. 20분 Round 동안 그것이 §8.1의 2GB 상한을 위협한다. 그래서 여기서
   bounded scalar로 축약하고, 경로는 되돌릴 수 없는 digest로만 남긴다.
2. **큐가 가득 차도 hot path는 기다리지 않는다.** `put_nowait`만 쓰고 실패하면
   들어오려는 최신 event를 O(1)로 버린다(drop-newest). 기존 FIFO 순서를 유지하는
   쪽을 고른 이유는, 오래된 것을 밀어내려면 큐를 건드려야 하고 그 비용이 hot
   path에 있기 때문이다. queue full은 `DROP` 사유가 아니다(§6.2).
"""

from __future__ import annotations

import hashlib
import queue
from dataclasses import dataclass

from .packet import ParsedPacket, ParseStatus, FlowKey, is_scan_flag_combination
from .protocol import VERDICT_ACCEPT

DEFAULT_EVENT_QUEUE_CAPACITY = 1024

# 요청 라인은 이 길이 안에서만 찾는다. 못 찾으면 경로 없는 event가 되고, 그것은
# 정상이다 — 모든 프로토콜이 HTTP는 아니다.
MAX_REQUEST_LINE_SCAN = 512
LONG_URI_THRESHOLD = 256

_HTTP_METHODS = (
    b"GET ", b"POST ", b"HEAD ", b"PUT ", b"DELETE ",
    b"OPTIONS ", b"PATCH ", b"TRACE ", b"CONNECT ",
)

EVENT_PACKET = "packet"
EVENT_SIG_HIT = "sig-hit"
EVENT_SCAN_FLAGS = "scan-flags"


@dataclass(frozen=True, slots=True)
class CorrelationEvent:
    """compact parsed record. 원본 payload와 packet 객체를 참조하지 않는다(§8)."""

    event_type: str
    flow_key: FlowKey
    monotonic_ts: float
    protocol: int
    dst_port: int
    payload_len: int
    verdict: int
    evidence_source: str
    path_digest: str = ""
    path_length: int = 0
    encoded_nesting: bool = False
    long_uri: bool = False
    scan_flag_name: str = ""
    sig_category: str = ""
    rule_id: str = ""


class BoundedEventQueue:
    """고정 길이 FIFO. 가득 차면 들어오려는 event를 버린다(drop-newest)."""

    def __init__(self, capacity: int = DEFAULT_EVENT_QUEUE_CAPACITY) -> None:
        self._queue: queue.Queue[CorrelationEvent] = queue.Queue(maxsize=capacity)
        self._capacity = capacity
        self.dropped_newest = 0

    @property
    def capacity(self) -> int:
        return self._capacity

    def put_nowait(self, event: CorrelationEvent) -> bool:
        """넣었으면 True, 버렸으면 False. 절대 블로킹하지 않는다."""
        try:
            self._queue.put_nowait(event)
        except queue.Full:
            self.dropped_newest += 1
            return False
        return True

    def get(self, timeout: float = 0.2) -> CorrelationEvent | None:
        try:
            return self._queue.get(timeout=timeout)
        except queue.Empty:
            return None

    def qsize(self) -> int:
        return self._queue.qsize()


def _extract_request_path(payload: bytes) -> bytes:
    """payload 앞부분에서 HTTP 요청 경로를 찾는다. 없으면 빈 바이트열."""
    head = payload[:MAX_REQUEST_LINE_SCAN]
    if not head.startswith(_HTTP_METHODS):
        return b""
    first_space = head.find(b" ")
    if first_space < 0:
        return b""
    second_space = head.find(b" ", first_space + 1)
    end = second_space if second_space > 0 else len(head)
    return head[first_space + 1:end]


def _digest_path(path: bytes) -> str:
    """경로를 되돌릴 수 없는 8자리 digest로.

    원본 경로를 그대로 들고 있으면 그것이 곧 payload 조각이고, 큐·로그·LLM
    프롬프트로 흘러나갈 표면이 된다(§12). digest는 "같은 경로인가"만 답하면
    되므로 상관분석에 필요한 정보를 잃지 않는다.
    """
    return hashlib.blake2s(path, digest_size=4).hexdigest()


class EventAdapter:
    """판정 결과와 파싱 결과를 최소 event로 바꾼다. 변환 실패 시 event를 버린다."""

    def to_event(
        self,
        parsed: ParsedPacket,
        monotonic_ts: float,
        verdict: int = VERDICT_ACCEPT,
        sig_category: str = "",
        rule_id: str = "",
        evidence_source: str = "hot-path",
    ) -> CorrelationEvent | None:
        try:
            return self._to_event(
                parsed, monotonic_ts, verdict, sig_category, rule_id, evidence_source
            )
        except Exception:  # noqa: BLE001 - §7 변환 실패 시 event 폐기
            return None

    def _to_event(
        self,
        parsed: ParsedPacket,
        monotonic_ts: float,
        verdict: int,
        sig_category: str,
        rule_id: str,
        evidence_source: str,
    ) -> CorrelationEvent | None:
        flow_key = parsed.flow_key
        if flow_key is None:
            # flow 좌표가 없으면 상관분석의 대상이 될 수 없다. 파싱을 포기한
            # 패킷은 verdict만 남기고 비동기 경로에 넣지 않는다.
            return None

        payload = parsed.payload
        path = _extract_request_path(payload) if payload else b""
        scan_flag = (
            is_scan_flag_combination(parsed.tcp_flags)
            if parsed.status is ParseStatus.OK and parsed.protocol == 6
            else None
        )

        event_type = EVENT_PACKET
        if rule_id:
            event_type = EVENT_SIG_HIT
        elif scan_flag:
            event_type = EVENT_SCAN_FLAGS

        return CorrelationEvent(
            event_type=event_type,
            flow_key=flow_key,
            monotonic_ts=monotonic_ts,
            protocol=parsed.protocol,
            dst_port=parsed.dst_port,
            payload_len=len(payload),
            verdict=verdict,
            evidence_source=evidence_source,
            path_digest=_digest_path(path) if path else "",
            path_length=len(path),
            # `%252e` 처럼 인코딩을 겹친 흔적(§9.4). payload 전체가 아니라 존재
            # 여부만 boolean 으로 남긴다.
            encoded_nesting=b"%25" in payload[:MAX_REQUEST_LINE_SCAN],
            long_uri=len(path) > LONG_URI_THRESHOLD,
            scan_flag_name=scan_flag or "",
            sig_category=sig_category,
            rule_id=rule_id,
        )
