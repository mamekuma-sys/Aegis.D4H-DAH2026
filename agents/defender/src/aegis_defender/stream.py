"""Bounded in-order TCP stitching for request semantics and egress markers.

The Broker verdict is packet-scoped, while the protected application consumes a TCP
stream.  This module keeps only the small request prefix needed to finish one HTTP
header and, when a bounded ``Content-Length`` is present, its request body.  Gaps,
oversized input, unsupported traffic, and capacity pressure all fail open and discard
state; no packet waits for a future segment.
"""

from __future__ import annotations

from collections import OrderedDict
from dataclasses import dataclass

from .packet import IPPROTO_TCP, TCP_FIN, TCP_RST, TCP_SYN, FlowKey, ParsedPacket

MAX_STREAM_BYTES = 4096
MAX_STREAM_FLOWS = 2048
STREAM_TTL_SECONDS = 5.0
MAX_EGRESS_TAIL_BYTES = 133
MAX_EGRESS_FLOWS = 2048
EGRESS_TTL_SECONDS = 2.0
_HEADER_END = b"\r\n\r\n"
_CONTENT_LENGTH = b"content-length"
_METHOD_PREFIXES = (
    b"GET ", b"POST ", b"PUT ", b"PATCH ", b"DELETE ",
    b"HEAD ", b"OPTIONS ",
)


@dataclass(slots=True)
class _StreamState:
    next_sequence: int
    data: bytearray
    expires_at: float


@dataclass(slots=True)
class _EgressState:
    start_sequence: int
    next_sequence: int
    head: bytearray
    tail: bytearray
    expires_at: float
    pending_start: int | None = None
    pending_end: int = 0
    pending_head: bytearray | None = None
    pending_tail: bytearray | None = None


class EgressStreamStitcher:
    """보호 서비스 응답의 경계 분할 marker만 복원하는 bounded tail stitcher.

    `FLAG{` + 최대 128 hex + `}`의 전체 길이는 134바이트다. 각 contiguous 구간의
    양끝 133바이트와 133바이트 미만의 단일 out-of-order gap만 보존하면 marker가
    어느 TCP 경계에서 갈려도 현재 packet이 완성하는 순간 검출할 수 있다. 더 큰
    gap·truncation·capacity pressure에서는 오래된 상태를 버리고 fail-open하며,
    미래 packet을 기다리느라 verdict를 지연하지 않는다.
    """

    def __init__(
        self,
        max_tail_bytes: int = MAX_EGRESS_TAIL_BYTES,
        max_flows: int = MAX_EGRESS_FLOWS,
        ttl_seconds: float = EGRESS_TTL_SECONDS,
    ) -> None:
        self._max_tail = max(1, min(MAX_EGRESS_TAIL_BYTES, int(max_tail_bytes)))
        self._max_flows = max(1, int(max_flows))
        self._ttl = max(0.1, float(ttl_seconds))
        self._flows: OrderedDict[FlowKey, _EgressState] = OrderedDict()

    @property
    def flow_count(self) -> int:
        return len(self._flows)

    @property
    def buffered_bytes(self) -> int:
        return sum(
            len(state.head)
            + len(state.tail)
            + len(state.pending_head or ())
            + len(state.pending_tail or ())
            for state in self._flows.values()
        )

    def discard(self, flow_key: FlowKey | None) -> None:
        if flow_key is not None:
            self._flows.pop(flow_key, None)

    def clear(self) -> None:
        self._flows.clear()

    def _store(self, key: FlowKey, next_sequence: int, payload: bytes, now: float) -> None:
        self._ensure_capacity(now)
        start_sequence = (next_sequence - len(payload)) & 0xFFFFFFFF
        self._flows[key] = _EgressState(
            start_sequence=start_sequence,
            next_sequence=next_sequence & 0xFFFFFFFF,
            head=bytearray(payload[:self._max_tail]),
            tail=bytearray(payload[-self._max_tail:]),
            expires_at=now + self._ttl,
        )
        self._flows.move_to_end(key)

    @staticmethod
    def _signed_delta(value: int, base: int) -> int:
        delta = (value - base) & 0xFFFFFFFF
        return delta - 0x100000000 if delta & 0x80000000 else delta

    def _set_pending(
        self,
        state: _EgressState,
        sequence: int,
        next_sequence: int,
        payload: bytes,
    ) -> None:
        state.pending_start = sequence
        state.pending_end = next_sequence
        state.pending_head = bytearray(payload[:self._max_tail])
        state.pending_tail = bytearray(payload[-self._max_tail:])

    def _consume_pending(self, state: _EgressState, combined: bytes) -> bytes:
        pending_start = state.pending_start
        pending_head = state.pending_head
        pending_tail = state.pending_tail
        if pending_start is None or pending_head is None or pending_tail is None:
            return combined
        gap = self._signed_delta(pending_start, state.next_sequence)
        if gap > 0:
            return combined

        overlap = -gap
        if overlap < len(pending_head):
            addition = bytes(pending_head[overlap:])
            combined += addition
            span = self._signed_delta(state.next_sequence, state.start_sequence)
            if span < self._max_tail:
                state.head[:] = (bytes(state.head) + addition)[:self._max_tail]
        if self._signed_delta(state.pending_end, state.next_sequence) > 0:
            state.next_sequence = state.pending_end
            state.tail[:] = pending_tail
        state.pending_start = None
        state.pending_end = 0
        state.pending_head = None
        state.pending_tail = None
        return combined

    def feed(self, parsed: ParsedPacket, now: float) -> bytes | None:
        if (
            not parsed.ok
            or parsed.protocol != IPPROTO_TCP
            or parsed.flow_key is None
        ):
            return None

        key = parsed.flow_key
        flags = parsed.tcp_flags
        payload = parsed.payload
        state = self._flows.get(key)

        if state is not None and state.expires_at <= now:
            self._flows.pop(key, None)
            state = None

        if flags & TCP_SYN:
            self._flows.pop(key, None)
            state = None

        if not payload:
            if flags & (TCP_FIN | TCP_RST):
                self._flows.pop(key, None)
            return None
        if parsed.payload_truncated:
            self._flows.pop(key, None)
            return None

        sequence = (parsed.tcp_sequence + (1 if flags & TCP_SYN else 0)) & 0xFFFFFFFF
        next_sequence = (sequence + len(payload)) & 0xFFFFFFFF
        terminal = bool(flags & (TCP_FIN | TCP_RST))

        if state is None:
            if not terminal:
                self._store(key, next_sequence, payload, now)
            return None

        start_offset = self._signed_delta(sequence, state.start_sequence)
        span = self._signed_delta(state.next_sequence, state.start_sequence)
        end_offset = start_offset + len(payload)

        if end_offset < 0:
            # 먼저 관측한 suffix 바로 앞의 작은 gap은 pending으로 뒤집어 보관한다.
            gap = -end_offset
            old = state
            self._flows.pop(key, None)
            if terminal:
                return None
            self._store(key, next_sequence, payload, now)
            state = self._flows[key]
            if gap < self._max_tail:
                state.pending_start = old.start_sequence
                state.pending_end = old.next_sequence
                state.pending_head = old.head
                state.pending_tail = old.tail
            return None

        if start_offset < 0:
            prefix_length = min(len(payload), -start_offset)
            prefix = payload[:prefix_length]
            combined = prefix + bytes(state.head)
            state.start_sequence = sequence
            state.head[:] = combined[:self._max_tail]
            if end_offset > span:
                state.next_sequence = next_sequence
                state.tail[:] = payload[-self._max_tail:]
        elif start_offset <= span:
            overlap = span - start_offset
            if overlap >= len(payload):
                if terminal:
                    self._flows.pop(key, None)
                else:
                    state.expires_at = now + self._ttl
                    self._flows.move_to_end(key)
                return None
            suffix = payload[overlap:]
            combined = bytes(state.tail) + suffix
            if span < self._max_tail:
                state.head[:] = (bytes(state.head) + suffix)[:self._max_tail]
            state.next_sequence = next_sequence
            state.tail[:] = combined[-self._max_tail:]
        else:
            # FLAG 전체 길이보다 큰 hole은 한 marker에 속할 수 없다. 작은 hole은
            # 한 조각만 기억해 중간 segment가 나중에 올 때 결합한다.
            gap = start_offset - span
            if terminal:
                self._flows.pop(key, None)
            elif gap < self._max_tail:
                self._set_pending(state, sequence, next_sequence, payload)
                state.expires_at = now + self._ttl
                self._flows.move_to_end(key)
            else:
                self._flows.pop(key, None)
                self._store(key, next_sequence, payload, now)
            return None

        combined = self._consume_pending(state, combined)
        if terminal:
            self._flows.pop(key, None)
        else:
            state.expires_at = now + self._ttl
            self._flows.move_to_end(key)
        return combined

    def _ensure_capacity(self, now: float) -> None:
        while self._flows:
            oldest_key = next(iter(self._flows))
            oldest = self._flows[oldest_key]
            if oldest.expires_at > now and len(self._flows) < self._max_flows:
                break
            self._flows.popitem(last=False)


class HttpStreamStitcher:
    """Single-owner, bounded TCP prefix stitcher.

    ``feed`` returns a complete HTTP request prefix when the current packet completes
    it.  It returns ``None`` for an incomplete or unsupported shape, which preserves
    the caller's fail-open verdict contract.
    """

    def __init__(
        self,
        max_bytes: int = MAX_STREAM_BYTES,
        max_flows: int = MAX_STREAM_FLOWS,
        ttl_seconds: float = STREAM_TTL_SECONDS,
    ) -> None:
        self._max_bytes = max(512, int(max_bytes))
        self._max_flows = max(1, int(max_flows))
        self._ttl = max(0.1, float(ttl_seconds))
        self._flows: OrderedDict[FlowKey, _StreamState] = OrderedDict()

    @property
    def flow_count(self) -> int:
        return len(self._flows)

    def discard(self, flow_key: FlowKey | None) -> None:
        if flow_key is not None:
            self._flows.pop(flow_key, None)

    def clear(self) -> None:
        self._flows.clear()

    def _required_bytes(self, data: bytes | bytearray) -> int | None:
        """완전한 header가 있으면 필요한 request prefix 길이를 돌려준다.

        본선 GraphQL 요청은 header와 JSON body가 서로 다른 TCP segment로 전달됐다.
        body 전체를 무조건 기다리면 hot path와 가용성을 해치므로, 숫자 하나로 명확한
        bounded ``Content-Length``만 따른다. 누락·중복 불일치·비정상 값은 header까지만
        완성된 것으로 취급해 기존 fail-open 동작을 보존한다.
        """
        header_end = data.find(_HEADER_END)
        if header_end < 0:
            return None
        header_bytes = header_end + len(_HEADER_END)
        lengths: list[int] = []
        for line in bytes(data[:header_end]).split(b"\r\n")[1:]:
            name, separator, value = line.partition(b":")
            if not separator or name.strip().lower() != _CONTENT_LENGTH:
                continue
            stripped = value.strip()
            if not stripped.isdigit():
                return header_bytes
            lengths.append(int(stripped))
        if not lengths or any(value != lengths[0] for value in lengths[1:]):
            return header_bytes
        return header_bytes + lengths[0]

    def _start(self, parsed: ParsedPacket, now: float) -> bytes | None:
        payload = parsed.payload
        required = self._required_bytes(payload)
        if required is not None:
            if required <= len(payload) or required > self._max_bytes:
                return payload
        if parsed.payload_truncated or len(payload) >= self._max_bytes:
            return None
        self._ensure_capacity(now)
        sequence = parsed.tcp_sequence + (1 if parsed.tcp_flags & TCP_SYN else 0)
        self._flows[parsed.flow_key] = _StreamState(
            next_sequence=(sequence + len(payload)) & 0xFFFFFFFF,
            data=bytearray(payload),
            expires_at=now + self._ttl,
        )
        return None

    def feed(self, parsed: ParsedPacket, now: float) -> bytes | None:
        if (
            not parsed.ok
            or parsed.protocol != IPPROTO_TCP
            or parsed.flow_key is None
            or not parsed.payload
        ):
            return None

        key = parsed.flow_key
        payload = parsed.payload
        state = self._flows.get(key)

        if state is not None and state.expires_at <= now:
            self._flows.pop(key, None)
            state = None

        starts_request = payload.startswith(_METHOD_PREFIXES)
        if state is None:
            if not starts_request:
                return None
            return self._start(parsed, now)

        if parsed.tcp_flags & (TCP_FIN | TCP_RST):
            self._flows.pop(key, None)
            return None

        sequence = parsed.tcp_sequence + (1 if parsed.tcp_flags & TCP_SYN else 0)
        expected = state.next_sequence
        if sequence == expected:
            suffix = payload
        elif sequence < expected:
            overlap = expected - sequence
            if overlap >= len(payload):
                state.expires_at = now + self._ttl
                self._flows.move_to_end(key)
                return None
            suffix = payload[overlap:]
        else:
            # A gap means the application and this bounded view no longer agree.
            self._flows.pop(key, None)
            if starts_request:
                return self.feed(parsed, now)
            return None

        if len(state.data) + len(suffix) > self._max_bytes:
            self._flows.pop(key, None)
            return None
        state.data.extend(suffix)
        state.next_sequence = (expected + len(suffix)) & 0xFFFFFFFF
        state.expires_at = now + self._ttl
        self._flows.move_to_end(key)

        required = self._required_bytes(state.data)
        if required is None or len(state.data) < required:
            return None
        complete = bytes(state.data)
        self._flows.pop(key, None)
        return complete

    def _ensure_capacity(self, now: float) -> None:
        while self._flows:
            oldest_key = next(iter(self._flows))
            oldest = self._flows[oldest_key]
            if oldest.expires_at > now and len(self._flows) < self._max_flows:
                break
            self._flows.popitem(last=False)
