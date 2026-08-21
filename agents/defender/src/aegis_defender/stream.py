"""Bounded TCP stitching for request semantics and egress markers.

The Broker verdict is packet-scoped, while the protected application consumes a TCP
stream.  This module keeps only the small request prefix needed to finish one HTTP
header and, when a bounded ``Content-Length`` is present, its request body.  Gaps,
oversized input, unsupported traffic, and capacity pressure all fail open and discard
state; no packet waits for a future segment.  A small sparse window tolerates
ordinary TCP reordering while fixed byte, segment, flow, and TTL caps preserve the
hot-path budget.
"""

from __future__ import annotations

from collections import OrderedDict
from dataclasses import dataclass

from .packet import IPPROTO_TCP, TCP_FIN, TCP_RST, TCP_SYN, FlowKey, ParsedPacket

MAX_STREAM_BYTES = 4096
MAX_STREAM_FLOWS = 2048
STREAM_TTL_SECONDS = 5.0
MAX_STREAM_SEGMENTS = 8
# JSON ``\u00xx`` is the longest supported flag representation: six wire bytes
# per logical byte plus the prefix/suffix.  Keeping this tail catches a marker
# split at any packet boundary without retaining a response body.
MAX_EGRESS_TAIL_BYTES = 786
MAX_EGRESS_FLOWS = 2048
EGRESS_TTL_SECONDS = 2.0
MAX_EGRESS_PENDING_SEGMENTS = 8
_HEADER_END = b"\r\n\r\n"
_CONTENT_LENGTH = b"content-length"
_METHOD_PREFIXES = (
    b"GET ", b"POST ", b"PUT ", b"PATCH ", b"DELETE ",
    b"HEAD ", b"OPTIONS ",
)


@dataclass(slots=True)
class _StreamState:
    start_sequence: int
    segments: list[tuple[int, bytes]]
    expires_at: float


@dataclass(slots=True)
class _EgressState:
    start_sequence: int
    next_sequence: int
    head: bytearray
    tail: bytearray
    expires_at: float
    pending: list[tuple[int, int, bytearray, bytearray]] | None = None


class EgressStreamStitcher:
    """보호 서비스 응답의 경계 분할 marker만 복원하는 bounded tail stitcher.

    raw, URL escape, JSON unicode escape 표현 중 가장 긴 marker의 경계 앞뒤만
    보존한다. 최대 8개의 작은 out-of-order gap을 처리하되, 더 큰 gap·truncation·
    capacity pressure에서는 오래된 상태를 버리고 fail-open한다. 미래 packet을
    기다리느라 verdict를 지연하지 않는다.
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
            + sum(len(head) + len(tail) for _, _, head, tail in (state.pending or ()))
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
            pending=[],
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
    ) -> bool:
        pending = state.pending
        if pending is None:
            pending = state.pending = []
        if any(start == sequence and end == next_sequence for start, end, _, _ in pending):
            return True
        if len(pending) >= MAX_EGRESS_PENDING_SEGMENTS:
            return False
        pending.append((
            sequence,
            next_sequence,
            bytearray(payload[:self._max_tail]),
            bytearray(payload[-self._max_tail:]),
        ))
        return True

    def _consume_pending(self, state: _EgressState, combined: bytes) -> bytes:
        pending = state.pending
        if not pending:
            return combined
        while pending:
            pending.sort(key=lambda item: self._signed_delta(item[0], state.next_sequence))
            pending_start, pending_end, pending_head, pending_tail = pending[0]
            gap = self._signed_delta(pending_start, state.next_sequence)
            if gap > 0:
                break
            pending.pop(0)
            overlap = -gap
            if overlap < len(pending_head):
                addition = bytes(pending_head[overlap:])
                combined += addition
                span = self._signed_delta(state.next_sequence, state.start_sequence)
                if span < self._max_tail:
                    state.head[:] = (bytes(state.head) + addition)[:self._max_tail]
            if self._signed_delta(pending_end, state.next_sequence) > 0:
                state.next_sequence = pending_end
                state.tail[:] = pending_tail
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
                state.pending = [(
                    old.start_sequence, old.next_sequence, old.head, old.tail
                )]
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
                if self._set_pending(state, sequence, next_sequence, payload):
                    state.expires_at = now + self._ttl
                    self._flows.move_to_end(key)
                else:
                    self._flows.pop(key, None)
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

    @staticmethod
    def _signed_delta(value: int, base: int) -> int:
        delta = (value - base) & 0xFFFFFFFF
        return delta - 0x100000000 if delta & 0x80000000 else delta

    @staticmethod
    def _could_be_http_fragment(payload: bytes) -> bool:
        if not payload or payload.startswith(b"PRI * HTTP/2.0") or b"\x00" in payload:
            return False
        printable = sum(byte in (9, 10, 13) or 32 <= byte <= 126 for byte in payload)
        return printable * 10 >= len(payload) * 9 and (
            b"\r\n" in payload or b":" in payload or payload[:1] in b"{["
        )

    def _insert_segment(
        self, state: _StreamState, sequence: int, payload: bytes
    ) -> bool:
        if self._signed_delta(sequence, state.start_sequence) < 0:
            state.start_sequence = sequence
        items = state.segments + [(sequence, payload)]
        items.sort(key=lambda item: self._signed_delta(item[0], state.start_sequence))
        merged: list[tuple[int, bytes]] = []
        for item_sequence, item_payload in items:
            offset = self._signed_delta(item_sequence, state.start_sequence)
            if offset < 0 or offset + len(item_payload) > self._max_bytes:
                return False
            if not merged:
                merged.append((item_sequence, item_payload))
                continue
            previous_sequence, previous_payload = merged[-1]
            previous_offset = self._signed_delta(previous_sequence, state.start_sequence)
            previous_end = previous_offset + len(previous_payload)
            if offset > previous_end:
                merged.append((item_sequence, item_payload))
                continue
            overlap = previous_end - offset
            if overlap < len(item_payload):
                merged[-1] = (previous_sequence, previous_payload + item_payload[overlap:])
        if len(merged) > MAX_STREAM_SEGMENTS:
            return False
        state.segments = merged
        return True

    def _complete_request(self, state: _StreamState) -> bytes | None:
        if not state.segments:
            return None
        sequence, data = state.segments[0]
        if sequence != state.start_sequence or not data.startswith(_METHOD_PREFIXES):
            return None
        required = self._required_bytes(data)
        if required is None or len(data) < required:
            return None
        return data

    def _start(self, parsed: ParsedPacket, now: float, *, candidate: bool = False) -> bytes | None:
        payload = parsed.payload
        if not candidate:
            required = self._required_bytes(payload)
            if required is not None and (required <= len(payload) or required > self._max_bytes):
                return payload
        if parsed.payload_truncated or len(payload) >= self._max_bytes:
            return None
        self._ensure_capacity(now)
        sequence = (parsed.tcp_sequence + (1 if parsed.tcp_flags & TCP_SYN else 0)) & 0xFFFFFFFF
        self._flows[parsed.flow_key] = _StreamState(
            start_sequence=sequence,
            segments=[(sequence, payload)],
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
        if parsed.tcp_flags & TCP_SYN and state is not None:
            self._flows.pop(key, None)
            state = None
        if state is None:
            if not starts_request and not self._could_be_http_fragment(payload):
                return None
            return self._start(parsed, now, candidate=not starts_request)

        if parsed.tcp_flags & (TCP_FIN | TCP_RST):
            self._flows.pop(key, None)
            return None

        if parsed.payload_truncated:
            self._flows.pop(key, None)
            return None
        sequence = (parsed.tcp_sequence + (1 if parsed.tcp_flags & TCP_SYN else 0)) & 0xFFFFFFFF
        if not self._insert_segment(state, sequence, payload):
            self._flows.pop(key, None)
            return None
        state.expires_at = now + self._ttl
        self._flows.move_to_end(key)
        complete = self._complete_request(state)
        if complete is None:
            return None
        self._flows.pop(key, None)
        return complete

    def _ensure_capacity(self, now: float) -> None:
        while self._flows:
            oldest_key = next(iter(self._flows))
            oldest = self._flows[oldest_key]
            if oldest.expires_at > now and len(self._flows) < self._max_flows:
                break
            self._flows.popitem(last=False)
