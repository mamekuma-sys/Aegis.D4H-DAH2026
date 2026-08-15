"""Bounded in-order TCP request-header stitching for semantic HTTP policy.

The Broker verdict is packet-scoped, while the protected application consumes a TCP
stream.  This module keeps only the small request prefix needed to finish one HTTP
header.  Gaps, oversized input, unsupported traffic, and capacity pressure all fail
open and discard state; no packet waits for a future segment.
"""

from __future__ import annotations

from collections import OrderedDict
from dataclasses import dataclass

from .packet import IPPROTO_TCP, TCP_FIN, TCP_RST, TCP_SYN, FlowKey, ParsedPacket

MAX_STREAM_BYTES = 4096
MAX_STREAM_FLOWS = 2048
STREAM_TTL_SECONDS = 5.0
_HEADER_END = b"\r\n\r\n"
_METHOD_PREFIXES = (
    b"GET ", b"POST ", b"PUT ", b"PATCH ", b"DELETE ",
    b"HEAD ", b"OPTIONS ",
)


@dataclass(slots=True)
class _StreamState:
    next_sequence: int
    data: bytearray
    expires_at: float


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
            if _HEADER_END in payload:
                return payload
            if parsed.payload_truncated or len(payload) >= self._max_bytes:
                return None
            self._ensure_capacity(now)
            sequence = parsed.tcp_sequence + (1 if parsed.tcp_flags & TCP_SYN else 0)
            self._flows[key] = _StreamState(
                next_sequence=(sequence + len(payload)) & 0xFFFFFFFF,
                data=bytearray(payload),
                expires_at=now + self._ttl,
            )
            return None

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

        if _HEADER_END not in state.data:
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
