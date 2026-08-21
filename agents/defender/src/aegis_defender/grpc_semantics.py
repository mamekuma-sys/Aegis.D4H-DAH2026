"""Bounded HTTP/2 DATA and gRPC request semantic inspection.

The finals captures contain SatDiag requests whose gRPC envelope was split into
one-byte HTTP/2 DATA frames and whose ``:path`` header used HPACK Huffman coding.
Header-text regexes therefore cannot be the enforcement boundary.  This module
only reconstructs the bounded, in-order client DATA stream and classifies exact
protobuf values observed to retrieve a flag.  Gaps, malformed frames, compression,
and capacity pressure discard state and fail open.
"""

from __future__ import annotations

from collections import OrderedDict
from dataclasses import dataclass, field

from .packet import IPPROTO_TCP, TCP_FIN, TCP_RST, TCP_SYN, FlowKey, ParsedPacket

CLIENT_PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
MAX_H2_FRAME_BYTES = 16 * 1024
MAX_GRPC_MESSAGE_BYTES = 4096
MAX_STREAM_BYTES = 16 * 1024
MAX_STREAM_FLOWS = 2048
STREAM_TTL_SECONDS = 5.0

TAIL_SENSITIVE_FILE = "satdiag-tail-sensitive-file"
EXPORT_FLAG_COMMAND = "satdiag-export-flag-command"


@dataclass(slots=True)
class _GrpcState:
    next_sequence: int
    wire: bytearray
    expires_at: float
    frame_offset: int = 0
    data_streams: dict[int, bytearray] = field(default_factory=dict)


def _read_varint(data: bytes, offset: int) -> tuple[int, int] | None:
    value = 0
    for shift in range(0, 70, 7):
        if offset >= len(data):
            return None
        byte = data[offset]
        offset += 1
        value |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return value, offset
    return None


def _protobuf_fields(message: bytes) -> dict[int, list[bytes | int]] | None:
    """Parse only bounded varint and length-delimited fields."""
    fields: dict[int, list[bytes | int]] = {}
    offset = 0
    while offset < len(message):
        key_result = _read_varint(message, offset)
        if key_result is None:
            return None
        key, offset = key_result
        field_number, wire_type = key >> 3, key & 7
        if not (1 <= field_number < (1 << 29)):
            return None
        if wire_type == 0:
            value_result = _read_varint(message, offset)
            if value_result is None:
                return None
            value, offset = value_result
            fields.setdefault(field_number, []).append(value)
        elif wire_type == 2:
            length_result = _read_varint(message, offset)
            if length_result is None:
                return None
            length, offset = length_result
            if length > MAX_GRPC_MESSAGE_BYTES or offset + length > len(message):
                return None
            fields.setdefault(field_number, []).append(message[offset:offset + length])
            offset += length
        else:
            return None
    return fields


def classify_grpc_message(message: bytes) -> str | None:
    fields = _protobuf_fields(message)
    if not fields:
        return None
    field_one = [value for value in fields.get(1, ()) if isinstance(value, bytes)]
    if not field_one:
        return None
    primary = field_one[0]
    if primary == b"/flag" and any(isinstance(value, int) for value in fields.get(2, ())):
        return TAIL_SENSITIVE_FILE

    lowered = primary.lower()
    flag_references = (b"${flag}", b"$flag", b"/flag", b"printenv flag")
    command_markers = (b";", b"|", b"`", b"$(", b"echo", b"printf", b"cat ")
    if any(token in lowered for token in flag_references) and any(
        token in lowered for token in command_markers
    ):
        return EXPORT_FLAG_COMMAND
    return None


class GrpcH2StreamInspector:
    """Single-owner bounded in-order HTTP/2 client stream inspector."""

    def __init__(
        self,
        max_bytes: int = MAX_STREAM_BYTES,
        max_flows: int = MAX_STREAM_FLOWS,
        ttl_seconds: float = STREAM_TTL_SECONDS,
    ) -> None:
        self._max_bytes = max(len(CLIENT_PREFACE) + 9, int(max_bytes))
        self._max_flows = max(1, int(max_flows))
        self._ttl = max(0.1, float(ttl_seconds))
        self._flows: OrderedDict[FlowKey, _GrpcState] = OrderedDict()

    @property
    def flow_count(self) -> int:
        return len(self._flows)

    def discard(self, flow_key: FlowKey | None) -> None:
        if flow_key is not None:
            self._flows.pop(flow_key, None)

    def _ensure_capacity(self, now: float) -> None:
        while self._flows:
            key = next(iter(self._flows))
            if self._flows[key].expires_at > now and len(self._flows) < self._max_flows:
                break
            self._flows.popitem(last=False)

    def _start(self, parsed: ParsedPacket, now: float) -> _GrpcState | None:
        payload = parsed.payload
        if not CLIENT_PREFACE.startswith(payload) and not payload.startswith(CLIENT_PREFACE):
            return None
        if parsed.payload_truncated or len(payload) > self._max_bytes:
            return None
        self._ensure_capacity(now)
        sequence = parsed.tcp_sequence + (1 if parsed.tcp_flags & TCP_SYN else 0)
        state = _GrpcState(
            next_sequence=(sequence + len(payload)) & 0xFFFFFFFF,
            wire=bytearray(payload),
            expires_at=now + self._ttl,
            frame_offset=len(CLIENT_PREFACE) if payload.startswith(CLIENT_PREFACE) else 0,
        )
        self._flows[parsed.flow_key] = state
        return state

    def _consume_frames(self, state: _GrpcState) -> str | None:
        if len(state.wire) < len(CLIENT_PREFACE):
            return None
        if bytes(state.wire[:len(CLIENT_PREFACE)]) != CLIENT_PREFACE:
            return None
        if state.frame_offset < len(CLIENT_PREFACE):
            state.frame_offset = len(CLIENT_PREFACE)

        while len(state.wire) - state.frame_offset >= 9:
            offset = state.frame_offset
            length = int.from_bytes(state.wire[offset:offset + 3], "big")
            frame_type = state.wire[offset + 3]
            flags = state.wire[offset + 4]
            stream_id = int.from_bytes(state.wire[offset + 5:offset + 9], "big") & 0x7FFFFFFF
            if length > MAX_H2_FRAME_BYTES:
                return None
            frame_end = offset + 9 + length
            if frame_end > len(state.wire):
                return None
            frame_payload = bytes(state.wire[offset + 9:frame_end])
            state.frame_offset = frame_end
            if frame_type != 0 or stream_id == 0:
                continue
            if flags & 0x08:  # PADDED
                if not frame_payload or frame_payload[0] >= len(frame_payload):
                    return None
                frame_payload = frame_payload[1:len(frame_payload) - frame_payload[0]]
            grpc_data = state.data_streams.setdefault(stream_id, bytearray())
            if len(grpc_data) + len(frame_payload) > MAX_GRPC_MESSAGE_BYTES + 5:
                return None
            grpc_data.extend(frame_payload)
            while len(grpc_data) >= 5:
                if grpc_data[0] != 0:  # compressed/unknown messages fail open
                    return None
                message_length = int.from_bytes(grpc_data[1:5], "big")
                if message_length > MAX_GRPC_MESSAGE_BYTES:
                    return None
                total = 5 + message_length
                if len(grpc_data) < total:
                    break
                message = bytes(grpc_data[5:total])
                del grpc_data[:total]
                semantic = classify_grpc_message(message)
                if semantic is not None:
                    return semantic
        return None

    def feed(self, parsed: ParsedPacket, now: float) -> str | None:
        if (
            not parsed.ok
            or parsed.protocol != IPPROTO_TCP
            or parsed.dst_port != 9000
            or parsed.flow_key is None
        ):
            return None
        key = parsed.flow_key
        state = self._flows.get(key)
        if parsed.tcp_flags & (TCP_FIN | TCP_RST):
            self._flows.pop(key, None)
            return None
        if state is not None and (state.expires_at <= now or parsed.tcp_flags & TCP_SYN):
            self._flows.pop(key, None)
            state = None
        if not parsed.payload:
            return None
        if state is None:
            state = self._start(parsed, now)
            if state is None:
                return None
        else:
            sequence = parsed.tcp_sequence + (1 if parsed.tcp_flags & TCP_SYN else 0)
            expected = state.next_sequence
            if sequence == expected:
                suffix = parsed.payload
            elif sequence < expected:
                overlap = expected - sequence
                if overlap >= len(parsed.payload):
                    state.expires_at = now + self._ttl
                    self._flows.move_to_end(key)
                    return None
                suffix = parsed.payload[overlap:]
            else:
                self._flows.pop(key, None)
                return None
            if len(state.wire) + len(suffix) > self._max_bytes:
                self._flows.pop(key, None)
                return None
            state.wire.extend(suffix)
            state.next_sequence = (expected + len(suffix)) & 0xFFFFFFFF
            state.expires_at = now + self._ttl
            self._flows.move_to_end(key)

        semantic = self._consume_frames(state)
        if semantic is not None:
            self._flows.pop(key, None)
        return semantic
