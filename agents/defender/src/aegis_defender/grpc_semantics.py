"""Bounded HTTP/2 DATA and gRPC request semantic inspection.

The finals captures contain SatDiag requests whose gRPC envelope was split into
one-byte HTTP/2 DATA frames and whose ``:path`` header used HPACK Huffman coding.
Header-text regexes therefore cannot be the enforcement boundary.  This module
only reconstructs a bounded client DATA stream and classifies exact protobuf values
observed to retrieve a flag.  A small out-of-order window handles ordinary TCP
reordering without waiting in the packet verdict path.  Malformed frames,
compression, and capacity pressure discard state and fail open.
"""

from __future__ import annotations

import base64
import json
import pickletools
from collections import OrderedDict
from dataclasses import dataclass, field

from .packet import IPPROTO_TCP, TCP_FIN, TCP_RST, TCP_SYN, FlowKey, ParsedPacket

CLIENT_PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
MAX_H2_FRAME_BYTES = 16 * 1024
MAX_GRPC_MESSAGE_BYTES = 4096
MAX_STREAM_BYTES = 16 * 1024
MAX_STREAM_FLOWS = 2048
STREAM_TTL_SECONDS = 5.0
MAX_REORDER_SEGMENTS = 8
MAX_REORDER_SPAN_BYTES = 16 * 1024

TAIL_SENSITIVE_FILE = "satdiag-tail-sensitive-file"
EXPORT_FLAG_COMMAND = "satdiag-export-flag-command"
L4_DIAGNOSTIC_MAP_SNAPSHOT = "l4-diagnostic-map-snapshot"
L4_CALIBRATION_PICKLE_CODE = "l4-calibration-pickle-code"
L4_PROGRAMMING_SECRET_SOURCE = "l4-programming-secret-source"
L4_SERVER_REFLECTION = "l4-server-reflection"
L4_GET_CATALOG = "l4-get-catalog"
L4_PORTS = frozenset({8410, 8420})
GRPC_PORTS = frozenset({9000}) | L4_PORTS

_DANGEROUS_PICKLE_OPCODES = frozenset({
    "EXT1", "EXT2", "EXT4", "GLOBAL", "INST", "NEWOBJ", "NEWOBJ_EX",
    "OBJ", "PERSID", "BINPERSID", "REDUCE", "STACK_GLOBAL",
})
_SECRET_SOURCE_MARKERS = (
    b"/flag", b"flag{", b"os.environ", b"os.getenv", b"subprocess",
    b"__import__", b"open(", b"read_text", b"read_bytes", b"printenv",
    b"cat ", b"pathlib.path",
)
_L4_REFLECTION_PATHS = (
    b"/grpc.reflection.v1.ServerReflection/ServerReflectionInfo",
    b"/grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo",
)
_L4_GET_CATALOG_PATH = b"/g2dds.v1.Layer4Service/GetCatalog"


@dataclass(slots=True)
class _GrpcState:
    next_sequence: int
    wire: bytearray
    expires_at: float
    dst_port: int
    frame_offset: int = 0
    data_streams: dict[int, bytearray] = field(default_factory=dict)
    pending: list[tuple[int, bytes]] = field(default_factory=list)


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


def _first_int(fields: dict[int, list[bytes | int]], number: int) -> int | None:
    return next((value for value in fields.get(number, ()) if isinstance(value, int)), None)


def _first_bytes(fields: dict[int, list[bytes | int]], number: int) -> bytes | None:
    return next((value for value in fields.get(number, ()) if isinstance(value, bytes)), None)


def _decode_l4_envelope(
    fields: dict[int, list[bytes | int]],
) -> tuple[int, int, bytes] | None:
    """Decode the three observed Exchange encodings without protobuf imports."""
    encoded = _first_bytes(fields, 4)
    if encoded is None:
        return None
    encoding = _first_int(fields, 3) or 0
    if encoding == 1:
        try:
            encoded = base64.b64decode(encoded, validate=True)
        except (ValueError, TypeError):
            return None
    elif encoding == 2:
        try:
            document = json.loads(encoded.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return None
        if not isinstance(document, dict):
            return None
        topic_id = document.get("topicId")
        type_id = document.get("typeId")
        sample_text = document.get("sample")
        if (
            not isinstance(topic_id, int) or isinstance(topic_id, bool)
            or not isinstance(type_id, int) or isinstance(type_id, bool)
            or not isinstance(sample_text, str)
        ):
            return None
        try:
            sample = base64.b64decode(sample_text, validate=True)
        except (ValueError, TypeError):
            return None
        if len(sample) > MAX_GRPC_MESSAGE_BYTES:
            return None
        return topic_id, type_id, sample
    elif encoding != 0:
        return None

    envelope = _protobuf_fields(encoded)
    if not envelope:
        return None
    topic_id = _first_int(envelope, 3)
    type_id = _first_int(envelope, 4)
    sample = _first_bytes(envelope, 7)
    if topic_id is None or type_id is None or sample is None:
        return None
    return topic_id, type_id, sample


def _pickle_has_code_execution(blob: bytes) -> bool:
    """Inspect opcodes only.  Never unpickle attacker-controlled bytes."""
    try:
        return any(
            opcode.name in _DANGEROUS_PICKLE_OPCODES
            for opcode, _, _ in pickletools.genops(blob)
        )
    except (ValueError, UnicodeDecodeError):
        return False


def _classify_l4_exchange(fields: dict[int, list[bytes | int]]) -> str | None:
    decoded = _decode_l4_envelope(fields)
    if decoded is None:
        return None
    topic_id, type_id, sample = decoded
    sample_fields = _protobuf_fields(sample)
    if not sample_fields:
        return None

    # Exact topic/type pairs are from the R11 GetCatalog/Exchange wire contract.
    if (topic_id, type_id) == (65536, 4097):
        if _first_int(sample_fields, 1) == 4:
            return L4_DIAGNOSTIC_MAP_SNAPSHOT
        return None

    if (topic_id, type_id) == (393216, 16384):
        apply_requested = _first_int(sample_fields, 5) == 1
        pickle_format = _first_int(sample_fields, 3) == 1
        blob = _first_bytes(sample_fields, 4)
        if apply_requested and pickle_format and blob and _pickle_has_code_execution(blob):
            return L4_CALIBRATION_PICKLE_CODE
        return None

    if (topic_id, type_id) == (655360, 28672):
        if _first_int(sample_fields, 2) != 1002:  # STORE; RUN is 1003.
            return None
        source = _first_bytes(sample_fields, 6)
        if source and any(marker in source.lower() for marker in _SECRET_SOURCE_MARKERS):
            return L4_PROGRAMMING_SECRET_SOURCE
    return None


def classify_grpc_message(message: bytes, dst_port: int = 9000) -> str | None:
    fields = _protobuf_fields(message)
    if not fields:
        return None
    if dst_port in L4_PORTS:
        return _classify_l4_exchange(fields)
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


def classify_grpc_headers(header_block: bytes) -> str | None:
    """Classify exact literal paths; unsupported HPACK forms fail open."""
    if any(path in header_block for path in _L4_REFLECTION_PATHS):
        return L4_SERVER_REFLECTION
    if _L4_GET_CATALOG_PATH in header_block:
        return L4_GET_CATALOG
    return None


class GrpcH2StreamInspector:
    """Single-owner bounded HTTP/2 client stream inspector."""

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
            dst_port=parsed.dst_port,
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
            if frame_type == 1 and stream_id != 0:  # HEADERS
                if flags & 0x08:  # PADDED
                    if not frame_payload or frame_payload[0] >= len(frame_payload):
                        return None
                    frame_payload = frame_payload[1:len(frame_payload) - frame_payload[0]]
                if flags & 0x20:  # PRIORITY
                    if len(frame_payload) < 5:
                        return None
                    frame_payload = frame_payload[5:]
                semantic = classify_grpc_headers(frame_payload)
                if semantic is not None:
                    return semantic
                continue
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
                semantic = classify_grpc_message(message, state.dst_port)
                if semantic is not None:
                    return semantic
        return None

    @staticmethod
    def _signed_delta(value: int, base: int) -> int:
        delta = (value - base) & 0xFFFFFFFF
        return delta - 0x100000000 if delta & 0x80000000 else delta

    def _append_payload(self, state: _GrpcState, sequence: int, payload: bytes) -> bool:
        delta = self._signed_delta(sequence, state.next_sequence)
        if delta > 0:
            return False
        overlap = -delta
        if overlap >= len(payload):
            return True
        suffix = payload[overlap:]
        if len(state.wire) + len(suffix) > self._max_bytes:
            return False
        state.wire.extend(suffix)
        state.next_sequence = (state.next_sequence + len(suffix)) & 0xFFFFFFFF
        return True

    def _drain_pending(self, state: _GrpcState) -> bool:
        while state.pending:
            state.pending.sort(key=lambda item: self._signed_delta(item[0], state.next_sequence))
            sequence, payload = state.pending[0]
            if self._signed_delta(sequence, state.next_sequence) > 0:
                break
            state.pending.pop(0)
            if not self._append_payload(state, sequence, payload):
                return False
        return True

    def feed(self, parsed: ParsedPacket, now: float) -> str | None:
        if (
            not parsed.ok
            or parsed.protocol != IPPROTO_TCP
            or parsed.dst_port not in GRPC_PORTS
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
            gap = self._signed_delta(sequence, expected)
            if gap > 0:
                pending_bytes = sum(len(payload) for _, payload in state.pending)
                duplicate = any(
                    pending_sequence == sequence and pending_payload == parsed.payload
                    for pending_sequence, pending_payload in state.pending
                )
                if (
                    gap > MAX_REORDER_SPAN_BYTES
                    or len(state.pending) >= MAX_REORDER_SEGMENTS
                    or pending_bytes + len(parsed.payload) > self._max_bytes
                ):
                    self._flows.pop(key, None)
                    return None
                if not duplicate:
                    state.pending.append((sequence, parsed.payload))
                state.expires_at = now + self._ttl
                self._flows.move_to_end(key)
                return None
            if not self._append_payload(state, sequence, parsed.payload):
                self._flows.pop(key, None)
                return None
            if not self._drain_pending(state):
                self._flows.pop(key, None)
                return None
            state.expires_at = now + self._ttl
            self._flows.move_to_end(key)

        semantic = self._consume_frames(state)
        if semantic is not None:
            self._flows.pop(key, None)
        return semantic
