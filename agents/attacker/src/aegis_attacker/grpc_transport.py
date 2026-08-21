"""본선 9000/tcp plaintext gRPC unary 전송.

외부 패키지 없이 PCAP에서 관측된 ``satdiag.v1.SatDiag`` 메서드만 호출한다.
HTTP/2·HPACK·protobuf 전체 구현이 아니라 unary 요청에 필요한 최소 부분만 bounded하게
구현하며, 응답 원문은 로그로 남기지 않고 상위 flag 파이프라인에만 전달한다.
"""

from __future__ import annotations

import gzip
import socket
import time

from .observation import HttpResponse

CLIENT_PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
MAX_GRPC_REQUEST_BYTES = 16 * 1024
MAX_GRPC_RESPONSE_BYTES = 1024 * 1024
DELIVERY_STANDARD = "standard"
DELIVERY_FRAGMENTED = "fragmented"
DELIVERY_FRAGMENTED_HUFFMAN = "fragmented_huffman"
ALLOWED_DELIVERY_MODES = frozenset({
    DELIVERY_STANDARD, DELIVERY_FRAGMENTED, DELIVERY_FRAGMENTED_HUFFMAN,
})

# Health/Probe/Tail은 읽기 전용. Export는 P1-R2에서 flag echo에 쓰인 관측 RPC다.
ALLOWED_GRPC_RPCS = frozenset({
    "/satdiag.v1.SatDiag/Health",
    "/satdiag.v1.SatDiag/ProbeEndpoint",
    "/satdiag.v1.SatDiag/TailDiagnosticLog",
    "/satdiag.v1.SatDiag/ExportDiagnosticBundle",
})
# 하위 호환 별칭 — 기존 테스트·호출부가 READ_ONLY_RPCS를 참조한다.
READ_ONLY_RPCS = ALLOWED_GRPC_RPCS


def _varint(value: int) -> bytes:
    if not isinstance(value, int) or value < 0:
        raise ValueError("protobuf varint는 음이 아닌 정수여야 한다")
    encoded = bytearray()
    while value >= 0x80:
        encoded.append((value & 0x7F) | 0x80)
        value >>= 7
    encoded.append(value)
    return bytes(encoded)


def encode_protobuf(string_fields=None, varint_fields=None) -> bytes:
    """관측된 string·varint 필드만 protobuf wire 형식으로 직렬화한다."""
    message = bytearray()
    for raw_number, value in sorted((string_fields or {}).items(), key=lambda item: int(item[0])):
        number = int(raw_number)
        if not (1 <= number < (1 << 29)) or not isinstance(value, str):
            raise ValueError("잘못된 protobuf string field")
        raw = value.encode("utf-8")
        message.extend(_varint((number << 3) | 2))
        message.extend(_varint(len(raw)))
        message.extend(raw)
    for raw_number, value in sorted((varint_fields or {}).items(), key=lambda item: int(item[0])):
        number = int(raw_number)
        if not (1 <= number < (1 << 29)):
            raise ValueError("잘못된 protobuf varint field")
        message.extend(_varint(number << 3))
        message.extend(_varint(int(value)))
    if len(message) > MAX_GRPC_REQUEST_BYTES:
        raise ValueError("gRPC 요청 protobuf 상한 초과")
    return bytes(message)


def _hpack_integer(value: int, prefix_bits: int, first_bits: int = 0) -> bytes:
    prefix_max = (1 << prefix_bits) - 1
    if value < prefix_max:
        return bytes((first_bits | value,))
    encoded = bytearray((first_bits | prefix_max,))
    value -= prefix_max
    while value >= 128:
        encoded.append((value & 0x7F) | 0x80)
        value >>= 7
    encoded.append(value)
    return bytes(encoded)


def _hpack_string(value: str) -> bytes:
    raw = value.encode("utf-8")
    return _hpack_integer(len(raw), 7) + raw  # Huffman bit 0


def _literal_indexed_name(name_index: int, value: str) -> bytes:
    # Literal Header Field without Indexing — Indexed Name (0000 prefix).
    return _hpack_integer(name_index, 4) + _hpack_string(value)


def _literal_new_name(name: str, value: str) -> bytes:
    return b"\x00" + _hpack_string(name) + _hpack_string(value)


_HUFFMAN_PATH_VALUES = {
    "/satdiag.v1.SatDiag/TailDiagnosticLog": bytes.fromhex(
        "61034c861ccbf70afb869be61ccc6f19a8be61cd51d0931339e6"
    ),
    "/satdiag.v1.SatDiag/ExportDiagnosticBundle": bytes.fromhex(
        "61034c861ccbf70afb869be61ccc60f359ec4df30e6a8e8498976daa4a0b"
    ),
}


def _path_header(rpc: str, huffman: bool) -> bytes:
    encoded = _HUFFMAN_PATH_VALUES.get(rpc) if huffman else None
    if encoded is None:
        return _literal_indexed_name(4, rpc)
    # Literal Header Field with Incremental Indexing, indexed name :path (4),
    # followed by a Huffman-coded string. These exact encodings were accepted in R6.
    return b"\x44" + _hpack_integer(len(encoded), 7, 0x80) + encoded


def _request_headers(host: str, port: int, rpc: str, huffman: bool = False) -> bytes:
    return b"".join((
        b"\x83",  # :method POST, static table index 3
        b"\x86",  # :scheme http, static table index 6
        _path_header(rpc, huffman),
        _literal_indexed_name(1, f"{host}:{port}"),
        _literal_indexed_name(31, "application/grpc"),
        _literal_new_name("te", "trailers"),
    ))


def _frame(frame_type: int, flags: int, stream_id: int, payload: bytes = b"") -> bytes:
    if len(payload) >= (1 << 24):
        raise ValueError("HTTP/2 frame 상한 초과")
    return (len(payload).to_bytes(3, "big")
            + bytes((frame_type, flags))
            + (stream_id & 0x7FFFFFFF).to_bytes(4, "big")
            + payload)


def _recv_exact(connection, size: int):
    chunks = bytearray()
    while len(chunks) < size:
        chunk = connection.recv(size - len(chunks))
        if not chunk:
            return None
        chunks.extend(chunk)
    return bytes(chunks)


def _decode_grpc_messages(data: bytes) -> str:
    parts = []
    offset = 0
    while offset + 5 <= len(data):
        compressed = data[offset]
        length = int.from_bytes(data[offset + 1:offset + 5], "big")
        offset += 5
        if length > MAX_GRPC_RESPONSE_BYTES or offset + length > len(data):
            break
        message = data[offset:offset + length]
        offset += length
        if compressed == 1:
            try:
                message = gzip.decompress(message)
            except (OSError, EOFError):
                continue
        elif compressed != 0:
            continue
        parts.append(message.decode("utf-8", "replace"))
    # 비정상 envelope도 bounded 원문에서 flag 문자열을 놓치지 않되 외부로 로그하지 않는다.
    return "\n".join(parts) if parts else data.decode("utf-8", "replace")


def grpc_unary_request(host: str, port: int, rpc: str, string_fields=None,
                       varint_fields=None, timeout: float = 6.0,
                       delivery: str = DELIVERY_STANDARD) -> HttpResponse:
    """관측된 SatDiag RPC 하나를 h2c unary 요청으로 실행한다."""
    if rpc not in ALLOWED_GRPC_RPCS or delivery not in ALLOWED_DELIVERY_MODES:
        return HttpResponse(0, "", {})
    try:
        message = encode_protobuf(string_fields, varint_fields)
        envelope = b"\x00" + len(message).to_bytes(4, "big") + message
        fragmented = delivery in (DELIVERY_FRAGMENTED, DELIVERY_FRAGMENTED_HUFFMAN)
        huffman = delivery == DELIVERY_FRAGMENTED_HUFFMAN
        data_frames = (
            b"".join(
                _frame(0, 0x01 if index == len(envelope) - 1 else 0, 1, bytes((byte,)))
                for index, byte in enumerate(envelope)
            )
            if fragmented else _frame(0, 0x01, 1, envelope)
        )
        request = b"".join((
            CLIENT_PREFACE,
            _frame(4, 0, 0),  # SETTINGS
            _frame(1, 0x04, 1, _request_headers(host, port, rpc, huffman)),
            data_frames,
        ))
        response_data = bytearray()
        saw_stream = False
        truncated = False
        deadline = time.monotonic() + max(0.1, float(timeout))
        frames_seen = 0
        with socket.create_connection((host, port), timeout=timeout) as connection:
            connection.settimeout(timeout)
            connection.sendall(request)
            while True:
                frames_seen += 1
                if frames_seen > 256:
                    return HttpResponse(0, "", {})
                remaining_time = deadline - time.monotonic()
                if remaining_time <= 0:
                    return HttpResponse(0, "", {})
                connection.settimeout(remaining_time)
                header = _recv_exact(connection, 9)
                if header is None:
                    break
                length = int.from_bytes(header[:3], "big")
                frame_type = header[3]
                flags = header[4]
                stream_id = int.from_bytes(header[5:9], "big") & 0x7FFFFFFF
                if length > MAX_GRPC_RESPONSE_BYTES:
                    return HttpResponse(0, "", {})
                payload = _recv_exact(connection, length)
                if payload is None:
                    return HttpResponse(0, "", {})
                if frame_type == 4 and stream_id == 0 and not (flags & 0x01):
                    connection.sendall(_frame(4, 0x01, 0))  # SETTINGS ACK
                    continue
                if stream_id != 1:
                    continue
                saw_stream = True
                if frame_type == 0:  # DATA
                    if flags & 0x08:  # PADDED
                        if not payload:
                            return HttpResponse(0, "", {})
                        padding = payload[0]
                        if padding + 1 > len(payload):
                            return HttpResponse(0, "", {})
                        payload = payload[1:len(payload) - padding]
                    remaining = MAX_GRPC_RESPONSE_BYTES - len(response_data)
                    response_data.extend(payload[:remaining])
                    if len(payload) > remaining:
                        truncated = True
                    if payload and not (flags & 0x01):
                        increment = min(len(payload), 0x7FFFFFFF)
                        connection.sendall(_frame(8, 0, 0, increment.to_bytes(4, "big")))
                        connection.sendall(_frame(8, 0, 1, increment.to_bytes(4, "big")))
                elif frame_type in (3, 7):  # RST_STREAM / GOAWAY
                    return HttpResponse(0, "", {})
                if flags & 0x01:  # END_STREAM on DATA or trailers HEADERS
                    break
        if not saw_stream:
            return HttpResponse(0, "", {})
        return HttpResponse(
            200,
            _decode_grpc_messages(bytes(response_data)),
            {"Content-Type": "application/grpc"},
            truncated=truncated,
        )
    except (OSError, ValueError, OverflowError):
        return HttpResponse(0, "", {})
