"""L3 MQTT(1883) 최소 클라이언트 — CONNECT + SUBSCRIBE 후 PUBLISH 수집.

외부 패키지 없이 MQTT 3.1.1 CONNECT/SUBSCRIBE만 bounded로 보낸다. 응답 원문은
로그에 남기지 않고 flag 파이프라인에만 넘긴다.
"""

from __future__ import annotations

import socket
import struct

from .observation import HttpResponse

MAX_MQTT_RESPONSE_BYTES = 256 * 1024
DEFAULT_CLIENT_ID = "aegis-l3"
DEFAULT_KEEPALIVE = 30


def _remaining_length(value: int) -> bytes:
    if value < 0 or value > 268_435_455:
        raise ValueError("MQTT remaining length 범위 밖")
    encoded = bytearray()
    while True:
        byte = value % 128
        value //= 128
        if value > 0:
            byte |= 0x80
        encoded.append(byte)
        if value == 0:
            break
    return bytes(encoded)


def _encode_string(value: str) -> bytes:
    raw = value.encode("utf-8")
    if len(raw) > 65535:
        raise ValueError("MQTT 문자열 상한 초과")
    return struct.pack("!H", len(raw)) + raw


def build_connect(client_id: str = DEFAULT_CLIENT_ID, keepalive: int = DEFAULT_KEEPALIVE) -> bytes:
    variable = (
        _encode_string("MQTT")
        + bytes((0x04, 0x02))  # level 4, clean session
        + struct.pack("!H", int(keepalive))
        + _encode_string(client_id)
    )
    return bytes((0x10,)) + _remaining_length(len(variable)) + variable


def build_subscribe(packet_id: int, topics: list[str]) -> bytes:
    if not (1 <= packet_id <= 65535):
        raise ValueError("MQTT packet id 범위 밖")
    payload = struct.pack("!H", packet_id)
    for topic in topics:
        payload += _encode_string(topic) + bytes((0x00,))  # QoS 0
    return bytes((0x82,)) + _remaining_length(len(payload)) + payload


def mqtt_subscribe_collect(
    host: str,
    port: int,
    topics: list[str],
    timeout: float = 4.0,
    max_bytes: int = MAX_MQTT_RESPONSE_BYTES,
) -> HttpResponse:
    """CONNECT→SUBSCRIBE 후 수신 바이트를 모아 본문으로 반환한다."""
    wait = max(0.2, min(float(timeout), 12.0))
    limit = max(64, min(int(max_bytes), MAX_MQTT_RESPONSE_BYTES))
    request = build_connect() + build_subscribe(1, list(topics)[:16])
    try:
        with socket.create_connection((host, port), timeout=wait) as connection:
            connection.settimeout(wait)
            connection.sendall(request)
            chunks = bytearray()
            while len(chunks) < limit:
                try:
                    piece = connection.recv(min(8192, limit - len(chunks) + 1))
                except OSError:
                    break
                if not piece:
                    break
                chunks.extend(piece)
                if len(chunks) > limit:
                    break
        if not chunks:
            return HttpResponse(0, "", {})
        body = bytes(chunks[:limit]).decode("utf-8", "replace")
        return HttpResponse(200, body, {"Content-Type": "application/mqtt"}, truncated=len(chunks) > limit)
    except OSError:
        return HttpResponse(0, "", {})
