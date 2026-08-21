"""L3 MQTT/RTSP의 bounded read-only 전송.

대시보드로 확인된 1883/MQTT와 8554/RTSP만 다룬다. MQTT는 CONNECT와
SUBSCRIBE만, RTSP는 OPTIONS와 DESCRIBE만 허용하며 publish·play·제어 명령은
만들지 않는다. 모든 read는 시간·크기 상한을 가진다.
"""

from __future__ import annotations

import socket
import time

from .observation import HttpResponse, MAX_RESPONSE_BYTES

MQTT_PORT = 1883
RTSP_PORT = 8554
MQTT_READ_TOPICS = (
    "#", "$SYS/#",
    "flag/#", "flags/#", "FLAG/#",
    "uav/#", "drone/#", "mavlink/#", "telemetry/#",
    "mission/#", "command/#", "status/#", "secret/#",
    "+/flag", "uav/+/flag", "drone/+/telemetry",
)
RTSP_READ_METHODS = frozenset({"OPTIONS", "DESCRIBE"})
_RTSP_BASE_PATHS = (
    "/", "/stream", "/live", "/video", "/cam", "/camera", "/uav",
    "/drone", "/flag", "/secret", "/0", "/1", "/track1", "/media",
    "/rtsp",
)
RTSP_DISCOVERY_PATHS = tuple(dict.fromkeys(
    path for base in _RTSP_BASE_PATHS
    for path in (base, base.rstrip("/") + "/flag")
))
_MAX_PROTOCOL_BYTES = min(MAX_RESPONSE_BYTES, 128 * 1024)


def _mqtt_varint(value: int) -> bytes:
    if not 0 <= value <= 268_435_455:
        raise ValueError("MQTT remaining length 범위 밖")
    encoded = bytearray()
    while True:
        digit = value % 128
        value //= 128
        if value:
            digit |= 0x80
        encoded.append(digit)
        if not value:
            return bytes(encoded)


def _mqtt_utf8(value: str) -> bytes:
    raw = value.encode("utf-8")
    if not raw or len(raw) > 65535 or "\x00" in value:
        raise ValueError("MQTT 문자열 범위 밖")
    return len(raw).to_bytes(2, "big") + raw


def _mqtt_connect(client_id: str) -> bytes:
    variable = b"\x00\x04MQTT\x04\x02\x00\x05"  # 3.1.1, clean session, 5s
    payload = _mqtt_utf8(client_id)
    return b"\x10" + _mqtt_varint(len(variable) + len(payload)) + variable + payload


def _mqtt_subscribe(topics: tuple[str, ...]) -> bytes:
    payload = b"".join(_mqtt_utf8(topic) + b"\x00" for topic in topics)
    body = b"\x00\x01" + payload
    return b"\x82" + _mqtt_varint(len(body)) + body


def _read_bounded(connection, timeout: float, *, first_only: bool = False) -> bytes:
    deadline = time.monotonic() + max(0.05, min(timeout, 6.0))
    chunks = bytearray()
    while len(chunks) <= _MAX_PROTOCOL_BYTES:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        connection.settimeout(min(remaining, 0.35))
        try:
            chunk = connection.recv(min(8192, _MAX_PROTOCOL_BYTES + 1 - len(chunks)))
        except (TimeoutError, socket.timeout):
            break
        if not chunk:
            break
        chunks.extend(chunk)
        if first_only:
            break
    return bytes(chunks[:_MAX_PROTOCOL_BYTES])


def mqtt_read_request(host: str, port: int, topics=(), timeout: float = 3.0) -> HttpResponse:
    """MQTT CONNECT 후 선택적으로 wildcard read subscription을 한 번 수행한다."""
    normalized = tuple(dict.fromkeys(str(topic) for topic in (topics or ())))
    if port != MQTT_PORT or any(topic not in MQTT_READ_TOPICS for topic in normalized):
        return HttpResponse(0, "", {})
    client_id = "aegis-readonly"
    try:
        with socket.create_connection((host, port), timeout=min(timeout, 3.0)) as connection:
            connection.sendall(_mqtt_connect(client_id))
            connack = _read_bounded(connection, timeout, first_only=True)
            if not connack:
                return HttpResponse(0, "", {})
            status = 200
            if len(connack) >= 4 and connack[0] >> 4 == 2 and connack[3] != 0:
                status = 403
            payload = bytearray(connack)
            if normalized and status == 200:
                connection.sendall(_mqtt_subscribe(normalized))
                payload.extend(_read_bounded(connection, timeout))
        return HttpResponse(
            status,
            bytes(payload).decode("utf-8", "replace"),
            {"X-Aegis-Protocol": "mqtt"},
            truncated=len(payload) >= _MAX_PROTOCOL_BYTES,
        )
    except (OSError, ValueError):
        return HttpResponse(0, "", {})


def rtsp_read_request(host: str, port: int, method: str, path: str,
                      timeout: float = 3.0) -> HttpResponse:
    """RTSP OPTIONS 또는 DESCRIBE 요청 하나를 새 연결에서 실행한다."""
    normalized_method = str(method).upper()
    if port != RTSP_PORT or normalized_method not in RTSP_READ_METHODS:
        return HttpResponse(0, "", {})
    if normalized_method == "OPTIONS":
        if path != "*":
            return HttpResponse(0, "", {})
        target = "*"
    else:
        if path not in RTSP_DISCOVERY_PATHS:
            return HttpResponse(0, "", {})
        target = f"rtsp://{host}:{port}{path}"
    request = (
        f"{normalized_method} {target} RTSP/1.0\r\n"
        "CSeq: 1\r\n"
        "User-Agent: Aegis-readonly/1\r\n"
        "Accept: application/sdp\r\n\r\n"
    ).encode("ascii")
    try:
        with socket.create_connection((host, port), timeout=min(timeout, 3.0)) as connection:
            connection.sendall(request)
            raw = _read_bounded(connection, timeout)
        if not raw:
            return HttpResponse(0, "", {})
        first_line = raw.split(b"\r\n", 1)[0].decode("ascii", "replace")
        parts = first_line.split()
        status = int(parts[1]) if len(parts) >= 2 and parts[1].isdigit() else 200
        return HttpResponse(
            status,
            raw.decode("utf-8", "replace"),
            {"X-Aegis-Protocol": "rtsp"},
            truncated=len(raw) >= _MAX_PROTOCOL_BYTES,
        )
    except OSError:
        return HttpResponse(0, "", {})
