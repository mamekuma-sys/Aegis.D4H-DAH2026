"""Minimal bounded RFC6455 client for the observed L2 mission feed."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import socket
import time

from .observation import HttpResponse, MAX_RESPONSE_BYTES

MISSION_FEED_PATH = "/ws/mission-feed"
MAX_HANDSHAKE_BYTES = 8192
MAX_FRAME_BYTES = 1024 * 1024
MAX_MESSAGES = 64
_GUID = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


def _recv_exact(connection, size: int) -> bytes | None:
    data = bytearray()
    while len(data) < size:
        chunk = connection.recv(size - len(data))
        if not chunk:
            return None
        data.extend(chunk)
    return bytes(data)


def _client_frame(payload: bytes, opcode: int = 1) -> bytes:
    if len(payload) > 65535:
        raise ValueError("WebSocket client frame too large")
    mask = os.urandom(4)
    if len(payload) < 126:
        header = bytes((0x80 | opcode, 0x80 | len(payload)))
    else:
        header = bytes((0x80 | opcode, 0x80 | 126)) + len(payload).to_bytes(2, "big")
    masked = bytes(byte ^ mask[index % 4] for index, byte in enumerate(payload))
    return header + mask + masked


def _buffered_recv_exact(connection, size: int, buffered: bytearray) -> bytes | None:
    data = bytearray()
    if buffered:
        take = min(size, len(buffered))
        data.extend(buffered[:take])
        del buffered[:take]
    if len(data) < size:
        suffix = _recv_exact(connection, size - len(data))
        if suffix is None:
            return None
        data.extend(suffix)
    return bytes(data)


def _server_frame(connection, buffered: bytearray) -> tuple[int, bytes] | None:
    header = _buffered_recv_exact(connection, 2, buffered)
    if header is None:
        return None
    opcode = header[0] & 0x0F
    masked = bool(header[1] & 0x80)
    length = header[1] & 0x7F
    if length == 126:
        raw = _buffered_recv_exact(connection, 2, buffered)
        if raw is None:
            return None
        length = int.from_bytes(raw, "big")
    elif length == 127:
        raw = _buffered_recv_exact(connection, 8, buffered)
        if raw is None:
            return None
        length = int.from_bytes(raw, "big")
    if length > MAX_FRAME_BYTES:
        return None
    mask = _buffered_recv_exact(connection, 4, buffered) if masked else None
    payload = _buffered_recv_exact(connection, length, buffered)
    if payload is None:
        return None
    if mask is not None:
        payload = bytes(byte ^ mask[index % 4] for index, byte in enumerate(payload))
    return opcode, payload


def mission_feed_request(
    host: str,
    port: int,
    path: str,
    session_token: str,
    timeout: float = 6.0,
) -> HttpResponse:
    """Authenticate with a fresh guest session and request the admin fleet snapshot."""
    if path != MISSION_FEED_PATH or not session_token:
        return HttpResponse(0, "", {})
    try:
        key = base64.b64encode(os.urandom(16)).decode("ascii")
        request = (
            f"GET {path} HTTP/1.1\r\nHost: {host}:{port}\r\n"
            "Upgrade: websocket\r\nConnection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n"
        ).encode("ascii")
        deadline = time.monotonic() + max(0.1, float(timeout))
        with socket.create_connection((host, port), timeout=timeout) as connection:
            connection.settimeout(timeout)
            connection.sendall(request)
            handshake = bytearray()
            while b"\r\n\r\n" not in handshake:
                if len(handshake) >= MAX_HANDSHAKE_BYTES:
                    return HttpResponse(0, "", {})
                chunk = connection.recv(min(1024, MAX_HANDSHAKE_BYTES - len(handshake)))
                if not chunk:
                    return HttpResponse(0, "", {})
                handshake.extend(chunk)
            header, _, remainder = bytes(handshake).partition(b"\r\n\r\n")
            buffered = bytearray(remainder)
            lines = header.split(b"\r\n")
            if not lines or b" 101 " not in lines[0]:
                return HttpResponse(0, "", {})
            headers = {}
            for line in lines[1:]:
                name, separator, value = line.partition(b":")
                if separator:
                    headers[name.strip().lower()] = value.strip()
            expected = base64.b64encode(hashlib.sha1(key.encode("ascii") + _GUID).digest())
            if headers.get(b"sec-websocket-accept") != expected:
                return HttpResponse(0, "", {})

            auth = json.dumps(
                {"type": "auth", "token": session_token}, separators=(",", ":")
            ).encode("utf-8")
            connection.sendall(_client_frame(auth))
            messages = []
            response_bytes = 0
            requested = False
            for _ in range(MAX_MESSAGES):
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                connection.settimeout(remaining)
                frame = _server_frame(connection, buffered)
                if frame is None:
                    break
                opcode, payload = frame
                if opcode == 8:
                    break
                if opcode == 9:
                    connection.sendall(_client_frame(payload, opcode=10))
                    continue
                if opcode != 1:
                    continue
                response_bytes += len(payload)
                if response_bytes > MAX_RESPONSE_BYTES:
                    return HttpResponse(
                        101,
                        "\n".join(messages),
                        {"Upgrade": "websocket"},
                        truncated=True,
                    )
                text = payload.decode("utf-8", "replace")
                messages.append(text)
                if not requested and '"auth_ok"' in text:
                    command = json.dumps(
                        {"type": "admin_fleet_request"}, separators=(",", ":")
                    ).encode("utf-8")
                    connection.sendall(_client_frame(command))
                    requested = True
                if "FLAG{" in text:
                    break
            return HttpResponse(
                101, "\n".join(messages), {"Upgrade": "websocket"},
                truncated=len(messages) >= MAX_MESSAGES,
            )
    except (OSError, ValueError, OverflowError):
        return HttpResponse(0, "", {})
