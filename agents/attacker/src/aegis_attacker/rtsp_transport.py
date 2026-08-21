"""L3 RTSP(8554) 최소 클라이언트 — OPTIONS/DESCRIBE bounded probe.

외부 패키지 없이 RTSP/1.0 텍스트 요청만 보낸다. SDP·응답 원문은 로그에 남기지
않고 flag 파이프라인에만 전달한다.
"""

from __future__ import annotations

import socket

from .observation import HttpResponse

MAX_RTSP_RESPONSE_BYTES = 256 * 1024


def build_rtsp_request(method: str, url: str, cseq: int, extra_headers=None) -> bytes:
    lines = [
        f"{method} {url} RTSP/1.0",
        f"CSeq: {int(cseq)}",
        "User-Agent: aegis-l3",
    ]
    for key, value in (extra_headers or {}).items():
        lines.append(f"{key}: {value}")
    lines.append("")
    lines.append("")
    return "\r\n".join(lines).encode("ascii", "ignore")


def rtsp_exchange(
    host: str,
    port: int,
    method: str,
    path: str,
    cseq: int = 1,
    timeout: float = 4.0,
    max_bytes: int = MAX_RTSP_RESPONSE_BYTES,
    extra_headers=None,
) -> HttpResponse:
    """단일 RTSP 요청을 보내고 응답 텍스트를 회수한다."""
    wait = max(0.2, min(float(timeout), 12.0))
    limit = max(64, min(int(max_bytes), MAX_RTSP_RESPONSE_BYTES))
    if path == "*":
        url = "*"
    else:
        path = path if path.startswith("/") else "/" + path
        url = f"rtsp://{host}:{int(port)}{path}"
    request = build_rtsp_request(method, url, cseq, extra_headers=extra_headers)
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
                if b"\r\n\r\n" in chunks and method.upper() == "OPTIONS":
                    # OPTIONS는 헤더만으로 충분한 경우가 많다.
                    break
                if len(chunks) > limit:
                    break
        if not chunks:
            return HttpResponse(0, "", {})
        text = bytes(chunks[:limit]).decode("utf-8", "replace")
        status = 200 if text.startswith("RTSP/1.") else 200
        first = text.split("\r\n", 1)[0]
        if first.startswith("RTSP/1.") and " " in first:
            try:
                status = int(first.split(" ", 2)[1])
            except ValueError:
                status = 200
        return HttpResponse(
            status,
            text,
            {"Content-Type": "application/rtsp"},
            truncated=len(chunks) > limit,
        )
    except OSError:
        return HttpResponse(0, "", {})
