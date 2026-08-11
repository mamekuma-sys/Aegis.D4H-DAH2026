"""관측 수집과 정규화.

설계 §9.7. HTTP 전송을 주입 가능하게 하여(네트워크 없이 테스트) 배너·응답을 증거로
정규화한다. timeout·연결거부·비정상 응답은 실패가 아니라 관측(status=0 포함)으로 기록한다.
본문·요청은 fingerprint(단방향 해시)로만 로그·식별한다(운영세칙 제23·24조).
"""

from __future__ import annotations

import hashlib
import socket
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field

from .models import Endpoint, Observation

# 관측 시 주목하는 응답 헤더(스켈레톤 agent-guide 관측 관례).
NOTABLE_HEADERS = (
    "x-role", "x-user", "x-username", "role", "x-admin", "set-cookie",
    "www-authenticate", "location", "server", "x-powered-by", "x-flag",
)


def fingerprint(text: str, length: int = 16) -> str:
    """본문·요청의 비민감 단방향 지문. 원문 대신 로그·중복 식별에 쓴다."""
    return hashlib.sha256((text or "").encode("utf-8", "replace")).hexdigest()[:length]


def notable_headers(headers) -> dict:
    return {k: v for k, v in (headers or {}).items() if k.lower() in NOTABLE_HEADERS}


@dataclass
class HttpResponse:
    status: int  # 0 = 응답 없음(연결거부/timeout/필터 DROP)
    body: str = ""
    headers: dict = field(default_factory=dict)


class UrllibHttp:
    """표준 라이브러리 urllib 기반 HTTP 전송."""

    def request(self, method: str, url: str, headers=None, body=None,
                timeout: float = 6.0) -> HttpResponse:
        data = body.encode() if isinstance(body, str) else body
        req = urllib.request.Request(url, data=data, method=method)
        for k, v in (headers or {}).items():
            req.add_header(k, v)
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return HttpResponse(getattr(r, "status", 200),
                                    r.read().decode("utf-8", "replace"),
                                    dict(r.headers.items()))
        except urllib.error.HTTPError as e:
            try:
                text = e.read().decode("utf-8", "replace")
            except Exception:
                text = ""
            return HttpResponse(e.code, text, dict(e.headers.items()) if e.headers else {})
        except Exception:
            # timeout·연결거부·필터 DROP 모두 status 0 관측으로 수렴
            return HttpResponse(0, "", {})


def port_open(host: str, port: int, timeout: float = 2.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


class Observer:
    """rate limit을 지키며 표적을 관측한다."""

    def __init__(self, http, rate, clock=time.monotonic):
        self._http = http
        self._rate = rate
        self._clock = clock

    def observe(self, endpoint: Endpoint, method: str = "GET", path: str = "/",
                headers=None, body=None, timeout: float = 6.0):
        """(Observation, HttpResponse) 반환. 원시 응답 본문은 로그로 남기지 않는다."""
        self._rate.acquire_request()
        start = self._clock()
        resp = self._http.request(method, endpoint.base_url() + path, headers, body, timeout)
        latency_ms = (self._clock() - start) * 1000.0
        obs = Observation(
            endpoint=endpoint,
            request_fingerprint=fingerprint(f"{method} {path}"),
            status=resp.status,
            header_hints=notable_headers(resp.headers),
            body_fingerprint=fingerprint(resp.body),
            latency_ms=latency_ms,
            note="no-response" if resp.status == 0 else "",
        )
        return obs, resp

    def observe_banner(self, endpoint: Endpoint, timeout: float = 6.0):
        """기초 관측: GET / 배너."""
        return self.observe(endpoint, "GET", "/", timeout=timeout)
