"""관측 수집과 정규화.

설계 §9.7. HTTP 전송을 주입 가능하게 하여(네트워크 없이 테스트) 배너·응답을 증거로
정규화한다. timeout·연결거부·비정상 응답은 실패가 아니라 관측(status=0 포함)으로 기록한다.
본문·요청은 fingerprint(단방향 해시)로만 로그·식별한다(운영세칙 제23·24조).
"""

from __future__ import annotations

import hashlib
import socket
import ssl
import threading
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field

from .models import Capability, Endpoint, EvidenceRef, Observation

# 관측 시 주목하는 응답 헤더(스켈레톤 agent-guide 관측 관례).
NOTABLE_HEADERS = (
    "x-role", "x-user", "x-username", "role", "x-admin", "set-cookie",
    "www-authenticate", "location", "server", "x-powered-by", "x-flag",
)

# 공격 대상은 신뢰 경계 밖이다. Content-Length가 없거나 거짓이어도 한 응답이
# 컨테이너 메모리와 LLM prompt를 무제한 점유하지 못하도록 실제 read를 제한한다.
MAX_RESPONSE_BYTES = 1024 * 1024
MAX_PASSIVE_BANNER_BYTES = 4096
PASSIVE_BANNER_TIMEOUT = 0.75


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
    truncated: bool = False


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """리다이렉트를 따라가지 않는다(§9.10). 3xx는 관측 결과로 반환된다."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class UrllibHttp:
    """표준 라이브러리 urllib 기반 HTTP 전송. 프록시 비활성·리다이렉트 미추적(§9.10)."""

    def __init__(self):
        # 환경 프록시 비활성(ProxyHandler({})) + 리다이렉트 미추적.
        self._opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}), _NoRedirect())
        # 경기 대상은 self-signed 인증서를 사용할 수 있다. 이 opener는
        # ATTACK_TARGET 전용이며 제출·LLM에는 절대 사용하지 않는다.
        self._target_opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}),
            urllib.request.HTTPSHandler(context=ssl._create_unverified_context()),
            _NoRedirect(),
        )

    def request(self, method: str, url: str, headers=None, body=None,
                timeout: float = 6.0) -> HttpResponse:
        return self._request_with(self._opener, method, url, headers, body, timeout)

    def request_target(self, method: str, url: str, headers=None, body=None,
                       timeout: float = 6.0) -> HttpResponse:
        """ATTACK_TARGET 전용 HTTP(S). 경기 대상 TLS만 인증서 검증을 완화한다."""
        return self._request_with(self._target_opener, method, url, headers, body, timeout)

    @staticmethod
    def request_grpc(host: str, port: int, rpc: str, string_fields=None,
                     varint_fields=None, timeout: float = 6.0) -> HttpResponse:
        """ATTACK_TARGET의 관측된 plaintext gRPC unary 메서드를 호출한다."""
        from .grpc_transport import grpc_unary_request
        return grpc_unary_request(
            host, port, rpc, string_fields, varint_fields, timeout
        )

    @staticmethod
    def request_mqtt(host: str, port: int, topics, timeout: float = 4.0) -> HttpResponse:
        from .mqtt_transport import mqtt_subscribe_collect
        return mqtt_subscribe_collect(host, port, list(topics or ()), timeout=timeout)

    @staticmethod
    def request_rtsp(host: str, port: int, method: str, path: str, cseq: int = 1,
                     extra_headers=None, timeout: float = 4.0) -> HttpResponse:
        from .rtsp_transport import rtsp_exchange
        return rtsp_exchange(
            host, port, method, path, cseq=cseq, timeout=timeout,
            extra_headers=dict(extra_headers or {}),
        )

    @staticmethod
    def _request_with(opener, method: str, url: str, headers=None, body=None,
                      timeout: float = 6.0) -> HttpResponse:
        data = body.encode() if isinstance(body, str) else body
        req = urllib.request.Request(url, data=data, method=method)
        for k, v in (headers or {}).items():
            req.add_header(k, v)
        try:
            with opener.open(req, timeout=timeout) as r:
                raw = r.read(MAX_RESPONSE_BYTES + 1)
                truncated = len(raw) > MAX_RESPONSE_BYTES
                return HttpResponse(
                    getattr(r, "status", 200),
                    raw[:MAX_RESPONSE_BYTES].decode("utf-8", "replace"),
                    dict(r.headers.items()),
                    truncated=truncated,
                )
        except urllib.error.HTTPError as e:
            try:
                raw = e.read(MAX_RESPONSE_BYTES + 1)
                truncated = len(raw) > MAX_RESPONSE_BYTES
                text = raw[:MAX_RESPONSE_BYTES].decode("utf-8", "replace")
            except Exception:
                text = ""
                truncated = False
            return HttpResponse(
                e.code,
                text,
                dict(e.headers.items()) if e.headers else {},
                truncated=truncated,
            )
        except Exception:
            # timeout·연결거부·필터 DROP 모두 status 0 관측으로 수렴
            return HttpResponse(0, "", {})

    @staticmethod
    def read_passive_banner(host: str, port: int,
                            timeout: float = PASSIVE_BANNER_TIMEOUT,
                            max_bytes: int = MAX_PASSIVE_BANNER_BYTES) -> HttpResponse:
        """TCP handshake 뒤 서버가 먼저 보내는 bytes만 bounded read한다."""
        limit = max(1, min(int(max_bytes), MAX_PASSIVE_BANNER_BYTES))
        wait = max(0.01, min(float(timeout), PASSIVE_BANNER_TIMEOUT))
        try:
            with socket.create_connection((host, port), timeout=wait) as connection:
                connection.settimeout(wait)
                raw = connection.recv(limit + 1)
            if not raw:
                return HttpResponse(0, "", {})
            return HttpResponse(
                200,
                raw[:limit].decode("utf-8", "replace"),
                {},
                truncated=len(raw) > limit,
            )
        except OSError:
            return HttpResponse(0, "", {})


def port_open(host: str, port: int, timeout: float = 2.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


class EvidenceFactory:
    """Round·endpoint에 묶인 TTL 증거 참조를 만든다(§9.6). 병렬 안전."""

    def __init__(self, round_id: str, clock=time.monotonic, ttl: float = 90.0):
        self._round_id = round_id
        self._clock = clock
        self._ttl = ttl
        self._n = 0
        self._lock = threading.Lock()

    def make(self, endpoint: Endpoint, observation_fingerprint: str) -> EvidenceRef:
        with self._lock:
            self._n += 1
            n = self._n
        now = self._clock()
        return EvidenceRef(
            evidence_id=f"ev-{self._round_id}-{n}",
            round_id=self._round_id,
            endpoint_id=endpoint.endpoint_id,
            observed_at_monotonic=now,
            expires_at_monotonic=now + self._ttl,
            observation_fingerprint=observation_fingerprint,
        )


class Observer:
    """rate limit을 지키며 `ATTACK_TARGET` egress로 표적을 관측한다."""

    def __init__(self, egress, rate, round_id: str = "", clock=time.monotonic,
                 evidence: EvidenceFactory = None):
        self._egress = egress
        self._rate = rate
        self._round_id = round_id
        self._clock = clock
        self._evidence = evidence or EvidenceFactory(round_id, clock)

    def observe(self, endpoint: Endpoint, method: str = "GET", path: str = "/",
                headers=None, body=None, timeout: float = 6.0):
        """(Observation, HttpResponse) 반환. 원시 응답 본문은 로그로 남기지 않는다."""
        self._rate.acquire_request()
        start = self._clock()
        resp = self._egress.request(
            Capability.ATTACK_TARGET, method, endpoint.base_url() + path,
            headers, body, timeout)
        latency_ms = (self._clock() - start) * 1000.0
        body_fp = fingerprint(resp.body)
        obs = Observation(
            endpoint=endpoint,
            request_fingerprint=fingerprint(f"{method} {path}"),
            status=resp.status,
            redacted_header_hints=notable_headers(resp.headers),
            body_fingerprint=body_fp,
            latency_ms=latency_ms,
            note="no-response" if resp.status == 0 else "",
            round_id=self._round_id,
            evidence_ref=self._evidence.make(endpoint, body_fp),
        )
        return obs, resp

    def observe_banner(self, endpoint: Endpoint, timeout: float = 6.0):
        """기초 관측: GET / 배너."""
        return self.observe(endpoint, "GET", "/", timeout=timeout)

    def observe_banner_adaptive(self, endpoint: Endpoint, timeout: float = 6.0):
        """평문 HTTP 무응답일 때만 같은 endpoint를 HTTPS로 한 번 재관측한다."""
        obs, resp = self.observe_banner(endpoint, timeout=timeout)
        if resp.status != 0 or endpoint.scheme == "https":
            return obs, resp, endpoint, 1
        secure = endpoint.with_scheme("https")
        secure_obs, secure_resp = self.observe_banner(secure, timeout=timeout)
        return secure_obs, secure_resp, secure, 2

    def observe_passive_banner(self, endpoint: Endpoint):
        """HTTP(S) 무응답 endpoint에서 client application write 없이 TCP banner를 읽는다."""
        self._rate.acquire_request()
        start = self._clock()
        resp = self._egress.read_passive_banner(
            Capability.ATTACK_TARGET,
            endpoint.host,
            endpoint.port,
            timeout=PASSIVE_BANNER_TIMEOUT,
            max_bytes=MAX_PASSIVE_BANNER_BYTES,
        )
        latency_ms = (self._clock() - start) * 1000.0
        body_fp = fingerprint(resp.body)
        obs = Observation(
            endpoint=endpoint,
            request_fingerprint=fingerprint("TCP PASSIVE_BANNER"),
            status=resp.status,
            redacted_header_hints={},
            body_fingerprint=body_fp,
            latency_ms=latency_ms,
            note="no-response" if resp.status == 0 else "passive-tcp-banner",
            round_id=self._round_id,
            evidence_ref=self._evidence.make(endpoint, body_fp),
        )
        return obs, resp

    def observe_grpc(self, endpoint: Endpoint, rpc: str, string_fields=None,
                     varint_fields=None, timeout: float = 6.0):
        """관측된 gRPC 메서드로 bootstrap하고 Round·endpoint 증거를 만든다."""
        self._rate.acquire_request()
        start = self._clock()
        resp = self._egress.request_grpc(
            Capability.ATTACK_TARGET,
            endpoint.host,
            endpoint.port,
            rpc,
            string_fields,
            varint_fields,
            timeout,
        )
        latency_ms = (self._clock() - start) * 1000.0
        body_fp = fingerprint(resp.body)
        obs = Observation(
            endpoint=endpoint,
            request_fingerprint=fingerprint(f"GRPC {rpc}"),
            status=resp.status,
            redacted_header_hints=notable_headers(resp.headers),
            body_fingerprint=body_fp,
            latency_ms=latency_ms,
            note="no-response" if resp.status == 0 else "grpc",
            round_id=self._round_id,
            evidence_ref=self._evidence.make(endpoint, body_fp),
        )
        return obs, resp

    def observe_mqtt(self, endpoint: Endpoint, topics, timeout: float = 4.0):
        self._rate.acquire_request()
        start = self._clock()
        resp = self._egress.request_mqtt(
            Capability.ATTACK_TARGET, endpoint.host, endpoint.port, topics, timeout,
        )
        latency_ms = (self._clock() - start) * 1000.0
        body_fp = fingerprint(resp.body)
        topic_label = ",".join(topics[:3]) if topics else "#"
        obs = Observation(
            endpoint=endpoint,
            request_fingerprint=fingerprint(f"MQTT SUB {topic_label}"),
            status=resp.status,
            redacted_header_hints=notable_headers(resp.headers),
            body_fingerprint=body_fp,
            latency_ms=latency_ms,
            note="no-response" if resp.status == 0 else "mqtt",
            round_id=self._round_id,
            evidence_ref=self._evidence.make(endpoint, body_fp),
        )
        return obs, resp

    def observe_rtsp(self, endpoint: Endpoint, method: str, path: str,
                     extra_headers=None, timeout: float = 4.0):
        self._rate.acquire_request()
        start = self._clock()
        resp = self._egress.request_rtsp(
            Capability.ATTACK_TARGET, endpoint.host, endpoint.port,
            method, path, 1, extra_headers, timeout,
        )
        latency_ms = (self._clock() - start) * 1000.0
        body_fp = fingerprint(resp.body)
        obs = Observation(
            endpoint=endpoint,
            request_fingerprint=fingerprint(f"RTSP {method} {path}"),
            status=resp.status,
            redacted_header_hints=notable_headers(resp.headers),
            body_fingerprint=body_fp,
            latency_ms=latency_ms,
            note="no-response" if resp.status == 0 else "rtsp",
            round_id=self._round_id,
            evidence_ref=self._evidence.make(endpoint, body_fp),
        )
        return obs, resp
