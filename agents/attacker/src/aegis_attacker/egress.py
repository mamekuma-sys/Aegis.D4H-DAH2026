"""Typed egress gateway.

설계 §9.5·§9.10. 모든 네트워크 호출을 capability(ATTACK_TARGET·SUBMIT·LLM)별로 분리한다.
각 capability는 설정 검증 시 확정한 endpoint allowlist만 쓰며 다른 capability의 URL을
재사용하지 않는다. 환경 프록시 비활성, 리다이렉트 미추적(3xx는 관측 결과로 반환), host·port
변경이나 capability 교차는 네트워크 호출 전에 거부한다.
"""

from __future__ import annotations

import urllib.parse

from .models import Capability

_DEFAULT_PORT = {"http": 80, "https": 443}


class EgressError(Exception):
    """capability allowlist 밖 대상 또는 capability 교차."""


def _host_port(url: str):
    parts = urllib.parse.urlsplit(url)
    host = parts.hostname or ""
    port = parts.port or _DEFAULT_PORT.get(parts.scheme, 80)
    return host, port


def build_allowlists(config) -> dict:
    """설정에서 capability별 (host, port) allowlist를 확정한다."""
    allow = {
        Capability.ATTACK_TARGET: {(e.host, e.port) for e in config.endpoints()},
        Capability.SUBMIT: set(),
        Capability.LLM: set(),
    }
    if config.submit_url:
        allow[Capability.SUBMIT].add(_host_port(config.submit_url))
    if config.llm_base_url:
        allow[Capability.LLM].add(_host_port(config.llm_base_url))
    return allow


class EgressGateway:
    """capability 검증 후에만 전송을 호출한다."""

    def __init__(self, transport, allowlists: dict):
        self._transport = transport
        self._allow = allowlists

    def allows(self, capability: Capability, url: str) -> bool:
        return _host_port(url) in self._allow.get(capability, set())

    def request(self, capability: Capability, method: str, url: str,
                headers=None, body=None, timeout: float = 6.0):
        if not self.allows(capability, url):
            host, port = _host_port(url)
            raise EgressError(
                f"{capability.value} egress 거부: {host}:{port} 는 allowlist 밖")
        # 대상 TLS는 target 전용 opener를 사용한다. 제출·LLM 인증서 정책과 분리한다.
        if (capability == Capability.ATTACK_TARGET
                and hasattr(self._transport, "request_target")):
            return self._transport.request_target(method, url, headers, body, timeout)
        # 전송은 프록시 비활성·리다이렉트 미추적. 3xx는 그대로 반환된다.
        return self._transport.request(method, url, headers, body, timeout)

    def read_passive_banner(self, capability: Capability, host: str, port: int,
                            timeout: float = 0.75, max_bytes: int = 4096):
        """Allowlisted ATTACK_TARGET에서 서버 주도 TCP banner만 bounded read한다."""
        if capability != Capability.ATTACK_TARGET:
            raise EgressError("passive TCP banner는 ATTACK_TARGET 전용")
        if (host, port) not in self._allow.get(capability, set()):
            raise EgressError(
                f"{capability.value} egress 거부: {host}:{port} 는 allowlist 밖"
            )
        reader = getattr(self._transport, "read_passive_banner", None)
        if reader is None:
            # 주입형 테스트 transport나 제한된 embedder는 안전하게 무응답으로 수렴한다.
            from .observation import HttpResponse
            return HttpResponse(0, "", {})
        return reader(host, port, timeout, max_bytes)

    def request_grpc(self, capability: Capability, host: str, port: int, rpc: str,
                     string_fields=None, varint_fields=None, timeout: float = 6.0):
        """Allowlisted ATTACK_TARGET의 plaintext gRPC unary 요청만 전달한다."""
        if capability != Capability.ATTACK_TARGET:
            raise EgressError("gRPC 요청은 ATTACK_TARGET 전용")
        from .grpc_transport import ALLOWED_GRPC_RPCS
        if port != 9000 or rpc not in ALLOWED_GRPC_RPCS:
            raise EgressError("관측되지 않은 gRPC port 또는 RPC")
        if (host, port) not in self._allow.get(capability, set()):
            raise EgressError(
                f"{capability.value} egress 거부: {host}:{port} 는 allowlist 밖"
            )
        requester = getattr(self._transport, "request_grpc", None)
        if requester is None:
            from .observation import HttpResponse
            return HttpResponse(0, "", {})
        return requester(
            host, port, rpc, string_fields, varint_fields, timeout
        )

    def request_mqtt(self, capability: Capability, host: str, port: int, topics,
                     timeout: float = 4.0):
        """Allowlisted ATTACK_TARGET의 MQTT CONNECT+SUBSCRIBE 수집."""
        if capability != Capability.ATTACK_TARGET:
            raise EgressError("MQTT 요청은 ATTACK_TARGET 전용")
        if port != 1883:
            raise EgressError("관측되지 않은 MQTT port")
        if (host, port) not in self._allow.get(capability, set()):
            raise EgressError(
                f"{capability.value} egress 거부: {host}:{port} 는 allowlist 밖"
            )
        requester = getattr(self._transport, "request_mqtt", None)
        if requester is not None:
            return requester(host, port, list(topics or ()), timeout)
        from .mqtt_transport import mqtt_subscribe_collect
        return mqtt_subscribe_collect(host, port, list(topics or ()), timeout=timeout)

    def request_rtsp(self, capability: Capability, host: str, port: int,
                     method: str, path: str, cseq: int = 1,
                     extra_headers=None, timeout: float = 4.0):
        """Allowlisted ATTACK_TARGET의 RTSP OPTIONS/DESCRIBE."""
        if capability != Capability.ATTACK_TARGET:
            raise EgressError("RTSP 요청은 ATTACK_TARGET 전용")
        if port != 8554:
            raise EgressError("관측되지 않은 RTSP port")
        if (host, port) not in self._allow.get(capability, set()):
            raise EgressError(
                f"{capability.value} egress 거부: {host}:{port} 는 allowlist 밖"
            )
        requester = getattr(self._transport, "request_rtsp", None)
        if requester is not None:
            return requester(
                host, port, method, path, cseq, extra_headers, timeout,
            )
        from .rtsp_transport import rtsp_exchange
        return rtsp_exchange(
            host, port, method, path, cseq=cseq, timeout=timeout,
            extra_headers=dict(extra_headers or {}),
        )
