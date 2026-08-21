"""환경변수 검증과 설정 타입.

설계 §9.5 설정 검증기, §9.13 오류 처리. 주소·포트·토큰을 하드코딩하지 않고 주입된
환경변수로만 참조한다(운영세칙 제7조). 형식 오류는 ConfigError로 거부하고, 값 누락은
inert(무동작)로 처리해 런타임이 판단한다.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping

from .models import Endpoint

DEFAULT_LLM_BASE_URL = "http://litellm.lig.internal:4000"
DEFAULT_LLM_MODEL = "gpt-5.4-pro"
DEFAULT_CONCURRENCY = 16
MAX_CONCURRENCY = 32


class ConfigError(ValueError):
    """필수 환경변수의 형식 오류."""


@dataclass(frozen=True)
class AttackerConfig:
    targets: tuple = ()
    ports: tuple = ()
    submit_url: str = ""
    submit_token: str = ""
    llm_base_url: str = DEFAULT_LLM_BASE_URL
    llm_api_key: str = ""
    llm_model: str = DEFAULT_LLM_MODEL
    concurrency: int = DEFAULT_CONCURRENCY

    @property
    def can_attack(self) -> bool:
        """표적만 있으면 결정론 정찰을 수행한다. LLM 키 부재는 inert가 아니다(§9.12)."""
        return bool(self.targets and self.ports)

    @property
    def can_submit(self) -> bool:
        return bool(self.submit_url and self.submit_token)

    def endpoints(self) -> list:
        """TARGETS × PORTS 전체 조합을 누락 없이 열거한다(§9.7)."""
        return [Endpoint(host, port) for host in self.targets for port in self.ports]


def _parse_csv(raw: str) -> list:
    return [item.strip() for item in (raw or "").split(",") if item.strip()]


def _parse_concurrency(raw: str) -> int:
    """선택적 ATTACK_CONCURRENCY(기본 8). 공식 계약 필수 입력이 아니라 런타임 튜닝 파라미터."""
    token = (raw or "").strip()
    if token.isdigit():
        return max(1, min(MAX_CONCURRENCY, int(token)))
    return DEFAULT_CONCURRENCY


def _parse_ports(raw: str) -> tuple:
    ports = []
    for token in _parse_csv(raw):
        if not token.isdigit():
            raise ConfigError(f"PORTS 에 숫자 아닌 값: {token!r}")
        value = int(token)
        if not (1 <= value <= 65535):
            raise ConfigError(f"PORTS 범위 밖: {value}")
        if value not in ports:
            ports.append(value)
    return tuple(ports)


def load_config(env: Mapping) -> AttackerConfig:
    """환경변수 매핑에서 설정을 파싱·검증한다.

    형식 오류(비숫자 포트 등)는 ConfigError. 값 누락은 빈 값으로 두고 inert 판단은
    런타임에 맡긴다.
    """
    targets = tuple(dict.fromkeys(_parse_csv(env.get("TARGETS", ""))))  # 순서 유지 중복 제거
    ports = _parse_ports(env.get("PORTS", ""))
    return AttackerConfig(
        targets=targets,
        ports=ports,
        submit_url=(env.get("SUBMIT_URL", "") or "").strip(),
        submit_token=(env.get("SUBMIT_TOKEN", "") or "").strip(),
        llm_base_url=(env.get("LLM_BASE_URL", "") or DEFAULT_LLM_BASE_URL).rstrip("/"),
        llm_api_key=(env.get("LLM_API_KEY", "") or "").strip(),
        llm_model=(env.get("LLM_MODEL", "") or DEFAULT_LLM_MODEL).strip(),
        concurrency=_parse_concurrency(env.get("ATTACK_CONCURRENCY", "")),
    )
