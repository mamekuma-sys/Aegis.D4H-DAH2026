"""Round 비밀 저장소와 SecretHandle.

설계 §9.6·§9.11·§9.12. flag·세션·제출 토큰·LLM 키 원문은 Round 비밀 저장소 메모리에만
존재한다. 계획·증거·로그·보고서·LLM 프롬프트에는 handle·해시·마스크만 흐른다. handle은
비직렬화·비로그 타입이며 Round 종료·TTL 만료 시 원문과 함께 즉시 폐기한다.
"""

from __future__ import annotations

import time
from dataclasses import dataclass

# 비밀 종류
KIND_FLAG = "flag"
KIND_SESSION = "session"
KIND_SUBMIT_TOKEN = "submit_token"
KIND_LLM_KEY = "llm_key"
_KINDS = {KIND_FLAG, KIND_SESSION, KIND_SUBMIT_TOKEN, KIND_LLM_KEY}

DEFAULT_TTL = 20 * 60.0  # Round(20분) 상한


class SecretError(Exception):
    """만료·Round 불일치·미존재 handle 해석 시도."""


@dataclass(frozen=True)
class SecretHandle:
    """비직렬화·비로그 비밀 참조. 원문을 담지 않는다."""

    secret_id: str
    round_id: str
    kind: str
    expires_at_monotonic: float

    # 로그·프롬프트에 원문이 새지 않도록 마스크만 노출.
    def __repr__(self) -> str:
        return f"<SecretHandle {self.kind} {self.secret_id} [masked]>"

    __str__ = __repr__

    # 직렬화 금지 — 이미지·로그·상태로 새어나가지 않도록.
    def __reduce__(self):
        raise TypeError("SecretHandle 은 직렬화할 수 없다")

    def __getstate__(self):
        raise TypeError("SecretHandle 은 직렬화할 수 없다")


class RoundSecretStore:
    """Round 한정 비밀 저장소. 원문은 이 인스턴스 메모리에만 산다."""

    def __init__(self, round_id: str, clock=time.monotonic, ttl: float = DEFAULT_TTL):
        self._round_id = round_id
        self._clock = clock
        self._ttl = ttl
        self._plaintext = {}  # secret_id -> plaintext
        self._counter = 0

    @property
    def round_id(self) -> str:
        return self._round_id

    def put(self, kind: str, plaintext: str) -> SecretHandle:
        if kind not in _KINDS:
            raise SecretError(f"알 수 없는 비밀 종류: {kind}")
        self._counter += 1
        secret_id = f"sec-{self._round_id}-{self._counter}"
        self._plaintext[secret_id] = plaintext
        return SecretHandle(secret_id, self._round_id, kind,
                            self._clock() + self._ttl)

    def resolve(self, handle: SecretHandle) -> str:
        """권한 있는 소비자만 호출한다. 만료·Round 불일치·미존재는 거부."""
        if handle.round_id != self._round_id:
            raise SecretError("다른 Round 의 handle")
        if self._clock() >= handle.expires_at_monotonic:
            raise SecretError("만료된 handle")
        if handle.secret_id not in self._plaintext:
            raise SecretError("폐기되었거나 없는 secret")
        return self._plaintext[handle.secret_id]

    def secrets_snapshot(self) -> set:
        """등록된 원문 값 집합(로그 Redactor 시드용). 값 자체는 반환하되 로그엔 안 씀."""
        return {v for v in self._plaintext.values() if v}

    def expire_all(self) -> None:
        """Round 종료 시 원문 즉시 폐기."""
        self._plaintext.clear()
