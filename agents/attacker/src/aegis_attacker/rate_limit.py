"""전역·제출 rate limiter와 429 backoff.

설계 §9.5·§9.10. 계약(운영세칙 제10·12조):
- 상대 방어망 요청: 공격 에이전트당 초당 10회, 버스트 20. 병렬 실행도 이 전역 제한을 공유한다.
- flag 제출: 분당 30회. 초과 시 429 → backoff.

rate limit 자체를 우회하는 조작은 금지(제24조 8호)이므로, 이 limiter는 회피가 아니라
준수를 위한 것이다. clock·sleep을 주입 가능하게 하여 결정론적으로 테스트한다.
"""

from __future__ import annotations

import threading
import time

REQUEST_RATE = 10.0     # 초당 10회
REQUEST_BURST = 20      # 버스트 20
SUBMIT_RATE = 30.0 / 60.0  # 분당 30회
SUBMIT_BURST = 30

BACKOFF_BASE = 1.0
BACKOFF_FACTOR = 2.0
BACKOFF_CAP = 30.0


class TokenBucket:
    """스레드 안전 토큰 버킷. 병렬 도구 실행이 하나의 전역 버킷을 공유한다."""

    def __init__(self, rate: float, capacity: float, clock=time.monotonic):
        self.rate = float(rate)
        self.capacity = float(capacity)
        self._tokens = float(capacity)
        self._clock = clock
        self._last = clock()
        self._lock = threading.Lock()

    def _refill_locked(self) -> None:
        now = self._clock()
        if now > self._last:
            self._tokens = min(self.capacity, self._tokens + (now - self._last) * self.rate)
            self._last = now

    def try_acquire(self, n: int = 1) -> bool:
        with self._lock:
            self._refill_locked()
            if self._tokens >= n:
                self._tokens -= n
                return True
            return False

    def wait_time(self, n: int = 1) -> float:
        """n개 토큰이 찰 때까지 남은 초. 이미 가능하면 0."""
        with self._lock:
            self._refill_locked()
            if self._tokens >= n:
                return 0.0
            if self.rate <= 0:
                return float("inf")
            return (n - self._tokens) / self.rate


class Backoff:
    """429·일시 오류용 지수 backoff. 성공 시 reset. 동일 요청 즉시 반복을 막는다."""

    def __init__(self, base: float = BACKOFF_BASE, factor: float = BACKOFF_FACTOR,
                 cap: float = BACKOFF_CAP):
        self.base = base
        self.factor = factor
        self.cap = cap
        self._attempt = 0

    def next_delay(self) -> float:
        delay = min(self.cap, self.base * (self.factor ** self._attempt))
        self._attempt += 1
        return delay

    def reset(self) -> None:
        self._attempt = 0


class RateLimiter:
    """요청·제출 버킷을 묶은 전역 limiter."""

    def __init__(self, clock=time.monotonic, sleep=time.sleep,
                 request_rate: float = REQUEST_RATE, request_burst: int = REQUEST_BURST,
                 submit_rate: float = SUBMIT_RATE, submit_burst: int = SUBMIT_BURST):
        self._clock = clock
        self._sleep = sleep
        self.requests = TokenBucket(request_rate, request_burst, clock)
        self.submits = TokenBucket(submit_rate, submit_burst, clock)

    def try_request(self, n: int = 1) -> bool:
        return self.requests.try_acquire(n)

    def try_submit(self, n: int = 1) -> bool:
        return self.submits.try_acquire(n)

    def acquire_request(self, n: int = 1) -> None:
        self._block(self.requests, n)

    def acquire_submit(self, n: int = 1) -> None:
        self._block(self.submits, n)

    def _block(self, bucket: TokenBucket, n: int) -> None:
        while True:
            if bucket.try_acquire(n):
                return
            wait = bucket.wait_time(n)
            self._sleep(wait if wait > 0 else 0.001)
