"""전역 요청 rate limiter, 제출 60초 sliding window, 429 backoff·Retry-After.

설계 §9.5·§9.11·§9.13. 계약(운영세칙 제10·12조):
- 상대 방어망 요청: 초당 10회, 버스트 20(토큰 버킷). 병렬 실행도 이 전역 제한을 공유한다.
- flag 제출: **어떤 연속 60초 구간에서도 최대 30회**. burst capacity를 두지 않는 sliding window.
- 429: 유효한 `Retry-After` 우선, 없거나 무효할 때만 상한 지수 backoff.

rate limit 자체를 우회하는 조작은 금지(제24조 8호)이므로 이 limiter는 회피가 아니라 준수를
위한 것이다. clock·sleep을 주입해 결정론적으로 테스트한다.
"""

from __future__ import annotations

import email.utils
import threading
import time
from collections import deque

REQUEST_RATE = 10.0     # 초당 10회
REQUEST_BURST = 20      # 버스트 20
SUBMIT_MAX = 30         # 60초당 30회
SUBMIT_WINDOW = 60.0

BACKOFF_BASE = 1.0
BACKOFF_FACTOR = 2.0
BACKOFF_CAP = 30.0

_EPS = 1e-9  # 부동소수 오차 허용치(토큰 버킷)


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
            # epsilon 으로 부동소수 오차를 흡수해 refill 이 정확히 n 에 못 미치는 무한 대기를 막는다.
            if self._tokens >= n - _EPS:
                self._tokens -= n
                return True
            return False

    def wait_time(self, n: int = 1) -> float:
        with self._lock:
            self._refill_locked()
            if self._tokens >= n - _EPS:
                return 0.0
            if self.rate <= 0:
                return float("inf")
            return (n - self._tokens) / self.rate


class SlidingWindowLimiter:
    """공유 monotonic timestamp deque 기반 sliding window. burst 없음, 원자적."""

    def __init__(self, max_events: int = SUBMIT_MAX, window: float = SUBMIT_WINDOW,
                 clock=time.monotonic):
        self.max_events = max_events
        self.window = window
        self._clock = clock
        self._events = deque()
        self._lock = threading.Lock()

    def _evict_locked(self, now: float) -> None:
        # now - window 이전(창을 벗어난) 기록 제거
        boundary = now - self.window
        while self._events and self._events[0] <= boundary:
            self._events.popleft()

    def try_acquire(self) -> bool:
        with self._lock:
            now = self._clock()
            self._evict_locked(now)
            if len(self._events) < self.max_events:
                self._events.append(now)
                return True
            return False

    def wait_time(self) -> float:
        with self._lock:
            now = self._clock()
            self._evict_locked(now)
            if len(self._events) < self.max_events:
                return 0.0
            # 가장 오래된 기록이 창을 벗어날 시각까지 대기
            return (self._events[0] + self.window) - now

    def clear(self) -> None:
        with self._lock:
            self._events.clear()


class Backoff:
    """`Retry-After`가 없거나 무효할 때만 쓰는 상한 지수 backoff. 성공 시 reset."""

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


def parse_retry_after(value, now_epoch=None):
    """`Retry-After` 헤더를 초 단위 대기로 해석. delta-seconds 또는 HTTP-date.

    유효하지 않으면 None(→ 호출측이 지수 backoff로 대체).
    """
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    if text.isdigit():
        return float(text)
    try:
        dt = email.utils.parsedate_to_datetime(text)
    except (TypeError, ValueError):
        return None
    if dt is None:
        return None
    target = dt.timestamp()
    now = now_epoch if now_epoch is not None else time.time()
    return max(0.0, target - now)


class RateLimiter:
    """요청(토큰 버킷)·제출(60초 sliding window)을 묶은 전역 limiter."""

    def __init__(self, clock=time.monotonic, sleep=time.sleep,
                 request_rate: float = REQUEST_RATE, request_burst: int = REQUEST_BURST,
                 submit_max: int = SUBMIT_MAX, submit_window: float = SUBMIT_WINDOW):
        self._clock = clock
        self._sleep = sleep
        self.requests = TokenBucket(request_rate, request_burst, clock)
        self.submits = SlidingWindowLimiter(submit_max, submit_window, clock)

    def try_request(self, n: int = 1) -> bool:
        return self.requests.try_acquire(n)

    def try_submit(self) -> bool:
        return self.submits.try_acquire()

    def acquire_request(self, n: int = 1) -> None:
        while not self.requests.try_acquire(n):
            wait = self.requests.wait_time(n)
            self._sleep(wait if wait > 0 else 0.001)

    def acquire_submit(self) -> None:
        while not self.submits.try_acquire():
            wait = self.submits.wait_time()
            self._sleep(wait if wait > 0 else 0.001)
