"""시간 윈도우 — 도착 간격과 bounded 최근 관측.

설계 §9.4 Score 단계 신호 표의 "요청 간격이 기계적으로 균일", §11 bounded state.

여기서 계산하는 값은 전부 **비동기 경로 전용**이다. hot path는 이 계산을 하지
않고 `CorrelationSnapshot`에서 완성된 점수 하나만 읽는다(§4.1).

임계는 이 모듈에 없다. §9.4가 못박듯 "임계는 반드시 관측된 정상 baseline 위에서
정한다"이고, baseline은 `FinalsPhase 1`에서 관측한 뒤 policy file에 들어간다.
"""

from __future__ import annotations

from collections import deque

DEFAULT_INTERVAL_CAPACITY = 32
DEFAULT_WINDOW_SECONDS = 30.0

# 변동계수를 신뢰하려면 최소한의 간격 표본이 필요하다. 표본이 적을 때 나온 높은
# 균일성은 신호가 아니라 잡음이므로 0.0으로 보고한다.
MIN_INTERVALS_FOR_REGULARITY = 4


class IntervalTracker:
    """flow 하나의 최근 도착 시각. 고정 길이라 메모리가 flow 수에만 비례한다."""

    __slots__ = ("_timestamps", "_window")

    def __init__(
        self,
        capacity: int = DEFAULT_INTERVAL_CAPACITY,
        window_seconds: float = DEFAULT_WINDOW_SECONDS,
    ) -> None:
        self._timestamps: deque[float] = deque(maxlen=capacity)
        self._window = window_seconds

    def observe(self, monotonic_ts: float) -> None:
        self._timestamps.append(monotonic_ts)

    def _recent(self, now: float) -> list[float]:
        threshold = now - self._window
        return [ts for ts in self._timestamps if ts >= threshold]

    def rate_per_second(self, now: float) -> float:
        recent = self._recent(now)
        if len(recent) < 2:
            return 0.0
        span = recent[-1] - recent[0]
        if span <= 0.0:
            return float(len(recent))
        return (len(recent) - 1) / span

    def regularity(self, now: float) -> float:
        """0.0~1.0. 1.0에 가까울수록 도착 간격이 기계적으로 균일하다.

        간격의 변동계수(표준편차/평균)를 1에서 뺀 값이다. 사람이 만드는 트래픽은
        간격이 흩어지고 자동화된 반복은 모인다. 절대 임계를 두지 않고 값만
        내보내며, 차단 여부는 승인된 rule의 `min_score`가 결정한다.
        """
        recent = self._recent(now)
        if len(recent) < MIN_INTERVALS_FOR_REGULARITY + 1:
            return 0.0
        intervals = [b - a for a, b in zip(recent, recent[1:]) if b > a]
        if len(intervals) < MIN_INTERVALS_FOR_REGULARITY:
            return 0.0
        mean = sum(intervals) / len(intervals)
        if mean <= 0.0:
            return 0.0
        variance = sum((value - mean) ** 2 for value in intervals) / len(intervals)
        deviation = variance ** 0.5
        coefficient = deviation / mean
        return max(0.0, min(1.0, 1.0 - coefficient))


class BoundedDistinctSet:
    """상한 있는 distinct 값 집합.

    §8.1의 per-key cap을 만족시키기 위해 상한에 도달하면 새 값을 더 넣지 않고
    `saturated`만 표시한다. 오래된 값을 밀어내지 않는 이유는, "서로 다른 경로를
    몇 개나 시도했는가"라는 신호에서 상한 도달 자체가 이미 충분한 정보이기
    때문이다.
    """

    __slots__ = ("_values", "_cap", "saturated")

    def __init__(self, cap: int) -> None:
        self._values: set[str] = set()
        self._cap = cap
        self.saturated = False

    def add(self, value: str) -> None:
        if len(self._values) >= self._cap:
            self.saturated = True
            return
        self._values.add(value)

    def __len__(self) -> int:
        return len(self._values)
