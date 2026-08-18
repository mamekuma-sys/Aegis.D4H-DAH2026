"""카운터와 지연 분포 (`Metrics`).

설계 §7 구성요소 표의 마지막 행 — verdict count, accept/drop, parser failure,
queue drop, heartbeat gap, latency 분포.

§15.4가 p50·p95·p99·max를 요구하므로 지연 표본을 보관해야 하는데, 20분 Round 동안
무한히 쌓으면 §8.1의 메모리 상한을 깬다. 따라서 지표별로 고정 길이 ring buffer를
쓴다. 오래된 표본을 덮어쓰므로 "최근 N개의 분포"이며 Round 전체 분포가 아니라는
점을 그대로 보고한다.

hot path에서 호출되므로 lock 구간을 산술 연산 몇 개로 유지하고 문자열 포매팅이나
정렬을 하지 않는다. 정렬은 `snapshot()` 호출 시점에만 수행한다.
"""

from __future__ import annotations

import threading
from typing import Iterable

DEFAULT_SAMPLE_CAPACITY = 4096


class _Reservoir:
    """고정 길이 ring buffer. 가득 차면 가장 오래된 표본을 덮어쓴다."""

    __slots__ = ("_capacity", "_samples", "_index", "_count", "_max")

    def __init__(self, capacity: int) -> None:
        self._capacity = capacity
        self._samples: list[float] = [0.0] * capacity
        self._index = 0
        self._count = 0
        self._max = 0.0

    def add(self, value: float) -> None:
        self._samples[self._index] = value
        self._index = (self._index + 1) % self._capacity
        if self._count < self._capacity:
            self._count += 1
        if value > self._max:
            self._max = value

    def values(self) -> list[float]:
        return self._samples[: self._count]

    @property
    def observed_max(self) -> float:
        return self._max


def _percentile(ordered: list[float], fraction: float) -> float:
    """nearest-rank 백분위. 표본이 비면 0.0.

    보간하지 않는 이유는 §5.2의 예산이 "실측 표본 중 하나"로 표현돼야 회귀
    분석에서 원 표본을 되짚을 수 있기 때문이다.
    """
    if not ordered:
        return 0.0
    rank = max(1, min(len(ordered), int(round(fraction * len(ordered) + 0.5))))
    return ordered[rank - 1]


class Metrics:
    """스레드 안전 카운터와 지연 분포."""

    def __init__(self, sample_capacity: int = DEFAULT_SAMPLE_CAPACITY) -> None:
        self._lock = threading.Lock()
        self._counters: dict[str, int] = {}
        self._gauges: dict[str, float] = {}
        self._latency: dict[str, _Reservoir] = {}
        self._sample_capacity = sample_capacity

    def incr(self, name: str, amount: int = 1) -> None:
        with self._lock:
            self._counters[name] = self._counters.get(name, 0) + amount

    def gauge(self, name: str, value: float) -> None:
        with self._lock:
            self._gauges[name] = value

    def observe(self, name: str, seconds: float) -> None:
        """지연 표본 하나를 기록한다. 단위는 초(monotonic 차이)."""
        with self._lock:
            reservoir = self._latency.get(name)
            if reservoir is None:
                reservoir = _Reservoir(self._sample_capacity)
                self._latency[name] = reservoir
            reservoir.add(seconds)

    def counter(self, name: str) -> int:
        with self._lock:
            return self._counters.get(name, 0)

    def counters(self) -> dict[str, int]:
        with self._lock:
            return dict(self._counters)

    def latency_summary(self, name: str) -> dict[str, float]:
        """마이크로초 단위 p50·p95·p99·max와 표본 수."""
        with self._lock:
            reservoir = self._latency.get(name)
            values = reservoir.values() if reservoir else []
            observed_max = reservoir.observed_max if reservoir else 0.0
        ordered = sorted(values)
        return {
            "count": float(len(ordered)),
            "p50_us": _percentile(ordered, 0.50) * 1e6,
            "p95_us": _percentile(ordered, 0.95) * 1e6,
            "p99_us": _percentile(ordered, 0.99) * 1e6,
            "max_us": observed_max * 1e6,
        }

    def latency_names(self) -> Iterable[str]:
        with self._lock:
            return tuple(self._latency)

    def snapshot(self) -> dict[str, object]:
        """비민감 요약. 로그와 Break 인계 자료에 그대로 쓸 수 있어야 한다."""
        with self._lock:
            counters = dict(self._counters)
            gauges = dict(self._gauges)
            names = tuple(self._latency)
        return {
            "counters": counters,
            "gauges": gauges,
            "latency": {name: self.latency_summary(name) for name in names},
        }


# hot path와 lifecycle에서 쓰는 지표 이름. 문자열 오타로 지표가 조용히 갈라지는 것을
# 막기 위해 상수로 고정한다.
M_PACKET_RECEIVED = "packet.received"
M_FRAME_UNKNOWN_TYPE = "frame.unknown_type"
M_FRAME_SHORT_HEADER = "frame.short_header"
M_FRAME_LENGTH_MISMATCH = "frame.length_mismatch"
M_FRAME_TRAILING_BYTES = "frame.trailing_bytes"
M_VERDICT_ACCEPT = "verdict.accept"
M_VERDICT_DROP = "verdict.drop"
M_VERDICT_SOFT_CUTOFF = "verdict.soft_cutoff"
M_PARSER_FAILURE = "parser.failure"
M_PARSER_UNSUPPORTED = "parser.unsupported"
M_POLICY_EXCEPTION = "policy.exception"
M_POLICY_CONFLICT = "policy.conflict"
M_RULE_SHADOW_HIT = "rule.shadow_hit"
M_RULE_CANARY_SKIP = "rule.canary_skip"
M_ENQUEUE_OK = "outbound.enqueued"
M_ENQUEUE_FULL = "outbound.enqueue_full"
M_SEND_OK = "outbound.sent"
M_SEND_TIMEOUT = "outbound.send_timeout"
M_SEND_ERROR = "outbound.send_error"
M_SEND_PARTIAL = "outbound.send_partial"
M_SEND_STALE = "outbound.send_stale"
M_VERDICT_EXPIRED = "outbound.verdict_expired"
M_HEARTBEAT_SENT = "heartbeat.sent"
M_HEARTBEAT_EXPIRED = "heartbeat.expired"
M_HEARTBEAT_COALESCED = "heartbeat.coalesced"
M_HEARTBEAT_GAP = "heartbeat.gap_seconds"
M_SESSION_CONNECTED = "session.connected"
M_SESSION_FAULT = "session.fault"
M_SESSION_RECONNECT_ATTEMPT = "session.reconnect_attempt"
M_EVENT_ENQUEUED = "async.event_enqueued"
M_EVENT_DROPPED_NEWEST = "async.event_dropped_newest"
M_CORR_SNAPSHOT_PUBLISHED = "async.snapshot_published"
M_CORR_STALE_SNAPSHOT = "async.snapshot_stale"
M_FLOW_EVICTED = "async.flow_evicted"
M_ADVISORY_CALL = "advisory.call"
M_ADVISORY_FAILURE = "advisory.failure"
M_ADVISORY_TOKENS = "advisory.tokens"
M_ANOMALY_ALERT = "anomaly.alert"
M_WORKER_UNHEALTHY = "worker.unhealthy"
M_WORKER_RESTARTED = "worker.restarted"
M_WORKER_RESTART_FAILED = "worker.restart_failed"

L_HOT_PATH = "latency.hot_path"
L_FRAME_DECODE = "latency.frame_decode"
L_PARSE = "latency.parse"
L_POLICY = "latency.policy"
L_GATE = "latency.gate"
L_SIG = "latency.sig"
L_SCORE = "latency.score"
L_ENQUEUE = "latency.enqueue"
L_SEND = "latency.send"
L_VERDICT_SEND_E2E = "latency.verdict_send_e2e"
