"""worker 전용 상관 상태와 immutable snapshot publication.

설계 §8 상태와 데이터 모델, §8.1 용량 상한, §11 온라인 비동기 상관분석.

핵심 경계는 하나다. **mutable state는 상관 worker 하나만 만진다. hot path는
immutable snapshot 참조 하나를 lock 없이 한 번 읽는다.**

이 분리가 필요한 이유는 성능이 아니라 정확성이다. hot path가 worker의 mutable
dict를 직접 읽으면 부분 갱신된 중간 상태를 보게 되고, 그것을 막으려면 lock이
필요한데, lock은 §5.2의 `Score` 25μs 예산과 300ms deadline 위에 예측 불가능한
대기를 얹는다. 참조 하나를 원자적으로 바꾸는 publication은 두 문제를 동시에
없앤다 — 읽는 쪽은 항상 완결된 한 세대를 보고, 아무도 기다리지 않는다.

Python 3.12 CPython의 GIL 아래에서 참조 대입은 원자적이며, publisher를 단일
worker로 제한해 write-write 경합 자체를 없앤다(§11).
"""

from __future__ import annotations

import threading
from collections import OrderedDict
from dataclasses import dataclass
from types import MappingProxyType
from typing import Mapping

from .correlation.causal import CausalMatcher, ChainEvidence
from .correlation.risk import FlowFeatures, RiskModel
from .correlation.window import BoundedDistinctSet, IntervalTracker
from .events import BoundedEventQueue, CorrelationEvent
from .metrics import (
    M_CORR_SNAPSHOT_PUBLISHED,
    M_FLOW_EVICTED,
    Metrics,
)
from .packet import FlowKey

# §8.1 용량 상한
FLOW_TTL_SECONDS = 120.0
MAX_FLOWS = 5000
FLOW_BUFFER_BYTES = 16384
PER_KEY_DISTINCT_CAP = 64
MAX_CATEGORIES_PER_FLOW = 8

# snapshot이 이보다 오래되면 hot path는 없는 것으로 취급한다(§11). stale 점수를
# 계속 쓰면 이미 끝난 flow가 뒤늦게 정상 트래픽을 막을 수 있다.
SNAPSHOT_TTL_SECONDS = 5.0
SNAPSHOT_INTERVAL_SECONDS = 0.5

# 상관 점수가 이 값 이하인 flow는 snapshot에 싣지 않는다. snapshot 크기를 실제
# 의미 있는 flow로 묶어 hot path lookup과 메모리를 함께 제한한다.
MIN_PUBLISHED_SCORE = 1


class FlowReassemblyBuffer:
    """flow당 16KB 링버퍼(§8.1). 넘치면 오래된 앞부분을 버린다.

    **현재 판정 경로에서 사용하지 않는다.** §9.3은 여러 패킷에 걸친 요청을 잡기
    위한 flow별 재조립을 요구하지만, §8은 `CorrelationEvent`가 원본 payload를
    참조하는 것을 금지한다. 두 조건을 동시에 만족하려면 재조립을 hot path의 공유
    상태에 두어야 하는데, 그것은 "builder state를 hot path에 노출하지 않는다"는
    §11 경계를 깬다.

    따라서 이 컨테이너는 §8.1 상한을 지키는 검증된 비동기 상관용 원시 자료구조로만
    제공하고 판정 경로에는 배선하지 않는다. R17의 분할 HTTP header는 별도
    `HttpStreamStitcher`가 단일 producer 소유·4KB 상한·짧은 TTL로만 처리한다.
    """

    __slots__ = ("_data",)

    def __init__(self) -> None:
        self._data = bytearray()

    def append(self, chunk: bytes) -> None:
        self._data += chunk
        overflow = len(self._data) - FLOW_BUFFER_BYTES
        if overflow > 0:
            del self._data[:overflow]

    def view(self) -> bytes:
        return bytes(self._data)

    def __len__(self) -> int:
        return len(self._data)


@dataclass(frozen=True, slots=True)
class FlowScore:
    """snapshot에 실리는 frozen entry(§8 `CorrelationSnapshot`).

    frozen dataclass와 tuple만 담는다. publication 이후 내부를 바꾸는 경로가
    존재하지 않아야 hot path가 본 값이 읽는 도중 달라지지 않는다.
    """

    score: int
    sig_hits: int
    distinct_paths: int
    scan_flag_hits: int
    matched_stages: tuple[str, ...]
    updated_at: float


@dataclass(frozen=True, slots=True)
class CorrelationSnapshot:
    generation: int
    published_at: float
    expires_at: float
    entries: Mapping[FlowKey, FlowScore]

    def lookup(self, key: FlowKey, now: float) -> FlowScore | None:
        """만료됐으면 `None`. hot path는 이 결과가 없으면 즉시 `ACCEPT`한다."""
        if now >= self.expires_at:
            return None
        return self.entries.get(key)


class CorrelationSnapshotRef:
    """현재 snapshot 참조 하나. worker만 쓰고 hot path는 읽기만 한다."""

    __slots__ = ("_snapshot",)

    def __init__(self) -> None:
        self._snapshot: CorrelationSnapshot | None = None

    def publish(self, snapshot: CorrelationSnapshot) -> None:
        """참조 하나의 원자적 교체. lock을 쓰지 않는다(§11)."""
        self._snapshot = snapshot

    def read(self) -> CorrelationSnapshot | None:
        """hot path가 함수 시작에서 정확히 한 번 호출한다."""
        return self._snapshot


class _FlowState:
    """worker 전용 mutable 상태. hot path에 절대 노출하지 않는다."""

    __slots__ = (
        "first_seen", "last_seen", "packets", "sig_hits", "encoded_hits",
        "long_uri_hits", "scan_flag_hits", "paths", "intervals", "categories",
        "first_hit_at", "packets_after_first_hit", "last_signature",
    )

    def __init__(self, now: float) -> None:
        self.first_seen = now
        self.last_seen = now
        self.packets = 0
        self.sig_hits = 0
        self.encoded_hits = 0
        self.long_uri_hits = 0
        self.scan_flag_hits = 0
        self.paths = BoundedDistinctSet(PER_KEY_DISTINCT_CAP)
        self.intervals = IntervalTracker()
        self.categories: list[str] = []
        self.first_hit_at: float | None = None
        self.packets_after_first_hit = 0
        self.last_signature: tuple[float, str] | None = None

    def features(self, now: float) -> FlowFeatures:
        return FlowFeatures(
            packets=self.packets,
            sig_hits=self.sig_hits,
            distinct_paths=len(self.paths),
            distinct_paths_saturated=self.paths.saturated,
            encoded_hits=self.encoded_hits,
            long_uri_hits=self.long_uri_hits,
            scan_flag_hits=self.scan_flag_hits,
            interval_regularity=self.intervals.regularity(now),
            duration=max(0.0, self.last_seen - self.first_seen),
        )

    def evidence(self) -> ChainEvidence:
        return ChainEvidence(
            scan_flag_hits=self.scan_flag_hits,
            sig_categories=tuple(self.categories),
            sig_hits=self.sig_hits,
            packets_after_first_hit=self.packets_after_first_hit,
        )


class CorrelationBuilder:
    """TTL·용량이 제한된 mutable flow 상태와 snapshot 생성(§7, §8.1)."""

    def __init__(
        self,
        risk_model: RiskModel | None = None,
        causal_matcher: CausalMatcher | None = None,
        ttl: float = FLOW_TTL_SECONDS,
        max_flows: int = MAX_FLOWS,
        metrics: Metrics | None = None,
    ) -> None:
        self._flows: OrderedDict[FlowKey, _FlowState] = OrderedDict()
        self._risk = risk_model or RiskModel()
        self._causal = causal_matcher or CausalMatcher()
        self._ttl = ttl
        self._max_flows = max_flows
        self._metrics = metrics
        self._generation = 0
        self.evicted = 0
        self.duplicates_ignored = 0
        self.late_events_dropped = 0

    @property
    def flow_count(self) -> int:
        return len(self._flows)

    @property
    def generation(self) -> int:
        return self._generation

    def observe(self, event: CorrelationEvent, now: float) -> bool:
        """event 하나를 반영한다. 반영했으면 True.

        out-of-order·duplicate·late 처리 규칙(§11):

        - **late**: TTL보다 오래된 event는 버린다. 이미 만료된 flow를 되살리면
          §8.1의 flow 수 상한이 의미를 잃는다.
        - **duplicate**: 같은 timestamp에 같은 경로 digest가 연속으로 오면
          무시한다. Broker 재전송이 카운터를 부풀리는 것을 막는다.
        - **out-of-order**: 카운터는 순서와 무관하므로 그대로 반영하되,
          `last_seen`을 되돌리지 않고 도착 간격 통계에도 넣지 않는다. 간격
          계산은 단조 증가하는 시각열에서만 의미가 있기 때문이다.
        """
        if now - event.monotonic_ts > self._ttl:
            self.late_events_dropped += 1
            return False

        key = event.flow_key
        state = self._flows.get(key)
        if state is None:
            state = self._new_flow(key, event.monotonic_ts)
        else:
            self._flows.move_to_end(key)

        signature = (event.monotonic_ts, event.path_digest)
        if state.last_signature == signature:
            self.duplicates_ignored += 1
            return False
        state.last_signature = signature

        state.packets += 1
        if event.monotonic_ts >= state.last_seen:
            state.last_seen = event.monotonic_ts
            state.intervals.observe(event.monotonic_ts)

        if event.path_digest:
            state.paths.add(event.path_digest)
        if event.encoded_nesting:
            state.encoded_hits += 1
        if event.long_uri:
            state.long_uri_hits += 1
        if event.scan_flag_name:
            state.scan_flag_hits += 1

        if event.rule_id:
            state.sig_hits += 1
            if state.first_hit_at is None:
                state.first_hit_at = event.monotonic_ts
            if event.sig_category and event.sig_category not in state.categories:
                if len(state.categories) < MAX_CATEGORIES_PER_FLOW:
                    state.categories.append(event.sig_category)

        if state.first_hit_at is not None and event.monotonic_ts > state.first_hit_at:
            state.packets_after_first_hit += 1

        return True

    def _new_flow(self, key: FlowKey, now: float) -> _FlowState:
        if len(self._flows) >= self._max_flows:
            # §8.1 — 전체 flow 수 상한 초과 시 신규 flow 상태추적을 포기하는 대신,
            # 가장 오래 쓰이지 않은 flow를 밀어낸다. 최근 활동이 판단에 더
            # 유용하고, 어느 쪽이든 hot path는 `ACCEPT`이므로 SLA 위험이 없다.
            self._flows.popitem(last=False)
            self.evicted += 1
            if self._metrics is not None:
                self._metrics.incr(M_FLOW_EVICTED)
        state = _FlowState(now)
        self._flows[key] = state
        return state

    def sweep(self, now: float) -> int:
        """TTL이 지난 flow를 제거한다. 제거 개수를 돌려준다."""
        threshold = now - self._ttl
        expired = [key for key, state in self._flows.items() if state.last_seen < threshold]
        for key in expired:
            del self._flows[key]
        return len(expired)

    def build_snapshot(self, now: float, ttl: float = SNAPSHOT_TTL_SECONDS) -> CorrelationSnapshot:
        """builder에서 완전히 분리된 새 immutable snapshot을 만든다(§11).

        새 private dict를 만들고 그 alias를 남기지 않은 채
        `types.MappingProxyType`으로 감싼다. entry는 frozen dataclass와 tuple만
        가지므로 publication 이후 내부를 바꿀 경로가 없다.
        """
        entries: dict[FlowKey, FlowScore] = {}
        for key, state in self._flows.items():
            features = state.features(now)
            score = self._risk.score(features)
            if score < MIN_PUBLISHED_SCORE:
                continue
            entries[key] = FlowScore(
                score=score,
                sig_hits=state.sig_hits,
                distinct_paths=len(state.paths),
                scan_flag_hits=state.scan_flag_hits,
                matched_stages=self._causal.match(state.evidence()),
                updated_at=state.last_seen,
            )

        self._generation += 1
        return CorrelationSnapshot(
            generation=self._generation,
            published_at=now,
            expires_at=now + ttl,
            entries=MappingProxyType(entries),
        )


class CorrelationWorker:
    """event 큐를 소비하고 snapshot을 발행하는 단일 worker 스레드.

    이 스레드가 정확히 하나여야 하는 이유는 §11의 publication 규약이 단일
    publisher를 전제하기 때문이다. 재연결 중에도 상관 state는 유지되며 Round
    경계에서만 사라진다(§4.2 재연결 규칙, §8.1).
    """

    def __init__(
        self,
        event_queue: BoundedEventQueue,
        snapshot_ref: CorrelationSnapshotRef,
        builder: CorrelationBuilder | None = None,
        metrics: Metrics | None = None,
        clock=None,
        publish_interval: float = SNAPSHOT_INTERVAL_SECONDS,
    ) -> None:
        import time as _time

        self._queue = event_queue
        self._ref = snapshot_ref
        self._builder = builder or CorrelationBuilder(metrics=metrics)
        self._metrics = metrics
        self._clock = clock or _time.monotonic
        self._publish_interval = publish_interval
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._last_publish = 0.0

    @property
    def builder(self) -> CorrelationBuilder:
        return self._builder

    def start(self) -> None:
        if self.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self.run, name="correlation", daemon=True)
        self._thread.start()

    def is_alive(self) -> bool:
        thread = self._thread
        return thread is not None and thread.is_alive()

    def stop(self, timeout: float = 2.0) -> None:
        self._stop.set()
        thread = self._thread
        self._thread = None
        if thread is not None:
            thread.join(timeout=timeout)

    def run(self) -> None:
        while not self._stop.is_set():
            try:
                self.drain_once(timeout=0.2)
            except Exception:  # noqa: BLE001 - worker 예외가 verdict를 막지 않는다(§13)
                continue

    def drain_once(self, timeout: float = 0.2) -> None:
        """큐에서 하나를 꺼내 반영하고, 주기가 되면 snapshot을 발행한다."""
        event = self._queue.get(timeout=timeout)
        now = self._clock()
        if event is not None:
            self._builder.observe(event, now)
        if now - self._last_publish >= self._publish_interval:
            self.publish(now)

    def publish(self, now: float | None = None) -> CorrelationSnapshot:
        moment = self._clock() if now is None else now
        self._builder.sweep(moment)
        snapshot = self._builder.build_snapshot(moment)
        self._ref.publish(snapshot)
        self._last_publish = moment
        if self._metrics is not None:
            self._metrics.incr(M_CORR_SNAPSHOT_PUBLISHED)
        return snapshot
