"""HEARTBEAT 스케줄러 (`HeartbeatScheduler`).

설계 §4.2 HEARTBEAT epoch 규칙, §8.3 시간·실패 계약, §15.2 HEARTBEAT와 session.

계약은 단순하지만 실패 결과가 크다. Broker는 약 3초간 HEARTBEAT가 없으면
에이전트를 죽은 것으로 보고 **fail-open으로 전 패킷을 통과**시킨다(운영세칙
제13조 2항). 즉 HEARTBEAT 하나를 놓치는 것은 방어가 잠시 느려지는 게 아니라
그 순간부터 방어가 없어지는 것이다.

그래서 epoch 규칙을 엄격하게 잡는다.

- 각 성공한 socket 연결이 **별도의 epoch**를 만든다. 연결 직후
  `last_successful_heartbeat = None`이고 `heartbeat_epoch = session_connected_at`이다.
- 따라서 최초 HEARTBEAT는 `연결 + 1초` due, `연결 + 2초` service deadline이다.
- **전체 frame의 성공 송신이 확인된 뒤에만** epoch를 그 완료 시각으로 옮긴다.
  timeout·partial send·socket 오류는 epoch를 갱신하지 않는다. 보내려고 시도한
  것을 보낸 것으로 치면 3초 침묵을 2초 deadline이 못 잡는다.
- reconnect는 이전 session의 timestamp와 pending item을 전부 폐기한다.

2초 service deadline은 Broker의 3초 임계 전에 장애를 감지하고 재연결할 1초
여유를 남기기 위한 값이다.

주기 대기는 `sleep`이 아니라 이벤트 대기다(§4.2). 종료 신호와 epoch 변경에 즉시
반응해야 shutdown이 2초 안에 끝난다(§15.2).
"""

from __future__ import annotations

import threading
import time

from .logging import AuditLogger
from .metrics import (
    M_HEARTBEAT_COALESCED,
    M_HEARTBEAT_GAP,
    M_HEARTBEAT_SENT,
    Metrics,
)
from .protocol import HEARTBEAT_FRAME
from .session import TYPE_RANK_HEARTBEAT, OutboundItem, OutboundQueue

HEARTBEAT_PERIOD = 1.0
HEARTBEAT_SERVICE_BUDGET = 2.0

# 운영세칙 제13조 2항 — Broker가 사망으로 판정하는 침묵 시간. 우리 deadline보다
# 1초 뒤에 있으며, 이 값에 접근하면 경보를 남긴다.
BROKER_LIVENESS_THRESHOLD = 3.0
GAP_ALERT_THRESHOLD = 2.5

_IDLE_WAIT = 0.2
_RETRY_WAIT = 0.05


class HeartbeatScheduler:
    """약 1초 cadence와 2초 service deadline 감시.

    판정 로직과 완전히 분리돼 있다. 이 스레드는 무거운 작업을 하지 않으며
    frame을 만들어 큐에 넣을 뿐 `socket.send`를 직접 호출하지 않는다.
    """

    def __init__(
        self,
        queue: OutboundQueue,
        metrics: Metrics | None = None,
        audit: AuditLogger | None = None,
        clock=time.monotonic,
        stop_event: threading.Event | None = None,
        period: float = HEARTBEAT_PERIOD,
        service_budget: float = HEARTBEAT_SERVICE_BUDGET,
    ) -> None:
        self._queue = queue
        self._metrics = metrics
        self._audit = audit
        self._clock = clock
        self._stop = stop_event or threading.Event()
        self._period = period
        self._service_budget = service_budget

        self._cv = threading.Condition()
        self._epoch: float | None = None
        self._session_connected_at: float | None = None
        self._last_successful_heartbeat: float | None = None
        self._session_id: int | None = None
        self._thread: threading.Thread | None = None
        self.sent_count = 0
        self.stale_completions_ignored = 0

    # ── epoch 상태 ──────────────────────────────────────────────────────────

    @property
    def epoch(self) -> float | None:
        return self._epoch

    @property
    def session_connected_at(self) -> float | None:
        return self._session_connected_at

    @property
    def last_successful_heartbeat(self) -> float | None:
        return self._last_successful_heartbeat

    def due_at(self) -> float | None:
        return None if self._epoch is None else self._epoch + self._period

    def service_deadline(self) -> float | None:
        return None if self._epoch is None else self._epoch + self._service_budget

    def reset(self, session_connected_at: float, session_id: int | None = None) -> None:
        """새 session의 epoch를 연다. 이전 session의 시각을 재사용하지 않는다."""
        with self._cv:
            self._session_connected_at = session_connected_at
            self._epoch = session_connected_at
            self._last_successful_heartbeat = None
            self._session_id = session_id
            self._cv.notify_all()

    def clear(self) -> None:
        """session이 닫혔다. 다음 연결까지 tick을 멈춘다."""
        with self._cv:
            self._epoch = None
            self._session_connected_at = None
            self._last_successful_heartbeat = None
            self._session_id = None
            self._cv.notify_all()

    def on_sent(self, completed_at: float, session_id: int | None = None) -> bool:
        """writer가 **전체 frame 송신 성공**을 확인했을 때만 호출된다.

        `session_id`가 현재 session과 다르면 무시한다. writer가 성공을 통보하는
        시점과 재연결이 겹칠 수 있는데, 이전 session의 성공 시각으로 epoch를
        옮기면 방금 연 session의 첫 HEARTBEAT due가 과거로 당겨지거나 미뤄져
        §4.2의 "reconnect는 이전 session의 timestamp를 재사용하지 않는다"가 깨진다.
        generation 확인과 epoch 갱신을 같은 lock 안에서 끝낸다.
        """
        with self._cv:
            # 양쪽 generation이 모두 알려져 있고 서로 다를 때만 거절한다. 한쪽이
            # 미지정이면 비교할 근거가 없으므로 그것을 이유로 epoch 갱신을 막지
            # 않는다 — 막으면 HEARTBEAT가 영영 나가지 않아 fail-open이 된다.
            if (
                session_id is not None
                and self._session_id is not None
                and session_id != self._session_id
            ):
                self.stale_completions_ignored += 1
                return False
            previous = self._last_successful_heartbeat
            reference = previous if previous is not None else self._session_connected_at
            self._last_successful_heartbeat = completed_at
            self._epoch = completed_at
            self.sent_count += 1
            self._cv.notify_all()

        if self._metrics is not None:
            self._metrics.incr(M_HEARTBEAT_SENT)
            if reference is not None:
                gap = completed_at - reference
                self._metrics.gauge(M_HEARTBEAT_GAP, gap)
                if gap >= GAP_ALERT_THRESHOLD and self._audit is not None:
                    # 3초 임계에 닿기 전에 남긴다. 닿은 뒤의 로그는 이미 늦다.
                    self._audit.log(
                        "heartbeat-gap-warning",
                        gap_seconds=round(gap, 3),
                        threshold=BROKER_LIVENESS_THRESHOLD,
                    )
        return True

    # ── tick ────────────────────────────────────────────────────────────────

    def tick(self, now: float | None = None) -> bool:
        """due가 됐으면 HEARTBEAT를 enqueue한다. 넣었으면 True."""
        with self._cv:
            epoch = self._epoch
            if epoch is None:
                return False
            moment = self._clock() if now is None else now
            if moment < epoch + self._period:
                return False
            deadline = epoch + self._service_budget

        item = OutboundItem(
            absolute_send_deadline=deadline,
            type_rank=TYPE_RANK_HEARTBEAT,
            sequence=self._queue.next_sequence(),
            frame=HEARTBEAT_FRAME,
            session_id=self._queue.current_session(),
        )
        if self._queue.offer_heartbeat(item):
            return True
        if self._metrics is not None:
            self._metrics.incr(M_HEARTBEAT_COALESCED)
        return False

    # ── 스레드 lifecycle ────────────────────────────────────────────────────

    def start(self) -> None:
        if self._thread is not None:
            return
        self._thread = threading.Thread(target=self.run, name="heartbeat", daemon=True)
        self._thread.start()

    def stop(self, timeout: float = 2.0) -> None:
        self._stop.set()
        with self._cv:
            self._cv.notify_all()
        thread = self._thread
        self._thread = None
        if thread is not None:
            thread.join(timeout=timeout)

    def run(self) -> None:
        while not self._stop.is_set():
            with self._cv:
                epoch = self._epoch
                if epoch is None:
                    self._cv.wait(_IDLE_WAIT)
                    continue
                wait = (epoch + self._period) - self._clock()
                if wait > 0:
                    self._cv.wait(min(wait, _IDLE_WAIT))
                    continue

            if not self.tick():
                # 이미 pending인 HEARTBEAT가 있어 coalesce됐다. 바쁜 대기를 피한다.
                with self._cv:
                    self._cv.wait(_RETRY_WAIT)
