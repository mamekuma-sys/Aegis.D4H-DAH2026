"""HEARTBEAT epoch와 cadence 테스트.

설계 §4.2 HEARTBEAT epoch 규칙, §8.3 시간·실패 계약, §15.2, §15.4.

HEARTBEAT를 3초간 놓치면 Broker가 에이전트를 죽은 것으로 보고 fail-open으로
전 패킷을 통과시킨다(운영세칙 제13조 2항). 그래서 "보내려고 시도한 것"과
"보낸 것"을 구분하는 것이 이 파일의 주제다.
"""

import threading
import unittest

from aegis_defender.heartbeat import (
    BROKER_LIVENESS_THRESHOLD,
    HEARTBEAT_PERIOD,
    HEARTBEAT_SERVICE_BUDGET,
    HeartbeatScheduler,
)
from aegis_defender.metrics import Metrics
from aegis_defender.protocol import HEARTBEAT_FRAME
from aegis_defender.session import (
    TYPE_RANK_HEARTBEAT,
    OutboundQueue,
    SendOutcome,
    SocketWriter,
    VerdictSender,
    WriterState,
)
from aegis_defender.protocol import VERDICT_ACCEPT

from .fakes import FakeClock, FakeTransport


class TestEpochRules(unittest.TestCase):
    def setUp(self):
        self.clock = FakeClock()
        self.queue = OutboundQueue()
        self.queue.new_session()
        self.scheduler = HeartbeatScheduler(self.queue, clock=self.clock)

    def test_budgets_match_the_contract(self):
        self.assertEqual(HEARTBEAT_PERIOD, 1.0)
        self.assertEqual(HEARTBEAT_SERVICE_BUDGET, 2.0)
        self.assertEqual(BROKER_LIVENESS_THRESHOLD, 3.0)

    def test_first_heartbeat_uses_the_connection_epoch(self):
        """§4.2 — 연결 직후 `last_successful_heartbeat=None`, epoch=연결 시각."""
        self.scheduler.reset(0.0)
        self.assertIsNone(self.scheduler.last_successful_heartbeat)
        self.assertEqual(self.scheduler.due_at(), 1.0)
        self.assertEqual(self.scheduler.service_deadline(), 2.0)

    def test_tick_before_due_does_nothing(self):
        self.scheduler.reset(0.0)
        self.assertFalse(self.scheduler.tick(0.99))
        self.assertEqual(self.queue.qsize(), 0)

    def test_tick_at_due_enqueues_one_heartbeat(self):
        self.scheduler.reset(0.0)
        self.assertTrue(self.scheduler.tick(1.0))
        item = self.queue.get(0.0)
        self.assertEqual(item.frame, HEARTBEAT_FRAME)
        self.assertEqual(item.type_rank, TYPE_RANK_HEARTBEAT)
        self.assertEqual(item.absolute_send_deadline, 2.0)

    def test_epoch_advances_only_on_successful_send(self):
        self.scheduler.reset(0.0)
        self.scheduler.tick(1.0)
        # 아직 성공 통보가 없다 → epoch 그대로
        self.assertEqual(self.scheduler.due_at(), 1.0)
        self.scheduler.on_sent(1.05)
        self.assertEqual(self.scheduler.last_successful_heartbeat, 1.05)
        self.assertEqual(self.scheduler.due_at(), 2.05)
        self.assertEqual(self.scheduler.service_deadline(), 3.05)

    def test_reconnect_discards_previous_session_timestamps(self):
        """§4.2 — 이전 session의 성공 시각을 새 session에서 재사용하지 않는다."""
        self.scheduler.reset(0.0)
        self.scheduler.tick(1.0)
        self.scheduler.on_sent(0.75)
        self.assertEqual(self.scheduler.due_at(), 1.75)

        self.queue.new_session()
        self.scheduler.reset(10.0)
        self.assertIsNone(self.scheduler.last_successful_heartbeat)
        self.assertEqual(self.scheduler.session_connected_at, 10.0)
        self.assertEqual(self.scheduler.due_at(), 11.0)
        self.assertEqual(self.scheduler.service_deadline(), 12.0)
        self.assertEqual(self.queue.qsize(), 0)

    def test_pending_heartbeat_is_coalesced_to_one(self):
        metrics = Metrics()
        scheduler = HeartbeatScheduler(self.queue, metrics=metrics, clock=self.clock)
        scheduler.reset(0.0)
        self.assertTrue(scheduler.tick(1.0))
        self.assertFalse(scheduler.tick(2.0))
        self.assertFalse(scheduler.tick(3.0))
        self.assertEqual(self.queue.qsize(), 1)
        self.assertEqual(metrics.counter("heartbeat.coalesced"), 2)

    def test_coalesced_tick_keeps_the_earlier_deadline(self):
        self.scheduler.reset(0.0)
        self.scheduler.tick(1.0)
        self.scheduler.tick(5.0)
        self.assertEqual(self.queue.get(0.0).absolute_send_deadline, 2.0)

    def test_clear_stops_ticking(self):
        self.scheduler.reset(0.0)
        self.scheduler.clear()
        self.assertIsNone(self.scheduler.due_at())
        self.assertFalse(self.scheduler.tick(100.0))

    def test_gap_metric_and_warning(self):
        metrics = Metrics()
        logged = []

        class Recorder:
            def log(self, event, **fields):
                logged.append((event, fields))

        scheduler = HeartbeatScheduler(
            self.queue, metrics=metrics, audit=Recorder(), clock=self.clock
        )
        scheduler.reset(0.0)
        scheduler.on_sent(2.7)  # 3초 임계에 접근
        self.assertEqual(metrics.counter("heartbeat.sent"), 1)
        self.assertTrue(any(event == "heartbeat-gap-warning" for event, _ in logged))


class TestHeartbeatUnderVerdictBacklog(unittest.TestCase):
    """§15.4 — verdict backlog가 계속 nonempty여도 HEARTBEAT가 굶지 않는다."""

    def test_heartbeat_goes_out_before_its_service_deadline(self):
        clock = FakeClock()
        queue = OutboundQueue()
        scheduler = HeartbeatScheduler(queue, clock=clock)
        writer = SocketWriter(queue, clock=clock, on_heartbeat_sent=scheduler.on_sent)
        transport = FakeTransport()
        session_id = queue.new_session()
        writer.attach(transport, session_id)
        sender = VerdictSender(queue, clock=clock)
        scheduler.reset(0.0, session_id)

        heartbeat_sent_at = None
        verdict_results = []

        for _ in range(300):
            # 매 tick 마다 새 verdict 를 넣어 backlog 를 비지 않게 유지한다.
            sender.send(int(clock.now * 1000), VERDICT_ACCEPT, clock.now)
            scheduler.tick()
            result = writer.send_once(0.0)
            if result is not None and result.outcome is SendOutcome.SENT:
                if result.item.type_rank == TYPE_RANK_HEARTBEAT and heartbeat_sent_at is None:
                    heartbeat_sent_at = clock.now
                if result.item.is_verdict:
                    verdict_results.append(result)
            clock.advance(0.01)

        self.assertIsNotNone(heartbeat_sent_at, "HEARTBEAT 가 한 번도 나가지 않았다")
        self.assertLess(heartbeat_sent_at, 2.0, "service deadline 을 넘겨서 나갔다")
        self.assertGreater(scheduler.sent_count, 0)

        # 전송된 verdict 는 모두 packet 수신 후 300ms 안이다.
        self.assertTrue(verdict_results)
        for result in verdict_results:
            self.assertLess(result.completed_at - result.item.received_at, 0.300)

    def test_cadence_stays_near_one_second(self):
        clock = FakeClock()
        queue = OutboundQueue()
        scheduler = HeartbeatScheduler(queue, clock=clock)
        writer = SocketWriter(queue, clock=clock, on_heartbeat_sent=scheduler.on_sent)
        session_id = queue.new_session()
        writer.attach(FakeTransport(), session_id)
        scheduler.reset(0.0, session_id)

        sent_at = []
        for _ in range(1000):
            scheduler.tick()
            result = writer.send_once(0.0)
            if result is not None and result.outcome is SendOutcome.SENT:
                sent_at.append(clock.now)
            clock.advance(0.01)

        self.assertGreaterEqual(len(sent_at), 8)
        gaps = [b - a for a, b in zip(sent_at, sent_at[1:])]
        for gap in gaps:
            self.assertGreaterEqual(gap, 0.99)
            self.assertLess(gap, 1.1)


class TestTickGenerationRace(unittest.TestCase):
    """epoch snapshot과 session id 부착 사이의 재연결(§4.2).

    둘을 따로 읽으면 "이전 epoch에서 계산한 deadline"과 "새 session의 id"가
    결합된 item이 만들어진다. 그 item은 session 검사를 모두 통과하지만 deadline은
    이미 지나 있어, writer가 새 session의 HEARTBEAT를 만료로 처리하고 방금 연
    소켓을 닫는다 — 재연결 직후 다시 fail-open이 되는 경로다.
    """

    def setUp(self):
        self.clock = FakeClock()
        self.queue = OutboundQueue()
        self.faults = []
        self.scheduler = HeartbeatScheduler(self.queue, clock=self.clock)
        self.writer = SocketWriter(
            self.queue, clock=self.clock,
            on_fault=lambda reason, session_id=None: self.faults.append((reason, session_id)),
            on_heartbeat_sent=self.scheduler.on_sent,
        )
        self.old_transport = FakeTransport()
        self.old_session = self.queue.new_session()
        self.writer.attach(self.old_transport, self.old_session)
        self.scheduler.reset(0.0, self.old_session)

    def _reconnect_during_item_construction(self):
        """epoch/session snapshot 직후, item이 큐에 들어가기 전에 재연결시킨다."""
        interposed = {}
        original = self.queue.next_sequence

        def next_sequence_then_reconnect():
            sequence = original()
            if "done" not in interposed:
                interposed["done"] = True
                new_transport = FakeTransport()
                new_session = self.queue.new_session()
                self.writer.attach(new_transport, new_session)
                self.clock.now = 3.0
                self.scheduler.reset(self.clock.now, new_session)
                interposed["transport"] = new_transport
                interposed["session"] = new_session
            return sequence

        self.queue.next_sequence = next_sequence_then_reconnect
        return interposed

    def test_stale_tick_is_discarded_instead_of_expiring_the_new_session(self):
        self.clock.now = 1.0  # epoch 0 기준 due
        interposed = self._reconnect_during_item_construction()

        queued = self.scheduler.tick()

        self.assertTrue(interposed.get("done"), "삽입 지점이 실행되지 않았다")
        self.assertNotEqual(interposed["session"], self.old_session)
        self.assertFalse(queued, "이전 epoch 의 tick 이 새 session 에 enqueue 됐다")
        self.assertEqual(self.queue.qsize(), 0)
        self.assertEqual(self.scheduler.stale_ticks_discarded, 1)
        self.assertEqual(self.queue.stale_heartbeat_offers, 1)

        # writer 는 보낼 것이 없고, 새 transport 는 열린 채로 남는다.
        self.assertIsNone(self.writer.send_once(0.0))
        self.assertFalse(interposed["transport"].closed, "새 socket 이 닫혔다")
        self.assertIs(self.writer.state, WriterState.READY)
        self.assertEqual(self.faults, [], "새 session 에 fault 가 통보됐다")

    def test_next_tick_uses_the_new_epoch(self):
        """폐기된 tick은 손실이 아니다 — 다음 tick이 새 epoch로 다시 만든다."""
        self.clock.now = 1.0
        interposed = self._reconnect_during_item_construction()
        self.scheduler.tick()

        # 새 epoch 3.0 → due 4.0, service deadline 5.0
        self.clock.now = 4.0
        self.assertTrue(self.scheduler.tick())

        # 큐에서 직접 꺼내 검사하면 writer 가 보낼 것이 없어지므로, 실제 송신
        # 결과에서 item 을 확인한다.
        result = self.writer.send_once(0.0)
        self.assertIs(result.outcome, SendOutcome.SENT)
        self.assertEqual(result.item.session_id, interposed["session"])
        self.assertEqual(result.item.absolute_send_deadline, 5.0)
        self.assertEqual(self.faults, [])
        self.assertEqual(self.scheduler.last_successful_heartbeat, 4.0)

    def test_item_carries_the_scheduler_session_not_the_queue_session(self):
        """부착하는 id의 출처가 계약이다.

        큐의 현재 session을 읽으면 epoch와 id가 서로 다른 시점의 값이 되어
        위 경합이 그대로 생긴다.
        """
        self.clock.now = 1.0
        # scheduler 만 이전 generation 에 남기고 큐를 먼저 넘긴다.
        new_session = self.queue.new_session()
        self.assertNotEqual(new_session, self.old_session)

        self.assertFalse(self.scheduler.tick())
        self.assertEqual(self.queue.qsize(), 0)
        self.assertEqual(self.scheduler.stale_ticks_discarded, 1)


class TestSchedulerThread(unittest.TestCase):
    def test_stop_returns_quickly(self):
        queue = OutboundQueue()
        queue.new_session()
        scheduler = HeartbeatScheduler(queue)
        scheduler.reset(0.0)
        scheduler.start()
        started = threading.Event()
        started.wait(0.05)
        scheduler.stop(timeout=2.0)
        self.assertIsNone(scheduler._thread)

    def test_start_is_idempotent(self):
        queue = OutboundQueue()
        queue.new_session()
        scheduler = HeartbeatScheduler(queue)
        scheduler.start()
        first = scheduler._thread
        scheduler.start()
        self.assertIs(scheduler._thread, first)
        scheduler.stop(timeout=2.0)


if __name__ == "__main__":
    unittest.main()
