"""Broker session, 재연결, 단일 writer 테스트.

설계 §4.2 writer 상태기계, §5.3 승인된 실행 모델, §13 오류 처리, §15.2, §15.4.
"""

import threading
import unittest

from aegis_defender.config import RuntimeConfig
from aegis_defender.metrics import Metrics
from aegis_defender.protocol import (
    HEARTBEAT_FRAME,
    VERDICT_ACCEPT,
    encode_verdict,
)
from aegis_defender.session import (
    MAX_OUTBOUND_IN_FLIGHT,
    SOCKET_FAULT_TIMEOUT,
    TYPE_RANK_HEARTBEAT,
    TYPE_RANK_VERDICT,
    BrokerSession,
    OutboundFull,
    OutboundItem,
    OutboundQueue,
    SendOutcome,
    SocketWriter,
    VerdictSender,
    WriterState,
)

from .fakes import FakeClock, FakeTransport, ipv4_tcp, packet_frame

CONFIG = RuntimeConfig(agent_socket="/run/agent.sock")


def heartbeat_item(queue: OutboundQueue, service_deadline: float) -> OutboundItem:
    return OutboundItem(
        absolute_send_deadline=service_deadline,
        type_rank=TYPE_RANK_HEARTBEAT,
        sequence=queue.next_sequence(),
        frame=HEARTBEAT_FRAME,
        session_id=queue.current_session(),
    )


def verdict_item(queue: OutboundQueue, pkt_id: int, received_at: float) -> OutboundItem:
    return OutboundItem(
        absolute_send_deadline=received_at + 0.200,
        type_rank=TYPE_RANK_VERDICT,
        sequence=queue.next_sequence(),
        frame=encode_verdict(pkt_id, VERDICT_ACCEPT),
        session_id=queue.current_session(),
        pkt_id=pkt_id,
        received_at=received_at,
        broker_deadline=received_at + 0.300,
    )


class TestOutboundQueue(unittest.TestCase):
    """§4.2 — 정렬 key는 `(absolute_send_deadline, type_rank, sequence)`."""

    def setUp(self):
        self.queue = OutboundQueue()
        self.queue.new_session()

    def test_earliest_absolute_deadline_first_regardless_of_type(self):
        # HEARTBEAT service deadline 이 두 VERDICT deadline 사이에 오면
        # 이른 VERDICT → HEARTBEAT → 늦은 VERDICT 순서다. type-first 우선순위가
        # 없어야 verdict backlog 가 HEARTBEAT 를 굶기지 않는다.
        early = verdict_item(self.queue, 1, received_at=0.0)      # deadline 0.200
        late = verdict_item(self.queue, 2, received_at=0.2)       # deadline 0.400
        beat = heartbeat_item(self.queue, service_deadline=0.300)

        self.queue.put_nowait(late)
        self.queue.offer_heartbeat(beat)
        self.queue.put_nowait(early)

        order = [self.queue.get(0.0), self.queue.get(0.0), self.queue.get(0.0)]
        self.assertEqual(order[0].pkt_id, 1)
        self.assertEqual(order[1].type_rank, TYPE_RANK_HEARTBEAT)
        self.assertEqual(order[2].pkt_id, 2)

    def test_deadline_tie_prefers_verdict(self):
        beat = heartbeat_item(self.queue, service_deadline=0.200)
        verdict = verdict_item(self.queue, 5, received_at=0.0)  # deadline 0.200
        self.queue.offer_heartbeat(beat)
        self.queue.put_nowait(verdict)
        self.assertEqual(self.queue.get(0.0).pkt_id, 5)
        self.assertEqual(self.queue.get(0.0).type_rank, TYPE_RANK_HEARTBEAT)

    def test_heartbeat_coalesces_to_one_pending(self):
        self.assertTrue(self.queue.offer_heartbeat(heartbeat_item(self.queue, 2.0)))
        self.assertFalse(self.queue.offer_heartbeat(heartbeat_item(self.queue, 3.0)))
        self.assertEqual(self.queue.heartbeat_coalesced, 1)
        self.assertEqual(self.queue.qsize(), 1)

    def test_coalesce_does_not_extend_the_earlier_deadline(self):
        self.queue.offer_heartbeat(heartbeat_item(self.queue, 2.0))
        self.queue.offer_heartbeat(heartbeat_item(self.queue, 9.0))
        self.assertEqual(self.queue.get(0.0).absolute_send_deadline, 2.0)

    def test_in_flight_cap_is_256(self):
        self.assertEqual(MAX_OUTBOUND_IN_FLIGHT, 256)
        for index in range(MAX_OUTBOUND_IN_FLIGHT):
            self.queue.put_nowait(verdict_item(self.queue, index, 0.0))
        self.assertEqual(self.queue.in_flight(), 256)
        with self.assertRaises(OutboundFull):
            self.queue.put_nowait(verdict_item(self.queue, 999, 0.0))

    def test_sending_item_still_counts_toward_in_flight(self):
        for index in range(MAX_OUTBOUND_IN_FLIGHT):
            self.queue.put_nowait(verdict_item(self.queue, index, 0.0))
        item = self.queue.get(0.0)  # SENDING 으로 넘어갔지만 아직 in-flight 다
        self.assertEqual(self.queue.in_flight(), 256)
        with self.assertRaises(OutboundFull):
            self.queue.put_nowait(verdict_item(self.queue, 999, 0.0))
        self.queue.complete(item)
        self.queue.put_nowait(verdict_item(self.queue, 1000, 0.0))

    def test_new_session_discards_previous_items(self):
        self.queue.put_nowait(verdict_item(self.queue, 1, 0.0))
        self.queue.new_session()
        self.assertEqual(self.queue.qsize(), 0)
        self.assertEqual(self.queue.in_flight(), 0)

    def test_stale_session_item_is_rejected(self):
        item = verdict_item(self.queue, 1, 0.0)
        self.queue.new_session()
        with self.assertRaises(OutboundFull):
            self.queue.put_nowait(item)


class TestSocketWriterBudget(unittest.TestCase):
    """§4.2 — item별 남은 예산을 dequeue 직후와 send 직전에 다시 계산한다."""

    def setUp(self):
        self.clock = FakeClock()
        self.queue = OutboundQueue()
        self.metrics = Metrics()
        self.faults = []
        self.writer = SocketWriter(
            self.queue, metrics=self.metrics, clock=self.clock,
            on_fault=self.faults.append,
        )
        self.transport = FakeTransport()
        self.session_id = self.queue.new_session()
        self.writer.attach(self.transport, self.session_id)

    def test_verdict_timeout_is_min_50ms_and_broker_remaining_minus_100ms(self):
        self.queue.put_nowait(verdict_item(self.queue, 1, received_at=0.0))
        self.clock.advance(0.17)  # broker_remaining = 0.13
        result = self.writer.send_once(0.0)
        self.assertIs(result.outcome, SendOutcome.SENT)
        # min(50ms, 130ms - 100ms) = 30ms
        self.assertAlmostEqual(self.transport.timeouts[-1], 0.03, places=6)

    def test_verdict_timeout_capped_at_socket_fault_timeout(self):
        self.queue.put_nowait(verdict_item(self.queue, 1, received_at=0.0))
        result = self.writer.send_once(0.0)
        self.assertIs(result.outcome, SendOutcome.SENT)
        self.assertAlmostEqual(self.transport.timeouts[-1], SOCKET_FAULT_TIMEOUT, places=6)

    def test_verdict_expires_at_internal_hard_cutoff(self):
        # broker_remaining <= 100ms 는 내부 200ms hard cutoff 도달과 같다.
        self.queue.put_nowait(verdict_item(self.queue, 1, received_at=0.0))
        self.clock.advance(0.200)
        result = self.writer.send_once(0.0)
        self.assertIs(result.outcome, SendOutcome.EXPIRED)
        self.assertEqual(self.transport.sent, [])
        self.assertEqual(self.faults, ["deadline-exhausted"])
        self.assertEqual(self.metrics.counter("outbound.verdict_expired"), 1)

    def test_expired_verdict_is_not_replayed_to_a_new_session(self):
        self.queue.put_nowait(verdict_item(self.queue, 77, received_at=0.0))
        self.clock.advance(0.25)
        self.writer.send_once(0.0)
        # fault 후 새 session 을 열고 다시 돌려도 보낼 것이 없다.
        new_transport = FakeTransport()
        self.writer.attach(new_transport, self.queue.new_session())
        self.assertIsNone(self.writer.send_once(0.0))
        self.assertEqual(new_transport.sent, [])

    def test_heartbeat_timeout_uses_service_deadline(self):
        self.queue.offer_heartbeat(heartbeat_item(self.queue, service_deadline=2.0))
        self.clock.advance(1.98)
        result = self.writer.send_once(0.0)
        self.assertIs(result.outcome, SendOutcome.SENT)
        self.assertAlmostEqual(self.transport.timeouts[-1], 0.02, places=6)

    def test_stale_heartbeat_is_not_sent(self):
        self.queue.offer_heartbeat(heartbeat_item(self.queue, service_deadline=2.0))
        self.clock.advance(2.5)
        result = self.writer.send_once(0.0)
        self.assertIs(result.outcome, SendOutcome.EXPIRED)
        self.assertEqual(self.transport.sent, [])
        self.assertTrue(self.faults)

    def test_blocked_send_times_out_and_reconnects(self):
        self.transport.blocked = True
        self.queue.put_nowait(verdict_item(self.queue, 1, received_at=0.0))
        self.queue.put_nowait(verdict_item(self.queue, 2, received_at=0.0))
        result = self.writer.send_once(0.0)
        self.assertIs(result.outcome, SendOutcome.TIMEOUT)
        self.assertTrue(self.transport.closed)
        self.assertEqual(self.queue.qsize(), 0)  # 같은 session item 폐기
        self.assertIs(self.writer.state, WriterState.DISCONNECTED)

    def test_partial_send_is_a_fault(self):
        self.transport.partial_by = 1
        self.queue.put_nowait(verdict_item(self.queue, 1, received_at=0.0))
        result = self.writer.send_once(0.0)
        self.assertIs(result.outcome, SendOutcome.PARTIAL)
        self.assertTrue(self.faults)

    def test_broken_pipe_is_a_fault(self):
        self.transport.error = BrokenPipeError()
        self.queue.put_nowait(verdict_item(self.queue, 1, received_at=0.0))
        self.assertIs(self.writer.send_once(0.0).outcome, SendOutcome.ERROR)
        self.assertTrue(self.faults)

    def test_connection_reset_is_a_fault(self):
        self.transport.error = ConnectionResetError()
        self.queue.put_nowait(verdict_item(self.queue, 1, received_at=0.0))
        self.assertIs(self.writer.send_once(0.0).outcome, SendOutcome.ERROR)
        self.assertTrue(self.faults)

    def test_heartbeat_epoch_advances_only_on_full_success(self):
        completions = []
        writer = SocketWriter(
            self.queue, clock=self.clock, on_heartbeat_sent=completions.append,
            on_fault=self.faults.append,
        )
        transport = FakeTransport()
        writer.attach(transport, self.queue.current_session())

        transport.blocked = True
        self.queue.offer_heartbeat(heartbeat_item(self.queue, 2.0))
        writer.send_once(0.0)
        self.assertEqual(completions, [])

        transport = FakeTransport()
        writer.attach(transport, self.queue.new_session())
        self.clock.advance(1.0)
        self.queue.offer_heartbeat(heartbeat_item(self.queue, 3.0))
        writer.send_once(0.0)
        self.assertEqual(len(completions), 1)


class TestStaleSessionResults(unittest.TestCase):
    """blocking send 중에 재연결이 끼어드는 경쟁 상황(§4.2).

    `send`는 lock 밖에서 일어나므로, 반환할 때쯤이면 수신 쪽이 EOF를 받아 이미
    재연결했을 수 있다. 이전 session의 뒤늦은 결과가 현재 session을 끊으면 방금
    enqueue한 verdict가 폐기되고 그 구간이 그대로 fail-open이 된다.
    """

    def setUp(self):
        self.clock = FakeClock()
        self.queue = OutboundQueue()
        self.metrics = Metrics()
        self.faults = []
        self.writer = SocketWriter(
            self.queue, metrics=self.metrics, clock=self.clock,
            on_fault=self.faults.append,
        )
        self.sender = VerdictSender(self.queue, clock=self.clock)

        self.old = FakeTransport()
        self.old.hold = threading.Event()
        self.old_session = self.queue.new_session()
        self.writer.attach(self.old, self.old_session)

    def _start_blocked_send(self):
        """이전 session의 send를 시작해 transport 안에서 멈춘 상태로 둔다."""
        self.sender.send(1, VERDICT_ACCEPT, self.clock.now)
        box = []
        thread = threading.Thread(target=lambda: box.append(self.writer.send_once(0.0)))
        thread.start()
        self.assertTrue(self.old.entered_send.wait(2.0), "send 에 진입하지 못했다")
        return thread, box

    def _reconnect(self):
        """수신 쪽이 EOF를 받아 재연결한 상황을 재현한다."""
        self.writer.detach(self.old, self.old_session)
        new_transport = FakeTransport()
        new_session = self.queue.new_session()
        self.writer.attach(new_transport, new_session)
        return new_transport, new_session

    def _release(self, thread, outcome_error=None):
        if outcome_error is not None:
            self.old.error = outcome_error
        self.old.hold.set()
        thread.join(timeout=3.0)
        self.assertFalse(thread.is_alive())

    def test_late_timeout_does_not_kill_the_new_session(self):
        thread, box = self._start_blocked_send()
        new_transport, _ = self._reconnect()
        self.assertTrue(self.sender.send(2, VERDICT_ACCEPT, self.clock.now))
        self.assertEqual(self.queue.qsize(), 1)

        self._release(thread, TimeoutError("late timeout"))

        self.assertIs(box[0].outcome, SendOutcome.STALE)
        self.assertEqual(self.queue.qsize(), 1, "새 session verdict 가 폐기됐다")
        self.assertFalse(new_transport.closed, "새 socket 이 닫혔다")
        self.assertIs(self.writer.state, WriterState.READY)
        self.assertEqual(self.faults, [], "이전 session 실패가 재연결을 유발했다")
        self.assertEqual(self.metrics.counter("outbound.send_stale"), 1)

    def test_late_socket_error_does_not_kill_the_new_session(self):
        thread, box = self._start_blocked_send()
        new_transport, _ = self._reconnect()
        self.sender.send(2, VERDICT_ACCEPT, self.clock.now)

        self._release(thread, ConnectionResetError("late reset"))

        self.assertIs(box[0].outcome, SendOutcome.STALE)
        self.assertEqual(self.queue.qsize(), 1)
        self.assertFalse(new_transport.closed)
        self.assertEqual(self.faults, [])

    def test_late_success_does_not_free_the_new_session_in_flight(self):
        """뒤늦은 성공도 현재 session의 in-flight 카운트를 건드리면 안 된다."""
        thread, box = self._start_blocked_send()
        self._reconnect()
        self.sender.send(2, VERDICT_ACCEPT, self.clock.now)
        before = self.queue.in_flight()

        self._release(thread)

        self.assertIs(box[0].outcome, SendOutcome.STALE)
        self.assertEqual(self.queue.in_flight(), before)

    def test_late_heartbeat_success_does_not_advance_the_new_epoch(self):
        """§4.2 — reconnect는 이전 session의 HEARTBEAT 시각을 재사용하지 않는다."""
        completions = []
        writer = SocketWriter(
            self.queue, clock=self.clock, on_heartbeat_sent=completions.append,
            on_fault=self.faults.append,
        )
        old = FakeTransport()
        old.hold = threading.Event()
        writer.attach(old, self.queue.current_session())

        self.queue.offer_heartbeat(heartbeat_item(self.queue, service_deadline=2.0))
        box = []
        thread = threading.Thread(target=lambda: box.append(writer.send_once(0.0)))
        thread.start()
        self.assertTrue(old.entered_send.wait(2.0))

        writer.detach(old, self.queue.current_session())
        writer.attach(FakeTransport(), self.queue.new_session())

        old.hold.set()
        thread.join(timeout=3.0)

        self.assertIs(box[0].outcome, SendOutcome.STALE)
        self.assertEqual(completions, [], "이전 session 의 HEARTBEAT 가 epoch 를 옮겼다")

    def test_late_heartbeat_does_not_reopen_the_new_pending_slot(self):
        """뒤늦은 완료가 HEARTBEAT slot을 열면 pending 중인 것이 중복 발행된다."""
        thread, box = self._start_blocked_send()
        self._reconnect()
        self.assertTrue(
            self.queue.offer_heartbeat(heartbeat_item(self.queue, service_deadline=2.0))
        )

        # 이전 session 의 HEARTBEAT 완료를 흉내 낸다.
        stale_heartbeat = OutboundItem(
            absolute_send_deadline=2.0,
            type_rank=TYPE_RANK_HEARTBEAT,
            sequence=0,
            frame=HEARTBEAT_FRAME,
            session_id=self.old_session,
        )
        self.assertFalse(self.queue.complete(stale_heartbeat))
        self.assertFalse(
            self.queue.offer_heartbeat(heartbeat_item(self.queue, service_deadline=3.0)),
            "HEARTBEAT slot 이 다시 열렸다",
        )

        self._release(thread)
        del box

    def test_detach_ignores_a_generation_that_is_no_longer_current(self):
        new_transport, new_session = self._reconnect()
        # 이미 지나간 generation 으로 detach 를 시도해도 현재 것을 닫지 않는다.
        self.assertFalse(self.writer.detach(self.old, self.old_session))
        self.assertFalse(new_transport.closed)
        self.assertIs(self.writer.state, WriterState.READY)
        # 현재 generation 으로는 정상 동작한다.
        self.assertTrue(self.writer.detach(new_transport, new_session))
        self.assertTrue(new_transport.closed)
        self.old.hold.set()


class TestSingleWriterOwnership(unittest.TestCase):
    """§4.2 — 소켓에 쓰는 주체는 `SocketWriter` 하나뿐이다."""

    def test_only_one_thread_ever_writes(self):
        clock = FakeClock()
        queue = OutboundQueue()
        writer = SocketWriter(queue, clock=clock)
        transport = FakeTransport()
        writer.attach(transport, queue.new_session())
        sender = VerdictSender(queue, clock=clock)

        producers = []
        for index in range(4):
            thread = threading.Thread(
                target=lambda i=index: [sender.send(i * 10 + n, VERDICT_ACCEPT, 0.0) for n in range(5)]
            )
            producers.append(thread)
            thread.start()
        for thread in producers:
            thread.join()

        writer.start()
        deadline = threading.Event()
        deadline.wait(0.3)
        writer.stop(1.0)

        self.assertEqual(len(transport.callers), 1)
        self.assertIn("socket-writer", next(iter(transport.callers)))

    def test_verdict_sender_owns_no_socket_or_deadline_api(self):
        # §7 — VerdictSender 는 frame·metadata enqueue 와 계측만 한다. socket,
        # send timeout, deadline 만료, priority dequeue, reconnect 판단은 전부
        # SocketWriter 가 소유한다.
        forbidden = ("settimeout", "close", "attach", "detach", "socket", "transport")
        for name in forbidden:
            self.assertFalse(
                hasattr(VerdictSender, name), f"VerdictSender 에 {name} 이 있어서는 안 된다"
            )

    def test_verdict_enqueue_works_with_no_socket_attached(self):
        # socket 을 전혀 모른다는 사실의 직접 증거 — writer 가 attach 되지 않아도
        # enqueue 는 성공한다.
        queue = OutboundQueue()
        queue.new_session()
        sender = VerdictSender(queue, clock=FakeClock())
        self.assertTrue(sender.send(1, VERDICT_ACCEPT, 0.0))
        self.assertEqual(queue.qsize(), 1)

    def test_enqueue_failure_returns_false_without_dropping_silently(self):
        clock = FakeClock()
        queue = OutboundQueue()
        queue.new_session()
        metrics = Metrics()
        sender = VerdictSender(queue, metrics=metrics, clock=clock)
        for index in range(MAX_OUTBOUND_IN_FLIGHT):
            self.assertTrue(sender.send(index, VERDICT_ACCEPT, 0.0))
        self.assertFalse(sender.send(9999, VERDICT_ACCEPT, 0.0))
        self.assertEqual(metrics.counter("outbound.enqueue_full"), 1)


class TestBrokerSessionLifecycle(unittest.TestCase):
    def _session(self, connect_fn, metrics=None):
        clock = FakeClock()
        queue = OutboundQueue()
        writer = SocketWriter(queue, clock=clock)
        return BrokerSession(
            config=CONFIG, queue=queue, writer=writer, heartbeat=None,
            metrics=metrics or Metrics(), clock=clock, connect_fn=connect_fn,
        ), writer, queue

    def test_connect_retries_until_success(self):
        """§13 — 재시도 포기는 곧 fail-open이다."""
        attempts = {"count": 0}
        transport = FakeTransport()

        def connect(path):
            attempts["count"] += 1
            if attempts["count"] < 4:
                raise ConnectionRefusedError("broker not ready")
            transport.feed(b"")  # 연결되자마자 EOF → 루프 종료용
            return transport

        session, _, _ = self._session(connect)
        received = []

        def run():
            session.run(lambda envelope: received.append(envelope) or True)

        thread = threading.Thread(target=run, daemon=True)
        thread.start()
        threading.Event().wait(0.6)
        session.stop()
        thread.join(timeout=2.0)

        self.assertGreaterEqual(attempts["count"], 4)
        self.assertGreaterEqual(session.sessions_opened, 1)

    def test_packets_reach_the_producer(self):
        transport = FakeTransport()
        transport.feed(packet_frame(1, ipv4_tcp(b"GET / HTTP/1.1\r\n\r\n")))
        transport.feed(packet_frame(2, ipv4_tcp(b"GET /x HTTP/1.1\r\n\r\n")))
        transport.feed(b"")

        session, _, _ = self._session(lambda path: transport)
        seen = []

        def on_packet(envelope):
            seen.append(envelope.pkt_id)
            if len(seen) == 2:
                session.stop()
            return True

        session.run(on_packet)
        self.assertEqual(seen, [1, 2])

    def test_unknown_message_type_does_not_end_the_session(self):
        metrics = Metrics()
        transport = FakeTransport()
        transport.feed(bytes([0x09, 0x00]))
        transport.feed(packet_frame(7, ipv4_tcp()))
        transport.feed(b"")

        session, _, _ = self._session(lambda path: transport, metrics=metrics)
        seen = []

        def on_packet(envelope):
            seen.append(envelope.pkt_id)
            session.stop()
            return True

        session.run(on_packet)
        self.assertEqual(seen, [7])
        self.assertEqual(metrics.counter("frame.unknown_type"), 1)

    def test_short_header_ends_the_session_without_a_verdict(self):
        """§13 — 존재하지 않는 ID로 verdict를 만들지 않는다.

        같은 session의 뒤 frame도 읽지 않는다. 짧은 frame은 protocol desync이고
        desync 상태에서 읽은 바이트는 어떤 frame의 일부인지 알 수 없기 때문이다.
        """
        metrics = Metrics()
        first = FakeTransport()
        first.feed(bytes([0x01, 0x00, 0x00]))
        first.feed(packet_frame(9, ipv4_tcp()))
        calls = {"count": 0}

        def connect(path):
            calls["count"] += 1
            if calls["count"] == 1:
                return first
            session.stop()
            return FakeTransport()

        session, _, _ = self._session(connect, metrics=metrics)
        seen = []
        session.run(lambda envelope: seen.append(envelope.pkt_id) or True)

        self.assertEqual(seen, [])
        self.assertEqual(metrics.counter("frame.short_header"), 1)
        self.assertTrue(first.closed)

    def test_length_mismatch_still_produces_an_envelope(self):
        transport = FakeTransport()
        transport.feed(packet_frame(11, b"\xaa" * 5, declared_len=40))
        transport.feed(b"")

        session, _, _ = self._session(lambda path: transport)
        seen = []

        def on_packet(envelope):
            seen.append(envelope)
            session.stop()
            return True

        session.run(on_packet)
        self.assertEqual(len(seen), 1)
        self.assertEqual(seen[0].pkt_id, 11)
        self.assertEqual(seen[0].frame_status.value, "frame-length-mismatch")

    def test_producer_fault_ends_the_session(self):
        transport = FakeTransport()
        transport.feed(packet_frame(1, ipv4_tcp()))
        transport.feed(packet_frame(2, ipv4_tcp()))

        session, _, _ = self._session(lambda path: transport)
        seen = []

        def on_packet(envelope):
            seen.append(envelope.pkt_id)
            session.stop()
            return False  # enqueue 실패 = session fault

        session.run(on_packet)
        self.assertEqual(seen, [1])

    def test_reconnect_opens_a_new_session_id_and_discards_old_items(self):
        made = []

        def connect(path):
            transport = FakeTransport()
            transport.feed(b"")  # 즉시 EOF → 재연결
            made.append(transport)
            if len(made) >= 3:
                session.stop()
            return transport

        session, _, queue = self._session(connect)
        session.run(lambda envelope: True)

        self.assertGreaterEqual(session.sessions_opened, 3)
        self.assertGreaterEqual(queue.current_session(), 3)
        self.assertEqual(queue.qsize(), 0)
        self.assertEqual(queue.in_flight(), 0)
        self.assertTrue(all(transport.closed for transport in made))


if __name__ == "__main__":
    unittest.main()
