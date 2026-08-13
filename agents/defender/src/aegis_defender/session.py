"""Broker session, 재연결, deadline-aware 단일 writer.

설계 §4.2 동시성 경계와 writer 상태기계, §5.3 승인된 실행 모델, §13 오류 처리.

레퍼런스 구현과 의도적으로 다른 두 지점이 이 모듈에 있다.

1. **소켓 오류·EOF에서 프로세스를 종료하지 않는다.** 레퍼런스는 그 경우 그대로
   죽는데, 에이전트가 죽으면 Broker는 fail-open으로 전 패킷을 통과시킨다
   (운영세칙 제13조 2항). 즉 종료는 곧 무방비다. 그래서 재연결은 선택이 아니라
   필수이고, **재시도 포기가 곧 fail-open**이므로 bounded backoff로 무한 재시도한다.
2. **`sock.send`를 timeout 없이 호출하지 않는다.** 레퍼런스는 무기한 블로킹하므로
   소켓 송신 버퍼가 차면 VERDICT와 HEARTBEAT가 함께 멈춘다. 여기서는 item별 남은
   예산으로 상한을 두고, 넘기면 소켓을 닫아 재연결한다.

`settimeout`을 쓰지 않고 non-blocking 소켓 + `select`를 쓰는 이유도 같은 맥락이다.
읽기 스레드와 쓰기 스레드가 같은 fd를 공유하는데 `settimeout`은 소켓 전역 상태라
한쪽이 바꾸면 다른 쪽의 블로킹 동작이 함께 바뀐다. 연산별 deadline을 `select`로
직접 다루면 그 공유 상태가 사라진다.
"""

from __future__ import annotations

import heapq
import select
import socket
import threading
import time
from dataclasses import dataclass
from enum import Enum
from typing import Callable

from .config import RuntimeConfig
from .logging import AuditLogger
from .metrics import (
    L_SEND,
    M_FRAME_LENGTH_MISMATCH,
    M_FRAME_SHORT_HEADER,
    M_FRAME_TRAILING_BYTES,
    M_FRAME_UNKNOWN_TYPE,
    M_PACKET_RECEIVED,
    M_SEND_ERROR,
    M_SEND_OK,
    M_SEND_PARTIAL,
    M_SEND_TIMEOUT,
    M_SESSION_CONNECTED,
    M_SESSION_FAULT,
    M_SESSION_RECONNECT_ATTEMPT,
    M_VERDICT_EXPIRED,
    Metrics,
)
from .protocol import (
    MAX_PACKET_MSG_SIZE,
    FrameOutcome,
    FrameStatus,
    decode_frame,
)

# §5.2 확정 예산
VERDICT_INTERNAL_BUDGET = 0.200
BROKER_DEADLINE_BUDGET = 0.300
BROKER_SAFETY_MARGIN = 0.100
SOCKET_FAULT_TIMEOUT = 0.050

MAX_OUTBOUND_IN_FLIGHT = 256

BACKOFF_INITIAL = 0.05
BACKOFF_MAX = 1.0
BACKOFF_FACTOR = 2.0

READ_POLL_SECONDS = 0.2
QUEUE_POLL_SECONDS = 0.2

TYPE_RANK_VERDICT = 0
TYPE_RANK_HEARTBEAT = 1


class OutboundFull(Exception):
    """in-flight 상한 초과. backpressure가 아니라 session fault다(§4.2)."""


class WriterState(str, Enum):
    DISCONNECTED = "disconnected"
    READY = "ready"
    SENDING = "sending"
    FAULT = "fault"
    STOPPED = "stopped"


class SendOutcome(str, Enum):
    SENT = "sent"
    EXPIRED = "expired"
    TIMEOUT = "timeout"
    ERROR = "error"
    PARTIAL = "partial"
    STALE = "stale-session"

    @property
    def is_fault(self) -> bool:
        return self in (
            SendOutcome.EXPIRED, SendOutcome.TIMEOUT,
            SendOutcome.ERROR, SendOutcome.PARTIAL,
        )


@dataclass(frozen=True, slots=True)
class PacketEnvelope:
    """§8 — monotonic 기준 시각이 필수다.

    벽시계를 쓰지 않는 이유는 NTP 보정 때문이다. Round 중 벽시계가 한 번 조정되면
    "수신 후 300ms"라는 계산이 통째로 어긋난다(§5.2).
    """

    pkt_id: int
    declared_len: int
    raw_ip: bytes
    received_at_monotonic: float
    frame_status: FrameStatus


@dataclass(frozen=True, slots=True)
class OutboundItem:
    absolute_send_deadline: float
    type_rank: int
    sequence: int
    frame: bytes
    session_id: int
    pkt_id: int = -1
    received_at: float = 0.0
    broker_deadline: float = 0.0

    @property
    def is_verdict(self) -> bool:
        return self.type_rank == TYPE_RANK_VERDICT

    def sort_key(self) -> tuple[float, int, int]:
        """§4.2 — 두 message type을 하나의 절대 send deadline으로 비교한다.

        deadline이 같을 때만 VERDICT가 앞선다. type을 1차 기준으로 쓰지 않는
        이유는, 그렇게 하면 verdict backlog가 이어지는 동안 HEARTBEAT가 굶어
        3초 침묵 → fail-open에 이를 수 있기 때문이다.
        """
        return (self.absolute_send_deadline, self.type_rank, self.sequence)


@dataclass(frozen=True, slots=True)
class SendResult:
    item: OutboundItem
    outcome: SendOutcome
    completed_at: float
    detail: str = ""


class OutboundQueue:
    """deadline 우선순위 큐. `put_nowait`만 제공하고 절대 블로킹하지 않는다."""

    def __init__(self, capacity: int = MAX_OUTBOUND_IN_FLIGHT) -> None:
        self._cv = threading.Condition()
        self._heap: list[tuple[tuple[float, int, int], OutboundItem]] = []
        self._capacity = capacity
        self._in_flight = 0
        self._session_id = 0
        self._sequence = 0
        self._heartbeat_pending = False
        self._closed = False
        self.heartbeat_coalesced = 0

    @property
    def capacity(self) -> int:
        return self._capacity

    def current_session(self) -> int:
        with self._cv:
            return self._session_id

    def next_sequence(self) -> int:
        with self._cv:
            self._sequence += 1
            return self._sequence

    def new_session(self) -> int:
        """새 session을 연다. 이전 session의 item과 HEARTBEAT slot을 폐기한다."""
        with self._cv:
            self._heap.clear()
            self._in_flight = 0
            self._heartbeat_pending = False
            self._session_id += 1
            self._cv.notify_all()
            return self._session_id

    def in_flight(self) -> int:
        """`SENDING` 1건과 pending item의 합(§4.2)."""
        with self._cv:
            return self._in_flight

    def qsize(self) -> int:
        with self._cv:
            return len(self._heap)

    def put_nowait(self, item: OutboundItem) -> None:
        """VERDICT enqueue. 상한 초과는 `OutboundFull`이며 곧 session fault다."""
        with self._cv:
            if self._closed:
                raise OutboundFull("writer stopped")
            if item.session_id != self._session_id:
                raise OutboundFull("stale session")
            if self._in_flight >= self._capacity:
                raise OutboundFull(f"in-flight {self._in_flight} >= {self._capacity}")
            heapq.heappush(self._heap, (item.sort_key(), item))
            self._in_flight += 1
            self._cv.notify()

    def offer_heartbeat(self, item: OutboundItem) -> bool:
        """HEARTBEAT는 최대 1건만 pending이다. 이미 있으면 coalesce한다.

        기존 pending의 더 이른 service deadline을 연장하지 않는다(§4.2). 새 tick을
        버리는 쪽이 그 규칙을 만족하는 가장 단순한 구현이다 — 시간은 앞으로만
        가므로 나중 tick의 deadline이 항상 같거나 더 늦기 때문이다.
        """
        with self._cv:
            if self._closed or item.session_id != self._session_id:
                return False
            if self._heartbeat_pending:
                self.heartbeat_coalesced += 1
                return False
            if self._in_flight >= self._capacity:
                self.heartbeat_coalesced += 1
                return False
            heapq.heappush(self._heap, (item.sort_key(), item))
            self._in_flight += 1
            self._heartbeat_pending = True
            self._cv.notify()
            return True

    def get(self, timeout: float = QUEUE_POLL_SECONDS) -> OutboundItem | None:
        """가장 이른 절대 deadline의 item. 없으면 `None`."""
        with self._cv:
            if not self._heap:
                self._cv.wait(timeout)
            if not self._heap:
                return None
            return heapq.heappop(self._heap)[1]

    def complete(self, item: OutboundItem) -> None:
        """send 시도가 끝났다. in-flight를 줄이고 HEARTBEAT slot을 연다."""
        with self._cv:
            if self._in_flight > 0:
                self._in_flight -= 1
            if item.type_rank == TYPE_RANK_HEARTBEAT:
                self._heartbeat_pending = False

    def purge_session(self) -> int:
        """현재 session의 대기 item을 모두 버린다. 새 session에 replay하지 않는다."""
        with self._cv:
            dropped = len(self._heap)
            self._heap.clear()
            self._in_flight = 0
            self._heartbeat_pending = False
            return dropped

    def close(self) -> None:
        with self._cv:
            self._closed = True
            self._heap.clear()
            self._in_flight = 0
            self._cv.notify_all()


class SocketTransport:
    """non-blocking 소켓 위의 deadline 있는 송수신.

    `settimeout`을 쓰지 않는다. 읽기 스레드와 쓰기 스레드가 같은 fd를 공유하는데
    `settimeout`은 소켓 전역 상태여서, 한쪽이 timeout을 바꾸면 이미 블로킹 중인
    다른 쪽의 동작까지 바뀐다.
    """

    def __init__(self, sock: socket.socket, clock=time.monotonic) -> None:
        self._sock = sock
        self._clock = clock
        sock.setblocking(False)

    def send(self, frame: bytes, timeout: float) -> int:
        """timeout 안에 보내지 못하면 `TimeoutError`."""
        deadline = self._clock() + timeout
        while True:
            try:
                return self._sock.send(frame)
            except BlockingIOError:
                pass
            remaining = deadline - self._clock()
            if remaining <= 0.0:
                raise TimeoutError("send budget exhausted")
            if not select.select([], [self._sock], [], remaining)[1]:
                raise TimeoutError("send budget exhausted")

    def recv(self, timeout: float) -> bytes | None:
        """`None`은 timeout, `b""`는 EOF다."""
        try:
            return self._sock.recv(MAX_PACKET_MSG_SIZE)
        except BlockingIOError:
            pass
        if not select.select([self._sock], [], [], timeout)[0]:
            return None
        try:
            return self._sock.recv(MAX_PACKET_MSG_SIZE)
        except BlockingIOError:
            return None

    def close(self) -> None:
        try:
            self._sock.close()
        except OSError:
            pass


class SocketWriter:
    """**소켓에 쓰는 유일한 주체**(§4.2).

    상태는 다섯 개뿐이다.

        DISCONNECTED → READY → SENDING → READY | FAULT → DISCONNECTED
                                                      ↘ STOPPED

    writer는 parsing, policy, correlation, LLM을 실행하지 않는다. 남은 deadline
    계산, priority dequeue, send, `SendResult` 발행, session fault 신호만 한다.
    """

    def __init__(
        self,
        queue: OutboundQueue,
        metrics: Metrics | None = None,
        audit: AuditLogger | None = None,
        clock=time.monotonic,
        on_fault: Callable[[str], None] | None = None,
        on_heartbeat_sent: Callable[[float], None] | None = None,
        fault_timeout: float = SOCKET_FAULT_TIMEOUT,
        safety_margin: float = BROKER_SAFETY_MARGIN,
    ) -> None:
        self._queue = queue
        self._metrics = metrics
        self._audit = audit
        self._clock = clock
        self._on_fault = on_fault
        self._on_heartbeat_sent = on_heartbeat_sent
        self._fault_timeout = fault_timeout
        self._safety_margin = safety_margin

        self._lock = threading.Lock()
        self._transport: SocketTransport | None = None
        self._session_id = 0
        self._state = WriterState.DISCONNECTED
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self.last_result: SendResult | None = None

    @property
    def state(self) -> WriterState:
        return self._state

    def attach(self, transport: SocketTransport, session_id: int) -> None:
        with self._lock:
            self._transport = transport
            self._session_id = session_id
            self._state = WriterState.READY

    def detach(self) -> None:
        with self._lock:
            transport = self._transport
            self._transport = None
            if self._state is not WriterState.STOPPED:
                self._state = WriterState.DISCONNECTED
        if transport is not None:
            transport.close()
        self._queue.purge_session()

    def start(self) -> None:
        if self._thread is not None:
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self.run, name="socket-writer", daemon=True)
        self._thread.start()

    def stop(self, timeout: float = 2.0) -> None:
        self._stop.set()
        thread = self._thread
        self._thread = None
        if thread is not None:
            thread.join(timeout=timeout)
        self._state = WriterState.STOPPED
        self.detach()
        self._queue.close()

    def run(self) -> None:
        while not self._stop.is_set():
            try:
                self.send_once()
            except Exception as exc:  # noqa: BLE001 - writer 사망은 fail-open 이다
                self._fault(f"writer-exception:{type(exc).__name__}")

    def send_once(self, timeout: float = QUEUE_POLL_SECONDS) -> SendResult | None:
        """item 하나를 처리한다. 큐가 비었으면 `None`."""
        item = self._queue.get(timeout)
        if item is None:
            return None

        with self._lock:
            transport = self._transport
            session_id = self._session_id

        if transport is None or item.session_id != session_id:
            # 이전 session의 잔여 item. 새 session으로 replay하지 않는다(§4.2).
            result = SendResult(item, SendOutcome.STALE, self._clock())
            self._queue.complete(item)
            self.last_result = result
            return result

        budget = self._remaining_budget(item)
        if budget <= 0.0:
            outcome = SendOutcome.EXPIRED
            self._count(M_VERDICT_EXPIRED if item.is_verdict else M_SEND_TIMEOUT)
            result = SendResult(item, outcome, self._clock(), "deadline-exhausted")
            self._queue.complete(item)
            self.last_result = result
            self._fault("deadline-exhausted")
            return result

        self._state = WriterState.SENDING
        started = self._clock()
        try:
            sent = transport.send(item.frame, budget)
        except TimeoutError:
            result = SendResult(item, SendOutcome.TIMEOUT, self._clock(), "send-timeout")
            self._count(M_SEND_TIMEOUT)
        except OSError as exc:
            result = SendResult(item, SendOutcome.ERROR, self._clock(), type(exc).__name__)
            self._count(M_SEND_ERROR)
        else:
            completed = self._clock()
            if sent != len(item.frame):
                result = SendResult(item, SendOutcome.PARTIAL, completed, f"sent={sent}")
                self._count(M_SEND_PARTIAL)
            else:
                result = SendResult(item, SendOutcome.SENT, completed)
                self._count(M_SEND_OK)
                self._observe(L_SEND, completed - started)
                if not item.is_verdict and self._on_heartbeat_sent is not None:
                    # §4.2 — **전체 frame의 성공 송신이 확인된 뒤에만** epoch를 갱신한다.
                    self._on_heartbeat_sent(completed)

        self._queue.complete(item)
        self.last_result = result

        if result.outcome.is_fault:
            self._fault(f"send-{result.outcome.value}")
        else:
            self._state = WriterState.READY
        return result

    def _remaining_budget(self, item: OutboundItem) -> float:
        """dequeue 직후와 send 직전에 다시 계산하는 item별 남은 예산(§4.2).

            broker_remaining  = broker_deadline - now
            verdict_send_wait = min(50ms, broker_remaining - 100ms)
            heartbeat_wait    = min(50ms, service_deadline - now)

        `broker_remaining <= 100ms`는 내부 200ms hard cutoff에 닿았다는 뜻이다.
        그 verdict는 로컬에서 만료 처리하고 재연결한다 — 이미 만료된 verdict를
        늦게 보내면 Broker는 어차피 그 패킷을 DROP하고, 그 사이 소켓이 막혀
        HEARTBEAT까지 밀린다.
        """
        now = self._clock()
        if item.is_verdict:
            broker_remaining = item.broker_deadline - now
            if broker_remaining <= self._safety_margin:
                return 0.0
            return min(self._fault_timeout, broker_remaining - self._safety_margin)
        remaining = item.absolute_send_deadline - now
        if remaining <= 0.0:
            return 0.0
        return min(self._fault_timeout, remaining)

    def _fault(self, reason: str) -> None:
        self._state = WriterState.FAULT
        self._count(M_SESSION_FAULT)
        if self._audit is not None:
            self._audit.log("session-fault", source="writer", reason=reason)
        self.detach()
        if self._on_fault is not None:
            self._on_fault(reason)

    def _count(self, name: str) -> None:
        if self._metrics is not None:
            self._metrics.incr(name)

    def _observe(self, name: str, seconds: float) -> None:
        if self._metrics is not None:
            self._metrics.observe(name, seconds)


class BrokerSession:
    """connect, 재연결, 수신 lifecycle.

    재연결 규칙(§4.2)을 그대로 구현한다.

    - bounded backoff로 **무한** 재시도한다. 포기는 fail-open이다.
    - 이전 session의 in-flight item을 비우고 그 `pkt_id`의 verdict를 새 session에
      보내지 않는다.
    - 연결 성공 시 새 `session_connected_at`을 monotonic으로 기록하고
      `last_successful_heartbeat = None`으로 초기화한다.
    - `SocketWriter`와 HEARTBEAT scheduler가 각각 하나만 존재하게 한다.
    """

    def __init__(
        self,
        config: RuntimeConfig,
        queue: OutboundQueue,
        writer: SocketWriter,
        heartbeat=None,
        metrics: Metrics | None = None,
        audit: AuditLogger | None = None,
        clock=time.monotonic,
        connect_fn: Callable[[str], SocketTransport] | None = None,
        stop_event: threading.Event | None = None,
    ) -> None:
        self._config = config
        self._queue = queue
        self._writer = writer
        self._heartbeat = heartbeat
        self._metrics = metrics
        self._audit = audit
        self._clock = clock
        self._connect_fn = connect_fn or self._dial_seqpacket
        self._stop = stop_event or threading.Event()
        self._fault = threading.Event()
        self.connect_attempts = 0
        self.sessions_opened = 0

    @staticmethod
    def _dial_seqpacket(path: str) -> SocketTransport:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        sock.connect(path)
        return SocketTransport(sock)

    def request_reconnect(self, reason: str = "") -> None:
        """writer나 producer가 session fault를 알린다."""
        self._fault.set()
        if self._audit is not None and reason:
            self._audit.log("reconnect-requested", reason=reason)

    def stop(self) -> None:
        self._stop.set()
        self._fault.set()

    @property
    def stopping(self) -> bool:
        return self._stop.is_set()

    def run(self, on_packet: Callable[[PacketEnvelope], bool]) -> None:
        while not self._stop.is_set():
            transport = self._connect_with_backoff()
            if transport is None:
                return

            self._fault.clear()
            session_id = self._queue.new_session()
            connected_at = self._clock()
            self._writer.attach(transport, session_id)
            if self._heartbeat is not None:
                self._heartbeat.reset(connected_at)
            self.sessions_opened += 1
            self._count(M_SESSION_CONNECTED)
            if self._audit is not None:
                self._audit.log("session-connected", session_id=session_id)

            try:
                self._recv_loop(transport, on_packet)
            finally:
                self._writer.detach()

    def _connect_with_backoff(self) -> SocketTransport | None:
        """연결될 때까지 재시도한다. `stop` 이외의 이유로 포기하지 않는다."""
        delay = BACKOFF_INITIAL
        while not self._stop.is_set():
            self.connect_attempts += 1
            self._count(M_SESSION_RECONNECT_ATTEMPT)
            try:
                return self._connect_fn(self._config.agent_socket)
            except OSError as exc:
                if self._audit is not None:
                    self._audit.log(
                        "connect-failed", error=type(exc).__name__, retry_in=round(delay, 3)
                    )
                # shutdown 이벤트 대기로 backoff를 구현해 종료 신호에 즉시 반응한다.
                if self._stop.wait(delay):
                    return None
                delay = min(BACKOFF_MAX, delay * BACKOFF_FACTOR)
        return None

    def _recv_loop(
        self, transport: SocketTransport, on_packet: Callable[[PacketEnvelope], bool]
    ) -> None:
        while not self._stop.is_set() and not self._fault.is_set():
            try:
                data = transport.recv(READ_POLL_SECONDS)
            except InterruptedError:
                continue
            except OSError as exc:
                if self._audit is not None:
                    self._audit.log("recv-failed", error=type(exc).__name__)
                return

            if data is None:
                continue
            if not data:
                if self._audit is not None:
                    self._audit.log("broker-eof")
                return

            received_at = self._clock()
            frame = decode_frame(data)

            if frame.outcome is FrameOutcome.UNKNOWN_TYPE:
                # 프레임을 버리고 루프를 계속한다. 알 수 없는 type은 desync가
                # 아니라 우리가 모르는 확장일 수 있다(§13).
                self._count(M_FRAME_UNKNOWN_TYPE)
                continue

            if frame.outcome.is_session_fault:
                self._count(M_FRAME_SHORT_HEADER)
                if self._audit is not None:
                    self._audit.log("frame-desync", outcome=frame.outcome.value, size=frame.frame_len)
                return

            packet = frame.packet
            if packet is None:
                continue

            if packet.status is FrameStatus.LENGTH_MISMATCH:
                self._count(M_FRAME_LENGTH_MISMATCH)
            elif packet.status is FrameStatus.TRAILING_BYTES:
                self._count(M_FRAME_TRAILING_BYTES)

            self._count(M_PACKET_RECEIVED)
            envelope = PacketEnvelope(
                pkt_id=packet.pkt_id,
                declared_len=packet.declared_len,
                raw_ip=packet.raw_ip,
                received_at_monotonic=received_at,
                frame_status=packet.status,
            )
            if not on_packet(envelope):
                # enqueue 실패는 조용히 verdict를 버리는 backpressure가 아니라
                # session fault다. 같은 session의 수신을 즉시 중단한다(§4.2).
                if self._audit is not None:
                    self._audit.log("producer-fault", pkt_id=envelope.pkt_id)
                return

    def _count(self, name: str) -> None:
        if self._metrics is not None:
            self._metrics.incr(name)


class VerdictSender:
    """verdict frame 생성, deadline metadata 부착, `put_nowait`, 계측(§7).

    **socket, send timeout, deadline 만료, priority dequeue, reconnect 판단을
    소유하지 않는다.** 그 권한을 전부 `SocketWriter` 한 곳에 모아야 "누가 언제
    소켓을 만졌는가"가 한 줄로 답해지고, deadline 집행이 두 군데로 갈라지지
    않는다.
    """

    def __init__(
        self,
        queue: OutboundQueue,
        metrics: Metrics | None = None,
        clock=time.monotonic,
        internal_budget: float = VERDICT_INTERNAL_BUDGET,
        broker_budget: float = BROKER_DEADLINE_BUDGET,
    ) -> None:
        self._queue = queue
        self._metrics = metrics
        self._clock = clock
        self._internal_budget = internal_budget
        self._broker_budget = broker_budget

    def send(self, pkt_id: int, verdict: int, received_at: float) -> bool:
        """enqueue 성공 여부. False면 호출자는 session fault로 처리해야 한다."""
        from .metrics import L_ENQUEUE, M_ENQUEUE_FULL, M_ENQUEUE_OK
        from .protocol import encode_verdict

        started = self._clock()
        item = OutboundItem(
            # 200ms 절대 send deadline은 Broker의 300ms 계약에서 100ms 안전 여유를
            # 뺀 값이다(§4.2).
            absolute_send_deadline=received_at + self._internal_budget,
            type_rank=TYPE_RANK_VERDICT,
            sequence=self._queue.next_sequence(),
            frame=encode_verdict(pkt_id, verdict),
            session_id=self._queue.current_session(),
            pkt_id=pkt_id,
            received_at=received_at,
            broker_deadline=received_at + self._broker_budget,
        )
        try:
            self._queue.put_nowait(item)
        except OutboundFull:
            if self._metrics is not None:
                self._metrics.incr(M_ENQUEUE_FULL)
            return False
        if self._metrics is not None:
            self._metrics.incr(M_ENQUEUE_OK)
            self._metrics.observe(L_ENQUEUE, self._clock() - started)
        return True

    def record_result(self, result: SendResult) -> None:
        """writer가 돌려준 `SendResult`만 계측한다. 판단하지 않는다."""
        if self._metrics is None or not result.item.is_verdict:
            return
        if result.outcome is SendOutcome.SENT:
            self._metrics.observe(
                "latency.verdict_end_to_end", result.completed_at - result.item.received_at
            )
