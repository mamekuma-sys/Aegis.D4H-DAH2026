"""entrypoint와 lifecycle (`DefenderRuntime`).

설계 §4 런타임 흐름, §7 구성요소 경계, §19 구현 우선순위.

    startup validation
      → AGENT_SOCKET connect (실패 시 bounded backoff 재시도)
      → 독립 HEARTBEAT 스케줄러와 단일 SocketWriter 기동
      → PACKET frame 수신과 header 검증
      → bounded raw IP parser
      → 사전 승인된 결정론적 policy (Gate → Sig → Score)
      → ACCEPT/DROP VERDICT를 deadline priority queue에 enqueue
      → SocketWriter가 VERDICT/HEARTBEAT를 단독 송신
      → bounded 비동기 event enqueue
      → Corr / Advisory / 로그 분석
      → 연결 끊김 시 재연결하고 위 흐름 재개

수신·판정 producer(메인) 외 helper는 `SocketWriter`, HEARTBEAT scheduler,
correlation worker, audit logger, worker watchdog, 그리고 선택적 advisory다. §5.3의 승인된 실행
모델대로 producer는 하나이고 inbound queue는 없다. producer worker를 늘리거나
inbound queue를 추가하는 것은 단순 최적화가 아니라 packet ordering·memory
상한·deadline backpressure를 바꾸는 변경이므로 별도 설계 승인이 필요하다.
"""

from __future__ import annotations

import os
import signal
import sys
import threading
import time

from . import __version__
from .advisory import AdvisoryWorker
from .anomaly import AnomalyMonitor
from .config import ConfigError, RuntimeConfig, load_config
from .events import BoundedEventQueue, EventAdapter
from .heartbeat import HeartbeatScheduler
from .logging import AuditLogger
from .metrics import (
    L_HOT_PATH,
    L_PARSE,
    L_VERDICT_SEND_E2E,
    M_EVENT_DROPPED_NEWEST,
    M_EVENT_ENQUEUED,
    M_PARSER_FAILURE,
    M_PARSER_UNSUPPORTED,
    M_VERDICT_ACCEPT,
    M_VERDICT_DROP,
    Metrics,
)
from .packet import ParseStatus, parse_ip
from .policy import HotPolicy, R_CONFLICT, R_SHADOW
from .protocol import FrameStatus, VERDICT_DROP
from .rules import load_policy
from .session import (
    BrokerSession,
    OutboundQueue,
    PacketEnvelope,
    SocketWriter,
    VerdictSender,
)
from .state import CorrelationSnapshotRef, CorrelationWorker
from .watchdog import WorkerProbe, WorkerWatchdog

SHUTDOWN_JOIN_TIMEOUT = 2.0
ANOMALY_EVALUATION_INTERVAL = 10.0
HEALTH_SUMMARY_INTERVAL_SECONDS = 60.0
MAX_OBSERVED_SERVICES = 64


class DefenderRuntime:
    """모든 구성요소를 배선하고 lifecycle을 소유한다."""

    def __init__(
        self,
        config: RuntimeConfig,
        clock=time.monotonic,
        audit: AuditLogger | None = None,
        metrics: Metrics | None = None,
        connect_fn=None,
    ) -> None:
        self.config = config
        self.clock = clock
        self.metrics = metrics or Metrics()
        self.audit = audit or AuditLogger()
        self.stop_event = threading.Event()
        self._last_health_summary = self.clock()

        compiled, report = load_policy(config.policy_dir)
        self.policy_report = report
        self.compiled_policy = compiled

        self.snapshot_ref = CorrelationSnapshotRef()
        self.hot_policy = HotPolicy(
            policy=compiled,
            snapshot_ref=self.snapshot_ref,
            metrics=self.metrics,
            clock=clock,
        )
        self.event_queue = BoundedEventQueue()
        self.event_adapter = EventAdapter()
        self.correlation = CorrelationWorker(
            self.event_queue, self.snapshot_ref, metrics=self.metrics, clock=clock
        )
        self.anomaly = AnomalyMonitor(
            compiled.alert_profiles, metrics=self.metrics, audit=self.audit, clock=clock
        )
        self.advisory = AdvisoryWorker(
            config, self.snapshot_ref, metrics=self.metrics, audit=self.audit,
            clock=clock, stop_event=self.stop_event,
        )

        self.outbound = OutboundQueue()
        self.heartbeat = HeartbeatScheduler(
            self.outbound, metrics=self.metrics, audit=self.audit,
            clock=clock, stop_event=self.stop_event,
        )
        self.writer = SocketWriter(
            self.outbound,
            metrics=self.metrics,
            audit=self.audit,
            clock=clock,
            on_fault=self._on_writer_fault,
            on_heartbeat_sent=self.heartbeat.on_sent,
        )
        self.verdict_sender = VerdictSender(self.outbound, metrics=self.metrics, clock=clock)
        self.session = BrokerSession(
            config=config,
            queue=self.outbound,
            writer=self.writer,
            heartbeat=self.heartbeat,
            metrics=self.metrics,
            audit=self.audit,
            clock=clock,
            connect_fn=connect_fn,
            stop_event=self.stop_event,
        )
        self.watchdog = WorkerWatchdog(
            probes=(
                WorkerProbe(
                    "socket-writer", self.writer.is_alive, self.writer.start, critical=True
                ),
                WorkerProbe(
                    "heartbeat", self.heartbeat.is_alive, self.heartbeat.start, critical=True
                ),
                WorkerProbe("correlation", self.correlation.is_alive, self.correlation.start),
                WorkerProbe("audit-log", self.audit.is_alive, self.audit.start),
                WorkerProbe(
                    "advisory",
                    self.advisory.is_alive,
                    self.advisory.start,
                    expected=lambda: self.advisory.enabled,
                ),
            ),
            metrics=self.metrics,
            audit=self.audit,
            runtime_stop=self.stop_event,
            on_critical_restart=self._on_critical_worker_restart,
            on_tick=self._emit_health_summary_if_due,
        )
        self._last_anomaly_check = 0.0
        # producer 한 곳에서만 갱신하는 Round 한정 관측 목록. 본선 L4의 포트/프로토콜을
        # 사전 추측해 차단하지 않고, 실제로 받은 raw IP에서 처음 본 service 좌표만
        # 비동기 감사 로그로 남긴다. verdict나 policy에는 어떤 영향도 주지 않는다.
        self._observed_services: set[tuple[int, int, int | None]] = set()
        self._service_inventory_full_logged = False

    # ── hot path ────────────────────────────────────────────────────────────

    def on_packet(self, envelope: PacketEnvelope) -> bool:
        """PACKET 하나를 판정하고 VERDICT를 enqueue한다.

        반환값은 **session을 계속 쓸 수 있는가**이지 verdict가 아니다. `False`는
        enqueue 실패, 즉 outbound in-flight 상한 도달을 뜻하며 §4.2에 따라
        backpressure가 아니라 session fault다.

        비동기 event enqueue와 anomaly 집계는 VERDICT enqueue **뒤에** 온다.
        순서를 바꾸면 그 두 작업의 지연이 300ms 예산에 들어간다.
        """
        received_at = envelope.received_at_monotonic

        parse_started = self.clock()
        parsed = parse_ip(envelope.raw_ip)
        self.metrics.observe(L_PARSE, self.clock() - parse_started)

        decision = self.hot_policy.decide(
            envelope.pkt_id, parsed, received_at, envelope.frame_status
        )

        if not self.verdict_sender.send(envelope.pkt_id, decision.verdict, received_at):
            self.session.request_reconnect("verdict-enqueue-full")
            return False

        # producer 측 hot path 경과. writer의 물리 송신은 별도 지표다(§5.2).
        self.metrics.observe(L_HOT_PATH, self.clock() - received_at)
        self.metrics.incr(M_VERDICT_DROP if decision.is_drop else M_VERDICT_ACCEPT)

        parser_failed = self._record_parse_status(parsed.status, envelope.frame_status)
        self._record_async(parsed, decision, received_at)
        self._record_anomaly(decision, parser_failed)
        return True

    def _record_parse_status(self, status: ParseStatus, frame_status: FrameStatus) -> bool:
        if frame_status is not FrameStatus.OK:
            return True
        if status is ParseStatus.OK:
            return False
        if status is ParseStatus.EXCEPTION:
            self.metrics.incr(M_PARSER_FAILURE)
        else:
            self.metrics.incr(M_PARSER_UNSUPPORTED)
        return True

    def _record_async(self, parsed, decision, received_at: float) -> None:
        event = self.event_adapter.to_event(
            parsed,
            received_at,
            verdict=decision.verdict,
            sig_category=decision.match.category if decision.match else "",
            rule_id=decision.rule_id,
        )
        if event is None:
            return
        if self.event_queue.put_nowait(event):
            self.metrics.incr(M_EVENT_ENQUEUED)
        else:
            # queue full 은 DROP 사유가 아니다(§6.2). 지표만 남기고 진행한다.
            self.metrics.incr(M_EVENT_DROPPED_NEWEST)
        self._record_service_observation(parsed.profile)

    def _record_service_observation(self, profile) -> None:
        """처음 본 protocol/port/subnet 후보를 bounded observation으로만 기록한다."""
        if profile is None:
            return
        key = (profile.protocol, profile.dst_port, profile.dst_subnet_candidate)
        if key in self._observed_services:
            return
        if len(self._observed_services) >= MAX_OBSERVED_SERVICES:
            if not self._service_inventory_full_logged:
                self._service_inventory_full_logged = True
                self.audit.log("service-inventory-full", capacity=MAX_OBSERVED_SERVICES)
            return
        self._observed_services.add(key)
        self.audit.log(
            "service-observed",
            protocol=profile.protocol,
            dst_port=profile.dst_port,
            dst_subnet_candidate=profile.dst_subnet_candidate,
            parser_version=profile.parser_version,
            authority="observation-only",
        )

    def _record_anomaly(self, decision, parser_failed: bool) -> None:
        rule = self.compiled_policy.rules_by_id.get(decision.rule_id)
        cohort_conflict = (
            decision.reason_code == R_CONFLICT
            and rule is not None
            and rule.promoted_in_bundle == self.compiled_policy.bundle_id
        )
        self.anomaly.record(
            dropped=decision.verdict == VERDICT_DROP,
            parser_failed=parser_failed,
            baseline_match=decision.baseline_match,
            rule_id=decision.rule_id,
            cohort_conflict=cohort_conflict,
            shadow_hit=decision.reason_code == R_SHADOW,
        )

        now = self.clock()
        if now - self._last_anomaly_check >= ANOMALY_EVALUATION_INTERVAL:
            self._last_anomaly_check = now
            # 반환된 alert는 로그로만 나간다. policy 를 바꾸는 경로가 없다(§10.3).
            self.anomaly.evaluate(now)

    # ── lifecycle ───────────────────────────────────────────────────────────

    def _on_writer_fault(self, reason: str, session_id: int | None = None) -> None:
        """writer가 알린 session fault를 수신 쪽에 전달한다.

        `session_id`를 그대로 넘겨 `BrokerSession`이 generation을 확인하게 한다.
        이전 session의 뒤늦은 실패가 이미 정상 연결된 session의 수신 루프를
        끊으면 그 구간이 그대로 fail-open이 된다.
        """
        self.session.request_reconnect(reason, session_id)

    def _on_critical_worker_restart(self, worker: str) -> None:
        # writer/heartbeat가 죽었던 session의 queue와 epoch를 그대로 재사용하지
        # 않는다. 새 generation으로 넘겨 stale verdict replay를 구조적으로 막는다.
        self.session.request_reconnect(f"watchdog-restarted:{worker}")

    def _emit_health_summary_if_due(self) -> None:
        """저빈도 운영 요약을 watchdog 스레드에서 기록한다.

        packet producer나 SocketWriter에서 snapshot 정렬·JSON 직렬화를 하지 않는다.
        따라서 로그 I/O와 percentile 계산은 300ms verdict hot path 밖에 있다.
        """
        now = self.clock()
        if now - self._last_health_summary < HEALTH_SUMMARY_INTERVAL_SECONDS:
            return
        self._last_health_summary = now
        self.audit.log(
            "health-summary",
            policy_source=self.policy_report.source,
            bundle_id=self.policy_report.bundle_id,
            drop_capable_rules=self.policy_report.drop_capable_rules,
            sessions=self.session.sessions_opened,
            heartbeats=self.heartbeat.sent_count,
            audit_dropped=self.audit.dropped,
            counters=self.metrics.counters(),
            rule_activity=self.anomaly.rule_summary(),
            hot_path=self.metrics.latency_summary(L_HOT_PATH),
            verdict_send_e2e=self.metrics.latency_summary(L_VERDICT_SEND_E2E),
        )

    def start_workers(self) -> None:
        self.audit.start()
        self.writer.start()
        self.heartbeat.start()
        self.correlation.start()
        self.advisory.start()
        self.watchdog.start()

    def run(self) -> int:
        self.start_workers()
        self.audit.log(
            "startup",
            agent_version=__version__,
            agent_socket=self.config.agent_socket,
            policy_source=self.policy_report.source,
            bundle_id=self.policy_report.bundle_id,
            rules=self.policy_report.rule_count,
            drop_capable_rules=self.policy_report.drop_capable_rules,
            policy_errors=list(self.policy_report.errors),
            demotions=list(self.policy_report.demotions),
            advisory_enabled=self.config.advisory_enabled,
        )
        try:
            self.session.run(self.on_packet)
        finally:
            self.shutdown()
        return 0

    def shutdown(self) -> None:
        """SIGTERM에서 2초 안에 정리 종료한다(§15.2)."""
        self.stop_event.set()
        self.session.stop()
        self.watchdog.stop(SHUTDOWN_JOIN_TIMEOUT)
        self.heartbeat.stop(SHUTDOWN_JOIN_TIMEOUT)
        self.writer.stop(SHUTDOWN_JOIN_TIMEOUT)
        self.correlation.stop(SHUTDOWN_JOIN_TIMEOUT)
        self.advisory.stop(SHUTDOWN_JOIN_TIMEOUT)
        self.audit.log(
            "shutdown",
            sessions=self.session.sessions_opened,
            heartbeats=self.heartbeat.sent_count,
            advisory=self.advisory.usage_evidence(),
            counters=self.metrics.counters(),
            rule_activity=self.anomaly.rule_summary(),
            hot_path=self.metrics.latency_summary(L_HOT_PATH),
            verdict_send_e2e=self.metrics.latency_summary(L_VERDICT_SEND_E2E),
        )
        self.audit.stop(SHUTDOWN_JOIN_TIMEOUT)


def main(env=None) -> int:
    try:
        config = load_config(os.environ if env is None else env)
    except ConfigError as exc:
        audit = AuditLogger()
        audit.log("config-error", error=str(exc))
        return 1

    runtime = DefenderRuntime(config)

    def _handle_signal(signum, _frame):
        runtime.audit.log("signal", signum=signum)
        runtime.stop_event.set()
        runtime.session.stop()

    for received in (signal.SIGTERM, signal.SIGINT):
        try:
            signal.signal(received, _handle_signal)
        except (ValueError, OSError):
            # 메인 스레드가 아니면 등록할 수 없다. 테스트 경로에서 정상이다.
            pass

    return runtime.run()


if __name__ == "__main__":
    sys.exit(main())
