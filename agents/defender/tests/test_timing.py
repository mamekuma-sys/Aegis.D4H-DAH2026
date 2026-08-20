"""시간 예산과 부하 프로파일 측정.

설계 §5.2 확정 예산, §15.4 timing과 load.

**성능을 측정하지 않고 예상치만 적지 않는다**(§15.4). 이 파일은 실제 표본을
측정해 예산과 대조하고, 실패하면 rule이나 parser를 hot path 밖으로 옮기라는
신호로 쓴다. 문서의 숫자를 조용히 완화하지 않는다.

측정 환경이 공식 컨테이너와 다르면 그 차이를 기록해야 한다(§15.4). 여기서 나온
수치는 개발 머신 값이며, 공식 이미지(`python:3.12-slim`, cpu-shares 2048)에서
다시 측정해 Docker 담당자 인계 자료에 넣는다.
"""

import threading
import time
import unittest

from aegis_defender.metrics import (
    L_GATE,
    L_HOT_PATH,
    L_POLICY,
    L_SCORE,
    L_SIG,
    Metrics,
)
from aegis_defender.packet import parse_ip
from aegis_defender.policy import SOFT_CUTOFF_SECONDS, HotPolicy
from aegis_defender.protocol import decode_frame, encode_verdict
from aegis_defender.rules import compile_bundle
from aegis_defender.session import (
    BROKER_DEADLINE_BUDGET,
    BROKER_SAFETY_MARGIN,
    SOCKET_FAULT_TIMEOUT,
    VERDICT_INTERNAL_BUDGET,
    OutboundQueue,
    SendOutcome,
    SocketWriter,
    VerdictSender,
)
from aegis_defender.protocol import VERDICT_ACCEPT

from .fakes import (
    FakeClock,
    FakeTransport,
    fault_recorder,
    ipv4_tcp,
    minimal_bundle,
    packet_frame,
    rule_document,
)

# §5.2 확정 예산 (초)
BUDGET_HOT_PATH_P50 = 150e-6
BUDGET_HOT_PATH_P99 = 500e-6
BUDGET_GATE_P99 = 25e-6
BUDGET_SIG_P99 = 100e-6
BUDGET_SCORE_P99 = 25e-6
BUDGET_POLICY_P99 = 150e-6

LOAD_PROFILES = (1, 100, 550, 1100)


def build_policy(metrics):
    rules = [
        rule_document("r-traversal", pattern="\\.\\./", ports=[]),
        rule_document("r-sql", pattern="union\\s+select", category="sql-injection", ports=[]),
        rule_document("r-cmd", pattern=";\\s*ls\\s|\\$\\(", category="command-injection", ports=[]),
        rule_document("r-tpl", pattern="\\{\\{|<%=", category="template-injection", ports=[]),
        rule_document("r-file", pattern="/etc/passwd|/proc/self/", category="file-read", ports=[]),
        rule_document(
            "r-l1-ssrf",
            pattern=(
                "(?:GET|POST) [^\\r\\n ]{0,1000}(?:helper-box\\.?(?::|%3a)8080"
                "(?:/|%2f)secret|%68%65%6c%70%65%72%2d%62%6f%78%3a%38%30%38%30"
                "%2f%73%65%63%72%65%74) HTTP/1\\.[01]"
            ),
            category="ssrf",
            ports=[8082],
        ),
        rule_document(
            "r-l2-admin",
            kind="http_json_cookie_claim",
            category="broken-auth",
            ports=[8083],
            http_method="GET",
            http_path="/admin",
            cookie_name="session",
            claim_key="role",
            claim_values=["admin"],
        ),
    ]
    compiled, _ = compile_bundle(minimal_bundle(rules=rules, baseline_profiles=["6/80"]))
    return HotPolicy(policy=compiled, metrics=metrics)


def sample_frames(count: int) -> list[bytes]:
    """정상 요청 위주에 공격 형태를 섞은 표본."""
    frames = []
    for index in range(count):
        if index % 40 == 0:
            payload = (
                b"GET /fetch?url=http://helper-box:8080/secret HTTP/1.1\r\n"
                b"Host: team1.lig.internal:8082\r\n\r\n"
            )
            dst_port = 8082
        elif index % 40 == 1:
            payload = (
                b"GET /admin HTTP/1.1\r\nHost: team1.lig.internal:8083\r\n"
                b"Cookie: session=eyJ1c2VyIjoiZ3Vlc3QiLCJyb2xlIjoiYWRtaW4ifQ==\r\n\r\n"
            )
            dst_port = 8083
        else:
            payload = (
                b"GET /index.html?page=" + str(index).encode() +
                b" HTTP/1.1\r\nHost: team1.lig.internal\r\nUser-Agent: sla-check\r\n"
                b"Accept: text/html\r\n\r\n" + b"B" * 200
            )
            dst_port = 80
        raw = ipv4_tcp(
            payload,
            src_port=1024 + (index % 4096),
            dst_port=dst_port,
        )
        frames.append(packet_frame(index, raw))
    return frames


def percentile(ordered: list[float], fraction: float) -> float:
    if not ordered:
        return 0.0
    rank = max(1, min(len(ordered), int(round(fraction * len(ordered) + 0.5))))
    return ordered[rank - 1]


class TestMonotonicClock(unittest.TestCase):
    """§5.2 — 모든 시간은 벽시계가 아니라 monotonic clock으로 잰다."""

    def test_defaults_use_monotonic(self):
        policy = HotPolicy()
        self.assertIs(policy._clock, time.monotonic)
        self.assertIs(VerdictSender(OutboundQueue())._clock, time.monotonic)
        self.assertIs(SocketWriter(OutboundQueue())._clock, time.monotonic)

    def test_budget_constants_match_the_design(self):
        self.assertEqual(SOFT_CUTOFF_SECONDS, 0.005)
        self.assertEqual(VERDICT_INTERNAL_BUDGET, 0.200)
        self.assertEqual(BROKER_DEADLINE_BUDGET, 0.300)
        self.assertEqual(BROKER_SAFETY_MARGIN, 0.100)
        self.assertEqual(SOCKET_FAULT_TIMEOUT, 0.050)

    def test_measured_budgets_are_pinned_too(self):
        """§5.2 예산은 이 파일의 지역 상수지만 완화가 조용히 일어나면 안 된다.

        `AGENTS.md`의 "defender의 packet별 동기 verdict 경로에 원격 LLM 호출을 두지
        않는다"를 기계적으로 지키는 것은 결국 아래 p99 예산이다. 동기 네트워크
        호출은 밀리초 단위라 반드시 이 한계를 넘긴다. Break Copilot의 평가
        (`scripts/break_copilot/evaluate.py`)도 hot path를 직접 보지 않고
        `{side}_unit_tests`로 이 검사에 기댄다.

        따라서 예산을 늘리는 변경은 그 자체로 이 테스트를 깨야 하고, 방어자
        owner와 팀장이 의도적으로 값을 고쳐야만 통과한다.
        """
        self.assertEqual(BUDGET_HOT_PATH_P50, 150e-6)
        self.assertEqual(BUDGET_HOT_PATH_P99, 500e-6)
        self.assertEqual(BUDGET_GATE_P99, 25e-6)
        self.assertEqual(BUDGET_SIG_P99, 100e-6)
        self.assertEqual(BUDGET_SCORE_P99, 25e-6)
        self.assertEqual(BUDGET_POLICY_P99, 150e-6)


class TestHotPathBudget(unittest.TestCase):
    """§15.4 — 1, 100, 550, 1100 packet/s 부하 프로파일 측정."""

    def _measure(self, frames, metrics):
        policy = build_policy(metrics)
        queue = OutboundQueue()
        queue.new_session()
        sender = VerdictSender(queue, metrics=metrics)
        latencies = []
        over_deadline = 0

        for frame in frames:
            received_at = time.monotonic()
            decoded = decode_frame(frame)
            parsed = parse_ip(decoded.packet.raw_ip)
            decision = policy.decide(
                decoded.packet.pkt_id, parsed, received_at, decoded.packet.status
            )
            encode_verdict(decision.pkt_id, decision.verdict)
            if queue.in_flight() >= 200:
                while queue.get(0.0) is not None:
                    pass
                queue.new_session()
            sender.send(decision.pkt_id, decision.verdict, received_at)
            elapsed = time.monotonic() - received_at
            latencies.append(elapsed)
            metrics.observe(L_HOT_PATH, elapsed)
            if elapsed > BROKER_DEADLINE_BUDGET:
                over_deadline += 1

        latencies.sort()
        return latencies, over_deadline

    def test_load_profiles_stay_within_budget(self):
        report = {}
        for rate in LOAD_PROFILES:
            with self.subTest(packets_per_second=rate):
                metrics = Metrics()
                # 한 프로파일당 1초치 부하를 처리한다. 도착 간격을 실제로 기다리면
                # 테스트가 느려지기만 하므로, 측정 대상인 처리 시간만 연속으로 잰다.
                frames = sample_frames(max(rate, 200))
                latencies, over_deadline = self._measure(frames, metrics)
                p50 = percentile(latencies, 0.50)
                p99 = percentile(latencies, 0.99)
                report[rate] = (p50 * 1e6, p99 * 1e6, max(latencies) * 1e6)

                self.assertEqual(over_deadline, 0, "300ms 를 넘긴 verdict 가 있다")
                self.assertLess(p50, BUDGET_HOT_PATH_P50, f"{rate}pkt/s p50 초과")
                self.assertLess(p99, BUDGET_HOT_PATH_P99, f"{rate}pkt/s p99 초과")

        # 실측치를 남긴다. 예산 대비 여유가 얼마나 되는지가 회귀 판단 근거다.
        print("\n[hot path us] " + " ".join(
            f"{rate}pkt/s p50={values[0]:.1f} p99={values[1]:.1f} max={values[2]:.1f}"
            for rate, values in report.items()
        ))

    def test_component_decomposition_matches_the_policy_budget(self):
        """§5.2 — Gate 25 + Sig 100 + Score 25 = policy 150μs."""
        metrics = Metrics()
        self._measure(sample_frames(2000), metrics)

        gate = metrics.latency_summary(L_GATE)["p99_us"]
        sig = metrics.latency_summary(L_SIG)["p99_us"]
        score = metrics.latency_summary(L_SCORE)["p99_us"]
        policy = metrics.latency_summary(L_POLICY)["p99_us"]

        print(f"\n[policy us] gate p99={gate:.1f} sig p99={sig:.1f} "
              f"score p99={score:.1f} policy p99={policy:.1f}")

        self.assertLess(gate, BUDGET_GATE_P99 * 1e6)
        self.assertLess(sig, BUDGET_SIG_P99 * 1e6)
        self.assertLess(score, BUDGET_SCORE_P99 * 1e6)
        self.assertLess(policy, BUDGET_POLICY_P99 * 1e6)

    def test_latency_does_not_grow_under_sustained_load(self):
        """§15.4 — 1100 pkt/s에서 처리 지연이 누적되지 않는다.

        `_measure`는 분포를 보려고 정렬한 값을 돌려주므로 여기서는 시간순 표본이
        필요하다. 처음 10%와 마지막 10%의 중앙값을 비교해, 상관 상태나 metric
        reservoir가 자라면서 판정이 느려지지 않는지 본다.
        """
        policy = build_policy(Metrics())
        ordered = []
        for frame in sample_frames(6000):
            received_at = time.monotonic()
            decoded = decode_frame(frame)
            parsed = parse_ip(decoded.packet.raw_ip)
            policy.decide(decoded.packet.pkt_id, parsed, received_at, decoded.packet.status)
            ordered.append(time.monotonic() - received_at)

        head_median = percentile(sorted(ordered[:600]), 0.5)
        tail_median = percentile(sorted(ordered[-600:]), 0.5)
        self.assertLess(tail_median, head_median * 3 + 20e-6)

    def test_hot_path_holds_while_a_worker_thread_stalls(self):
        """§15.4 — 큐가 가득 차거나 LLM이 멈춰도 latency 기준을 유지한다.

        30초 정지를 그대로 재현하면 테스트가 30초 걸린다. 검증 대상은 "얼마나
        오래 멈췄는가"가 아니라 "멈춘 스레드가 hot path와 자원을 공유하지
        않는가"이므로, 짧게 멈춘 스레드로 같은 성질을 확인한다.
        """
        release = threading.Event()

        def stalled_worker():
            release.wait(2.0)

        thread = threading.Thread(target=stalled_worker, daemon=True)
        thread.start()

        metrics = Metrics()
        latencies, over_deadline = self._measure(sample_frames(2000), metrics)
        release.set()
        thread.join(timeout=2.0)

        self.assertEqual(over_deadline, 0)
        self.assertLess(percentile(latencies, 0.99), BUDGET_HOT_PATH_P99)


class TestCutoffIndependence(unittest.TestCase):
    """§5.2 — 5ms soft cutoff, 200ms hard cutoff, 300ms deadline, 50ms fault timeout."""

    def setUp(self):
        self.clock = FakeClock()
        self.queue = OutboundQueue()
        self.faults = []
        self.writer = SocketWriter(
            self.queue, clock=self.clock, on_fault=fault_recorder(self.faults)
        )
        self.transport = FakeTransport()
        self.writer.attach(self.transport, self.queue.new_session())
        self.sender = VerdictSender(self.queue, clock=self.clock)

    def test_soft_cutoff_is_measured_from_packet_receipt_not_queue_entry(self):
        policy = HotPolicy(clock=self.clock)
        received_at = self.clock.now
        self.clock.advance(0.004)
        parsed = parse_ip(ipv4_tcp(b"GET / HTTP/1.1\r\n\r\n"))
        self.assertNotEqual(policy.decide(1, parsed, received_at).stage, "cutoff")
        self.clock.advance(0.002)  # 누적 6ms
        self.assertEqual(policy.decide(2, parsed, received_at).stage, "cutoff")

    def test_internal_hard_cutoff_at_200ms(self):
        received_at = self.clock.now
        self.sender.send(1, VERDICT_ACCEPT, received_at)
        self.clock.advance(0.199)
        # 아직 예산이 남아 있다.
        self.assertIs(self.writer.send_once(0.0).outcome, SendOutcome.SENT)

        self.writer.attach(FakeTransport(), self.queue.new_session())
        received_at = self.clock.now
        self.sender.send(2, VERDICT_ACCEPT, received_at)
        self.clock.advance(0.201)
        self.assertIs(self.writer.send_once(0.0).outcome, SendOutcome.EXPIRED)

    def test_fault_timeout_is_not_a_normal_path_budget(self):
        # 50ms 는 blocked send 를 유한 시간에 탐지하기 위한 상한이며 정상 p99
        # 목표가 아니다. 정상 경로에서는 그보다 훨씬 빨리 끝난다.
        self.sender.send(1, VERDICT_ACCEPT, self.clock.now)
        result = self.writer.send_once(0.0)
        self.assertIs(result.outcome, SendOutcome.SENT)
        self.assertLessEqual(self.transport.timeouts[-1], SOCKET_FAULT_TIMEOUT)

    def test_expired_verdict_and_fault_timeout_are_separate_metrics(self):
        from aegis_defender.metrics import Metrics as M

        metrics = M()
        writer = SocketWriter(
            self.queue, metrics=metrics, clock=self.clock, on_fault=fault_recorder(self.faults)
        )
        writer.attach(self.transport, self.queue.current_session())

        self.sender.send(1, VERDICT_ACCEPT, self.clock.now)
        self.clock.advance(0.25)
        writer.send_once(0.0)
        self.assertEqual(metrics.counter("outbound.verdict_expired"), 1)
        self.assertEqual(metrics.counter("outbound.send_timeout"), 0)

        writer.attach(self.transport, self.queue.new_session())
        self.transport.blocked = True
        self.sender.send(2, VERDICT_ACCEPT, self.clock.now)
        writer.send_once(0.0)
        self.assertEqual(metrics.counter("outbound.send_timeout"), 1)


if __name__ == "__main__":
    unittest.main()
