"""Broker E2E mutation 테스트.

`2026-08-20-finals-candidate-verdict.md` §11의 P1 `PCAP-001`–`104`은 known capture
replay가 100% 차단이지만 **TCP·부하 일반화가 미검증**이라고 남겼다. 해제 조건이
"encoding·TCP split·retransmit·worker death·reconnect mutation 통과"이고 수단이
"Broker E2E mutation tests"다. 이 파일이 그 다섯 가지를 런타임 전 구간에서 돌린다.

replay 테스트(`test_pcap_replay.py`)는 policy만 통과시키고, stitcher 테스트
(`test_stream.py`)는 `HotPolicy`만 본다. 여기서는 frame 수신 → parser → stitcher →
policy → verdict queue → writer 까지 실제 세션 위에서 확인한다. 새 ACTIVE rule을
추가하지 않으며, 기존 rule이 변형된 전달 방식에서도 유지되는지만 본다.

불변식은 두 가지다.

1. 알려진 exploit은 전달 방식이 변해도 DROP된다(미탐 금지).
2. 정상 요청은 같은 변형에서도 ACCEPT되고, **모든 패킷은 verdict를 받는다**
   (가용성·deadline). verdict 누락은 Broker 300ms 만료 → fail-open이다.
"""

from __future__ import annotations

import base64
import io
import json
import os
import threading
import time
import unittest

from aegis_defender.config import RuntimeConfig
from aegis_defender.logging import AuditLogger
from aegis_defender.main import DefenderRuntime
from aegis_defender.protocol import (
    HEARTBEAT_FRAME,
    MSG_VERDICT,
    VERDICT_ACCEPT,
    VERDICT_DROP,
    decode_verdict,
)

from .fakes import FakeTransport, http_request, ipv4_tcp, packet_frame

_POLICY_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "policy"))
_EXPLOIT_PORT = 8082
_EXPLOIT_RULE = "http-l2-forged-admin-session-001"
_SETTLE = 0.5


def forged_admin_request(role: str = "admin", path: str = "/admin?") -> bytes:
    """`http-l2-forged-admin-session-001`이 잡는 위조 admin session 요청."""
    claim = base64.urlsafe_b64encode(
        json.dumps({"user": "guest", "role": role}, separators=(",", ":")).encode()
    ).decode("ascii")
    return (
        f"GET {path} HTTP/1.1\r\nHost: team1.lig.internal:{_EXPLOIT_PORT}\r\n"
        f"Cookie: session={claim}\r\n\r\n"
    ).encode("ascii")


def segment(payload: bytes, pkt_id: int, sequence: int) -> bytes:
    return packet_frame(
        pkt_id, ipv4_tcp(payload, dst_port=_EXPLOIT_PORT, sequence=sequence)
    )


class MutationHarness:
    """세션을 여러 번 열 수 있는 런타임 하네스.

    `test_round_lifecycle.RuntimeHarness`는 두 번째 connect에서 세션을 닫는다.
    reconnect mutation은 두 세션에 걸친 전달을 봐야 하므로 세션 목록을 받는다.
    """

    def __init__(self, sessions: list[list[bytes]], policy_dir: str = _POLICY_DIR) -> None:
        self.transports: list[FakeTransport] = []
        self._sessions = list(sessions)
        self._index = 0
        self.stream = io.StringIO()
        self.runtime = DefenderRuntime(
            RuntimeConfig(
                agent_socket="/run/agent.sock",
                llm_base_url="http://litellm.lig.internal:4000",
                llm_api_key="",  # advisory 비활성 — 테스트가 외부로 나가지 않는다
                policy_dir=policy_dir,
            ),
            audit=AuditLogger(stream=self.stream),
            connect_fn=self._connect,
        )
        self._thread: threading.Thread | None = None

    def _connect(self, path: str) -> FakeTransport:
        transport = FakeTransport()
        if self._index < len(self._sessions):
            for frame in self._sessions[self._index]:
                transport.feed(frame)
            self._index += 1
        else:
            # 준비된 세션을 모두 소진하면 루프를 세운다.
            self.runtime.session.stop()
        self.transports.append(transport)
        return transport

    def start(self) -> "MutationHarness":
        self._thread = threading.Thread(target=self.runtime.run, daemon=True)
        self._thread.start()
        return self

    def drop_session(self) -> None:
        """현재 세션을 끊어 재연결을 유도한다."""
        self.runtime.session.request_reconnect("mutation-test")

    def stop(self) -> None:
        self.runtime.session.stop()
        self.runtime.stop_event.set()
        if self._thread is not None:
            self._thread.join(timeout=5.0)

    def verdicts(self) -> list[tuple[int, int]]:
        out: list[tuple[int, int]] = []
        for transport in self.transports:
            for frame in transport.sent:
                if frame and frame[0] == MSG_VERDICT:
                    out.append(decode_verdict(frame))
        return out

    def verdict_map(self) -> dict[int, int]:
        return dict(self.verdicts())

    def audit_lines(self) -> list[dict]:
        lines = []
        for raw in self.stream.getvalue().splitlines():
            try:
                lines.append(json.loads(raw))
            except ValueError:
                continue
        return lines


def run_once(sessions: list[list[bytes]], settle: float = _SETTLE) -> MutationHarness:
    harness = MutationHarness(sessions).start()
    time.sleep(settle)
    harness.stop()
    return harness


class TestEncodingMutation(unittest.TestCase):
    """같은 exploit을 다른 표기로 보내도 잡아야 한다."""

    def test_equivalent_encodings_stay_blocked(self):
        """같은 자원을 가리키는 표기는 전부 잡아야 한다."""
        variants = {
            1: forged_admin_request(path="/admin?"),
            2: forged_admin_request(path="/%61dmin?"),      # RFC 3986 percent-decoding
            3: forged_admin_request(path="/admin?x=1&y=2"),
            4: forged_admin_request(path="/admin?y=2&x=1"),  # query 순서
        }
        frames = [
            segment(payload, pkt_id, 1000 + pkt_id * 4096)
            for pkt_id, payload in variants.items()
        ]
        harness = run_once([frames])
        verdicts = harness.verdict_map()

        self.assertEqual(
            sorted(verdicts), sorted(variants), "모든 패킷이 verdict를 받아야 한다"
        )
        for pkt_id in variants:
            self.assertEqual(
                verdicts[pkt_id], VERDICT_DROP, f"변형 {pkt_id} 이 통과했다"
            )

    def test_case_varied_path_is_not_broadened_into_a_false_positive(self):
        """`/ADMIN`은 admin 자원이 아니다 — 잡으면 오탐이다.

        HTTP path는 대소문자를 구분한다(RFC 9110 §4.2.3, RFC 3986 §6.2.2.1). 공식
        스켈레톤의 L2도 Flask `@app.route("/admin")`이라 `/ADMIN`은 admin 핸들러에
        닿지 않는다. 즉 이 경로를 막아도 얻는 것이 없고 정상 트래픽만 잃는다.

        이 테스트는 rule을 대소문자 무시로 넓히는 변경을 막는 negative 가드다
        (GAP-005: 신규·확장 rule은 SHADOW와 negative corpus 통과 후 승격).

        다만 본선 L2가 실제로 대소문자를 구분하는지는 스켈레톤으로 확정할 수
        없다(운영진이 "데모 문제는 본선과 무관"이라고 명시). 당일 첫 capture로
        확인이 필요하며, 대소문자 무시로 밝혀지면 이 가드와 rule을 함께 바꿔야
        한다 — 방어자 owner + 팀장 승인 사항이다.
        """
        harness = run_once([[segment(forged_admin_request(path="/ADMIN?"), 1, 1500)]])
        self.assertEqual(
            harness.verdict_map().get(1), VERDICT_ACCEPT,
            "대소문자 변형까지 막으면 근거 없는 확장이다",
        )

    def test_normal_traffic_with_the_same_shapes_is_not_dropped(self):
        """encoding 변형을 넓게 잡다가 정상 요청까지 죽이면 오탐이다."""
        benign = {
            1: http_request("/index.html"),
            2: http_request("/%69ndex.html"),
            3: http_request("/INDEX.HTML"),
            4: forged_admin_request(role="user", path="/admin"),
        }
        frames = [
            segment(payload, pkt_id, 2000 + pkt_id * 4096)
            for pkt_id, payload in benign.items()
        ]
        harness = run_once([frames])
        verdicts = harness.verdict_map()

        self.assertEqual(sorted(verdicts), sorted(benign))
        for pkt_id in benign:
            self.assertEqual(
                verdicts[pkt_id], VERDICT_ACCEPT, f"정상 요청 {pkt_id} 을 DROP했다"
            )


class TestSplitAndRetransmitMutation(unittest.TestCase):
    """분할·재전송은 공격자가 공짜로 쓸 수 있는 변형이다."""

    def _split(self, request: bytes) -> tuple[bytes, bytes]:
        cut = request.index(b"Cookie:") + 24
        return request[:cut], request[cut:]

    def test_split_exploit_is_blocked_on_the_completing_packet(self):
        first, second = self._split(forged_admin_request())
        harness = run_once([[
            segment(first, 1, 3000),
            segment(second, 2, 3000 + len(first)),
        ]])
        verdicts = harness.verdict_map()

        self.assertEqual(sorted(verdicts), [1, 2])
        self.assertEqual(verdicts[1], VERDICT_ACCEPT, "앞 조각만으로는 판단할 수 없다")
        self.assertEqual(verdicts[2], VERDICT_DROP, "완성 패킷을 놓쳤다")

    def test_duplicate_retransmit_does_not_open_a_hole(self):
        """같은 조각이 두 번 오면 stitcher가 어긋나 미탐이 날 수 있다."""
        first, second = self._split(forged_admin_request())
        harness = run_once([[
            segment(first, 1, 4000),
            segment(first, 2, 4000),                      # 정확한 재전송
            segment(second, 3, 4000 + len(first)),
        ]])
        verdicts = harness.verdict_map()

        self.assertEqual(sorted(verdicts), [1, 2, 3])
        self.assertEqual(verdicts[3], VERDICT_DROP, "재전송 뒤 완성 패킷이 통과했다")

    def test_overlapping_retransmit_does_not_open_a_hole(self):
        """겹치는 재전송은 offset 계산을 흔든다."""
        request = forged_admin_request()
        cut = request.index(b"Cookie:") + 24
        overlap = 8
        first = request[:cut]
        replayed = request[cut - overlap : cut]
        second = request[cut:]
        harness = run_once([[
            segment(first, 1, 5000),
            segment(replayed, 2, 5000 + cut - overlap),   # 겹치는 재전송
            segment(second, 3, 5000 + cut),
        ]])
        verdicts = harness.verdict_map()

        self.assertEqual(sorted(verdicts), [1, 2, 3])
        self.assertEqual(verdicts[3], VERDICT_DROP, "겹친 재전송 뒤 완성 패킷이 통과했다")

    def test_reordered_segments_still_get_a_verdict(self):
        """뒤 조각이 먼저 와도 모든 패킷은 verdict를 받아야 한다(가용성)."""
        first, second = self._split(forged_admin_request())
        harness = run_once([[
            segment(second, 1, 6000 + len(first)),        # 뒤 조각 먼저
            segment(first, 2, 6000),
        ]])
        self.assertEqual(sorted(harness.verdict_map()), [1, 2])


class TestReconnectMutation(unittest.TestCase):
    """세션 경계는 stitcher 상태와 verdict 전달 모두에 영향을 준다."""

    def test_exploit_split_across_a_reconnect_still_gets_verdicts(self):
        request = forged_admin_request()
        cut = request.index(b"Cookie:") + 24
        first, second = request[:cut], request[cut:]
        harness = MutationHarness([
            [segment(first, 1, 7000)],
            [segment(second, 2, 7000 + len(first))],
        ]).start()
        time.sleep(0.25)
        harness.drop_session()
        time.sleep(0.5)
        harness.stop()

        verdicts = harness.verdict_map()
        # 어느 세션에서 오든 두 패킷 모두 verdict를 받아야 한다. 재연결 구간에
        # verdict가 비면 Broker deadline이 만료돼 그대로 fail-open이다.
        self.assertEqual(sorted(verdicts), [1, 2], f"verdict 누락: {verdicts}")
        self.assertGreaterEqual(harness.runtime.session.sessions_opened, 2)

    def test_whole_exploit_after_a_reconnect_is_still_blocked(self):
        """재연결이 policy 상태를 훼손하면 두 번째 세션이 미탐이 된다."""
        harness = MutationHarness([
            [segment(http_request("/index.html"), 1, 8000)],
            [segment(forged_admin_request(), 2, 9000)],
        ]).start()
        time.sleep(0.25)
        harness.drop_session()
        time.sleep(0.5)
        harness.stop()

        verdicts = harness.verdict_map()
        self.assertEqual(verdicts.get(2), VERDICT_DROP, "재연결 뒤 exploit이 통과했다")


class TestWorkerDeathMutation(unittest.TestCase):
    """worker가 죽어도 hot path는 유지돼야 한다(§13, GAP-006)."""

    def test_watchdog_restarts_a_dead_noncritical_worker(self):
        harness = MutationHarness([[segment(http_request(), 1, 10000)]]).start()
        time.sleep(0.2)
        try:
            harness.runtime.correlation.stop()
            self.assertFalse(harness.runtime.correlation.is_alive())
            restarted = harness.runtime.watchdog.check_once()
            self.assertIn("correlation", restarted)
            self.assertTrue(harness.runtime.correlation.is_alive())
        finally:
            harness.stop()

    def test_exploit_is_still_blocked_after_a_worker_restart(self):
        harness = MutationHarness([
            [segment(http_request(), 1, 11000)],
            [segment(forged_admin_request(), 2, 12000)],
        ]).start()
        time.sleep(0.2)
        try:
            harness.runtime.correlation.stop()
            harness.runtime.watchdog.check_once()
            harness.drop_session()
            time.sleep(0.5)
        finally:
            harness.stop()

        self.assertEqual(
            harness.verdict_map().get(2), VERDICT_DROP,
            "worker 재시작 뒤 exploit이 통과했다",
        )

    def test_dead_critical_writer_is_restarted_and_reported(self):
        harness = MutationHarness([[segment(http_request(), 1, 13000)]]).start()
        time.sleep(0.2)
        try:
            harness.runtime.writer.stop()
            self.assertFalse(harness.runtime.writer.is_alive())
            restarted = harness.runtime.watchdog.check_once()
            self.assertIn("socket-writer", restarted)
            self.assertTrue(harness.runtime.writer.is_alive())
        finally:
            harness.stop()

        names = {line.get("event") for line in harness.audit_lines()}
        self.assertIn("worker-restarted", names)


if __name__ == "__main__":
    unittest.main()
