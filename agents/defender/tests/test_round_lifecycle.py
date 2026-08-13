"""Round lifecycle 통합 테스트.

설계 §4 런타임 흐름, §7.6 Round 간 학습과 상태 경계, §15.2, §17.

컨테이너는 매 Round 새로 생성되고 종료 시 삭제되며 기동 시간도 Round 시간에
포함된다(운영세칙 제6조 3항, 제15조 4항). **런타임 메모리의 학습 내용은 전부
사라진다.** 그것을 정상으로 취급하고 disk persistence를 요구하지 않는 것이
§8.1의 결정이며, 이 파일이 그 사실을 회귀 검증한다.
"""

import io
import json
import os
import tempfile
import threading
import time
import unittest

from aegis_defender.config import (
    UNCONTRACTED_ENV_NAMES,
    ConfigError,
    RuntimeConfig,
    load_config,
)
from aegis_defender.logging import AuditLogger
from aegis_defender.main import DefenderRuntime
from aegis_defender.protocol import (
    MSG_VERDICT,
    VERDICT_ACCEPT,
    HEARTBEAT_FRAME,
    decode_verdict,
)

from .fakes import FakeTransport, http_request, ipv4_tcp, packet_frame

_POLICY_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "policy"))


def config(policy_dir=_POLICY_DIR) -> RuntimeConfig:
    return RuntimeConfig(
        agent_socket="/run/agent.sock",
        llm_base_url="http://litellm.lig.internal:4000",
        llm_api_key="",  # advisory 비활성 — 테스트가 외부로 나가지 않는다
        policy_dir=policy_dir,
    )


class RuntimeHarness:
    """fake transport 위에서 런타임을 한 세션 돌린다."""

    def __init__(self, frames, policy_dir=_POLICY_DIR, stream=None):
        self.transport = FakeTransport()
        for frame in frames:
            self.transport.feed(frame)
        self.connects = 0
        self.stream = stream or io.StringIO()
        self.runtime = DefenderRuntime(
            config(policy_dir),
            audit=AuditLogger(stream=self.stream),
            connect_fn=self._connect,
        )
        self._thread = None

    def _connect(self, path):
        self.connects += 1
        if self.connects == 1:
            return self.transport
        self.runtime.session.stop()
        return FakeTransport()

    def start(self):
        self._thread = threading.Thread(target=self.runtime.run, daemon=True)
        self._thread.start()

    def stop(self, settle=0.0):
        if settle:
            time.sleep(settle)
        self.runtime.session.stop()
        self.runtime.stop_event.set()
        if self._thread is not None:
            self._thread.join(timeout=5.0)

    def verdicts(self):
        return [
            decode_verdict(frame)
            for frame in self.transport.sent
            if frame and frame[0] == MSG_VERDICT
        ]

    def heartbeats(self):
        return [frame for frame in self.transport.sent if frame == HEARTBEAT_FRAME]


class TestRuntimeConfig(unittest.TestCase):
    """§16.1 — 공식 환경변수는 세 개뿐이다."""

    def test_defaults_match_the_contract(self):
        loaded = load_config({})
        self.assertEqual(loaded.agent_socket, "/run/agent.sock")
        self.assertEqual(loaded.llm_base_url, "http://litellm.lig.internal:4000")
        self.assertEqual(loaded.llm_model, "gpt-4o-mini")
        self.assertFalse(loaded.advisory_enabled)

    def test_trailing_slash_is_stripped(self):
        loaded = load_config({"LLM_BASE_URL": "http://litellm.lig.internal:4000/"})
        self.assertEqual(loaded.llm_base_url, "http://litellm.lig.internal:4000")

    def test_relative_socket_path_is_rejected(self):
        # 계약은 절대 경로 mount 다(운영세칙 제16조 1항).
        with self.assertRaises(ConfigError):
            load_config({"AGENT_SOCKET": "agent.sock"})

    def test_bad_llm_scheme_is_rejected(self):
        with self.assertRaises(ConfigError):
            load_config({"LLM_BASE_URL": "ftp://litellm"})

    def test_uncontracted_env_is_ignored(self):
        """공식 계약에 없는 PHASE·LAYER·ROUND·TEAM_ID를 요구하지 않는다."""
        noisy = {name: "9" for name in UNCONTRACTED_ENV_NAMES}
        self.assertEqual(load_config(noisy), load_config({}))

    def test_advisory_enabled_requires_a_key(self):
        self.assertTrue(load_config({"LLM_API_KEY": "x"}).advisory_enabled)


class TestEndToEnd(unittest.TestCase):
    def test_every_packet_gets_a_verdict(self):
        frames = [
            packet_frame(index, ipv4_tcp(http_request(f"/page{index}")))
            for index in range(20)
        ]
        harness = RuntimeHarness(frames)
        harness.start()
        time.sleep(0.4)
        harness.stop()

        verdicts = harness.verdicts()
        self.assertEqual(len(verdicts), 20)
        self.assertEqual([pkt_id for pkt_id, _ in verdicts], list(range(20)))
        # 현재 이미지에는 차단 rule 이 없다(§16.2).
        self.assertTrue(all(value == VERDICT_ACCEPT for _, value in verdicts))

    def test_malformed_and_unknown_frames_do_not_stop_verdicts(self):
        frames = [
            packet_frame(1, b"\x45\x00"),                       # 파싱 실패
            bytes([0x09, 0x00, 0x00]),                          # 알 수 없는 type
            packet_frame(2, ipv4_tcp(http_request()), declared_len=900),  # 길이 불일치
            packet_frame(3, bytes([0x60]) + b"\x00" * 39),      # IPv6
            packet_frame(4, ipv4_tcp(http_request())),          # 정상
        ]
        harness = RuntimeHarness(frames)
        harness.start()
        time.sleep(0.4)
        harness.stop()

        verdicts = harness.verdicts()
        # 알 수 없는 type 을 뺀 네 건 모두 verdict 를 받는다.
        self.assertEqual(sorted(pkt_id for pkt_id, _ in verdicts), [1, 2, 3, 4])
        self.assertTrue(all(value == VERDICT_ACCEPT for _, value in verdicts))

    def test_heartbeat_goes_out_during_the_session(self):
        frames = [packet_frame(index, ipv4_tcp(http_request())) for index in range(5)]
        harness = RuntimeHarness(frames)
        harness.start()
        time.sleep(1.4)
        harness.stop()
        self.assertGreaterEqual(len(harness.heartbeats()), 1)

    def test_startup_is_logged_with_policy_provenance(self):
        harness = RuntimeHarness([])
        harness.start()
        time.sleep(0.2)
        harness.stop()

        lines = [json.loads(line) for line in harness.stream.getvalue().splitlines() if line]
        startup = [line for line in lines if line["event"] == "startup"]
        self.assertEqual(len(startup), 1)
        self.assertEqual(startup[0]["policy_source"], "active")
        self.assertEqual(startup[0]["drop_capable_rules"], 0)
        self.assertFalse(startup[0]["advisory_enabled"])


class TestFailureIsolation(unittest.TestCase):
    def test_missing_policy_directory_still_runs(self):
        """§10.2 — policy를 못 읽어도 HEARTBEAT와 ACCEPT 경로는 살아 있다."""
        with tempfile.TemporaryDirectory() as empty:
            frames = [packet_frame(1, ipv4_tcp(http_request()))]
            harness = RuntimeHarness(frames, policy_dir=empty)
            harness.start()
            time.sleep(0.3)
            harness.stop()

            self.assertEqual(harness.runtime.policy_report.source, "empty")
            self.assertEqual(harness.runtime.compiled_policy.drop_capable_rule_count, 0)
            self.assertEqual(len(harness.verdicts()), 1)

    def test_reconnect_keeps_one_thread_of_each_kind(self):
        """§15.2 — 반복 reconnect에서도 각 스레드가 정확히 하나다."""
        before = {thread.name for thread in threading.enumerate()}
        frames = [packet_frame(index, ipv4_tcp(http_request())) for index in range(3)]
        harness = RuntimeHarness(frames)
        harness.start()
        time.sleep(0.3)

        running = [
            thread.name for thread in threading.enumerate() if thread.name not in before
        ]
        for name in ("socket-writer", "heartbeat", "correlation"):
            self.assertEqual(running.count(name), 1, f"{name} 스레드가 하나가 아니다")

        harness.stop()


class TestShutdown(unittest.TestCase):
    def test_shutdown_completes_within_two_seconds(self):
        """§15.2 — SIGTERM에서 2초 내 정리 종료."""
        frames = [packet_frame(index, ipv4_tcp(http_request())) for index in range(5)]
        harness = RuntimeHarness(frames)
        harness.start()
        time.sleep(0.3)

        started = time.monotonic()
        harness.stop()
        elapsed = time.monotonic() - started
        self.assertLess(elapsed, 2.0, f"종료에 {elapsed:.2f}초 걸렸다")

    def test_worker_threads_are_gone_after_shutdown(self):
        harness = RuntimeHarness([])
        harness.start()
        time.sleep(0.2)
        harness.stop()
        time.sleep(0.1)

        names = {thread.name for thread in threading.enumerate()}
        for name in ("socket-writer", "heartbeat", "correlation", "audit-log"):
            self.assertNotIn(name, names)

    def test_shutdown_log_carries_nonsensitive_summary(self):
        harness = RuntimeHarness([packet_frame(1, ipv4_tcp(http_request()))])
        harness.start()
        time.sleep(0.3)
        harness.stop()

        lines = [json.loads(line) for line in harness.stream.getvalue().splitlines() if line]
        shutdown = [line for line in lines if line["event"] == "shutdown"]
        self.assertEqual(len(shutdown), 1)
        self.assertIn("counters", shutdown[0])
        self.assertIn("advisory", shutdown[0])
        self.assertEqual(shutdown[0]["advisory"]["calls"], 0)


class TestRoundStateBoundary(unittest.TestCase):
    """§7.6, §8.1 — Round 종료 후 상태가 사라지는 것을 정상으로 취급한다."""

    def test_new_runtime_starts_with_empty_state(self):
        frames = [
            packet_frame(index, ipv4_tcp(http_request(f"/p{index}")))
            for index in range(10)
        ]
        first = RuntimeHarness(frames)
        first.start()
        time.sleep(0.4)
        first.stop()
        self.assertGreater(first.runtime.anomaly.total, 0)

        second = RuntimeHarness([])
        self.assertEqual(second.runtime.anomaly.total, 0)
        self.assertEqual(second.runtime.correlation.builder.flow_count, 0)
        self.assertIsNone(second.runtime.snapshot_ref.read())
        self.assertEqual(second.runtime.event_queue.qsize(), 0)

    def test_round_writes_nothing_to_disk(self):
        """PCAP·로그·cache·생성 결과가 파일로 남지 않는다(§15.7)."""
        with tempfile.TemporaryDirectory() as workdir:
            original = os.getcwd()
            os.chdir(workdir)
            try:
                frames = [
                    packet_frame(index, ipv4_tcp(http_request(f"/p{index}")))
                    for index in range(10)
                ]
                harness = RuntimeHarness(frames)
                harness.start()
                time.sleep(0.4)
                harness.stop()
            finally:
                os.chdir(original)
            self.assertEqual(os.listdir(workdir), [])

    def test_policy_files_are_not_modified_at_runtime(self):
        """§10.2 — 실행 중 파일 변경과 self-modification을 금지한다."""
        before = {
            name: os.stat(os.path.join(_POLICY_DIR, name)).st_mtime
            for name in os.listdir(_POLICY_DIR)
        }
        harness = RuntimeHarness([packet_frame(1, ipv4_tcp(http_request()))])
        harness.start()
        time.sleep(0.3)
        harness.stop()
        after = {
            name: os.stat(os.path.join(_POLICY_DIR, name)).st_mtime
            for name in os.listdir(_POLICY_DIR)
        }
        self.assertEqual(before, after)


if __name__ == "__main__":
    unittest.main()
