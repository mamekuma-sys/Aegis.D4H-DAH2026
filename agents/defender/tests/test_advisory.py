"""비동기 LLM 조언 경계 테스트.

설계 §0.5, §12 LLM 사용 경계, §12.1 model 선택과 증빙, §15.7.

검증 대상은 조언의 품질이 아니라 **경계**다. 원격 호출이 판정 경로에 없고,
prompt에 비밀이 없고, 장애가 HEARTBEAT·verdict에 닿지 않고, 출력에 실행 권한이
없다는 것.
"""

import io
import json
import threading
import unittest
import urllib.error
from types import MappingProxyType

from aegis_defender.advisory import (
    FAILURE_BACKOFF_SECONDS,
    MAX_CALLS_PER_ROUND,
    MAX_CONSECUTIVE_FAILURES,
    MAX_RECENT_ADVISORIES,
    MIN_CALL_INTERVAL_SECONDS,
    REQUEST_TIMEOUT_SECONDS,
    AdvisoryWorker,
    SecretLeakError,
    assert_no_secrets,
    parse_advisory_candidates,
)
from aegis_defender.config import RuntimeConfig
from aegis_defender.logging import AuditLogger
from aegis_defender.packet import FlowKey
from aegis_defender.policy import HotPolicy
from aegis_defender.rules import CompiledPolicy
from aegis_defender.state import CorrelationSnapshot, CorrelationSnapshotRef, FlowScore

from .fakes import FakeClock

ENABLED = RuntimeConfig(
    agent_socket="/run/agent.sock",
    llm_base_url="http://litellm.lig.internal:4000",
    llm_api_key="test-key-value",
)
DISABLED = RuntimeConfig(agent_socket="/run/agent.sock", llm_api_key="")


def published_ref(clock: FakeClock, count: int = 3) -> CorrelationSnapshotRef:
    ref = CorrelationSnapshotRef()
    entries = {}
    for index in range(count):
        key = FlowKey(bytes((10, 1, 0, 4)), 1024 + index, bytes((10, 1, 1, 4)), 80, 6)
        entries[key] = FlowScore(
            score=90 - index, sig_hits=index + 1, distinct_paths=index,
            scan_flag_hits=0, matched_stages=("observed-path-probe",),
            updated_at=clock.now,
        )
    ref.publish(CorrelationSnapshot(1, clock.now, clock.now + 5, MappingProxyType(entries)))
    return ref


class TestEnablement(unittest.TestCase):
    def test_disabled_without_api_key(self):
        worker = AdvisoryWorker(DISABLED, CorrelationSnapshotRef(), clock=FakeClock())
        self.assertFalse(worker.enabled)
        self.assertIsNone(worker.run_once())
        self.assertEqual(worker.calls, 0)

    def test_start_is_a_noop_when_disabled(self):
        worker = AdvisoryWorker(DISABLED, CorrelationSnapshotRef(), clock=FakeClock())
        worker.start()
        self.assertIsNone(worker._thread)


class TestRedaction(unittest.TestCase):
    """§12 — raw payload, secret, token, flag를 prompt에 넣지 않는다."""

    def test_features_are_aggregates_only(self):
        clock = FakeClock()
        worker = AdvisoryWorker(ENABLED, published_ref(clock), clock=clock)
        features = worker.collect_features()
        self.assertTrue(features)
        for item in features:
            self.assertRegex(item.flow_label, r"^\d+/\d+$")
            self.assertIsInstance(item.score, int)

    def test_prompt_contains_no_addresses_or_payload(self):
        clock = FakeClock()
        worker = AdvisoryWorker(ENABLED, published_ref(clock), clock=clock)
        messages = worker.build_messages(worker.collect_features())
        blob = json.dumps(messages)
        self.assertNotIn("10.1.0.4", blob)
        self.assertNotIn("10.1.1.4", blob)
        self.assertNotIn("test-key-value", blob)
        self.assertIn("8410/8420", blob)

    def test_secret_guard_blocks_flag_shaped_text(self):
        with self.assertRaises(SecretLeakError):
            assert_no_secrets("candidate seen near FLAG{aaaaaaaabbbbbbbbccccccccdddddddd}")

    def test_secret_guard_blocks_bearer_token(self):
        with self.assertRaises(SecretLeakError):
            assert_no_secrets("Authorization: Bearer abcdef123456")

    def test_secret_guard_allows_plain_aggregates(self):
        assert_no_secrets("- flow 6/80: score=90 sig_hits=3 distinct_paths=4 stages=none")

    def test_structured_candidates_are_bounded_for_break_review(self):
        content = json.dumps({"candidates": [{
            "protocol": "tcp",
            "port": 8410,
            "field": "Exchange.Envelope.sample",
            "pattern_family": "exact topic and action tuple",
            "evidence_needed": "positive plus normal negative and SLA fixtures",
            "false_positive_risk": "unknown action overlap",
        }]})
        candidates = parse_advisory_candidates(content)
        self.assertEqual(len(candidates), 1)
        self.assertEqual(candidates[0].port, 8410)
        self.assertEqual(candidates[0].protocol, "tcp")

    def test_unstructured_or_invalid_candidates_remain_non_actionable(self):
        self.assertEqual(parse_advisory_candidates("DROP everything"), ())
        self.assertEqual(parse_advisory_candidates(json.dumps({"candidates": [{
            "protocol": "tcp", "port": 70000, "field": "x",
            "pattern_family": "x", "evidence_needed": "x",
            "false_positive_risk": "x",
        }]})), ())

    def test_blocked_prompt_does_not_call_out(self):
        clock = FakeClock()
        calls = []

        def transport(url, key, body, timeout):
            calls.append(url)
            return {}

        def leaky_messages(features):
            raise SecretLeakError("guard tripped")

        worker = AdvisoryWorker(ENABLED, published_ref(clock), clock=clock, transport=transport)
        worker.build_messages = leaky_messages
        clock.advance(301.0)
        self.assertIsNone(worker.run_once())
        self.assertEqual(calls, [], "guard 에 걸렸는데도 외부 호출이 나갔다")
        self.assertEqual(worker.failures, 1)


class TestBudget(unittest.TestCase):
    """§12.1 — 동점 시 token 비용이 적은 팀이 우선하므로 예산을 관리한다."""

    def _worker(self, clock, transport=None, max_calls=20):
        return AdvisoryWorker(
            ENABLED, published_ref(clock), clock=clock,
            transport=transport or self._ok_transport, max_calls=max_calls,
        )

    @staticmethod
    def _ok_transport(url, key, body, timeout):
        return {
            "choices": [{"message": {"content": "candidate: inspect request path length"}}],
            "usage": {"prompt_tokens": 120, "completion_tokens": 40},
        }

    def test_minimum_interval_between_calls(self):
        clock = FakeClock()
        worker = self._worker(clock)
        clock.advance(MIN_CALL_INTERVAL_SECONDS + 1.0)
        self.assertIsNotNone(worker.run_once())
        self.assertIsNone(worker.run_once())  # 간격 미충족
        clock.advance(MIN_CALL_INTERVAL_SECONDS - 1.0)
        self.assertIsNone(worker.run_once())
        clock.advance(2.0)
        self.assertIsNotNone(worker.run_once())
        self.assertEqual(worker.calls, 2)

    def test_production_budget_is_break_only_and_bounded(self):
        self.assertEqual(MIN_CALL_INTERVAL_SECONDS, 300.0)
        self.assertEqual(MAX_CALLS_PER_ROUND, 4)
        self.assertEqual(REQUEST_TIMEOUT_SECONDS, 15.0)
        self.assertEqual(MAX_CONSECUTIVE_FAILURES, 2)
        self.assertEqual(FAILURE_BACKOFF_SECONDS, 600.0)

    def test_uses_official_completion_token_parameter(self):
        clock = FakeClock()
        sent = {}

        def transport(url, key, body, timeout):
            sent.update(body)
            return self._ok_transport(url, key, body, timeout)

        worker = self._worker(clock, transport=transport)
        clock.advance(301.0)
        self.assertIsNotNone(worker.run_once())
        self.assertEqual(sent["max_completion_tokens"], 768)
        self.assertNotIn("max_tokens", sent)

    def test_gpt56_uses_low_reasoning_and_developer_message(self):
        clock = FakeClock()
        sent = {}

        def transport(url, key, body, timeout):
            sent.update(body)
            return self._ok_transport(url, key, body, timeout)

        # 명시적으로 gpt-5.6-sol을 선택해도 low effort로 제한한다.
        from aegis_defender.config import RuntimeConfig
        cfg = RuntimeConfig(
            agent_socket="/run/agent.sock",
            llm_base_url="http://litellm.lig.internal:4000",
            llm_api_key="test-key-value",
            llm_model="gpt-5.6-sol",
        )
        worker = AdvisoryWorker(
            cfg, published_ref(clock), clock=clock, transport=transport,
        )
        clock.advance(301.0)
        self.assertIsNotNone(worker.run_once())
        self.assertEqual(sent["model"], "gpt-5.6-sol")
        self.assertEqual(sent["reasoning_effort"], "low")
        self.assertEqual(sent["messages"][0]["role"], "developer")
        self.assertNotIn("temperature", sent)

    def test_primary_default_uses_gpt54_chat_temperature(self):
        # 기본 모델은 gpt-5.4(chat) — reasoning_effort 대신 낮은 temperature로
        # 60초 안에 완료된다. R9의 gpt-5.6-sol 9/9 TimeoutError 회귀 방지.
        clock = FakeClock()
        sent = {}

        def transport(url, key, body, timeout):
            sent.update(body)
            return self._ok_transport(url, key, body, timeout)

        worker = self._worker(clock, transport=transport)
        clock.advance(301.0)
        self.assertIsNotNone(worker.run_once())
        self.assertEqual(sent["model"], "gpt-5.4")
        self.assertNotIn("reasoning_effort", sent)
        self.assertEqual(sent["temperature"], 0.2)

    def test_round_call_cap(self):
        clock = FakeClock()
        worker = self._worker(clock, max_calls=3)
        for _ in range(10):
            clock.advance(301.0)
            worker.run_once()
        self.assertEqual(worker.calls, 3)

    def test_recent_advisories_are_bounded(self):
        clock = FakeClock()
        worker = self._worker(clock, max_calls=1000)
        for _ in range(MAX_RECENT_ADVISORIES + 10):
            clock.advance(301.0)
            worker.run_once()
        self.assertEqual(len(worker.recent), MAX_RECENT_ADVISORIES)

    def test_usage_evidence_is_recorded(self):
        """제23조 — 외부 API 사용 내역과 호출 증빙."""
        clock = FakeClock()
        worker = self._worker(clock)
        clock.advance(301.0)
        worker.run_once()
        evidence = worker.usage_evidence()
        self.assertEqual(evidence["model_id"], "gpt-5.4")
        self.assertEqual(evidence["calls"], 1)
        self.assertEqual(evidence["prompt_tokens"], 120)
        self.assertEqual(evidence["completion_tokens"], 40)
        self.assertEqual(evidence["failure_rate"], 0.0)


class TestFailureIsolation(unittest.TestCase):
    """§13 — LLM timeout·429·invalid JSON·quota 소진이 verdict에 무영향."""

    def _run_with(self, error, clock=None):
        clock = clock or FakeClock()

        def transport(url, key, body, timeout):
            raise error

        worker = AdvisoryWorker(ENABLED, published_ref(clock), clock=clock, transport=transport)
        clock.advance(301.0)
        result = worker.run_once()
        return worker, result

    def test_timeout(self):
        worker, result = self._run_with(TimeoutError("slow"))
        self.assertIsNone(result)
        self.assertEqual(worker.failures, 1)

    def test_http_429(self):
        error = urllib.error.HTTPError("u", 429, "Too Many Requests", {}, None)
        worker, result = self._run_with(error)
        self.assertIsNone(result)
        self.assertEqual(worker.failures, 1)

    def test_connection_error(self):
        worker, result = self._run_with(urllib.error.URLError("no route"))
        self.assertIsNone(result)
        self.assertEqual(worker.failures, 1)

    def test_malformed_response(self):
        clock = FakeClock()

        def transport(url, key, body, timeout):
            return {"unexpected": True}

        worker = AdvisoryWorker(ENABLED, published_ref(clock), clock=clock, transport=transport)
        clock.advance(301.0)
        self.assertIsNone(worker.run_once())
        self.assertEqual(worker.failures, 1)

    def test_consecutive_failures_trigger_backoff(self):
        clock = FakeClock()

        def transport(url, key, body, timeout):
            raise TimeoutError("slow")

        worker = AdvisoryWorker(ENABLED, published_ref(clock), clock=clock, transport=transport)
        for _ in range(MAX_CONSECUTIVE_FAILURES):
            clock.advance(301.0)
            worker.run_once()
        self.assertEqual(worker.failures, MAX_CONSECUTIVE_FAILURES)
        clock.advance(FAILURE_BACKOFF_SECONDS - 1.0)
        self.assertFalse(worker.should_call(clock.now))
        clock.advance(2.0)
        self.assertTrue(worker.should_call(clock.now))

    def test_no_snapshot_means_no_call(self):
        clock = FakeClock()
        calls = []
        worker = AdvisoryWorker(
            ENABLED, CorrelationSnapshotRef(), clock=clock,
            transport=lambda *args: calls.append(args) or {},
        )
        clock.advance(301.0)
        self.assertIsNone(worker.run_once())
        self.assertEqual(calls, [])


class TestAuditRedaction(unittest.TestCase):
    """§15.7 — token·API key·raw payload·`FLAG{...}`·credential이 로그에 없다."""

    def _emit(self, **fields):
        stream = io.StringIO()
        logger = AuditLogger(stream=stream)
        logger.log("test", **fields)
        return stream.getvalue()

    def test_flag_value_is_redacted(self):
        output = self._emit(note="captured FLAG{aaaaaaaabbbbbbbbccccccccdddddddd}")
        self.assertNotIn("aaaaaaaabbbbbbbb", output)
        self.assertIn("REDACTED", output)

    def test_long_final_format_flag_is_redacted(self):
        secret = "FLAG{" + ("z" * 512) + "}"
        output = self._emit(note="captured " + secret)
        self.assertNotIn("z" * 32, output)
        self.assertIn("REDACTED", output)

    def test_api_key_is_redacted(self):
        output = self._emit(note="using sk-abcdefghijklmnop for auth")
        self.assertNotIn("abcdefghijklmnop", output)

    def test_authorization_header_is_redacted(self):
        output = self._emit(header="Authorization: Bearer abcdef123456")
        self.assertNotIn("abcdef123456", output)

    def test_bytes_are_never_decoded_into_logs(self):
        output = self._emit(payload=b"GET /secret?token=abcdef HTTP/1.1")
        self.assertNotIn("secret", output)
        self.assertIn("bytes", output)

    def test_long_fields_are_truncated(self):
        output = self._emit(note="A" * 5000)
        self.assertLess(len(output), 1000)

    def test_logging_never_raises(self):
        class Unserializable:
            def __repr__(self):
                raise RuntimeError("boom")

        stream = io.StringIO()
        logger = AuditLogger(stream=stream)
        logger.log("test", value=Unserializable())
        self.assertEqual(logger.dropped, 1)

    def test_queue_full_drops_logs_instead_of_blocking(self):
        # 로그를 지키자고 verdict 를 늦추지 않는다.
        stream = io.StringIO()
        logger = AuditLogger(stream=stream, capacity=4)
        logger._thread = threading.current_thread()  # 비동기 모드로 강제
        try:
            for index in range(50):
                logger.log("spam", index=index)
        finally:
            logger._thread = None
        self.assertGreater(logger.dropped, 0)


class TestNoRuntimeAuthority(unittest.TestCase):
    """§12 — LLM 출력은 어떤 packet도 직접 ACCEPT/DROP하지 않는다."""

    def test_worker_references_no_policy_object(self):
        clock = FakeClock()
        worker = AdvisoryWorker(ENABLED, published_ref(clock), clock=clock)
        for value in vars(worker).values():
            self.assertNotIsInstance(value, HotPolicy)
            self.assertNotIsInstance(value, CompiledPolicy)

    def test_worker_exposes_no_policy_mutation_api(self):
        forbidden = ("apply", "promote", "install_rule", "add_rule", "set_policy")
        for name in forbidden:
            self.assertFalse(hasattr(AdvisoryWorker, name))

    def test_advisory_record_is_frozen(self):
        clock = FakeClock()
        worker = AdvisoryWorker(
            ENABLED, published_ref(clock), clock=clock,
            transport=TestBudget._ok_transport,
        )
        clock.advance(301.0)
        advisory = worker.run_once()
        self.assertIsNotNone(advisory)
        with self.assertRaises(Exception):
            advisory.recommendation = "DROP everything"

    def test_recommendation_is_redacted_before_storage(self):
        clock = FakeClock()

        def transport(url, key, body, timeout):
            return {
                "choices": [{"message": {
                    "content": "found FLAG{aaaaaaaabbbbbbbbccccccccdddddddd} in traffic"
                }}],
                "usage": {},
            }

        worker = AdvisoryWorker(ENABLED, published_ref(clock), clock=clock, transport=transport)
        clock.advance(301.0)
        advisory = worker.run_once()
        self.assertNotIn("aaaaaaaabbbbbbbb", advisory.recommendation)


if __name__ == "__main__":
    unittest.main()
