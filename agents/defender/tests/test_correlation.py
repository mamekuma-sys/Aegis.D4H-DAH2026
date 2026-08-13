"""비동기 event 경계와 상관분석 테스트.

설계 §11, §8.1 비동기 event queue, §15.5.
"""

import threading
import time
import unittest
from types import MappingProxyType

from aegis_defender.correlation.causal import (
    STAGE_INJECTION,
    STAGE_PATH_PROBE,
    STAGE_REPEAT_AFTER_HIT,
    STAGE_SCAN,
    CausalMatcher,
    ChainEvidence,
)
from aegis_defender.correlation.risk import MAX_SCORE, FlowFeatures, RiskModel
from aegis_defender.correlation.window import IntervalTracker
from aegis_defender.events import (
    DEFAULT_EVENT_QUEUE_CAPACITY,
    BoundedEventQueue,
    CorrelationEvent,
    EventAdapter,
)
from aegis_defender.packet import ParseStatus, ParsedPacket, parse_ip
from aegis_defender.state import (
    CorrelationBuilder,
    CorrelationSnapshotRef,
    CorrelationWorker,
)

from .fakes import FakeClock, http_request, ipv4_tcp


def make_event(index: int) -> CorrelationEvent:
    parsed = parse_ip(ipv4_tcp(http_request(f"/p{index}"), src_port=1024 + index))
    return EventAdapter().to_event(parsed, float(index))


class TestBoundedEventQueue(unittest.TestCase):
    """§8.1 — 가득 차면 들어오려는 최신 event를 O(1)로 버린다(drop-newest)."""

    def test_default_capacity(self):
        self.assertEqual(BoundedEventQueue().capacity, DEFAULT_EVENT_QUEUE_CAPACITY)
        self.assertEqual(DEFAULT_EVENT_QUEUE_CAPACITY, 1024)

    def test_exactly_full_then_one_more_drops_the_newest(self):
        queue = BoundedEventQueue(capacity=1024)
        events = [make_event(index) for index in range(1024)]
        for item in events:
            self.assertTrue(queue.put_nowait(item))
        self.assertEqual(queue.qsize(), 1024)

        newest = make_event(9999)
        self.assertFalse(queue.put_nowait(newest))
        self.assertEqual(queue.qsize(), 1024)
        self.assertEqual(queue.dropped_newest, 1)

        # 기존 FIFO 순서가 보존된다. 오래된 것을 밀어내지 않았다.
        self.assertEqual(queue.get().monotonic_ts, events[0].monotonic_ts)

    def test_repeated_enqueue_on_saturated_queue(self):
        queue = BoundedEventQueue(capacity=16)
        for index in range(16):
            queue.put_nowait(make_event(index))
        for index in range(100):
            self.assertFalse(queue.put_nowait(make_event(1000 + index)))
        self.assertEqual(queue.qsize(), 16)
        self.assertEqual(queue.dropped_newest, 100)

    def test_get_on_empty_queue_returns_none(self):
        self.assertIsNone(BoundedEventQueue().get(timeout=0.01))


class TestEventAdapter(unittest.TestCase):
    """§8 — compact parsed record. 원본 payload·packet 객체를 참조하지 않는다."""

    def setUp(self):
        self.adapter = EventAdapter()

    def test_event_holds_no_payload(self):
        payload = b"SECRET-MARKER-" + b"x" * 400
        parsed = parse_ip(ipv4_tcp(b"GET /a HTTP/1.1\r\n\r\n" + payload))
        event = self.adapter.to_event(parsed, 1.0)

        # flow_key 를 뺀 모든 field 가 스칼라다. bytes 가 하나라도 남으면 큐가
        # 보유하는 메모리가 capacity 가 아니라 패킷 크기에 비례하게 된다.
        for name in CorrelationEvent.__slots__:
            if name == "flow_key":
                continue
            self.assertNotIsInstance(
                getattr(event, name), (bytes, bytearray, memoryview), f"{name} 이 원본을 참조한다"
            )
        self.assertEqual(event.payload_len, len(parsed.payload))
        self.assertNotIn(b"SECRET-MARKER", repr(event).encode("latin-1", "replace"))

    def test_path_digest_is_irreversible_and_stable(self):
        first = self.adapter.to_event(parse_ip(ipv4_tcp(http_request("/admin"))), 1.0)
        second = self.adapter.to_event(parse_ip(ipv4_tcp(http_request("/admin"))), 2.0)
        third = self.adapter.to_event(parse_ip(ipv4_tcp(http_request("/other"))), 3.0)
        self.assertEqual(first.path_digest, second.path_digest)
        self.assertNotEqual(first.path_digest, third.path_digest)
        self.assertEqual(len(first.path_digest), 8)
        self.assertNotIn("admin", first.path_digest)

    def test_encoded_nesting_flag(self):
        event = self.adapter.to_event(parse_ip(ipv4_tcp(http_request("/a?p=%252e%252e"))), 1.0)
        self.assertTrue(event.encoded_nesting)

    def test_long_uri_flag(self):
        event = self.adapter.to_event(parse_ip(ipv4_tcp(http_request("/" + "a" * 300))), 1.0)
        self.assertTrue(event.long_uri)

    def test_scan_flag_event_type(self):
        event = self.adapter.to_event(parse_ip(ipv4_tcp(flags=0x00)), 1.0)
        self.assertEqual(event.scan_flag_name, "tcp-null")
        self.assertEqual(event.event_type, "scan-flags")

    def test_unparsed_packet_yields_no_event(self):
        self.assertIsNone(self.adapter.to_event(ParsedPacket(ParseStatus.EXCEPTION), 1.0))

    def test_adapter_never_raises(self):
        class Broken:
            status = ParseStatus.OK
            flow_key = object()

            @property
            def payload(self):
                raise RuntimeError("boom")

        self.assertIsNone(self.adapter.to_event(Broken(), 1.0))


class TestCorrelationWorker(unittest.TestCase):
    def test_worker_publishes_snapshot(self):
        clock = FakeClock()
        queue = BoundedEventQueue()
        ref = CorrelationSnapshotRef()
        worker = CorrelationWorker(queue, ref, metrics=None, clock=clock)

        parsed = parse_ip(ipv4_tcp(http_request("/a/../../etc/passwd")))
        for index in range(4):
            clock.advance(0.1)
            queue.put_nowait(EventAdapter().to_event(
                parsed, clock.now, rule_id="r1", sig_category="path-traversal"
            ))
            worker.drain_once(timeout=0.01)

        snapshot = worker.publish(clock.now)
        self.assertIsNotNone(ref.read())
        self.assertIn(parsed.flow_key, snapshot.entries)
        self.assertGreater(snapshot.entries[parsed.flow_key].score, 0)

    def test_reader_always_sees_a_complete_generation(self):
        """§11 — hot path는 builder의 부분 갱신을 보지 않는다."""
        clock = FakeClock()
        queue = BoundedEventQueue()
        ref = CorrelationSnapshotRef()
        builder = CorrelationBuilder()
        worker = CorrelationWorker(queue, ref, builder=builder, clock=clock)
        parsed = parse_ip(ipv4_tcp(http_request("/a/../../etc/passwd")))

        stop = threading.Event()
        observed = []

        def reader():
            while not stop.is_set():
                snapshot = ref.read()
                if snapshot is not None:
                    observed.append((
                        snapshot.generation,
                        isinstance(snapshot.entries, MappingProxyType),
                        tuple(snapshot.entries.values()),
                    ))

        builder.observe(EventAdapter().to_event(
            parsed, clock.now, rule_id="r1", sig_category="path-traversal"
        ), clock.now)
        worker.publish(clock.now)

        thread = threading.Thread(target=reader, daemon=True)
        thread.start()
        # publish 루프가 μs 단위라 reader 가 한 번도 스케줄되지 않은 채 끝날 수 있다.
        # 최소 한 건을 읽은 것을 확인한 뒤에 경쟁 구간으로 들어간다.
        deadline = time.monotonic() + 2.0
        while not observed and time.monotonic() < deadline:
            time.sleep(0.001)

        for _ in range(200):
            clock.advance(0.01)
            builder.observe(EventAdapter().to_event(
                parsed, clock.now, rule_id="r1", sig_category="path-traversal"
            ), clock.now)
            worker.publish(clock.now)
        stop.set()
        thread.join(timeout=2.0)

        self.assertTrue(observed, "reader 가 snapshot 을 한 건도 읽지 못했다")
        for generation, is_proxy, entries in observed:
            self.assertGreater(generation, 0)
            self.assertTrue(is_proxy)
            for entry in entries:
                self.assertIsInstance(entry.matched_stages, tuple)


class TestCausalMatcher(unittest.TestCase):
    """§2, §11 — 관측된 evidence로만 단계를 만든다."""

    def setUp(self):
        self.matcher = CausalMatcher()

    def test_no_evidence_no_stages(self):
        self.assertEqual(self.matcher.match(ChainEvidence()), ())

    def test_scan_evidence(self):
        self.assertIn(STAGE_SCAN, self.matcher.match(ChainEvidence(scan_flag_hits=2)))

    def test_category_maps_to_stage(self):
        stages = self.matcher.match(ChainEvidence(
            sig_categories=("path-traversal", "sql-injection"), sig_hits=2
        ))
        self.assertIn(STAGE_PATH_PROBE, stages)
        self.assertIn(STAGE_INJECTION, stages)

    def test_repeat_after_hit(self):
        stages = self.matcher.match(ChainEvidence(sig_hits=1, packets_after_first_hit=3))
        self.assertIn(STAGE_REPEAT_AFTER_HIT, stages)

    def test_stage_names_do_not_encode_report_numbering(self):
        # §2 — S4ChainStage 1~5 와 FinalsPhase 번호를 임의로 대응시키지 않는다.
        stages = self.matcher.match(ChainEvidence(
            scan_flag_hits=1, sig_categories=("sql-injection",), sig_hits=1,
            packets_after_first_hit=1,
        ))
        for stage in stages:
            self.assertTrue(stage.startswith("observed-"))
            self.assertFalse(any(character.isdigit() for character in stage))

    def test_unobserved_keys_are_not_required(self):
        # session_id·vehicle_id·MissionState 없이 동작한다(§11).
        evidence = ChainEvidence(sig_hits=1, sig_categories=("file-read",))
        self.assertTrue(self.matcher.match(evidence))


class TestRiskModel(unittest.TestCase):
    def test_score_is_bounded(self):
        extreme = FlowFeatures(
            packets=10**6, sig_hits=10**6, distinct_paths=10**6,
            distinct_paths_saturated=True, encoded_hits=10**6, long_uri_hits=10**6,
            scan_flag_hits=10**6, interval_regularity=1.0, duration=10**6,
        )
        self.assertLessEqual(RiskModel().score(extreme), MAX_SCORE)
        self.assertGreaterEqual(RiskModel().score(FlowFeatures()), 0)

    def test_empty_features_score_zero(self):
        self.assertEqual(RiskModel().score(FlowFeatures()), 0)

    def test_preliminary_synthetic_scores_are_not_thresholds(self):
        """§3 — 예선 합성 점수 15→52→131→196→238을 본선에 복사하지 않는다.

        점수 상한이 100이므로 보고서의 131·196·238은 이 모델에서 표현조차 되지
        않는다. 값을 옮겨 적는 실수가 구조적으로 불가능하다.
        """
        self.assertEqual(MAX_SCORE, 100)
        for forbidden in (131, 196, 238):
            self.assertGreater(forbidden, MAX_SCORE)
        model = RiskModel()
        self.assertLessEqual(model.score(FlowFeatures(sig_hits=100)), MAX_SCORE)

    def test_low_regularity_adds_nothing(self):
        model = RiskModel()
        base = model.score(FlowFeatures(sig_hits=1))
        self.assertEqual(model.score(FlowFeatures(sig_hits=1, interval_regularity=0.3)), base)


class TestIntervalTracker(unittest.TestCase):
    def test_insufficient_samples_report_zero(self):
        tracker = IntervalTracker()
        for index in range(3):
            tracker.observe(float(index))
        self.assertEqual(tracker.regularity(3.0), 0.0)

    def test_uniform_intervals_are_highly_regular(self):
        tracker = IntervalTracker()
        for index in range(20):
            tracker.observe(index * 0.5)
        self.assertGreater(tracker.regularity(10.0), 0.9)

    def test_irregular_intervals_score_lower(self):
        tracker = IntervalTracker()
        for ts in (0.0, 0.01, 1.5, 1.51, 5.0, 5.02, 9.9, 10.0):
            tracker.observe(ts)
        self.assertLess(tracker.regularity(10.0), 0.9)

    def test_window_bounds_memory(self):
        tracker = IntervalTracker(capacity=8)
        for index in range(100):
            tracker.observe(float(index))
        self.assertLessEqual(len(tracker._recent(200.0)), 8)


if __name__ == "__main__":
    unittest.main()
