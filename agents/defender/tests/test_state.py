"""bounded state와 snapshot publication 테스트.

설계 §8.1 용량 상한, §11 온라인 비동기 상관분석, §15.5.
"""

import unittest
from types import MappingProxyType

from aegis_defender.events import CorrelationEvent
from aegis_defender.packet import FlowKey
from aegis_defender.state import (
    FLOW_BUFFER_BYTES,
    PER_KEY_DISTINCT_CAP,
    CorrelationBuilder,
    CorrelationSnapshot,
    CorrelationSnapshotRef,
    FlowReassemblyBuffer,
    FlowScore,
)

from .fakes import FakeClock


def flow(port: int = 80, src_port: int = 51234) -> FlowKey:
    return FlowKey(bytes((10, 1, 0, 4)), src_port, bytes((10, 1, 1, 4)), port, 6)


def event(key: FlowKey, ts: float, **overrides) -> CorrelationEvent:
    fields = {
        "event_type": "packet",
        "flow_key": key,
        "monotonic_ts": ts,
        "protocol": 6,
        "dst_port": key.dst_port,
        "payload_len": 100,
        "verdict": 0,
        "evidence_source": "test",
    }
    fields.update(overrides)
    return CorrelationEvent(**fields)


class TestFlowReassemblyBuffer(unittest.TestCase):
    """§8.1 — flow당 16KB 링버퍼. 넘치면 오래된 앞부분을 버린다."""

    def test_stays_within_bound(self):
        buffer = FlowReassemblyBuffer()
        for _ in range(40):
            buffer.append(b"A" * 1024)
        self.assertEqual(len(buffer), FLOW_BUFFER_BYTES)

    def test_keeps_the_newest_bytes(self):
        buffer = FlowReassemblyBuffer()
        buffer.append(b"O" * FLOW_BUFFER_BYTES)
        buffer.append(b"NEW")
        view = buffer.view()
        self.assertEqual(len(view), FLOW_BUFFER_BYTES)
        self.assertTrue(view.endswith(b"NEW"))

    def test_small_appends_are_kept_whole(self):
        buffer = FlowReassemblyBuffer()
        buffer.append(b"abc")
        buffer.append(b"def")
        self.assertEqual(buffer.view(), b"abcdef")


class TestSnapshotPublication(unittest.TestCase):
    """§11 — 참조 하나의 원자적 교체. 읽는 쪽은 lock을 잡지 않는다."""

    def test_read_before_publish_is_none(self):
        self.assertIsNone(CorrelationSnapshotRef().read())

    def test_publish_replaces_reference(self):
        ref = CorrelationSnapshotRef()
        first = CorrelationSnapshot(1, 0.0, 5.0, MappingProxyType({}))
        second = CorrelationSnapshot(2, 1.0, 6.0, MappingProxyType({}))
        ref.publish(first)
        self.assertIs(ref.read(), first)
        ref.publish(second)
        self.assertIs(ref.read(), second)

    def test_ref_has_only_the_snapshot_slot(self):
        # lock 이나 다른 상태가 붙으면 §11 의 "lock 없이 한 번 읽는다"가 깨진다.
        self.assertEqual(CorrelationSnapshotRef.__slots__, ("_snapshot",))

    def test_snapshot_entries_are_read_only(self):
        snapshot = CorrelationSnapshot(1, 0.0, 5.0, MappingProxyType({flow(): FlowScore(
            score=10, sig_hits=1, distinct_paths=1, scan_flag_hits=0,
            matched_stages=(), updated_at=0.0,
        )}))
        with self.assertRaises(TypeError):
            snapshot.entries[flow(81)] = None

    def test_snapshot_entry_is_frozen(self):
        score = FlowScore(10, 1, 1, 0, (), 0.0)
        with self.assertRaises(Exception):
            score.score = 99

    def test_expired_snapshot_returns_none(self):
        key = flow()
        snapshot = CorrelationSnapshot(1, 0.0, 5.0, MappingProxyType({
            key: FlowScore(50, 1, 1, 0, (), 0.0)
        }))
        self.assertIsNotNone(snapshot.lookup(key, 4.9))
        self.assertIsNone(snapshot.lookup(key, 5.0))

    def test_builder_and_snapshot_do_not_share_state(self):
        clock = FakeClock()
        builder = CorrelationBuilder()
        key = flow()
        builder.observe(event(key, clock.now, rule_id="r1", sig_category="path-traversal"), clock.now)
        snapshot = builder.build_snapshot(clock.now)
        before = snapshot.entries[key].sig_hits

        clock.advance(1.0)
        for _ in range(5):
            builder.observe(
                event(key, clock.advance(0.1), rule_id="r1", sig_category="path-traversal"),
                clock.now,
            )
        # 이미 발행한 snapshot 은 builder 갱신의 영향을 받지 않는다.
        self.assertEqual(snapshot.entries[key].sig_hits, before)

    def test_each_publication_gets_a_new_generation(self):
        builder = CorrelationBuilder()
        first = builder.build_snapshot(0.0)
        second = builder.build_snapshot(1.0)
        self.assertEqual(second.generation, first.generation + 1)


class TestBoundedBuilder(unittest.TestCase):
    """§8.1 — TTL, 전체 flow 수, per-key cap."""

    def test_ttl_sweep_removes_idle_flows(self):
        builder = CorrelationBuilder(ttl=120.0)
        builder.observe(event(flow(), 0.0), 0.0)
        self.assertEqual(builder.flow_count, 1)
        self.assertEqual(builder.sweep(60.0), 0)
        self.assertEqual(builder.sweep(200.0), 1)
        self.assertEqual(builder.flow_count, 0)

    def test_max_flows_evicts_least_recently_used(self):
        builder = CorrelationBuilder(max_flows=10)
        for index in range(25):
            builder.observe(event(flow(src_port=1000 + index), 0.0), 0.0)
        self.assertEqual(builder.flow_count, 10)
        self.assertEqual(builder.evicted, 15)

    def test_distinct_paths_are_capped(self):
        builder = CorrelationBuilder()
        key = flow()
        for index in range(PER_KEY_DISTINCT_CAP * 3):
            builder.observe(event(key, float(index), path_digest=f"{index:08x}"), float(index))
        snapshot = builder.build_snapshot(float(PER_KEY_DISTINCT_CAP * 3))
        self.assertLessEqual(snapshot.entries[key].distinct_paths, PER_KEY_DISTINCT_CAP)

    def test_late_event_beyond_ttl_is_dropped(self):
        builder = CorrelationBuilder(ttl=120.0)
        self.assertFalse(builder.observe(event(flow(), 0.0), 500.0))
        self.assertEqual(builder.late_events_dropped, 1)
        self.assertEqual(builder.flow_count, 0)

    def test_duplicate_event_is_ignored(self):
        builder = CorrelationBuilder()
        key = flow()
        duplicate = event(key, 1.0, path_digest="deadbeef")
        self.assertTrue(builder.observe(duplicate, 1.0))
        self.assertFalse(builder.observe(duplicate, 1.0))
        self.assertEqual(builder.duplicates_ignored, 1)

    def test_out_of_order_event_does_not_rewind_last_seen(self):
        builder = CorrelationBuilder()
        key = flow()
        builder.observe(event(key, 10.0, path_digest="a"), 10.0)
        builder.observe(event(key, 5.0, path_digest="b"), 10.0)
        snapshot = builder.build_snapshot(10.0)
        # 카운터에는 반영되지만 시각은 되돌아가지 않는다.
        self.assertEqual(snapshot.entries[key].distinct_paths, 2)
        self.assertEqual(snapshot.entries[key].updated_at, 10.0)

    def test_zero_score_flows_are_not_published(self):
        # snapshot 크기를 의미 있는 flow 로 묶어 hot path lookup 을 제한한다.
        builder = CorrelationBuilder()
        builder.observe(event(flow(), 0.0), 0.0)
        snapshot = builder.build_snapshot(0.0)
        self.assertEqual(len(snapshot.entries), 0)

    def test_memory_stays_bounded_under_sustained_load(self):
        builder = CorrelationBuilder(max_flows=500)
        now = 0.0
        for index in range(5000):
            now += 0.01
            builder.observe(
                event(flow(src_port=1024 + (index % 900)), now, path_digest=f"{index:08x}"),
                now,
            )
        self.assertLessEqual(builder.flow_count, 500)


if __name__ == "__main__":
    unittest.main()
