import io
import json
import threading
import unittest

from aegis_defender.logging import AuditLogger
from aegis_defender.metrics import (
    M_WORKER_RESTART_FAILED,
    M_WORKER_RESTARTED,
    M_WORKER_UNHEALTHY,
    Metrics,
)
from aegis_defender.watchdog import WorkerProbe, WorkerWatchdog


class FakeWorker:
    def __init__(self, recover=True):
        self.alive = False
        self.recover = recover
        self.starts = 0

    def is_alive(self):
        return self.alive

    def start(self):
        self.starts += 1
        if self.recover:
            self.alive = True


class TestWorkerWatchdog(unittest.TestCase):
    def test_restarts_critical_worker_and_requests_fresh_session(self):
        worker = FakeWorker()
        metrics = Metrics()
        stream = io.StringIO()
        reconnects = []
        watchdog = WorkerWatchdog(
            (WorkerProbe("socket-writer", worker.is_alive, worker.start, critical=True),),
            metrics=metrics,
            audit=AuditLogger(stream=stream),
            on_critical_restart=reconnects.append,
        )

        self.assertEqual(watchdog.check_once(), ("socket-writer",))
        self.assertEqual(worker.starts, 1)
        self.assertEqual(reconnects, ["socket-writer"])
        self.assertEqual(metrics.counter(M_WORKER_UNHEALTHY), 1)
        self.assertEqual(metrics.counter(M_WORKER_RESTARTED), 1)
        events = [json.loads(line)["event"] for line in stream.getvalue().splitlines()]
        self.assertEqual(events, ["worker-unhealthy", "worker-restarted"])

    def test_disabled_optional_worker_is_not_started(self):
        worker = FakeWorker()
        watchdog = WorkerWatchdog(
            (
                WorkerProbe(
                    "advisory",
                    worker.is_alive,
                    worker.start,
                    expected=lambda: False,
                ),
            )
        )
        self.assertEqual(watchdog.check_once(), ())
        self.assertEqual(worker.starts, 0)

    def test_failed_restart_is_counted_without_log_flood(self):
        worker = FakeWorker(recover=False)
        metrics = Metrics()
        stream = io.StringIO()
        watchdog = WorkerWatchdog(
            (WorkerProbe("heartbeat", worker.is_alive, worker.start, critical=True),),
            metrics=metrics,
            audit=AuditLogger(stream=stream),
        )
        watchdog.check_once()
        watchdog.check_once()

        self.assertEqual(metrics.counter(M_WORKER_UNHEALTHY), 1)
        self.assertEqual(metrics.counter(M_WORKER_RESTART_FAILED), 2)
        events = [json.loads(line)["event"] for line in stream.getvalue().splitlines()]
        self.assertEqual(events.count("worker-unhealthy"), 1)
        self.assertEqual(events.count("worker-restart-failed"), 1)

    def test_watchdog_thread_stops_promptly(self):
        watchdog = WorkerWatchdog((), interval=0.05)
        watchdog.start()
        self.assertTrue(watchdog.is_alive())
        watchdog.stop(1.0)
        self.assertFalse(watchdog.is_alive())
        self.assertNotIn("worker-watchdog", {thread.name for thread in threading.enumerate()})

    def test_runtime_stop_prevents_restart(self):
        worker = FakeWorker()
        runtime_stop = threading.Event()
        runtime_stop.set()
        watchdog = WorkerWatchdog(
            (WorkerProbe("heartbeat", worker.is_alive, worker.start, critical=True),),
            runtime_stop=runtime_stop,
        )
        self.assertEqual(watchdog.check_once(), ())
        self.assertEqual(worker.starts, 0)


if __name__ == "__main__":
    unittest.main()
