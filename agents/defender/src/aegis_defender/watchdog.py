"""Bounded worker liveness monitor and restart coordinator.

The watchdog never parses packets or changes policy. It only detects an unexpectedly
dead helper thread, starts the same bounded worker again, and asks the Broker session
to reconnect when the failed worker is critical to VERDICT or HEARTBEAT delivery.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass
from typing import Callable

from .logging import AuditLogger
from .metrics import (
    M_WORKER_RESTART_FAILED,
    M_WORKER_RESTARTED,
    M_WORKER_UNHEALTHY,
    Metrics,
)

WATCHDOG_INTERVAL_SECONDS = 0.5


@dataclass(frozen=True, slots=True)
class WorkerProbe:
    name: str
    is_alive: Callable[[], bool]
    start: Callable[[], None]
    critical: bool = False
    expected: Callable[[], bool] = lambda: True


class WorkerWatchdog:
    """Restart dead helper workers without entering the packet hot path."""

    def __init__(
        self,
        probes: tuple[WorkerProbe, ...],
        metrics: Metrics | None = None,
        audit: AuditLogger | None = None,
        runtime_stop: threading.Event | None = None,
        on_critical_restart: Callable[[str], None] | None = None,
        interval: float = WATCHDOG_INTERVAL_SECONDS,
    ) -> None:
        self._probes = probes
        self._metrics = metrics
        self._audit = audit
        self._runtime_stop = runtime_stop or threading.Event()
        self._on_critical_restart = on_critical_restart
        self._interval = max(0.05, float(interval))
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._reported: set[str] = set()

    def is_alive(self) -> bool:
        thread = self._thread
        return thread is not None and thread.is_alive()

    def start(self) -> None:
        if self.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(
            target=self.run, name="worker-watchdog", daemon=True
        )
        self._thread.start()

    def stop(self, timeout: float = 2.0) -> None:
        self._stop.set()
        thread = self._thread
        self._thread = None
        if thread is not None:
            thread.join(timeout=timeout)

    def run(self) -> None:
        while not self._runtime_stop.is_set() and not self._stop.wait(self._interval):
            try:
                self.check_once()
            except Exception:  # noqa: BLE001 - watchdog itself must stay alive
                continue

    def check_once(self) -> tuple[str, ...]:
        """Check all probes once and return successfully restarted worker names."""
        if self._runtime_stop.is_set():
            return ()
        restarted: list[str] = []
        for probe in self._probes:
            try:
                expected = probe.expected()
                alive = probe.is_alive() if expected else True
            except Exception:  # noqa: BLE001 - a broken probe is unhealthy
                expected = True
                alive = False
            if not expected:
                self._reported.discard(probe.name)
                continue
            if alive:
                if probe.name in self._reported:
                    self._reported.discard(probe.name)
                    self._log("worker-recovered", worker=probe.name)
                continue

            first_report = probe.name not in self._reported
            self._reported.add(probe.name)
            if first_report:
                self._count(M_WORKER_UNHEALTHY)
                self._log("worker-unhealthy", worker=probe.name, critical=probe.critical)

            try:
                probe.start()
                recovered = probe.is_alive()
            except Exception as exc:  # noqa: BLE001 - retry next bounded tick
                recovered = False
                failure = type(exc).__name__
            else:
                failure = "not-alive-after-start"

            if not recovered:
                self._count(M_WORKER_RESTART_FAILED)
                if first_report:
                    self._log(
                        "worker-restart-failed", worker=probe.name, reason=failure
                    )
                continue

            self._reported.discard(probe.name)
            restarted.append(probe.name)
            self._count(M_WORKER_RESTARTED)
            self._log("worker-restarted", worker=probe.name, critical=probe.critical)
            if probe.critical and self._on_critical_restart is not None:
                try:
                    self._on_critical_restart(probe.name)
                except Exception as exc:  # noqa: BLE001 - worker remains recovered
                    self._log(
                        "worker-reconnect-signal-failed",
                        worker=probe.name,
                        reason=type(exc).__name__,
                    )
        return tuple(restarted)

    def _count(self, name: str) -> None:
        if self._metrics is not None:
            self._metrics.incr(name)

    def _log(self, event: str, **fields: object) -> None:
        if self._audit is not None:
            self._audit.log(event, **fields)
