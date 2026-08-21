"""alert-only anomaly monitor (`AnomalyMonitor`).

설계 §10.3 ③, §15.6 packet-derived anomaly 조작 저항 검증.

**이 모듈은 어떤 경우에도 runtime policy state를 바꾸지 않는다.** 그것이 이
모듈의 존재 이유이자 유일한 계약이다.

이유는 입력 경계에 있다. Broker가 주는 것은 `raw_ip`뿐이고, organizer가 보증한
SLA checker 식별자도, application 성공 결과도, 정상-health 신호도 없다(§10.3).
따라서 여기서 계산하는 모든 값은 **공격자가 오염할 수 있는 관측값**이지 실제
SLA의 ground truth가 아니다.

    raw_drop_rate              활성 signature를 반복 자극하면 올릴 수 있다
    baseline_violation_rate    정상 형태 replay와 profile 경계 탐색으로 올릴 수 있다
    parser_failure_rate        malformed 입력을 쏟으면 올릴 수 있다
    rule_concentration         특정 rule만 반복 자극하면 올릴 수 있다
    promotion_cohort_conflict  baseline 자체가 packet-derived다

이 값들로 런타임이 rule을 자동 rollback하거나 전체 관찰 모드로 전환하면, 공격자는
패킷만 보내서 우리 방어를 끄게 만들 수 있다. 그래서 Round 중 허용되는 동작은
**카운터 갱신, 구조화 로그, alert 발행뿐**이다. 상태 변경은 Break에서 사람이
공식 SLA 결과와 fixture를 대조하고 팀장이 승인한 새 bundle로만 일어난다.

구조적으로도 이를 강제한다 — 이 클래스는 `CompiledPolicy`를 참조하지 않는다.
바꿀 대상을 손에 쥐고 있지 않으면 실수로도 바꿀 수 없다.
"""

from __future__ import annotations

import time
from collections.abc import Mapping
from dataclasses import dataclass

from .logging import AuditLogger
from .metrics import M_ANOMALY_ALERT, Metrics
from .rules import AlertProfile

METRIC_RAW_DROP_RATE = "raw_drop_rate"
METRIC_BASELINE_VIOLATION_RATE = "baseline_violation_rate"
METRIC_PARSER_FAILURE_RATE = "parser_failure_rate"
METRIC_RULE_CONCENTRATION = "rule_concentration"
METRIC_PROMOTION_COHORT_CONFLICT = "promotion_cohort_conflict"

ANOMALY_METRICS = (
    METRIC_RAW_DROP_RATE,
    METRIC_BASELINE_VIOLATION_RATE,
    METRIC_PARSER_FAILURE_RATE,
    METRIC_RULE_CONCENTRATION,
    METRIC_PROMOTION_COHORT_CONFLICT,
)

MAX_TRACKED_RULES = 128
MAX_SUMMARY_RULES = 10


@dataclass(frozen=True, slots=True)
class Alert:
    """경보 하나. Break에서 사람이 읽는 자료이지 런타임 명령이 아니다."""

    profile_id: str
    metric: str
    value: float
    threshold: float
    samples: int
    sustained_seconds: float
    runbook: str


class AnomalyMonitor:
    def __init__(
        self,
        alert_profiles: Mapping[str, AlertProfile] | None = None,
        metrics: Metrics | None = None,
        audit: AuditLogger | None = None,
        clock=time.monotonic,
    ) -> None:
        self._profiles = dict(alert_profiles or {})
        self._metrics = metrics
        self._audit = audit
        self._clock = clock

        self.total = 0
        self.drops = 0
        self.parser_failures = 0
        self.baseline_total = 0
        self.baseline_drops = 0
        self.cohort_conflicts = 0
        self._rule_drops: dict[str, int] = {}
        self._rule_shadows: dict[str, int] = {}
        self._first_exceeded: dict[tuple[str, str], float] = {}

    def record(
        self,
        *,
        dropped: bool = False,
        parser_failed: bool = False,
        baseline_match: bool = False,
        rule_id: str = "",
        cohort_conflict: bool = False,
        shadow_hit: bool = False,
    ) -> None:
        """패킷 하나의 관측 사실을 집계한다. 정수 증가 외에 하는 일이 없다."""
        self.total += 1
        if parser_failed:
            self.parser_failures += 1
        if baseline_match:
            self.baseline_total += 1
        if dropped:
            self.drops += 1
            if baseline_match:
                self.baseline_drops += 1
            if rule_id:
                if rule_id in self._rule_drops or len(self._rule_drops) < MAX_TRACKED_RULES:
                    self._rule_drops[rule_id] = self._rule_drops.get(rule_id, 0) + 1
            if cohort_conflict:
                self.cohort_conflicts += 1
        if shadow_hit and rule_id:
            if rule_id in self._rule_shadows or len(self._rule_shadows) < MAX_TRACKED_RULES:
                self._rule_shadows[rule_id] = self._rule_shadows.get(rule_id, 0) + 1

    def rule_summary(self, limit: int = MAX_SUMMARY_RULES) -> dict[str, list[dict[str, object]]]:
        """Break용 rule별 비민감 집계. payload나 flow 식별자는 포함하지 않는다."""
        size = max(0, min(MAX_SUMMARY_RULES, int(limit)))

        def ranked(values: dict[str, int]) -> list[dict[str, object]]:
            return [
                {"rule_id": rule_id, "count": count}
                for rule_id, count in sorted(
                    values.items(), key=lambda item: (-item[1], item[0])
                )[:size]
            ]

        return {"drops": ranked(self._rule_drops), "shadow_hits": ranked(self._rule_shadows)}

    def values(self) -> dict[str, float]:
        """현재 지표값. 표본이 없으면 0.0."""
        total = float(self.total)
        baseline = float(self.baseline_total)
        drops = float(self.drops)
        concentration = 0.0
        if self.drops > 0 and self._rule_drops:
            concentration = max(self._rule_drops.values()) / drops
        return {
            METRIC_RAW_DROP_RATE: (drops / total) if total else 0.0,
            METRIC_BASELINE_VIOLATION_RATE: (self.baseline_drops / baseline) if baseline else 0.0,
            METRIC_PARSER_FAILURE_RATE: (self.parser_failures / total) if total else 0.0,
            METRIC_RULE_CONCENTRATION: concentration,
            METRIC_PROMOTION_COHORT_CONFLICT: (self.cohort_conflicts / baseline) if baseline else 0.0,
        }

    def evaluate(self, now: float | None = None) -> tuple[Alert, ...]:
        """임계를 넘고 최소 표본과 지속 시간을 충족한 경보를 돌려준다.

        **부작용은 로그와 카운터뿐이다.** 반환값을 policy에 반영하는 코드는
        이 저장소 어디에도 없어야 하며, `test_anomaly.py`가 그것을 회귀 검증한다.
        """
        moment = self._clock() if now is None else now
        current = self.values()
        alerts: list[Alert] = []

        for profile in self._profiles.values():
            if self.total < profile.minimum_samples:
                continue
            for metric, threshold in profile.alert_thresholds.items():
                value = current.get(metric)
                if value is None:
                    continue
                key = (profile.profile_id, metric)
                if value < threshold:
                    self._first_exceeded.pop(key, None)
                    continue
                started = self._first_exceeded.setdefault(key, moment)
                sustained = moment - started
                if sustained < profile.sustain_window_seconds:
                    continue
                alert = Alert(
                    profile_id=profile.profile_id,
                    metric=metric,
                    value=round(value, 4),
                    threshold=threshold,
                    samples=self.total,
                    sustained_seconds=round(sustained, 3),
                    runbook=profile.reviewer_runbook,
                )
                alerts.append(alert)
                if self._metrics is not None:
                    self._metrics.incr(M_ANOMALY_ALERT)
                if self._audit is not None:
                    self._audit.log(
                        "anomaly-alert",
                        profile=alert.profile_id,
                        metric=alert.metric,
                        value=alert.value,
                        threshold=alert.threshold,
                        samples=alert.samples,
                        sustained_seconds=alert.sustained_seconds,
                        action="alert-only-no-policy-change",
                    )

        return tuple(alerts)
