"""versioned PolicyBundle 로더와 matcher 사전 컴파일 (`PolicyLoader`).

설계 §10.2 DROP rule마다 필요한 기록, §10.4 rule 승격 단계, §15.3 PolicyBundle 검증.

rule과 운영 임계값을 Python 분기문에 하드코딩하지 않는다. 이유는 운영 구조에
있다 — Break는 10분이고 그 안에 사람이 검토·수정·빌드·push를 끝내야 한다(§17).
분기문에 흩어진 임계값은 그 시간 안에 안전하게 리뷰할 수 없다.

로딩 순서는 `active.json` → `fallback.json` → **DROP rule 0개**다. 마지막 단계가
핵심이다. policy를 못 읽는 것은 기동 실패 사유가 아니다. 판정을 못 해도 HEARTBEAT와
`ACCEPT` 경로만 살아 있으면 SLA는 지켜지고 Broker fail-open보다 낫기 때문이다.

**런타임은 어떤 방향으로도 승격 상태를 바꾸지 않는다**(§10.3). 이 모듈에 상태를
변경하는 공개 API가 없는 것은 누락이 아니라 설계다.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import time
from collections.abc import Mapping
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from enum import Enum
from types import MappingProxyType
from typing import Any

from .packet import IPPROTO_TCP, IPPROTO_UDP, PARSER_VERSION

SUPPORTED_SCHEMA_VERSION = 1

ACTIVE_BUNDLE_FILENAME = "active.json"
FALLBACK_BUNDLE_FILENAME = "fallback.json"

# §9.3 — catastrophic backtracking을 유발하는 패턴을 금지하고 각 패턴에 대해 최악
# 입력 실행시간을 측정한다. 아래 상한은 그 측정을 가능한 범위로 묶기 위한 것이다.
MAX_PATTERN_LENGTH = 512
MAX_REPETITION_BOUND = 1000
MAX_RULES_PER_BUNDLE = 512

_APPROVED_REVIEW_VALUES = frozenset({"approved"})

_PROTOCOL_NAMES = {"tcp": IPPROTO_TCP, "udp": IPPROTO_UDP}

# 중첩 수량자 `(...+)*` 는 지수 시간 backtracking의 대표 형태다.
_NESTED_QUANTIFIER = re.compile(r"\([^()]*[+*][^()]*\)\s*[+*{]")
_BACKREFERENCE = re.compile(r"(?<!\\)\\[1-9]")
_CAPTURING_GROUP = re.compile(r"\((?!\?)")
_REPETITION_BOUND = re.compile(r"\{(\d+)(?:,(\d*))?\}")
_ESCAPED_CHAR = re.compile(r"\\.", re.DOTALL)
_CHARACTER_CLASS = re.compile(r"\[[^\]]*\]")


class PolicyValidationError(ValueError):
    """bundle 전체를 사용할 수 없게 만드는 구조 오류."""


class PromotionState(str, Enum):
    SHADOW = "SHADOW"
    CANARY = "CANARY"
    ACTIVE = "ACTIVE"


class MatchKind(str, Enum):
    PAYLOAD_REGEX = "payload_regex"
    TCP_FLAGS = "tcp_flags"
    FLOW_SCORE = "flow_score"
    ALLOW_PROFILE = "allow_profile"


@dataclass(frozen=True, slots=True)
class Rule:
    rule_id: str
    kind: MatchKind
    category: str
    reason_code: str
    protocol: int
    ports: tuple[int, ...]
    promotion_state: PromotionState
    canary_fraction: float
    canary_seed: str
    promotion_cohort: str
    promoted_in_bundle: str
    parser_version: int
    profile_scope: tuple[str, ...]
    evidence_id: str
    positive_fixture_id: str
    negative_fixture_id: str
    sla_fixture_id: str
    expires_at: str
    expires_epoch: float
    rollback_condition: str
    owner_review: str
    lead_review: str
    pattern_source: str = ""
    ignore_case: bool = False
    tcp_flags_name: str = ""
    min_score: int = 0

    @property
    def enforces_drop(self) -> bool:
        """이 rule이 실제로 패킷을 막을 수 있는가.

        `SHADOW`는 로그만 남긴다. `CANARY`는 flow별 결정론적 bucket에 든 경우에만
        막으므로 여기서는 "막을 수 있음"으로 센다.
        """
        return self.promotion_state in (PromotionState.CANARY, PromotionState.ACTIVE)


@dataclass(frozen=True, slots=True)
class AlertProfile:
    """alert-only anomaly monitor의 임계와 runbook(§10.3).

    이 값들은 경보 발생 조건일 뿐이며 어떤 경우에도 verdict나 승격 상태를
    바꾸지 않는다.
    """

    profile_id: str
    minimum_samples: int
    sustain_window_seconds: float
    alert_thresholds: Mapping[str, float]
    reviewer_runbook: str


@dataclass(frozen=True)
class CompiledMatcher:
    """한 scope의 모든 정규식을 합친 단일 패턴(§9.3).

    정규식 수십 개를 패킷마다 순차 실행하면 §5.2의 `Sig` 100μs 예산을 지킬 수
    없다. 각 rule을 이름 있는 그룹으로 감싸 하나로 합치면 한 번의 `search`로
    "매치 여부"와 "어느 rule인지"를 동시에 얻는다. 그룹 이름으로 rule을 되찾기
    위해 rule 패턴 자체에는 capturing group을 금지한다.
    """

    pattern: re.Pattern
    rules_by_group: Mapping[str, Rule]


@dataclass(frozen=True)
class CompiledPolicy:
    bundle_id: str
    schema_version: int
    payload_matchers: Mapping[tuple[int, int], CompiledMatcher]
    wildcard_matchers: Mapping[int, CompiledMatcher]
    flag_rules: tuple[Rule, ...]
    score_rules: tuple[Rule, ...]
    allow_rules: tuple[Rule, ...]
    alert_profiles: Mapping[str, AlertProfile]
    rules_by_id: Mapping[str, Rule]
    baseline_profiles: frozenset[str] = frozenset()

    @property
    def drop_capable_rule_count(self) -> int:
        return sum(1 for rule in self.rules_by_id.values() if rule.enforces_drop)


@dataclass(frozen=True)
class PolicyLoadReport:
    """어떤 bundle이 왜 선택됐는지. 비민감 reason code로만 구성한다(§10.2)."""

    source: str
    bundle_id: str
    rule_count: int
    drop_capable_rules: int
    errors: tuple[str, ...] = ()
    demotions: tuple[str, ...] = ()


EMPTY_POLICY = CompiledPolicy(
    bundle_id="empty",
    schema_version=SUPPORTED_SCHEMA_VERSION,
    payload_matchers=MappingProxyType({}),
    wildcard_matchers=MappingProxyType({}),
    flag_rules=(),
    score_rules=(),
    allow_rules=(),
    alert_profiles=MappingProxyType({}),
    rules_by_id=MappingProxyType({}),
)


def canary_selected(rule: Rule, flow_material: bytes) -> bool:
    """`hashlib.blake2s(seed + rule_id + FlowKey)` 결정론적 bucket(§6.4, §10.4).

    packet마다 난수를 다시 뽑지 않는다. 같은 `rule_id`와 같은 `FlowKey`는 Round
    안에서 항상 같은 판정을 받아야 재현성과 장애 분석이 가능하고, SLA 손실 분포도
    불필요하게 넓어지지 않는다. Python의 `hash()`는 프로세스마다 seed가 달라
    재시작 시 bucket이 바뀌므로 쓰지 않는다.
    """
    if rule.canary_fraction <= 0.0:
        return False
    if rule.canary_fraction >= 1.0:
        return True
    digest = hashlib.blake2s(
        rule.canary_seed.encode("utf-8") + b"|" + rule.rule_id.encode("utf-8") + b"|" + flow_material,
        digest_size=8,
    ).digest()
    bucket = int.from_bytes(digest, "big") / float(1 << 64)
    return bucket < rule.canary_fraction


def _require(mapping: Mapping[str, Any], key: str, context: str) -> Any:
    if key not in mapping:
        raise PolicyValidationError(f"{context}: 필수 field 누락 {key!r}")
    return mapping[key]


def _parse_expiry(raw: str, context: str) -> float:
    """ISO-8601 만료 시각을 epoch 초로.

    여기서만 벽시계를 쓴다. 만료는 달력 값이고 §5.2의 monotonic 규칙은 지연
    예산에 적용되는 것이지 날짜 비교에 적용되는 것이 아니기 때문이다.
    """
    text = str(raw).strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError as exc:
        raise PolicyValidationError(f"{context}: expires_at 파싱 실패 {raw!r}") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.timestamp()


def _structural_view(pattern: str) -> str:
    """구조 검사용으로 이스케이프와 문자 클래스를 제거한 사본.

    `sleep\\(` 의 괄호는 리터럴이고 `[fF]` 안의 문자는 구조가 아니다. 이것을
    걸러내지 않으면 정상적인 패턴이 capturing group으로 오인된다.
    """
    without_escapes = _ESCAPED_CHAR.sub("", pattern)
    return _CHARACTER_CLASS.sub("", without_escapes)


def validate_pattern(pattern: str, context: str) -> None:
    """정규식 크기와 금지 패턴 검사(§15.3)."""
    if not pattern:
        raise PolicyValidationError(f"{context}: 빈 정규식")
    if len(pattern) > MAX_PATTERN_LENGTH:
        raise PolicyValidationError(
            f"{context}: 정규식 길이 {len(pattern)} > 상한 {MAX_PATTERN_LENGTH}"
        )
    if _BACKREFERENCE.search(pattern):
        raise PolicyValidationError(f"{context}: 역참조는 금지된다")

    structural = _structural_view(pattern)
    if _CAPTURING_GROUP.search(structural):
        raise PolicyValidationError(f"{context}: capturing group 대신 (?:...) 를 쓴다")
    if _NESTED_QUANTIFIER.search(structural):
        raise PolicyValidationError(f"{context}: 중첩 수량자는 backtracking 폭발을 유발한다")
    for lower, upper in _REPETITION_BOUND.findall(structural):
        bound = int(upper) if upper else int(lower)
        if bound > MAX_REPETITION_BOUND:
            raise PolicyValidationError(
                f"{context}: 반복 상한 {bound} > {MAX_REPETITION_BOUND}"
            )


def _parse_rule(raw: Mapping[str, Any], index: int) -> tuple[Rule, str | None]:
    """rule 하나를 검증한다. (rule, 강등사유) 를 돌려준다."""
    context = f"rules[{index}]"
    rule_id = str(_require(raw, "rule_id", context)).strip()
    if not rule_id:
        raise PolicyValidationError(f"{context}: 빈 rule_id")
    context = f"rule {rule_id!r}"

    try:
        kind = MatchKind(str(_require(raw, "kind", context)))
    except ValueError as exc:
        raise PolicyValidationError(f"{context}: 알 수 없는 kind {raw.get('kind')!r}") from exc

    try:
        promotion_state = PromotionState(str(_require(raw, "promotion_state", context)))
    except ValueError as exc:
        raise PolicyValidationError(
            f"{context}: 알 수 없는 promotion_state {raw.get('promotion_state')!r}"
        ) from exc

    parser_version = int(raw.get("parser_version", PARSER_VERSION))
    if parser_version > PARSER_VERSION:
        raise PolicyValidationError(
            f"{context}: parser_version {parser_version} 이 런타임 {PARSER_VERSION} 보다 높다"
        )

    protocol_name = str(raw.get("protocol", "tcp")).lower()
    if protocol_name not in _PROTOCOL_NAMES:
        raise PolicyValidationError(f"{context}: 알 수 없는 protocol {protocol_name!r}")
    protocol = _PROTOCOL_NAMES[protocol_name]

    ports_raw = raw.get("ports", [])
    if not isinstance(ports_raw, list):
        raise PolicyValidationError(f"{context}: ports 는 배열이어야 한다")
    ports: list[int] = []
    for port in ports_raw:
        value = int(port)
        if not (1 <= value <= 65535):
            raise PolicyValidationError(f"{context}: 포트 범위 밖 {value}")
        if value not in ports:
            ports.append(value)

    canary_fraction = float(raw.get("canary_fraction", 0.0))
    if not (0.0 <= canary_fraction <= 1.0):
        raise PolicyValidationError(f"{context}: canary_fraction 범위 밖 {canary_fraction}")
    canary_seed = str(raw.get("canary_seed", ""))
    if promotion_state is PromotionState.CANARY:
        if canary_fraction <= 0.0:
            raise PolicyValidationError(f"{context}: CANARY 인데 canary_fraction 이 0 이다")
        if not canary_seed:
            raise PolicyValidationError(f"{context}: CANARY 인데 canary_seed 가 없다")

    promotion_cohort = str(_require(raw, "promotion_cohort", context)).strip()
    if not promotion_cohort:
        raise PolicyValidationError(f"{context}: 빈 promotion_cohort")

    expires_at = str(_require(raw, "expires_at", context))
    expires_epoch = _parse_expiry(expires_at, context)

    pattern_source = ""
    ignore_case = bool(raw.get("ignore_case", False))
    tcp_flags_name = ""
    min_score = 0

    if kind is MatchKind.PAYLOAD_REGEX:
        pattern_source = str(_require(raw, "pattern", context))
        validate_pattern(pattern_source, context)
    elif kind is MatchKind.TCP_FLAGS:
        tcp_flags_name = str(_require(raw, "tcp_flags_name", context))
        if protocol != IPPROTO_TCP:
            raise PolicyValidationError(f"{context}: tcp_flags rule 의 protocol 이 tcp 가 아니다")
    elif kind is MatchKind.FLOW_SCORE:
        min_score = int(_require(raw, "min_score", context))
        if min_score <= 0:
            raise PolicyValidationError(f"{context}: min_score 는 양수여야 한다")

    reason_code = str(raw.get("reason_code", "") or f"rule-{rule_id}")
    for review_key in ("owner_review", "lead_review"):
        _require(raw, review_key, context)
    for evidence_key in (
        "evidence_id", "positive_fixture_id", "negative_fixture_id", "sla_fixture_id",
        "rollback_condition",
    ):
        _require(raw, evidence_key, context)

    rule = Rule(
        rule_id=rule_id,
        kind=kind,
        category=str(raw.get("category", "uncategorized")),
        reason_code=reason_code,
        protocol=protocol,
        ports=tuple(ports),
        promotion_state=promotion_state,
        canary_fraction=canary_fraction,
        canary_seed=canary_seed,
        promotion_cohort=promotion_cohort,
        promoted_in_bundle=str(raw.get("promoted_in_bundle", "")),
        parser_version=parser_version,
        profile_scope=tuple(str(item) for item in raw.get("profile_scope", ())),
        evidence_id=str(raw["evidence_id"]),
        positive_fixture_id=str(raw["positive_fixture_id"]),
        negative_fixture_id=str(raw["negative_fixture_id"]),
        sla_fixture_id=str(raw["sla_fixture_id"]),
        expires_at=expires_at,
        expires_epoch=expires_epoch,
        rollback_condition=str(raw["rollback_condition"]),
        owner_review=str(raw["owner_review"]),
        lead_review=str(raw["lead_review"]),
        pattern_source=pattern_source,
        ignore_case=ignore_case,
        tcp_flags_name=tcp_flags_name,
        min_score=min_score,
    )
    return rule, None


def _demote(rule: Rule) -> Rule:
    """차단 권한을 제거하고 `SHADOW`로 내린다."""
    return replace(rule, promotion_state=PromotionState.SHADOW, canary_fraction=0.0)


def _demotion_reason(rule: Rule, now: float, baseline_profiles: frozenset[str]) -> str | None:
    """차단 권한을 가진 rule을 기동 시 강등해야 하는 이유. 없으면 `None`.

    구조 오류와 달리 이 셋은 bundle 전체를 거부하지 않는다. `SHADOW`로 내리면
    정상 트래픽에 무해해지므로, 나머지 검증된 rule까지 함께 버리는 것보다
    강등이 낫기 때문이다.
    """
    if rule.expires_epoch <= now:
        return "expired"
    if not (
        rule.owner_review in _APPROVED_REVIEW_VALUES
        and rule.lead_review in _APPROVED_REVIEW_VALUES
    ):
        # §10.2 — 두 review 가 모두 승인이 아니면 기동 시 SHADOW 로 강등한다.
        return "review-not-approved"
    if not baseline_profiles:
        # §15.6 마지막 항목 — 정상 profile 이 비어 있으면 DROP rule 을 활성화하지
        # 않는다. 무엇이 정상인지 모르는 상태의 차단은 오탐 여부조차 판정할 수
        # 없고, `FinalsPhase 1` 초반과 새 레이어 첫 Round 가 정확히 그 상태다(§16.2).
        return "no-baseline-profile"
    return None


def compile_bundle(document: Mapping[str, Any], now_epoch: float | None = None) -> tuple[CompiledPolicy, tuple[str, ...]]:
    """검증된 JSON 문서를 실행 가능한 policy로 컴파일한다.

    구조 오류는 `PolicyValidationError`로 bundle 전체를 거부한다. 반면 만료와
    review 미승인은 §10.2에 따라 **강등**으로 처리한다. 두 처리를 나누는 기준은
    "그 rule을 안전하게 무력화할 수 있는가"다. 만료된 rule은 `SHADOW`로 내리면
    정상 트래픽에 무해하지만, 중복 `rule_id`나 깨진 정규식은 bundle 전체의
    해석을 신뢰할 수 없게 만든다.
    """
    now = time.time() if now_epoch is None else now_epoch

    schema_version = int(_require(document, "schema_version", "bundle"))
    if schema_version != SUPPORTED_SCHEMA_VERSION:
        raise PolicyValidationError(
            f"지원하지 않는 schema_version {schema_version} (지원: {SUPPORTED_SCHEMA_VERSION})"
        )
    bundle_id = str(_require(document, "bundle_id", "bundle")).strip()
    if not bundle_id:
        raise PolicyValidationError("bundle: 빈 bundle_id")

    raw_rules = document.get("rules", [])
    if not isinstance(raw_rules, list):
        raise PolicyValidationError("bundle: rules 는 배열이어야 한다")
    if len(raw_rules) > MAX_RULES_PER_BUNDLE:
        raise PolicyValidationError(f"bundle: rule 수 {len(raw_rules)} > {MAX_RULES_PER_BUNDLE}")

    raw_baselines = document.get("baseline_profiles", []) or []
    if not isinstance(raw_baselines, list):
        raise PolicyValidationError("bundle: baseline_profiles 는 배열이어야 한다")
    baseline_profiles = frozenset(str(item) for item in raw_baselines)

    demotions: list[str] = []
    rules: list[Rule] = []
    seen_ids: set[str] = set()
    cohort_bundles: dict[str, str] = {}

    for index, raw_rule in enumerate(raw_rules):
        if not isinstance(raw_rule, Mapping):
            raise PolicyValidationError(f"rules[{index}]: 객체가 아니다")
        rule, _ = _parse_rule(raw_rule, index)
        if rule.rule_id in seen_ids:
            raise PolicyValidationError(f"중복 rule_id: {rule.rule_id!r}")
        seen_ids.add(rule.rule_id)

        previous = cohort_bundles.setdefault(rule.promotion_cohort, rule.promoted_in_bundle)
        if previous != rule.promoted_in_bundle:
            raise PolicyValidationError(
                f"promotion_cohort {rule.promotion_cohort!r} 의 promoted_in_bundle 이 모순된다"
            )

        if rule.promotion_state is not PromotionState.SHADOW:
            reason = _demotion_reason(rule, now, baseline_profiles)
            if reason is not None:
                demotions.append(f"{rule.rule_id}:{reason}")
                rule = _demote(rule)

        rules.append(rule)

    payload_buckets: dict[tuple[int, int], list[Rule]] = {}
    wildcard_buckets: dict[int, list[Rule]] = {}
    flag_rules: list[Rule] = []
    score_rules: list[Rule] = []
    allow_rules: list[Rule] = []

    for rule in rules:
        if rule.kind is MatchKind.PAYLOAD_REGEX:
            if rule.ports:
                for port in rule.ports:
                    payload_buckets.setdefault((rule.protocol, port), []).append(rule)
            else:
                wildcard_buckets.setdefault(rule.protocol, []).append(rule)
        elif rule.kind is MatchKind.TCP_FLAGS:
            flag_rules.append(rule)
        elif rule.kind is MatchKind.FLOW_SCORE:
            score_rules.append(rule)
        else:
            allow_rules.append(rule)

    payload_matchers = {
        key: _compile_matcher(bucket) for key, bucket in payload_buckets.items()
    }
    wildcard_matchers = {
        key: _compile_matcher(bucket) for key, bucket in wildcard_buckets.items()
    }

    alert_profiles: dict[str, AlertProfile] = {}
    for index, raw_profile in enumerate(document.get("alert_profiles", []) or []):
        if not isinstance(raw_profile, Mapping):
            raise PolicyValidationError(f"alert_profiles[{index}]: 객체가 아니다")
        profile_id = str(_require(raw_profile, "profile_id", f"alert_profiles[{index}]"))
        thresholds = raw_profile.get("alert_thresholds", {})
        if not isinstance(thresholds, Mapping):
            raise PolicyValidationError(f"alert_profiles[{index}]: alert_thresholds 는 객체여야 한다")
        alert_profiles[profile_id] = AlertProfile(
            profile_id=profile_id,
            minimum_samples=int(raw_profile.get("minimum_samples", 0)),
            sustain_window_seconds=float(raw_profile.get("sustain_window", 0.0)),
            alert_thresholds=MappingProxyType({str(k): float(v) for k, v in thresholds.items()}),
            reviewer_runbook=str(raw_profile.get("reviewer_runbook", "")),
        )

    compiled = CompiledPolicy(
        bundle_id=bundle_id,
        schema_version=schema_version,
        payload_matchers=MappingProxyType(payload_matchers),
        wildcard_matchers=MappingProxyType(wildcard_matchers),
        flag_rules=tuple(flag_rules),
        score_rules=tuple(score_rules),
        allow_rules=tuple(allow_rules),
        alert_profiles=MappingProxyType(alert_profiles),
        rules_by_id=MappingProxyType({rule.rule_id: rule for rule in rules}),
        baseline_profiles=baseline_profiles,
    )
    return compiled, tuple(demotions)


def _compile_matcher(bucket: list[Rule]) -> CompiledMatcher:
    """한 scope의 rule들을 이름 있는 그룹 하나로 합쳐 컴파일한다."""
    fragments: list[str] = []
    rules_by_group: dict[str, Rule] = {}
    ignore_case = False
    for index, rule in enumerate(bucket):
        group = f"r{index}"
        rules_by_group[group] = rule
        fragments.append(f"(?P<{group}>{rule.pattern_source})")
        ignore_case = ignore_case or rule.ignore_case

    flags = re.IGNORECASE if ignore_case else 0
    try:
        pattern = re.compile("|".join(fragments).encode("latin-1"), flags)
    except re.error as exc:
        raise PolicyValidationError(f"정규식 컴파일 실패: {exc}") from exc
    return CompiledMatcher(pattern=pattern, rules_by_group=MappingProxyType(rules_by_group))


def load_bundle_file(path: str, now_epoch: float | None = None) -> tuple[CompiledPolicy, tuple[str, ...]]:
    with open(path, "r", encoding="utf-8") as handle:
        document = json.load(handle)
    if not isinstance(document, Mapping):
        raise PolicyValidationError(f"{path}: 최상위가 객체가 아니다")
    return compile_bundle(document, now_epoch=now_epoch)


def load_policy(
    policy_dir: str, now_epoch: float | None = None
) -> tuple[CompiledPolicy, PolicyLoadReport]:
    """`active.json` → `fallback.json` → DROP rule 0개 순으로 시도한다(§10.2).

    어떤 단계에서 실패했는지는 비민감 reason code로 남긴다. 세 번째 단계에서도
    프로세스를 종료하지 않는 것이 핵심이다 — 판정을 포기해도 HEARTBEAT와
    `ACCEPT` 경로가 살아 있어야 Broker fail-open보다 낫다.
    """
    errors: list[str] = []
    for source, filename in (("active", ACTIVE_BUNDLE_FILENAME), ("fallback", FALLBACK_BUNDLE_FILENAME)):
        path = os.path.join(policy_dir, filename)
        if not os.path.isfile(path):
            errors.append(f"{source}:missing")
            continue
        try:
            compiled, demotions = load_bundle_file(path, now_epoch=now_epoch)
        except (PolicyValidationError, json.JSONDecodeError, OSError, ValueError, TypeError) as exc:
            errors.append(f"{source}:invalid:{type(exc).__name__}")
            continue
        return compiled, PolicyLoadReport(
            source=source,
            bundle_id=compiled.bundle_id,
            rule_count=len(compiled.rules_by_id),
            drop_capable_rules=compiled.drop_capable_rule_count,
            errors=tuple(errors),
            demotions=demotions,
        )

    return EMPTY_POLICY, PolicyLoadReport(
        source="empty",
        bundle_id=EMPTY_POLICY.bundle_id,
        rule_count=0,
        drop_capable_rules=0,
        errors=tuple(errors),
        demotions=(),
    )
