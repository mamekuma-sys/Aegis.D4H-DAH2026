"""공격 런타임의 상태·데이터 모델.

설계 §9.6. 코드는 타입의 필드와 불변조건만 정의하고, 네트워크 실행·계획 판단·제출
상태를 한 타입이 동시에 소유하지 않도록 분리한다. 본문·응답·flag 원문을 장기 식별자로
쓰지 않고 비민감 fingerprint 또는 단방향 해시를 사용한다(운영세칙 제23·24조).
"""

from __future__ import annotations

import enum
import threading
from dataclasses import dataclass, field
from typing import Optional

MIN_PORT = 1
MAX_PORT = 65535


class Scenario(enum.Enum):
    """예선 S1~S5 가설. 본선 취약점 목록이 아니라 정찰 우선순위 가설이다(§9.8)."""

    S1 = "S1"  # 인증/세션 경계 (예선 GCS 계정 탈취)
    S2 = "S2"  # 파라미터/설정 변조
    S3 = "S3"  # 입력 반영/상태 은폐
    S4 = "S4"  # 다단계 체인 (S4ChainStage 1~5)
    S5 = "S5"  # 방어 AI 입력 경계 (조건부)


class VulnClass(enum.Enum):
    """관측된 서비스에 대한 공격 부류. 데모/도메인 예시일 뿐 본선 사실이 아니다."""

    LFI = "LFI"
    SSRF = "SSRF"
    AUTH = "AUTH"
    SQLI = "SQLI"
    OTHER = "OTHER"


class Outcome(enum.Enum):
    """도구 실행 결과. 성공·실패·timeout을 동일 인터페이스로 반환한다(§9.10)."""

    SUCCESS = "success"
    FAIL = "fail"
    TIMEOUT = "timeout"


class Capability(enum.Enum):
    """typed egress capability(§9.5·§9.10). 각 capability는 전용 allowlist·인증만 쓴다."""

    ATTACK_TARGET = "ATTACK_TARGET"
    SUBMIT = "SUBMIT"
    LLM = "LLM"


class SideEffectClass(enum.Enum):
    """실행 부작용 등급(§9.10). 기본은 읽기 전용."""

    READ_ONLY = "READ_ONLY"
    BOUNDED_FLAG_DIRECTED_MUTATION = "BOUNDED_FLAG_DIRECTED_MUTATION"
    DISALLOWED = "DISALLOWED"


class FinalsPhase(enum.IntEnum):
    """본선 레이어 누적 개방 경기 단계(§7.1). S4ChainStage·MissionState와 다른 타입이다."""

    P1 = 1
    P2 = 2
    P3 = 3
    P4 = 4


class S4ChainStage(enum.IntEnum):
    """예선 S4 다단계 체인 국면 1~5(§7.1). FinalsPhase 번호와 대응한다고 가정하지 않는다."""

    STAGE1 = 1
    STAGE2 = 2
    STAGE3 = 3
    STAGE4 = 4
    STAGE5 = 5


class MissionState(enum.Enum):
    """예선 기체 임무 상태(§7.1). 수신 데이터 파서로 존재가 증명될 때만 인스턴스화한다."""

    PRE_FLIGHT = "pre_flight"
    TAKEOFF = "takeoff"
    CRUISE = "cruise"
    MISSION = "mission"
    RTL = "rtl"
    LAND = "land"


class SubmitState(enum.Enum):
    """flag 제출 결과 5종(운영세칙 제10조)."""

    ACCEPTED = "accepted"
    OWN_TEAM = "own_team"
    DUPLICATE = "duplicate"
    REJECTED = "rejected"
    CLOSED = "closed"
    ERROR = "error"  # 네트워크 오류 등 서버 상태 아님(런타임 내부용)


@dataclass(frozen=True)
class Endpoint:
    """공격 대상 = TARGETS × PORTS 조합의 한 원소.

    불변: host 비어있지 않음, 1 <= port <= 65535. host는 자기 팀 제외(호출측 보장).
    """

    host: str
    port: int
    # Scheme is an endpoint-local transport observation, not a new target.
    # Equality/hash intentionally remain TARGETS × PORTS based.
    scheme: str = field(default="http", compare=False, hash=False)

    def __post_init__(self) -> None:
        if not self.host or not self.host.strip():
            raise ValueError("Endpoint.host 비어있음")
        if not (MIN_PORT <= self.port <= MAX_PORT):
            raise ValueError(f"Endpoint.port 범위 밖: {self.port}")
        if self.scheme not in ("http", "https"):
            raise ValueError(f"Endpoint.scheme 지원 밖: {self.scheme}")

    def base_url(self) -> str:
        return f"{self.scheme}://{self.host}:{self.port}"

    def with_scheme(self, scheme: str) -> "Endpoint":
        return Endpoint(self.host, self.port, scheme=scheme)

    def key(self) -> str:
        return f"{self.host}:{self.port}"

    @property
    def endpoint_id(self) -> str:
        """검증된 host·port 쌍에 대해 Round 내에서 안정적인 식별자(§9.6)."""
        return f"{self.host}:{self.port}"


@dataclass(frozen=True)
class FinalsPhaseHint:
    """레이어·FinalsPhase 우선순위 힌트. 증거 참조가 있을 때만 생성한다(§9.6·§7.3).

    불변: finals_phase 1~4, layer 1~4, reason·evidence_ref 비어있지 않음.
    """

    finals_phase: int
    layer: int
    reason: str
    evidence_ref: str

    def __post_init__(self) -> None:
        if not (1 <= self.finals_phase <= 4):
            raise ValueError("finals_phase 는 1~4")
        if not (1 <= self.layer <= 4):
            raise ValueError("layer 는 1~4")
        if not self.reason or not self.evidence_ref:
            raise ValueError("FinalsPhaseHint 는 근거(reason·evidence_ref)를 요구한다")


@dataclass(frozen=True)
class EvidenceRef:
    """관측 증거 참조. 생성 Round·endpoint 밖에서 재사용 금지, TTL 경과 시 무효(§9.6)."""

    evidence_id: str
    round_id: str
    endpoint_id: str
    observed_at_monotonic: float
    expires_at_monotonic: float
    observation_fingerprint: str

    def valid_at(self, now: float, round_id: str, endpoint_id: str) -> bool:
        return (self.round_id == round_id
                and self.endpoint_id == endpoint_id
                and now < self.expires_at_monotonic)


@dataclass
class Observation:
    """단일 관측. timeout·연결거부·비정상 응답도 실패가 아니라 관측으로 기록한다(§9.7)."""

    endpoint: Endpoint
    request_fingerprint: str
    status: int  # 0 = 응답 없음(연결거부/timeout)
    redacted_header_hints: dict = field(default_factory=dict)
    body_fingerprint: str = ""
    latency_ms: float = 0.0
    note: str = ""
    round_id: str = ""
    evidence_ref: Optional["EvidenceRef"] = None

    @property
    def no_response(self) -> bool:
        return self.status == 0


@dataclass
class ObservedServiceProfile:
    """표적 서비스의 관측 프로파일(§9.6). 증거 기반으로만 채운다."""

    endpoint: Endpoint
    banner_fingerprint: str = ""
    status_codes: set = field(default_factory=set)
    redacted_header_hints: dict = field(default_factory=dict)
    error_signatures: list = field(default_factory=list)
    latency_band: str = "unknown"
    evidence: list = field(default_factory=list)
    finals_phase_hint: Optional[FinalsPhaseHint] = None

    def add_evidence(self, item: str) -> None:
        if item and item not in self.evidence:
            self.evidence.append(item)


@dataclass
class ScenarioHypothesis:
    """S1~S5 가설의 활성화·중단 상태(§9.8)."""

    scenario: Scenario
    activation_evidence: list = field(default_factory=list)
    preconditions: list = field(default_factory=list)
    stop_reason: Optional[str] = None

    @property
    def active(self) -> bool:
        return self.stop_reason is None and bool(self.activation_evidence)


@dataclass
class ExecutionPlan:
    """허용 도구 실행 계획(§9.6·§9.10). 실행 직전 capability·binding·TTL·예산 재검증 대상.

    `args`는 비밀 원문 대신 `SecretHandle`만 담는다. 모든 `evidence_refs`는 해당
    `round_id`·`endpoint_id`와 일치해야 한다.
    """

    tool: str
    target: Endpoint
    args: dict = field(default_factory=dict)
    plan_id: str = ""
    round_id: str = ""
    endpoint_id: str = ""
    capability: Capability = Capability.ATTACK_TARGET
    evidence_refs: list = field(default_factory=list)
    created_at_monotonic: float = 0.0
    expires_at_monotonic: float = float("inf")
    preconditions: list = field(default_factory=list)
    side_effect_class: SideEffectClass = SideEffectClass.READ_ONLY
    expected_cost: int = 1
    timeout: float = 6.0
    budget_charge: int = 1
    scenario: Optional[Scenario] = None
    reason: str = ""


@dataclass
class ToolResult:
    """도구 실행 결과. 성공·실패·timeout 동일 인터페이스(§9.10)."""

    plan: ExecutionPlan
    outcome: Outcome
    observation: Optional[Observation] = None
    body: str = ""  # flag 추출용 원시 본문(로그로 남기지 않음)


@dataclass
class FlagCandidate:
    """flag 후보. 원문 대신 해시로 중복 확인하고, 원문은 SecretHandle로만 참조한다(§9.6·§9.11)."""

    flag_hash: str
    secret_handle: object = None  # SecretHandle (원문은 Round 비밀 저장소에만)
    format_valid: bool = True
    submit_state: Optional[SubmitState] = None


@dataclass
class RoundBudget:
    """라운드 한정 예산·사용량(§9.6·§9.12). 병렬 공격에서 원자적으로 갱신된다."""

    request_count: int = 0
    submit_count: int = 0
    llm_calls: int = 0
    llm_tokens: int = 0
    _lock: object = field(default_factory=threading.Lock, repr=False, compare=False)

    def add_llm(self, calls: int = 1, tokens: int = 0) -> None:
        with self._lock:
            self.llm_calls += calls
            self.llm_tokens += tokens

    def try_reserve_llm(self, max_calls: int) -> bool:
        """호출 상한 검사와 예약을 원자적으로 수행(병렬 안전). 여유 없으면 False."""
        with self._lock:
            if self.llm_calls >= max_calls:
                return False
            self.llm_calls += 1
            return True

    def reset(self) -> None:
        """Round 시작 시 사용량을 0으로 되돌린다(라운드별 예산 격리)."""
        with self._lock:
            self.request_count = 0
            self.submit_count = 0
            self.llm_calls = 0
            self.llm_tokens = 0
