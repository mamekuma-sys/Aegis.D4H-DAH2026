"""선택적 비동기 LLM 조언 (`AdvisoryWorker`).

설계 §0.5 AI는 패킷 경로에 넣을 수 없다, §12 LLM 사용 경계, §12.1 model 선택과 증빙.

300ms 시한에 원격 LLM 호출은 물리적으로 불가능하다. 레퍼런스 구현조차 호출 함수를
정의만 하고 판정 경로에서 부르지 않으며, `contracts/defender/README.md`가 이를
계약으로 못박는다. 따라서 예선의 "결정론적 판단과 AI 판단 분리"는 본선에서
설계 취향이 아니라 **시간 계약상 필연**이 된다.

이 worker가 지키는 경계:

- 출력은 현재 또는 이후 packet을 직접 `ACCEPT`/`DROP`하지 않는다. `AsyncAdvisory`에
  runtime authority가 없다는 것은 주석이 아니라 배선의 사실이다 — 이 모듈은
  `HotPolicy`나 `CompiledPolicy`를 참조하지 않는다.
- raw payload, secret, token, **flag**, 전체 PCAP, 인증 header를 prompt에 넣지
  않는다. 입력은 parser가 만든 redacted feature와 집계값, `rule_id`, 비민감
  reason뿐이다. 그럼에도 송신 직전에 한 번 더 검사한다(2차 방어).
- timeout, quota 소진, invalid response, proxy 장애가 HEARTBEAT·verdict에
  영향을 주지 않는다. 이 스레드는 조용히 물러난다.

예산도 계약이다. 제22조상 동점이면 **LLM token 비용이 적은 팀이 우선**하고,
제24조 5호는 클라우드 자원 악용을 금지한다. 그래서 전체 트래픽을 보내지 않고
의심 상위 K개만 요약하며, Round당 호출 수에 상한을 둔다. 제23조 진위 검증에
대비해 model ID·호출 수·token 사용량·실패율을 비민감 형태로 상시 기록한다.
"""

from __future__ import annotations

import json
import threading
import time
from dataclasses import dataclass
from typing import Callable

from .config import RuntimeConfig
from .logging import AuditLogger, contains_secret_like, redact_secrets
from .metrics import M_ADVISORY_CALL, M_ADVISORY_FAILURE, M_ADVISORY_TOKENS, Metrics
from .state import CorrelationSnapshotRef

# 호출 예산(§12.1). P4-R13에서 gpt-5.4 조언은 실제로 성공했으므로 마지막 라운드는
# redacted 상위 flow를 더 자주 검토한다. 이 worker는 판정 핫패스와 분리되어 있고
# 출력에 runtime authority가 없으므로 호출 증가가 verdict 지연이나 정책 변경으로
# 이어지지는 않는다.
MIN_CALL_INTERVAL_SECONDS = 45.0
MAX_CALLS_PER_ROUND = 12
TOP_K_FLOWS = 48
REQUEST_TIMEOUT_SECONDS = 20.0
MAX_RECENT_ADVISORIES = 256
MAX_RECOMMENDATION_CHARS = 12000
MAX_ADVISORY_CANDIDATES = 16
MAX_CANDIDATE_FIELD_CHARS = 256
ADVISORY_TTL_SECONDS = 1800.0
ADVISORY_MAX_COMPLETION_TOKENS = 2048
ADVISORY_REASONING_EFFORT = "low"

# 연속 timeout이면 남은 호출·token을 보존한다. 다음 Break 후보를 완전히 잃지
# 않도록 영구 disable 대신 bounded circuit break를 쓴다.
FAILURE_BACKOFF_SECONDS = 90.0
MAX_CONSECUTIVE_FAILURES = 3

_SYSTEM_PROMPT = (
    "You are assisting Team1 finals defense (Aegis). You receive only aggregated, "
    "redacted flow statistics - never payloads, flags, tokens, or secrets. "
    "Propose up to sixteen precise DROP-candidate signatures for the open layers: "
    "L1 8080/9000 (portal,/svc/flag-*, SatDiag Export/Tail), "
    "L2 8082 (GraphQL missionAudit, /api/rsc-action, /ws/mission-feed, forged admin), "
    "L3 9090 HTTP UNION SQLi; MQTT 1883 (#/$SYS/flag topics); RTSP 8554 DESCRIBE /flag. "
    "L4 8410/8420 uses g2dds.v1 Layer4Service Exchange plus observed ROS/mission HTTP shapes. "
    "Prefer regex/http semantic checks that miss normal SLA probes. "
    "Return one JSON object with a candidates array (maximum sixteen). Every item must have "
    "protocol, port, field, pattern_family, evidence_needed, and false_positive_risk. "
    "Do not return executable code or raw secret values. Candidates begin as SHADOW only. "
    "You have NO runtime DROP authority - your text is Break review input only."
)


@dataclass(frozen=True, slots=True)
class AdvisoryFeature:
    """LLM에 보낼 수 있는 유일한 형태의 입력. 전부 집계값과 논리 ID다."""

    flow_label: str
    score: int
    sig_hits: int
    distinct_paths: int
    scan_flag_hits: int
    matched_stages: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class AdvisoryCandidate:
    """검증·fixture 작성에 필요한 최소 Break 후보 schema."""

    protocol: str
    port: int
    field: str
    pattern_family: str
    evidence_needed: str
    false_positive_risk: str


@dataclass(frozen=True, slots=True)
class AsyncAdvisory:
    """**runtime authority 없음**(§8). 사람이 Break에서 읽는 후보일 뿐이다."""

    input_feature_ids: tuple[str, ...]
    recommendation: str
    candidates: tuple[AdvisoryCandidate, ...]
    model_id: str
    prompt_tokens: int
    completion_tokens: int
    created_at: float
    expires_at: float

    @property
    def total_tokens(self) -> int:
        return self.prompt_tokens + self.completion_tokens


class SecretLeakError(RuntimeError):
    """redaction 검사에 걸렸다. 호출을 취소한다."""


def assert_no_secrets(text: str) -> None:
    """prompt 송신 직전 2차 방어.

    1차 방어는 애초에 payload를 event에 담지 않는 것이다(§8). 그럼에도 검사하는
    이유는, 이 경로의 실패 비용이 비대칭이기 때문이다 — flag 하나가 외부 프록시
    로그에 남으면 되돌릴 방법이 없다.
    """
    if contains_secret_like(text):
        raise SecretLeakError("prompt 에 비밀로 보이는 문자열이 있어 호출을 취소했습니다")


def parse_advisory_candidates(content: str) -> tuple[AdvisoryCandidate, ...]:
    """LLM text에서 실행 권한 없는 bounded 후보만 구조화한다."""
    try:
        document = json.loads(content)
    except (json.JSONDecodeError, TypeError):
        return ()
    raw_candidates = document.get("candidates") if isinstance(document, dict) else None
    if not isinstance(raw_candidates, list):
        return ()
    candidates: list[AdvisoryCandidate] = []
    for raw in raw_candidates[:MAX_ADVISORY_CANDIDATES]:
        if not isinstance(raw, dict):
            continue
        protocol = str(raw.get("protocol", "")).strip().lower()
        try:
            port = int(raw.get("port", 0))
        except (TypeError, ValueError):
            continue
        fields = []
        valid = protocol in {"tcp", "udp"} and 1 <= port <= 65535
        for key in ("field", "pattern_family", "evidence_needed", "false_positive_risk"):
            value = str(raw.get(key, "")).strip()
            if not value or len(value) > MAX_CANDIDATE_FIELD_CHARS or "\x00" in value:
                valid = False
            fields.append(value[:MAX_CANDIDATE_FIELD_CHARS])
        if not valid:
            continue
        candidate = AdvisoryCandidate(protocol, port, *fields)
        if contains_secret_like(json.dumps(raw, ensure_ascii=True)):
            continue
        candidates.append(candidate)
    return tuple(candidates)


def _post_json(url: str, api_key: str, body: dict, timeout: float) -> dict:
    # 원격 I/O 모듈은 비동기 advisory가 실제 호출될 때만 로드한다. Broker 연결과
    # verdict 경로는 http/ssl/email import 비용을 지불하지 않는다.
    import urllib.request

    payload = json.dumps(body).encode("utf-8")
    request = urllib.request.Request(
        url,
        data=payload,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}",
        },
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310
        return json.load(response)


class AdvisoryWorker:
    """의심 상위 flow를 요약해 다음 이미지의 `SHADOW` rule 후보를 받는다."""

    def __init__(
        self,
        config: RuntimeConfig,
        snapshot_ref: CorrelationSnapshotRef,
        metrics: Metrics | None = None,
        audit: AuditLogger | None = None,
        clock=time.monotonic,
        transport: Callable[[str, str, dict, float], dict] | None = None,
        stop_event: threading.Event | None = None,
        min_interval: float = MIN_CALL_INTERVAL_SECONDS,
        max_calls: int = MAX_CALLS_PER_ROUND,
    ) -> None:
        self._config = config
        self._ref = snapshot_ref
        self._metrics = metrics
        self._audit = audit
        self._clock = clock
        self._transport = transport or _post_json
        self._stop = stop_event or threading.Event()
        self._min_interval = min_interval
        self._max_calls = max_calls

        self._thread: threading.Thread | None = None
        self._last_call_at = 0.0
        self._blocked_until = 0.0
        self._consecutive_failures = 0
        self.calls = 0
        self.failures = 0
        self.prompt_tokens = 0
        self.completion_tokens = 0
        self.recent: list[AsyncAdvisory] = []

    # ── 상태 ────────────────────────────────────────────────────────────────

    @property
    def enabled(self) -> bool:
        return self._config.advisory_enabled

    def usage_evidence(self) -> dict[str, object]:
        """제23조 진위 검증용 비민감 사용 내역."""
        return {
            "model_id": self._config.llm_model,
            "calls": self.calls,
            "failures": self.failures,
            "prompt_tokens": self.prompt_tokens,
            "completion_tokens": self.completion_tokens,
            "recent_candidates": sum(len(item.candidates) for item in self.recent),
            "failure_rate": round(self.failures / self.calls, 4) if self.calls else 0.0,
        }

    # ── feature 추출 ────────────────────────────────────────────────────────

    def collect_features(self) -> tuple[AdvisoryFeature, ...]:
        """현재 snapshot에서 상위 K개 flow만 요약한다.

        전체 트래픽을 넣지 않는 것은 예산 문제만이 아니다. 요약이 클수록 그 안에
        의도치 않은 식별 정보가 섞일 표면도 커진다.
        """
        snapshot = self._ref.read()
        if snapshot is None:
            return ()
        ranked = sorted(
            snapshot.entries.items(), key=lambda pair: pair[1].score, reverse=True
        )[:TOP_K_FLOWS]
        return tuple(
            AdvisoryFeature(
                # flow 좌표는 protocol/port 라는 비식별 label 로만 보낸다. NAT 로
                # 정규화된 source IP 는 어차피 식별자가 아니고(§8.4), 목적지 주소는
                # 팀 내부 토폴로지다.
                flow_label=f"{key.protocol}/{key.dst_port}",
                score=entry.score,
                sig_hits=entry.sig_hits,
                distinct_paths=entry.distinct_paths,
                scan_flag_hits=entry.scan_flag_hits,
                matched_stages=entry.matched_stages,
            )
            for key, entry in ranked
        )

    def build_messages(self, features: tuple[AdvisoryFeature, ...]) -> list[dict[str, str]]:
        lines = [
            f"- flow {item.flow_label}: score={item.score} sig_hits={item.sig_hits} "
            f"distinct_paths={item.distinct_paths} scan_flags={item.scan_flag_hits} "
            f"stages={','.join(item.matched_stages) or 'none'}"
            for item in features
        ]
        user = "Aggregated flow statistics from the current round:\n" + "\n".join(lines)
        assert_no_secrets(user)
        is_gpt56 = self._config.llm_model.startswith("gpt-5.6-")
        return [
            {"role": "developer" if is_gpt56 else "system", "content": _SYSTEM_PROMPT},
            {"role": "user", "content": user},
        ]

    # ── 호출 ────────────────────────────────────────────────────────────────

    def should_call(self, now: float) -> bool:
        if not self.enabled:
            return False
        if self.calls >= self._max_calls:
            return False
        if now < self._blocked_until:
            return False
        return (now - self._last_call_at) >= self._min_interval

    def run_once(self, now: float | None = None) -> AsyncAdvisory | None:
        """조언을 한 번 요청한다. 어떤 실패도 밖으로 전파하지 않는다."""
        moment = self._clock() if now is None else now
        if not self.should_call(moment):
            return None

        features = self.collect_features()
        if not features:
            self._last_call_at = moment
            return None

        # custom transport가 URLError를 반환하는 테스트와 기본 transport를 같은
        # 경로로 처리하되, 이 import도 첫 비동기 호출 전에는 실행하지 않는다.
        import urllib.error

        try:
            messages = self.build_messages(features)
        except SecretLeakError:
            self.failures += 1
            self._count(M_ADVISORY_FAILURE)
            if self._audit is not None:
                self._audit.log("advisory-blocked", reason="redaction-guard")
            return None

        self._last_call_at = moment
        self.calls += 1
        self._count(M_ADVISORY_CALL)

        body = {
            "model": self._config.llm_model,
            "messages": messages,
            "max_completion_tokens": ADVISORY_MAX_COMPLETION_TOKENS,
        }
        model_id = self._config.llm_model
        if model_id.startswith("gpt-5.6-"):
            body["reasoning_effort"] = ADVISORY_REASONING_EFFORT
        elif model_id.endswith("-pro") or model_id in {"o3", "o4-mini"}:
            # Responses 계열 — temperature 미지원에 가깝게 취급한다.
            pass
        else:
            body["temperature"] = 0.2
        url = f"{self._config.llm_base_url}/v1/chat/completions"

        try:
            document = self._transport(url, self._config.llm_api_key, body, REQUEST_TIMEOUT_SECONDS)
            content = document["choices"][0]["message"]["content"]
            usage = document.get("usage", {}) or {}
        except (urllib.error.URLError, OSError, TimeoutError, KeyError, IndexError,
                TypeError, ValueError, json.JSONDecodeError) as exc:
            return self._handle_failure(type(exc).__name__, moment)

        self._consecutive_failures = 0
        recommendation = redact_secrets(str(content))[:MAX_RECOMMENDATION_CHARS]
        advisory = AsyncAdvisory(
            input_feature_ids=tuple(item.flow_label for item in features),
            # 사람이 읽을 조언문이므로 길이는 자체 상한까지 남기되 비밀 형태는 지운다.
            recommendation=recommendation,
            candidates=parse_advisory_candidates(recommendation),
            model_id=self._config.llm_model,
            prompt_tokens=int(usage.get("prompt_tokens", 0) or 0),
            completion_tokens=int(usage.get("completion_tokens", 0) or 0),
            created_at=moment,
            expires_at=moment + ADVISORY_TTL_SECONDS,
        )
        self.prompt_tokens += advisory.prompt_tokens
        self.completion_tokens += advisory.completion_tokens
        if self._metrics is not None:
            self._metrics.incr(M_ADVISORY_TOKENS, advisory.total_tokens)

        self.recent.append(advisory)
        if len(self.recent) > MAX_RECENT_ADVISORIES:
            self.recent.pop(0)

        if self._audit is not None:
            self._audit.log(
                "advisory-received",
                model_id=advisory.model_id,
                total_tokens=advisory.total_tokens,
                features=len(features),
                candidates=len(advisory.candidates),
                authority="none-shadow-candidate-only",
            )
        return advisory

    def _handle_failure(self, reason: str, now: float) -> None:
        self.failures += 1
        self._consecutive_failures += 1
        self._count(M_ADVISORY_FAILURE)
        if self._consecutive_failures >= MAX_CONSECUTIVE_FAILURES:
            # quota 소진이나 proxy 장애일 때 예산을 태우지 않는다(§13).
            self._blocked_until = now + FAILURE_BACKOFF_SECONDS
        if self._audit is not None:
            self._audit.log("advisory-failed", reason=reason, consecutive=self._consecutive_failures)
        return None

    # ── 스레드 lifecycle ────────────────────────────────────────────────────

    def start(self) -> None:
        if self.is_alive() or not self.enabled:
            return
        self._thread = threading.Thread(target=self.run, name="advisory", daemon=True)
        self._thread.start()

    def is_alive(self) -> bool:
        thread = self._thread
        return thread is not None and thread.is_alive()

    def stop(self, timeout: float = 2.0) -> None:
        self._stop.set()
        thread = self._thread
        self._thread = None
        if thread is not None:
            thread.join(timeout=timeout)

    def run(self) -> None:
        while not self._stop.wait(1.0):
            try:
                self.run_once()
            except Exception:  # noqa: BLE001 - advisory 장애는 verdict 에 무영향(§13)
                self.failures += 1

    def _count(self, name: str, amount: int = 1) -> None:
        if self._metrics is not None:
            self._metrics.incr(name, amount)
