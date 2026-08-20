"""flag 후보 추출·형식 검증·해시 중복 제거·제출.

설계 §9.6·§9.11. flag 원문은 Round 비밀 저장소에만 두고 handle로만 참조한다. 중복은
해시로 확인한다. 제출은 `SUBMIT` egress로 60초 sliding window를 지키며, 429에는 유효한
`Retry-After`를 우선 준수하되 Round 잔여 시간을 넘으면 현 Round에는 재시도하지 않는다.
"""

from __future__ import annotations

import hashlib
import json
import re
import threading
from dataclasses import dataclass

from .models import Capability, SubmitState
from .rate_limit import Backoff, parse_retry_after
from .secrets import KIND_FLAG

# 운영진이 명시한 형식은 대문자 ``FLAG{...}``이다. 빈 값·개행·중첩 brace는
# 제출 후보가 아니며, 비정상적으로 큰 응답 하나가 메모리와 제출 큐를 점유하지
# 않도록 후보 길이를 제한한다. 실제 flag 원문은 여전히 Round 비밀 저장소 밖으로
# 나가지 않는다.
MAX_FLAG_CONTENT_CHARS = 1024
FLAG_RE = re.compile(rf"FLAG\{{[^{{}}\r\n]{{1,{MAX_FLAG_CONTENT_CHARS}}}\}}")
MAX_SUBMIT_RETRIES = 3

_STATE_MAP = {
    "accepted": SubmitState.ACCEPTED,
    "own_team": SubmitState.OWN_TEAM,
    "duplicate": SubmitState.DUPLICATE,
    "rejected": SubmitState.REJECTED,
    "closed": SubmitState.CLOSED,
}


@dataclass(frozen=True)
class SubmitResult:
    state: SubmitState
    attempted: bool


def flag_fingerprint(flag: str) -> str:
    """flag 원문의 단방향 해시(전체). 로그·중복 식별에만 쓴다."""
    return hashlib.sha256((flag or "").encode("utf-8", "replace")).hexdigest()


def is_valid_flag(flag: str) -> bool:
    return bool(flag) and FLAG_RE.fullmatch(flag) is not None


def extract_flags(text: str) -> list:
    """응답에서 FLAG{...} 후보를 순서 유지·중복 제거로 추출한다."""
    seen = set()
    out = []
    for m in FLAG_RE.findall(text or ""):
        if m not in seen:
            seen.add(m)
            out.append(m)
    return out


class FlagStore:
    """flag 결과와 제출 중 claim을 라운드 한정으로 보관한다(원문 없음)."""

    def __init__(self):
        self._states = {}  # fingerprint -> SubmitState
        self._in_flight = set()
        self._lock = threading.Lock()

    def try_claim(self, flag_hash: str) -> bool:
        """미해결 fingerprint의 제출 권한을 한 worker에게만 원자적으로 부여한다."""
        with self._lock:
            state = self._states.get(flag_hash)
            if flag_hash in self._in_flight or (
                    state is not None and state != SubmitState.ERROR):
                return False
            self._in_flight.add(flag_hash)
            return True

    def release_claim(self, flag_hash: str) -> None:
        """제출 예외 뒤 후속 발견이 다시 시도할 수 있도록 claim을 해제한다."""
        with self._lock:
            self._in_flight.discard(flag_hash)

    def is_resolved(self, flag_hash: str) -> bool:
        with self._lock:
            st = self._states.get(flag_hash)
        return st is not None and st != SubmitState.ERROR

    def state_of(self, flag_hash: str):
        with self._lock:
            return self._states.get(flag_hash)

    def record(self, flag_hash: str, state: SubmitState) -> None:
        with self._lock:
            self._states[flag_hash] = state
            self._in_flight.discard(flag_hash)

    def accepted_count(self) -> int:
        with self._lock:
            return sum(1 for s in self._states.values() if s == SubmitState.ACCEPTED)


class SubmitClient:
    """flag 제출 클라이언트. `SUBMIT` egress + 제출 rate limit + Retry-After."""

    def __init__(self, egress, rate, submit_url: str, submit_token_handle,
                 secret_store, clock=None, sleep=None, backoff: Backoff = None,
                 round_deadline: float = float("inf")):
        self._egress = egress
        self._rate = rate
        self._url = submit_url
        self._token_handle = submit_token_handle
        self._store = secret_store
        self._clock = clock or (lambda: 0.0)
        self._sleep = sleep or (lambda dt: None)
        self._backoff = backoff or Backoff()
        self._round_deadline = round_deadline

    def submit(self, flag_handle) -> SubmitResult:
        if not self._url or self._token_handle is None:
            return SubmitResult(SubmitState.ERROR, attempted=False)
        flag = self._store.resolve(flag_handle)          # 원문은 여기서만 해석
        token = self._store.resolve(self._token_handle)
        body = json.dumps({"flag": flag, "token": token})
        for _ in range(MAX_SUBMIT_RETRIES):
            self._rate.acquire_submit()
            resp = self._egress.request(
                Capability.SUBMIT, "POST", self._url,
                headers={"Content-Type": "application/json"}, body=body, timeout=10.0)
            if resp.status == 429:
                wait = parse_retry_after(resp.headers.get("Retry-After"))
                if wait is None:
                    wait = self._backoff.next_delay()  # header 없거나 무효
                if self._clock() + wait > self._round_deadline:
                    return SubmitResult(SubmitState.ERROR, attempted=True)  # 현 Round 재시도 안 함
                self._sleep(wait)
                continue
            self._backoff.reset()
            return SubmitResult(self._parse_state(resp), attempted=True)
        return SubmitResult(SubmitState.ERROR, attempted=True)

    @staticmethod
    def _parse_state(resp) -> SubmitState:
        if resp.status == 0:
            return SubmitState.ERROR
        try:
            obj = json.loads(resp.body)
            status = str(obj.get("status", "")).lower()
        except Exception:
            return SubmitState.ERROR
        return _STATE_MAP.get(status, SubmitState.ERROR)


class FlagPipeline:
    """추출 → 형식검증 → 비밀 저장소 보관 → 해시 중복확인 → 제출 → 결과 기록."""

    def __init__(self, submit_client: SubmitClient, secret_store, store: FlagStore = None):
        self._client = submit_client
        self._secret_store = secret_store
        self.store = store or FlagStore()

    def process(self, text: str) -> list:
        """응답의 flag를 처리해 (fingerprint, state, submitted) 목록을 반환한다."""
        results = []
        for flag in extract_flags(text):
            if not is_valid_flag(flag):
                continue
            fp = flag_fingerprint(flag)
            if not self.store.try_claim(fp):
                state = self.store.state_of(fp)
                if state is not None and state != SubmitState.ERROR:
                    results.append((fp, state, False))  # 완료된 결과는 재제출 안 함
                continue
            handle = self._secret_store.put(KIND_FLAG, flag)  # 원문은 저장소로
            try:
                result = self._client.submit(handle)
            except Exception:
                self.store.release_claim(fp)
                raise
            self.store.record(fp, result.state)
            results.append((fp, result.state, result.attempted))
        return results
