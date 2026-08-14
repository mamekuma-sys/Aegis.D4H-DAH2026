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

from .models import Capability, SubmitState
from .rate_limit import Backoff, parse_retry_after
from .secrets import KIND_FLAG

FLAG_RE = re.compile(r"FLAG\{[^}]*\}")
MAX_SUBMIT_RETRIES = 3

_STATE_MAP = {
    "accepted": SubmitState.ACCEPTED,
    "own_team": SubmitState.OWN_TEAM,
    "duplicate": SubmitState.DUPLICATE,
    "rejected": SubmitState.REJECTED,
    "closed": SubmitState.CLOSED,
}


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


# 서버가 확정한 종결 상태. 재제출하지 않는다(accepted/own_team/duplicate/closed/rejected).
# ERROR 는 네트워크 오류(서버 상태 아님)라 종결이 아니지만, 매 루프 재제출은 하지 않는다.
_TERMINAL_STATES = frozenset({
    SubmitState.ACCEPTED, SubmitState.OWN_TEAM, SubmitState.DUPLICATE,
    SubmitState.CLOSED, SubmitState.REJECTED,
})


class FlagStore:
    """제출한 flag의 해시별 결과를 컨테이너 한정으로 보관한다(원문 없음).

    check-reserve-submit-record를 원자화하기 위해 진행중(in-flight) 예약을 추적한다.
    동시에 같은 flag 를 본 여러 워커 중 정확히 하나만 HTTP 제출을 수행하고, 나머지는
    결과가 기록될 때까지 대기했다가 그 결과를 공유받는다(§9.6·§9.11).
    """

    def __init__(self):
        self._states = {}  # fingerprint -> SubmitState
        self._inflight = set()  # 제출 진행중인 fingerprint
        self._cond = threading.Condition(threading.Lock())

    def is_resolved(self, flag_hash: str) -> bool:
        with self._cond:
            return self._states.get(flag_hash) in _TERMINAL_STATES

    def state_of(self, flag_hash: str):
        with self._cond:
            return self._states.get(flag_hash)

    def try_begin_submit(self, flag_hash: str):
        """원자적 check-reserve. (should_submit, resolved_state)를 반환한다.

        - 이미 종결 상태면 (False, state) — 재제출 안 함.
        - 다른 워커가 제출 중이면 결과가 나올 때까지 대기 후 (False, state).
        - 아무도 제출하지 않았으면 예약하고 (True, None) — 호출자가 제출·finish 책임.
        """
        with self._cond:
            while True:
                st = self._states.get(flag_hash)
                if st in _TERMINAL_STATES:
                    return False, st
                if flag_hash in self._inflight:
                    self._cond.wait()  # 진행중인 제출의 결과를 기다린다
                    continue
                self._inflight.add(flag_hash)  # 예약(정확히 한 워커)
                return True, None

    def finish_submit(self, flag_hash: str, state: SubmitState) -> None:
        """예약한 워커가 제출 결과를 기록하고 대기자를 깨운다."""
        with self._cond:
            self._states[flag_hash] = state
            self._inflight.discard(flag_hash)
            self._cond.notify_all()

    def record(self, flag_hash: str, state: SubmitState) -> None:
        with self._cond:
            self._states[flag_hash] = state
            self._inflight.discard(flag_hash)
            self._cond.notify_all()

    def accepted_count(self) -> int:
        with self._cond:
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

    def submit(self, flag_handle) -> SubmitState:
        if not self._url or self._token_handle is None:
            return SubmitState.ERROR
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
                    return SubmitState.ERROR  # 현 Round 재시도 안 함
                self._sleep(wait)
                continue
            self._backoff.reset()
            return self._parse_state(resp)
        return SubmitState.ERROR

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
        """응답 텍스트에서 flag를 처리하고 (fingerprint, SubmitState) 목록을 반환한다.

        같은 flag 를 동시에 여러 워커가 봐도 원자적 예약으로 정확히 한 번만 HTTP 제출한다.
        """
        results = []
        for flag in extract_flags(text):
            if not is_valid_flag(flag):
                continue
            fp = flag_fingerprint(flag)
            should_submit, resolved = self.store.try_begin_submit(fp)
            if not should_submit:
                results.append((fp, resolved))  # 종결 상태 재사용 — 재제출 안 함
                continue
            try:
                handle = self._secret_store.put(KIND_FLAG, flag)  # 원문은 저장소로
                state = self._client.submit(handle)
            except Exception:
                # 제출 경로 예외 시 예약을 풀어 다음 기회에 재시도 가능하게 한다.
                self.store.finish_submit(fp, SubmitState.ERROR)
                raise
            self.store.finish_submit(fp, state)
            results.append((fp, state))
        return results
