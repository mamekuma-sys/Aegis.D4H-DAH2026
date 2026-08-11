"""flag 후보 추출·형식 검증·해시 중복 제거·제출.

설계 §9.11. flag 원문을 로그·장기 식별자로 쓰지 않고 단방향 해시로 중복을 확인한다.
제출은 분당 30회 제한(rate limiter)을 지키고 429에는 backoff한다. 한 flag의 경로가
여럿일 수 있으므로(운영세칙 제11조 ③) 서로 다른 경로에서 같은 flag를 얻어도 재제출하지 않는다.
"""

from __future__ import annotations

import hashlib
import json
import re

from .models import SubmitState
from .rate_limit import Backoff

FLAG_RE = re.compile(r"FLAG\{[^}]*\}")
MAX_SUBMIT_RETRIES = 3

# 서버 status 문자열 → SubmitState
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


class FlagStore:
    """제출한 flag의 해시별 결과를 라운드 한정으로 보관한다."""

    def __init__(self):
        self._states = {}  # fingerprint -> SubmitState

    def is_resolved(self, flag: str) -> bool:
        """이미 서버 판정을 받은 flag면 재제출하지 않는다(ERROR는 미해결)."""
        st = self._states.get(flag_fingerprint(flag))
        return st is not None and st != SubmitState.ERROR

    def state_of(self, flag: str):
        return self._states.get(flag_fingerprint(flag))

    def record(self, flag: str, state: SubmitState) -> None:
        self._states[flag_fingerprint(flag)] = state

    def accepted_count(self) -> int:
        return sum(1 for s in self._states.values() if s == SubmitState.ACCEPTED)


class SubmitClient:
    """flag 제출 클라이언트. 제출 rate limit 준수 + 429 backoff."""

    def __init__(self, http, rate, submit_url: str, submit_token: str,
                 sleep=None, backoff: Backoff = None):
        self._http = http
        self._rate = rate
        self._url = submit_url
        self._token = submit_token
        self._sleep = sleep or (lambda dt: None)
        self._backoff = backoff or Backoff()

    def submit(self, flag: str) -> SubmitState:
        if not self._url or not self._token:
            return SubmitState.ERROR
        body = json.dumps({"flag": flag, "token": self._token})
        for _ in range(MAX_SUBMIT_RETRIES):
            self._rate.acquire_submit()
            resp = self._http.request(
                "POST", self._url,
                headers={"Content-Type": "application/json"},
                body=body, timeout=10.0,
            )
            if resp.status == 429:
                self._sleep(self._backoff.next_delay())
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
    """추출 → 형식검증 → 해시 중복확인 → 제출 → 결과 기록."""

    def __init__(self, submit_client: SubmitClient, store: FlagStore = None):
        self._client = submit_client
        self.store = store or FlagStore()

    def process(self, text: str) -> list:
        """응답 텍스트에서 flag를 처리하고 (fingerprint, SubmitState) 목록을 반환한다."""
        results = []
        for flag in extract_flags(text):
            if not is_valid_flag(flag):
                continue
            fp = flag_fingerprint(flag)
            if self.store.is_resolved(flag):
                results.append((fp, self.store.state_of(flag)))  # 재제출 안 함
                continue
            state = self._client.submit(flag)
            self.store.record(flag, state)
            results.append((fp, state))
        return results
