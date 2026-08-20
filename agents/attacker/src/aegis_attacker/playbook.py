"""라운드 한정 성공 플레이북 — 교차 표적 재사용.

설계 §7.3·§7.6. 한 표적을 뚫은 exploit 형태(method·path 등, **비밀 없음**)를 배너 fingerprint로
기록하고, 같은 fingerprint의 다른 표적(같은 레이어의 다른 팀)에 LLM 전에 먼저 시도한다. 같은
챌린지 이미지는 같은 배너 → 같은 fingerprint이므로 라운드 내 교차 재사용이 성립한다. flag·세션·
토큰은 저장하지 않는다(경로·파라미터 형태만). 라운드 종료 시 폐기한다.
"""

from __future__ import annotations

import threading

# 같은 배너를 먼저 푸는 표적을 기다리는 최대 시간(초). 초과 시 이번 사이클 LLM은 생략한다.
SOLVE_WAIT = 10.0


class Playbook:
    """배너 fingerprint → 성공 exploit 형태(비밀 없음). 스레드 안전.

    같은 배너(같은 챌린지 이미지)를 여러 표적이 **동시에** LLM으로 푸는 낭비를 막기 위해
    single-flight 조정을 제공한다: 배너당 한 표적만 LLM으로 풀고(§7.6, 제22조), 나머지는
    그 결과가 playbook에 기록될 때까지 기다렸다 재사용한다.
    """

    def __init__(self):
        self._by_fp = {}
        self._inflight = {}   # banner_fp -> threading.Event (해결 시도 종료 시 set)
        self._generation = 0
        self._lock = threading.Lock()

    @property
    def generation(self) -> int:
        with self._lock:
            return self._generation

    @staticmethod
    def _sanitize(exploit: dict) -> dict:
        # 재사용에 필요한 exploit 형태(method·path·headers·body)를 보관한다. 헤더/바디는
        # LLM·결정론이 만든 권한 마커(X-Role: admin 등)이며 재사용의 핵심이다(인증형 exploit).
        # 라운드 종료 시 폐기되고 로그·LLM으로 나가지 않으므로 Round 메모리 범위 안이다.
        headers = exploit.get("headers")
        return {
            "method": str(exploit.get("method", "GET")).upper(),
            "path": exploit.get("path", "/"),
            "headers": dict(headers) if isinstance(headers, dict) else {},
            "body": exploit.get("body", "") or "",
        }

    def record(self, banner_fp: str, exploit: dict) -> None:
        if not banner_fp:
            return
        sanitized = self._sanitize(exploit)
        with self._lock:
            if self._by_fp.get(banner_fp) != sanitized:
                # A delivery encoding that crossed a stricter defender supersedes the
                # raw form learned from a weak team while preserving the same semantics.
                self._by_fp[banner_fp] = sanitized
                self._generation += 1

    def lookup(self, banner_fp: str):
        with self._lock:
            return self._by_fp.get(banner_fp)

    def claim_or_wait(self, banner_fp: str, wait_timeout: float = SOLVE_WAIT,
                      tried_reuse: bool = False) -> str:
        """LLM 해결 권한을 배너당 하나로 조정한다(single-flight).

        `tried_reuse=True`면 호출자가 이미 playbook 재사용을 시도했으나 이 표적에 안 맞았다는
        뜻이므로 "reuse"를 돌려주지 않고 직접 solver가 되게 한다(표적 특정 exploit 처리).

        반환:
          "solve" — 내가 이 배너를 LLM으로 푼다(끝나면 finish_llm 호출 필수).
          "reuse" — playbook에 답이 있으니 재사용하면 된다(tried_reuse=False일 때만).
          "skip"  — 다른 표적이 아직 푸는 중이고 대기 시간을 넘겼다. 이번 사이클 LLM 생략.
        """
        if not banner_fp:
            return "solve"
        with self._lock:
            if not tried_reuse and banner_fp in self._by_fp:
                return "reuse"
            if banner_fp not in self._inflight:
                self._inflight[banner_fp] = threading.Event()
                return "solve"
            event = self._inflight[banner_fp]
        event.wait(wait_timeout)
        with self._lock:
            if not tried_reuse and banner_fp in self._by_fp:
                return "reuse"
            if banner_fp not in self._inflight:
                # 앞선 solver가 성공 없이 종료 — 내가 이어서 solver가 된다.
                self._inflight[banner_fp] = threading.Event()
                return "solve"
            return "skip"

    def finish_llm(self, banner_fp: str) -> None:
        """solve 권한을 반납하고 대기 중인 표적을 깨운다. 반복 호출해도 안전하다."""
        if not banner_fp:
            return
        with self._lock:
            event = self._inflight.pop(banner_fp, None)
        if event is not None:
            event.set()

    def cancel_inflight(self) -> None:
        """종료 시 single-flight 대기자를 즉시 깨운다."""
        with self._lock:
            events = tuple(self._inflight.values())
            self._inflight.clear()
        for event in events:
            event.set()

    def clear(self) -> None:
        with self._lock:
            self._by_fp.clear()
            self._inflight.clear()
            self._generation = 0
