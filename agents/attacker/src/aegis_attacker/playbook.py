"""라운드 한정 성공 플레이북 — 교차 표적 재사용.

설계 §7.3·§7.6. 한 표적을 뚫은 exploit 형태(method·path 등, **비밀 없음**)를 배너 fingerprint로
기록하고, 같은 fingerprint의 다른 표적(같은 레이어의 다른 팀)에 LLM 전에 먼저 시도한다. 같은
챌린지 이미지는 같은 배너 → 같은 fingerprint이므로 라운드 내 교차 재사용이 성립한다. flag·세션·
토큰은 저장하지 않는다(경로·파라미터 형태만). 라운드 종료 시 폐기한다.
"""

from __future__ import annotations

import threading


class Playbook:
    """배너 fingerprint → 성공 exploit 형태(비밀 없음). 스레드 안전."""

    def __init__(self):
        self._by_fp = {}
        self._lock = threading.Lock()

    @staticmethod
    def _sanitize(exploit: dict) -> dict:
        # 경로·메서드·비민감 형태만 보관. body/headers는 값이 아니라 형태로만 남길 수 있으나
        # 데모 exploit은 표적별 상수 경로이므로 method·path만 재사용한다.
        return {
            "method": str(exploit.get("method", "GET")).upper(),
            "path": exploit.get("path", "/"),
        }

    def record(self, banner_fp: str, exploit: dict) -> None:
        if not banner_fp:
            return
        with self._lock:
            self._by_fp.setdefault(banner_fp, self._sanitize(exploit))

    def lookup(self, banner_fp: str):
        with self._lock:
            return self._by_fp.get(banner_fp)

    def clear(self) -> None:
        with self._lock:
            self._by_fp.clear()
