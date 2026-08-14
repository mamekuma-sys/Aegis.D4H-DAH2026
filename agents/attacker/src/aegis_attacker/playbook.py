"""라운드 한정 성공 플레이북 — 교차 표적 재사용.

설계 §7.3·§7.6. 한 표적을 뚫은 exploit 형태(method·path 등, **비밀 없음**)를 배너 fingerprint로
기록하고, 같은 fingerprint의 다른 표적(같은 레이어의 다른 팀)에 LLM 전에 먼저 시도한다. 같은
챌린지 이미지는 같은 배너 → 같은 fingerprint이므로 라운드 내 교차 재사용이 성립한다. flag·세션·
토큰은 저장하지 않는다(경로·파라미터 형태만). 라운드 종료 시 폐기한다.
"""

from __future__ import annotations

import re
import threading

_FLAG_RE = re.compile(r"FLAG\{[^}]*\}")
# 값에 세션·자격증명이 실리는 헤더 — 형태(키)는 남기되 원문 값은 재사용하지 않는다.
# 세션은 표적마다 다르므로 교차 표적 재사용 시 새 세션이 필요함을 뜻한다(KIND_SESSION 핸들).
_SENSITIVE_HEADERS = {"cookie", "authorization", "x-session", "x-auth-token", "set-cookie"}
_SESSION_PLACEHOLDER = "[SESSION]"


def _redact_value(value: str) -> str:
    """값에서 flag 원문을 제거한다(형태만 남김)."""
    return _FLAG_RE.sub("[FLAG]", str(value))


def _redact_headers(headers: dict) -> dict:
    """헤더 형태를 보존하되 Cookie/Authorization 등 자격증명 값은 마스크한다."""
    out = {}
    for k, v in (headers or {}).items():
        if str(k).lower() in _SENSITIVE_HEADERS:
            out[str(k)] = _SESSION_PLACEHOLDER  # 표적별 세션은 재사용 금지
        else:
            out[str(k)] = _redact_value(v)  # X-Role: admin 등 기법 힌트는 보존
    return out


class Playbook:
    """배너 fingerprint → 성공 exploit 형태(비밀 없음). 스레드 안전.

    method·path 뿐 아니라 headers·body **형태**까지 보관해 AUTH/POST 형 exploit도 두 번째
    LLM 호출 없이 재사용한다. Cookie/Authorization/flag 원문은 마스크한다(§7.3·§7.6).
    """

    def __init__(self):
        self._by_fp = {}
        self._lock = threading.Lock()

    @staticmethod
    def _sanitize(exploit: dict) -> dict:
        headers = exploit.get("headers") or {}
        if not isinstance(headers, dict):
            headers = {}
        return {
            "method": str(exploit.get("method", "GET")).upper(),
            "path": exploit.get("path", "/"),
            "headers": _redact_headers(headers),
            "body": _redact_value(exploit.get("body", "") or ""),
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
