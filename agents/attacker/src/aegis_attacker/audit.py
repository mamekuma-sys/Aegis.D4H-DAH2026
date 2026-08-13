"""비밀 제거 구조화 로그.

설계 §9.6·§9.12. 인증 키·제출 토큰·flag 원문·상대 팀 비밀을 로그에 남기지 않는다
(운영세칙 제23·24조). 모든 로그 필드는 Redactor를 통과한다.
"""

from __future__ import annotations

import json
import re
import sys
import threading

FLAG_PATTERN = re.compile(r"FLAG\{[^}]*\}")
FLAG_PLACEHOLDER = "[FLAG]"
SECRET_PLACEHOLDER = "[REDACTED]"


class Redactor:
    """flag 원문과 등록된 비밀 문자열을 치환한다."""

    def __init__(self, secrets=None, min_secret_len: int = 4):
        # 너무 짧은 값은 오탐 치환을 피한다.
        self._secrets = sorted(
            {s for s in (secrets or set()) if s and len(s) >= min_secret_len},
            key=len, reverse=True,
        )

    def scrub(self, text: str) -> str:
        if text is None:
            return ""
        out = FLAG_PATTERN.sub(FLAG_PLACEHOLDER, str(text))
        for secret in self._secrets:
            if secret in out:
                out = out.replace(secret, SECRET_PLACEHOLDER)
        return out

    def scrub_obj(self, obj):
        if isinstance(obj, str):
            return self.scrub(obj)
        if isinstance(obj, dict):
            return {k: self.scrub_obj(v) for k, v in obj.items()}
        if isinstance(obj, (list, tuple)):
            return [self.scrub_obj(v) for v in obj]
        return obj


class AuditLogger:
    """한 줄 JSON 구조화 로그. sink 주입 가능(테스트)."""

    def __init__(self, redactor: Redactor = None, sink=None):
        self._redactor = redactor or Redactor()
        self._sink = sink or (lambda line: print(line, file=sys.stderr, flush=True))
        self._lock = threading.Lock()

    def log(self, event: str, **fields) -> None:
        record = {"event": event}
        record.update(self._redactor.scrub_obj(fields))
        line = json.dumps(record, ensure_ascii=False, sort_keys=True)
        with self._lock:  # 병렬 로그 라인 섞임 방지
            self._sink(line)
