"""비밀 없는 구조화 로깅 (`AuditLogger`).

설계 §7 구성요소 표, §15.7 비동기·로그·보안, §17.2 다음 Round로 가져갈 수 있는 것.

두 가지 제약이 이 모듈의 형태를 결정한다.

1. **로그 I/O가 hot path를 막으면 안 된다.** stderr가 파이프이고 소비자가 느리면
   `write`는 블로킹한다. 판정 스레드에서 그 블로킹이 일어나면 300ms 예산이
   깨지므로, 기동 후에는 bounded queue에 넣고 별도 스레드가 배출한다. 큐가 차면
   로그를 버린다 — 로그를 지키자고 verdict를 늦추지 않는다.
2. **payload·secret·flag가 절대 나가면 안 된다.** 그래서 원본 payload를 받지
   않는 것이 1차 방어이고, 그럼에도 문자열에 섞여 들어오는 경우를 대비해
   출력 직전에 redaction을 한 번 더 건다(2차 방어).
"""

from __future__ import annotations

import json
import queue
import re
import sys
import threading
import time
from typing import Any, TextIO

DEFAULT_LOG_QUEUE_CAPACITY = 1024
MAX_FIELD_CHARS = 200

REDACTED = "[REDACTED]"

# flag는 챌린지 컨테이너의 `/flags/LAYER{n}_CHALL1_FLAG` 파일로 주입되고 형식은
# `FLAG{32 hex}`다(§0.4). 아웃바운드를 볼 수 없으므로 이 형식은 차단 패턴이 아니라
# **로그 유출 금지 대상**으로만 취급한다(§12).
_FLAG_PATTERN = re.compile(r"FLAG\{[^}\r\n]{0,128}\}", re.IGNORECASE)
# 키워드 뒤 **줄 끝까지** 지운다. `Authorization: Bearer <값>` 처럼 키워드가 연달아
# 나오면 값 하나만 소비하는 패턴은 정작 비밀인 뒷부분을 남긴다.
_BEARER_PATTERN = re.compile(
    r"(?i)\b(?:bearer|token|api[-_]?key|authorization|secret|password|passwd|credential)s?\b[^\r\n]*"
)
_APIKEY_PATTERN = re.compile(r"\bsk-[A-Za-z0-9_\-]{8,}")
_BASIC_AUTH_PATTERN = re.compile(r"(?i)\bbasic\s+[A-Za-z0-9+/=]{8,}")


_SECRET_PATTERNS = (_FLAG_PATTERN, _APIKEY_PATTERN, _BASIC_AUTH_PATTERN, _BEARER_PATTERN)


def contains_secret_like(value: str) -> bool:
    """비밀로 보이는 문자열이 있는가.

    길이 절단과 분리해 둔 이유는 호출자가 다르기 때문이다. 로그 필드는 잘라도
    되지만, 사람이 읽을 조언문을 200자로 자르면 쓸모가 없어진다. 그런데 "잘렸다"를
    "비밀이 있다"로 오인하면 정상 조언이 전부 차단된다.
    """
    return any(pattern.search(value) for pattern in _SECRET_PATTERNS)


def redact_secrets(value: str) -> str:
    """flag·토큰·키 형태만 지운다. 길이는 건드리지 않는다.

    비밀을 "가리는" 것이 목적이지 "탐지"가 목적이 아니므로 과탐이 나도 무해하다.
    reason code와 rule ID는 이 패턴들에 걸리지 않는 어휘로 정한다.
    """
    redacted = _FLAG_PATTERN.sub("FLAG{" + REDACTED + "}", value)
    redacted = _APIKEY_PATTERN.sub(REDACTED, redacted)
    redacted = _BASIC_AUTH_PATTERN.sub("Basic " + REDACTED, redacted)
    return _BEARER_PATTERN.sub(REDACTED, redacted)


def redact_text(value: str) -> str:
    """로그 필드 하나에 실을 수 있는 형태로. redaction 후 길이도 제한한다."""
    redacted = redact_secrets(value)
    if len(redacted) > MAX_FIELD_CHARS:
        redacted = redacted[:MAX_FIELD_CHARS] + "…"
    return redacted


def redact_value(value: Any) -> Any:
    """로그 필드 하나를 안전한 값으로 바꾼다.

    `bytes`는 절대 디코딩해 싣지 않는다. raw payload가 로그로 새는 가장 흔한
    경로가 "디버깅용으로 잠깐 넣은 bytes"이기 때문이다. 길이만 남긴다.
    """
    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, (bytes, bytearray, memoryview)):
        return f"<{len(value)} bytes>"
    if isinstance(value, (int, float, bool)) or value is None:
        return value
    if isinstance(value, (list, tuple)):
        return [redact_value(item) for item in value[:16]]
    if isinstance(value, dict):
        return {str(key): redact_value(item) for key, item in list(value.items())[:32]}
    return redact_text(str(value))


class AuditLogger:
    """단일 라인 JSON 감사 로그.

    `start()` 전에는 동기로 쓴다. 테스트가 스레드 타이밍 없이 출력 내용을
    검증할 수 있게 하기 위한 것이고, 실제 런타임은 `start()` 이후 비동기다.
    """

    def __init__(
        self,
        stream: TextIO | None = None,
        capacity: int = DEFAULT_LOG_QUEUE_CAPACITY,
        clock=time.time,
    ) -> None:
        self._stream = stream if stream is not None else sys.stderr
        self._queue: queue.Queue[str] = queue.Queue(maxsize=capacity)
        self._clock = clock
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()
        self.dropped = 0

    def start(self) -> None:
        if self._thread is not None:
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._drain, name="audit-log", daemon=True)
        self._thread.start()

    def stop(self, timeout: float = 2.0) -> None:
        self._stop.set()
        thread = self._thread
        self._thread = None
        if thread is not None:
            thread.join(timeout=timeout)
        self._flush_remaining()

    def log(self, event: str, **fields: Any) -> None:
        """비민감 이벤트 한 건을 기록한다. 어떤 경우에도 예외를 밖으로 내지 않는다."""
        try:
            record = {"ts": round(self._clock(), 3), "event": str(event)}
            for key, value in fields.items():
                record[str(key)] = redact_value(value)
            line = json.dumps(record, ensure_ascii=False, separators=(",", ":"))
        except Exception:  # noqa: BLE001 - 로깅 실패가 판정을 막아서는 안 된다
            self.dropped += 1
            return

        if self._thread is None:
            self._write(line)
            return
        try:
            self._queue.put_nowait(line)
        except queue.Full:
            # drop-newest. 로그 보존보다 hot path 진행이 우선이다.
            self.dropped += 1

    def _write(self, line: str) -> None:
        try:
            self._stream.write(line + "\n")
            self._stream.flush()
        except Exception:  # noqa: BLE001 - stderr 장애가 프로세스를 죽이지 않는다
            self.dropped += 1

    def _drain(self) -> None:
        while not self._stop.is_set():
            try:
                line = self._queue.get(timeout=0.2)
            except queue.Empty:
                continue
            self._write(line)

    def _flush_remaining(self) -> None:
        while True:
            try:
                line = self._queue.get_nowait()
            except queue.Empty:
                return
            self._write(line)
