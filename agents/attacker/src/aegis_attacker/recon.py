"""결정론적 저비용 사전 정찰.

설계 §9.4·§9.12. LLM 조언을 쓰기 전에 흔한 flag 위치를 읽기 전용 GET으로 먼저 찔러
쉬운 flag를 **토큰 0으로** 획득한다. 동점 시 LLM 토큰 비용이 적은 팀이 이기므로(운영세칙
제22조) 결정론 정찰이 유리하다. 모든 프로브는 READ_ONLY이며 rate limit·범위 검사를 거친다.
"""

from __future__ import annotations

import re

# 흔한 flag·노출 경로(읽기 전용). 짧게 유지해 요청 예산을 아낀다.
COMMON_PROBE_PATHS = (
    "/flag",
    "/flag.txt",
    "/flags",
    "/FLAG",
    "/secret",
    "/admin",
    "/robots.txt",
    "/.git/config",
    "/registry",
    "/api/flag",
    "/status",
    "/debug",
)

# robots.txt 지시자(추가 경로 노출)와 본문 속 경로 토큰을 추출한다.
_ROBOTS_RE = re.compile(r"(?im)^\s*(?:Allow|Disallow|Sitemap)\s*:\s*(\S+)")
_PATH_RE = re.compile(r"(?<![\w.])/[A-Za-z0-9_][A-Za-z0-9_./\-]{0,60}")

# 정찰 대상이 아닌 정적 자원 확장자(요청 예산 절약).
_SKIP_SUFFIXES = (".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff", ".woff2")

MAX_DISCOVERED_PATHS = 8


def discover_paths(text: str) -> list:
    """배너·robots·오류 본문에서 노출된 경로 후보를 추출한다(READ_ONLY 정찰용).

    robots.txt 의 Allow/Disallow/Sitemap 지시자와 본문 속 `/path` 토큰을 순서 유지·중복
    제거로 모은다. 상대 방어 필터를 건드리지 않는 단순 GET 대상만 반환한다.
    """
    if not text:
        return []
    seen = set()
    out = []

    def _add(raw: str) -> None:
        path = raw.split("#", 1)[0].strip()
        if not path.startswith("/") or len(path) < 2:
            return
        if any(path.lower().endswith(sfx) for sfx in _SKIP_SUFFIXES):
            return
        if path not in seen:
            seen.add(path)
            out.append(path)

    for m in _ROBOTS_RE.findall(text):
        _add(m)
    for m in _PATH_RE.findall(text):
        _add(m)
    return out[:MAX_DISCOVERED_PATHS]
