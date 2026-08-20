"""결정론적 저비용 사전 정찰.

설계 §9.4·§9.12. LLM 조언을 쓰기 전에 흔한 flag 위치를 읽기 전용 GET으로 먼저 찔러
쉬운 flag를 **토큰 0으로** 획득한다. 동점 시 LLM 토큰 비용이 적은 팀이 이기므로(운영세칙
제22조) 결정론 정찰이 유리하다. 모든 프로브는 READ_ONLY이며 rate limit·범위 검사를 거친다.
"""

from __future__ import annotations

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
    "/fetch",
    "/api/flag",
    "/status",
    "/debug",
    # L4를 특정 도메인 경로로 추측하지 않고, 서비스가 스스로 route/schema를
    # 공개하는 표준적인 읽기 전용 진입점만 확인한다.
    "/health",
    "/api",
    "/openapi.json",
    "/swagger.json",
)
