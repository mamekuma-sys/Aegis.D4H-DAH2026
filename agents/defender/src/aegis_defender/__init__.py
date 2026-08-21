"""Aegis 방어 런타임 패키지.

PACKET 수신 → 제한된 파싱 → 결정론적 판정 → VERDICT 송신 → 비동기 상관분석.
설계 근거: docs/superpowers/specs/2026-08-11-defender-runtime-design.md

표준 라이브러리만 사용한다(런타임 의존성 없음). 설계 §9.3의 근거는 다음과 같다.
레퍼런스 이미지가 `python:3.12-slim` + `USER 65534`로 실행되므로 외부 다중패턴
라이브러리를 넣으면 이미지 검증 부담과 Docker 담당자 승인 절차가 생긴다.

설계의 핵심 불변조건 세 가지를 패키지 전체에서 지킨다.

1. 불확실하면 빠르게 `ACCEPT`한다. parser 예외, 미지원 protocol, queue full,
   LLM 장애는 어느 것도 `DROP` 사유가 아니다(§6.2).
2. 소켓에 쓰는 주체는 `SocketWriter` 단일 스레드 하나뿐이다(§4.2).
3. 원격 LLM은 packet별 동기 판정 경로에 들어가지 않는다(§0.5, §12).
"""

__version__ = "0.2.3-llm-advisory-burn"
