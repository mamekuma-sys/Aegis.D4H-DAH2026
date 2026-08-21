"""Aegis 공격 런타임 패키지.

관측 → 계획 → 실행 → flag 제출의 누적 적응형 공격 에이전트.
설계 근거: docs/superpowers/specs/2026-08-11-attacker-runtime-design.md

표준 라이브러리만 사용한다(런타임 의존성 없음). 이미지 시작 경로를 짧게 유지하고
AI 진위 증빙(운영세칙 제23조)을 단순하게 만들기 위한 선택이다.
"""

__version__ = "0.9.0-final-g2dds"
ATTACK_PROFILE = "gpt-5.4+det-first+g2dds+r13-lfi+protocol-lock+llm2000x20+persistent"
