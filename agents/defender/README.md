# Defender

방어 담당자 전용 작업 영역입니다.

## 예정 구조

- `src/aegis_defender/`: 방어 런타임 패키지
- `tests/`: 방어 단위·계약 테스트
- `Dockerfile`: 방어 이미지 정의
- `requirements.txt`: 방어 이미지 런타임 의존성

## 설계 게이트

구현 전 패킷 가시성, 파서 경계, 300ms 동기 정책, 온라인 상관 상태, 비동기 AI 조언과 오탐 제어를 합의합니다. 원격 LLM 호출은 패킷별 동기 verdict 경로에 넣지 않습니다.
