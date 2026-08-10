# Attacker

공격 담당자 전용 작업 영역입니다.

## 예정 구조

- `src/aegis_attacker/`: 공격 런타임 패키지
- `tests/`: 공격 단위·계약 테스트
- `Dockerfile`: 공격 이미지 정의
- `requirements.txt`: 공격 이미지 런타임 의존성

## 설계 게이트

구현 전 관측 입력, 표적 상태, 도구 실행 경계, S1~S5 가설 선택, 플래그 생명주기와 rate limit 정책을 합의합니다. 예선의 `AttackSimulationAgent`는 합성 이벤트 생성기이므로 실제 공격 런타임으로 복사하지 않습니다.
