# 본선 인터페이스 계약

이 디렉터리는 공격·방어 전략과 무관하게 반드시 지켜야 하는 본선 실행 계약을 기록합니다.

## 우선순위

1. 최신 본선 운영세칙과 당일 공통 운영 안내
2. 공식 `deploy/docs/agent-guide.md`
3. 공식 스켈레톤의 실제 동작
4. 이 저장소의 계약 문서와 테스트

운영진 규격이 바뀌면 구현보다 먼저 이 문서와 계약 테스트를 갱신합니다.

## 분리 원칙

- 공격 계약은 [`attacker/README.md`](attacker/README.md)에서 관리합니다.
- 방어 계약은 [`defender/README.md`](defender/README.md)에서 관리합니다.
- LLM 모델·API 종류·quota는 [`llm/`](llm/)에서 관리합니다.
- Break 후보의 독립 루브릭·결합 결과·사람 승인은 [`break-copilot/`](break-copilot/) JSON Schema로
  고정합니다.
- 바이너리 예시는 [`fixtures/`](fixtures/)에 저장합니다.
