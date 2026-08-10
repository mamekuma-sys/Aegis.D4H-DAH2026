# 코드 소유권과 리뷰

## 역할

- 공격 담당자: `agents/attacker/**`, 공격 관련 테스트와 연구 문서
- 방어 담당자: `agents/defender/**`, 방어 관련 테스트와 연구 문서
- 팀장 이경준: `contracts/**`, `integration/**`, 공통 문서, CI, 전체 최종 리뷰

## 필수 교차 리뷰

다음 변경은 팀장 리뷰를 거칩니다.

- 공격 또는 방어 Dockerfile
- 본선 환경변수, 플래그 제출 형식, Broker 프레임
- 300ms verdict 또는 heartbeat 동작
- CI와 외부 스켈레톤 연동

## CODEOWNERS 적용 조건

실제 GitHub 사용자 또는 팀 이름이 확정되면 이 문서의 경계를 `.github/CODEOWNERS`에 옮깁니다. 확인되지 않은 계정 이름은 추측해서 기록하지 않습니다.
