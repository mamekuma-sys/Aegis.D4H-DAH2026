# 코드 소유권과 리뷰

## 역할

| 역할 | 주 담당 경로 | 핵심 책임 |
|---|---|---|
| 공격 담당자 | `agents/attacker/**`의 Python·테스트, `research/attack-scenarios.md` | 공격 설계·구현·테스트와 Docker 실행 계약 전달 |
| 방어 담당자 | `agents/defender/**`의 Python·테스트, `research/defense-mapping.md` | 방어 설계·구현·테스트와 300ms 성능 계약 전달 |
| Docker 담당자 | 양쪽 Dockerfile, `integration/**`, 이미지 관련 `scripts/**`와 CI | 독립 이미지 빌드·smoke test·스켈레톤·Registry 연동 |
| 팀장 이경준 | `contracts/**`, 공통 문서, `docs/references/**`, 최종 병합 | 요구사항·계약·PR·통합 결과 검증과 최종 승인 |

## 공동 소유

- Python 의존성은 에이전트 담당자가 제안하고 Docker 담당자가 설치·고정·이미지 크기를 검증하며 팀장이 승인합니다.
- 공격 Dockerfile은 Docker 담당자가 작성하고 공격 담당자와 팀장이 검토합니다.
- 방어 Dockerfile은 Docker 담당자가 작성하고 방어 담당자와 팀장이 검토합니다.
- `contracts/**` 변경은 영향받는 담당자에게 알린 후 팀장이 확정합니다.

## 금지사항

- 공격·방어 담당자는 Dockerfile과 공통 계약을 단독 확정하지 않습니다.
- Docker 담당자는 전략 코드를 담당자 동의 없이 수정하지 않습니다.
- 팀장을 포함한 누구도 `main`에 직접 작업하거나 강제 push하지 않습니다.
- 실제 GitHub 계정이 확인되기 전에는 추측한 이름으로 `CODEOWNERS`를 만들지 않습니다.

## 필수 검토자

| 변경 | 필수 검토자 |
|---|---|
| 공격 Python·테스트 | 팀장 |
| 방어 Python·테스트 | 팀장 |
| 공격 Dockerfile | 공격 담당자, 팀장 |
| 방어 Dockerfile | 방어 담당자, 팀장 |
| 통합·이미지 CI | 영향받는 에이전트 담당자, 팀장 |
| 공통 계약 | 영향받는 담당자, 팀장 |
