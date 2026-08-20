# 기여 가이드

## 기본 흐름

```powershell
git switch main
git pull --ff-only
git switch -c feat/attacker-runtime-foundation
```

브랜치 이름은 사람 이름이 아니라 작업 목적을 나타냅니다. 한 브랜치에는 한 가지 검토 가능한 변경만 포함하고 PR 병합 후 삭제합니다.

## 브랜치 예시

```text
feat/attacker-scenario-planner
feat/defender-broker-protocol
chore/docker-attacker-image
chore/docker-defender-image
chore/docker-compose-integration
docs/reference-index
fix/defender-verdict-timeout
```

`attacker`, `defender`, `docker`, `develop`, `integration` 같은 장기 작업 브랜치는 만들지 않습니다.

## 구현 순서

1. GitHub Issue에서 목적, 담당자와 완료 조건을 확인합니다.
2. 필요한 경우 설계 PR을 먼저 제출합니다.
3. 테스트를 먼저 작성하고 실패를 확인합니다.
4. 최소 구현으로 테스트를 통과시킵니다.
5. 전체 관련 테스트와 macOS/Linux의 `bash scripts/check-layout.sh` 또는 Windows의
   `scripts/check-layout.ps1`을 실행합니다.
6. PR 템플릿에 명령과 결과, 위험과 롤백 방법을 기록합니다.
7. 필수 검토자 승인 후 팀장이 병합합니다.

## 필수 검토

- 공격 Python: 팀장
- 방어 Python: 팀장
- 공격 Dockerfile: 공격 담당자와 팀장
- 방어 Dockerfile: 방어 담당자와 팀장
- 통합·CI: 영향받는 에이전트 담당자와 팀장
- 공통 계약: 영향받는 담당자와 팀장

## 에이전트에서 Docker로 전달할 정보

- 실행 명령과 필수·선택 환경변수
- 런타임 의존성과 테스트 명령
- 정상 시작 로그와 종료 코드
- 재시작·상태 저장·소켓·네트워크 요구사항
- 비밀값 비출력 검증

## Docker에서 팀으로 전달할 정보

- 재현 가능한 빌드와 실행 명령
- 이미지 이름, 태그, digest와 크기
- 독립 smoke test와 공식 스켈레톤 통합 결과
- 시작 시간, 종료 동작과 주요 로그
