# DAH 2026 리허설 감사 보강 작업 인계

## 현재 상태

- 팀 번호: 1
- 리허설 URL: https://rade.dev.ctf-zone.com/
- 계정·비밀번호·Registry token: 저장소에 기록하지 않음
- 현재 PR: Round FlagStore persistence, cross-cycle/concurrent dedup,
  actual transport reporting, immutable image context와 revision verification
- 현재 정책: 11개 rule 모두 `SHADOW`; 정상 baseline 확보 전까지 승격하지 않는다.
- 마지막으로 review remediation 이전에 clean-build를 확인한 이미지 SHA: `f07f6b25877de8ae38e12380d8f6eb020dce692c`
- 새 final-SHA clean build와 이미지 검증은 Task 5에서 수행할 예정이다. 이 문서가 포함된 커밋의 SHA는 문서에 기록하지 않고, handoff 커밋 이후 PR 검증 기록에 남긴다.
- deferred: Registry 인증·push 방식, pull 마감, 공식 스켈레톤 30초 동시 실행

## 이번 PR에서 완료된 범위 (Tasks 1~3)

1. Round 하나의 scan cycle 사이에서 `FlagStore`와 제출 상태를 보존하고, cross-cycle 및 concurrent 중복 제출을 제거했다.
2. 실제 flag submit transport 호출만 제출 통계에 반영하도록 결과를 연결했다.
3. 이미지 build context를 committed tree에서 만들고, 이미지 revision provenance를 검증하도록 보강했다.
4. Round deadline 이후 새 scan cycle을 시작하지 않도록 경계를 적용했다.

## Deferred 리허설 작업

다음 항목은 아직 구현·검증 완료로 표시하지 않는다.

- 리허설 감사 계획 Task 2: attacker target/DNS 범위 강화
- Task 3: defender 물리 송신 E2E latency 관측
- Task 4: bounded TCP flow 재조립과 immutable verdict snapshot 연결
- Task 5: 필수 worker watchdog
- Task 6의 미구현분: CI gate, README·preflight verifier 및 관련 운영 검증

따라서 전체 감사 계획은 아직 완료되지 않았다. 실제 LLM accepted 결과와 policy 승격도 리허설 외부 입력과 baseline 검증 전까지 별도 `BLOCKED`로 보고한다.

## 재개 및 운영 경계

- 공식 스켈레톤은 저장소 밖의 운영진 제공 경로에서만 사용한다.
- Registry login/push와 실제 리허설 대상 요청은 운영진 입력과 별도 명시 권한이 있을 때만 수행한다.
- 새로운 공격·방어 전략을 추가하지 않으며 defender packet hot path에서 원격 LLM을 기다리지 않는다.
- flow 재조립 원문은 로그, snapshot, LLM prompt, disk에 남기지 않는다.
- `.env`, token, API key, flag, PCAP, log, cache 및 생성 이미지는 commit하지 않는다.

## Task 5 인계 검증

Task 5에서 전체 회귀·layout·skeleton·Compose 검사를 수행하고, 최종 remediation SHA로 attacker/defender `linux/amd64` 이미지를 clean-build 및 inspect한다. 두 이미지의 revision label이 최종 SHA와 일치하는지 확인한 뒤 PR 검증 기록에 결과를 남긴다.
