# DAH 2026 리허설 감사 보강 작업 인계

## 재개 기준

- 작업 브랜치: `fix/rehearsal-audit-findings`
- 기준 main: `aa1c4b57b885a9bfa4fbd6921ac6a88a4f67e2ea`
- 공식 스켈레톤: `$env:USERPROFILE\Downloads\DAH2026_스켈레톤코드`
- 현재 정책: 11개 rule 모두 `SHADOW`; 정상 baseline 확보 전까지 승격하지 않는다.
- 실제 팀 번호, 리허설 접속 URL, Registry token은 아직 확인되지 않았다.

내일 시작할 때 다음 명령으로 위치와 상태를 확인한다.

```powershell
Set-Location "$env:USERPROFILE\Aegis.D4H-DAH2026"
git switch fix/rehearsal-audit-findings
git pull --ff-only
git status --short --branch
```

## 완료한 작업

1. 감사 finding을 구현 가능한 범위와 안전 경계로 재정리했다.
2. 다음 설계 문서를 작성하고 커밋했다.
   - `docs/superpowers/specs/2026-08-14-rehearsal-audit-remediation-design.md`
3. RED-GREEN 테스트, 변경 파일, Docker·공식 스켈레톤 검증 명령을 포함한 구현 계획을 작성하고 커밋했다.
   - `docs/superpowers/plans/2026-08-14-rehearsal-audit-remediation.md`
4. 첫 번째 작업인 attacker Round lifecycle의 기존 기준 테스트를 실행했다.

기준 테스트 결과:

```text
Command: wsl env PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.test_runtime.TestRuntimeResilience -v
Result: Ran 3 tests, OK
```

현재까지 production code와 test code는 변경하지 않았다. 즉, 감사에서 확인한 P1 중복 제출 결함은 아직 수정 전이다.

## 커밋 상태

```text
41a4a85 docs: design rehearsal audit remediation
e411e23 docs: plan rehearsal audit remediation
```

이 인계 문서와 설계 문서 EOF 정리는 다음 커밋에 포함된다.

사용자 소유의 미추적 파일 `docs/superpowers/plans/2026-08-13-pr-stack-review-and-merge.md`는 이번 작업에 포함하거나 수정하지 않는다.

## 다음 작업 순서

상세 단계와 예상 실패·성공 명령은 구현 계획 문서를 기준으로 한다.

1. **Task 1 — attacker Round 상태 보존**
   - `run_forever`의 두 scan cycle에서 같은 합성 flag가 두 번 제출되는 failing test를 먼저 추가한다.
   - RED를 확인한 뒤 공식 Round와 scan cycle을 분리한다.
   - 서로 다른 `run_once()` 호출은 서로 다른 Round라는 기존 의미를 유지한다.
2. **Task 2 — attacker target/DNS 범위 강화**
   - 선택적 `TEAM_NUMBER`로 자기 팀 target을 제외한다.
   - DNS answer 변경과 위험 IP를 transport 호출 전에 거부한다.
3. **Task 3 — defender 물리 송신 E2E latency**
   - `SocketWriter`의 `SendResult` callback을 `VerdictSender.record_result()`에 연결한다.
   - shutdown 로그에 p50/p95/p99/max와 outcome count를 남긴다.
4. **Task 4 — bounded TCP flow 재조립 연결**
   - verdict enqueue 이후 비동기 worker에서만 최대 16KB를 재조립한다.
   - immutable snapshot에는 payload 없이 matching `rule_id`만 게시한다.
   - 다음 packet의 기존 SHADOW/CANARY/ACTIVE 집행 경로에서 사용한다.
5. **Task 5 — 필수 worker watchdog**
   - writer, heartbeat, correlation의 조용한 사망을 탐지하고 non-zero 종료한다.
6. **Task 6 — CI·Docker provenance·README·preflight verifier**
   - attacker test와 두 이미지 `linux/amd64` build를 CI gate에 추가한다.
   - image revision label과 비파괴 리허설 검증 스크립트를 추가한다.
7. **Task 7 — 전체 검증**
   - attacker/defender 전체 test, layout, skeleton validator, Compose 계약 실행
   - 수정 SHA의 두 이미지 clean build 및 inspect
   - 공식 스켈레톤에서 최소 30초 round, latency, SIGTERM, reconnect 재검증

## 지켜야 할 결정

- 새로운 공격·방어 전략을 추가하지 않는다.
- defender packet hot path에서 원격 LLM을 기다리지 않는다.
- flow 재조립 원문은 로그, snapshot, LLM prompt, disk에 남기지 않는다.
- baseline 없이 policy를 CANARY/ACTIVE로 올리지 않는다.
- 공식 스켈레톤 파일을 수정하거나 저장소로 복사하지 않는다.
- `.env`, token, API key, flag, PCAP, log, cache를 commit하지 않는다.
- 각 behavior 변경은 test를 먼저 작성하고 올바른 이유로 실패하는 RED를 확인한다.
- Registry login/push와 실제 리허설 대상 요청은 운영진 입력과 별도 명시 권한이 있을 때만 수행한다.

## 완료 조건

현재 작업은 문서 단계까지만 완료됐다. 다음 조건을 모두 증명해야 전체 목표가 끝난다.

- 한 공식 Round의 반복 scan에서 같은 flag submit 호출이 한 번뿐이다.
- defender의 성공 VERDICT 수와 E2E latency 표본 수가 일치한다.
- split TCP signature가 bounded worker 재조립 후 snapshot에 기록된다.
- 필수 worker 사망 시 container가 살아 있는 척하지 않고 명시적으로 실패한다.
- 모든 unit/contract/layout 검사가 통과한다.
- 현재 commit에서 만든 두 `linux/amd64` 이미지에 올바른 revision이 기록된다.
- 공식 스켈레톤 30초 실행에서 PACKET=VERDICT, HEARTBEAT, 300ms E2E 지표, SIGTERM, reconnect가 확인된다.
- 실제 LLM accepted와 policy 승격은 리허설 외부 입력이 제공되기 전까지 별도 `BLOCKED`로 보고한다.
