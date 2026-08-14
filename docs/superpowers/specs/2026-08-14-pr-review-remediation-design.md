# PR 병합 전 리뷰 보강 설계

- 작성일: 2026-08-14
- 상태: 사용자 설계 승인, 구현 전
- 기준 범위: `aa1c4b57b885a9bfa4fbd6921ac6a88a4f67e2ea..f07f6b25877de8ae38e12380d8f6eb020dce692c`
- 선행 설계: `2026-08-14-rehearsal-audit-remediation-design.md`

## 1. 목적

PR 병합 전 독립 리뷰에서 확인된 네 가지 간극을 기존 리허설 보강 설계의 불변조건에 맞춘다.

1. 이미지 revision label이 가리키는 commit과 실제 build context의 바이트를 일치시킨다.
2. 실제 제출 transport 호출만 Round 제출 통계에 반영한다.
3. production `run_forever()`가 공식 20분 Round deadline 뒤 새 scan cycle을 시작하지 않게 한다.
4. handoff 문서가 이미 완료된 작업을 미수정 상태로 설명하지 않게 한다.

새로운 공격·방어 전략, Registry 작업, 공식 스켈레톤 실행은 이 보강에 포함하지 않는다.

## 2. 결정과 대안

### 2.1 선택한 방식

- Docker build context는 live worktree가 아니라 `git archive HEAD`에서 만든 임시 staging tree를 사용한다.
- 제출 결과는 `SubmitResult(state, attempted)`로 표현한다.
- Round 생성 시 단일 monotonic deadline을 저장하고 제출 재시도와 scan loop가 같은 값을 공유한다.
- 기존 handoff 문서를 현재 상태와 명시적 deferred 범위로 갱신한다.

### 2.2 선택하지 않은 방식

`.dockerignore`만 추가하는 방식은 repository-local ignore만 다루며 global ignore나 이후 추가되는 패턴을 놓칠 수 있다. 이미지가 commit 바이트만 포함한다는 provenance 증명으로는 부족하다.

`SubmitClient.is_configured()`를 pipeline이 사전 확인하는 방식은 설정 유무와 실제 transport 시도를 혼동한다. 첫 요청 뒤 429·parse error가 발생한 경우에도 transport 시도는 기록되어야 하므로 결과 객체가 시도 여부를 직접 전달한다.

컨테이너가 20분에 종료된다는 외부 동작에만 의존하는 방식은 secret TTL과 scan loop의 경계를 분리한다. runtime 자체도 deadline 뒤 새 작업을 시작하지 않아야 한다.

## 3. Immutable Docker build context

`scripts/build-images.sh`는 다음 순서를 지킨다.

1. `git rev-parse HEAD`로 full SHA를 얻는다.
2. `git status --porcelain`이 비어 있지 않으면 중단한다.
3. `mktemp -d`로 임시 staging root를 만들고 종료 시 그 정확한 경로만 제거한다.
4. `git archive --format=tar HEAD agents/attacker agents/defender` 출력을 staging root에 푼다.
5. Docker에는 staging root 아래 `agents/attacker`, `agents/defender`만 context로 전달한다.
6. 기존 revision·platform·CMD·USER·secret-env inspect를 그대로 수행한다.

따라서 build context에 들어가는 파일 집합과 내용은 label의 SHA가 가리키는 Git tree에서만 온다. worktree의 ignored `.env`, `__pycache__`, 로그, 생성 파일은 이미지에 포함될 수 없다. staging 경로와 archive 내용은 출력하지 않는다.

archive 또는 extract가 실패하면 Docker를 호출하지 않고 non-zero로 종료한다. 임시 staging root는 성공·실패 모두 정리한다.

## 4. 실제 제출 시도 모델

`SubmitClient.submit()`은 `SubmitState` 단독 대신 immutable `SubmitResult`를 반환한다.

- 제출 URL 또는 token handle이 없으면 `SubmitResult(ERROR, attempted=False)`다.
- `EgressGateway.request()`를 한 번이라도 호출하면 최종 state와 관계없이 `attempted=True`다.
- 429가 Round deadline을 넘어 재시도를 중단해도 첫 요청은 실제 전송됐으므로 `attempted=True`다.
- transport 전에 secret resolve가 예외를 내면 기존처럼 예외를 전달하고 `FlagPipeline`이 claim을 해제한다.

`FlagPipeline`은 state를 `FlagStore`에 기록하고 `(fingerprint, state, attempted)`를 반환한다. terminal cache hit와 concurrent claim loser는 `attempted=False`다. `AttackerRuntime._process_flags()`는 `attempted=True`인 결과만 `RoundReport.record_submit()`에 전달한다.

이 변경은 `ERROR` 재발견 시 다음 시도를 허용하는 현재 정책과 terminal state 중복 방지를 유지한다.

## 5. 20분 Round deadline

`AttackerRuntime._build_round()`은 `now + ROUND_DURATION`을 `_round_deadline`에 한 번 저장하고 같은 값을 `SubmitClient`에 전달한다.

`run_forever()`는 다음 규칙을 사용한다.

- deadline에 도달했으면 새 `run_cycle()`을 시작하지 않는다.
- cycle이 deadline 전에 시작했지만 실행 중 deadline을 넘으면 그 cycle의 bounded 요청을 마친 뒤 종료한다.
- 다음 cycle 전 sleep은 `min(LOOP_SLEEP, remaining)`이며 remaining이 0 이하면 sleep하지 않는다.
- `max_cycles` 테스트 경계와 20분 deadline 중 먼저 도달한 조건이 loop를 끝낸다.
- 모든 종료 경로는 기존 `finally`를 통해 `finish_round()`를 호출하고 Round secret을 폐기한다.

외부 컨테이너 종료는 여전히 hard boundary다. 이번 변경은 실행 중인 endpoint 작업을 강제 취소하거나 thread cancellation을 추가하지 않는다.

## 6. Handoff 갱신

`docs/superpowers/handoffs/2026-08-14-rehearsal-audit-remediation.md`의 현재 상태를 다음처럼 갱신한다.

- Task 1의 Round 상태 보존과 cross-cycle/concurrent 회귀는 완료로 기록한다.
- clean build·revision 검증의 완료 범위와 정확한 검증 SHA를 기록한다.
- 팀 번호 1과 공개 리허설 URL은 기록하되 계정, 비밀번호, token은 기록하지 않는다.
- Registry 인증·push 방식, pull 마감, 공식 스켈레톤 30초 동시 실행은 deferred로 명시한다.
- 나머지 감사 계획 Task 2~5와 전체 Task 6은 구현 완료라고 표현하지 않는다.

초기 인계 시점의 사실은 역사적 기록으로 구분하고 현재 상태의 출처로 사용하지 않는다.

## 7. 테스트 전략

각 behavior 수정은 RED를 먼저 확인한다.

1. build script contract test는 agent context 안에 ignored marker를 만들고 fake Docker가 받은 context에 marker가 없으며 경로가 live worktree가 아님을 확인한다. archive/extract 실패가 Docker 호출 전에 전파되는 경우도 검증한다.
2. flag pipeline test는 제출 설정이 없을 때 `ERROR, attempted=False`이고 transport와 Round submit 통계가 증가하지 않음을 확인한다. 429 deadline 경로는 `attempted=True`를 확인한다.
3. runtime test는 짧게 patch한 `ROUND_DURATION`과 fake monotonic clock으로 deadline에서 loop가 끝나고 secret이 폐기되며 sleep이 remaining을 넘지 않음을 확인한다.
4. handoff는 완료·deferred 문구와 금지된 credential 부재를 정적 검사한다.

항목별 GREEN 뒤 attacker 전체 164개 이상, defender 전체 275개, build script contract, macOS layout·skeleton·Compose 동등 검사, `git diff --check`를 실행한다. 최종 commit에서 두 이미지를 다시 clean no-cache build·inspect하고 revision이 최종 SHA와 같은지 확인한다.

## 8. 완료 조건

- Docker가 받는 agent context는 `git archive HEAD`에서만 생성된다.
- ignored worktree 파일을 만들어도 이미지 context에 들어가지 않는다.
- 제출 설정이 없는 경로는 submit 통계를 증가시키지 않는다.
- 실제 transport 요청이 한 번이라도 발생한 결과는 최종 state가 `ERROR`여도 한 번 기록된다.
- `run_forever()`는 Round deadline 뒤 새 cycle이나 sleep을 시작하지 않는다.
- deadline 종료에서도 Round secret이 폐기된다.
- handoff가 완료·deferred 상태를 현재 사실과 일치하게 설명하고 credential을 포함하지 않는다.
- 전체 회귀와 최종 SHA 이미지 provenance 검증이 통과한다.

## 9. 비범위

- attacker target/DNS 범위 강화
- defender 물리 송신 E2E latency, TCP 재조립, worker watchdog
- policy 승격 또는 새 공격 전략
- Registry login·push·pull
- 공식 스켈레톤에서 30초 동시 실행
- GitHub Actions 확대
