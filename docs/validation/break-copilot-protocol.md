# Break Copilot 운영 프로토콜

## 목적과 경계

Break Copilot은 라운드 사이에 전달된 capture/log를 비식별 파생 증거로 바꾸고, LLM의 분석과
코드 패치 제안을 격리된 후보 worktree에서 검증하는 로컬 도구다. 실행 중인 공격·방어 컨테이너를
스스로 수정하지 않으며, Defender의 패킷별 300ms 동기 판정 경로에는 원격 LLM을 넣지 않는다.

사실의 우선순위는 최신 당일 공지, 공식 `deploy/docs/agent-guide.md`, 공식 스켈레톤 관측,
실제 라운드 증거, 예선 자료, 팀 문서 순서다. 파일명의 Phase/Round 표기는 공식 mapping이
확정될 때까지 단순 evidence label로만 취급한다.

## 안전 흐름

```text
raw capture/log (저장소 밖)
  -> 안정성 확인 + SHA-256 ID
  -> 구조 정보만 추출 + 비밀정보 제거
  -> sanitized manifest (captures/ 아래, gitignore)
  -> gpt-5.6-sol 원인 분석
  -> gpt-5.3-codex 단일-side unified diff 제안
  -> 경로/크기/비밀/바이너리 검사
  -> 별도 short-lived worktree에 적용
  -> 고정 테스트 + replay + 선택적 scrimmage
  -> AI/사람 독립 루브릭
  -> 사람 승인 JSON
  -> clean commit 이미지 build
  -> 명시적 -Push일 때만 Registry latest push
```

원본, prompt 전문, API key, flag, token, cookie, payload는 산출물에 저장하지 않는다. 산출물 기본
위치는 이미 무시되는 `captures/break-copilot/<run-id>/`다. evidence ID는 원본 SHA-256 앞 12자를
사용하며, 원본 파일명은 경로를 제거한 뒤 안전한 label 또는 template hash로만 기록한다.

## 5분 Break 권장 타임박스

| 경과 | 작업 | 중단 조건 |
|---:|---|---|
| 0~30초 | 입력 안정성·해시·비식별 ingest | 파일이 계속 쓰이는 중, 허용되지 않은 형식 |
| 30~90초 | Sol 분석 | 근거 ID 없는 주장, LLM key 사용 불가 |
| 90~150초 | Codex 패치 후보 | 양쪽 agent 동시 변경, 제한 경로 밖 변경 |
| 150~240초 | 단위 테스트·layout·diff·replay | 기존 회귀 또는 hard gate 실패 |
| 240초 이후 | 사람 리뷰·승인·clean commit·build | 검토자 미지정, 평가 digest 불일치 |
| 공지 cutoff 전 | 선택적 `latest` push | `-Push` 미지정, Registry 미로그인 |

운영진 pull 시각과 당일 변경 공지가 이 표보다 우선한다. 팀이 이미지를 push하면 운영진이 정해진
시점에 pull한다. 자동 push나 운영진 환경으로의 pull 요청은 이 도구의 역할이 아니다.

## 모델과 비용 정책

- 분석 기본값: `gpt-5.6-sol`
- 코드 패치 기본값: `gpt-5.3-codex`
- 둘 다 대회 계약대로 LiteLLM의 `/v1/chat/completions`를 사용한다.
- 호출 모델은 `contracts/llm/model-quotas.json` allowlist에 있어야 한다.
- 자동 `run`은 분석 1회와 패치 1회만 호출하며 재시도하지 않는다. 분석 입력 180KB, 코드 context
  140KB, 출력 2,200/5,000 token으로 제한한다. 최종 AI 루브릭은 사람이 별도로 요청할 때 1회다.
- 호출·token 사용량은 ledger에 남기지만, 당일 가격표가 없으므로 비용을 추정해 사실처럼 쓰지 않는다.
- `LLM_API_KEY`가 Break 도구에서 사용 가능한지와 Break 시간 사용이 허용되는지는 당일 운영진에게
  확인한다. 불명확하면 `ingest`와 사람이 직접 작성·검토하는 분석까지만 사용한다.

## 명령 예시

macOS에서 zsh와 PowerShell Core를 병행하는 전체 준비 절차는
[`macOS 본선 Break 운영 런북`](macos-finals-runbook.md)을 따른다.

```powershell
# 0. 전날/당일 사전 점검. 실제 API 호출은 하지 않는다.
pwsh -NoProfile -File scripts/break-copilot.ps1 preflight --require-llm --require-docker
# preflight가 sandbox_test_image를 실패하면 Break 전에 한 번만 준비한다.
docker pull python:3.12-slim

# 1. 원본은 저장소 밖 경로로 전달한다.
pwsh -NoProfile -File scripts/break-copilot.ps1 ingest --input <capture-or-log> --side defender

# 2. 비식별 manifest를 분석한다.
pwsh -NoProfile -File scripts/break-copilot.ps1 analyze --manifest <manifest.json>

# 3. 분석 결과로 패치를 제안하고 로컬 검사를 통과시킨다.
pwsh -NoProfile -File scripts/break-copilot.ps1 propose --analysis <analysis.json> --side defender
pwsh -NoProfile -File scripts/break-copilot.ps1 validate-patch --patch <proposal.diff> --side defender

# 4. 명시한 후보 worktree에만 적용하고 검증한다.
pwsh -NoProfile -File scripts/break-copilot.ps1 prepare-candidate --candidate <candidate-path> --base-ref HEAD
pwsh -NoProfile -File scripts/break-copilot.ps1 apply --candidate <candidate-path> --patch <proposal.diff> --side defender
pwsh -NoProfile -File scripts/break-copilot.ps1 evaluate --candidate <candidate-path> --side defender --pcap <pcap-path>

# 5. owner가 diff를 검토·commit하고 같은 base-ref로 evaluate를 다시 실행한다.
pwsh -NoProfile -File scripts/break-copilot.ps1 evaluate --candidate <candidate-path> `
  --side defender --base-ref <candidate-base-commit> --pcap <pcap-path>

# 6. AI는 고정 결과·diff·비식별 evidence에 루브릭을 적용하고, 사람은 빈 템플릿을 독립 작성한다.
pwsh -NoProfile -File scripts/break-copilot.ps1 assess --candidate <candidate-path> `
  --base-ref <candidate-base-commit> --side defender --evaluation <evaluation.json> `
  --manifest <manifest.json> --scrimmage <comparison.json> --output <ai-readiness.json>
pwsh -NoProfile -File scripts/break-copilot.ps1 rubric-template `
  --candidate-id <candidate-commit> --evaluator human --output <human-readiness.json>

# 7. AI·사람 평가를 결합한다. 항목별 낮은 점수와 중재 규칙이 적용된다.
pwsh -NoProfile -File scripts/break-copilot.ps1 combine-rubric `
  --ai <ai-readiness.json> --human <human-readiness.json> --output <combined-rubric.json>

# 8. 역할별 검토자는 각 review와 최상위 decision을 APPROVE 또는 REJECT로 확정한다.
pwsh -NoProfile -File scripts/break-copilot.ps1 approval-template --candidate <candidate-path> `
  --evaluation <evaluation.json> --rubric <combined-rubric.json> --side defender `
  --agent-owner <name> --team-lead <name> --docker-owner <name>

# 9. 승인과 두 digest가 일치할 때만 build. -Push를 붙여야 Registry가 변경된다.
pwsh -NoProfile -File integration/promote-candidate.ps1 -CandidatePath <candidate-path> `
  -EvaluationPath <evaluation.json> -RubricPath <combined-rubric.json> `
  -ApprovalPath <approval.json> -Agent defender -TeamNumber 1
```

`prepare-candidate`는 `break/<run-id>` short-lived branch를 만든다. 후보를 merge한 뒤 branch와 worktree는
팀 절차로 제거한다. 원본 스켈레톤은 항상 저장소 밖에 두고 수정하지 않는다.
LLM patch가 포함된 단위 테스트와 replay는 `python:3.12-slim` 컨테이너에서 network none,
read-only root/repository, no-new-privileges, cap-drop ALL, PID·memory·CPU·tmpfs 제한으로만 실행한다.
평가 결과에는 실제 로컬 sandbox image ID를 기록한다. 당일에는 검증한 digest를
`BREAK_COPILOT_TEST_IMAGE`로 고정할 수 있다.
도구는 원격 branch를 자동 pull/rebase하지 않는다. `--base-ref`는 현재 `origin/main` commit과
정확히 같아야 하며, 원격이 없는 격리 테스트 저장소에서만 로컬 `main`을 기준으로 사용한다. 후보의
기존 단위 테스트는 trusted gate라 수정할 수 없고 `test_*.py` 신규 파일만 추가할 수 있다.

승인 역할은 GitHub 계정에 고정한다. 공격 owner는 `kts6450`, 방어 owner는 `apple1231`, Docker
owner는 `bigparty31`, 팀장은 `mamekuma-sys`다. 세 역할은 서로 다른 계정이어야 하며 side와 다른
owner 이름이나 자유 입력 이름으로는 승인 검증을 통과할 수 없다.

## 실패 시 행동

- 분석이 불충분하면 코드 상태를 바꾸지 않고 evidence manifest와 다음 관측 목록만 보존한다.
- Defender 후보가 300ms E2E, heartbeat, 재연결을 실제 Broker에서 재검증하지 못하면 `READY`가 아니다.
- L4처럼 실제 parser 입력이 없는 레이어는 observation-only를 유지한다.
- 스켈레톤 결함으로 scrimmage가 불가능하면 그 결함을 결과에 표시하며 합성 테스트를 실전 검증으로
  승격하지 않는다.
