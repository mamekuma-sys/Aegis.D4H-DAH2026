# Team Workflow and References Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Apply the approved four-person ownership model, task-branch and PR workflow, and private-original/reference-index policy to the repository.

**Architecture:** Team responsibilities remain path-oriented: attacker and defender own their Python implementations, Docker owns both image definitions and integration, and the team lead owns shared contracts and final review. Original competition documents and preliminary source stay outside Git; portable Markdown inventories record their identities, precedence, hashes, and mapping into finals code.

**Tech Stack:** Git, Markdown, PowerShell 7, GitHub pull requests and GitHub Actions

## Global Constraints

- Use short-lived task branches from the latest `main`; do not create person-specific long-lived branches.
- Do not commit original PDFs, preliminary source snapshots, official skeleton files, archives, credentials, tokens, PCAPs, logs, or personal absolute paths.
- Do not create `.github/CODEOWNERS` until real GitHub user or team names are confirmed.
- Attacker and defender owners write their own Python code and tests.
- Docker owner writes both Dockerfiles, integration scripts, image CI, and registry procedures without changing strategy code unilaterally.
- Team lead Lee Gyeong-jun approves shared contracts, all agent PRs, Docker integration, and final merges.
- Treat finals rules and same-day organizer guidance as higher priority than the preliminary guide, preliminary report, team notes, and prior code.
- Do not add attacker, defender, or Docker runtime implementations in this plan.
- Keep team-facing documentation in Korean and branch names, file names, and commit messages in English.

---

### Task 1: Portable reference inventory and source traceability

**Files:**
- Create: `docs/references/README.md`
- Create: `docs/references/source-inventory.md`
- Create: `docs/references/rules-checklist.md`
- Create: `docs/references/preliminary-code-map.md`
- Modify: `scripts/check-layout.ps1`

**Interfaces:**
- Consumes: `docs/superpowers/specs/2026-08-10-team-workflow-design.md`, the three original PDFs, the preliminary source snapshot, and the external `deploy` snapshot.
- Produces: Four portable reference documents and a layout gate that prevents raw competition artifacts from being tracked.

- [ ] **Step 1: Add the failing reference-layout and raw-artifact checks**

In `scripts/check-layout.ps1`, add these entries to `$requiredFiles` after `docs/ownership.md`:

```powershell
    'docs/references/README.md'
    'docs/references/source-inventory.md'
    'docs/references/rules-checklist.md'
    'docs/references/preliminary-code-map.md'
```

After `$trackedFiles = git -C $repoRoot ls-files`, add:

```powershell
$forbiddenTrackedExtensions = @('.pdf', '.zip', '.tar', '.gz', '.pcap', '.pcapng')
$trackedArtifacts = @()
foreach ($relativePath in $trackedFiles) {
    $extension = [System.IO.Path]::GetExtension($relativePath).ToLowerInvariant()
    if ($forbiddenTrackedExtensions -contains $extension) {
        $trackedArtifacts += $relativePath
    }
}

if ($trackedArtifacts.Count -gt 0) {
    Write-Error ("Raw or generated artifacts are tracked:`n- " + (($trackedArtifacts | Sort-Object -Unique) -join "`n- "))
    exit 1
}
```

- [ ] **Step 2: Run the layout check and verify the expected failure**

Run:

```powershell
pwsh -NoProfile -File scripts/check-layout.ps1
```

Expected: exit code 1 listing exactly the four missing files under `docs/references/`. It must not report any tracked raw artifact.

- [ ] **Step 3: Create the reference policy and inventory**

Create `docs/references/README.md`:

```markdown
# 대회 자료 참조 정책

이 디렉터리는 원본 파일을 보관하지 않고, 팀원이 동일한 자료를 확인하고 구현 근거를 추적할 수 있는 메타데이터만 관리합니다.

## 근거 우선순위

충돌이 발생하면 다음 순서로 판단합니다.

1. 최신 본선 운영세칙과 본선 당일 공통 운영 안내
2. 공식 스켈레톤의 `deploy/docs/agent-guide.md`
3. 공식 스켈레톤의 실제 동작
4. 예선 안내서와 Aegis.0xD4H 예선 보고서
5. 예선 제출 소스
6. 팀이 작성한 연구·설계 문서

## 원본 보관

원본 PDF, 예선 소스, 공식 스켈레톤과 운영진 공지는 팀장이 지정한 비공개 팀 저장소에 보관합니다. 재배포 권한을 확인하기 전에는 현재 Git 저장소에 원본을 추가하지 않습니다.

## 동일성 확인

일반 파일은 SHA-256으로 확인합니다.

```powershell
$originalPath = Read-Host '원본 파일 경로'
Get-FileHash -Algorithm SHA256 -LiteralPath $originalPath
```

디렉터리 snapshot은 상대경로를 POSIX 형식으로 정렬하고, 각 파일에 대해 `상대경로 + NUL + 파일 SHA-256 소문자 hex + LF`를 이어 붙인 값의 SHA-256으로 식별합니다. 파일 추가·삭제·이름 변경·내용 변경 중 하나라도 발생하면 tree hash가 달라집니다.

## 갱신 절차

1. 운영진의 새 문서 또는 스켈레톤을 비공개 원본 저장소에 보존합니다.
2. 파일명, 날짜, 크기와 SHA-256을 `source-inventory.md`에 추가합니다.
3. 변경된 규칙을 `rules-checklist.md`에 반영합니다.
4. 계약이 달라지면 `contracts/`와 자동 테스트를 먼저 수정합니다.
5. 영향받는 공격·방어·Docker 담당자에게 알리고 팀장이 변경을 승인합니다.
```

Create `docs/references/source-inventory.md`:

```markdown
# 원본 자료 인벤토리

기준일: 2026-08-10

| ID | 원본 파일 또는 snapshot | 크기·파일 수 | SHA-256 | Git 정책 |
|---|---|---:|---|---|
| PRELIM-GUIDE | `DAH 예선_안내서.pdf` | 201,795 bytes | `F23CC3F96A1AA2FFBEBB9A46AFD82DBCEC34D72A5342B3EBEAB5E954666770BF` | 원본 커밋 금지 |
| PRELIM-REPORT | `DAH2026_예선보고서_Aegis.0xD4H.pdf` | 2,589,793 bytes | `1DD42B99A8816C3B7A543929BA0AEE90E5565CFC853E19E1455F76631CD1894E` | 원본 커밋 금지 |
| FINALS-RULES | `DAH2026_본선운영세칙.pdf` | 384,262 bytes | `FFE8E6BEECB628F93F20A9F5D0F41203CADBF28EE7E56C9A91FDAB87A1655A5F` | 원본 커밋 금지 |
| PRELIM-SOURCE | `DAH2026_소스코드_Aegis.0xD4H/` tree snapshot | 115 files | `62320D2100C4BE70997CE595C8952FE924D8EF17061F8575DA0AB753E58C6402` | 원본 tree 커밋 금지 |
| OFFICIAL-SKELETON | `deploy/` tree snapshot | 34 files | `8B7552FB285C3DBB75285BB083F09A5B72322B867F2472A873C2C738C20C73CE` | 외부 통합 시험장으로 유지 |

## 보관과 접근

- 원본 접근 위치는 Git이 아닌 팀 내부 채널에서 팀장이 공지합니다.
- 자격증명이나 개인 PC 절대경로는 이 문서에 기록하지 않습니다.
- 새로운 버전은 기존 행을 덮어쓰지 않고 별도 행으로 추가합니다.
- 운영세칙과 스켈레톤은 버전 또는 수령일을 함께 기록합니다.

## Tree hash 주의사항

`PRELIM-SOURCE` hash에는 snapshot 안의 생성 파일과 캐시도 포함되어 원본 폴더 전체의 동일성을 식별합니다. 본선 코드로 이식할 때는 `.pyc`, `__pycache__`, `output`과 생성 데이터는 복사하지 않습니다.
```

- [ ] **Step 4: Create the rules checklist and preliminary-code map**

Create `docs/references/rules-checklist.md`:

```markdown
# 규칙 및 인터페이스 체크리스트

## 자료별 용도

| 자료 | 사용하는 내용 | 사용하지 않는 내용 |
|---|---|---|
| 예선 안내서 | 예선 평가 목적, 제출물 범위, 평가 항목 | 본선 실행 인터페이스 추정 |
| 예선 보고서 | A1~A5, S1~S5, 상관분석, 가용성 우선 원칙 | 합성 지표를 본선 성능으로 주장 |
| 예선 소스 | 검증된 스키마·상관분석 아이디어와 테스트 | `AttackSimulationAgent`를 실제 공격기로 사용 |
| 본선 운영세칙 | 제출 이미지, 라운드 운영, 점수·SLA, 증빙 의무 | 예선 구현과의 동일성 의무를 임의로 추가 |
| 공식 agent guide | 환경변수, 제출 API, Broker 프레임, 시간 계약 | 데모 취약점을 본선 취약점으로 간주 |

## 현재 고정된 본선 계약

### 공통

- 공격·방어는 각각 독립 Docker 이미지입니다.
- 컨테이너의 외부 인터넷 연결은 제한되며 대회 LiteLLM Proxy를 사용합니다.
- 소스·모델·API 사용 증빙을 요청받을 수 있으므로 변경 근거를 보존합니다.

### 공격

- `TARGETS`, `PORTS`, `SUBMIT_URL`, `SUBMIT_TOKEN`을 환경변수로 받습니다.
- 대상은 `TARGETS × PORTS` 조합이며 주소와 포트를 하드코딩하지 않습니다.
- 플래그는 제출 API에 JSON으로 전송합니다.
- 제출 결과와 HTTP 429 rate limit을 처리합니다.

### 방어

- `AGENT_SOCKET`에서 `AF_UNIX`/`SOCK_SEQPACKET`으로 Broker에 연결합니다.
- `PACKET(0x01)`을 받고 300ms 안에 `VERDICT(0x02)`를 반환합니다.
- verdict는 `ACCEPT(0x00)` 또는 `DROP(0x01)`입니다.
- 약 1초마다 `HEARTBEAT(0x05)`를 보냅니다.
- 원격 LLM 호출을 패킷별 동기 hot path에 넣지 않습니다.

## 아직 가정하면 안 되는 내용

- 본선 표적이 예선 S1~S5 취약점을 그대로 포함한다는 보장
- 방어 에이전트가 차량 상태, 미션 의미, 파라미터 해시나 물리 상태를 직접 받는다는 가정
- 공식 계약에 없는 RTL, 롤백 또는 기체 제어 권한
- 로컬 데모 챌린지의 SSRF, 세션 변조, SQLi가 본선에 동일하게 등장한다는 가정

## 변경 관리

운영진의 새 안내가 이 체크리스트와 다르면 새 안내가 우선합니다. 팀장은 원본 인벤토리, 이 체크리스트, `contracts/`와 관련 테스트를 같은 PR에서 갱신하거나 변경 순서를 PR 본문에 명시합니다.
```

Create `docs/references/preliminary-code-map.md`:

```markdown
# 예선 소스와 본선 구현 매핑

이 문서는 원본 코드 복사를 지시하지 않습니다. 담당자가 예선 아이디어를 본선 입력과 시간 제약에 맞게 이식할 때 근거와 검증 상태를 기록하는 기준입니다.

| 예선 모듈 | 분류 | 본선 대상 | 담당 | 검증 요구사항 |
|---|---|---|---|---|
| `src/schema.py`의 `CommonEvent` | 재구현 | `agents/defender/src/aegis_defender/events.py` | 방어 | 원시 패킷에서 실제 관측 가능한 필드만 허용 |
| `src/correlation/normalizer.py` | 선별 이식 | `agents/defender/src/aegis_defender/normalizer.py` | 방어 | 잘린·미지원 패킷에서도 예외가 hot path를 중단하지 않음 |
| `src/correlation/time_window.py` | 재구현 | `agents/defender/src/aegis_defender/correlation/window.py` | 방어 | 제한된 메모리와 시간 기반 만료 테스트 |
| `src/correlation/causal_matcher.py` | 재구현 | `agents/defender/src/aegis_defender/correlation/causal.py` | 방어 | 관측된 프로토콜 필드만으로 규칙 구성 |
| `src/correlation/risk_scorer.py` | 재보정 후 이식 | `agents/defender/src/aegis_defender/correlation/risk.py` | 방어 | 합성 점수를 그대로 사용하지 않고 본선 fixture로 검증 |
| `src/agents/deterministic.py` | 선별 이식 | 방어 hot-path 정책 모듈 | 방어 | 패킷별 동기 경로의 시간 예산 검증 |
| `src/agents/ai_module.py` | 직접 이식 금지 | 비동기 AI 조언 모듈 | 방어 | 예선 모듈이 실제 ML/LLM이 아니라 feature rule임을 명시 |
| `src/agents/comparator.py` | 재설계 | 결정론·AI 결과 비교 모듈 | 방어 | 독립 입력이 실제 수집 가능한지 먼저 확인 |
| `src/agents/defense_agent.py` | 분해 후 재구현 | Broker·parser·policy·correlation 모듈 | 방어 | 배치 API를 온라인 패킷 처리로 교체하고 300ms 계약 검증 |
| `src/agents/attack_agent.py` | 코드 이식 금지 | 공격 S1~S5 가설 문서 | 공격 | 실제 표적·네트워크·플래그를 다루지 않는 생성기임을 유지 |
| `src/data/recipes/` | 연구 자료 | 공격 플레이북 설계 입력 | 공격 | 본선 취약점 목록으로 하드코딩하지 않음 |
| `src/evaluation.py`, `src/reporting.py` | 런타임 제외 | 오프라인 평가 도구 검토 | 팀장 | 합성 수치와 실전 수치를 분리 |

## 이식 PR 기록

예선 아이디어를 사용하는 PR에는 다음을 기록합니다.

- 예선 원본 모듈과 관련 테스트
- 새 파일과 공개 인터페이스
- 복사, 수정, 재구현 또는 제외 중 선택한 방식
- 본선 입력·시간 제약 때문에 달라진 부분
- 새 테스트와 실행 결과
- 합성 데이터 외에 사용한 검증 fixture
```

- [ ] **Step 5: Verify and commit the reference system**

Run:

```powershell
pwsh -NoProfile -File scripts/check-layout.ps1
rg -n "F23CC3F96A1AA2FFBEBB9A46AFD82DBCEC34D72A5342B3EBEAB5E954666770BF|1DD42B99A8816C3B7A543929BA0AEE90E5565CFC853E19E1455F76631CD1894E|FFE8E6BEECB628F93F20A9F5D0F41203CADBF28EE7E56C9A91FDAB87A1655A5F|62320D2100C4BE70997CE595C8952FE924D8EF17061F8575DA0AB753E58C6402|8B7552FB285C3DBB75285BB083F09A5B72322B867F2472A873C2C738C20C73CE" docs/references/source-inventory.md
git diff --check
```

Expected:

- `Repository layout check passed.`
- `rg` prints five inventory rows.
- `git diff --check` exits 0.

Commit:

```powershell
git add docs/references scripts/check-layout.ps1
git commit -m "docs: add competition reference inventory"
```

---

### Task 2: Four-person ownership and Docker handoff documentation

**Files:**
- Modify: `docs/ownership.md`
- Modify: `AGENTS.md`
- Modify: `README.md`

**Interfaces:**
- Consumes: The approved role matrix and reference policy.
- Produces: Human-facing and agent-facing ownership rules that agree on all four roles.

- [ ] **Step 1: Demonstrate the current ownership gap**

Run:

```powershell
rg -n "Docker 담당자|chore/docker-defender-image|docs/references" docs/ownership.md AGENTS.md README.md
```

Expected: exit code 1 because the current ownership documents do not describe the new Docker owner and reference area.

- [ ] **Step 2: Replace the ownership document**

Replace `docs/ownership.md` with:

```markdown
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
```

- [ ] **Step 3: Update agent-facing repository instructions**

In `AGENTS.md`, replace the `## Ownership` section with:

```markdown
## Ownership

- Attacker owner: attacker Python, tests, and `research/attack-scenarios.md`
- Defender owner: defender Python, tests, and `research/defense-mapping.md`
- Docker owner: both Dockerfiles, `integration/**`, image scripts, image CI, and Registry procedures
- Team lead Lee Gyeong-jun: `contracts/**`, shared architecture and decisions, `docs/references/**`, PR verification, and final merge

Docker changes require the affected agent owner and team lead to review. Docker owner must not change strategy code unilaterally. Agent owners must not finalize Dockerfiles or shared contracts alone.

Use a short-lived branch for one task and delete it after merge. Never create permanent person branches or push directly to `main`.
```

Under `## Repository boundary`, add:

```markdown
- Keep raw competition documents and preliminary source in private team storage; track only hashes and mappings under `docs/references`.
```

- [ ] **Step 4: Add the four-person workflow to the README**

Append to `README.md`:

```markdown
## 팀 작업 방식

| 역할 | 작업 영역 |
|---|---|
| 공격 담당자 | 공격 설계, Python 구현과 테스트 |
| 방어 담당자 | 방어 설계, Python 구현과 테스트 |
| Docker 담당자 | 공격·방어 Dockerfile, 이미지 빌드, CI와 스켈레톤 연동 |
| 팀장 이경준 | 계약, 자료 추적, PR 검증과 최종 병합 |

사람별 장기 브랜치를 만들지 않습니다. 최신 `main`에서 작업 하나당 짧은 브랜치를 만들고, 필수 검토를 거친 PR만 병합합니다. 원본 대회 자료는 Git에 넣지 않으며 [`docs/references/`](docs/references/)에서 해시와 구현 매핑을 확인합니다.
```

- [ ] **Step 5: Verify and commit ownership documentation**

Run:

```powershell
rg -n "Docker 담당자|Docker owner|docs/references|직접 작업" docs/ownership.md AGENTS.md README.md
pwsh -NoProfile -File scripts/check-layout.ps1
git diff --check
```

Expected: each role appears in the appropriate document, the layout passes, and `git diff --check` exits 0.

Commit:

```powershell
git add docs/ownership.md AGENTS.md README.md
git commit -m "docs: define four-person ownership"
```

---

### Task 3: Task-branch workflow and pull request enforcement

**Files:**
- Create: `CONTRIBUTING.md`
- Create: `.github/pull_request_template.md`
- Modify: `scripts/check-layout.ps1`

**Interfaces:**
- Consumes: The ownership matrix and PR approval rules.
- Produces: A contributor workflow and a PR template that collect evidence required by the team lead.

- [ ] **Step 1: Add the failing contribution-file gate**

Add these entries to `$requiredFiles` in `scripts/check-layout.ps1`:

```powershell
    '.github/pull_request_template.md'
    'CONTRIBUTING.md'
```

Run:

```powershell
pwsh -NoProfile -File scripts/check-layout.ps1
```

Expected: exit code 1 listing only `.github/pull_request_template.md` and `CONTRIBUTING.md` as missing.

- [ ] **Step 2: Create the task-branch contribution guide**

Create `CONTRIBUTING.md`:

```markdown
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
5. 전체 관련 테스트와 `scripts/check-layout.ps1`을 실행합니다.
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
```

- [ ] **Step 3: Create the pull request template**

Create `.github/pull_request_template.md`:

```markdown
## 변경 목적

<!-- 해결하는 문제와 이 PR이 포함하는 범위를 적어주세요. -->

## 담당 영역

- [ ] 공격 Python·테스트
- [ ] 방어 Python·테스트
- [ ] 공격 Dockerfile
- [ ] 방어 Dockerfile
- [ ] 통합·CI
- [ ] 공통 계약·문서

## 근거

- 관련 Issue:
- 관련 설계·ADR:
- 관련 운영세칙·계약:
- 예선 코드 또는 보고서 매핑:

## 검증

```text
실행한 명령과 결과를 그대로 기록합니다.
```

- [ ] 관련 단위 테스트 통과
- [ ] 관련 계약 테스트 통과
- [ ] `scripts/check-layout.ps1` 통과
- [ ] Docker 변경 시 독립 이미지 빌드·smoke test 통과
- [ ] 비밀값·개인 절대경로·원본 대회 자료 미포함

## 영향과 복구

- 성능·이미지·계약 영향:
- 남아 있는 위험:
- 롤백 방법:

## 필수 검토자

- [ ] 해당 공격 또는 방어 담당자
- [ ] Docker 담당자
- [ ] 팀장 이경준
```

- [ ] **Step 4: Run the workflow checks**

Run:

```powershell
pwsh -NoProfile -File scripts/check-layout.ps1
rg -n "chore/docker-defender-image|장기 작업 브랜치|공격 Dockerfile|방어 Dockerfile" CONTRIBUTING.md .github/pull_request_template.md
git diff --check
```

Expected: layout passes, the branch and review rules are found, and `git diff --check` exits 0.

- [ ] **Step 5: Commit the contributor workflow**

Run:

```powershell
git add CONTRIBUTING.md .github/pull_request_template.md scripts/check-layout.ps1
git commit -m "docs: add task branch and PR workflow"
```

Expected: one commit containing only contributor workflow enforcement.

---

### Task 4: Full verification and implementation handoff

**Files:**
- Verify: all files changed by Tasks 1-3

**Interfaces:**
- Consumes: The complete team workflow and reference implementation.
- Produces: A clean branch ready for team-lead review and integration.

- [ ] **Step 1: Verify repository policy and existing tests**

Run:

```powershell
pwsh -NoProfile -File scripts/check-layout.ps1
pwsh -NoProfile -File scripts/tests/test-validate-skeleton.ps1
```

Expected:

- `Repository layout check passed.`
- `Skeleton validator tests passed: 2 cases.`

- [ ] **Step 2: Verify the current external skeleton when available**

In the current repository layout, run:

```powershell
pwsh -NoProfile -File scripts/validate-skeleton.ps1 -SkeletonPath ..
```

Expected: `Validated DAH skeleton` followed by the resolved local skeleton root. This output may contain a local path at runtime; it must not be written into tracked files.

- [ ] **Step 3: Verify no forbidden source or secrets are tracked**

Run:

```powershell
git ls-files "*.pdf" "*.zip" "*.tar" "*.tar.gz" "*.pcap" "*.pcapng"
rg -n --hidden --glob '!.git/**' --glob '!.env.example' --glob '!docs/superpowers/plans/**' "SUBMIT_TOKEN=.+|LLM_API_KEY=.+|BEGIN (RSA|OPENSSH|PRIVATE) KEY" .
```

Expected: both commands produce no matches. `rg` exits 1 because no secret pattern is present.

- [ ] **Step 4: Verify design coverage and Git cleanliness**

Run:

```powershell
rg -n "공격 담당자|방어 담당자|Docker 담당자|팀장 이경준" docs/ownership.md README.md
rg -n "PRELIM-GUIDE|PRELIM-REPORT|FINALS-RULES|PRELIM-SOURCE|OFFICIAL-SKELETON" docs/references/source-inventory.md
rg -n "feat/attacker|feat/defender|chore/docker-attacker|chore/docker-defender" CONTRIBUTING.md
git diff --check
git status --short --branch
```

Expected: all four roles, five source IDs, attacker/defender/Docker branch examples are present; `git diff --check` exits 0; the branch has no uncommitted changes.

- [ ] **Step 5: Prepare the next three design issues**

Create no files in this step. Use these exact issue titles and scopes when the team starts runtime work:

```text
[Attack Design] Observation-plan-execution loop and S1-S5 hypothesis selection
[Defense Design] Broker protocol, 300ms hot path, online correlation, and false-positive control
[Docker Design] Independent attacker/defender images, dependency pinning, smoke tests, Compose override, and Registry flow
```

Expected: the documentation implementation is ready for review without adding runtime code or creating issues before the team lead requests external GitHub writes.
