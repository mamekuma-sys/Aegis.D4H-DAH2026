# Repository Foundation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Create the agent-centered repository foundation, document the finals contracts and preliminary-report mapping, and validate an external DAH skeleton checkout without adding attacker or defender runtime logic yet.

**Architecture:** The repository owns only team-authored agent code, contracts, research notes, CI, and integration adapters. The official `deploy` tree remains outside the repository and is supplied by path when validating or running local integration. Attacker and defender runtime implementations remain separate follow-up projects so each can be designed, tested, and reviewed independently.

**Tech Stack:** Git, Markdown, PowerShell 7, GitHub Actions

## Global Constraints

- The final deliverables are two independent Docker images: attacker and defender.
- Do not copy `deploy/router`, `deploy/backend`, `deploy/challenges`, `deploy/litellm-gw`, or the `broker` binary into this repository.
- Do not commit PDFs, `.env`, credentials, tokens, flags, PCAPs, logs, `__pycache__`, `.pyc`, `tmp`, or generated output.
- Treat finals rules and `deploy/docs/agent-guide.md` as authoritative over preliminary materials and team-authored notes.
- Use the preliminary report's A1-A5 and S1-S5 material as strategy input, not as proof of finals vulnerabilities.
- Do not create `CODEOWNERS` until the real GitHub user or team names are known.
- Use PowerShell scripts that accept explicit paths; never commit a developer-specific absolute path.
- This plan creates no attacker or defender runtime behavior. Those require separate approved designs and implementation plans.

---

### Task 1: Repository guardrails and ownership map

**Files:**
- Create: `.gitignore`
- Create: `.gitattributes`
- Create: `.env.example`
- Create: `README.md`
- Create: `docs/ownership.md`
- Create: `scripts/check-layout.ps1`

**Interfaces:**
- Consumes: The approved repository design in `docs/superpowers/specs/2026-08-10-agent-repository-design.md`.
- Produces: A documented repository boundary and `scripts/check-layout.ps1`, used by local checks and CI.

- [ ] **Step 1: Write the failing layout check**

Create `scripts/check-layout.ps1`:

```powershell
$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot

$requiredFiles = @(
    '.gitattributes'
    '.gitignore'
    '.env.example'
    'README.md'
    'docs/ownership.md'
    'contracts/README.md'
    'contracts/attacker/README.md'
    'contracts/defender/README.md'
    'contracts/fixtures/README.md'
    'integration/README.md'
    'research/preliminary-strategy.md'
    'research/attack-scenarios.md'
    'research/defense-mapping.md'
)

$missing = @()
foreach ($relativePath in $requiredFiles) {
    $fullPath = Join-Path $repoRoot $relativePath
    if (-not (Test-Path -LiteralPath $fullPath -PathType Leaf)) {
        $missing += $relativePath
    }
}

if ($missing.Count -gt 0) {
    Write-Error ("Missing repository files:`n- " + ($missing -join "`n- "))
    exit 1
}

$forbiddenDirectories = @('deploy', 'tmp', 'output', '__pycache__')
foreach ($relativePath in $forbiddenDirectories) {
    $fullPath = Join-Path $repoRoot $relativePath
    if (Test-Path -LiteralPath $fullPath) {
        Write-Error "Forbidden repository path exists: $relativePath"
        exit 1
    }
}

Write-Output 'Repository layout check passed.'
```

- [ ] **Step 2: Run the layout check and verify it fails**

Run:

```powershell
pwsh -NoProfile -File scripts/check-layout.ps1
```

Expected: exit code 1 with `Missing repository files` because the repository foundation does not exist yet.

- [ ] **Step 3: Add ignore and line-ending rules**

Create `.gitignore`:

```gitignore
.env
.env.*
!.env.example

__pycache__/
*.py[cod]
.pytest_cache/
.coverage
htmlcov/

tmp/
output/
captures/
archives/
*.pcap
*.pcapng
*.log

*.tar
*.tar.gz
*.zip
*.pdf

.idea/
.vscode/
.DS_Store
Thumbs.db
```

Create `.gitattributes`:

```gitattributes
* text=auto
*.md text eol=lf
*.py text eol=lf
*.sh text eol=lf
*.yml text eol=lf
*.yaml text eol=lf
*.ps1 text eol=crlf
```

Create `.env.example`:

```dotenv
LLM_BASE_URL=http://litellm.lig.internal:4000
LLM_API_KEY=
TARGETS=team2.lig.internal
PORTS=8082,8083,8084
SUBMIT_URL=http://backend:4100/submit
SUBMIT_TOKEN=
AGENT_SOCKET=/run/agent.sock
```

- [ ] **Step 4: Document the repository and ownership boundary**

Create `README.md`:

```markdown
# Aegis.0xD4H DAH 2026 Agents

DAH 2026 본선용 공격·방어 에이전트를 개발하는 팀 저장소입니다.

## 핵심 원칙

- 공격과 방어는 각각 독립 Docker 이미지로 빌드합니다.
- 본선 인터페이스는 개발 초기부터 계약 테스트로 고정합니다.
- 공식 스켈레톤 전체는 이 저장소에 복사하지 않고 외부 로컬 시험장으로 사용합니다.
- 예선 보고서의 전략을 기반으로 하되, 실제 본선에서 관측 가능한 입력에 맞춰 재구현합니다.

## 개발 영역

- `agents/attacker/`: 공격 담당자 영역
- `agents/defender/`: 방어 담당자 영역
- `contracts/`: 본선 인터페이스 계약과 테스트 자료
- `integration/`: 외부 스켈레톤 연동
- `research/`: 예선 전략과 본선 구현의 연결 근거
- `docs/`: 아키텍처, 의사결정, 회의 기록
- `scripts/`: 공통 검증과 실행 도구

## 현재 단계

저장소 기반 설계를 확정한 상태입니다. 공격 런타임과 방어 런타임은 각각 별도 설계 승인 후 구현합니다.

## 로컬 검사

```powershell
pwsh -NoProfile -File scripts/check-layout.ps1
```

외부 스켈레톤 검증 방법은 `integration/README.md`를 따릅니다.
```

Create `docs/ownership.md`:

```markdown
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
```

- [ ] **Step 5: Commit the guardrails**

Run:

```powershell
git add .gitignore .gitattributes .env.example README.md docs/ownership.md scripts/check-layout.ps1
git commit -m "chore: establish repository guardrails"
```

Expected: one commit containing only repository-wide guardrails and ownership documentation. The layout check still fails because later tasks have not created all required files.

---

### Task 2: Finals interface contract documentation

**Files:**
- Create: `contracts/README.md`
- Create: `contracts/attacker/README.md`
- Create: `contracts/defender/README.md`
- Create: `contracts/fixtures/README.md`
- Create: `contracts/fixtures/packet-frame.hex`
- Create: `contracts/fixtures/accept-verdict.hex`
- Create: `contracts/fixtures/heartbeat.hex`

**Interfaces:**
- Consumes: Finals rules and `deploy/docs/agent-guide.md`.
- Produces: Exact names and byte fixtures used by the future attacker and defender contract tests.

- [ ] **Step 1: Document contract precedence**

Create `contracts/README.md`:

```markdown
# 본선 인터페이스 계약

이 디렉터리는 공격·방어 전략과 무관하게 반드시 지켜야 하는 본선 실행 계약을 기록합니다.

## 우선순위

1. 최신 본선 운영세칙과 당일 공통 운영 안내
2. 공식 `deploy/docs/agent-guide.md`
3. 공식 스켈레톤의 실제 동작
4. 이 저장소의 계약 문서와 테스트

운영진 규격이 바뀌면 구현보다 먼저 이 문서와 계약 테스트를 갱신합니다.

## 분리 원칙

- 공격 계약은 `attacker/README.md`에서 관리합니다.
- 방어 계약은 `defender/README.md`에서 관리합니다.
- 바이너리 예시는 `fixtures/`에 저장합니다.
```

- [ ] **Step 2: Document the attacker contract**

Create `contracts/attacker/README.md`:

```markdown
# 공격 에이전트 계약

## 입력 환경변수

| 이름 | 의미 |
|---|---|
| `TARGETS` | 상대 팀 주소 CSV |
| `PORTS` | 상대 팀 공통 진입 포트 CSV |
| `SUBMIT_URL` | 플래그 제출 엔드포인트 |
| `SUBMIT_TOKEN` | 팀 제출 인증 토큰 |
| `LLM_BASE_URL` | OpenAI 호환 LiteLLM Proxy URL |
| `LLM_API_KEY` | LiteLLM 인증 키 |

공격 대상은 `TARGETS × PORTS`의 모든 조합입니다. 주소와 포트를 코드에 하드코딩하지 않습니다.

## 플래그 제출

```http
POST {SUBMIT_URL}
Content-Type: application/json

{"flag":"FLAG{...}","token":"{SUBMIT_TOKEN}"}
```

처리할 상태는 `accepted`, `own_team`, `duplicate`, `rejected`, `closed`이며, HTTP 429는 rate limit으로 처리합니다.

## 네트워크 제한

본선 에이전트는 상대 팀 서비스, 제출 엔드포인트, 대회 LiteLLM Proxy 등 운영진이 허용한 내부 경로만 사용합니다. 임의의 외부 인터넷 의존성을 두지 않습니다.
```

- [ ] **Step 3: Document the defender contract**

Create `contracts/defender/README.md`:

```markdown
# 방어 에이전트 계약

## 연결

- 환경변수: `AGENT_SOCKET`
- 기본 경로: `/run/agent.sock`
- 소켓: `AF_UNIX` / `SOCK_SEQPACKET`
- `router/broker.yaml`의 `agent-event.sock`은 사용하지 않습니다.

## 메시지

모든 정수는 big-endian입니다.

| 타입 | 방향 | 프레임 |
|---|---|---|
| `0x01` PACKET | Broker → Agent | `type(1) + pkt_id(8) + pkt_len(2) + raw_ip(pkt_len)` |
| `0x02` VERDICT | Agent → Broker | `type(1) + pkt_id(8) + verdict(1)` |
| `0x05` HEARTBEAT | Agent → Broker | `type(1)` |

Verdict 값은 `0x00` ACCEPT, `0x01` DROP입니다.

## 시간 계약

- 패킷 수신 후 300ms 안에 verdict를 반환합니다.
- 약 1초마다 heartbeat를 보냅니다.
- Broker는 약 3초 동안 heartbeat가 없으면 에이전트 연결을 죽은 것으로 판단합니다.
- 원격 LLM 호출을 패킷별 동기 판정 경로에 넣지 않습니다.
```

- [ ] **Step 4: Add byte-level protocol fixtures**

Create `contracts/fixtures/README.md`:

```markdown
# Broker 프레임 고정 예시

공백과 줄바꿈을 제거한 뒤 hex 문자열을 바이트로 변환합니다.

- `packet-frame.hex`: packet id 42, 20바이트 IPv4 예시
- `accept-verdict.hex`: packet id 42에 대한 ACCEPT
- `heartbeat.hex`: HEARTBEAT 한 바이트

이 예시는 향후 `struct.pack`/`struct.unpack` 계약 테스트의 고정 입력으로 사용합니다.
```

Create `contracts/fixtures/packet-frame.hex`:

```text
01000000000000002A00144500001400000000400600007F0000017F000001
```

Create `contracts/fixtures/accept-verdict.hex`:

```text
02000000000000002A00
```

Create `contracts/fixtures/heartbeat.hex`:

```text
05
```

- [ ] **Step 5: Commit the contracts**

Run:

```powershell
git add contracts
git commit -m "docs: record finals interface contracts"
```

Expected: one commit containing contract documentation and deterministic byte fixtures only.

---

### Task 3: Preliminary-report traceability

**Files:**
- Create: `research/preliminary-strategy.md`
- Create: `research/attack-scenarios.md`
- Create: `research/defense-mapping.md`
- Create: `docs/decisions/0001-external-skeleton.md`

**Interfaces:**
- Consumes: The preliminary report, preliminary source, and the repository design.
- Produces: The source-of-truth mapping that future attacker and defender plans must cite.

- [ ] **Step 1: Record the reusable preliminary strategy**

Create `research/preliminary-strategy.md`:

```markdown
# 예선 결과물 활용 경계

## 그대로 가져오지 않는 것

- `AttackSimulationAgent`: 실제 표적을 공격하지 않는 합성 이벤트 생성기
- 합성 데이터의 점수와 탐지율: 실환경 성능 수치가 아님
- 외부 AI/LLM이 아닌 feature-rule 기반 `SimulatedAIModule`
- 배치 `list[CommonEvent]` 처리 방식

## 공격에서 계승하는 것

- A1~A5 공격자 모델
- S1~S5 다단계 공격 시나리오
- 단일 이벤트보다 시간·세션·대상·인과관계를 중시하는 계획
- 관측 결과에 따라 다음 단계를 바꾸는 적응 루프

## 방어에서 계승하는 것

- CommonEvent 정규화 개념
- 시간창 상관분석과 인과 그래프
- 결정론 규칙과 AI 조언의 독립 경로
- 가용성을 보존하는 단계적 대응

## 본선에서 새로 필요한 것

- 실제 네트워크 입력과 출력 어댑터
- 공격 도구 실행과 플래그 제출
- 원시 패킷 파싱과 온라인 상태
- 300ms 판정 경로와 heartbeat
- Docker 이미지 단위의 빌드·실행·관찰성
```

- [ ] **Step 2: Record the attack hypotheses**

Create `research/attack-scenarios.md`:

```markdown
# 공격 시나리오 가설

예선 보고서의 시나리오는 본선 취약점 목록이 아니라 정찰 우선순위를 정하는 가설입니다.

| 시나리오 | 예선 개념 | 본선 적용 원칙 |
|---|---|---|
| S1 | GCS 계정·세션 탈취와 미션 명령 변경 | 인증·세션·권한 경계가 관측될 때만 플레이북 활성화 |
| S2 | Autopilot 파라미터와 failsafe 조작 | 파라미터 인터페이스가 실제 노출될 때만 검증 |
| S3 | 센서·텔레메트리 은폐 | 프로토콜과 데이터 흐름을 식별한 뒤 적용 |
| S4 | 여러 레이어를 잇는 공격 체인 | 관측 증거가 이어질 때 다음 단계 선택 |
| S5 | 방어 AI 입력 오염 | 탐지·분류 입력 경계가 노출될 때만 평가 |

공격 에이전트는 하드코딩된 시나리오 순서를 강제하지 않습니다. 표적의 배너, 응답, 오류, 프로토콜 특징을 근거로 가설을 선택하고 중단합니다.
```

- [ ] **Step 3: Map defense ideas to observable inputs**

Create `research/defense-mapping.md`:

```markdown
# 예선 방어 개념의 본선 매핑

| 예선 개념 | 현재 본선 입력에서의 상태 | 구현 방향 |
|---|---|---|
| 이벤트 정규화 | 원시 패킷에서 일부 생성 가능 | 패킷 파서 뒤에 event adapter 배치 |
| 시간창 상관분석 | 가능 | 흐름별 제한된 메모리 상태 사용 |
| 인과관계 매칭 | 부분 가능 | 관측된 프로토콜 필드만 사용 |
| Golden Profile | 부분 가능 | 정상 트래픽·프로토콜 기준선으로 재정의 |
| 파라미터 해시 | 직접 제공되지 않음 | 실제 페이로드에서 추출 가능할 때만 사용 |
| 물리 상태 비교 | 직접 제공되지 않음 | 별도 텔레메트리 계약 없이는 제외 |
| HITL·RTL·롤백 | 직접 실행 인터페이스 없음 | ACCEPT/DROP 정책과 경보 로그로 축소 |
| AI 비교기 | 비동기 경로에서 가능 | hot path 밖에서 규칙 개선과 분석에 사용 |

방어 구현은 보고서에 나온 신호가 존재한다고 가정하지 않습니다. 파싱 실패나 미지원 프로토콜에서도 300ms 판정 계약을 지킵니다.
```

- [ ] **Step 4: Record the external-skeleton decision**

Create `docs/decisions/0001-external-skeleton.md`:

```markdown
# ADR-0001: 공식 스켈레톤을 외부 통합 시험장으로 유지

## 상태

승인됨 — 2026-08-10

## 결정

공식 `deploy` 트리는 이 저장소에 복사하지 않습니다. 개발자는 로컬 스켈레톤 경로를 명시하고, 팀의 두 에이전트만 Compose override로 연결합니다.

## 이유

- 최종 제출물은 스켈레톤 소스가 아니라 공격·방어 Docker 이미지입니다.
- 대회 인프라 코드와 팀 전략 코드의 변경 이력을 분리할 수 있습니다.
- 스켈레톤이 갱신되어도 팀 코드와 충돌하지 않습니다.
- 라우터, 백엔드, 챌린지, Broker 바이너리의 불필요한 복사를 피합니다.

## 결과

- 본선 인터페이스는 `contracts/`와 자동 테스트로 고정합니다.
- 로컬 통합에는 공식 스켈레톤이 별도로 필요합니다.
- 스켈레톤 변경 시 계약 차이를 먼저 검토합니다.
```

- [ ] **Step 5: Commit the traceability documents**

Run:

```powershell
git add research docs/decisions/0001-external-skeleton.md
git commit -m "docs: map preliminary strategy to finals"
```

Expected: one commit that clearly separates reusable ideas from unimplemented or unobservable preliminary assumptions.

---

### Task 4: External skeleton validator

**Files:**
- Create: `scripts/validate-skeleton.ps1`
- Create: `integration/README.md`
- Modify: `scripts/check-layout.ps1`

**Interfaces:**
- Consumes: A caller-provided `-SkeletonPath` pointing to a directory that contains `deploy/docker-compose.yml`.
- Produces: Exit code 0 for the verified skeleton shape; exit code 1 with exact missing paths otherwise.

- [ ] **Step 1: Write the skeleton validator**

Create `scripts/validate-skeleton.ps1`:

```powershell
param(
    [Parameter(Mandatory = $true)]
    [string]$SkeletonPath
)

$ErrorActionPreference = 'Stop'
$resolvedSkeleton = (Resolve-Path -LiteralPath $SkeletonPath).Path

$requiredPaths = @(
    'deploy/docker-compose.yml'
    'deploy/docs/agent-guide.md'
    'deploy/agents/team1/attacker/Dockerfile'
    'deploy/agents/team1/defender/Dockerfile'
    'deploy/router/broker'
)

$missing = @()
foreach ($relativePath in $requiredPaths) {
    $fullPath = Join-Path $resolvedSkeleton $relativePath
    if (-not (Test-Path -LiteralPath $fullPath -PathType Leaf)) {
        $missing += $relativePath
    }
}

if ($missing.Count -gt 0) {
    Write-Error ("Invalid DAH skeleton. Missing:`n- " + ($missing -join "`n- "))
    exit 1
}

Write-Output "Validated DAH skeleton: $resolvedSkeleton"
```

- [ ] **Step 2: Verify the validator rejects the repository itself**

Run:

```powershell
pwsh -NoProfile -File scripts/validate-skeleton.ps1 -SkeletonPath .
```

Expected: exit code 1 with `Invalid DAH skeleton` because the team repository intentionally does not contain `deploy`.

- [ ] **Step 3: Verify the validator accepts the supplied skeleton**

From `aegis-dah2026-agents`, run:

```powershell
pwsh -NoProfile -File scripts/validate-skeleton.ps1 -SkeletonPath ..
```

Expected: exit code 0 and `Validated DAH skeleton`, because the current parent directory contains the verified `deploy` tree.

- [ ] **Step 4: Document integration responsibilities**

Create `integration/README.md`:

```markdown
# 외부 스켈레톤 연동

공식 스켈레톤은 이 저장소에 포함하지 않습니다.

## 현재 가능한 검사

```powershell
pwsh -NoProfile -File scripts/validate-skeleton.ps1 -SkeletonPath <스켈레톤-루트>
```

검사 대상은 Compose 파일, 공식 에이전트 가이드, Team 1 Dockerfile, Broker 바이너리입니다.

## 후속 단계

공격·방어 Dockerfile이 각각 구현되면 `compose.agents.yml`과 `run-with-skeleton.ps1`을 추가합니다. 이 파일들은 Team 1의 빌드 컨텍스트만 팀 저장소의 에이전트로 교체해야 하며, 공식 스켈레톤 파일을 수정하거나 복사하지 않습니다.
```

- [ ] **Step 5: Add the validator to the layout check**

In `scripts/check-layout.ps1`, add `'scripts/validate-skeleton.ps1'` immediately after `'README.md'` in `$requiredFiles`:

```powershell
    'README.md'
    'scripts/validate-skeleton.ps1'
    'docs/ownership.md'
```

Run:

```powershell
pwsh -NoProfile -File scripts/check-layout.ps1
```

Expected: `Repository layout check passed.`

- [ ] **Step 6: Commit the external skeleton validator**

Run:

```powershell
git add scripts/validate-skeleton.ps1 scripts/check-layout.ps1 integration/README.md
git commit -m "chore: validate external DAH skeleton"
```

Expected: one commit containing the path validator and integration documentation.

---

### Task 5: Foundation CI and final verification

**Files:**
- Create: `.github/workflows/ci.yml`
- Modify: `README.md`

**Interfaces:**
- Consumes: `scripts/check-layout.ps1`.
- Produces: A GitHub Actions check named `repository-foundation` on pushes and pull requests.

- [ ] **Step 1: Add the CI workflow**

Create `.github/workflows/ci.yml`:

```yaml
name: CI

on:
  push:
  pull_request:

permissions:
  contents: read

jobs:
  repository-foundation:
    runs-on: windows-latest
    steps:
      - name: Check out repository
        uses: actions/checkout@v4

      - name: Validate repository layout
        shell: pwsh
        run: ./scripts/check-layout.ps1
```

- [ ] **Step 2: Document CI and the next design gates**

Append this section to `README.md`:

```markdown
## CI

모든 push와 pull request에서 저장소 경계와 필수 문서를 검사합니다. 공격·방어 구현이 시작되면 각 이미지의 단위 테스트, 계약 테스트, 독립 Docker 빌드를 같은 CI에 추가합니다.

## 다음 설계 게이트

1. 공격 담당자와 S1~S5 기반 관측-계획-실행 구조를 확정합니다.
2. 방어 담당자와 300ms hot path 및 비동기 상관분석 경계를 확정합니다.
3. 두 Dockerfile이 준비되면 외부 스켈레톤 Compose override를 추가합니다.
```

- [ ] **Step 3: Run all foundation checks**

Run:

```powershell
pwsh -NoProfile -File scripts/check-layout.ps1
pwsh -NoProfile -File scripts/validate-skeleton.ps1 -SkeletonPath ..
git diff --check
git status --short
```

Expected:

- `Repository layout check passed.`
- `Validated DAH skeleton` with the resolved parent path.
- `git diff --check` exits 0.
- `git status --short` lists only `.github/workflows/ci.yml` and `README.md` before the final commit.

- [ ] **Step 4: Commit the CI foundation**

Run:

```powershell
git add .github/workflows/ci.yml README.md
git commit -m "ci: validate repository foundation"
git status --short --branch
```

Expected: clean `main` branch with no untracked or modified files.

- [ ] **Step 5: Record the next two planning sessions**

Create no files in this step. Schedule the next design reviews with these exact scopes:

```text
Attack design: observable inputs, target state, tool boundary, S1-S5 hypothesis selection, flag lifecycle, and rate limiting.
Defense design: packet visibility, parser boundary, 300ms synchronous policy, online correlation state, asynchronous AI advisory, and false-positive controls.
```

Expected: the repository foundation is complete without prematurely coupling the attacker and defender implementations.

