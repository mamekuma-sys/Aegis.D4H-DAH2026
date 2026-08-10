# Finals Source Alignment Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 본선 자료 5개의 출처와 핵심 운영 계약을 저장소 문서에 정규화하고, 원본 파일은 Git 밖의 비공개 보관소로 안전하게 이동한 뒤 단기 브랜치를 원격에 푸시한다.

**Architecture:** Git에는 재현 가능한 해시·출처 분류·런타임 계약만 남기고 원본 PDF와 파생 Markdown은 저장소 밖에 보관한다. 공통 규칙, 공격·방어 계약, Docker 통합 규칙을 책임별 문서에 나누어 기록하며, 공식 스켈레톤은 복사하지 않고 나중에 Compose override로 연결한다.

**Tech Stack:** Markdown, PowerShell 7, Git

## Global Constraints

- 작업 브랜치는 `docs/finals-source-alignment`이며 `main`에 직접 커밋하거나 푸시하지 않는다.
- 사실 우선순위는 당일 운영진 안내, 본선 운영세칙, 공식 `deploy/docs/agent-guide.md`, 실제 스켈레톤, 예선 자료, 파생 팀 메모 순이다.
- 원본 5개 파일, PDF, PCAP, 로그, 토큰, 키, 개인 PC 절대경로를 Git에 커밋하지 않는다.
- 공격 대상은 운영진이 허용한 팀 진입점, LiteLLM, 제출 서버로 제한한다.
- 방어의 패킷별 동기 판정 경로에는 원격 LLM 호출을 넣지 않는다.
- 원시 IP 패킷에서 파싱으로 증명되지 않은 차량 상태, 임무 의미, 파라미터 해시, 물리 상태를 가정하지 않는다.
- 공식 스켈레톤은 이 저장소 밖에 유지하고 `deploy/router`, `deploy/backend`, `deploy/challenges`, `deploy/litellm-gw`, Broker 바이너리를 복사하지 않는다.
- 저장소 변경은 문서와 ignore 규칙으로만 제한하며 공격·방어 Python, Dockerfile, Compose 구현은 추가하지 않는다.

---

### Task 1: 원본 출처 보호와 인벤토리 정규화

**Files:**
- Modify: `.gitignore`
- Modify: `docs/references/source-inventory.md`

**Interfaces:**
- Consumes: 승인된 설계의 원본 분류, 파일 크기, SHA-256
- Produces: Git 차단 규칙과 저장소에서 참조할 정규 출처 ID

- [ ] **Step 1: 첨부 Markdown 두 파일을 루트 전용 ignore 규칙에 추가**

`*.pdf` 바로 다음에 다음 두 줄을 추가한다.

```gitignore
/DAH2026_본선_당일_진행_안내.md
/DAH2026_스켈레톤코드_상세_설명.md
```

- [ ] **Step 2: ignore 규칙이 세 원본 PDF와 두 Markdown에 적용되는지 확인**

Run:

```powershell
git check-ignore -v -- 'DAH 예선_안내서.pdf' 'DAH2026_예선보고서_Aegis.0xD4H.pdf' 'DAH2026_본선운영세칙.pdf' 'DAH2026_본선_당일_진행_안내.md' 'DAH2026_스켈레톤코드_상세_설명.md'
```

Expected: PDF 세 개는 `*.pdf`, Markdown 두 개는 각각의 루트 전용 규칙과 매칭된다.

- [ ] **Step 3: 인벤토리에 파생 자료 두 행과 검증 상태를 추가**

기존 표에 다음 행을 추가한다.

```markdown
| FINALS-DAY-NOTE | `DAH2026_본선_당일_진행_안내.md` | 9,019 bytes | `AA704A259A3A59B10A844A59AA6B1593DEDF31D99662B70A8D7CD58EFECD5D9E` | 파생 팀 메모, 원본 커밋 금지 |
| SKELETON-EXPLANATION | `DAH2026_스켈레톤코드_상세_설명.md` | 27,110 bytes | `BF1CC690C82605497A03B959B93784663EC6D7DFD9949DCBE9C7151B3C07A6AA` | 파생 팀 메모, 원본 커밋 금지 |
```

표 아래에 다음 원칙을 명시한다.

```markdown
## 2026-08-10 첨부본 검증

- PDF 세 개의 SHA-256은 기존 인벤토리 값과 일치했습니다.
- Markdown 두 개는 운영세칙과 스켈레톤을 설명하는 파생 팀 메모이며 공식 원본으로 취급하지 않습니다.
- 다섯 파일의 보관 위치는 팀 내부 채널에서만 공유하고 이 저장소에는 해시와 논리적 분류만 남깁니다.
```

- [ ] **Step 4: 출처 변경 diff를 검증**

Run:

```powershell
git diff --check
git diff -- .gitignore docs/references/source-inventory.md
```

Expected: 공백 오류가 없고 두 파일에 계획된 내용만 나타난다.

- [ ] **Step 5: 출처 보호 변경을 커밋**

```powershell
git add -- .gitignore docs/references/source-inventory.md
git diff --cached --check
git commit -m "docs: record finals source provenance"
```

---

### Task 2: 공통 본선 규칙과 관측 경계 문서화

**Files:**
- Modify: `docs/references/rules-checklist.md`
- Modify: `docs/architecture.md`

**Interfaces:**
- Consumes: `FINALS-RULES`, 예선 보고서의 전략 개념, 공식 Broker 계약
- Produces: 공격·방어·Docker 설계가 공통으로 따를 규칙과 관측 가능성 경계

- [ ] **Step 1: 규칙 체크리스트의 공통·공격·방어·운영 항목을 확장**

기존 고정 계약에 다음 내용을 책임별로 배치한다.

```markdown
### 공통

- 컨테이너와 flag는 라운드마다 초기화되므로 런타임 상태를 영속 상태로 간주하지 않습니다.
- DoS, 운영 범위 밖 접근, 운영망 침범, rate limit 우회, flag 획득 목적 밖의 파괴·변조를 금지합니다.
- 동점 시 LLM 토큰 비용이 사용되므로 호출 예산과 사용 증빙을 관리합니다.

### 공격

- 상대 방어망 접근 한도는 공격 에이전트당 초당 10회, 버스트 20입니다.
- flag 제출 한도는 분당 30회이며 HTTP 429에 backoff를 적용합니다.
- 허용된 팀 진입점, 대회 LiteLLM Proxy, 제출 서버 외부로 요청하지 않습니다.

### 방어

- NAT가 소스 IP를 정규화하므로 소스 IP만으로 공격자를 식별하지 않습니다.
- 각 레이어에는 30ms 지연과 0.3% 패킷 손실이 모사됩니다.
- 방어 에이전트가 없거나 죽으면 Broker는 fail-open으로 동작하고, verdict가 300ms를 넘으면 해당 패킷은 DROP됩니다.

### 이미지 운영

- `latest` 이미지는 라운드 시작 5분 전에 pull되며 pull timeout은 20분입니다.
- 컨테이너는 라운드마다 새로 생성되고 종료 후 삭제되며 시작 시간도 라운드 시간에 포함됩니다.
```

- [ ] **Step 2: 아키텍처에 본선 관측 가능성과 예선 개념의 축소 경계를 추가**

`예선 결과물 연결` 뒤에 다음 내용을 추가한다.

```markdown
## 관측 가능성 경계

- 공격은 `TARGETS`, `PORTS`, HTTP 응답, flag 제출 결과처럼 본선 인터페이스에서 실제 관측되는 신호만 계획 입력으로 사용합니다.
- 방어의 계약 입력은 Broker가 전달하는 원시 IP 패킷입니다. 차량 상태, 임무 의미, 파라미터 해시, 물리 상태는 파서와 fixture로 존재가 증명되기 전까지 판정 입력으로 사용하지 않습니다.
- 예선의 RTL, 롤백, HITL은 본선 에이전트가 직접 실행할 수 있는 인터페이스가 아닙니다. 런타임 제어는 동기 `ACCEPT/DROP` 판정과 판정을 막지 않는 비동기 분석으로 축소합니다.
```

- [ ] **Step 3: 공통 규칙 문서의 표현과 범위를 검증**

Run:

```powershell
git diff --check
rg -n "10회|버스트 20|분당 30회|30ms|0.3%|fail-open|300ms|5분|20분|관측 가능성" docs/references/rules-checklist.md docs/architecture.md
```

Expected: 각 수치와 관측 경계가 한 번 이상 검색되고 예선 합성 성능을 본선 성능으로 주장하지 않는다.

- [ ] **Step 4: 공통 규칙 변경을 커밋**

```powershell
git add -- docs/references/rules-checklist.md docs/architecture.md
git diff --cached --check
git commit -m "docs: align architecture with finals rules"
```

---

### Task 3: 공격·방어 런타임 계약 구체화

**Files:**
- Modify: `contracts/attacker/README.md`
- Modify: `contracts/defender/README.md`

**Interfaces:**
- Consumes: Task 2의 고정 본선 규칙
- Produces: 구현 담당자가 코드와 테스트에 직접 적용할 공격·방어 런타임 계약

- [ ] **Step 1: 공격 계약에 요청·제출·상태·비용 요구를 추가**

`네트워크 제한`과 `플래그 제출`을 보강해 다음을 명시한다.

```markdown
## 실행 제한

- 대상 방어망 요청은 공격 에이전트당 초당 10회, 버스트 20을 넘지 않습니다.
- flag 제출은 분당 30회를 넘지 않으며 HTTP 429에는 재시도 간격을 둡니다.
- `accepted`, `own_team`, `duplicate`, `rejected`, `closed` 결과를 구분하고 동일 flag의 불필요한 재제출을 막습니다.
- 라운드마다 컨테이너와 flag가 초기화되므로 캐시·중복 집합·관측 이력은 라운드 한정 임시 상태로 취급합니다.
- LiteLLM 호출에는 라운드별 예산을 두고 모델, 호출 목적, 토큰 사용량을 증빙할 수 있게 기록합니다. 인증 키와 flag 원문은 로그에 남기지 않습니다.
```

네트워크 제한에는 상대 팀 진입점, 제출 서버, 대회 LiteLLM Proxy만 허용되고 운영망·외부 인터넷·rate limit 우회는 금지된다고 명시한다.

- [ ] **Step 2: 방어 계약에 Broker 실패·시간·입력 의미를 추가**

기존 시간 계약 뒤에 다음 내용을 추가한다.

```markdown
## Broker 실패와 네트워크 의미

- NAT로 소스 IP가 정규화되므로 소스 IP만으로 공격자나 팀을 식별하지 않습니다.
- 각 레이어의 30ms 지연과 0.3% 손실을 고려하되 에이전트 내부에서 운영진 제한을 상쇄하려 하지 않습니다.
- 에이전트가 연결되지 않았거나 죽으면 Broker는 fail-open으로 패킷을 통과시킵니다.
- 300ms 안에 verdict가 도착하지 않으면 Broker는 해당 패킷을 DROP합니다.

## 입력 경계와 동시성

- 계약된 판정 입력은 PACKET 프레임의 `raw_ip`뿐입니다.
- 차량 상태, 임무 의미, 파라미터 해시, 물리 상태는 파서와 fixture로 필드 존재가 증명되기 전까지 사용하지 않습니다.
- heartbeat 송신, PACKET 수신, VERDICT 송신은 하나의 느린 분석 작업이 서로를 막지 않도록 분리합니다.
- 비동기 상관분석과 원격 LLM은 동기 verdict 반환 이후의 보조 경로에서만 실행합니다.
```

- [ ] **Step 3: 계약의 핵심 수치와 금지 가정을 검증**

Run:

```powershell
git diff --check
rg -n "10회|버스트 20|분당 30회|duplicate|토큰|NAT|30ms|0.3%|fail-open|300ms|raw_ip|heartbeat" contracts/attacker/README.md contracts/defender/README.md
```

Expected: 공격과 방어의 구현 입력이 명시되고, 방어 문서에 본선에서 제공되지 않는 상태를 직접 받는다는 주장이 없다.

- [ ] **Step 4: 런타임 계약 변경을 커밋**

```powershell
git add -- contracts/attacker/README.md contracts/defender/README.md
git diff --cached --check
git commit -m "docs: define finals runtime constraints"
```

---

### Task 4: Docker 이미지 운영 계약 문서화

**Files:**
- Modify: `integration/README.md`

**Interfaces:**
- Consumes: 본선 이미지 명명 규칙, pull 정책, 컨테이너 실행 제한
- Produces: Docker 담당자가 이미지·smoke test·Compose 설계에 적용할 운영 계약

- [ ] **Step 1: 이미지 이름과 라운드 생명주기를 추가**

다음 섹션을 추가한다.

```markdown
## 이미지 제출 계약

- 공격 이미지: `ligacr.azurecr.io/team{N}/attacker:latest`
- 방어 이미지: `ligacr.azurecr.io/team{N}/defender:latest`
- 운영진은 라운드 시작 5분 전에 `latest`를 pull하며 pull timeout은 20분입니다.
- 컨테이너는 라운드마다 새로 생성되고 종료 후 삭제됩니다. 이미지 시작 시간도 라운드 시간에 포함되므로 시작 경로를 짧게 유지합니다.

## 실행 제한

- 공통: `no-new-privileges`, memory reservation `2g`, CPU shares `2048`, PID limit `512`
- 방어: Linux capability 전체 제거(`cap-drop ALL`)와 Broker socket mount
- 비밀값과 환경별 주소는 이미지에 넣지 않고 운영진이 주입하는 환경변수와 socket만 사용합니다.
```

- [ ] **Step 2: Compose 연동 원칙을 기존 후속 단계와 연결**

`compose.agents.yml`이 공식 파일을 복사하지 않고 팀 이미지, 환경변수, 방어 socket mount만 override하며 Docker 변경에는 해당 에이전트 소유자와 팀장 검토가 필요하다고 명시한다.

- [ ] **Step 3: Docker 운영 계약을 검증**

Run:

```powershell
git diff --check
rg -n "ligacr.azurecr.io|5분|20분|no-new-privileges|2g|2048|512|cap-drop ALL|socket" integration/README.md
```

Expected: 두 이미지 이름, pull 정책, 자원 제한, 방어 socket 요구가 모두 검색된다.

- [ ] **Step 4: Docker 운영 문서를 커밋**

```powershell
git add -- integration/README.md
git diff --cached --check
git commit -m "docs: record finals image operations"
```

---

### Task 5: 원본 자료 비공개 이동과 최종 검증·푸시

**Files:**
- Create outside Git: `../Aegis.D4H-DAH2026-private/references/2026-08-10/MANIFEST.md`
- Move outside Git: 원본 5개 파일
- Verify: repository tracked files and branch history

**Interfaces:**
- Consumes: Task 1의 파일 ID와 SHA-256, Tasks 2~4의 문서 변경
- Produces: 해시가 검증된 비공개 원본 보관소와 원격 단기 브랜치

- [ ] **Step 1: 이동 대상과 목적지 충돌을 읽기 전용으로 검사**

Run:

```powershell
$archiveRoot = Join-Path (Split-Path -Parent (Get-Location)) 'Aegis.D4H-DAH2026-private\references\2026-08-10'
$sourceNames = @('DAH 예선_안내서.pdf', 'DAH2026_예선보고서_Aegis.0xD4H.pdf', 'DAH2026_본선운영세칙.pdf', 'DAH2026_본선_당일_진행_안내.md', 'DAH2026_스켈레톤코드_상세_설명.md')
$sourceNames | ForEach-Object { [pscustomobject]@{ Name = $_; SourceExists = Test-Path -LiteralPath $_ } }
Test-Path -LiteralPath $archiveRoot
```

Expected: 다섯 source가 모두 존재한다. 목적지가 이미 있으면 같은 이름의 파일 해시를 먼저 비교하고, 값이 다르면 이동을 중단한다.

- [ ] **Step 2: 이동 전 SHA-256을 검증**

Run:

```powershell
Get-FileHash -Algorithm SHA256 -LiteralPath 'DAH 예선_안내서.pdf', 'DAH2026_예선보고서_Aegis.0xD4H.pdf', 'DAH2026_본선운영세칙.pdf', 'DAH2026_본선_당일_진행_안내.md', 'DAH2026_스켈레톤코드_상세_설명.md' | Select-Object Path, Hash
```

Expected hashes, in the same order:

```text
F23CC3F96A1AA2FFBEBB9A46AFD82DBCEC34D72A5342B3EBEAB5E954666770BF
1DD42B99A8816C3B7A543929BA0AEE90E5565CFC853E19E1455F76631CD1894E
FFE8E6BEECB628F93F20A9F5D0F41203CADBF28EE7E56C9A91FDAB87A1655A5F
AA704A259A3A59B10A844A59AA6B1593DEDF31D99662B70A8D7CD58EFECD5D9E
BF1CC690C82605497A03B959B93784663EC6D7DFD9949DCBE9C7151B3C07A6AA
```

- [ ] **Step 3: 비공개 디렉터리와 로컬 매니페스트를 준비**

승인을 받아 `official`, `team-submission`, `derived-notes` 디렉터리를 만든다. `apply_patch`로 저장소 루트에 이동용 `reference-archive-manifest.md`를 만들되 stage하지 않고, 다음 내용 전체를 기록한다.

```markdown
# DAH 2026 Reference Archive Manifest

보관일: 2026-08-10

| 분류 | 파일 | SHA-256 | 권위와 보존 이유 |
|---|---|---|---|
| 공식 예선 자료 | `official/DAH 예선_안내서.pdf` | `F23CC3F96A1AA2FFBEBB9A46AFD82DBCEC34D72A5342B3EBEAB5E954666770BF` | 예선 목적과 제출 배경 확인 |
| 팀 제출 원본 | `team-submission/DAH2026_예선보고서_Aegis.0xD4H.pdf` | `1DD42B99A8816C3B7A543929BA0AEE90E5565CFC853E19E1455F76631CD1894E` | A1~A5, S1~S5와 상관분석 추적 근거 |
| 공식 본선 자료 | `official/DAH2026_본선운영세칙.pdf` | `FFE8E6BEECB628F93F20A9F5D0F41203CADBF28EE7E56C9A91FDAB87A1655A5F` | 본선 네트워크, 제출, 실행, 채점, 금지행위 기준 |
| 파생 팀 메모 | `derived-notes/DAH2026_본선_당일_진행_안내.md` | `AA704A259A3A59B10A844A59AA6B1593DEDF31D99662B70A8D7CD58EFECD5D9E` | 공식 운영세칙의 팀용 설명, 공식 원본보다 낮은 권위 |
| 파생 팀 메모 | `derived-notes/DAH2026_스켈레톤코드_상세_설명.md` | `BF1CC690C82605497A03B959B93784663EC6D7DFD9949DCBE9C7151B3C07A6AA` | 실제 스켈레톤 검증 전 이해 보조, 공식 guide와 관측 결과보다 낮은 권위 |

Git에는 이 파일들의 원본을 저장하지 않습니다. 사실 충돌 시 당일 운영진 안내, 본선 운영세칙, 공식 agent guide, 실제 스켈레톤, 예선 자료, 파생 팀 메모 순으로 판단합니다.
```

- [ ] **Step 4: 검증된 목적지로 각 파일과 매니페스트를 이동**

PowerShell의 `Move-Item -LiteralPath`만 사용해 PDF 두 개를 `official`, 예선 보고서를 `team-submission`, Markdown 두 개를 `derived-notes`, 임시 매니페스트를 보관 루트의 `MANIFEST.md`로 이동한다. 이동 직전에 `$archiveRoot`를 절대경로로 해석해 저장소의 형제 `Aegis.D4H-DAH2026-private` 아래인지 확인한다.

- [ ] **Step 5: 이동 후 파일 수와 해시를 재검증**

Run:

```powershell
Get-ChildItem -LiteralPath $archiveRoot -Recurse -File | Select-Object FullName, Length
Get-FileHash -Algorithm SHA256 -LiteralPath (Join-Path $archiveRoot 'official\DAH 예선_안내서.pdf'), (Join-Path $archiveRoot 'team-submission\DAH2026_예선보고서_Aegis.0xD4H.pdf'), (Join-Path $archiveRoot 'official\DAH2026_본선운영세칙.pdf'), (Join-Path $archiveRoot 'derived-notes\DAH2026_본선_당일_진행_안내.md'), (Join-Path $archiveRoot 'derived-notes\DAH2026_스켈레톤코드_상세_설명.md') | Select-Object Path, Hash
```

Expected: 원본 5개와 `MANIFEST.md`가 존재하고, 원본 5개의 해시가 Step 2와 정확히 일치한다.

- [ ] **Step 6: 저장소에 원본·비밀·절대경로가 남지 않았는지 검사**

Run:

```powershell
git ls-files -- 'DAH 예선_안내서.pdf' 'DAH2026_예선보고서_Aegis.0xD4H.pdf' 'DAH2026_본선운영세칙.pdf' 'DAH2026_본선_당일_진행_안내.md' 'DAH2026_스켈레톤코드_상세_설명.md'
git status --short --branch
rg -n "[A-Za-z]:\\Users\\|/Users/|/home/" .gitignore docs contracts integration
rg -n -i "(api[_-]?key|token|password)[[:space:]]*[:=][[:space:]]*[^<{[:space:]]" .gitignore docs contracts integration
```

Expected: `git ls-files`는 출력이 없고, status에는 원본 5개가 나타나지 않으며, 절대경로와 실제 비밀값 검색 결과가 없다.

- [ ] **Step 7: 필수 저장소 검사와 스켈레톤 가용성 확인**

Run:

```powershell
pwsh -NoProfile -File scripts/check-layout.ps1
Test-Path -LiteralPath '..\deploy'
```

Expected: `Repository layout check passed.`와 `False`. 외부 스켈레톤이 나중에 제공되면 다음 명령을 별도 실행한다.

```powershell
pwsh -NoProfile -File scripts/validate-skeleton.ps1 -SkeletonPath '..\deploy'
```

- [ ] **Step 8: 브랜치 diff와 커밋 범위를 최종 검증**

Run:

```powershell
git diff main...HEAD --check
git diff main...HEAD --name-only
git log --oneline --decorate main..HEAD
git status --short --branch
```

Expected: 변경 파일은 설계·계획 문서, `.gitignore`, `docs/references`, `docs/architecture.md`, 두 contracts README, `integration/README.md`뿐이고 worktree가 깨끗하다.

- [ ] **Step 9: 단기 브랜치를 원격에 푸시**

```powershell
git push -u origin docs/finals-source-alignment
```

- [ ] **Step 10: 원격 브랜치와 최종 커밋을 확인**

Run:

```powershell
git status --short --branch
git ls-remote --heads origin docs/finals-source-alignment
```

Expected: 로컬 브랜치가 `origin/docs/finals-source-alignment`를 추적하고 원격 HEAD가 로컬 `HEAD`와 일치한다.
