# Defender Strategy Alternatives Review Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

> **Superseded decision notice (2026-08-13):** 이 문서는 당시 검토 과정을 보존하는 역사적 plan이다. 아래 완료 항목 중 packet-derived `baseline_violation_rate` 등으로 CANARY/ACTIVE를 runtime `SHADOW`로 자동 rollback하는 결정은 폐기됐다. organizer-guaranteed 정상-health/SLA 신호가 없는 동안 해당 지표는 metric·경보·Break 분석 전용이며, 상태 변경은 Break에서 방어 담당자와 팀장이 승인한 다음 PolicyBundle로만 수행한다. 최종 구현 권한은 `docs/superpowers/specs/2026-08-11-defender-runtime-design.md` §10.3과 `research/defense-mapping.md`에 있다.

**Goal:** A~H 방어 전략 제안을 본선 입력 계약과 라운드 운영에 대조해 채택·조건부 채택·제외로 판정하고, 기존 방어 설계 PR의 계산 및 서킷 브레이커 오류를 바로잡는다.

**Architecture:** 300ms 동기 경로에는 bounded parser, 고신뢰 signature, 사전 계산된 flow state 조회만 둔다. 무거운 분석과 LLM은 verdict 이후 또는 Break에 수행하고, rule과 임계값은 이미지에 포함된 별도 정책 파일로 관리한다. 당시에는 packet-derived 지표로 최근 승격 rule과 해당 traffic profile만 자동 rollback하는 범위 제한형 서킷 브레이커를 제안했으나, 위 supersession에 따라 finals runtime에는 구현하지 않는다.

**Tech Stack:** Markdown 설계 문서, Python 3.12 표준 라이브러리 전제, PowerShell 저장소 검사

## Global Constraints

- 판정 입력은 Broker가 전달하는 인바운드 `raw_ip`뿐이다.
- 모든 PACKET verdict는 300ms 안에 반환하고 원격 LLM을 동기 hot path에 넣지 않는다.
- NAT 환경에서 source IP만으로 공격자를 식별하지 않는다.
- 아웃바운드 응답과 상태코드는 관측 증거가 없으므로 사용하지 않는다.
- 컨테이너는 Round마다 재생성되며 rule 변경은 다음 이미지에 포함한다.
- 실제 런타임 구현은 observation-plan-execution 설계 승인 전 시작하지 않는다.

---

### Task 1: A~H 전략 근거 대조표

**Files:**
- Modify: `research/defense-mapping.md`

**Interfaces:**
- Consumes: `contracts/defender/README.md`의 입력·시간 계약과 방어 설계 §4, §6, §9~§12
- Produces: A~H별 `채택`, `조건부 채택`, `제외` 판정과 런타임 적용 경계

- [x] **Step 1: 제안의 원래 평가와 실패 모드를 보존한 비교표를 추가한다**

  A~H의 SLA 안전성, 미지 공격 대응, 지연, 구현 난이도, 초반 투입, 실패 모드를 표로 기록한다.

- [x] **Step 2: 본선 근거에 따른 판정을 추가한다**

  D/A/H는 채택, B/C/F는 조건부 채택, E/G는 인바운드 전용 계약 때문에 제외로 판정한다. D는 현재 PACKET의 300ms 의무를 없애지 않고 무거운 분석만 이후 packet으로 미룬다는 한계를 명시한다.

- [x] **Step 3: 라운드 계획을 layer/profile 범위로 재작성한다**

  R1~R2 관측, R3~R4 A 활성·B Shadow, R5~R8 검증된 profile만 B/CANARY, R9~R14 H 보강을 적용하되 새 레이어는 항상 Shadow부터 시작하도록 기록한다.

### Task 2: 기존 방어 설계 정정

**Files:**
- Modify: `docs/superpowers/specs/2026-08-11-defender-runtime-design.md`

**Interfaces:**
- Consumes: Task 1의 전략 판정
- Produces: 구현자가 사용할 점수 계산, 정책 파일, 중간 대응, 서킷 브레이커, 라운드 운영 규칙

- [x] **Step 1: 점수 손익분기 계산을 정정한다**

  `S=20`, SLA 100에서 flag 1개 손실 1,000점은 SLA 실패 `1,000 / 20 = 50회`와 같다고 고친다. 고정 `30%대` 결론을 제거하고 공격 점수와 잔존 flag 수에 따라 손익분기가 바뀐다고 명시한다.

- [x] **Step 2: 별도 정책 파일 계약을 추가한다**

  rule, profile scope, 승격 상태, threshold, 만료, rollback metadata를 이미지에 포함된 versioned JSON 파일에 저장하고 startup에서 schema·중복 ID·범위·정규식 안전성을 검증하도록 설계한다. active bundle 검증 실패 시 직전 검증 fallback을 사용하고 둘 다 실패할 때만 DROP rule 없이 시작한다.

- [x] **Step 3: 애매한 구간의 중간 대응을 결정론적으로 제한한다**

  무작위 packet DROP은 재현성과 SLA 예측을 해치므로 직접 채택하지 않는다. `SHADOW` 관측과 flow/profile 단위의 결정론적 `CANARY`만 허용하고, positive·negative·SLA fixture와 오탐 예산을 통과한 rule에 한정한다.

- [x] **Step 4: 서킷 브레이커를 범위 제한형으로 수정한다 — 역사적 완료, 자동 전환 결정은 폐기됨**

  당시에는 `baseline_violation_rate`를 공격자 영향이 남는 proxy로 정의하고 낮은 임계에서 최근 승격 CANARY cohort만 Shadow로 되돌리도록 제안했다. 최종 설계는 이 신호도 공격자가 오염할 수 있어 자동 rollback 근거로 부족하다고 판정했다. 현재 요구는 alert-only metric test와 Break 사람 승인 audit이며 Round 중 effective policy는 불변이다.

- [x] **Step 5: 절대 Round와 누적 layer 운영을 연결한다**

  기존 FinalsPhase별 표를 유지하면서 새 layer/profile은 매번 Shadow로 시작하고, 이전 layer의 검증된 rule만 계속 ACTIVE라는 원칙을 명시한다.

### Task 3: 검증과 PR 인계

**Files:**
- Verify: `docs/superpowers/plans/2026-08-11-defender-strategy-alternatives-review.md`
- Verify: `docs/superpowers/specs/2026-08-11-defender-runtime-design.md`
- Verify: `research/defense-mapping.md`

**Interfaces:**
- Consumes: Tasks 1~2의 문서 변경
- Produces: 팀장 검토 가능한 clean diff와 검사 결과

- [x] **Step 1: 문서 일관성을 검색한다**

  Run: `rg -n "33회|조작할 수 없는|전체 정책을 관찰 모드|확률적 DROP|아웃바운드|Golden Response" docs/superpowers/specs/2026-08-11-defender-runtime-design.md research/defense-mapping.md`

  Expected: 잘못된 `33회`와 무조건 전체 관찰 모드 표현이 없고, E/G 제외 근거와 F 조건부 판정이 존재한다.

- [x] **Step 2: 필수 저장소 검사를 실행한다**

  Run: `pwsh -NoProfile -File scripts/check-layout.ps1`

  Expected: `Repository layout check passed.`

- [x] **Step 3: 스켈레톤 검증기 회귀 테스트를 실행한다**

  Run: `pwsh -NoProfile -File scripts/tests/test-validate-skeleton.ps1`

  Expected: `Skeleton validator tests passed: 2 cases.`

- [x] **Step 4: 변경 범위와 소유권을 확인한다**

  Run: `git status --short` and `git diff --check`

  Expected: 변경은 방어 연구·설계 문서와 이 계획 문서에 한정되고 whitespace 오류가 없다.
