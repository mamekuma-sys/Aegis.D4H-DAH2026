# 방어 런타임 설계 인수인계

이 문서는 방어 담당자와 작업을 수행할 AI가 함께 읽는 단일 실행 지침이다. AI는 문서를 요약만 하지 말고 아래 순서대로 저장소와 공식 자료를 조사하고, 예선 보고서 54쪽을 전부 추적하며, 본선 방어 런타임 설계 문서를 작성하고, 검증하고, PR 준비 상태까지 완료한다.

## 1. 이번 작업의 목표

본선 방어 에이전트의 **PACKET 수신 → 제한된 파싱 → 300ms 이내 결정론적 판정 → VERDICT 송신 → 비동기 상관분석** 구조를 설계한다. 하나의 방어 런타임이 본선 `FinalsPhase 1~4`에서 누적 개방되는 레이어의 실제 트래픽을 증거 기반으로 식별하고, 정상 서비스의 SLA를 보존하면서 고신뢰 공격 패킷만 차단하도록 설계한다.

설계는 공식 Broker가 전달하는 `raw_ip`에서 실제로 관측되고 fixture로 증명된 필드만 사용해야 한다. 예선 보고서의 Mission Context, Golden Profile, Shadow State, 파라미터 해시, 기체 상태 같은 신호는 이름만 옮기지 않는다. 파서와 입력 fixture가 존재를 증명하지 못하면 비동기 연구 가설로 낮추거나 본선 런타임에서 제외한다.

이번 브랜치에서는 실제 방어 런타임 코드를 작성하지 않는다.

완료 산출물은 다음 세 파일이다.

- 새 파일: `docs/references/preliminary-report-defender-map.md`
- 새 파일: `docs/superpowers/specs/2026-08-11-defender-runtime-design.md`
- 수정 파일: `research/defense-mapping.md`

`docs/references/preliminary-report-defender-map.md`는 예선 보고서 PDF 54쪽 전체를 페이지별로 검토했다는 추적 근거다. 각 물리 PDF 페이지를 한 행씩 기록하고 본선 방어 설계에서 `계승`, `재설계`, `배경`, `제외` 중 하나로 판정한다. 각 행에는 관련 예선 시나리오, `FinalsPhase`, 본선 레이어, 관측 가능성, 동기 hot path 포함 여부를 함께 기록한다. 이 파일은 팀장 소유 경로이므로 방어 담당자가 초안을 작성하되 팀장 이경준이 내용과 원본 동일성을 검토한다.

`research/defense-mapping.md`에는 S1~S5와 예선 방어 방법별로 관측 증거, parser 요구사항, 동기·비동기·제외 판정, 차단 조건, SLA 보호 조건, 관련 `FinalsPhase`와 레이어를 추가한다. 설계 본문, 페이지 매핑, 방어 매핑 표는 서로 모순되면 안 된다.

## 2. 운영사무국 최신 안내

2026-08-11 팀장이 전달한 운영사무국 답변을 다음과 같이 적용한다.

- 예선 제출 소스와 본선 에이전트의 구현 일관성은 요구되지 않는다.
- 예선 대비 변경점을 별도로 제출할 필요가 없다.
- 본선 코드는 공식 스켈레톤 형식과 최신 본선 규칙에 맞게 변경하거나 재구현할 수 있다.
- 이 안내는 Broker 시간 계약, SLA, 네트워크 제한, 금지 행위, 증빙 의무를 완화하지 않는다.

예선 `DefenseAgent`는 synthetic `CommonEvent` 배치 입력을 처리한다. 본선 방어 에이전트는 Broker의 `raw_ip` 패킷을 온라인으로 처리하므로 예선 런타임을 통째로 복사하지 않는다. `CommonEvent`, Normalizer, Time Window, Causal Graph, Risk Scorer, Deterministic-AI 비교 구조는 본선 입력과 시간 계약에 맞게 선별 재설계한다.

본선 당일 진행 안내는 공식 운영세칙을 팀용으로 풀어쓴 파생 메모다. 운영 구조를 이해하는 입력으로 전체를 읽되, 공식 운영세칙·같은 날 운영진 공지·공식 스켈레톤과 충돌하면 상위 자료를 따른다.

## 3. 소스 우선순위

사실이 충돌하면 다음 순서를 적용한다.

1. 최신 본선 규칙과 같은 날 전달된 운영사무국 지침
2. 외부 공식 스켈레톤의 `deploy/docs/agent-guide.md`
3. 공식 스켈레톤에서 직접 관측한 동작
4. 예선 보고서와 예선 소스
5. 팀 작성 문서

팀 문서와 상위 자료가 충돌하면 팀 문서를 근거로 상위 자료를 재해석하지 않는다. 충돌 내용, 근거 경로, 설계 영향만 기록하고 팀장 이경준에게 확인을 요청한다.

## 4. 작업 전 브랜치 점검

이 문서는 `docs/defender-runtime-design` 브랜치에서 실행한다. 새 브랜치를 만들거나 `main` 또는 공격 설계 브랜치에서 직접 수정하지 않는다.

저장소 루트에서 다음을 실행한다.

```powershell
git status --short --branch
git fetch origin
git switch docs/defender-runtime-design
git pull --ff-only
git branch --show-current
git merge-base --is-ancestor 6c5f8ed HEAD
```

`git branch --show-current` 출력은 `docs/defender-runtime-design`이어야 하고 마지막 명령은 성공해야 한다. 커밋 `6c5f8ed`는 본선 자료 정렬 작업의 검토 완료 지점이다.

이 방어 설계 브랜치는 `docs/finals-source-alignment`의 정렬 커밋 위에 쌓여 있을 수 있다. 이 경우 설계 작업은 진행할 수 있지만, 방어 설계 PR을 `main`에 병합하기 전에 선행 정렬 PR이 먼저 병합됐는지 확인한다. 선행 PR이 병합된 뒤에는 `origin/main`이 현재 브랜치의 조상인지 다시 검증한다.

공격용 루트 `handoff.md`가 이 브랜치에 없더라도 정상이다. 방어 인수인계 문서는 `agents/defender/handoff.md`에 있으며 공격 설계 브랜치의 고유 커밋을 방어 브랜치에 merge하지 않는다.

다음 상황에서는 삭제, reset, 강제 checkout, 강제 push를 하지 말고 중단한다.

- 작업 트리에 본인이 만들지 않은 변경이 있다.
- 현재 브랜치가 `docs/defender-runtime-design`이 아니다.
- 정렬 커밋 `6c5f8ed`가 현재 브랜치에 포함되지 않았다.
- 브랜치에 출처를 알 수 없는 고유 커밋이 있다.
- 선행 정렬 PR보다 방어 설계 PR을 먼저 병합하려는 상태다.

## 5. 먼저 읽을 자료

다음 순서로 읽는다. 공식 스켈레톤과 비공개 원본은 이 저장소 밖에 있으며 개인 절대경로를 산출물에 기록하지 않는다.

1. `AGENTS.md`
2. 같은 날 운영사무국이 전달한 최신 안내
3. 비공개 공식 원본 `DAH2026_본선운영세칙.pdf` 전체
4. 외부 공식 스켈레톤의 `deploy/docs/agent-guide.md` 전체
5. 비공개 파생 메모 `DAH2026_본선_당일_진행_안내.md` 전체
6. `docs/references/rules-checklist.md`
7. `contracts/defender/README.md`
8. `contracts/fixtures/README.md`와 모든 defender 관련 fixture
9. `docs/architecture.md`
10. `docs/references/source-inventory.md`
11. `docs/references/preliminary-code-map.md`
12. 비공개 원본 `DAH2026_예선보고서_Aegis.0xD4H.pdf` 54쪽 전체
13. 비공개 예선 소스 snapshot의 README, `src/schema.py`, `src/config.py`, `src/correlation/**`, `src/agents/deterministic.py`, `src/agents/ai_module.py`, `src/agents/comparator.py`, `src/agents/defense_agent.py`, 관련 테스트
14. `agents/defender/README.md`
15. `research/preliminary-strategy.md`
16. `research/defense-mapping.md`
17. `docs/ownership.md`
18. `CONTRIBUTING.md`

공식 운영세칙과 당일 진행 안내의 동일성을 먼저 확인한다.

```powershell
$finalsRulesPath = Read-Host '본선 운영세칙 PDF 경로'
$finalsDayNotePath = Read-Host '본선 당일 진행 안내 Markdown 경로'
Get-FileHash -Algorithm SHA256 -LiteralPath $finalsRulesPath, $finalsDayNotePath
```

예상 SHA-256은 다음과 같다.

```text
DAH2026_본선운영세칙.pdf
FFE8E6BEECB628F93F20A9F5D0F41203CADBF28EE7E56C9A91FDAB87A1655A5F

DAH2026_본선_당일_진행_안내.md
AA704A259A3A59B10A844A59AA6B1593DEDF31D99662B70A8D7CD58EFECD5D9E
```

해시가 다르면 새 판본인지 확인하고 `docs/references/source-inventory.md`를 팀장 소유 변경으로 갱신하기 전까지 판본을 임의로 섞어 사용하지 않는다.

스켈레톤 루트가 제공됐다면 먼저 구조를 검증한다.

```powershell
pwsh -NoProfile -File scripts/validate-skeleton.ps1 -SkeletonPath <스켈레톤-루트>
```

스켈레톤 경로가 없으면 한 번만 요청한다. 공식 가이드 없이 소켓 메시지, 시간 계약, heartbeat 또는 fail-open 동작을 추정해서 설계를 확정하지 않는다.

비공개 예선 소스 snapshot이 현재 제공되지 않으면 한 번만 요청한다. 받을 수 없으면 `docs/references/preliminary-code-map.md`와 보고서를 근거로 설계하되, 소스 직접 검증을 완료했다고 표현하지 않고 차단 요소에 기록한다.

## 6. 예선 보고서 54쪽 전체 검토

예선 보고서는 방어 장만 골라 읽지 않는다. 표지, 목차, 공격자 모델, S1~S5, 방어 아키텍처, AI 에이전트, 평가, 한계, 결론, 부록, 참고문헌을 포함한 물리 PDF 페이지 1~54를 모두 읽고 시각 요소도 확인한다. 텍스트 추출 결과만으로 그림, 표, 각주를 검토했다고 간주하지 않는다.

### 6.1 원본 동일성 확인

원본 PDF는 저장소 밖 비공개 팀 보관소에서 읽는다. 저장소 안으로 복사하거나 추출 텍스트, 렌더링 이미지, 임시 PDF를 추가하지 않는다.

```powershell
$reportPath = Read-Host '예선 보고서 PDF 경로'
Get-FileHash -Algorithm SHA256 -LiteralPath $reportPath
```

예상 SHA-256은 다음과 같다.

```text
1DD42B99A8816C3B7A543929BA0AEE90E5565CFC853E19E1455F76631CD1894E
```

해시가 다르거나 페이지 수가 54가 아니면 다른 판본일 수 있으므로 작업을 중단하고 팀장에게 보고한다.

### 6.2 페이지별 매핑 작성

`docs/references/preliminary-report-defender-map.md`에 원본 ID `PRELIM-REPORT`, 예상 SHA-256, 확인한 물리 페이지 수 54를 기록하고 다음 표를 작성한다.

| PDF 페이지 | 인쇄 페이지 | 절·그림·표 | 핵심 내용 요약 | 관련 S1~S5 | 관련 FinalsPhase·레이어 | 필요한 입력 필드 | 관측 증거 | 방어 경로 | 판정 | 본선 근거 | 반영 위치 또는 제외 이유 |
|---:|---:|---|---|---|---|---|---|---|---|---|---|

표에는 PDF 페이지 1부터 54까지 정확히 한 행씩 넣는다. 인쇄 페이지 번호가 없으면 `없음`으로 기록한다. 여러 페이지를 한 행으로 묶거나 표지·목차·참고문헌이라는 이유로 생략하지 않는다.

`방어 경로`는 다음 네 값 중 하나만 사용한다.

- `동기`: 현재 PACKET의 300ms verdict hot path에 포함 가능한 결정론적 처리
- `온라인 비동기`: 현재 verdict 뒤에 수행하고 이후 패킷의 제한된 상태 판단을 보조
- `오프라인`: PCAP·로그 분석과 다음 이미지 개선에만 사용
- `제외`: 공식 입력이나 실행 권한이 없어 본선 에이전트에 사용하지 않음

`판정`은 다음 네 값 중 하나만 사용한다.

- `계승`: 본선 설계에도 같은 원칙을 직접 사용
- `재설계`: 목적이나 아이디어는 유지하지만 본선 입력·출력·시간·네트워크 계약에 맞게 구조를 변경
- `배경`: 위협 모델, 평가 맥락, 가용성 원칙처럼 판단의 배경으로만 사용
- `제외`: synthetic 전용, 본선에서 관측 불가, 실행 권한 없음 등의 이유로 사용하지 않음

`제외`도 누락이 아니다. 제외 이유와 이를 뒷받침하는 본선 근거를 반드시 적는다. 장문의 원문이나 표 전체를 복사하지 말고 팀의 표현으로 요약한다.

### 6.3 빠짐없이 추출할 관점

보고서의 실제 목차와 내용을 기준으로 다음 관점을 놓치지 않는다. 보고서에 없는 항목을 만들어 채우지는 않는다.

- 5개 세그먼트와 5계층 방어 아키텍처의 역할
- 공격자 모델 A1~A5의 능력, 전제, 가용성 인식
- S1~S5의 선행조건, 관측 신호, 방어 방법, 차단·복구 정책
- Normalizer → Time-Window Correlator → Causal Graph Matcher → Risk Scorer 파이프라인
- Common Event Schema의 필드와 그 필드가 본선 `raw_ip`에서 실제 생성 가능한지
- Mission Context Validator가 요구하는 mission plan, vehicle state, mission phase
- Golden Profile과 해시 체인이 요구하는 전체 파라미터 세트와 변경 이력
- Physics-Based Detector와 Shadow State가 요구하는 명령, 센서, 역학 파라미터
- S4 5단계 인과 체인의 세션·기체·시간·계층 연결 키
- Deterministic-AI 이중 판단과 입력 파이프라인 독립성
- Schema·통계·서명 기반 AI 입력 검증
- Graduated Response, Graceful Degradation, availability-aware 원칙
- HITL, RTL, Land, rollback, session lock 등 본선 에이전트가 직접 실행할 수 없는 액션
- DR, FPR, MTTD, MTTR, Mission Availability 목표와 synthetic 실측값의 성격 차이
- 예선 프로토타입의 배치 입력, 결정론적 시드, 8개 synthetic dataset, 평가 한계
- 보고서가 명시한 SITL·실 로그·임계 보정·확장 과제
- 표·그림·각주가 본문에 추가하는 제약 또는 의미

공격 중심 내용도 생략하지 않는다. 각 시나리오가 방어 rule의 입력 증거가 되는지, 본선 인터페이스에서 관측 불가해 제외되는지 판정한다.

### 6.4 예선 개념의 기본 재분류

다음 표는 시작점이며 최종 판정은 공식 skeleton 관측과 fixture로 확정한다.

| 예선 개념 | 본선 기본 판정 | 이유 |
|---|---|---|
| `CommonEvent` | 재설계 | `raw_ip`에서 증명 가능한 IP·L4·검증된 애플리케이션 필드만 사용 |
| Normalizer | 재설계 | 잘림·fragment·미지원 프로토콜에서도 verdict를 막지 않는 bounded parser 필요 |
| Time Window | 재설계 | verdict 이후 bounded queue와 TTL 상태로 운영 |
| Causal Graph | 재설계 | session_id·vehicle_id 대신 실제 파싱된 flow·protocol key만 사용 |
| Risk Scorer | 재보정 | 보고서 synthetic 점수와 15→52→131→196→238을 본선 threshold로 사용 금지 |
| Deterministic Module | 선별 계승 | 계산량이 작고 입력이 증명된 규칙만 hot path 후보 |
| AI Module | 직접 이식 금지 | 예선 구현은 실제 LLM/ML이 아닌 feature rule이며 본선에서는 verdict 뒤 조언만 허용 |
| Comparator | 재설계 | 독립 입력이 실제 확보되는지 증명하고 오프라인 또는 비동기에서 사용 |
| Mission Context Validator | 조건부 제외 | mission plan·vehicle state·mission phase가 `raw_ip` parser로 증명되기 전에는 사용 불가 |
| Golden Profile·파라미터 해시 | 조건부 제외 | 전체 기준 파라미터와 변경 이벤트가 제공된다는 계약이 없음 |
| Physics-Based Detector·Shadow State | 조건부 제외 | 제어 명령·센서·역학 파라미터와 동기화된 상태가 계약 입력이 아님 |
| Graduated Response | 원칙 계승 | 본선 출력은 ACCEPT/DROP뿐이므로 고신뢰 DROP·불확실 ACCEPT로 축소 |
| HITL·RTL·Land·rollback | 런타임 제외 | 본선 방어 에이전트에 해당 실행 인터페이스가 없음 |
| DR·FPR·MTTD 목표 | 배경 | 설계 목표일 뿐 본선 측정값이 아니며 fixture와 실측으로 새로 보정 |

### 6.5 전체 보고서에서 설계로 연결

페이지 매핑을 먼저 완료한 뒤 방어 설계를 작성한다.

- `계승`과 `재설계`로 판정한 각 항목은 설계 문서의 정확한 절을 `반영 위치`에 기록한다.
- 설계 문서의 주요 결정은 관련 보고서 PDF 페이지와 페이지 매핑 행을 역참조한다.
- S1~S5는 이름만 옮기지 말고 원래 전제, 필요한 관측 신호, 탐지·차단·복구 조건, 한계를 확인한다.
- 예선 성능 수치, synthetic 탐지율, synthetic 위험도 점수를 본선 예상 성능이나 DROP threshold로 사용하지 않는다.
- 보고서 내용이 본선 규칙이나 공식 스켈레톤과 충돌하면 본선 자료를 우선하고 보고서 항목은 `재설계` 또는 `제외`로 판정한다.
- 보고서에 있지만 본선에서 관측 또는 실행할 인터페이스가 증명되지 않은 기능은 코드 계획에 넣지 않는다.

54쪽 전체 검토가 끝나지 않으면 방어 런타임 설계 문서를 완료 처리하지 않는다.

## 7. 본선 FinalsPhase 1~4 적응 전략

### 7.1 서로 다른 Phase 용어 분리

문서와 향후 코드에서 다음 세 개념을 다른 이름과 타입으로 취급한다.

| 이름 | 개수 | 의미 | 사용 제한 |
|---|---:|---|---|
| `FinalsPhase` | 1~4 | 본선에서 레이어가 누적 개방되는 경기 단계 | 운영 일정 설명에 사용하며 런타임 env로 주어진다고 가정하지 않음 |
| `S4ChainStage` | 1~5 | 예선 보고서 S4의 다단계 공격 체인 국면 | `FinalsPhase` 번호와 대응한다고 가정하지 않음 |
| `MissionState` | 구현 보류 | 이륙 전·순항·임무·복귀 같은 기체 상태 | 수신 패킷 parser와 fixture로 존재가 증명될 때만 사용 |

문맥 없이 `Phase 1`, `P1` 같은 표현을 사용하지 않는다. 예선 보고서의 S4 5-Phase는 설계 문서에서 `S4ChainStage 1~5`로 다시 표기한다.

### 7.2 공식 본선 구조와 방어 목표

본선은 4개 `FinalsPhase`, 총 14개 Round다. 새 레이어가 열려도 이전 레이어는 닫히지 않는다.

| FinalsPhase | Round 수 | 새 레이어 | 누적 개방 | 방어 초기 목표 | 사용 전 필요한 증거 |
|---|---:|---|---|---|---|
| 1 | 2 | Layer 1 위성망 게이트웨이 | L1 | 정상 트래픽 기준선, parser 안전성, heartbeat·latency 안정화 | 실제 패킷, 정상 SLA 흐름, protocol·port fixture |
| 2 | 4 | Layer 2 임무 통제 서버(MCS) | L1~L2 | MCS 트래픽 fingerprint와 세션·명령 패턴 후보 검증 | 애플리케이션 프로토콜과 필드가 payload에서 파싱됨 |
| 3 | 4 | Layer 3 무인이동체(UAV) | L1~L3 | UAV 관련 telemetry·command 후보를 별도 parser로 검증 | 실제 메시지 형식·길이·field fixture와 정상 traffic negative 사례 |
| 4 | 4 | Layer 4 사족보행 로봇(UGV) | L1~L4 | UGV를 UAV와 별도 profile로 식별하고 전체 레이어 회귀 | UGV 고유 프로토콜·정상 트래픽·공격 증거 |

이 표는 프로토콜 또는 취약점 목록이 아니다. 위성망 게이트웨이를 예선 Communication 세그먼트와 동일시하거나 MCS를 GCS와 동일시하지 않는다. UAV parser·threshold를 UGV에 복사하지 않는다.

### 7.3 하나의 누적 적응형 런타임

`FinalsPhase`별로 네 개의 방어 이미지나 네 개의 독립 프로그램을 만들지 않는다. 하나의 런타임이 다음 원칙으로 모든 레이어를 처리한다.

- 공식 환경변수는 `AGENT_SOCKET`, `LLM_BASE_URL`, `LLM_API_KEY`뿐이다.
- 공식 계약에 없는 `PHASE`, `LAYER`, `ROUND`, `TEAM_ID` 환경변수를 요구하지 않는다.
- `raw_ip`의 검증된 네트워크·전송·애플리케이션 필드로 `ObservedTrafficProfile`을 만든다.
- destination subnet, port, protocol을 레이어 식별에 사용하려면 실제 Broker packet과 fixture로 일치함을 먼저 증명한다.
- NAT로 정규화된 source IP를 공격자·팀 식별자 또는 신뢰 점수로 사용하지 않는다.
- 새 레이어가 열려도 이전 레이어의 정상 트래픽 fixture와 검증된 규칙을 계속 회귀 테스트한다.
- protocol을 식별하지 못한 패킷은 공격으로 간주하지 않고 빠르게 `ACCEPT`한다.
- 새 rule은 현재 이미지에 자동 생성·적용하지 않는다. PCAP·로그 근거, 양성·정상 fixture, 리뷰를 거쳐 다음 이미지에 포함한다.

### 7.4 FinalsPhase별 기본 라운드 목표

다음은 초기 운영 가설이다. 실제 로그, PCAP, flag 탈취 결과, SLA 결과가 다르면 관측 증거를 우선해 순서를 바꾼다.

| FinalsPhase | Round 1 | Round 2 | Round 3 | Round 4 |
|---|---|---|---|---|
| 1 | L1 정상 packet inventory, heartbeat와 verdict latency 기준선 측정 | 고신뢰 규칙 후보 검증, 정상 SLA fixture 회귀, parser 오류 제거 | 해당 없음 | 해당 없음 |
| 2 | 새 MCS traffic fingerprint와 L1 회귀 | 검증된 protocol에서만 S1 명령·세션 패턴 후보 분석 | L1↔L2 온라인 상관 키 검증과 오탐 측정 | 효과 없는 rule 제거, 검증된 최소 rule 안정화 |
| 3 | 새 UAV protocol 식별과 L1~L2 회귀 | 실제 파라미터 field가 보일 때만 S2 후보 검증 | telemetry와 상태 field가 충분할 때만 S3 후보 검증 | 관측된 key가 이어질 때만 L1~L3 S4 상관 후보 검증 |
| 4 | UGV를 UAV와 다른 profile로 식별하고 L1~L3 회귀 | UGV 증거로 S2·S3 후보를 독립 재검증 | L1~L4 bounded correlation과 S4 후보 검증 | 고신뢰 rule만 유지하고 오탐·latency·메모리 안정화 |

각 Round 목표에는 새 parser 또는 rule의 관측 근거, 정상 negative fixture, DROP 조건, rollback 조건, latency 측정, 다음 Round로 가져갈 비밀 없는 산출물을 명시한다.

### 7.5 당일 20분 Round와 10분 Break 운영

방어 담당자의 설계에는 런타임뿐 아니라 다음 이미지로 개선하는 운영 루프도 포함한다.

```text
현재 Round 20분
  → 에이전트 상태·heartbeat·verdict latency·SLA 관찰
  → 10분 간격 로그·PCAP에서 오탐·미탐·protocol 근거 분석
  → 다음 버전 parser·rule·threshold와 정상 fixture 수정
  → Break 시작 시 최종 테스트와 이미지 빌드
  → Break 전반 5분 안에 Registry push 완료
  → 운영 측 pull 상태 확인
  → 다음 Round에서 새 이미지·SLA 회귀 검증
```

- 운영 측은 다음 Round 시작 5분 전에 `latest` 이미지를 가져간다.
- Break 후반까지 코드를 작성하는 계획을 세우지 않는다.
- 실행 중인 컨테이너는 새 push의 영향을 받지 않으며 다음 Round부터 반영된다.
- 방어 담당자는 변경한 parser, rule ID, latency, 정상 fixture, rollback 기준을 Docker 담당자에게 즉시 전달한다.
- Docker 담당자가 빌드·push를 수행하고, 방어 담당자와 팀장 이경준이 방어 이미지 변경을 검토한다.
- SLA 급락 시 새 공격 탐지율보다 정상 서비스 복구를 우선하고 직전 검증 이미지로 되돌릴 수 있어야 한다.
- 같은 날 운영진이 일정을 변경하면 현장 공지를 우선하고 이 기본 타임라인을 갱신한다.

### 7.6 Round 간 학습과 상태 경계

컨테이너와 런타임 메모리는 Round마다 초기화된다. PCAP 원본, 전체 payload, 자격증명, 토큰, 상대 팀 정보, flag를 이미지나 저장소에 넣지 않는다.

다음 Round로 가져갈 수 있는 것은 팀이 검토한 비밀 없는 개발 산출물뿐이다.

- protocol·field parser 개선
- 고신뢰 rule과 reason code
- 정상·공격 packet에서 민감 내용을 제거한 최소 fixture
- false-positive를 재현하는 regression fixture
- bounded state의 TTL·capacity 조정
- verdict latency와 heartbeat cadence 측정 결과
- 실패한 가설과 rule rollback 기준

Round 간 상관은 숨은 영속 상태가 아니라 코드·테스트·검토된 설정의 새 버전으로 구현한다.

### 7.7 적응 실패와 fallback

- 새 protocol을 식별하지 못하면 bounded IP/L4 파싱만 수행하고 `ACCEPT`한다.
- parser가 예외를 내거나 지원되지 않는 packet이면 `pkt_id`를 읽을 수 있는 경우 즉시 `ACCEPT`한다.
- 새 레이어 분석이 실패해도 이전 레이어의 heartbeat, verdict, 정상 회귀 규칙은 계속 동작한다.
- 비동기 queue는 고정 길이 FIFO와 `put_nowait`을 사용한다. 가득 차면 들어오려는 최신 event를 O(1)로 폐기(drop-newest)하고 기존 순서를 보존하며 현재 packet verdict를 지연하지 않는다.
- LLM 장애, timeout, quota 소진은 heartbeat, parser, policy, verdict를 막지 않는다.
- 메모리 압박 시 오래된 correlation state와 advisory를 먼저 제거하고 hot path 상태를 bounded limit 안에서 유지한다.
- 이미지 build 또는 push가 pull 시각을 놓치면 이전 이미지가 사용되거나 에이전트 없이 시작할 수 있음을 운영 담당자와 팀장에게 즉시 보고한다.

## 8. 고정된 본선 계약

설계에서 다음 조건을 정확히 보존한다.

### 8.1 입력과 소켓

- `AGENT_SOCKET`: Broker 통신 Unix socket, 기본값 `/run/agent.sock`
- 소켓: `AF_UNIX` / `SOCK_SEQPACKET`
- `router/broker.yaml`의 `agent-event.sock`은 사용하지 않는다.
- 계약된 판정 입력은 PACKET frame의 `raw_ip`뿐이다.
- `LLM_BASE_URL`과 `LLM_API_KEY`는 선택적 비동기 조언 경로에만 사용한다.

### 8.2 메시지 형식

모든 정수는 big-endian이다.

| 타입 | 방향 | 프레임 |
|---|---|---|
| `0x01` PACKET | Broker → Agent | `type(1) + pkt_id(8) + pkt_len(2) + raw_ip(pkt_len)` |
| `0x02` VERDICT | Agent → Broker | `type(1) + pkt_id(8) + verdict(1)` |
| `0x05` HEARTBEAT | Agent → Broker | `type(1)` |

Verdict 값은 `0x00` ACCEPT, `0x01` DROP이다. `pkt_len`, 실제 payload 길이, 최대 허용 길이, trailing bytes 처리 정책을 설계와 테스트에서 명시한다.

### 8.3 시간·실패 계약

- PACKET 수신 후 300ms 안에 VERDICT를 반환한다.
- 약 1초마다 HEARTBEAT를 보낸다.
- Broker는 3초 이상 HEARTBEAT가 없으면 에이전트가 죽은 것으로 판단한다.
- 에이전트가 없거나 죽으면 Broker는 fail-open으로 모든 패킷을 통과시킨다.
- VERDICT가 300ms를 넘으면 Broker는 해당 패킷을 DROP한다.
- Broker의 300ms를 구현 목표로 사용하지 않는다. 설계는 내부 deadline과 여유 시간을 별도로 둔다.
- 판정 soft cutoff는 PACKET 수신 후 5ms, 내부 send hard cutoff는 200ms, Broker deadline은 300ms다. socket fault timeout 최대 50ms는 정상-path p99 예산이 아니라 blocked send를 탐지하는 별도 상한이다.

### 8.4 네트워크와 관측 경계

- NAT로 source IP가 정규화되므로 source IP만으로 공격자·팀을 식별하지 않는다.
- 각 레이어의 30ms 지연과 0.3% packet loss를 고려하되 에이전트 내부에서 운영진 제한을 상쇄하려 하지 않는다.
- 차량 상태, 임무 의미, 파라미터 해시, 물리 상태, 정상 기준선은 parser와 fixture로 존재가 증명되기 전까지 판정 입력으로 사용하지 않는다.
- raw packet payload가 존재해도 protocol version, encoding, fragmentation, encryption을 확인하지 않고 semantic field를 읽었다고 간주하지 않는다.

### 8.5 이미지와 런타임 경계

- 공격·방어 이미지는 독립된 단일 Docker 이미지다.
- 방어 컨테이너는 `--cap-drop ALL`, `no-new-privileges`, memory reservation 2GB, CPU shares 2048, pids limit 512 조건으로 실행된다.
- `/run/agent.sock` mount가 필요하다.
- 각 Round마다 새 컨테이너가 생성되고 종료 후 삭제된다.
- 시작 시간은 Round 시간에 포함된다.
- 외부 인터넷은 차단되고 대회 LiteLLM Proxy만 제공된다.

### 8.6 점수와 SLA

- Round 점수는 `(공격 점수 + 방어 점수) × SLA`다.
- 방어 점수는 `10 × (배치된 flag 수 - 탈취당한 고유 flag 수)`이며 최소 0이다.
- 개방된 서비스에는 Round마다 랜덤한 주기로 총 100회의 SLA check pattern이 전달된다.
- SLA는 `100 - 실패 count`이며 실패 1회가 전체 합산 점수에 곱해지는 계수를 낮춘다.
- 고신뢰 공격 차단보다 넓은 DROP rule로 정상 요청을 막는 것이 전체 점수에 더 큰 손실을 줄 수 있다.
- 동점이면 LLM token 비용이 적은 팀이 우선하므로 비동기 LLM도 예산과 근거를 관리한다.

## 9. 설계 문서에 반드시 포함할 내용

`docs/superpowers/specs/2026-08-11-defender-runtime-design.md`를 다음 구조로 작성한다. 각 절은 결정 사항, 선택 이유, 실패 시 동작, 관련 테스트를 포함해야 한다.

### 9.1 범위와 비범위

범위에는 Broker session, PACKET parser, deterministic policy, VERDICT, HEARTBEAT, bounded online state, verdict 이후 correlation, optional LLM advisory, structured logging, metrics, shutdown을 포함한다.

비범위에는 Dockerfile 확정, 공통 계약 수정, official skeleton 복사, 원격 LLM의 packet별 동기 호출, 실제 기체 제어, RTL/Land/rollback/HITL 실행, 자동 rule 생성·실시간 self-modification, 영속 packet 저장을 포함한다.

### 9.2 근거 추적표

주요 설계 결정을 다음 열로 기록한다.

| 결정 | 상위 근거 | 예선 보고서 페이지 | 관측 증거·fixture | 동기/비동기/제외 | 실패 시 동작 | 테스트 |
|---|---|---:|---|---|---|---|

공식 규칙과 예선 아이디어가 충돌하면 상위 근거를 우선하고 차이를 명시한다.

### 9.3 런타임 흐름

다음 흐름을 순서와 동시성 경계까지 설계한다.

```text
startup validation
  → AGENT_SOCKET connect/reconnect
  → independent heartbeat scheduler and single SocketWriter
  → PACKET frame receive and header validation
  → bounded raw IP parser
  → pre-approved deterministic policy
  → ACCEPT/DROP VERDICT enqueue
  → SocketWriter-only VERDICT/HEARTBEAT send
  → latency record
  → bounded async event enqueue
  → time-window/correlation/advisory/log analysis
```

- PACKET receive, verdict decision, HEARTBEAT scheduling, socket send, async analysis의 책임을 분리한다.
- socket write는 `SocketWriter` 단일 스레드만 수행한다. verdict producer와 heartbeat scheduler는 frame을 만든 뒤 bounded priority queue에 `put_nowait`하고 socket 또는 writer lock을 직접 사용하지 않는다.
- queue key는 VERDICT `(0, broker_deadline, sequence)`, HEARTBEAT `(1, due_at, sequence)`로 고정해 가장 이른 VERDICT deadline을 모든 HEARTBEAT보다 먼저 보낸다. heartbeat item은 최대 하나로 coalesce한다.
- writer 상태는 `DISCONNECTED → READY → SENDING → READY|FAULT → DISCONNECTED`와 `STOPPED`로 한정한다. timeout·partial send·socket 오류·로컬 만료는 current session item을 폐기하고 재연결하며 새 session에 verdict를 replay하지 않는다.
- VERDICT의 `broker_remaining = received_at + 300ms - monotonic_now`, `send_wait = min(50ms, broker_remaining - 100ms)`를 dequeue 직후와 send 직전에 계산한다. `broker_remaining <= 100ms`이면 200ms 내부 hard cutoff로 로컬 폐기·재연결한다.
- 50ms는 socket fault timeout이고 정상 p99 send 목표가 아니다. shutdown과 reconnect 중 중복 writer·heartbeat thread, orphan queue, stale socket이 남지 않게 한다.

### 9.4 300ms hot path 예산

설계는 다음 초기 내부 예산을 명시적으로 승인하거나 더 엄격한 실측값으로 교체한다. 300ms 전체를 소비하는 설계는 승인하지 않는다.

| 구간 | 초기 목표 |
|---|---:|
| frame header validation·unpack | p99 50μs 이하 |
| bounded IP/L4 parse | p99 150μs 이하 |
| deterministic policy·immutable snapshot lookup | p99 150μs 이하 |
| VERDICT pack·writer enqueue | p99 50μs 이하 |
| writer queue·정상 socket send | p99 100μs 이하 |
| hot path 합계 | p50 150μs 이하, p99 500μs 이하 |
| 판정 soft cutoff | PACKET 수신 후 5ms — `ACCEPT` enqueue |
| 내부 send hard cutoff | PACKET 수신 후 200ms — 로컬 폐기·재연결 |
| Broker deadline | PACKET 수신 후 300ms |
| socket fault timeout | 최대 50ms — 정상 p99 예산과 별도 |

- 모든 시간은 wall clock이 아니라 monotonic clock으로 측정한다.
- 정상-path 구성요소 p99 상한 합은 `50+150+150+50+100=500μs`로 선언한 p99 목표를 넘지 않는다.
- `pkt_id`를 읽은 뒤 5ms soft cutoff에 도달하면 안전한 fallback verdict `ACCEPT`를 즉시 writer에 enqueue한다. 200ms hard cutoff, 300ms Broker deadline, 50ms socket fault timeout을 서로 대체하지 않는다.
- parsing failure, unknown protocol, async queue full, LLM failure를 이유로 300ms timeout DROP을 유발하지 않는다.
- 성능 실측이 초기 목표를 충족하지 못하면 rule 또는 parser를 hot path 밖으로 이동한다. 숫자를 문서에서 조용히 완화하지 않는다.

### 9.5 기본 verdict 정책

기본 정책은 **불확실하면 빠르게 ACCEPT, 고신뢰 증거가 있을 때만 DROP**이다.

`DROP`에는 다음 조건이 모두 필요하다.

1. packet 구조가 성공적으로 파싱됐다.
2. rule이 참조하는 모든 field의 존재와 encoding이 fixture로 증명됐다.
3. rule ID, protocol scope, layer/profile scope, match reason이 결정론적이다.
4. 동일 protocol의 정상 negative fixture를 통과한다.
5. latency와 bounded state 조건을 통과한다.
6. rule rollback 조건과 owner가 기록돼 있다.

다음은 `DROP` 사유가 아니다.

- parser exception 또는 지원하지 않는 protocol
- source IP가 특정 값이라는 사실만으로 내린 판단
- LLM의 공격 의심 문장 또는 confidence
- 예선 synthetic Risk Score threshold 초과
- state가 없거나 correlation queue가 가득 찬 상태
- heartbeat 또는 분석 worker 장애
- 새 레이어를 아직 식별하지 못한 상태

header가 유효해 `pkt_id`를 알지만 raw IP가 잘렸거나 비정상이면 `ACCEPT`와 비민감 reason code를 반환한다. `type=0x01` PACKET frame이 11-byte header보다 짧아 `pkt_id`를 알 수 없으면 존재하지 않는 ID로 verdict를 만들지 않고 socket을 닫아 재연결한다. 짧은 frame을 다음 seqpacket과 이어 붙이거나 프로세스를 종료하지 않는다.

### 9.6 구성요소 경계

각 구성요소의 입력, 출력, 시간 예산, 소유 상태, 실패 격리를 정의한다.

- `RuntimeConfig`: 환경변수 검증과 안전한 기본값
- `BrokerSession`: Unix socket 연결, reconnect, receive lifecycle
- `FrameCodec`: PACKET validation과 VERDICT·HEARTBEAT serialization
- `SocketWriter`: bounded deadline-priority queue와 socket send를 소유하는 단일 writer thread
- `HeartbeatScheduler`: 약 1초 cadence와 지연 감시
- `PacketParser`: bounded IP/L4 및 증명된 application parser dispatch
- `HotPolicy`: pre-approved rule과 immutable correlation snapshot의 bounded single read
- `AnomalyMonitor`: packet-derived metric 집계와 alert publication만 수행하며 runtime policy state는 변경하지 않음
- `VerdictSender`: deadline-aware frame 생성·writer enqueue와 latency 측정
- `EventAdapter`: verdict 이후 관측 field를 correlation event로 최소 변환
- `CorrelationBuilder`: worker 전용 TTL·capacity mutable state와 frozen snapshot 생성
- `CorrelationSnapshotRef`: worker가 참조 하나를 원자 교체하고 hot path가 lock 없이 한 번 읽는 publication 경계
- `CausalMatcher`: 관측된 key만 사용하는 비동기 chain match
- `RiskModel`: 본선 fixture로 보정된 비동기 우선순위
- `AdvisoryWorker`: redacted feature만 사용하는 optional LLM 조언
- `AuditLogger`: payload·secret 없이 reason·latency·health 기록
- `Metrics`: verdict count, accept/drop, parser failure, queue drop, heartbeat gap, latency distribution

한 구성요소의 예외가 heartbeat 또는 이미 받은 PACKET의 verdict를 막지 않게 한다.

### 9.7 상태와 데이터 모델

향후 구현자가 바로 타입을 만들 수 있도록 최소 필드와 불변조건을 설계한다.

- `PacketEnvelope`: `pkt_id`, `declared_len`, `raw_ip`, `received_at_monotonic`
- `ParsedPacket`: IP version, protocol, source/destination field, ports, bounded payload view, parser status
- `FlowKey`: 실제 파싱된 안정적인 tuple만 포함하며 NAT source identity를 신뢰하지 않음
- `ObservedTrafficProfile`: protocol·port·validated parser version·normal evidence
- `RuleMatch`: `rule_id`, confidence class, evidence fields, profile scope, reason code
- `VerdictDecision`: `pkt_id`, ACCEPT/DROP, rule ID, reason code, elapsed time
- `CorrelationEvent`: redacted observed field, timestamp, flow key, event type, evidence source
- `CorrelationState`: TTL, last update, bounded counters, matched stages
- `CorrelationSnapshot`: generation, published/expires monotonic, immutable `FlowKey → frozen score` map; publication 후 변경 금지
- `AsyncAdvisory`: input feature IDs, recommendation, model ID, token usage, expiration; runtime authority 없음

모든 collection에 max capacity와 eviction 정책을 둔다. Round 종료 후 상태가 사라지는 것을 정상으로 취급하고 disk persistence를 요구하지 않는다.

### 9.8 parser와 관측 증명

parser별로 다음 증거를 문서화한다.

- protocol/version 식별 byte와 최소 길이
- variable length, options, checksum, fragment, truncation 처리
- encrypted 또는 unknown payload 처리
- 추출 field의 byte offset 또는 decode rule
- positive fixture와 정상 negative fixture
- malformed fixture와 expected ACCEPT fallback
- parser 시간·메모리 상한
- 지원하지 않는 variant에서의 동작

IPv4만 지원한다고 가정하지 않는다. official skeleton에서 IPv4만 관측됐다면 그 사실과 fixture를 기록하고 IPv6 또는 unknown version은 bounded fallback으로 처리한다.

새 application parser는 PCAP 전체나 비밀 데이터를 저장소에 넣지 않는다. 재현에 필요한 최소 byte만 비식별 fixture로 만들고 원본 PCAP은 비공개 팀 보관소의 논리 ID와 hash로 참조한다.

### 9.9 동기 정책과 SLA 보호

hot policy의 rule 우선순위, conflict resolution, expiry, rollback을 설계한다.

1. frame 또는 parser failure: 빠른 ACCEPT
2. 검증된 정상 traffic: ACCEPT
3. 고신뢰 exact signature 또는 pre-approved multi-signal rule: DROP
4. 애매한 anomaly 또는 비동기 분석 필요: ACCEPT + async event
5. rule conflict: SLA를 보존하는 ACCEPT + conflict metric

각 DROP rule은 다음 기록을 가진다.

- immutable `rule_id`와 설명
- source PCAP/log logical ID와 관측 시각
- protocol·field parser version
- 적용 profile·layer 범위
- 공격 positive fixture
- 정상 negative와 SLA fixture
- expected verdict와 reason code
- activation 근거와 expiration
- rollback 조건과 직전 안전 버전
- 방어 담당자와 팀장 review 상태

phase 또는 port 전체를 blanket DROP하는 rule을 금지한다. 서비스 정상성을 검사하지 않은 allowlist/denylist를 도입하지 않는다.

`raw_drop_rate`, `baseline_violation_rate`, `rule_concentration`, `promotion_cohort_conflict`를 포함한 packet-derived 지표는 organizer-guaranteed SLA 또는 정상-health 신호가 제공되기 전까지 metric·경보·Break 분석 전용이다. 공격자는 signature 반복 자극, 정상 형태 replay, profile 경계 탐색으로 이 값을 오염할 수 있으므로 Round 중 `SHADOW`·`CANARY`·`ACTIVE`, canary 비율, rule scope, threshold, PolicyBundle을 자동 변경하지 않는다. rollback·승격은 Break에서 방어 담당자가 공식 SLA 결과와 fixture를 대조하고 팀장 이경준이 승인한 새 bundle을 다음 image에 넣을 때만 발생한다.

### 9.10 온라인 상관분석

예선 Correlation Engine은 verdict 이후 경로로 재설계한다.

- current packet의 verdict를 기다리게 하지 않는다.
- queue는 고정 길이 FIFO이며 producer는 `put_nowait`만 사용한다. full이면 들어오려는 newest event를 O(1)로 폐기하고 기존 queue를 scan·재정렬하지 않는다.
- 단일 correlation worker가 `monotonic timestamp + TTL + max keys + per-key cap` mutable builder를 독점한다.
- out-of-order, duplicate, late event 처리 규칙을 정한다.
- session_id, vehicle_id, mission phase는 실제 parser가 생성한 경우에만 correlation key로 사용한다.
- S4 `S4ChainStage` matcher는 관측된 event와 key만 사용하며 보고서 15→52→131→196→238 점수를 복사하지 않는다.
- correlation 결과는 현재 packet을 소급 차단할 수 없다.
- worker는 builder를 alias 없는 private `dict`로 복사해 `types.MappingProxyType`으로 감싸고, `@dataclass(frozen=True)`·tuple entry만 넣은 새 snapshot을 만든 뒤 `current_snapshot = next_snapshot` 참조 하나를 원자적으로 교체한다. builder와 snapshot 내부 값은 공유하지 않는다.
- hot policy는 함수 시작에서 `snapshot = current_snapshot`을 한 번만 읽고 같은 generation에서 최대 한 번의 bounded key lookup만 한다. writer lock 또는 publication lock을 획득하거나 global reference를 다시 읽지 않는다.
- missing, stale, key miss, generation 오류 snapshot은 즉시 `ACCEPT`한다. 유효 score도 사전 승인된 rule만 사용한다.
- online state만으로 새 executable rule을 생성하지 않는다.

### 9.11 LLM 사용 경계

LLM은 선택적 비동기 조언자다.

- remote LLM 호출을 packet별 synchronous verdict path에 넣지 않는다.
- LLM timeout, quota, invalid response, proxy 장애가 heartbeat·verdict에 영향을 주지 않는다.
- raw packet payload, secret, token, flag, full PCAP, 개인 정보, 인증 header를 prompt에 보내지 않는다.
- parser가 만든 redacted feature, aggregate metric, rule ID, 비민감 reason만 입력 후보로 사용한다.
- LLM 출력은 현재 또는 이후 packet을 직접 ACCEPT/DROP하지 않는다.
- LLM이 작성한 signature 또는 code를 실행 중 image에 자동 반영하지 않는다.
- 조언은 사람이 PCAP·정상 fixture와 대조해 다음 Round rule 후보로만 사용한다.
- model ID, call count, token usage, 실패율을 증빙 가능한 비민감 형태로 기록한다.

### 9.12 오류 처리와 복구

각 오류의 탐지, hot-path verdict, heartbeat 영향, reconnect, log, 종료 조건을 정한다.

- `AGENT_SOCKET` 누락·경로 없음·permission denied
- connect 실패와 Broker가 아직 준비되지 않은 startup race
- Broker orderly close와 socket reset
- unknown message type
- PACKET header truncation
- `pkt_len`과 실제 payload length 불일치
- duplicate 또는 out-of-order `pkt_id`
- raw IP malformed·fragmented·unknown version
- parser exception과 policy exception
- send failure와 partial send 가능성
- heartbeat 지연·thread death
- async queue overflow와 worker crash
- state capacity 초과와 clock discontinuity
- LLM timeout·429·invalid JSON·quota exhaustion
- SIGTERM과 Round 종료

retry에는 bounded backoff와 shutdown interrupt를 둔다. reconnect 중 오래된 packet verdict를 새 session으로 보내지 않는다.

short-frame 정책은 결정되어 있다. `type=0x01`이고 총 길이가 11 byte 미만이면 `pkt_id`를 만들 수 없으므로 verdict 없이 socket close·reconnect한다. 11-byte header가 완전하고 선언 길이만 불일치하면 해당 `pkt_id`에 `ACCEPT`한다.

### 9.13 향후 파일 구조

설계 문서에서 다음 후보 구조를 검토하고 각 파일의 단일 책임을 확정한다. 실제 파일은 승인 후 구현 브랜치에서 만든다.

```text
agents/defender/
├── src/aegis_defender/
│   ├── __init__.py
│   ├── main.py
│   ├── config.py
│   ├── protocol.py
│   ├── session.py
│   ├── heartbeat.py
│   ├── packet.py
│   ├── policy.py
│   ├── rules.py
│   ├── state.py
│   ├── events.py
│   ├── correlation/
│   │   ├── __init__.py
│   │   ├── window.py
│   │   ├── causal.py
│   │   └── risk.py
│   ├── advisory.py
│   ├── logging.py
│   └── metrics.py
└── tests/
    ├── test_protocol.py
    ├── test_session.py
    ├── test_heartbeat.py
    ├── test_packet.py
    ├── test_policy.py
    ├── test_state.py
    ├── test_correlation.py
    ├── test_advisory.py
    ├── test_timing.py
    └── test_round_lifecycle.py
```

파일 수를 늘리는 것이 목표가 아니다. 책임이 겹치면 합치고, heartbeat·verdict·async analysis의 failure domain이 섞이면 분리한다. 실제 dependency와 entrypoint는 Docker 담당자와 검토하되 Dockerfile은 방어 담당자가 단독 확정하지 않는다.

### 9.14 테스트 전략과 승인 기준

테스트는 코드보다 먼저 작성하는 TDD 순서를 설계에 명시한다.

#### Broker protocol

- 제공된 PACKET fixture에서 type, `pkt_id`, `pkt_len`, `raw_ip`를 big-endian으로 정확히 해석
- ACCEPT·DROP VERDICT byte가 공식 fixture와 일치
- HEARTBEAT가 정확히 1 byte `0x05`
- unknown type과 trailing bytes 처리
- `type=0x01`, 총 길이 `<11` short header는 verdict 없이 socket close·reconnect하고, 완전한 header의 length mismatch는 해당 `pkt_id`에 ACCEPT
- `SOCK_SEQPACKET` message boundary 보존

#### heartbeat와 session

- 정상 부하와 async 부하에서 heartbeat cadence가 약 1초 유지
- heartbeat gap이 3초에 접근하기 전에 metric·failure handling 작동
- connect race, disconnect, reconnect, shutdown
- reconnect 후 worker와 heartbeat가 하나씩만 존재
- fake clock으로 heartbeat와 VERDICT를 동시에 enqueue해도 single writer만 fake socket에 쓰고 VERDICT가 먼저 전송됨
- writer를 멈춘 채 HEARTBEAT와 deadline이 다른 VERDICT 둘을 넣은 뒤 재개하면 earliest VERDICT, later VERDICT, HEARTBEAT 순서여서 priority inversion이 없음
- blocked fake-socket send는 `min(50ms, broker_remaining-100ms)` 안에 timeout되고 session queue 폐기·reconnect되며 verdict를 새 session에 replay하지 않음

#### parser와 policy

- IPv4·관측된 protocol positive fixture
- 정상 traffic negative fixture
- truncated, fragment, unknown protocol, unsupported version에서 빠른 ACCEPT
- NAT source IP만 바뀌어도 verdict가 달라지지 않음
- 각 DROP rule의 positive·negative·boundary fixture
- rule conflict에서 ACCEPT와 metric

#### timing과 load

- monotonic timing 사용
- 최소 1, 100, 500, 1000 packet/s load profile 측정
- hot path p50, p95, p99, max 기록
- 목표 환경에서 p50 150μs 이하, p99 500μs 이하, 300ms 초과 verdict 0건
- component p99 합이 500μs 이하이고 5ms soft cutoff, 200ms internal hard cutoff, 300ms Broker deadline, 50ms socket fault timeout이 fake clock에서 독립적으로 동작
- queue가 가득 차거나 LLM이 30초 멈춰도 hot path latency 기준 유지
- heartbeat와 verdict가 같은 socket writer를 사용할 때 starvation 없음

측정 환경이 공식 컨테이너와 다르면 환경 차이를 기록한다. 성능을 측정하지 않고 예상치만 적지 않는다.

#### bounded state와 correlation

- TTL expiry, max key eviction, per-key cap
- duplicate, late, out-of-order event
- queue saturation에서 newest event 하나만 O(1) drop되고 기존 FIFO 순서와 verdict latency가 변하지 않음
- worker가 snapshot을 연속 publish하는 동안 hot path read가 한 generation의 완전한 immutable 값만 보며 missing·stale snapshot은 ACCEPT
- snapshot read가 socket writer lock이나 publication lock을 획득하지 않음
- S4ChainStage가 FinalsPhase와 섞이지 않음
- 관측되지 않은 session_id·vehicle_id·MissionState를 요구하지 않음
- synthetic report score를 threshold로 사용하지 않음

#### SLA와 FinalsPhase 회귀

- 각 관측 profile의 정상 service request가 ACCEPT되고 application response가 유지됨
- 각 새 DROP rule마다 100회 SLA pattern 성격의 정상 fixture 회귀
- FinalsPhase N fixture set이 L1~LN을 모두 포함
- FinalsPhase 4에서 L1~L4 정상 회귀와 rule 회귀가 모두 실행
- UAV fixture에 맞춘 rule이 근거 없이 UGV fixture에 적용되지 않음
- 새 rule 활성화 전후 false positive count와 rollback 조건 기록
- attack-like baseline traffic으로 `raw_drop_rate`, `baseline_violation_rate`, `rule_concentration`, `promotion_cohort_conflict`를 모두 올려도 경보만 발생하고 runtime policy state는 불변
- packet-derived metric으로 Round 중 rollback·승격·전체 관찰 모드 전환이 불가능하며 Break 사람 승인 bundle에서만 상태가 변경됨

#### 비동기 LLM·로그·보안

- LLM disabled, timeout, 429, malformed response에서 verdict와 heartbeat 정상
- LLM 출력이 policy를 직접 변경하지 않음
- token, API key, raw payload, flag, credential이 log·prompt에 없음
- queue drop, parser failure, rule match, latency가 비민감 reason code로 관측 가능
- PCAP, log, cache, 생성 결과가 Git에 추가되지 않음

#### 공식 skeleton 통합

- `scripts/validate-skeleton.ps1` 통과
- official Broker에 연결해 heartbeat·PACKET·VERDICT 왕복 검증
- agent 미기동·kill 시 Broker fail-open 관측
- 300ms 초과 시 Broker DROP 관측
- Round 재시작을 모사해 in-memory state가 초기화됨
- skeleton 파일을 수정하지 않고 Compose override 또는 Docker 담당 경계에서만 연결

## 10. `research/defense-mapping.md` 수정 방법

기존 표를 다음 구조로 보강한다.

| 예선 개념·S1~S5 | 보고서 페이지 | 필요한 신호 | 본선 관측 상태 | parser·fixture 증거 | 동기/비동기/오프라인/제외 | ACCEPT/DROP 영향 | SLA 보호·fallback | 관련 FinalsPhase·레이어 | 테스트 |
|---|---:|---|---|---|---|---|---|---|---|

각 행에서 다음을 지킨다.

- `가능`이라고만 쓰지 말고 어떤 packet field와 parser가 근거인지 적는다.
- 아직 확인되지 않은 것은 `미확인`으로 기록하고 runtime DROP rule에서 제외한다.
- Mission Context, Golden Profile, Physics-Based Detector는 필요한 신호가 실제로 없으면 `제외`다.
- Causal Graph와 Risk Scorer는 verdict 이후 비동기라는 점을 명시한다.
- S5 AI poisoning은 본선 LLM 입력 경계와 redaction이 실제 설계된 경우에만 다룬다.
- 예선 합성 점수·threshold를 본선 rule에 복사하지 않는다.
- 관련 FinalsPhase가 있어도 runtime은 공식 phase env를 요구하지 않는다.
- 모든 DROP 영향 행에는 정상 negative fixture와 rollback 조건이 있다.

## 11. 수정 금지 범위

이번 방어 설계 작업에서는 다음을 수정하지 않는다.

- `agents/defender/src/**`의 Python runtime code
- `agents/defender/tests/**`의 runtime test
- `agents/defender/Dockerfile`과 dependency lock
- `agents/attacker/**`
- `contracts/**`
- `integration/**`
- official skeleton의 `deploy/**`
- root 공격용 `handoff.md`
- raw PDF, PCAP, log, credential, token, flag, cache, generated output

공식 계약 오류를 발견하면 이번 브랜치에서 조용히 수정하지 않는다. 충돌과 근거를 기록하고 팀장 소유 후속 작업으로 분리한다.

## 12. 자체 검토

설계 작성 후 다음을 확인하고 발견한 문제를 문서 안에서 바로 수정한다.

- 본선 운영세칙과 당일 진행 안내 hash가 inventory와 일치한다.
- 공식 skeleton guide 전체와 Broker protocol을 확인했다.
- 본선 구조가 4개 FinalsPhase, 14개 Round, FinalsPhase N에서 L1~LN 누적 개방으로 기록돼 있다.
- `FinalsPhase`, `S4ChainStage`, `MissionState`가 혼용되지 않는다.
- FinalsPhase 1~4에 각각 2·4·4·4개의 방어 Round 목표가 있다.
- FinalsPhase별 별도 image가 아니라 하나의 누적 적응형 runtime으로 설계돼 있다.
- 공식 계약에 없는 `PHASE`, `LAYER`, `ROUND`, `TEAM_ID` env를 요구하지 않는다.
- 원본 보고서 hash가 `1DD42B99A8816C3B7A543929BA0AEE90E5565CFC853E19E1455F76631CD1894E`와 일치하고 물리 페이지 수가 54다.
- 페이지 mapping에 PDF 페이지 1~54가 각각 정확히 한 번 등장한다.
- 표지, 목차, 공격 scenario, 방어 장, AI agent, 평가, 한계, 결론, 부록, 참고문헌을 모두 검토했다.
- 각 페이지에 방어 경로와 `계승`, `재설계`, `배경`, `제외` 판정이 있다.
- `계승`과 `재설계` 항목은 방어 설계의 정확한 반영 위치를 가리킨다.
- S1~S5의 전제, 필요한 signal, 탐지·차단·복구, 한계를 검토했다.
- CommonEvent, Mission Context, Golden Profile, Shadow State, AI comparator를 관측 가능성에 따라 재분류했다.
- 예선 synthetic 지표와 score를 본선 threshold 또는 성능 주장에 사용하지 않는다.
- PACKET, VERDICT, HEARTBEAT frame과 big-endian 규약이 정확하다.
- 300ms hard deadline, 약 1초 heartbeat, 3초 death 판단, fail-open, timeout DROP이 정확하다.
- internal hot-path target과 emergency cutoff가 300ms보다 충분히 작다.
- remote LLM이 synchronous verdict path에 없다.
- unknown·malformed packet, parser exception, async overload의 fallback이 빠른 ACCEPT다.
- source IP만으로 공격자를 식별하지 않는다.
- current packet verdict와 async correlation의 책임이 분리돼 있다.
- state, queue, payload view, log가 모두 bounded다.
- DROP rule마다 positive·normal negative fixture, reason, scope, expiry, rollback이 요구된다.
- 정상 traffic과 SLA를 독립 승인 기준으로 다룬다.
- heartbeat, verdict, reconnect가 느린 분석에 막히지 않는다.
- HITL, RTL, Land, rollback, vehicle control을 runtime action으로 약속하지 않는다.
- 미결정 표시, 빈 절, 임시 문구가 없다.
- 향후 구현 파일과 테스트 책임이 일대일로 이해된다.
- 설계 문서와 `research/defense-mapping.md`가 모순되지 않는다.

문서에 불확실한 사실을 남겨 승인받는 방식으로 완료 처리하지 않는다. 설계에 영향을 주는 사실이 확인되지 않으면 해당 기능을 제외하거나 차단 요소로 보고한다.

## 13. 검증 명령

저장소 루트에서 실행한다.

```powershell
pwsh -NoProfile -File scripts/check-layout.ps1
git diff --check
git diff --name-status 6c5f8ed...HEAD
git status --short --branch
git ls-files -- '*.pdf' '*.pcap' '*.pcapng' '*.log'
rg -n "FinalsPhase|S4ChainStage|MissionState|300ms|HEARTBEAT|fail-open|SLA|ACCEPT|DROP|비동기|누적 개방|Break 전반 5분" docs/references/preliminary-report-defender-map.md docs/superpowers/specs/2026-08-11-defender-runtime-design.md research/defense-mapping.md
rg -n "TBD|TODO|추후 결정|나중에 구현|임시 문구" docs/references/preliminary-report-defender-map.md docs/superpowers/specs/2026-08-11-defender-runtime-design.md research/defense-mapping.md
```

`git ls-files`와 마지막 placeholder scan은 출력이 없어야 한다.

페이지 매핑은 다음 검사로 1~54가 정확히 한 번씩 기록됐는지 확인한다.

```powershell
$mapPath = 'docs/references/preliminary-report-defender-map.md'
$mappedPages = @(
    Get-Content -LiteralPath $mapPath | ForEach-Object {
        if ($_ -match '^\|\s*(\d+)\s*\|') {
            [int]$Matches[1]
        }
    }
)
$difference = Compare-Object -ReferenceObject (1..54) -DifferenceObject $mappedPages
if ($mappedPages.Count -ne 54 -or $difference) {
    throw '예선 보고서 페이지 매핑이 1~54를 정확히 한 번씩 포함하지 않습니다.'
}
Write-Output 'Preliminary report coverage check passed: 54/54 pages.'
```

스켈레톤 경로가 제공됐다면 다음도 실행한다.

```powershell
pwsh -NoProfile -File scripts/validate-skeleton.ps1 -SkeletonPath <스켈레톤-루트>
```

검증 결과에서 이번 설계 작업의 변경 파일은 원칙적으로 다음뿐이어야 한다.

```text
docs/references/preliminary-report-defender-map.md
docs/superpowers/specs/2026-08-11-defender-runtime-design.md
research/defense-mapping.md
```

기존 변경이 함께 보이면 덮어쓰거나 되돌리지 말고 본인 변경과 분리해 보고한다.

## 14. 커밋과 PR 준비

검증이 통과한 뒤 다음 커밋 메시지를 사용한다.

```text
docs: design defender runtime
```

PR 제목 권장안은 다음과 같다.

```text
[Defender] Design 300ms verdict and async correlation runtime
```

PR 본문에는 다음을 포함한다.

- 목표: 300ms verdict, heartbeat, 비동기 correlation, SLA-aware 방어 설계 확정
- 변경 파일과 각 파일의 역할
- 본선 운영세칙·당일 진행 안내 SHA-256 검증 결과
- official skeleton validation과 agent guide 확인 결과
- FinalsPhase 1~4 누적 레이어·Round 전략과 세 Phase 용어 분리
- 20분 Round·10분 Break·pull 5분 전을 반영한 이미지 개선 루프
- 예선 보고서 원본 SHA-256과 페이지 coverage `54/54`
- 페이지별 `계승`·`재설계`·`배경`·`제외` 및 동기·비동기·오프라인·제외 건수
- 예선 CommonEvent·Correlation·Mission Context·Golden Profile·Physics·Det-AI의 재분류 결과
- hot-path 내부 budget, ACCEPT fallback, DROP approval 기준
- bounded queue·state와 LLM 격리 결정
- SLA·false-positive 테스트와 rollback 기준
- 실행한 검증 명령과 실제 결과
- 상위 자료 충돌 또는 source snapshot 미제공 여부
- 다음 작업: 승인 후 최신 `main`에서 `feat/defender-runtime-foundation`을 만들어 테스트 우선 구현

필수 검토자는 팀장 이경준이다. Dockerfile이 포함되는 후속 PR은 방어 담당자와 팀장 모두 검토한다. push, PR 생성, 병합은 사용자가 명시적으로 요청하거나 저장소 자동화에서 권한이 확인된 경우에만 수행한다.

방어 설계 PR이 승인되기 전에는 실제 방어 runtime 구현 branch를 시작하지 않는다.

## 15. 완료 정의

다음 조건을 모두 만족해야 완료다.

- 정확한 방어 설계 브랜치에서 작업했다.
- 본선 source alignment 커밋을 포함했고 선행 PR 순서를 확인했다.
- 본선 운영세칙과 당일 진행 안내 원본 hash를 검증하고 전체 내용을 읽었다.
- official agent guide와 skeleton의 Broker 동작을 확인했다.
- FinalsPhase 1~4의 2·4·4·4 Round와 누적 레이어 개방을 설계에 반영했다.
- `FinalsPhase`, `S4ChainStage`, `MissionState`를 구분했다.
- 하나의 누적 적응형 runtime과 당일 Round 개선 loop를 설계했다.
- 인벤토리와 일치하는 예선 보고서 원본을 사용했다.
- 예선 보고서 물리 PDF 페이지 1~54를 모두 검토하고 페이지별 판정을 기록했다.
- `계승`과 `재설계` 항목이 설계 문서의 반영 위치와 연결돼 있다.
- S1~S5의 원래 전제·signal·탐지·차단·복구·한계를 확인했다.
- 예선 source snapshot을 직접 읽었거나 미제공 사실을 차단 요소로 명시했다.
- 설계가 Broker session, parser, policy, verdict, heartbeat, correlation, LLM, logging, 오류 처리, Round lifecycle을 모두 다룬다.
- 300ms hot path와 비동기 경계가 분리돼 있다.
- unknown·malformed·overload·LLM failure에서 빠른 ACCEPT fallback이 있다.
- DROP rule 승인 조건과 SLA rollback 기준이 있다.
- source IP, vehicle state, parameter hash 등 증명되지 않은 signal을 가정하지 않는다.
- bounded queue·state·log와 monotonic timing을 설계했다.
- 실제 runtime code, Dockerfile, 공통 contract, official skeleton을 수정하지 않았다.
- 필수 검증 명령이 통과했다.
- commit과 PR 본문이 준비됐다.
- 팀장 이경준에게 검토를 요청할 수 있는 상태다.

## 16. 최종 보고 형식

작업을 마친 AI는 다음 형식으로 방어 담당자와 팀장에게 보고한다.

```text
브랜치:
커밋:
작성·수정한 파일:
본선 운영세칙·당일 진행 안내 SHA-256 검증:
official skeleton·agent guide 검증:
FinalsPhase·누적 레이어·Round 전략 요약:
예선 보고서 원본 SHA-256 검증:
예선 보고서 페이지 커버리지:
계승·재설계·배경·제외 건수:
동기·온라인 비동기·오프라인·제외 건수:
확정한 hot-path budget과 fallback:
DROP rule·SLA 승인 기준:
예선 source snapshot 직접 검토 여부:
실행한 검증과 결과:
상위 자료 충돌 또는 차단 요소:
다음 단계:
```

차단 요소가 있으면 완료했다고 표현하지 않는다. 어떤 근거가 부족한지, 어떤 설계 결정이 영향을 받는지, 누가 무엇을 확인해야 하는지를 적는다.

## 17. 설계 승인 후의 다음 작업

이 문서의 작업이 완료되고 방어 설계 PR이 승인·병합된 뒤에만 구현을 시작한다.

```powershell
git switch main
git pull --ff-only
git switch -c feat/defender-runtime-foundation
```

후속 구현은 `superpowers:test-driven-development`를 사용하여 failing test → 최소 구현 → 관련 test 통과 → 작은 commit 순서로 진행한다. 첫 구현 순서는 Broker frame codec, session·heartbeat, ACCEPT-only timing baseline, bounded parser, deterministic policy, async event boundary다. 고신뢰 DROP rule과 application parser는 정상 negative fixture와 SLA regression이 확보된 뒤 별도 짧은 branch로 추가한다.

Dockerfile과 official skeleton 통합은 Docker 담당자 소유다. 방어 담당자는 실행 명령, dependency, socket, heartbeat, startup time, test 명령, 정상 log, shutdown, secret redaction 요구사항을 전달하고 방어 image 변경을 팀장과 함께 검토한다.
