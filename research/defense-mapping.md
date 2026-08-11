# 예선 방어 개념의 본선 매핑

예선 보고서(`PRELIM-REPORT`, SHA-256 `1DD42B99…`, 54쪽)의 방어 개념을 본선 방어 런타임 관점에서 재분류한다. 페이지별 전수 검토 근거는 `docs/references/preliminary-report-defender-map.md`, 설계 본문은 `docs/superpowers/specs/2026-08-11-defender-runtime-design.md`에 있다. 세 문서는 서로 모순되지 않아야 한다.

## 전제

본선 방어 에이전트의 계약된 판정 입력은 Broker가 전달하는 **인바운드 `raw_ip` 패킷뿐**이다(운영세칙 제13조 1항, `contracts/defender/README.md`). 예선 보고서에 등장하는 신호는 이름을 옮기지 않는다. parser와 입력 fixture가 존재를 증명하지 못하면 비동기 연구 가설로 낮추거나 본선 런타임에서 제외한다.

`관련 FinalsPhase`가 있어도 런타임은 공식 phase 환경변수를 요구하지 않는다. 방어 환경변수는 `AGENT_SOCKET`, `LLM_BASE_URL`, `LLM_API_KEY`뿐이다(제16조 2항).

**예선의 합성 점수와 임계값을 본선 rule에 복사하지 않는다.** 보고서 §4.6·§5.2가 이 값들을 보정되지 않은 설계값으로 자체 명시한다.

## S1~S5 시나리오별 매핑

| 예선 개념·시나리오 | 보고서 페이지 | 필요한 신호 | 본선 관측 상태 | parser·fixture 증거 | 방어 경로 | ACCEPT/DROP 영향 | SLA 보호·fallback | 관련 FinalsPhase·레이어 | 테스트 |
|---|---:|---|---|---|---|---|---|---|---|
| **S1** GCS 계정 탈취 — Mission Context Validator | 17–19 | Mission Plan(웨이포인트·작전구역), Vehicle State(모드·위치·고도·배터리), Mission Phase | **제외** — 세 맥락 모두 `raw_ip`에 존재하지 않음 | 없음. parser 작성 불가 | **제외** | 없음. DROP rule을 만들지 않음 | 해당 없음 | 해당 없음 | 해당 없음 |
| S1 파생 — 명령 의미론 검증 원칙 | 5, 19 | 요청 내용과 맥락의 논리적 모순 | **미확인** — 애플리케이션 프로토콜 파싱이 선증명되어야 함 | `FinalsPhase 2` 이후 MCS 트래픽 fixture 필요 | 온라인 비동기 | 없음 | 미확인 상태에서 DROP rule 금지 | FinalsPhase 2~4 / L2~L4 | `test_correlation.py` |
| **S2** 파라미터 변조 — Golden Profile + 해시 체인 | 20–23 | 파라미터 전체 세트, `PARAM_SET` 메시지, 변경 이력 | **제외** — 파라미터 저장소가 노출되지 않음 | 없음 | **제외** | 없음 | 해당 없음 | 해당 없음 | 해당 없음 |
| S2 재정의 — 정상 트래픽 기준선(baseline profile) | 20, 35 | 관측된 정상 protocol·port·payload 패턴 집합 | **가능** — `FinalsPhase 1`에서 정상 트래픽을 수집해 구성 | IPv4/TCP 헤더 + bounded payload view. `FinalsPhase 1` 정상 fixture | 동기(조회) | **DROP 없음.** 서킷 브레이커의 `baseline_violation_rate` 산출에만 사용 | 이 지표가 관찰 모드 전환의 유일한 자동 트리거 | FinalsPhase 1~4 / L1~L4 | `test_breaker.py` |
| **S3** 센서 은폐 — Physics-Based Detector, Shadow State | 23–26 | 기체 질량·추력 계수·항력 계수, 명령·센서 시계열 | **제외** — 역학 파라미터와 기체 상태 모두 미관측 | 없음 | **제외** | 없음 | 해당 없음 | 해당 없음 | 해당 없음 |
| S3 파생 — 조작 불가 기준 선택 원칙 | 23 | 공격자가 통제할 수 없는 관측량 | **가능** — 개념으로 적용 | 정상 negative fixture 자체가 그 기준 | 동기 | 간접. DROP rule 활성화 조건(§6.1 4항)의 근거 | 서킷 브레이커 트리거 신호 선택에 적용 | FinalsPhase 1~4 / L1~L4 | `test_breaker.py` |
| **S4** Multi-stage — Causal Graph Matcher | 10, 27–29 | 이벤트 유형, 세션 ID, 기체 ID, 타임스탬프, 계층그룹 | **부분 가능** — flow key(5-tuple)와 monotonic 시각만 관측 가능. `session_id`·`vehicle_id`는 **미확인** | 관측된 flow key와 도착 시각. 애플리케이션 세션 키는 parser 선증명 필요 | **온라인 비동기 — verdict 이후 경로** | **없음. 상관 결과가 현재 packet을 소급 차단할 수 없다** | queue full 시 event 폐기, verdict 무영향 | FinalsPhase 2~4 / L1~L4 | `test_correlation.py` |
| S4 파생 — 체인 중간 선제 차단 | 10, 28 | 부분 매칭 상태 | **미확인** — 레이어 식별이 선증명되어야 함 | dst 3옥텟과 레이어 대응 관계 미증명(§16.1) | 온라인 비동기 | 이후 packet의 `Score` 조회에만 반영. 사전 승인된 rule 한정 | state 없으면 `ACCEPT` | FinalsPhase 2~4 / L2~L4 | `test_correlation.py` |
| S4 파생 — 미학습 변종 대응(다계층 집중 휴리스틱) | 28, 43 | 시간 윈도우 내 다계층 이상 이벤트 집중 | **미확인** — 레이어 식별 선증명 필요 | 위와 동일 | 온라인 비동기 | 없음. 조사 우선순위 신호로만 사용 | 해당 없음 | FinalsPhase 3~4 / L1~L4 | `test_correlation.py` |
| **S5** AI Poisoning — Deterministic-AI 이중판단 | 30–32, 41–42 | 독립 입력 파이프라인 2개, 판단 이력 | **가능** — 본선 시간 계약이 분리를 강제 | 동기 경로는 규칙만, LLM은 비동기 조언 전용 | 동기(규칙) + 온라인 비동기(조언) | **LLM 출력은 어떤 packet도 직접 ACCEPT/DROP 하지 않는다** | LLM 장애·timeout·quota 소진이 verdict와 HEARTBEAT에 영향 없음 | FinalsPhase 1~4 / L1~L4 | `test_advisory.py` |
| S5 파생 — AI 입력 검증 3단계 | 33 | 스키마 적합성, 입력 분포, 소스 서명 | **부분 가능** — 스키마 검증은 가능, 서명은 본선 이벤트에 없어 제외 | 자체 생성한 `CorrelationEvent` 스키마 | 온라인 비동기 | 없음 | 검증 미통과 입력은 LLM에 전달하지 않음 | FinalsPhase 1~4 | `test_advisory.py` |
| S5 파생 — 방어 시스템 자체가 공격 표면 | 11, 32 | 방어 동작을 유도하는 공격 패턴 | **가능** — 본선에서 서킷 브레이커 조작 형태로 재현 | raw DROP율 조작 시나리오 fixture | 동기 | 없음. 조작 시도 시에도 방어를 해제하지 않음 | raw DROP율을 자동 전환 트리거에서 제외 | FinalsPhase 1~4 / L1~L4 | `test_breaker.py` |

## 방어 파이프라인 구성요소별 매핑

| 예선 개념 | 보고서 페이지 | 필요한 신호 | 본선 관측 상태 | parser·fixture 증거 | 방어 경로 | ACCEPT/DROP 영향 | SLA 보호·fallback | 관련 FinalsPhase·레이어 | 테스트 |
|---|---:|---|---|---|---|---|---|---|---|
| Common Event Schema | 43 | 10개 필드(`session_id`, `vehicle_id`, `layer_group`, `signature` 포함) | **부분 가능** — 4개 필드 미관측 | 관측 가능한 필드만으로 `CorrelationEvent` 재정의(설계 §8) | 온라인 비동기 | 없음 | 변환 실패 시 event 폐기 | FinalsPhase 1~4 | `test_correlation.py` |
| Normalizer | 16, 40 | 계층별 원시 이벤트 | **가능** — `EventAdapter`로 축소 재설계 | 파싱 성공한 필드만 변환 | 온라인 비동기 | 없음. verdict 이후 실행 | 변환이 verdict를 지연시키지 않음 | FinalsPhase 1~4 | `test_correlation.py` |
| Time-Window Correlator | 16, 27 | 정규화 이벤트, 시간 근접성 | **가능** | monotonic 타임스탬프 + TTL + max keys + per-key cap | 온라인 비동기 | 없음 | out-of-order·duplicate·late event 처리 규칙 명시 | FinalsPhase 2~4 | `test_correlation.py` |
| Causal Graph Matcher | 27–29 | 사전 정의 체인 템플릿, 인과 키 | **부분 가능** — 관측된 key만 사용 | flow key와 시각. 보고서의 `S4ChainStage` 점수는 미사용 | 온라인 비동기 | 없음 | 매칭 실패가 hot path에 영향 없음 | FinalsPhase 2~4 | `test_correlation.py` |
| Risk Scorer | 16, 29, 40 | 앵커 점수, 계층 체인 보너스, 상관 보너스 | **부분 가능** — 구조만 계승, 점수표 미사용 | 본선 fixture로 보정한 값만 사용 | 온라인 비동기 | 이후 packet의 `Score` 조회에만 반영 | state 없으면 `ACCEPT` | FinalsPhase 2~4 | `test_correlation.py` |
| Risk Level 4단계 대응(INFO/LOW/HIGH/CRITICAL) | 16, 35 | 위험도 구간 | **제외** — 대응 액션이 본선 권한 밖 | 없음 | **제외** | 본선 출력은 `ACCEPT`/`DROP` 두 값뿐 | 해당 없음 | 해당 없음 | 해당 없음 |
| AI Defense Agent 자동 대응 | 16, 40 | 명령 차단·세션 제한·파라미터 롤백 | **제외** — 실행 인터페이스 없음 | 없음 | **제외** | 해당 없음 | 해당 없음 | 해당 없음 | 해당 없음 |
| HITL Console, 에스컬레이션, Timeout 정책 | 33–34 | 운용자 콘솔과 승인 절차 | **제외** — Round 20분 동안 사람 개입 불가(제6조 1항) | 없음 | **제외** | 해당 없음 | 사람 판단은 Break 때 이미지 개선으로 대체 | 해당 없음 | 해당 없음 |
| RTL·Land·Loiter·세션 잠금·파라미터 롤백 | 18, 22, 25, 28, 36 | 기체 제어 권한 | **제외** — 본선 에이전트는 패킷 필터 | 없음 | **제외** | 해당 없음 | 해당 없음 | 해당 없음 | 해당 없음 |

## 가용성·운영 원칙 매핑

| 예선 개념 | 보고서 페이지 | 본선 관측 상태 | 방어 경로 | ACCEPT/DROP 영향 | SLA 보호·fallback | 관련 FinalsPhase·레이어 | 테스트 |
|---|---:|---|---|---|---|---|---|
| Availability-First Response | 13, 35 | **가능** | 동기 | 불확실하면 빠른 `ACCEPT` | 설계 §6 기본 정책의 근거 | FinalsPhase 1~4 / L1~L4 | `test_policy.py` |
| Graduated Response(단계적 대응) | 35 | **부분 가능** — 출력이 2값이라 단계가 rule 승격 단계로 이동 | 동기 | `SHADOW`→`CANARY`→`ACTIVE` 승격 단계로 재구현 | 신규 rule은 관찰 전용부터 시작 | FinalsPhase 1~4 | `test_policy.py` |
| Graceful Degradation | 35 | **가능** | 동기 | 위험 임계에서 전체 관찰 모드(전부 `ACCEPT`) | 최대 지속 시간 후 자동 복귀 | FinalsPhase 1~4 | `test_breaker.py` |
| Mission-Phase Awareness | 35 | **제외** — `MissionState` 미관측 | **제외** | 없음 | 해당 없음 | 해당 없음 | 해당 없음 |
| Fail-Safe by Default | 13 | **재해석** — 본선의 안전 기본값은 차단이 아니라 통과 | 동기 | parser 실패·overload·LLM 장애에서 `ACCEPT` | Broker fail-open과 방향 일치 | FinalsPhase 1~4 | `test_policy.py` |
| Hard Negative(정상이나 의심스러운 케이스) | 43 | **가능** | 오프라인 | 각 DROP rule의 정상 negative fixture로 직접 반영 | 오탐률을 정직하게 측정하는 근거 | FinalsPhase 1~4 | `test_policy.py` |
| 회귀 가드(정답을 입력에 넣지 않는 반순환 테스트) | 46 | **가능** | 오프라인 | 없음 | fixture 기반 검증의 설계 원칙 | 해당 없음 | `test_policy.py` |
| 표준 라이브러리만 사용한 결정론적 재현 | 44 | **가능** | 오프라인 | 없음 | 서드파티 의존성 0개 유지(설계 §9.3·§14) | 해당 없음 | 해당 없음 |
| 예선 정량 지표(DR·FPR·MTTD·Precision·Recall) | 12, 37, 45 | **제외** — synthetic N=8 상대 비교값 | **제외** | 본선 threshold로 사용 금지 | 해당 없음 | 해당 없음 | 해당 없음 |

## DROP 영향이 있는 항목의 승인 조건

위 표에서 `ACCEPT`/`DROP` 영향이 있는 항목은 현재 **정상 트래픽 기준선(baseline profile)** 하나뿐이며, 이마저도 DROP을 발생시키지 않고 서킷 브레이커 지표 산출에만 쓰인다.

실제 `DROP` rule은 `FinalsPhase 1`의 관측 이후에 개별로 추가되며, 각 rule은 설계 §6.1의 6조건과 §10.2의 기록 항목을 모두 충족해야 한다. 최소 요건은 다음과 같다.

- 공격 positive fixture와 **동일 protocol의 정상 negative fixture**
- 100회 SLA check pattern 성격의 정상 fixture 회귀 통과
- `rule_id`, protocol scope, layer/profile scope, reason code
- **rollback 조건과 직전 안전 버전**
- 방어 담당자와 팀장 이경준의 review 상태

`미확인`으로 표시된 신호는 runtime `DROP` rule에서 제외한다. 관측 증거가 확보되면 해당 행을 갱신하고 rule 승격 절차를 밟는다.
