# 예선 방어 개념의 본선 매핑

예선 보고서(`PRELIM-REPORT`, SHA-256 `1DD42B99…`, 54쪽)의 방어 개념을 본선 방어 런타임 관점에서 재분류한다. 페이지별 전수 검토 근거는 `docs/references/preliminary-report-defender-map.md`, 설계 본문은 `docs/superpowers/specs/2026-08-11-defender-runtime-design.md`에 있다. 세 문서는 서로 모순되지 않아야 한다.

## 전제

본선 방어 에이전트의 계약된 판정 입력은 Broker가 전달하는 **인바운드 `raw_ip` 패킷뿐**이다(운영세칙 제13조 1항, `contracts/defender/README.md`). 예선 보고서에 등장하는 신호는 이름을 옮기지 않는다. parser와 입력 fixture가 존재를 증명하지 못하면 비동기 연구 가설로 낮추거나 본선 런타임에서 제외한다.

`관련 FinalsPhase`가 있어도 런타임은 공식 phase 환경변수를 요구하지 않는다. 방어 환경변수는 `AGENT_SOCKET`, `LLM_BASE_URL`, `LLM_API_KEY`뿐이다(제16조 2항).

**예선의 합성 점수와 임계값을 본선 rule에 복사하지 않는다.** 보고서 §4.6·§5.2가 이 값들을 보정되지 않은 설계값으로 자체 명시한다.

`raw_drop_rate`, `baseline_violation_rate`, `rule_concentration`, `promotion_cohort_conflict` 등 packet-derived 지표는 organizer-guaranteed 정상-health/SLA 신호가 없는 현재 계약에서 **metric·경보·Break 분석 전용**이다. Round 중 runtime `SHADOW`·`CANARY`·`ACTIVE`나 effective policy를 자동 변경할 수 없고, rollback·승격은 Break에서 공식 SLA 결과와 fixture를 대조한 뒤 방어 담당자와 팀장이 승인한 새 bundle로만 수행한다.

## A~H 전략 대안 검토

아래 평가는 전달받은 전략 비교안을 본선 입력 계약과 대조한 결과다. 원안의 평가는 비교 맥락을 보존하기 위해 그대로 기록하되, 실제 채택 여부는 오른쪽의 본선 판정을 따른다.

| 전략 | 원안 SLA 안전성 | 원안 미지 공격 | 원안 지연 | 원안 구현 난이도 | 초반 투입 | 원안 실패 모드 |
|---|---|---|---|---|---|---|
| A 시그니처+행위 | 중 | 낮음 | 중 | 낮음 | 가능 | rule 누적 → 오탐 증가 |
| B 화이트리스트 | 낮음(위험) | 높음 | 낮음 | 중 | R3부터 | profile 미비 → SLA 전멸 |
| C 프로토콜 정합성 | 중 | 높음 | 높음 | 높음 | 조건부 | parser 버그 → 정상 차단 |
| D 지연 집행 | 매우 높음 | 중 | 매우 낮음 | 낮음 | 가능 | 원샷 공격을 막지 못함 |
| E 아웃바운드 | 높음 | 높음 | 낮음 | 중 | 조건부 | 전제 불성립 시 무용 |
| F 확률적 DROP | 중 | 중 | 매우 낮음 | 매우 낮음 | 가능 | 공격 지연만, 차단은 아님 |
| G Golden Response | 높음 | 중 | 중 | 중 | 학습 필요 | 동적 응답에 취약 |
| H LLM 사전 컴파일 | 높음 | 중 | 없음 | 낮음 | 가능 | Round 내 대응 불가 |

### 본선 계약에 따른 판정

| 전략 | 판정 | 본선 적용 형태 | 원안에서 수정할 점 |
|---|---|---|---|
| **A 시그니처+행위** | **채택** | 고신뢰 exact signature는 동기 `Sig`, 누적 행위 계산은 비동기 `Corr`, 이후 packet은 bounded `Score` 조회 | 행위 계산을 300ms 경로에 넣지 않는다. rule은 profile 범위·만료·정상 negative fixture를 가져야 한다 |
| **B 화이트리스트** | **조건부 채택** | 엄격 allowlist가 아니라 정상 baseline과 profile 이탈을 `SHADOW`로 측정하는 용도 | profile 이탈만으로 바로 DROP하지 않는다. 정상 구조 안에서 실행되는 미지 공격은 잡지 못하므로 미지 공격 커버리지를 `높음`으로 단정하지 않는다 |
| **C 프로토콜 정합성** | **조건부 채택** | 관측된 protocol의 parser와 의미 invariant가 fixture로 증명된 경우에만 profile-scoped rule로 사용 | malformed·unknown·parser exception은 `ACCEPT`한다. 형식상 정상인 공격은 통과하므로 미지 공격 커버리지는 parser가 증명한 invariant 범위에 한정된다 |
| **D 지연 집행** | **채택 — 실행 골격** | 현재 verdict 이후 비동기 분석이 flow state를 갱신하고, 이후 packet이 O(1) 조회로 집행 | 현재 PACKET의 300ms 의무가 없어지는 것은 아니다. 무거운 분석을 hot path에서 제거할 뿐이며 원샷 공격은 A가 보완한다 |
| **E 아웃바운드** | **제외** | 구현하지 않음 | Broker가 각 레이어로 들어온 인바운드 `raw_ip`만 전달한다. 아웃바운드 관측 증거가 없으므로 조건부 후보로도 두지 않는다 |
| **F 확률적 DROP** | **조건부 재해석** | 무작위 packet DROP 대신 `SHADOW`와 flow/profile 단위의 결정론적 `CANARY`로 제한 | 무작위 DROP은 같은 입력의 verdict 재현성과 SLA 손실 예측을 해친다. canary도 positive·negative·SLA fixture와 오탐 예산을 통과한 사전 승인 rule만 사용한다 |
| **G Golden Response** | **제외** | 응답 기준선은 런타임 verdict에 사용하지 않음 | 응답·상태코드가 입력 계약에 없다. 예선 Golden Profile은 인바운드 정상 traffic baseline으로만 재해석한다 |
| **H LLM 사전 컴파일** | **채택 — Break 보조** | redacted feature와 논리적 PCAP/log 증거로 다음 이미지의 rule 후보를 만들고 사람이 검토한 뒤 `SHADOW`로 포함 | raw PCAP·전체 payload·flag·credential을 prompt나 이미지에 넣지 않는다. 생성 코드 자동 실행과 runtime self-modification을 금지한다 |

따라서 권장 골격은 **D + A + B(재해석) + H**다. C는 parser 증거가 생긴 profile에만 추가하고, F는 무작위 DROP이 아닌 결정론적 CANARY로만 쓴다. E와 G는 현재 인터페이스에서 제외한다. D는 A의 대체재가 아니라 A와 무거운 행위 분석을 300ms 경로에서 안전하게 분리하는 실행 모델이다.

### Round·누적 레이어 투입안

`FinalsPhase`가 바뀌면 이전 레이어는 계속 열려 있고 새 레이어가 추가된다. 따라서 같은 Round의 모든 레이어에 같은 승격 상태를 적용하지 않는다. **기존 profile의 ACTIVE rule은 유지할 수 있지만 새 레이어와 새 protocol은 항상 `SHADOW`부터 시작한다.**

| Round | 누적 레이어 | 투입 | 성공 기준 |
|---|---|---|---|
| R1~R2 | L1 | D 골격, 전 packet의 비민감 metadata·redacted feature 기록, DROP 0건 | verdict latency·HEARTBEAT 안정화, L1 정상 profile과 negative fixture 확보 |
| R3~R4 | L1~L2 | 검증된 L1 A rule만 ACTIVE, L2 A/B는 SHADOW | L1 SLA 회귀 유지, L2 parser와 정상 profile 확보 |
| R5~R6 | L1~L2 | 검증된 L2 A 승격, B는 profile별 SHADOW 또는 결정론적 CANARY | baseline 충돌·rule별 오탐·latency 예산 통과 |
| R7~R8 | L1~L3 | L1~L2의 검증 상태 유지, 새 L3 A/B/C는 SHADOW | UAV traffic을 기존 profile과 분리하고 parser fixture 확보 |
| R9~R10 | L1~L3 | 검증된 L3 rule만 CANARY/ACTIVE, H로 다음 이미지 후보 보강 | L1~L3 누적 SLA 회귀와 Break 사람 승인 rollback audit |
| R11~R12 | L1~L4 | L1~L3 상태 유지, 새 L4 A/B/C는 SHADOW | UGV를 UAV와 별도 profile로 식별하고 L4 정상 fixture 확보 |
| R13~R14 | L1~L4 | 검증된 L4 rule만 승격, 효과 없는 rule 제거, H 후보는 계속 SHADOW | 네 레이어 누적 회귀, 300ms 초과 0건, bounded memory 유지 |

여기서 "전량 로깅"은 raw payload·PCAP·flag·credential 저장이 아니다. 모든 packet에 대해 protocol/profile 후보, parser status, reason code, latency와 비민감 feature를 빠짐없이 집계한다는 뜻이다. 원본 PCAP는 운영진이 제공하는 공식 자료만 Break 분석 입력으로 사용하고 저장소나 이미지에 포함하지 않는다.

## S1~S5 시나리오별 매핑

| 예선 개념·시나리오 | 보고서 페이지 | 필요한 신호 | 본선 관측 상태 | parser·fixture 증거 | 방어 경로 | ACCEPT/DROP 영향 | SLA 보호·fallback | 관련 FinalsPhase·레이어 | 테스트 |
|---|---:|---|---|---|---|---|---|---|---|
| **S1** GCS 계정 탈취 — Mission Context Validator | 17–19 | Mission Plan(웨이포인트·작전구역), Vehicle State(모드·위치·고도·배터리), Mission Phase | **제외** — 세 맥락 모두 `raw_ip`에 존재하지 않음 | 없음. parser 작성 불가 | **제외** | 없음. DROP rule을 만들지 않음 | 해당 없음 | 해당 없음 | 해당 없음 |
| S1 파생 — 명령 의미론 검증 원칙 | 5, 19 | 요청 내용과 맥락의 논리적 모순 | **미확인** — 애플리케이션 프로토콜 파싱이 선증명되어야 함 | `FinalsPhase 2` 이후 MCS 트래픽 fixture 필요 | 온라인 비동기 | 없음 | 미확인 상태에서 DROP rule 금지 | FinalsPhase 2~4 / L2~L4 | `test_correlation.py` |
| **S2** 파라미터 변조 — Golden Profile + 해시 체인 | 20–23 | 파라미터 전체 세트, `PARAM_SET` 메시지, 변경 이력 | **제외** — 파라미터 저장소가 노출되지 않음 | 없음 | **제외** | 없음 | 해당 없음 | 해당 없음 | 해당 없음 |
| S2 재정의 — 정상 트래픽 기준선(baseline profile) | 20, 35 | 관측된 정상 protocol·port·payload 패턴 집합 | **가능** — `FinalsPhase 1`에서 정상 트래픽을 수집해 구성 | IPv4/TCP 헤더 + bounded payload view. `FinalsPhase 1` 정상 fixture | 온라인 비동기 경보 | **직접 DROP 없음.** 충돌률 metric·경보만 산출 | 공격자 영향이 남는 proxy이므로 runtime policy 불변. Break 사람 검토 자료로만 사용 | FinalsPhase 1~4 / L1~L4 | `test_anomaly.py`, `test_policy_audit.py` |
| **S3** 센서 은폐 — Physics-Based Detector, Shadow State | 23–26 | 기체 질량·추력 계수·항력 계수, 명령·센서 시계열 | **제외** — 역학 파라미터와 기체 상태 모두 미관측 | 없음 | **제외** | 없음 | 해당 없음 | 해당 없음 | 해당 없음 |
| S3 파생 — 조작 저항성 높은 기준 선택 원칙 | 23 | 공격자가 통제하기 어려운 관측량 | **부분 가능** — 선택 원칙으로 적용하되 현재 packet-derived ground truth는 없음 | 정상 negative fixture와 profile별 충돌 회귀 | 오프라인 승인 | 직접 영향 없음. 다음 bundle의 DROP rule 승인 근거 | packet-derived 지표는 alert-only, 상태 변경은 Break 사람 승인만 허용 | FinalsPhase 1~4 / L1~L4 | `test_anomaly.py`, `test_policy_audit.py` |
| **S4** Multi-stage — Causal Graph Matcher | 10, 27–29 | 이벤트 유형, 세션 ID, 기체 ID, 타임스탬프, 계층그룹 | **부분 가능** — flow key(5-tuple)와 monotonic 시각만 관측 가능. `session_id`·`vehicle_id`는 **미확인** | 관측된 flow key와 도착 시각. 애플리케이션 세션 키는 parser 선증명 필요 | **온라인 비동기 — verdict 이후 경로** | **없음. 상관 결과가 현재 packet을 소급 차단할 수 없다** | queue full 시 event 폐기, verdict 무영향 | FinalsPhase 2~4 / L1~L4 | `test_correlation.py` |
| S4 파생 — 체인 중간 선제 차단 | 10, 28 | 부분 매칭 상태 | **미확인** — 레이어 식별이 선증명되어야 함 | dst 3옥텟과 레이어 대응 관계 미증명(§16.1) | 온라인 비동기 | 이후 packet의 `Score` 조회에만 반영. 사전 승인된 rule 한정 | state 없으면 `ACCEPT` | FinalsPhase 2~4 / L2~L4 | `test_correlation.py` |
| S4 파생 — 미학습 변종 대응(다계층 집중 휴리스틱) | 28, 43 | 시간 윈도우 내 다계층 이상 이벤트 집중 | **미확인** — 레이어 식별 선증명 필요 | 위와 동일 | 온라인 비동기 | 없음. 조사 우선순위 신호로만 사용 | 해당 없음 | FinalsPhase 3~4 / L1~L4 | `test_correlation.py` |
| **S5** AI Poisoning — Deterministic-AI 이중판단 | 30–32, 41–42 | 독립 입력 파이프라인 2개, 판단 이력 | **가능** — 본선 시간 계약이 분리를 강제 | 동기 경로는 규칙만, LLM은 비동기 조언 전용 | 동기(규칙) + 온라인 비동기(조언) | **LLM 출력은 어떤 packet도 직접 ACCEPT/DROP 하지 않는다** | LLM 장애·timeout·quota 소진이 verdict와 HEARTBEAT에 영향 없음 | FinalsPhase 1~4 / L1~L4 | `test_advisory.py` |
| S5 파생 — AI 입력 검증 3단계 | 33 | 스키마 적합성, 입력 분포, 소스 서명 | **부분 가능** — 스키마 검증은 가능, 서명은 본선 이벤트에 없어 제외 | 자체 생성한 `CorrelationEvent` 스키마 | 온라인 비동기 | 없음 | 검증 미통과 입력은 LLM에 전달하지 않음 | FinalsPhase 1~4 | `test_advisory.py` |
| S5 파생 — 방어 시스템 자체가 공격 표면 | 11, 32 | 방어 동작을 유도하는 공격 패턴 | **가능** — packet-derived metric 오염 형태로 재현 | DROP율·baseline 충돌·rule 집중 조작 fixture | 온라인 비동기 경보 | 없음. 조작 시도 시에도 effective policy 불변 | 모든 packet-derived 지표를 runtime 전환 트리거에서 제외 | FinalsPhase 1~4 / L1~L4 | `test_anomaly.py` |

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
| Graceful Degradation | 35 | **Break 운영 절차로 재설계** | 오프라인 | Round 중 verdict·effective policy 변화 없음 | 경보를 공식 SLA·fixture와 대조하고 사람 승인한 다음 bundle에서만 범위 제한 rollback | FinalsPhase 1~4 | `test_anomaly.py`, `test_policy_audit.py` |
| Mission-Phase Awareness | 35 | **제외** — `MissionState` 미관측 | **제외** | 없음 | 해당 없음 | 해당 없음 | 해당 없음 |
| Fail-Safe by Default | 13 | **재해석** — 본선의 안전 기본값은 차단이 아니라 통과 | 동기 | parser 실패·overload·LLM 장애에서 `ACCEPT` | Broker fail-open과 방향 일치 | FinalsPhase 1~4 | `test_policy.py` |
| Hard Negative(정상이나 의심스러운 케이스) | 43 | **가능** | 오프라인 | 각 DROP rule의 정상 negative fixture로 직접 반영 | 오탐률을 정직하게 측정하는 근거 | FinalsPhase 1~4 | `test_policy.py` |
| 회귀 가드(정답을 입력에 넣지 않는 반순환 테스트) | 46 | **가능** | 오프라인 | 없음 | fixture 기반 검증의 설계 원칙 | 해당 없음 | `test_policy.py` |
| 표준 라이브러리만 사용한 결정론적 재현 | 44 | **가능** | 오프라인 | 없음 | 서드파티 의존성 0개 유지(설계 §9.3·§14) | 해당 없음 | 해당 없음 |
| 예선 정량 지표(DR·FPR·MTTD·Precision·Recall) | 12, 37, 45 | **제외** — synthetic N=8 상대 비교값 | **제외** | 본선 threshold로 사용 금지 | 해당 없음 | 해당 없음 | 해당 없음 |

## DROP 영향이 있는 항목의 승인 조건

위 S1~S5 및 파이프라인 매핑 표에서 runtime `ACCEPT`/`DROP`에 직접 연결되는 예선 개념은 아직 없다. 정상 트래픽 기준선과 packet-derived 충돌률은 metric·경보·Break 분석에만 쓰이며 runtime rollback이나 effective-policy 변경을 일으키지 않는다. 실제 DROP 후보는 앞의 A~H 검토에서 채택한 A, 증명된 C invariant와 사전 승인된 multi-signal rule에서 별도로 나온다.

실제 `DROP` rule은 `FinalsPhase 1`의 관측 이후에 개별로 추가되며, 각 rule은 설계 §6.1의 6조건과 §10.2의 기록 항목을 모두 충족해야 한다. 최소 요건은 다음과 같다.

- 공격 positive fixture와 **동일 protocol의 정상 negative fixture**
- 100회 SLA check pattern 성격의 정상 fixture 회귀 통과
- `rule_id`, protocol scope, layer/profile scope, reason code
- **rollback 조건과 직전 안전 버전**
- 방어 담당자와 팀장 이경준의 review 상태

`미확인`으로 표시된 신호는 runtime `DROP` rule에서 제외한다. 관측 증거가 확보되면 해당 행을 갱신하고 rule 승격 절차를 밟는다.
