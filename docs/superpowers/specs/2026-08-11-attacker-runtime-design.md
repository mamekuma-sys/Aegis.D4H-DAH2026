# 공격 런타임 설계 — 관측·계획·실행·제출

작성일: 2026-08-11
브랜치: `docs/attacker-runtime-design`
담당: 김태성(공격) · 검토: 이경준(팀장)
상태: 설계 확정(구현 코드 미작성). 승인 후 `feat/attacker-runtime-foundation`에서 테스트 우선 구현.

이 문서는 본선 공격 에이전트의 **관측 → 계획 → 실행 → flag 제출** 런타임을 설계한다. 하나의
누적 적응형 런타임이 본선 FinalsPhase 1~4에서 누적 개방되는 레이어를 증거 기반으로 식별하고,
검증된 플레이북을 유지하면서 새 레이어에 적응한다. 설계는 공식 스켈레톤에서 관측 가능한 입력과
동작, 본선 운영세칙, 당일 진행 안내만을 근거로 한다.

이 문서가 공격 런타임 구현의 **단일 규범적 권위**다. `handoff.md`는 작업 배경과 예전
점검표를 남긴 비규범적 자료이며, 두 문서가 다르면 이 설계와 상위 소스 우선순위를 따른다.

## 소스 우선순위

사실이 충돌하면 다음 순서를 적용한다. (1) 최신 본선 규칙·같은 날 운영사무국 지침 → (2) 공식
스켈레톤 `deploy/docs/agent-guide.md` → (3) 스켈레톤에서 직접 관측한 동작 → (4) 예선 보고서·소스 →
(5) 팀 문서. 팀 문서로 상위 자료를 재해석하지 않는다.

### 원본 SHA-256 검증

| 원본 | 예상·확인 SHA-256 | 상태 |
|---|---|---|
| `DAH2026_본선운영세칙.pdf` | `FFE8E6BEECB628F93F20A9F5D0F41203CADBF28EE7E56C9A91FDAB87A1655A5F` | 일치 |
| `DAH2026_본선_당일_진행_안내.md` | `AA704A259A3A59B10A844A59AA6B1593DEDF31D99662B70A8D7CD58EFECD5D9E` | 일치 |
| `DAH2026_예선보고서_Aegis.0xD4H.pdf` | `1DD42B99A8816C3B7A543929BA0AEE90E5565CFC853E19E1455F76631CD1894E` (54쪽) | 일치 |

인벤토리(`docs/references/source-inventory.md`)와 일치. 페이지별 검토는
`docs/references/preliminary-report-attacker-map.md` 참조.

---

## 9.1 범위와 비범위

### 이번 설계가 해결하는 문제
- 본선 A&D에서 상대 팀 진입점을 정찰하고, 관측 증거로 취약 가설을 세워 허용된 도구로 실행하며,
  응답에서 `FLAG{...}`를 추출해 제출 서버로 제출하는 단일 공격 런타임의 구조.
- FinalsPhase가 진행되며 레이어가 누적 개방될 때(§7), 이전 레이어의 검증된 플레이북을 중단하지
  않으면서 새 레이어에 적응하는 방법.
- 20분 Round·10분 Break 운영 주기에서 다음 이미지로 개선하는 루프(§7.5).

### 공식 인터페이스 밖에서 가정하지 않는 정보
- 본선 표적의 구체 취약점 존재. 운영세칙 제11조 ③에 따라 취약점과 flag는 1:1이 아니며 한 flag의
  경로가 여럿일 수 있다. 로컬 데모의 SSRF·세션 변조·SQLi는 **본선 사실이 아니라** 인터페이스
  이해용 예시다.
- 예선 S1~S5 취약점이 본선에 그대로 있다는 보장. 예선 세그먼트와 본선 레이어는 이름만 유사하다.
- 공식 계약에 없는 `PHASE`·`LAYER`·`ROUND` 환경변수, 차량 상태·파라미터 해시·물리 상태 같은
  관측 불가 신호.

### 예선에서 계승하는 개념과 폐기하는 구현
- 계승(개념): 단일 관측은 약하지만 세션·시간·인과로 연결하면 강해진다는 관점, 관측 결과에 따라 다음
  단계를 바꾸는 **적응 루프**, 합성 수치를 실전 성능으로 주장하지 않는 **정직성 원칙**.
- 재설계: A1~A5 공격자 모델과 S1~S5 시나리오를 **본선 HTTP 서비스 관측으로 증명될 때만** 쓰는
  가설로 변환.
- 폐기(구현): 예선 `AttackSimulationAgent`는 실제 표적을 공격하지 않는 합성 이벤트 생성기이므로
  본선 런타임으로 복사하지 않는다. 합성 데이터셋·평가 점수·혼동행렬도 본선 런타임에 넣지 않는다.

### 경계
이 설계는 실제 취약점·데모 취약점·S1~S5의 존재를 **보장하지 않는다.** 모든 실행은 관측 증거를
전제로 하며, 증거가 없으면 범용 저비용 관측으로 회귀한다.

## 9.2 근거 추적표

| 근거 | 예선 보고서 PDF 페이지 | 관측·계약·보고서 사실 | 설계에 미치는 영향 |
|---|---:|---|---|
| `TARGETS`/`PORTS` 입력, 대상=조합 | 해당없음 | 운영세칙 제16조, agent-guide, `contracts/attacker` | §9.5 대상 열거기, §9.7 완전 열거 |
| 접근 허용 범위(상대 진입점·LiteLLM·제출) | 해당없음 | 운영세칙 제8·11조, 제24조 2호 | §9.10 실행 직전 범위 재검증 |
| 취약점 ↔ flag 비1:1, 경로 복수 | 해당없음 | 운영세칙 제11조 ③ | §9.8 하드코딩 순서 금지, §9.11 다경로 |
| 상대 방어망 초당 10·버스트 20 | 해당없음 | 운영세칙 제12조 ③, agent-guide | §9.5 전역 rate limiter |
| flag 제출 rolling 60초 최대 30·429 | 해당없음 | 운영세칙 제10조 ③, agent-guide | §9.5 제출 limiter, §9.11 backoff |
| 제출 결과 5종 | 해당없음 | 운영세칙 제10조 ②, agent-guide | §9.11 결과 상태표 |
| 라운드마다 컨테이너·flag 초기화 | p13, p39(불변규칙) | 운영세칙 제6·15조, 당일안내 §2 | §9.6 라운드 한정 상태, §7.6 |
| FinalsPhase 1~4, 14 Round(2·4·4·4), 누적 개방 | 해당없음 | 운영세칙 제4·5조, 당일안내 §1 | §7.2, §9.9 |
| 20분 Round·10분 Break·pull 5분 전 | 해당없음 | 운영세칙 제6·15조, 당일안내 §2·§6 | §7.5 운영 루프 |
| SLA=(100−실패), 점수 계수 | 해당없음 | 운영세칙 제17·20조, 당일안내 §7 | §9.10 파괴·DoS 금지(SLA 훼손 회피) |
| AI 진위 증빙 의무 | 해당없음 | 운영세칙 제23조 | §9.6·§9.12 비밀 제거 로그, 증빙 보존 |
| LLM은 조언만·서버 tools 차단 | 해당없음 | agent-guide, `litellm-gw/config.yaml` | §9.12 LLM 경계 |
| 적응 루프(관측→다음 단계) | p3, p40, p41~42 | 예선 보고서 접근방식·Figure 4 | §9.4 런타임 흐름, §7.6 |
| A1~A5 능력 프레임 | p5 | 예선 1.6 | §9.3 |
| S1~S5 가설·성공·한계 | p8~11 | 예선 2.3~2.7 | §9.8, `research/attack-scenarios.md` |
| S4 다단계 체인(S4ChainStage) | p10 | 예선 2.6 Figure 3 | §7.1, §9.8 |
| 합성 수치를 실전 성능으로 주장 금지 | p12, p48, p46 | 예선 2.8·4.9·5.2 | §9.1 비범위, §9.12 |

`계승`·`재설계` 판정 페이지는 위 표 또는 각 절에서 PDF 페이지와 역참조된다. 예선 보고서에 근거가
없는 결정은 본선 계약 또는 관측 결과를 근거로 명시했다.

## 9.3 공격자 모델 A1~A5

예선 A1~A5는 UAV/UGV 통제 채널 능력 모델이다. 본선 공격 런타임에서는 **본선 인터페이스에서
증명되는 신호**로만 재해석하고, 증명되지 않은 능력은 표적 우선순위나 실행 권한으로 쓰지 않는다.

| 모델 | 보고서의 목표·능력·전제 (p5) | 본선에서 확인 가능한 신호 | 허용되는 설계 영향 | 사용하지 않을 가정 |
|---|---|---|---|---|
| A1 자격증명/세션 탈취 | 정당 세션 위장, 인증 통과 | 응답의 Set-Cookie·토큰·세션 blob, 인증 area 배너, 401/403 전이 | 인증·세션 경계가 관측될 때 S1형 가설 후보화 | MAVLink 세션·MFA 등 도메인 전제 |
| A2 제한적 명령 접근 | 탈취 세션 내 명령/파라미터 변경 | 파라미터/설정형 엔드포인트, 변경 요청에 대한 응답 차이 | 파라미터 인터페이스 노출 시 S2형 가설 | 오토파일럿 파라미터 명세 |
| A3 프로토콜/텔레메트리 변조 | 통제 채널로 메시지·센서 조작 | 조작 가능한 입력 파라미터, 서버측 반영 여부 | 입력 반영 경계 관측 시 S3형 가설 | 실제 센서/텔레메트리 스트림 |
| A4 물리 접근 없음 | 물리·하드웨어 접근·개조 없음 | 없음(정의상 관측 불가) | 물리·기체 제어를 설계에서 완전 배제 | 물리 로봇 조작(운영세칙 제24조 4호 금지) |
| A5 가용성 인식 적대자 | 오탐 유발·탐지 회피로 가용성 뒤에 숨음 | 없음(공격 목적 아님) | **사용 안 함** — SLA 훼손·DoS는 운영세칙 제24조 5호 위반 | 가용성 공격 자체 |

핵심: A4·A5는 본선 공격 런타임에서 **실행 권한으로 사용하지 않는다.** A4는 애초에 관측·실행 불가이고,
A5(가용성 공격)는 금지행위다. 우리 공격은 flag 획득 목적에 한정하며 파괴·DoS·rate 우회를 하지 않는다.
실패 시 동작: 어떤 모델의 신호도 관측되지 않으면 해당 가설을 활성화하지 않고 범용 관측을 계속한다.

## 9.4 런타임 흐름

```text
Round 비밀 저장소 생성
  → 공개 환경변수 검증과 비밀 환경변수의 typed handle bootstrap
  → TARGETS × PORTS 열거·정규화
  → 제한을 지키는 기초 관측 (배너/기본 응답)
  → ObservedServiceProfile과 관측 증거 기록
  → 증거가 있을 때만 레이어·FinalsPhase 우선순위 힌트 선택
  → S1~S5 가설 활성화 또는 폐기 (증거 부족 시 폐기)
  → 가설 ID와 근거가 결속된 허용 도구 계획 생성 (allowlist·대상·예산 선언)
  → 실행 전 가설·근거·범위·예산 preflight
  → 요청 charge 원자적 예약
  → 실행 결과를 관측 저장소에 반영
  → flag 후보 추출·형식 검증·해시 중복 제거
  → 제출·결과 기록·backoff
  → 다음 표적 또는 가설 선택 (공정 스케줄러)
```

결정: 어떤 단계도 관측 증거 없이 다음 공격 단계로 진행하지 않는다. 각 단계는 실패해도 다음 표적으로
격리된다.
이유: 취약점↔flag 비1:1(운영세칙 제11조 ③)이므로 "정찰 없는 즉시 익스플로잇"은 예산만 소모한다.
관측 증거에 기반한 가설 선택이 요청 예산 대비 효율을 높인다.
실패 시 동작: 관측이 실패(timeout·연결거부)하면 이를 **실패가 아닌 관측**으로 기록하고 공정 스케줄러가
다른 표적으로 넘어간다. LLM 장애·예산 소진은 결정론적 관측·범위 검사·제출 흐름을 막지 않는다.

## 9.5 구성요소 경계

한 구성요소가 네트워크 호출·계획 판단·제출 상태를 동시에 소유하지 않는다.

| 구성요소 | 입력 | 출력 | 의존성 |
|---|---|---|---|
| 설정 bootstrap·검증기 | 환경변수, 생성 완료된 비밀 저장소 | 원문 비밀 없는 검증된 설정 또는 종료 | Round 비밀 저장소 |
| 대상 열거기·공정 스케줄러 | `TARGETS`,`PORTS` | `Endpoint` 큐, 다음 대상 선택 | 설정 검증기, rate limiter |
| 전역/제출 rate limiter | monotonic 요청 시각 | 허용/대기(backoff) | 전역은 토큰 버킷, 제출은 공유 60초 sliding window |
| `EgressGateway` | capability, 정규화 destination, 구조화된 요청, 인증 handle | 허용된 네트워크 호출·3xx 관측 또는 거부 | 설정 검증기, rate limiter, 비밀 저장소, 비공개 HTTP transport |
| 관측 수집기 | `Endpoint` | 원시 응답 | `EgressGateway(ATTACK_TARGET)`만 사용 |
| Profile 분류기·관측 저장소 | 원시 응답 | `ObservedServiceProfile`, 증거 | 관측 수집기 |
| 관측 기반 우선순위 정책 | 관측 저장소, 증명된 profile hint | endpoint 우선순위 힌트(공정 pass 불변) | 관측 저장소 |
| S1~S5 가설 플래너 | Profile, 증거 | 활성 가설·중단 이유 | 관측 저장소 |
| 허용 도구 레지스트리·실행 어댑터 | 계획 | 도구 실행 결과(성공/실패/timeout) | preflight, `EgressGateway(ATTACK_TARGET)`만 사용, `SESSION` handle만 해석 가능 |
| flag 후보 추출기·중복 저장소 | 실행 결과 | flag 후보(해시) | 없음 |
| flag 제출 클라이언트 | flag 후보 | 제출 결과 상태 | `EgressGateway(SUBMIT)`만 사용, 제출 rate limiter, `FLAG`·`SUBMIT_TOKEN` handle만 해석 가능 |
| LLM 조언 경계·라운드 예산 관리자 | 관측 요약 | 우선순위 조언(비실행) | `EgressGateway(LLM)`만 사용, 예산 관리자, `LLM_KEY` handle만 해석 가능 |
| Round 비밀 저장소 | 비밀 원문 | TTL이 있는 비직렬화 handle | Round 시계·종료 신호 |
| 구조화 로그 기록기 | 이벤트 | 비밀 제거 로그 | 없음 |
| 라운드 수명주기 오케스트레이터 | 전 구성요소 | 라운드 진행 | 전부 |
| Round 결과 요약기 | 관측·결과 | 비밀 없는 산출물 | 로그 기록기 |

## 9.6 상태와 데이터 모델 (필드·불변조건)

코드는 작성하지 않고 타입의 필드와 불변조건만 정의한다.

- `Endpoint`: `{endpoint_id, host, port}`. 불변: `endpoint_id`는 검증된 host·port 쌍에 대해
  Round 내에서 안정적이고, 정확히 파싱·정규화한 `TARGETS × PORTS` allowlist의 원소다. 공식 고정
  입력에는 자기 팀 식별자가 없으므로 `host != self team`을 추론·하드코딩하거나 비공식 환경변수를
  추가하지 않는다. `TARGETS`는 운영진이 제공한 상대 팀 집합으로 해석한다.
- `EgressCapability = ATTACK_TARGET | SUBMIT | LLM`.
- `NormalizedDestination`: `{scheme, host, port, path_policy}`. scheme·host는 canonical form으로,
  port는 명시적 정수로 정규화하며 `path_policy`는 capability가 허용하는 정확한 경로 또는 명시적으로
  검증할 공격 요청 경로 규칙이다. 문자열 URL의 느슨한 prefix 비교는 금지한다.
- `ObservedServiceProfile`: `{endpoint, banner_fingerprint, status_codes, redacted_header_hints, error_signatures,
  latency_band, evidence[]}`. 선택적 `FinalsPhaseHint{finals_phase, layer, reason, evidence_ref}` —
  **증거 참조가 있을 때만** 채움.
- `S4ChainStage`(1~5): 예선 S4 체인 국면. `FinalsPhase` 번호와 대응한다고 가정하지 않는다.
- `MissionState`: 예선 임무 상태(이륙 전·순항 등). **수신 데이터 파서로 존재가 증명될 때만** 사용.
  본선 HTTP 표적에서 증명되기 전에는 인스턴스화하지 않는다.
- `EvidenceRef`: `{evidence_id, round_id, endpoint_id, hypothesis_ids[], observed_at_monotonic,
  expires_at_monotonic, observation_fingerprint}`. `hypothesis_ids`는 가설 레지스트리에 등록된 활성화·인과
  근거 결속이며 TTL이 지나면 무효다.
- `Observation`: `{round_id, endpoint, request_fingerprint, status, redacted_header_hints, body_fingerprint, latency,
  evidence_ref}`.
- `ScenarioHypothesis`: `{hypothesis_id, scenario∈{S1..S5}, registered_activation_evidence_refs[],
  registered_causal_lineage_refs[], preconditions[], stop_reason?}`. `hypothesis_id`는 Round 안에서 안정적이고
  레지스트리에서 유일하다. 모든 등록 근거는 같은 `round_id`에 속하며 가설과 명시적으로 결속된다.
- `ExecutionPlan`: `{plan_id, hypothesis_id, round_id, endpoint_id, tool, capability, args,
  execution_evidence_refs[], causal_lineage_refs[], created_at_monotonic, expires_at_monotonic,
  preconditions[], side_effect_class, expected_cost, timeout, budget_charge}`. `execution_evidence_refs`는 비어
  있을 수 없고 모두 현 `round_id`와 정확한 현 `endpoint_id`에 속하는 신선한 endpoint-local 근거다.
  `causal_lineage_refs`는 선택 사항이며 S4 인과 설명에만 쓴다. 다른 endpoint의 lineage는 같은 Round와
  같은 `hypothesis_id`에 명시 등록됐을 때만 허용되고 local 실행 근거를 대신할 수 없다. `args`는 비밀
  원문 대신 `SecretHandle`만 담고, `expected_cost`와 `budget_charge`는 양수다.
- `ToolResult`: `{plan, outcome∈{success,fail,timeout}, observation}`.
- `SecretHandle`: `{secret_id, round_id, kind, expires_at_monotonic}`. 비직렬화·비로그 타입이며
  `kind∈{FLAG,SESSION,SUBMIT_TOKEN,LLM_KEY}`이다. Round 종료·TTL 만료 시 원문과 handle을 즉시 폐기한다.
- `FlagCandidate`: `{hash, secret_handle, format_valid, submit_state?}`. **원문을 장기 식별자로 쓰지 않는다.**
- `RoundBudget`: `{endpoint_count=E, total_request_cap=10*E, total_reserved, endpoint_reserved[endpoint_id],
  planner_turns[endpoint_id], submit_count, llm_calls, llm_tokens}`. `E = len(TARGETS × PORTS)`이고 각
  endpoint의 request charge 상한은 10, planner turn 상한은 6이다.

불변조건: flag·세션·토큰·키 원문은 Round 비밀 저장소 메모리에만 존재한다. 계획·증거·로그·보고서·
LLM 프롬프트에는 handle, 단방향 해시, 비민감 fingerprint 또는 완전 마스크 값만 보낸다. 소비자 권한은
실행 어댑터=`SESSION`, 제출 클라이언트=`FLAG|SUBMIT_TOKEN`, LLM 경계=`LLM_KEY`로 서로 겹치지 않으며,
다른 kind의 resolve는 실패한다. `EgressGateway`는 요청의 소비자·capability·handle kind 조합을 다시
검사하고 허용된 소비자의 인증 handle만 소비한다. 관측 수집기의 원시 응답 버퍼는 비밀 경계 안의 일시
메모리로 다루고, flag·세션을 추출해 저장소로 옮긴 직후 영속 전에 마스크하거나 폐기한다. 캐시·중복
집합·관측 이력은 **Round 한정 임시 상태**다.

비밀 bootstrap 순서는 고정한다. 수명주기 오케스트레이터가 먼저 빈 Round 비밀 저장소를 생성한 뒤
`SUBMIT_TOKEN`·`LLM_API_KEY` 같은 비밀 환경변수를 하나씩 짧은 수명의 지역 변수로 읽고 즉시 올바른
kind의 `SecretHandle`로 저장한다. 검증된 config와 이후 런타임 객체에는 handle만 남기며 `repr`·로그·
직렬화는 원문을 거부하거나 완전 마스크한다. Python 문자열은 확실한 zeroization을 보장할 수 없으므로
bootstrap 지역 변수의 추가 복사·보존을 피하고 가능한 즉시 참조를 버리되, 메모리 zeroization을
보장한다고 주장하지 않는다. 저장소 `close`는 원자적이며 terminal이다. close와 write/resolve가
경합하면 선형화 순서상 close 뒤의 작업이 반드시 실패하고, 닫힌 저장소는 다시 열거나 기록·해석할 수 없다.

## 9.7 관측 전략

- 완전 열거: 매 라운드 `TARGETS × PORTS` 조합을 누락 없이 큐에 넣는다. 누적 레이어가 늘어도 이전
  포트를 제거하지 않는다(§7.3).
- 기초 관측: 엔드포인트당 최소 요청(포트 개방 확인 + `GET /` 배너)으로 시작한다. 배너·상태·헤더가
  다음 관측의 근거다.
- 정규화: 응답 상태·헤더 힌트·본문 특징·오류·지연을 `Observation`의 증거 필드로 정규화한다.
- timeout·연결거부·비정상 응답은 **실패가 아니라 관측**으로 기록한다(인라인 필터 신호일 수 있음).
- 결정론적 예산: `E = len(TARGETS × PORTS)`, endpoint별 request charge 상한은 10, Round 실행 창의
  총 request charge 상한은 `10 * E`다. `expected_cost > 0`과 `budget_charge > 0`을 요구한다. 현재
  `ExecutionPlan` 하나는 gateway 요청 하나만 표현하고 `budget_charge = 1`이다. 여러 요청을 포함하는
  action은 요청별 plan으로 분리해야 한다.
- 공정성: 활성 endpoint를 안정된 `endpoint_id` 순서의 pass로 순회해 pass마다 endpoint당 charge 하나만
  예약한다. 따라서 모든 활성 endpoint가 첫 관측 charge를 받기 전에 어떤 endpoint도 두 번째 charge를
  받지 못한다. 이후에도 같은 pass 규칙을 유지하며 관측 기반 우선순위는 pass 내부의 탈락·중단만
  결정하고 이 불변조건을 깨지 않는다.
- 중단: planner가 endpoint의 다음 follow-up plan 생성을 시도할 때마다 성공·거부와 무관하게 planner
  turn을 정확히 1 증가시키고 6에서 멈춘다. `INVALID_EVIDENCE`는 preflight가 local 실행 근거의
  누락·만료·binding 오류를 발견하고 그 endpoint에 다른 유효한 등록 가설·local 근거가 없을 때다.
  `NO_PROGRESS`는 직전 charged request 뒤 정규화 observation fingerprint와 등록 evidence 집합이
  직전 turn과 같고, 신선한 근거로 만들 수 있는 다른 allowlisted action도 없을 때다. endpoint는 이 두
  조건, `accepted` flag, 누적 10 charge, planner turn 6 중 하나에서 멈춘다. Round 실행 창은 모든
  endpoint가 중단·소진됐거나 총 `10 * E` charge가 예약되면 멈춘다. charge 예약은 원자적으로 성공해야
  하며 rate limiter 획득이나 어떤 I/O보다 먼저 수행한다.

증명되지 않은 프로토콜 필드·차량 상태·파라미터 해시는 관측 근거로 쓰지 않는다.

## 9.8 가설 플래너

S1~S5마다 (안정적 `hypothesis_id`, 등록 활성화 증거, 선행조건, 성공 증거, 중단 조건, 재시도 정책)을
정의한다. 상세 표는 `research/attack-scenarios.md`와 동일 용어를 사용한다.

- 하드코딩된 `S1 → S2 → S3` 순서를 만들지 않는다. **관측 증거가 가장 강한 가설**을 선택하고, 근거가
  사라지거나 예산이 소진되면 폐기한다.
- 활성화 근거 없는 시나리오는 실행하지 않는다. `FinalsPhase`가 같다는 이유만으로 활성화하지 않는다.
- 모든 `ExecutionPlan`은 레지스트리에 존재하는 `hypothesis_id`와 결속하고, 현 Round·정확한 현
  endpoint의 신선한 `execution_evidence_refs`를 하나 이상 가진다. S4의 선택적
  `causal_lineage_refs`는 같은 Round·같은 가설에 등록되면 다른 endpoint를 가리킬 수 있지만 인과 설명일
  뿐이며 endpoint-local 실행 근거를 대체하지 않는다.
- 재시도 정책: 같은 요청을 즉시 반복하지 않는다. 응답 없음(인라인 필터 의심)이면 동일 exploit·경로를
  유지하되 인코딩·표현을 바꿔 재시도하고, 그래도 실패하면 해당 가설을 중단한다.
- 예선 S4 다단계는 `S4ChainStage`로 표기하며, 각 국면의 관측 증거가 이어질 때만 다음 국면을 시도한다.
  (방어측이 체인 절반 지점에서 선제 차단할 수 있음을 배경으로 인지 — 예선 p27.)

실패 시 동작: 활성 가설이 없으면 범용 저비용 관측을 계속한다.

## 9.9 FinalsPhase 적응과 Round 운영

- 용어·타입 경계: `FinalsPhase(1~4)` ≠ `S4ChainStage(1~5)` ≠ `MissionState`. 문맥 없는 `Phase 1`·`P1`
  표기를 쓰지 않는다.
- FinalsPhase 1~4의 새 레이어·누적 레이어·Round 수·예선 세그먼트 관계는 §7.2 표.
- 위성망 게이트웨이·MCS·UAV·UGV는 각각 최초 관측 증거로 식별하며, UAV 가정을 UGV에 복사하지 않는다.
- 런타임 예산은 관측 가능한 endpoint 단위 pass로만 공정 배분한다(§9.7). 관측으로 증명된 레이어 매핑이
  없으면 레이어 ID를 생성하거나 그 ID로 예산을 나누지 않는다.
- FinalsPhase별 기본 Round 목표(§7.4)는 초기 가설이며, 실제 flag·로그·PCAP·서비스 변화가 다르면
  관측 증거를 우선해 순서를 바꾼다.
- 20분 Round 중 분석·수정하고 Break 전반 5분 안에 build·push하는 운영 루프(§7.5).
- Round 간 가져갈 수 있는 비밀 없는 산출물과 폐기 상태(§7.6).
- 이전 이미지 사용 감지·보고·rollback(§7.7).

공식 계약에 없는 Phase 환경변수·레이어 번호를 런타임 필수 입력으로 넣지 않는다. endpoint에 임의
레이어 ID를 부여하지도 않는다. Phase 일정과 실제 `TARGETS × PORTS`가 다르면 **실행 시 관측되는 표적
집합**을 우선하며, 증명된 매핑이 생기기 전에는 §9.7의 endpoint pass 공정성이 유일한 실행 규칙이다.

## 9.10 실행 안전 경계

- 도구는 (이름, 입력 스키마, 허용 대상, 예상 비용, timeout)이 선언된 **allowlist**로만 실행한다.
- 네트워크 가능 구성요소의 **유일한** transport 의존성은 `EgressGateway`다. 관측 수집기, 실행
  어댑터, 제출 클라이언트, LLM 클라이언트에는 generic HTTP client/session/socket을 주입하거나
  보관하지 않는다. raw HTTP transport는 `egress.py` 내부의 private 구현으로만 존재하고, 생성·조립
  루트가 모든 네트워크 호출에 같은 gateway 인스턴스를 주입한다.
- `EgressGateway`는 환경 프록시 비활성화, 자동 redirect 금지, method·정규화 path 검증, capability별
  destination allowlist, 인증 handle 소비 정책을 소유한다. 3xx는 따라가지 않고 status와 redacted
  location hint를 `Observation`으로 반환한다.

| `EgressCapability` | 허용 destination·path | method | 허용 secret kind |
|---|---|---|---|
| `ATTACK_TARGET` | 정확히 정규화한 `TARGETS × PORTS`의 host·port와 action registry가 명시한 scheme·요청 path | 등록 action의 명시 method | 실행 어댑터의 `SESSION`만 |
| `SUBMIT` | 정확히 정규화한 `SUBMIT_URL`의 scheme·host·port·path | `POST`만 | 제출 클라이언트의 `FLAG`, `SUBMIT_TOKEN`만 |
| `LLM` | 정규화한 `LLM_BASE_URL` 아래 고정 `/v1/chat/completions` path | `POST`만 | LLM 경계의 `LLM_KEY`만 |

  `ATTACK_TARGET` path는 요청마다 plan과 action registry에 명시되어야 하며 암묵적 wildcard·URL 문자열
  연결을 허용하지 않는다. `SUBMIT_URL`의 query·fragment 또는 `LLM_BASE_URL`에 대한 path 탈출은
  정규화 단계에서 거부한다. 다른 capability의 URL·인증은 재사용할 수 없다.
- 3xx의 수동 후속 hop은 redacted location 관측에서 신선한 근거를 등록하고 **새** `ExecutionPlan`을
  만든 경우에만 검토한다. gateway가 새 scheme·host·port·path를 처음부터 정규화·검증하며 capability
  crossing은 항상 거부한다.
- preflight 순서는 고정한다. (1) 계획의 `hypothesis_id`가 가설 레지스트리에 존재하고 같은 Round인지,
  (2) plan binding과 capability·destination allowlist, (3) 비어 있지 않은 endpoint-local
  `execution_evidence_refs`와 선택적 `causal_lineage_refs`의 등록·Round·endpoint 규칙, (4) 계획·근거
  TTL, (5) 구조화된 preconditions·side-effect action registry, (6) 양수 `expected_cost`·
  `budget_charge`를 검사한다. 하나라도 실패하면 예산을 예약하지 않고 네트워크에 접근하지 않는다.
  모두 통과한 뒤에만 endpoint·Round charge를 원자적으로 예약하고, 그 다음 rate limiter를 획득한 후
  gateway I/O를 수행한다.
- `side_effect_class`의 기본값은 `READ_ONLY`다. 상태 변경 요청은
  `BOUNDED_FLAG_DIRECTED_MUTATION`으로 명시되고, flag 획득에 필요한 유한 작업·변경 범위·안전
  precondition·중단 조건이 모두 구조화된 allowlist와 일치할 때만 허용한다.
- 물리 작동, 가용성 훼손, 지속성 확보, 파괴, 회복 불가, 범위 불명 작업은 항상
  `DISALLOWED`로 거부한다. LLM 추천은 안전 등급이나 precondition을 완화할 수 없다.
- 셸 문자열 연결보다 구조화된 인자 전달을 우선한다.
- 병렬 실행도 전역 초당 10·버스트 20 제한을 공유한다.
- 파괴적 동작·지속성 확보·범위 밖 이동·rate limit 우회를 금지한다. SLA 훼손(정상 서비스 방해)은
  점수·규칙 양면에서 금지다(운영세칙 제20·24조).
- 성공·실패·timeout을 동일한 `ToolResult` 인터페이스로 관측 저장소에 반환한다.

## 9.11 flag 생명주기

```text
① 응답에서 flag 후보 발견 (FLAG{...} 정규식)
② 형식 검증 (형식 불일치 폐기)
③ 원문을 Round 비밀 저장소에 보관 · 해시로 중복 확인 (이미 제출·확정된 flag면 건너뜀)
④ 어떤 연속 60초 구간에서도 최대 30회만 제출 (POST SUBMIT_URL, {flag, token})
⑤ 결과 저장: accepted | own_team | duplicate | rejected | closed
⑥ HTTP 429 → `Retry-After`를 한 번 delay로 변환해 monotonic deadline 생성; 신뢰할 Round deadline 안에 들 때만 재시도
⑦ 동일 flag 불필요한 재제출 금지
```

| 결과 | 의미 | 런타임 동작 |
|---|---|---|
| `accepted` | 타 팀 flag 정답, 득점(+3) | 해당 경로 우선순위 유지, flag 해시 확정 집합에 추가 |
| `own_team` | 본인 팀 flag | 제출 대상에서 제외, 재제출 안 함 |
| `duplicate` | 이미 제출됨 | 중복 집합에 추가, 재제출 안 함 |
| `rejected` | 잘못된 flag/토큰 | 후보 폐기, 추출 규칙 점검 |
| `closed` | 라운드 종료 후 | 제출 중단, 다음 라운드 대기 |

한 flag의 경로가 여럿일 수 있으므로(제11조 ③) 서로 다른 경로에서 같은 flag를 얻어도 해시 중복 검사로
재제출을 막는다. 제출 limiter는 공유 monotonic timestamp deque에 전송 시각을 기록하고,
`now - 60s` 이전 기록만 제거한 뒤 남은 항목이 30개이면 가장 오래된 기록이 60초 창을 벗어날
때까지 대기한다. 확인과 추가는 원자적으로 하며 burst capacity를 두지 않는다.

`Retry-After`의 clock domain 변환은 다음으로 고정한다.

1. delta-seconds는 파싱한 비음수 초를 그대로 `delay`로 쓴다.
2. HTTP-date는 wall clock을 정확히 한 번 읽고 `delay = max(0, parsed_http_date - wall_now)`로 정확히
   한 번 변환한다.
3. 그 직후 monotonic clock을 읽어 `retry_deadline = monotonic_now + delay`를 만든다. 이후 wall clock이
   앞뒤로 움직여도 delay나 deadline을 다시 계산하지 않으며 HTTP-date와 monotonic 값을 직접 비교하지
   않는다.
4. 수명주기 오케스트레이터가 신뢰할 수 있는 Round 경계를 관측한 경우에만 monotonic
   `round_deadline`을 공급한다. `retry_deadline <= round_deadline`일 때만 기다린다. 공식 Round 시작의
   신뢰할 신호가 없는데 프로세스 시작에 20분을 더해 경계를 발명하지 않는다.
5. 신뢰할 `round_deadline`이 없으면 양수 delay를 현 Round에 안전하다고 가정할 수 없으므로 현 Round
   재시도를 중단한다. header 누락·무효 시의 상한 지수 backoff도 양수 대기이므로 같은 deadline 검사를
   통과해야 한다.

라운드 종료 시 flag·세션 원문, handle, 중복 집합, deque를 폐기한다.

## 9.12 LLM 사용 경계

- 결정론적 파싱·범위 검사·rate limiting·flag 제출을 LLM에 맡기지 않는다.
- LLM은 관측 요약·가설 우선순위 조언·다음 허용 관측 제안에만 쓴다. LLM 출력이 도구를 직접 실행하지
  못한다. 모든 제안은 allowlist·대상 범위·요청 예산 검사를 **다시** 통과해야 한다.
- 서버 호스팅 tools(`web_search`·`code_interpreter`·`file_search`·`mcp`)는 프록시가 차단한다
  (`litellm-gw/config.yaml`). Responses 타입 모델도 `/v1/chat/completions`로 호출한다.
- 라운드별 LLM 호출 수·토큰 예산·사용 목적을 기록한다(운영세칙 제9·23조 증빙, 동점 시 토큰 비용
  제22조). 예산 소진 시 결정론 경로는 계속 동작한다.
- 프롬프트·로그에 `SUBMIT_TOKEN`·`LLM_API_KEY`·flag·세션 원문을 넣지 않는다. LLM에는
  비민감 fingerprint·마스크 요약만 전달한다.
- 예선 합성 성능 수치(P/R/FPR, 위험도 점수)를 본선 예상 성능으로 제시하지 않는다(예선 p12·p46·p48).

## 9.13 오류 처리와 종료

| 상황 | 동작 |
|---|---|
| 필수 환경변수 누락·형식 오류 | 로그 후 종료(inert). 임의 기본값으로 실행하지 않음 |
| 빈 대상 목록 | inert, 주기적 재확인 |
| 개별 표적 timeout·연결 실패 | 관측으로 기록, 해당 표적만 건너뜀, backoff 후 재시도 |
| 도구 실패 | `ToolResult(fail)`로 격리, 다른 표적 계속 |
| 제출 서버 429·일시 오류 | `Retry-After`를 단일 delay→monotonic deadline으로 변환. 신뢰할 monotonic Round deadline이 없거나 초과하면 현 Round 재시도 중단. header 누락·무효 시 backoff도 같은 deadline 검사 |
| LiteLLM 장애·예산 소진 | LLM 조언만 중단. 관측·범위 검사·제출은 계속 |
| 라운드 종료·종료 신호 | 임시 상태 폐기 후 정상 종료 |

전체 런타임 중단은 (환경변수 오류) 외에는 하지 않는다. 나머지는 표적 격리 또는 backoff 재시도다.

## 9.14 향후 파일 구조 (다음 구현 브랜치)

실제 파일은 만들지 않고 책임만 제안한다. 각 파일은 하나의 책임을 갖는다.

```text
agents/attacker/src/aegis_attacker/
├─ config.py         # 공개 환경변수 검증, secret bootstrap 후 handle만 든 설정 타입
├─ models.py         # Endpoint·ObservedServiceProfile·Observation·Hypothesis·FlagCandidate 등
├─ secrets.py        # terminal Round 저장소, typed handle, 소비자별 resolve 정책
├─ egress.py         # 유일한 raw transport 소유자, capability별 정규화·method·path·인증 검증
├─ preflight.py      # 가설·두 evidence class·TTL·precondition·cost 검증
├─ budget.py         # endpoint pass, 10/E 상한, planner turn·원자적 charge 예약
├─ rate_limit.py     # 전역 10/s·burst20 토큰 버킷, 제출 공유 60초 sliding window
├─ observation.py    # EgressGateway만 사용하는 관측 수집·정규화
├─ profiles.py       # ObservedServiceProfile 분류, FinalsPhaseHint
├─ priority.py       # 관측 증거 기반 우선순위 힌트(예산 공정성은 변경 불가)
├─ planner.py        # S1~S5 가설 선택·중단
├─ tools.py          # allowlist action registry·실행 어댑터(EgressGateway만 사용)
├─ flags.py          # 후보 추출·해시 중복
├─ submit.py         # SUBMIT gateway·FLAG/SUBMIT_TOKEN 전용 소비·Retry-After 변환
├─ llm_advisor.py    # LLM gateway·LLM_KEY 전용 소비·라운드 예산
├─ audit.py          # 비밀 제거 구조화 로그
├─ round_report.py   # 비밀 없는 Round 결과 요약
├─ runtime.py        # 수명주기 오케스트레이터
└─ __main__.py       # 진입점

agents/attacker/tests/
├─ test_config.py · test_secrets.py · test_egress.py · test_preflight.py · test_budget.py
├─ test_rate_limit.py · test_observation.py · test_profiles.py · test_priority.py
├─ test_planner.py · test_tools.py · test_flags.py · test_submit.py
├─ test_llm_advisor.py · test_round_report.py · test_runtime.py · test_composition.py
```

`test_composition.py`는 관측기·실행 어댑터·제출·LLM 객체 그래프가 오직 `EgressGateway`만 transport로
받고 generic HTTP transport를 받을 생성자·필드를 노출하지 않는지 검사한다. `egress.py` 밖에서 raw
HTTP client/session을 생성·주입하는 의존성 검사를 함께 둔다. 네트워크 실행(`tools`·`observation`),
계획 판단(`planner`·`priority`), flag 추출(`flags`), 제출(`submit`)의 경계와 단일 gateway 구조는 파일을
합치더라도 보존해야 한다.

## 9.15 테스트 전략과 승인 기준

구현 단계에서 필요한 실패·성공 사례(테스트 코드는 아직 작성 안 함).

| 대상 | 성공 기준 | 실패(거부) 기준 |
|---|---|---|
| 환경변수·secret bootstrap | 저장소를 먼저 만들고 raw secret을 즉시 typed handle로 치환; config `repr`·직렬화에 원문 없음 | 저장소 생성 전 secret 파싱, raw 값을 config에 보존, repr·직렬화 노출 |
| secret 소비자·수명주기 | 실행=`SESSION`, 제출=`FLAG|SUBMIT_TOKEN`, LLM=`LLM_KEY`; TTL·terminal close·동시 close/write 선형화 | wrong-kind resolve, TTL 이후 resolve, close 뒤 write/resolve·재개방 |
| `TARGETS × PORTS` 해석 | 운영진 상대 집합의 모든 정확한 정규화 조합 큐잉 | 조합 누락, self-team 비교·하드코딩·비공식 self env 요구 |
| FinalsPhase 문서 구조 | 일정 1~4·Round 수 2·4·4·4를 운영 힌트로만 보존 | 관측 없이 endpoint layer ID 생성·런타임 Phase 입력 요구 |
| 용어 분리 | `FinalsPhase`·`S4ChainStage`·`MissionState`가 다른 타입·용어 | 혼용 |
| profile 우선순위 | 서비스 증거로 힌트 선택 | Phase 환경변수 요구 |
| 미지 서비스 | 범용 저비용 관측 fallback | 임의 프로토콜 가정 |
| 결정론적 Round 예산 | `E`, endpoint 10, 총 `10*E`, plan당 charge 1, endpoint당 pass 1 charge, 첫 관측 전체 선행, planner turn 6·명시적 no-progress/invalid-evidence 중단 | 0/음수 cost·charge, plan charge≠1, endpoint 11번째·총 cap 초과, 첫 pass 전 재예약 |
| 예산 원자성 | preflight 성공 뒤 rate/I/O 전에 동시 요청 중 하나만 마지막 charge 예약 | 초과 예약, rate 획득·I/O 뒤 charge, 실패 preflight의 charge 소비 |
| UAV→UGV | 근거 없이 UAV profile 재사용 안 함 | 무근거 재사용 |
| rate limit | 초당 10·버스트 20 준수 | 초과 요청 |
| 제출 limiter | fake monotonic clock으로 60초 경계·동시성을 검증해 rolling 60초 ≤30 | 31번째 전송·burst |
| `Retry-After` clock | fake wall-clock/monotonic으로 delta-seconds 직접 변환, HTTP-date에서 wall clock 1회→delay 1회→monotonic deadline; 이후 wall-clock jump 무관 | HTTP-date와 monotonic 직접 비교, wall jump 뒤 재계산 |
| retry Round 경계 | authoritative monotonic deadline 이내만 대기; deadline 없음·초과 시 현 Round retry 중단 | 프로세스 시작으로 Round 경계 발명, 남은 deadline 초과 대기 |
| 가설·계획 binding | 등록 `hypothesis_id`, 현 endpoint의 신선한 local 실행 근거, 선택적 same-Round/same-hypothesis S4 lineage | 미등록 가설·근거, local 근거 없음, TTL·Round 불일치, lineage로 local 근거 대체 |
| typed egress destination | capability별 정규화 scheme·host·port·path와 method·secret kind, proxy 비활성, 3xx 관측 반환 | host·port·path 변경, method·secret kind·capability 교차, 자동 redirect |
| egress 우회 방지 | 모든 네트워크 객체가 단일 gateway만 의존하고 raw transport는 `egress.py` private | adapter/client의 generic HTTP transport 필드·직접 생성·주입 |
| redirect 수동 hop | 새 계획·신선한 local 근거와 전체 destination 재검증 | 기존 plan 재사용·capability crossing |
| 부작용 | 기본 읽기 전용, 제한 변경은 명시적 등급·precondition으로만 허용 | 등급 없는 변경·물리·가용성·지속성·파괴 작업 |
| 범위 | 허용 밖 대상 실행 거부 | 범위 밖 요청 |
| 도구 | timeout·부분 실패 격리 | 전체 중단 |
| flag | 중복 제출 방지, 5종 결과 처리 | 재제출·미처리 |
| LLM | 장애·소진 시 결정론 경로 유지 | 결정론 경로 중단 |
| 비밀 수명주기 | Round 메모리에만 보관, handle 사용, TTL·종료 폐기 | 직렬화·TTL 이후 잔존·LLM 원문 전달 |
| 로그 | 토큰·키·flag·세션 원문 제거 | 비밀 노출 |
| Round 요약 | 비밀·상대 팀 값 제거 | 비밀 포함 |
| 라운드 종료 | 임시 상태 폐기 | 상태 잔존 |

---

## 7. 본선 FinalsPhase 1~4 적응 전략

### 7.1 Phase 용어 분리

| 이름 | 개수 | 의미 | 사용 제한 |
|---|---:|---|---|
| `FinalsPhase` | 1~4 | 본선 레이어 누적 개방 경기 단계 | 공식 일정 또는 실제 개방 대상 근거와 함께 |
| `S4ChainStage` | 1~5 | 예선 S4 다단계 체인 국면(p10) | `FinalsPhase` 번호와 대응한다고 가정 안 함 |
| `MissionState` | 구현 시 enum 검토 | 예선 기체 임무 상태 | 수신 데이터 파서로 증명될 때만 |

예선 `S4 5-Phase`는 이 문서에서 `S4ChainStage 1~5`로 표기한다.

### 7.2 본선 구조와 예선 보고서 연결

본선은 4개 `FinalsPhase`, 총 14개 Round(2·4·4·4). 새 레이어가 열려도 이전 레이어는 닫히지 않는다.

| FinalsPhase | Round 수 | 새 레이어 | 누적 개방 | 예선 가장 가까운 세그먼트 | 기본 가설 | 활성화 전 필요한 증거 |
|---|---:|---|---|---|---|---|
| 1 | 2 | Layer 1 위성망 게이트웨이 | L1 | Communication 일부 | 저비용 서비스·프로토콜 관측 | 실제 배너·프로토콜·응답·오류 |
| 2 | 4 | Layer 2 임무 통제 서버(MCS) | L1~L2 | Ground/GCS 중심 | S1, S4ChainStage 초기부 | 인증·세션·명령 인터페이스 실제 노출 |
| 3 | 4 | Layer 3 무인이동체(UAV) | L1~L3 | Vehicle/Edge + Communication | S2, S3, 증거 기반 S4 | 파라미터·텔레메트리·상태 인터페이스 노출 |
| 4 | 4 | Layer 4 사족보행 로봇(UGV) | L1~L4 | Vehicle/Edge + Communication 재검증 | S2, S3, S4, 조건부 S5 | UGV 고유 인터페이스·AI 입력 경계 각각 노출 |

이 표는 취약점 목록이 아니다. 위성망 게이트웨이를 예선 Communication과 동일시하거나, MCS를 GCS
구현과 동일시하거나, UAV의 프로토콜·파라미터를 UGV에 재사용하지 않는다. S5는 AI 방어 입력 경계가
노출됐다는 증거가 있을 때만 어느 `FinalsPhase`에서든 활성화한다.

### 7.3 하나의 누적 적응형 런타임

FinalsPhase별 별도 이미지·네 개 프로그램을 만들지 않는다. 하나의 런타임이 다음 원칙으로 모든
`FinalsPhase`를 처리한다.

- 항상 `TARGETS × PORTS` 전체를 입력으로 받고 주소·포트를 하드코딩하지 않는다.
- 공식 계약에 없는 `PHASE`·`LAYER`·`ROUND` 환경변수를 요구하지 않는다.
- 표적의 배너·응답 형태·프로토콜 특징·오류·실제 성공 결과로 `ObservedServiceProfile`을 만든다.
- Phase·레이어 플레이북은 우선순위 힌트일 뿐, 증거가 맞지 않으면 범용 저비용 관측으로 회귀한다.
- 새 레이어가 열려도 이전 레이어의 검증된 플레이북을 중단하지 않는다.
- 런타임 요청 예산은 `TARGETS × PORTS` endpoint pass로 공정 배분한다. 관측으로 레이어 매핑을
  증명하기 전에는 레이어별 예산이나 ID를 만들지 않는다. 성공 가능성이 확인된 표적도 모든 활성
  endpoint의 같은 pass가 끝난 뒤에만 다음 charge를 받을 수 있다.
- 보고서 S1~S5는 `ObservedServiceProfile`과 선행 증거가 모두 맞을 때만 실행 후보가 된다.

### 7.4 FinalsPhase별 기본 Round 목표

초기 운영 가설이다. 실제 flag·로그·PCAP·서비스 변화가 다르면 관측 증거를 우선해 순서를 바꾼다.

| FinalsPhase | Round 1 | Round 2 | Round 3 | Round 4 |
|---|---|---|---|---|
| 1 | L1 전체 표적·서비스 inventory·기준선 수집 | 검증된 저비용 관측·flag 추출·제출 흐름 안정화 | 해당 없음 | 해당 없음 |
| 2 | 새 MCS fingerprint + L1 회귀 확인 | 세션·명령 경계 보일 때 S1 검증 | L1↔L2 인과 연결·S4ChainStage 가능성 검토 | 성공 플레이북 안정화, 실패 가설 제거 |
| 3 | 새 UAV 인터페이스 식별 + L1~L2 회귀 | 파라미터 인터페이스 보일 때 S2 검증 | 텔레메트리·상태 경계 보일 때 S3 검증 | 증거 이어질 때만 L1~L3 S4 체인 검토 |
| 4 | UGV를 UAV와 다른 profile로 식별 + L1~L3 회귀 | UGV 증거에 맞춰 S2·S3 독립 재검증 | 다계층 S4·AI 입력 경계 보이면 S5 검토 | 가장 안정적 고득점 플레이북 유지, 미검증 실험 축소 |

각 Round 목표에는 관측 신호, 성공 판정, 중단 조건, §9.7의 endpoint당 10·총 `10*E` 요청 charge
예산, 다음 Round로 가져갈 비밀 없는 산출물을 명시한다. 일정표의 레이어 이름은 운영 분석용이며
런타임 scheduler의 입력이나 예산 key가 아니다.

### 7.5 당일 20분 Round·10분 Break 운영 루프

```text
현재 Round 20분
  → 자동 공격 진행과 동시에 로그·PCAP·제출 결과 분석
  → 다음 버전 플레이북·파서·우선순위 수정
  → Break 시작 시 최종 테스트·이미지 빌드
  → Break 전반 5분 안에 Registry(ligacr.azurecr.io/team{N}) push 완료
  → 운영 측 pull 상태 확인
  → 다음 Round에서 새 이미지 검증
```

- 운영 측은 다음 Round 시작 **5분 전**에 `latest` 이미지를 pull한다(운영세칙 제15조, Pull Timeout 20분).
- Break 후반까지 코드를 작성하는 계획을 세우지 않는다. 실행 중 컨테이너는 새 push의 영향을 받지 않고
  다음 Round부터 반영된다.
- 공격 담당은 변경된 실행 명령·의존성·테스트 결과를 Docker 담당에게 즉시 전달하고, Docker 담당이
  build·push를, 공격 담당과 팀장 이경준이 공격 이미지 변경을 검토한다.
- 같은 날 운영진이 일정을 변경하면 현장 공지를 우선한다.

### 7.6 Round 간 학습과 상태 경계

컨테이너·flag·런타임 메모리는 Round마다 초기화된다. 과거 flag·토큰·세션 값·상대 팀 비밀을 이미지나
저장소에 넣지 않는다. 다음 Round로 가져갈 수 있는 것은 팀이 검토한 **비밀 없는 개발 산출물**뿐이다.

- 서비스 fingerprint 규칙, 응답 parser 개선
- 실패가 확인된 가설의 중단 규칙
- 요청 예산·timeout 조정, 도구 버전·비민감 결과 코드
- 로그·PCAP 분석에서 확인한 재현 가능한 일반 패턴

Round 간 상관은 숨은 영속 상태가 아니라 코드·테스트·검토된 설정의 새 버전으로 구현한다. 예선의
Adaptation Loop(p40) 개념은 이렇게 **오프라인 이미지 개선 루프**로 재설계한다.

### 7.7 적응 실패와 fallback

- 새 레이어를 식별하지 못하면 범용 저비용 관측으로 회귀하고 임의 프로토콜을 가정하지 않는다.
- 새 레이어 분석 실패해도 이전 레이어의 검증된 플레이북·제출 흐름은 계속 동작한다.
- 로그·PCAP 제공이 늦어도 결정론적 관측·범위 검사·제출 흐름은 중단하지 않는다.
- 이미지 build·push가 pull 시각을 놓치면 다음 Round에 이전 이미지가 쓰일 수 있음을 즉시 Docker
  담당·팀장에게 보고하고, 직전 정상 이미지를 rollback 기준으로 둔다.
- LLM 장애·예산 소진은 Phase 식별·rate limiting·도구 범위 검사·flag 제출을 막지 않는다.

---

## 고정된 본선 계약 (설계에서 보존)

### 입력과 대상
- `TARGETS`(상대 주소 CSV), `PORTS`(공통 진입 포트 CSV), `SUBMIT_URL`, `SUBMIT_TOKEN`,
  `LLM_BASE_URL`, `LLM_API_KEY`. 대상 = `TARGETS × PORTS` 전체 조합.
- 공식 `TARGETS`를 운영진이 제공한 상대 집합으로 그대로 해석한다. 공식 입력에 자기 팀 식별자가 없으므로
  별도 self-team 제외 검사를 만들지 않고 정확히 파싱한 allowlist membership만 검사한다.
- 주소·포트·토큰·팀별 값을 하드코딩하지 않는다(운영세칙 제7조).

### 요청·제출 제한
- 상대 방어망: 공격 에이전트당 초당 10회·버스트 20(제12조).
- flag 제출: 모든 rolling 60초에서 최대 30회, 초과 시 429(제10조).
- 제출 결과 `accepted`/`own_team`/`duplicate`/`rejected`/`closed` 구분, 동일 flag 불필요 재제출 방지.

### 네트워크·상태
- 허용된 상대 진입점·제출 서버(`10.99.50.4:4100`)·LiteLLM(`litellm.lig.internal:4000`)만 사용(제8·11조).
- 외부 인터넷·운영망·범위 밖 주소 접근 금지. DoS·rate 우회·flag 목적 밖 파괴·변조 금지(제24조).
- 컨테이너·flag는 라운드마다 초기화. 캐시·중복 집합·관측 이력은 라운드 한정 상태.
- 인증 키·토큰·flag 원문을 로그에 남기지 않는다.
- 모든 네트워크 호출은 capability별 scheme·host·port·path·method·secret kind를 검증하는 단일
  `EgressGateway`를 통과한다.

---

## 자체 검토 결과 (§12)

- 운영세칙·당일안내 SHA-256이 인벤토리와 일치(위 표).
- 본선 구조 4 FinalsPhase·14 Round·FinalsPhase N에서 Layer 1~N 누적 개방 기록(§7.2).
- `FinalsPhase 1~4`·`S4ChainStage 1~5`·`MissionState` 혼용 없음(§7.1).
- FinalsPhase 1~4 Round 목표 2·4·4·4, FinalsPhase 4에서 L1~L4 유지(§7.4).
- FinalsPhase별 별도 이미지가 아니라 하나의 누적 적응형 런타임(§7.3).
- `PHASE`·`LAYER`·`ROUND` 환경변수 미요구(§7.3·§9.9).
- self-team 입력·추론 없이 공식 `TARGETS × PORTS` membership만 검사(§9.6, 고정 계약).
- 위성망 게이트웨이·MCS·UAV·UGV 매핑은 관측 증거 요구, UAV 가정을 UGV에 복사 안 함(§7.2·§7.4).
- Round 중 분석·수정, Break 전반 5분 build·push 루프(§7.5).
- 예선 보고서 원본 해시 일치·물리 페이지 54, 페이지 매핑 1~54 각 1행(별도 문서).
- 요청·제출 제한 숫자와 endpoint 10·총 `10*E` 실행 charge가 결정론적으로 고정(§9.7·§9.10).
- 가설 ID·local 실행 근거와 S4 causal lineage가 분리되고 preflight에 결속(§9.6·§9.8·§9.10).
- 비밀 저장소 선생성, handle-only config, 소비자별 kind, terminal close를 고정(§9.6).
- 단일 typed egress가 관측·실행·제출·LLM의 raw transport 우회를 차단(§9.5·§9.10·§9.14).
- `Retry-After` HTTP-date를 wall→delay→monotonic으로 한 번 변환하고 신뢰할 Round deadline이 없으면
  양수 대기를 중단(§9.11).
- 관측·계획·실행·제출 책임 분리(§9.5), 향후 파일·설계 테스트 일대일(§9.14·§9.15).
- 설계 문서와 `research/attack-scenarios.md` 용어·내용 무모순.
- 미결정·빈 절·임시 문구 없음. 공식 자료로 증명되지 않은 취약점 미가정.

## 상위 자료 충돌 여부

확인된 충돌 없음. 운영세칙·당일안내·agent-guide·스켈레톤이 서로 정합하며, 예선 보고서는 본선 자료와
충돌하는 부분(합성 성능 수치, 도메인 취약점 존재)을 모두 `재설계`/`제외`로 판정했다. 팀장 이경준 확인이
필요한 상위 자료 충돌 항목은 현재 없다.

## 다음 단계

승인 후 `feat/attacker-runtime-foundation`에서 §9.14 구조를 테스트 우선(TDD)으로 구현한다. 공격 설계
PR 병합은 선행 정렬 PR(`docs/finals-source-alignment`)이 `main`에 병합된 뒤 진행한다.
