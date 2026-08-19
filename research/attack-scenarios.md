# 공격 시나리오 가설

예선 보고서의 시나리오(S1~S5)는 본선 취약점 목록이 아니라 **정찰 우선순위를 정하는 가설**이다.
공격 에이전트는 하드코딩된 시나리오 순서를 강제하지 않고, 표적의 배너·응답·오류·프로토콜 특징을
근거로 가설을 선택하고 중단한다. 용어와 활성화·중단 기준은 설계 문서
`docs/superpowers/specs/2026-08-11-attacker-runtime-design.md`의 §9.8 가설 플래너와 동일하다.

## 원칙

- 구체적 본선 취약점이 존재한다고 단정하지 않는다. 운영세칙 제11조 ③에 따라 취약점과 flag는 1:1이
  아니며 한 flag의 경로가 여럿일 수 있다.
- 로컬 데모의 SSRF·세션 변조·SQLi를 본선 사실로 적지 않는다(인터페이스 이해용 예시).
- 활성화 근거가 없으면 해당 시나리오를 실행하지 않는다. `FinalsPhase`가 같다는 이유만으로 활성화하지
  않는다.
- `S4ChainStage` 번호를 `FinalsPhase` 또는 레이어 번호와 대응시키지 않는다.
- 성공 증거와 중단 조건이 없는 시나리오를 남기지 않는다.
- 활성화된 각 가설은 Round 안에서 안정적이고 유일한 `hypothesis_id`를 가지며, 활성화 evidence를
  가설 레지스트리에 명시적으로 등록한다. `ExecutionPlan`은 반드시 그 ID에 결속한다.
- 후속 계획은 비어 있지 않은 현 Round·정확한 현 endpoint의 신선한 `execution_evidence_refs`에
  묶이며, 오래되거나 대상이 다른 근거로는 실행하지 않는다.
- 선택적 `causal_lineage_refs`는 S4 인과 설명용이다. 다른 endpoint의 lineage는 같은 Round·같은
  `hypothesis_id`에 명시 등록된 경우만 허용되며, 현 endpoint의 local 실행 근거를 대신하지 않는다.
- 후속 요청의 기본은 읽기 전용이다. 상태 변경은 flag 획득에 필요한 유한 작업으로 범위가
  명시되고 안전 등급·선행조건·중단 조건을 모두 통과할 때만 허용한다.
- 최초 관측은 가설·실행 근거만 면제된 typed bootstrap 계획으로 수행한다. 정확한 endpoint의 읽기 전용
  최소 요청도 공통 범위·비용 검증과 request charge 원자적 선예약을 통과하고, 일회용 reservation token을
  gateway가 소비해야 한다. 무계획·무과금 관측은 허용하지 않는다.
- endpoint별 PCAP-confirmed fast path 20회, 배너 기반 결정론 후보 44회, bounded recon 목록,
  planner turn 4의 개별 상한을 둔다. Round 전체 LLM 호출은 48회로 제한하고, 모든 요청은 공통
  rate limiter와 Round deadline을 통과한다.
  `accepted` flag·상한 소진·결정론적 no-progress/invalid-evidence면 해당 endpoint를 중단한다.

## 2026-08-15 TEAM1 관측 기반 실행 우선순위

TEAM1 자료의 동일성과 원시자료 비추적 경계는 `docs/references/team1-capture-defense-map.md`의 tree
SHA-256 및 분석 방법을 공동 근거로 사용한다. 공격 런타임에는 flag 응답과 직접 연결된 다음 읽기
전용 요청 형태만 일반 정찰보다 앞선 zero-token fast path로 반영한다.

| 레이어 | 관측된 성공 형태 | 런타임 처리 |
|---|---|---|
| L1 / 8082 | `helper-box:8080/secret`, Docker IP의 IPv4·정수·16진수·IPv4-mapped IPv6 표현, `/config?file=../../../../flag` | 관측된 SSRF target 표현과 exact config traversal을 먼저 실행 |
| L2 / 8083 | Base64-JSON `session`의 `role=admin`, loopback `/secret`·`/registry` SSRF | 비민감 claim 구조와 관측된 느슨한 padding 한 종을 재생성; `127.0.0.1`·`127.1` exact target 실행 |
| L3 / 8084 | `/product?id=... UNION SELECT ... FROM app_meta`, `/rc/status`·`/teleop/status`·`/debug`·`/admin` 직접 노출 | SQLi projection 뒤에 네 route를 읽기 전용으로 확인하고 flag가 있을 때만 제출 |
| L4 / UGV | Phase 4 도메인과 L1~L4 누적 개방만 공식 확인, 취약 route 미관측 | 사전 확인되지 않은 포트에서는 범용 exploit 경로를 생성하지 않음. 실제 root·probe 응답이 명시한 `GET` path와 query parameter, 또는 OpenAPI의 `get` operation만 공격 후보로 승격 |

Phase 4에서는 운영 측이 전달한 `TARGETS × PORTS` 전체를 유지한다. 알려진 데모 포트는
`L4→L1→L2→L3` 순환으로 섞어 새 UGV 레이어를 초반에 시작하면서도 기존 레이어를 굶기지 않는다.
포트 매핑이 관측되지 않으면 입력 순서를 보존한다.

### L4 증거 gate

현재 L4에 대해 확정된 것은 Phase 4의 UGV 명칭과 L1~L4 누적 개방뿐이다. 테스트의 `8085`,
`9001`, `/telemetry`, `source`는 **관측-계획-실행 결속을 검증하는 합성 fixture**이며 본선 port·route
사실이 아니다. 따라서 다음 경계를 런타임 회귀 조건으로 둔다.

- PCAP 또는 실제 HTTP 응답이 없는 포트에는 `observed_attempts`를 만들지 않는다.
- 미확인 포트의 배너가 단순히 UGV·URL·telemetry 같은 단어만 포함하면 공격 요청을 만들지 않는다.
- root, bounded probe, `robots.txt`, OpenAPI 문서가 명시한 읽기 전용 `GET` route와 query parameter만
  해당 endpoint의 신선한 evidence로 사용한다. 쓰기 method만 있는 route는 무시한다.
- 다른 endpoint의 성공 playbook은 구조 fingerprint가 같더라도 현 endpoint의 정찰과 evidence 갱신 뒤에만
  실행한다.
- 새 L4 PCAP이 들어오면 protocol·port·route·method·parameter를 먼저 inventory하고, positive와 정상
  negative fixture가 함께 생기기 전에는 port별 fast path를 추가하지 않는다.

### R17 피드백에 따른 적응 전략

R17 공격 로그는 33개 endpoint에 1,600회 요청과 111회 LLM 호출(93,427 token)을 사용했지만,
accepted flag는 한 팀의 L1·L2 두 개뿐이었다. 같은 서비스가 팀별 동적 문자열 때문에 서로 다른
배너로 인식됐고, 신선도가 지난 계획은 `PlanBindingError` 뒤에 복구되지 않았으며, 성공한 기본
delivery를 다른 팀 방어가 막아도 더 강한 우회 delivery가 playbook을 갱신하지 못했다.

이에 따라 런타임은 서비스 내용과 delivery 표현을 분리한다. 상태군·route·form parameter·HTML
구조·오류 표식으로 만든 구조 fingerprint를 팀 간 playbook key로 사용하고, 성공한 더 강한
delivery는 generation을 올려 기존 값을 대체한다. 완료 endpoint는 같은 Round에 재공격하지 않고,
실패 endpoint는 30초 cooldown 뒤 또는 새 playbook generation이 생겼을 때만 재시도한다.

실행 근거가 오래되면 요청을 억지로 재결속하지 않는다. 해당 endpoint의 root를 읽기 전용으로 한 번
재관측해 새 evidence를 만든 뒤 같은 계획을 다시 검증한다. R17에서 확인된 완전 request-target
percent encoding, trailing-dot·대소문자 host, 0-padding port, repeated slash, 중첩 SSRF, SQL control
whitespace·block comment·bracket identifier를 최대 6개의 bounded delivery 후보로 생성한다. 후보 하나가
HTTP 응답을 받았지만 flag가 없더라도 나머지 후보를 계속 시도하며, 실제 flag를 만든 delivery만
playbook에 저장한다.

## S1~S5 표

| 시나리오 | 예선 개념 | 관련 FinalsPhase·레이어 후보 | 활성화에 필요한 본선 관측 | 허용된 다음 단계 | 성공 증거 | 중단 조건 |
|---|---|---|---|---|---|---|
| S1 | GCS 계정·세션 탈취와 임무 명령 변조 (예선 p8) | FinalsPhase2 MCS(L2) 힌트, 인증 area가 보이면 어느 레이어든 | 인증/세션 경계 신호 — 로그인·admin·private area 배너, Set-Cookie·토큰·세션 blob, 401→200 전이 | 세션 원문은 Round 비밀 저장소 `SESSION` handle로만 참조하고, 현 endpoint의 신선한 local 실행 근거·읽기 전용 기본·예산 검사를 통과한 후속 관측만 수행 | 인증 경계 응답에서 `FLAG{...}` 추출·제출 `accepted` | 인증/세션 경계 신호 없음, 후속 관측에도 응답 불변, 증거 TTL·예산 소진 |
| S2 | Autopilot 파라미터·Failsafe 변조 (예선 p9) | FinalsPhase3/4 UAV·UGV(L3/L4) 힌트 | 파라미터/설정형 엔드포인트와, 변경 요청에 대한 서버측 반영 차이 관측 | 기본은 읽기 전용 추가 관측. 상태 변경은 신선한 endpoint 증거와 `BOUNDED_FLAG_DIRECTED_MUTATION` 등급·변경 범위·안전 선행조건을 모두 검사한 유한 작업만 허용 | 허용된 경로 응답에서 flag 추출·제출 `accepted` | 인터페이스 미노출, 안전 선행조건 미충족, 물리·가용성 영향, 증거 TTL·예산 소진 |
| S3 | 센서/텔레메트리 상태 은폐 (예선 p9) | FinalsPhase3/4 UAV·UGV(L3/L4) 힌트 | 입력값이 서버 상태·응답에 반영되는 경계(조작 가능한 입력 파라미터) 관측 | 기본은 읽기 전용 추가 관측. 상태 변경은 신선한 endpoint 증거와 `BOUNDED_FLAG_DIRECTED_MUTATION` 등급·변경 범위·안전 선행조건을 모두 검사한 유한 작업만 허용 | 허용된 경로 응답에서 flag 추출·제출 `accepted` | 입력 반영 경계 미관측, 안전 선행조건 미충족, 물리·가용성 영향, 증거 TTL·예산 소진 |
| S4 | 여러 레이어를 잇는 다단계 공격 체인 (`S4ChainStage 1~5`, 예선 p10) | 누적 개방 레이어 전반(L1~L4) | 같은 Round·같은 `hypothesis_id`에 등록된 **인과적으로 이어지는** 관측 lineage와 현재 endpoint의 독립 local 실행 근거 | `S4ChainStage` 순서로 진행하되 매 국면마다 현 endpoint의 `execution_evidence_refs`를 요구하고, cross-endpoint `causal_lineage_refs`는 인과 설명에만 사용 | 체인 경로 끝에서 flag 추출·제출 `accepted` | local 실행 근거 없음, lineage 미등록·Round/가설 불일치, 국면 간 인과 증거 끊김, 방어 선제 차단 정황, 예산 소진 |
| S5 | 방어 AI 입력 오염 (예선 p11) | 조건부 — AI 입력 경계 노출 증거 시 어느 FinalsPhase든 | 방어 AI의 입력 경계가 표적 인터페이스로 **실제 노출**됐다는 증거 | 노출된 입력 경계에 허용 범위·예산 안에서만 관측 요청 | 해당 경로가 flag 획득에 기여, 제출 `accepted` | AI 입력 경계 노출 증거 없음(대부분의 경우 미활성), 예산 소진 |

## 금지 경계 (모든 시나리오 공통)

- SLA 훼손(정상 서비스 방해)·DoS·rate limit 우회·flag 목적 밖 파괴·변조 금지(운영세칙 제20·24조).
- 허용된 상대 진입점·제출 서버·LiteLLM 외 접근 금지. 물리 로봇(UAV·UGV) 안전 침해 금지(제24조 4호).
- 예선 A5(가용성 인식 적대자)의 가용성 공격 성질은 본선 공격 런타임에서 **실행하지 않는다**(설계 §9.3).
- 인증 키·제출 토큰·flag·세션 원문은 Round 메모리에만 두고 로그·산출물·LLM에 남기지 않는다.
