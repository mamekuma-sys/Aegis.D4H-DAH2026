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
- endpoint별 PCAP-confirmed fast path 10회, 배너 기반 결정론 후보 44회, bounded recon 목록,
  planner turn 6의 개별 상한을 둔다. 모든 요청은 공통 rate limiter와 Round deadline을 통과한다.
  `accepted` flag·상한 소진·결정론적 no-progress/invalid-evidence면 해당 endpoint를 중단한다.

## 2026-08-15 TEAM1 관측 기반 실행 우선순위

TEAM1 자료의 동일성과 원시자료 비추적 경계는 `docs/references/team1-capture-defense-map.md`의 tree
SHA-256 및 분석 방법을 공동 근거로 사용한다. 공격 런타임에는 flag 응답과 직접 연결된 다음 읽기
전용 요청 형태만 일반 정찰보다 앞선 zero-token fast path로 반영한다.

| 레이어 | 관측된 성공 형태 | 런타임 처리 |
|---|---|---|
| L1 / 8082 | `helper-box:8080/secret` SSRF와 trailing-dot 변형 | `/fetch`·`/proxy`의 관측 파라미터 조합을 먼저 실행 |
| L2 / 8083 | Base64-JSON `session`의 `role=admin`, loopback `/secret` SSRF | 원본 cookie를 복사하지 않고 비민감 claim 구조를 재생성; loopback exact target도 실행 |
| L3 / 8084 | `/product?id=... UNION SELECT ... FROM app_meta` | 성공 응답과 연결된 `app_meta` projection을 먼저 실행 |
| L4 / UGV | Phase 4 도메인과 L1~L4 누적 개방만 공식 확인, 취약 route 미관측 | UGV 이름만으로 endpoint를 추측하지 않음. 실제 root·probe 응답이 노출한 path·parameter만 공격 후보로 승격 |

Phase 4에서는 운영 측이 전달한 `TARGETS × PORTS` 전체를 유지한다. 알려진 데모 포트는
`L4→L1→L2→L3` 순환으로 섞어 새 UGV 레이어를 초반에 시작하면서도 기존 레이어를 굶기지 않는다.
포트 매핑이 관측되지 않으면 입력 순서를 보존한다.

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
