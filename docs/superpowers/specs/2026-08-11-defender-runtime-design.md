# DAH 2026 본선 방어 런타임 설계

- 작성: 방어 담당자
- 브랜치: `docs/defender-runtime-design`
- 검증한 상위 근거: 본선 운영세칙(SHA-256 `FFE8E6BE…`, 11쪽 전문), 공식 스켈레톤 `deploy/` 트리 34파일(`deploy/docs/agent-guide.md`, 레퍼런스 `defender.py`, `router/broker.yaml`, `backend/backend.py`)
- 미검증 자료: 본선 당일 진행 안내, 예선 보고서, 예선 소스 스냅샷 (§18)
- 목표: **뚫기 어렵되 우리가 먼저 죽지 않는** 다층 필터

---

## 0. 설계 전제

### 0.1 에이전트 자체는 공격 표면이 아니다

제11조 2항상 공격 에이전트가 도달 가능한 대상은 타 팀 진입점(`team{N}.lig.internal`), LiteLLM(:4000), flag 제출 서버(:4100)뿐이며 그 외 인터넷·노드 접근은 차단된다. 방어 에이전트는 대상 팀 라우터 안에서 Broker와 Unix socket으로만 통신한다(제13조 1항).

따라서 목표는 "복잡해서 못 뚫게"가 아니라 "정확해서 못 통과하게"다. 코드 복잡도는 방어력을 올리지 않고 우리 쪽 버그와 지연 위험만 올린다.

### 0.2 점수 산식이 요구하는 것 — 정량 분석

세칙 제17~20조의 산식은 다음과 같다.

```
라운드 점수 = ( 공격 점수 + 방어 점수 ) × SLA
공격 점수  = 3 × (탈취하여 accepted 된 타 팀 flag 수)          제18조
방어 점수  = 10 × (배치 flag 수 N − 탈취당한 고유 flag 수)      제19조, 최소 0
SLA       = 100 − 실패 카운트   (Round당 SLA check 100회)      제20조
```

제20조 3항 공식 예시: `N=2`, 타 팀 flag 3개 탈취, 자기 flag 1개 탈취당함, SLA 만점 → `(3×3 + 10×(2−1)) × 100 = 1,900`.

이 예시에서 두 손실의 크기를 비교한다.

| 사건 | 결과 | 손실 |
|---|---|---:|
| 자기 flag 1개 더 탈취당함 | `(9 + 0) × 100 = 900` | **1,000** |
| SLA 1회 실패 | `19 × 99 = 1,881` | **19** |

공식 예시에서는 **flag 1개 ≈ SLA 53회**다. 일반화하면 기본 점수 `S = 공격 + 방어`일 때 flag 1개 손실은 SLA `10 × SLA / S` 회 실패와 등가다. 공격 0점·`N=2`·무실점(`S=20`, SLA 100)이면 `1,000 / 20 = 50`이므로 손익분기는 **SLA 50회 실패**다. 공격 점수와 남은 방어 점수가 바뀌면 `S`도 바뀌므로 고정된 오탐률 하나를 전 Round에 적용하지 않는다.

이로부터 세 가지 결론이 나온다.

1. **고신뢰 rule에는 상당한 SLA 손실을 감수할 점수상 여지가 있다.** 다만 손익분기는 매 Round의 `S`와 SLA에 따라 다시 계산한다.
2. **그러나 SLA는 곱수다.** 100회 전부 실패하면 계수가 0이 되어 공격 점수까지 함께 소멸한다. blanket DROP은 여전히 자살이다.
3. 따라서 안전장치는 **"소수의 오탐을 억제"하는 방향이 아니라 "SLA 붕괴를 차단"하는 방향**으로 설계한다. 다만 §10.3처럼 신뢰 가능한 SLA 신호가 없을 때 packet-derived metric은 경보에만 쓰고 정책 변경은 Break 사람 검토로 제한한다.

### 0.3 진짜 위험은 공격자가 아니라 우리 자신

방어 점수를 날리는 3대 원인:

1. 에이전트가 **죽거나 연결이 끊김** → Broker fail-open → 전 패킷 통과 → 무방비(제13조 2항)
2. 판정이 **느림** → 300ms 초과 → Broker가 해당 패킷 DROP → 누적되면 SLA 붕괴(제13조 3항)
3. rule을 잘못 넣어 **정상 트래픽 대량 차단** → SLA 붕괴

설계의 절반은 이 셋을 막는 데 쓴다. 구현 우선순위도 여기서 나온다(§19).

레퍼런스 구현은 소켓 오류·EOF에서 프로세스를 그대로 종료한다. 그 동작을 그대로 따르면 1번 원인에 직결되므로, 본 설계는 **재연결을 필수 요소로 둔다**(§13).

### 0.4 직교 3축과 축 C 제외 확정

같은 것을 두 번 검사하는 것은 심층방어가 아니다. 서로 다른 것을 보는 축을 겹쳐야 한다.

| 축 | 무엇을 보나 | 상태 |
|---|---|---|
| **축 A — 인바운드 내용** | 요청 payload에 공격 패턴이 있나 | **채택.** 동기 `Sig` 단계 |
| **축 B — 세션 행위 누적** | 이 flow가 얼마나 비정상적으로 굴었나 | **채택.** 계산은 비동기, 조회만 동기 |
| **축 C — 아웃바운드 응답** | 나가는 데이터에 flag가 섞여 있나 | **제외 확정** |

축 C는 이론적으로 가장 강한 방어지만 **관측 자체가 불가능함이 확인되어 제외한다.**

- 제13조 1항: "라우터의 broker 데몬이 각 레이어로 **들어온** 패킷을 유닉스 소켓을 통해 방어 에이전트로 전달한다"
- `deploy/docs/agent-guide.md`: "각 레이어로 **수신된** IP 패킷을 Broker가 Unix 소켓으로 전달하면"
- `contracts/defender/README.md`: 계약된 판정 입력은 PACKET 프레임의 `raw_ip`뿐

두 상위 근거와 계약이 모두 인바운드 전용을 지시하므로, 아웃바운드 flag 필터와 이를 전제한 신호는 본선 런타임에서 사용하지 않는다. 같은 이유로 **응답 상태코드 분포 신호도 제외한다**(§9.4).

부수적으로, flag는 챌린지 컨테이너 내부 파일(`/flags/LAYER{n}_CHALL1_FLAG`)로 주입되고 형식은 `FLAG{32 hex}`다. 아웃바운드를 볼 수 없으므로 이 형식은 차단 패턴이 아니라 **로그 유출 금지 대상**으로만 취급한다(§12).

### 0.5 AI는 패킷 경로에 넣을 수 없다

300ms 시한에 원격 LLM 호출은 물리적으로 불가능하다. 레퍼런스 구현도 LLM 호출 함수를 정의만 하고 판정 경로에서 호출하지 않으며, `contracts/defender/README.md`가 이를 계약으로 못박는다.

따라서 LLM은 **별도 경로에서 redacted feature를 분석해 다음 이미지의 rule 후보를 뽑는 용도**로만 쓴다. 예선의 결정론적 판단과 AI 판단 분리 구조가 여기서 우연이 아니라 **시간 계약상 필연**이 된다. 제23조 진위 검증에서 "외부 API 사용 내역 및 호출 증빙"과 "동작 원리 설명"을 요구하므로, 호출 기록을 증빙 가능한 형태로 남기는 것이 그대로 요구사항이 된다.

---

## 1. 범위와 비범위

**범위**: Broker session과 재연결, PACKET parser, 사전 승인된 결정론적 policy, VERDICT 반환, HEARTBEAT 송신, bounded online state, verdict 이후 비동기 상관분석, 선택적 LLM advisory, 비밀 없는 structured logging, metrics, shutdown.

**비범위**: Dockerfile 확정, 공통 계약(`contracts/**`) 수정, 공식 스켈레톤 복사·수정, 원격 LLM의 packet별 동기 호출, 실제 기체 제어, RTL·Land·rollback·HITL 실행, 자동 rule 생성과 실시간 self-modification, 영속 packet 저장.

이번 브랜치에서는 실제 방어 런타임 코드를 작성하지 않는다. 아래 코드 조각은 불변조건을 설명하기 위한 예시이며 구현은 승인 후 별도 브랜치에서 테스트 우선으로 진행한다.

---

## 2. 용어 분리

| 이름 | 범위 | 의미 | 사용 제한 |
|---|---|---|---|
| `FinalsPhase` | 1~4 | 레이어가 **누적 개방**되는 경기 단계(제5조 1항) | 운영 일정 설명 전용. 런타임 환경변수로 주어지지 않음 |
| `S4ChainStage` | 1~5 | 예선 보고서 S4의 다단계 공격 체인 국면 | `FinalsPhase` 번호와 대응한다고 가정하지 않음 |
| `MissionState` | 구현 보류 | 이륙 전·순항·임무·복귀 같은 기체 상태 | parser와 fixture로 존재가 증명될 때만 사용. 현재 제외 |

### 2.1 본선 레이어 vs 내부 처리 단계

**`L1`~`L4`는 본선 네트워크 레이어 전용 표기다.** 내부 파이프라인 단계에는 `L` 표기를 쓰지 않는다.

| 표기 | 대상 |
|---|---|
| `L1`~`L4` | 본선 네트워크 레이어 (위성망 게이트웨이 / MCS / UAV / UGV) |
| `Gate` | 동기 1단계 — 구조 sanity |
| `Sig` | 동기 2단계 — payload 시그니처 매칭 |
| `Score` | 동기 3단계 — flow 위험도 조회 |
| `Corr` | 비동기 상관분석 worker |
| `Advisory` | 비동기 LLM 조언 worker |

---

## 3. 근거 추적표

| 결정 | 상위 근거 | 예선 보고서 페이지 | 관측 증거 | 동기/비동기/제외 | 실패 시 동작 | 테스트 |
|---|---|---:|---|---|---|---|
| 소켓에 에이전트가 `connect` | agent-guide, 제16조 1항 `-v <router-path>/agent.sock:/run/agent.sock` | 해당 없음 | 레퍼런스 `dial_seqpacket` | 동기 | connect 실패 시 backoff 재시도 | `test_session.py` |
| 프레임 오프셋 `>Q`@1 `>H`@9 payload@11 | 제13조 4항, agent-guide | 해당 없음 | 레퍼런스 `_parse_packet` | 동기 | 헤더 손상 시 verdict 미생성 | `test_protocol.py` |
| 300ms 내 VERDICT, 내부 soft cutoff 5ms | 제13조 3항 | 해당 없음 | Broker 왕복 측정 예정 | 동기 | cutoff 도달 시 즉시 `ACCEPT` | `test_timing.py` |
| connection/success epoch+1초 HEARTBEAT, epoch+2초 service deadline, 3초 침묵 시 fail-open | 제13조 2항, agent-guide | 해당 없음 | 레퍼런스 `heartbeat_loop` | 동기 | 절대 deadline arbitration, 만료 전 재연결 | `test_heartbeat.py` |
| 판정 입력은 `raw_ip`뿐 | `contracts/defender/README.md` | 해당 없음 | PACKET 프레임 | 동기 | 파싱 실패 시 `ACCEPT` | `test_packet.py` |
| **아웃바운드 필터 미사용** | 제13조 1항 "들어온 패킷", agent-guide "수신된 IP 패킷" | 해당 없음 | 아웃바운드 PACKET 없음 | **제외** | 미구현 | 해당 없음 |
| **응답 상태코드 신호 미사용** | 위와 동일 | 해당 없음 | 관측 불가 | **제외** | 미구현 | 해당 없음 |
| **포트 게이트는 관측 기반** | 제16조 2항 — `PORTS`는 공격 에이전트 전용 env | 해당 없음 | 방어 env는 3개뿐 | 동기 | 목록 미확정 시 관찰 전용 | `test_policy.py` |
| source IP 단독 식별 금지 | 제12조 2항 NAT 통일 | 5–6 | 진입 IP `10.{N}.0.4` 단일 | 제외 | source IP만 바꾼 fixture로 verdict 불변 | `test_policy.py` |
| 레이어 식별에 dst 3옥텟 후보 사용 | 제5조 2항 `10.{N}.{L}.0/24` | 4, 13–14 | 포워딩 전·후 여부 미확인 | 비동기 우선 | 미확인 시 profile 미부여 | `test_packet.py` |
| 원격 LLM을 동기 경로에서 배제 | `contracts/defender/README.md`, 제9조 | 13, 30–32, 48 | 레퍼런스도 호출 안 함 | 비동기 | LLM 장애가 verdict·HEARTBEAT에 무영향 | `test_advisory.py` |
| 서드파티 의존성 0개 유지 | 제16조 실행 옵션, 레퍼런스 Dockerfile | 해당 없음 | `python:3.12-slim`, `USER 65534` | 해당 없음 | 표준 라이브러리로 대체 | `test_policy.py` |
| rule·임계는 별도 policy file | Break 10분, 제15조 이미지 재생성 | 35 | 다음 이미지에 포함된 versioned JSON | 기동 시 검증·고정 | active 실패 시 검증된 fallback, 둘 다 실패 시 DROP rule 0개 | `test_policy.py` |
| 세션 행위 누적 점수(축 B) | 예선 Correlation Engine 원칙 | 15–16, 27–29 | 인바운드 요청 field parser | 비동기 계산 + 동기 조회 | state 없으면 `ACCEPT` | `test_correlation.py` |
| packet-derived anomaly 지표는 alert-only | 제17·20조 산식(§0.2), 현재 `raw_ip` 입력 계약 | 35 | organizer-guaranteed SLA·정상-health 신호 없음 | 비동기 경보 전용 | Round 중 정책 불변, Break에서 사람 검토 | `test_anomaly.py` |
| 단일 deadline-aware socket writer | 제13조 2·3항, 레퍼런스 무기한 blocking send | 해당 없음 | 동일 socket에 VERDICT·HEARTBEAT 송신 | 동기 | 200ms 내부 만료 또는 send fault 시 폐기·재연결 | `test_session.py` |
| immutable correlation snapshot publication | `raw_ip` 관측 경계와 300ms hot path | 15–16, 27–29 | 비동기 worker 산출 bounded score | 비동기 생성 + 동기 단일 read | missing·stale snapshot이면 `ACCEPT` | `test_correlation.py` |
| writer-owned timeout과 earliest-absolute-deadline 송신 | 제13조 2·3항, 레퍼런스 무기한 blocking send | 해당 없음 | 소켓 버퍼 포화·VERDICT backlog 시 fail-open 위험 | 동기 | tie에서 VERDICT 우선, deadline 불충족 시 `SocketWriter` 재연결 | `test_session.py`, `test_heartbeat.py` |
| async event queue 1,024건·drop-newest | 300ms hot path와 2GB memory reservation | 15–16, 27–29 | compact parsed event만 enqueue | 비동기 | full이면 O(1) drop, verdict 무영향 | `test_correlation.py` |
| Round 간 상태 소실 허용 | 제15조 4항 | 해당 없음 | 컨테이너 매 Round 재생성 | 해당 없음 | disk persistence 미요구 | `test_round_lifecycle.py` |
| `MissionState`(임무 단계) 제외 | `contracts/defender/README.md` 입력 경계 | 17–19 | Mission Plan·Vehicle State·Mission Phase 미관측 | **제외** | 판정 입력 미사용 | 해당 없음 |
| 파라미터 해시(Golden Profile) 제외 | 위와 동일 | 20–23 | `PARAM_SET` 메시지·파라미터 세트 미관측 | **제외** | 판정 입력 미사용 | 해당 없음 |
| 물리 상태(Shadow State) 제외 | 위와 동일 | 23–26 | 명령·센서·역학 파라미터 미관측 | **제외** | 판정 입력 미사용 | 해당 없음 |
| Deterministic-AI 이중판단 계승 | 예선 §3.3.5, 제9조 시간 계약 | 30–32 | 동기 경로 LLM 배제로 구조가 강제됨 | 동기(Det) + 비동기(AI) | AI 부재 시 규칙 단독 동작 | `test_policy.py` |
| 예선 synthetic 지표·임계값 미사용 | 예선 §4.6·§5.2 자체 명시 | 12, 37, 44–46, 48 | 8개 synthetic 데이터셋, 보정되지 않은 설계값 | **제외** | 본선 threshold·성능 주장 근거 불가 | `test_correlation.py` |

54쪽 전수 매핑은 `docs/references/preliminary-report-defender-map.md`에 있다. 페이지 번호는 물리 PDF 페이지이며 인쇄 페이지와 동일하다.

---

## 4. 런타임 흐름

```text
startup validation
  → AGENT_SOCKET connect (실패 시 bounded backoff 재시도)
  → 독립 HEARTBEAT 스케줄러와 단일 SocketWriter 기동
  → PACKET frame 수신과 header 검증
  → bounded raw IP parser
  → 사전 승인된 결정론적 policy (Gate → Sig → Score)
  → ACCEPT/DROP VERDICT를 deadline priority queue에 enqueue
  → SocketWriter가 VERDICT/HEARTBEAT를 단독 송신
  → VerdictSender enqueue/result latency 계측
  → bounded 비동기 event enqueue
  → Corr / Advisory / 로그 분석
  → 연결 끊김 시 재연결하고 위 흐름 재개
```

### 4.1 동기 경로 — 예산 분리

```text
                    [ Broker ]
                        │ 0x01 PACKET (raw_ip, 인바운드 전용)
                        ▼
┌────────────────────────────────────────────────────────┐
│  Gate   parsed field 구조 constraint       p99 25μs 이하 │
│         파싱 실패·malformed → 즉시 ACCEPT (판정 포기)    │
│         명시적 스캔 플래그 조합만 DROP 후보              │
├────────────────────────────────────────────────────────┤
│  Sig    payload 시그니처 매칭             p99 100μs 이하 │
│         versioned policy를 기동 시 검증·고정             │
├────────────────────────────────────────────────────────┤
│  Score  immutable snapshot 단일 조회       p99 25μs 이하 │
│         Gate + Sig + Score 합계           p99 150μs 이하 │
└────────────────────────────────────────────────────────┘
                        │ 0x02 VERDICT
                        ▼
        ★ soft cutoff 초과 시 즉시 ACCEPT ★

──────── 여기서부터 패킷 경로 밖 (비동기) ────────

  Corr      상관분석 worker — flow risk 갱신 → Score가 읽음
  Advisory  LLM 조언 worker — redacted feature → rule 후보 → 사람 검토
```

이 구조는 전략 D의 **지연 집행**을 제한적으로 채택한 것이다. 현재 PACKET의 verdict를 나중에 보내는 것이 아니라, 현재 PACKET은 여전히 300ms 안에 `ACCEPT`/`DROP`하고 무거운 분석 결과만 이후 packet의 bounded `Score` 조회에 반영한다. 따라서 300ms 의무를 없애지는 않지만 원격 호출·상관 계산·대규모 parsing을 hot path에서 제거한다. 첫 packet 하나로 끝나는 공격은 이 경로가 막지 못하므로 검증된 exact signature인 `Sig`가 보완한다.

### 4.2 동시성 경계

- PACKET 수신, 판정, HEARTBEAT 스케줄링, 소켓 송신, 비동기 분석의 책임을 분리한다.
- **소켓에 쓰는 주체는 `SocketWriter` 단일 스레드 하나뿐이다.** 판정 스레드와 HEARTBEAT 스케줄러는 불변 outbound item을 만들고 우선순위 큐에 `put_nowait`할 뿐 `socket.send`를 직접 호출하지 않는다. 따라서 send lock과 lock 경합 자체가 없고, 한 item당 한 번의 `SOCK_SEQPACKET` send로 message boundary를 보존한다.
- `VerdictSender`는 `VerdictDecision`을 frame으로 pack하고 `received_at_monotonic`, `broker_deadline`, `absolute_send_deadline`, sequence를 붙여 `OutboundVerdict`를 `put_nowait`하며 enqueue 성공·실패와 writer가 돌려준 `SendResult`만 계측한다. socket, send timeout, deadline 만료, priority dequeue, reconnect 판단을 소유하지 않는다.
- **`SocketWriter`만 write와 deadline을 소유한다.** writer 스레드는 남은 deadline 계산, priority dequeue, socket timeout 설정, send, `SendResult` publication과 session fault 신호만 수행하며 parsing, policy, correlation, LLM을 실행하지 않는다.
- HEARTBEAT 주기 대기는 `sleep`이 아니라 shutdown 이벤트 대기로 구현해 종료 신호에 즉시 반응한다.
- packet 경로 밖의 bounded watchdog이 helper thread 생존 여부를 500ms마다 확인한다. 죽은 worker는
  동일 객체로 재기동하고, `SocketWriter` 또는 HEARTBEAT scheduler라면 현재 session을 폐기해 새
  generation으로 재연결한다. watchdog은 packet·payload·policy를 읽지 않는다.
- shutdown과 재연결 중 중복 writer·HEARTBEAT 스레드, orphan queue, stale socket이 남지 않게 한다.

#### deadline-aware 단일 writer 상태기계

레퍼런스는 `sock.send`를 timeout 없이 호출한다. 소켓 송신 버퍼가 가득 차면 무한 대기해 VERDICT와 HEARTBEAT가 함께 멈출 수 있다. 본 설계의 writer는 다음 상태만 가진다.

| 상태 | 진입과 동작 | 다음 상태 |
|---|---|---|
| `DISCONNECTED` | session queue를 비우고 이전 session item·HEARTBEAT 시각을 폐기한다. `BrokerSession`이 bounded backoff로 새 socket을 연결하고, 성공한 연결의 `monotonic_now`를 새 `session_connected_at`으로 기록한다 | 연결 성공 시 `READY`, shutdown 시 `STOPPED` |
| `READY` | 두 message type을 하나의 절대 send deadline으로 비교한다. 정렬 key는 `(absolute_send_deadline, type_rank, sequence)`이며 `type_rank`는 VERDICT 0, HEARTBEAT 1이다. 가장 이른 절대 deadline을 먼저 보내고 deadline이 같을 때만 VERDICT를 먼저 보낸다 | item을 얻으면 `SENDING` |
| `SENDING` | writer만 socket을 사용한다. 아래 item별 남은 예산으로 timeout을 제한해 한 번 send한다 | 전체 frame 성공 시 `READY`; timeout·partial send·socket 오류·만료 시 `FAULT` |
| `FAULT` | socket을 닫고 현재 item과 같은 session의 대기 item을 폐기한다. verdict를 새 session에 재전송하지 않는다 | 즉시 `DISCONNECTED` |
| `STOPPED` | 새 item을 받지 않고 queue와 socket을 정리한다 | 종료 상태 |

outbound in-flight 상한은 **현재 `SENDING` 1건과 pending item을 합쳐 session당 256건**이다. pending priority queue는 VERDICT item과 HEARTBEAT 단일 slot을 같은 절대 deadline key로 비교하며 HEARTBEAT tick은 slot에서 coalesce한다. coalesce는 이미 pending인 HEARTBEAT의 더 이른 service deadline을 연장하지 않는다. producer는 `put_nowait`만 사용하고 물리 send를 기다리지 않는다. VERDICT enqueue 성공 후 packet 참조를 해제하고 다음 `recv`로 진행한다. enqueue 실패는 verdict를 조용히 버리는 backpressure가 아니라 session fault다. producer는 즉시 현재 session의 `recv`를 중단하고 writer/BrokerSession에 reconnect를 요청하며, writer는 같은 session의 queued item을 모두 폐기한다.

VERDICT item은 `received_at_monotonic`, `broker_deadline = received_at + 300ms`, `absolute_send_deadline = internal_send_by = received_at + 200ms`를 함께 가진다. 200ms 절대 send deadline은 Broker의 300ms 계약에서 100ms 안전 여유를 뺀 값이다.

각 성공한 socket 연결은 별도의 HEARTBEAT epoch를 만든다. 연결 직후 `last_successful_heartbeat = None`으로 시작하고 `heartbeat_epoch = session_connected_at`을 사용한다. 따라서 최초 HEARTBEAT는 `due_at = session_connected_at + 1s`, `absolute_send_deadline = service_deadline = session_connected_at + 2s`다. HEARTBEAT 전체 frame의 성공 송신이 확인된 뒤에만 `last_successful_heartbeat = send_completed_at_monotonic`으로 갱신하고, 이후 `heartbeat_epoch`를 그 성공 시각으로 바꿔 다음 due와 service deadline을 계산한다. timeout·partial send·socket 오류는 epoch를 갱신하지 않는다. reconnect는 이전 세션의 `session_connected_at`, `last_successful_heartbeat`, pending HEARTBEAT item을 모두 폐기하고 새 연결 시각으로 초기화한다. 이 2초 service deadline은 Broker의 3초 liveness threshold 전에 장애를 감지하고 재연결할 1초 여유를 둔다.

writer는 dequeue 직후와 send 직전에 item별 남은 예산을 다시 계산한다.

```text
broker_remaining = broker_deadline - monotonic_now
verdict_send_wait = min(50ms, broker_remaining - 100ms)
heartbeat_remaining = heartbeat_service_deadline - monotonic_now
heartbeat_send_wait = min(50ms, heartbeat_remaining)
```

`broker_remaining <= 100ms`, 즉 내부 200ms hard cutoff에 닿았거나 `verdict_send_wait <= 0`이면 verdict는 로컬에서 만료 처리하고 socket을 닫아 재연결한다. `heartbeat_remaining <= 0`이면 stale HEARTBEAT를 보내지 않고 같은 fail-open 재연결을 수행한다. 어느 item이든 send timeout 안에 전체 frame을 보내지 못하면 current session item을 폐기하고 재연결한다. 이미 만료된 verdict를 늦게 보내거나 새 session으로 replay하지 않는다. 정상 경로의 p99 송신 목표와 **50ms socket fault timeout은 별개**이며, 50ms는 socket 장애를 유한 시간 안에 탐지하기 위한 상한일 뿐 정상-path 예산이 아니다.

#### in-flight 상한과 backpressure

| 항목 | 규칙 |
|---|---|
| receive/decision producer | 단일 스레드, inbound queue 없음. 한 번에 packet 1건만 parse·판정·enqueue |
| producer 진행 | VERDICT enqueue 성공 후 physical send를 기다리지 않고 다음 `recv` 진행. enqueue 실패 시 같은 session 수신 중단·재연결 |
| outbound in-flight | `SENDING`과 pending VERDICT·HEARTBEAT를 합쳐 session당 최대 256건. HEARTBEAT pending은 최대 1건 |
| **deadline 기준** | 경과 시간은 큐 진입 시각이 아니라 **PACKET 수신 시각(`received_at_monotonic`)**부터 잰다. 큐 대기시간이 예산에 포함된다 |
| outbound backpressure | VERDICT queue full이면 기다리거나 verdict를 drop하지 않는다. session fault로 전환해 같은 session item을 폐기하고 재연결 |
| 비동기 경로 | 기본 용량 1,024개의 compact `CorrelationEvent` FIFO에 `put_nowait`한다. 가득 차면 들어오려는 최신 event를 O(1)로 폐기(drop-newest)하고 기존 순서를 보존한다. verdict를 지연시키지 않는다 |

#### 재연결 규칙

- 재연결은 bounded backoff로 무한 재시도한다. **재시도 포기는 곧 fail-open이다.**
- 재연결 시 producer의 현재 packet과 outbound in-flight item을 비우고, 이전 session에서 받은 `pkt_id`의 verdict를 새 session으로 보내지 않는다.
- 재연결 성공 시 새 `session_connected_at`을 monotonic clock으로 기록하고 `last_successful_heartbeat = None`으로 초기화한다. 이전 session의 HEARTBEAT timestamp, due/deadline과 pending item은 새 session에서 재사용하지 않는다.
- 새 session에서 `SocketWriter`와 HEARTBEAT scheduler가 각각 하나만 존재하게 하고 이전 session thread의 종료를 확인한다.
- 재연결 중에도 비동기 상관 state는 유지한다. Round 경계에서만 초기화된다.

---

## 5. 시간 예산과 처리량 모델

### 5.1 처리량이 예산을 결정한다

레퍼런스 구현의 메인 루프는 `recv → verdict → send`를 **한 스레드에서 직렬로** 수행한다. 본 설계는 그 구조를 그대로 사용하지 않는다. 단일 receive/decision producer가 `recv → parse → decide → enqueue`를 수행하고, 단일 `SocketWriter`가 별도 스레드에서 `dequeue → deadline guard → send`를 수행한다. producer는 enqueue 성공까지만 기다리고 physical send와 겹쳐 다음 packet을 처리한다.

```
steady-state 처리량 ≈ 1 / max(producer 처리시간, writer 정상 send 시간)
packet end-to-end latency = producer + outbound queue wait + writer send
```

`latency.send`는 writer의 `socket.send` 호출 구간이고, `latency.verdict_send_e2e`는
`received_at_monotonic`부터 전체 frame send 성공 시각까지다. Broker ACK은 인터페이스에 없으므로
후자를 에이전트가 직접 관측 가능한 물리 송신 완료 경계로 사용한다.

부하 추정:

| 요소 | 근거 | 값 |
|---|---|---|
| 공격자당 접근 제한 | 제12조 3항 | 초당 10회, 버스트 20 |
| 동시 공격 팀 수 | 제2조 3항 (12팀 기준) | 최대 11 |
| 요청당 인바운드 패킷 | TCP 핸드셰이크 + 요청 + 제어 | 약 4~6 |
| **정상 부하** | 11 × 10 × 5 | **약 550 pkt/s** |
| **버스트** | 11 × 20 × 5 | **약 1,100 pkt/s** |

SLA check는 Round 20분에 100회이므로 초당 0.1회 미만으로 부하에 유의미하지 않다. 정상 서비스 트래픽은 별도로 더해진다.

**따라서 패킷당 판정은 1ms 미만이어야 한다.** 버스트 1,100 pkt/s에 안전계수 2배를 적용하면 목표는 약 450μs다.

### 5.2 확정 예산

| 구간 | 목표 |
|---|---:|
| frame header 검증·unpack | p99 50μs 이하 |
| bounded IP/L4 parse | p99 150μs 이하 |
| policy·immutable snapshot lookup | p99 150μs 이하 |
| VERDICT pack·writer enqueue | p99 50μs 이하 |
| writer queue·정상 socket send | p99 100μs 이하 |
| **hot path 합계** | **p50 150μs 이하, p99 500μs 이하** |
| **판정 soft cutoff** | **5ms — 추가 분석을 포기하고 `ACCEPT`를 writer에 enqueue** |
| **내부 send hard cutoff** | **PACKET 수신 후 200ms — 로컬 만료·재연결** |
| **Broker deadline** | **PACKET 수신 후 300ms(제13조 3항)** |
| **socket fault timeout** | **최대 50ms — 정상 p99 예산이 아닌 장애 탐지 상한** |

- **모든 시간은 벽시계가 아니라 monotonic clock으로 측정한다.** NTP 보정 시 벽시계 기반 예산 계산이 깨진다.
- 다섯 정상-path 구성요소의 p99 상한 합은 `50+150+150+50+100=500μs`로 선언한 end-to-end p99 목표를 넘지 않는다.
- policy 150μs는 §4.1의 `Gate 25μs + Sig 100μs + Score 25μs` 전체이며 이 세 stage를 500μs 표에 다시 더하지 않는다. 구현 benchmark와 테스트 assertion은 이 decomposition과 end-to-end 500μs를 동시에 사용한다.
- `pkt_id`를 읽은 직후부터 경과를 감시하고, 5ms soft cutoff 도달 시 즉시 `ACCEPT`를 enqueue한다. 이 cutoff는 200ms 내부 send hard cutoff, 300ms Broker deadline, 50ms socket fault timeout과 서로 다른 목적의 값이다.
- parsing failure, unknown protocol, 비동기 queue full, LLM 장애를 이유로 300ms timeout DROP을 유발하지 않는다.
- 실측이 목표를 충족하지 못하면 rule 또는 parser를 hot path 밖으로 옮긴다. 문서의 숫자를 조용히 완화하지 않는다.

### 5.3 승인된 실행 모델과 확장 금지선

승인된 모델은 **단일 receive/decision producer + 단일 SocketWriter + inbound queue 없음 + outbound in-flight 최대 256건**이다. 이 차이는 HEARTBEAT와 VERDICT를 같은 socket에 안전하게 직렬화하고 각 verdict deadline을 writer 한 곳에서 집행하기 위해 reference skeleton의 serial loop에서 의도적으로 벗어난 것이다.

producer worker를 늘리거나 inbound queue를 추가하면 packet ordering, memory 상한, deadline backpressure가 달라진다. 따라서 이를 단순 최적화로 구현하지 않는다. §15.4 실측에서 필요성이 확인되면 새 설계 승인과 별도 테스트를 거친다. 현재 구현 기준에서 overload는 inbound ACCEPT queue로 흡수하지 않고, outbound cap 도달 시 session fault·reconnect로 fail-open recovery를 선택한다.

---

## 6. 기본 verdict 정책

기본 원칙은 **불확실하면 빠르게 `ACCEPT`, 고신뢰 증거가 있을 때만 `DROP`**이다. 다만 §0.2에서 보였듯 소수의 오탐 비용은 flag 손실보다 훨씬 작으므로, **조건을 충족한 고신뢰 rule의 활성화를 오탐 우려로 미루지 않는다.**

### 6.1 DROP에 필요한 조건 (전부 충족)

1. packet 구조가 성공적으로 파싱됐다.
2. rule이 참조하는 모든 field의 존재와 encoding이 fixture로 증명됐다.
3. `rule_id`, protocol scope, layer/profile scope, match reason이 결정론적이다.
4. 동일 protocol의 정상 negative fixture를 통과한다.
5. latency와 bounded state 조건을 통과한다.
6. rollback 조건과 owner가 기록돼 있다.

### 6.2 DROP 사유가 아닌 것

parser exception 또는 지원하지 않는 protocol / source IP 값만으로 내린 판단 / LLM의 의심 문장이나 confidence / 예선 synthetic Risk Score threshold 초과 / state 부재 또는 correlation queue full / HEARTBEAT·분석 worker 장애 / 새 레이어를 아직 식별하지 못한 상태.

### 6.3 header 손상 시 처리

header가 유효해 `pkt_id`를 알지만 `raw_ip`가 잘렸거나 비정상이면 `ACCEPT`와 비민감 reason code를 반환한다. header 자체가 짧아 `pkt_id`를 알 수 없으면 **존재하지 않는 ID로 verdict를 만들지 않고** session 오류로 기록한 뒤 재연결한다. 레퍼런스는 이 경우 프레임을 폐기하고 루프를 계속한다.

### 6.4 애매한 구간의 중간 대응

본선 verdict는 `ACCEPT`와 `DROP`뿐이므로 별도의 "의심" 출력은 없다. 확신은 없지만 의심스러운 packet은 기본적으로 `ACCEPT`하고 비동기 event와 `SHADOW` match를 남긴다. 부분 집행이 필요하면 무작위 packet DROP 대신 **flow/profile 단위의 결정론적 `CANARY`**만 사용한다.

- `CANARY`는 §6.1의 조건을 충족했지만 전체 profile에 적용하기 전 오탐 예산을 확인하는 rule에만 허용한다. LLM confidence나 profile 이탈 하나만으로 만들지 않는다.
- 같은 `rule_id`와 `FlowKey`는 같은 bucket에 들어가 Round 안에서 verdict가 흔들리지 않아야 한다. 선택 비율과 seed는 versioned policy file에 고정하고 Python의 process-randomized `hash()` 대신 표준 라이브러리 `hashlib.blake2s`로 bucket을 계산한다.
- canary 범위는 rule·profile·만료 시각으로 제한하고, 정상 negative 및 100회 SLA fixture 회귀를 먼저 통과한다.
- random number generator로 packet마다 DROP 여부를 다시 뽑지 않는다. 무작위 DROP은 재현성과 장애 분석을 해치고 SLA 손실 분포를 불필요하게 넓힌다.
- canary가 공격을 완전히 차단한다고 주장하지 않는다. 목적은 제한된 blast radius로 rule의 실제 충돌을 검증하는 것이다.

---

## 7. 구성요소 경계

| 구성요소 | 책임 | 실패 격리 |
|---|---|---|
| `RuntimeConfig` | 환경변수 검증과 안전한 기본값 | 기동 실패를 명시적 종료로 |
| `BrokerSession` | connect, **재연결**, 수신 lifecycle | 재연결이 HEARTBEAT를 중복 생성하지 않음 |
| `FrameCodec` | PACKET 검증, VERDICT·HEARTBEAT 직렬화 | 인코딩 오류가 session을 죽이지 않음 |
| `SocketWriter` | deadline priority queue와 socket send를 소유하는 단일 writer 스레드 | producer는 socket에 직접 쓰지 않음. timeout·만료 시 session 재연결 |
| `HeartbeatScheduler` | 약 1초 cadence와 지연 감시 | 판정 로직과 완전 분리. 무거운 작업 금지 |
| `PacketParser` | bounded IP/L4 및 증명된 application parser dispatch | 예외를 밖으로 던지지 않음 |
| `PolicyLoader` | 이미지 내 versioned policy file 검증·컴파일 | active 실패 시 fallback, 둘 다 실패 시 DROP rule 0개. HEARTBEAT와 ACCEPT 경로는 기동 |
| `HotPolicy` | 사전 승인 rule과 immutable correlation snapshot의 bounded 조회 | snapshot 부재·stale·예외 시 `ACCEPT` |
| `AnomalyMonitor` | packet-derived 지표 집계와 alert publication | runtime policy state를 변경하지 않음. Break 사람 검토 전용 |
| `VerdictSender` | verdict frame 생성, deadline metadata 부착, `put_nowait`, enqueue·`SendResult` 계측 | socket·timeout·deadline 판단 없음. enqueue 실패 시 session fault 요청 |
| `EventAdapter` | verdict 이후 관측 field를 최소 event로 변환 | 변환 실패 시 event 폐기 |
| `CorrelationBuilder` | worker 전용 mutable TTL·capacity state와 snapshot 생성 | hot path와 공유하지 않음. 용량 초과 시 eviction |
| `CorrelationSnapshotRef` | 현재 immutable snapshot 참조 하나 publication | worker만 원자적으로 교체, hot path는 lock 없이 한 번 읽음 |
| `CausalMatcher` | 관측된 key만 사용하는 비동기 chain match | 실패해도 hot path 무영향 |
| `RiskModel` | 본선 fixture로 보정된 비동기 우선순위 | 예선 합성 점수 미사용 |
| `AdvisoryWorker` | redacted feature만 사용하는 LLM 조언 | 장애·quota 소진이 verdict에 무영향 |
| `AuditLogger` | payload·secret·flag 없는 reason·latency·health 기록 | 로그 I/O가 hot path를 막지 않음 |
| `WorkerWatchdog` | helper thread 사망 감지·동일 worker 재기동 | writer/HEARTBEAT 재기동 시 새 Broker session 요청. verdict·policy 권한 없음 |
| `Metrics` | verdict count, accept/drop, parser failure, queue drop, heartbeat gap, latency 분포 | — |

한 구성요소의 예외가 HEARTBEAT 또는 이미 수신한 PACKET의 verdict를 막지 않게 한다.

---

## 8. 상태와 데이터 모델

| 타입 | 최소 필드 | 불변조건 |
|---|---|---|
| `PacketEnvelope` | `pkt_id`, `declared_len`, `raw_ip`, `received_at_monotonic` | monotonic 기준 시각 필수 |
| `ParsedPacket` | IP version, protocol, src/dst, ports, bounded payload view, parser status | payload는 복사가 아니라 상한 있는 view |
| `FlowKey` | `(src_ip, src_port, dst_ip, dst_port, protocol)` | **protocol 포함 5-tuple.** NAT source identity를 신뢰 신호로 쓰지 않음 |
| `ObservedTrafficProfile` | protocol, port, dst subnet 후보, parser version, 정상 증거 | 레이어 식별에 쓰려면 fixture 일치 선증명 |
| `RuleMatch` | `rule_id`, confidence class, evidence fields, profile scope, reason code | — |
| `VerdictDecision` | `pkt_id`, ACCEPT/DROP, `rule_id`, reason code, elapsed | elapsed는 monotonic 차이 |
| `CorrelationEvent` | redacted bounded scalar field, timestamp, flow key, event type, evidence source | compact parsed record만 허용; 원본 payload·`PacketEnvelope`·`ParsedPacket` 참조 미포함 |
| `CorrelationState` | TTL, last update, bounded counters, matched stages | per-key cap 필수 |
| `CorrelationSnapshot` | generation, published/expires monotonic, immutable `FlowKey → frozen score` map | publication 후 내부 collection과 값 변경 금지 |
| `AsyncAdvisory` | input feature IDs, recommendation, model ID, token usage, expiration | **runtime authority 없음** |
| `PolicyBundle` | schema version, bundle ID, rules, profile thresholds, review metadata | 기동 후 immutable. runtime self-modification 금지 |

### 8.1 용량 상한

| 대상 | 상한 | 초과 시 |
|---|---|---|
| flow당 재조립 버퍼 | 16KB 링버퍼 | 오래된 앞부분 폐기 |
| 전체 flow 수 | 5,000 | 신규 flow 상태추적 포기, `ACCEPT` |
| flow TTL | 120초 | 주기 스윕으로 제거 |
| outbound in-flight/session | 256 (`SENDING` 포함, HEARTBEAT pending 최대 1) | VERDICT enqueue 실패 시 같은 session 수신 중단·재연결 |
| 비동기 event queue | 기본 1,024개의 compact `CorrelationEvent` FIFO | `put_nowait` 실패 시 들어오려는 최신 event를 O(1) 폐기(drop-newest) |

컨테이너 memory reservation은 2GB, pids limit 512, cpu-shares 2048이다(제16조 1항). 20분 Round 동안 상태가 무한 증가하면 OOM이다. **Round 종료 후 상태가 사라지는 것을 정상으로 취급하고 disk persistence를 요구하지 않는다**(제15조 4항).

---

## 9. parser와 관측 증명

### 9.1 parser별 문서화 항목

protocol/version 식별 byte와 최소 길이, variable length·options·checksum·fragment·truncation 처리, 암호화 또는 unknown payload 처리, 추출 field의 byte offset 또는 decode rule, positive fixture와 정상 negative fixture, malformed fixture와 기대 `ACCEPT` fallback, parser 시간·메모리 상한, 지원하지 않는 variant에서의 동작.

**IPv4만 지원한다고 가정하지 않는다.** 레퍼런스는 `(pkt[0] >> 4) != 4`이면 판정을 포기하고 `ACCEPT`한다. 같은 fallback을 유지하되 IPv6 관측 여부를 기록한다.

### 9.2 Gate 단계 — 오탐이 나면 안 되는 것만

**malformed는 DROP 사유가 아니다.** Gate는 구조를 검사하되 판정 실패를 차단으로 바꾸지 않는다. §6.2·§13·§15.3과 동일한 단일 정책이며, 구현자가 다르게 해석할 여지를 남기지 않는다.

| Gate 판정 대상 | verdict |
|---|---|
| IP header sanity 실패 (version, IHL, 총길이 불일치) | **`ACCEPT`** + reason code |
| `pkt_len`과 실제 payload 길이 불일치, trailing bytes | **`ACCEPT`** + reason code |
| fragmentation, truncation, unknown protocol, unsupported version | **`ACCEPT`** + reason code |
| parser 예외 | **`ACCEPT`** + 예외 metric |
| 명시적 스캔 플래그 조합 (TCP NULL/FIN/Xmas) | `DROP` 후보 — §6.1의 6조건을 충족하고 정상 negative fixture를 통과한 뒤에만 활성화 |

Gate에서 `DROP`이 가능한 유일한 범주는 마지막 행이다. 이는 구조 오류가 아니라 **정상 트래픽에 나타나지 않음이 fixture로 증명된 플래그 조합**이기 때문이며, 그 전까지는 관찰 전용이다. 비정상적으로 큰 패킷도 그 자체로는 차단하지 않고 bounded parse 대상에서 제외한 뒤 `ACCEPT`한다.

**포트 게이트는 관측으로만 구성한다.** 제16조 2항상 `PORTS`는 공격 에이전트에만 주입되며 방어 에이전트 env는 `AGENT_SOCKET`, `LLM_BASE_URL`, `LLM_API_KEY` 셋뿐이다. 열려 있어야 할 포트 목록을 런타임이 알 수 없으므로, `FinalsPhase 1`에서 정상 트래픽을 관측해 포트 인벤토리를 만들고 그 근거가 확보된 뒤에만 게이트를 활성화한다. 오리엔테이션에서 목록이 공지되면 그것을 상위 근거로 삼는다.

### 9.3 Sig 단계 — 시그니처 매칭

레퍼런스는 목적지 포트별 정규식 목록을 순회하며 **패킷 단위 payload**만 검사한다. 스트림 재조립이 없으므로 요청이 여러 패킷에 걸치면 탐지되지 않는다.

본 설계는 flow별 재조립 버퍼를 두어 이 한계를 보완하되, 다음 제약을 지킨다.

- **서드파티 의존성을 추가하지 않는다.** 레퍼런스 이미지는 `python:3.12-slim`에 `USER 65534`로 실행되며 설치 패키지가 없다. Aho-Corasick 같은 외부 다중패턴 라이브러리는 이미지 검증 부담과 Docker 담당자 승인 절차를 발생시키므로 사용하지 않는다.
- 대신 **카테고리별로 결합한 단일 정규식을 미리 컴파일**해 순회 횟수를 최소화한다. 정규식 수십 개를 패킷마다 순차 실행하면 §5.2 예산을 지킬 수 없다.
- 매칭 대상은 상한 있는 payload view로 제한한다.
- catastrophic backtracking을 유발하는 패턴을 금지하고, 각 패턴에 대해 최악 입력 실행시간을 측정한다.

시그니처 카테고리 후보:

```text
경로 탐색      ../  ..%2f  %2e%2e  ....//
SQL 인젝션      ' OR   UNION SELECT   ; DROP   sleep(   benchmark(
명령 주입      ; ls   | cat   $(   `   && curl   nc -e
템플릿 인젝션   {{   ${   <%=
역직렬화       언어별 매직 바이트
파일 읽기      /etc/passwd  /proc/self  file://
경로 특이성    /flags  /flag  .git/  .env  backup
```

이 목록은 **가설이다.** 각 항목은 parser가 field를 실제로 추출할 수 있음이 fixture로 증명되고 정상 negative fixture를 통과한 뒤에만 `DROP` rule이 된다. 그 전까지는 관찰 전용이다. flag가 `/flags/LAYER{n}_CHALL1_FLAG` 파일로 주입되는 점을 고려해 경로 특이성 패턴을 우선 검증한다.

### 9.4 Score 단계 — NAT 대응 세션 행위 (축 B)

진입 IP `10.{N}.0.4`를 통해 NAT되므로 소스 IP가 통일되어 공격자 식별이 불가능하다(제12조 2항). 행위 특징으로 판단한다.

| 신호 | 필요한 관측 | 상태 |
|---|---|---|
| 짧은 시간에 서로 다른 경로·엔드포인트 다수 시도 | 인바운드 요청 경로 parser | 채택 후보 |
| 요청 간격이 기계적으로 균일 | 인바운드 도착 시각 | 채택 후보 |
| 인코딩 중첩 (`%252e` 등) | 인바운드 payload | 채택 후보 |
| 비정상적으로 긴 URI·헤더 | 인바운드 payload | 채택 후보 |
| `Sig`에 걸린 이력이 있는 flow | 내부 상태 | 채택 후보 |
| 응답 상태코드 분포 | 아웃바운드 응답 | **제외 확정 (§0.4)** |

제12조 3항의 공격자당 초당 10회(버스트 20) 제한은 **운영진이 이미 거는 상한**이므로, 이보다 낮은 임계로 rate 기반 차단을 걸면 정상 트래픽을 먼저 때린다. 임계는 반드시 관측된 정상 baseline 위에서 정한다.

**Score는 조회만 한다.** 점수 계산은 비동기 `Corr`가 하고, 패킷 경로에서는 bounded lookup 1회만 수행한다.

---

## 10. 동기 정책과 SLA 보호

### 10.1 rule 우선순위

1. frame 또는 parser failure → 빠른 `ACCEPT`
2. 검증된 정상 traffic → `ACCEPT`
3. 고신뢰 exact signature 또는 사전 승인된 multi-signal rule → `DROP`
4. 애매한 anomaly, 비동기 분석 필요 → `ACCEPT` + async event
5. rule conflict → SLA를 보존하는 `ACCEPT` + conflict metric

`FinalsPhase` 또는 포트 전체를 blanket `DROP`하는 rule을 금지한다. 서비스 정상성을 검사하지 않은 allowlist/denylist를 도입하지 않는다.

### 10.2 DROP rule마다 필요한 기록

immutable `rule_id`와 설명, source PCAP/log 논리 ID와 관측 시각, protocol·field parser version, 적용 profile·레이어 범위, 공격 positive fixture, 정상 negative와 SLA fixture, 기대 verdict와 reason code, 활성화 근거와 만료, rollback 조건과 직전 안전 버전, 방어 담당자와 팀장 review 상태.

rule과 운영 임계값을 Python 분기문에 하드코딩하지 않는다. 다음 항목을 **이미지에 포함된 별도 versioned policy file**로 관리한다.

```text
schema_version, bundle_id, generated_at
rules[]:
  rule_id, parser_version, profile_scope, match specification
  promotion_state(SHADOW/CANARY/ACTIVE), canary_fraction, canary_seed
  promotion_cohort, promoted_in_bundle
  evidence_id, positive_fixture_id, negative_fixture_id, sla_fixture_id
  expires_at, rollback_condition, owner_review, lead_review
alert_profiles[]:
  profile_id, minimum_samples, sustain_window
  alert_thresholds, reviewer_runbook
```

- 구현 형식은 Python 3.12 표준 라이브러리 `json`으로 읽는 JSON으로 고정한다. host volume이나 runtime 다운로드에 의존하지 않고 이미지 build context에 포함한다.
- startup에서 schema version, 필수 field, 중복 `rule_id`, parser/profile 참조, 만료, 승격 상태, canary 범위, 정규식 크기·금지 패턴을 검증하고 정규식을 미리 컴파일한다.
- `active.json` 검증에 실패하면 이미지에 함께 넣은 직전 검증본 `fallback.json`을 검증해 사용한다. 둘 다 유효하지 않을 때만 **DROP rule 0개**로 시작해 HEARTBEAT와 `ACCEPT` 경로를 유지한다. 오류와 선택된 bundle ID는 비민감 reason code로 기록한다.
- 실행 중 파일 변경, LLM 출력의 자동 병합, self-modification을 금지한다. Break에서 사람이 파일과 fixture를 수정·검토하고 새 이미지를 build/push해야 다음 Round에 반영된다.
- `owner_review`와 `lead_review`가 모두 승인 상태가 아닌 `ACTIVE` rule은 기동 시 `SHADOW`로 강등한다.

### 10.3 자멸 방지 안전장치와 alert-only anomaly monitor

**① Deadline Guard** — §5.2. `pkt_id` 확보 직후부터 monotonic 경과를 감시하고 soft cutoff 5ms 초과 시 판단을 포기하고 `ACCEPT`.

**② Never-Die Wrapper** — 모든 패킷 처리를 예외 포착으로 감싸고 예외 시 `ACCEPT`. 별도 HEARTBEAT scheduler는 약 1초마다 frame을 enqueue하고 실제 송신은 단일 `SocketWriter`만 수행하므로 판정 로직과 cadence 책임이 분리된다. 3초간 HEARTBEAT가 없으면 Broker가 연결을 끊고 사망 판정하여 **전 패킷이 통과한다(fail-open)**. 소켓 오류·EOF에서 프로세스를 종료하지 않고 **bounded backoff로 재연결한다** — 레퍼런스와 의도적으로 다른 지점이다.

**③ alert-only anomaly monitor**

Broker 입력에는 organizer가 보증한 SLA checker 식별자, application 성공 결과, 정상-health 신호가 없다. 따라서 `raw_ip`와 verdict에서 계산한 지표는 공격자가 오염할 수 있는 관측값이지 실제 SLA의 ground truth가 아니다. **organizer가 신뢰 가능한 SLA 또는 정상-health 신호를 별도 계약으로 제공하기 전까지 모든 packet-derived baseline 지표는 metric·경보·Break 분석에만 사용하며 runtime policy state를 바꾸지 않는다.**

| 신호 | 정의 | 공격자 영향 | 허용 용도 |
|---|---|---|---|
| `raw_drop_rate` | 전체 packet 중 DROP 비율 | **높음** — 활성 signature 자극으로 상승 가능 | 경보·사후 분석만 |
| `baseline_violation_rate` | 정상 profile과 일치한다고 분류된 packet 중 DROP 비율 | **중간 이상** — 정상 형태 replay·profile 경계 탐색 가능 | 경보·Break review 후보만 |
| `parser_failure_rate` | parsing을 포기한 packet 비율 | **높음** — malformed 입력으로 상승 가능 | parser health 경보만. verdict는 `ACCEPT` |
| `rule_concentration` | 단일 `rule_id`에 DROP이 집중된 정도 | **높음** — 특정 rule을 반복 자극 가능 | 공격 집중 또는 rule 결함 조사 경보만 |
| `promotion_cohort_conflict` | 최근 이미지에서 승격한 rule과 baseline profile의 충돌 비율 | **중간 이상** — baseline 자체가 packet-derived | 경보·Break review 후보만 |

Round 중 허용되는 동작은 카운터 갱신, bounded structured log, alert 발행뿐이다. `SHADOW`·`CANARY`·`ACTIVE` 상태, canary 비율, rule scope, threshold, PolicyBundle은 어떤 packet-derived 임계 초과로도 변경하지 않는다. 전체 관찰 모드 전환, 범위 제한 rollback, 자동 재활성화 역시 금지한다.

상태 변경은 **Break에서만** 다음 순서로 사람이 수행한다.

```text
alert 확인
  → 방어 담당자가 비민감 로그, 공식 SLA 결과, 정상·공격 fixture를 대조
  → rollback 또는 승격 후보와 새 PolicyBundle diff 작성
  → 정상 negative·100회 SLA fixture·latency 회귀 실행
  → 방어 담당자와 팀장 이경준 승인
  → Docker 담당자가 다음 Round 이미지 build/push
```

organizer-guaranteed health signal이 추후 제공되더라도 parser·fixture·신뢰 경계를 별도 설계 변경으로 승인하기 전에는 자동화하지 않는다. 현재 이미지에서 지표 상승은 `rule_id`, profile, bundle ID, 표본 수, 관측률과 reason code를 남길 뿐 effective verdict 정책을 바꾸지 않는다. 정상 profile이 없는 `FinalsPhase 1` 초반과 새 레이어 첫 Round에는 DROP rule을 활성화하지 않는다(§16.2).

### 10.4 rule 승격 단계

```text
SHADOW (로그만) → CANARY (제한 범위만 차단) → ACTIVE (전면 차단)
```

신규 rule은 `SHADOW`로 투입해 정상 트래픽 충돌 여부를 확인한 뒤 승격한다. 다만 §0.2에 따라 **고신뢰 rule을 여러 Round에 걸쳐 SHADOW에 묶어두는 것은 손해**이므로, 정상 negative fixture를 통과하고 한 Round 관찰에서 충돌이 없으면 즉시 승격한다. LLM이 제안한 rule은 예외 없이 `SHADOW`부터 시작한다. 승격은 사람이 판단하며 런타임이 자동으로 수행하지 않는다.

`CANARY`의 제한 범위는 무작위 packet이 아니라 `hashlib.blake2s(rule_id + FlowKey + canary_seed)`의 결정론적 bucket, 명시된 profile, 만료 시각으로 정의한다. 같은 flow의 packet을 매번 다시 추첨하지 않는다. canary 비율 변경, `ACTIVE` 승격, `SHADOW` rollback은 모두 Break에서 policy file 변경, fixture 회귀, 방어 담당자와 팀장 review를 거쳐 다음 이미지에 포함한다. 런타임은 어떤 방향의 promotion state 변경도 수행하지 않는다.

---

## 11. 온라인 비동기 상관분석

예선 Correlation Engine을 verdict 이후 경로로 재설계한다.

- 현재 packet의 verdict를 기다리게 하지 않는다.
- async event queue의 기본 용량은 **compact parsed `CorrelationEvent` 1,024건**인 고정 길이 FIFO다. producer는 `put_nowait`만 사용하고 full이면 **들어오려는 최신 event를 O(1)로 폐기(drop-newest)**하여 기존 event의 순서와 비용을 보존한다. scan, priority 재정렬, 오래된 item 탐색을 금지하며 hot path는 queue 공간을 기다리지 않는다.
- 단일 correlation worker만 mutable builder를 소유한다. builder state는 `monotonic timestamp + TTL + max keys + per-key cap`으로 제한하며 hot path에 노출하지 않는다.
- out-of-order, duplicate, late event 처리 규칙을 정한다.
- `session_id`, `vehicle_id`, `MissionState`는 실제 parser가 생성한 경우에만 correlation key로 쓴다. 현재는 어느 것도 증명되지 않아 사용하지 않는다.
- `S4ChainStage` matcher는 관측된 event와 key만 사용하며 예선 보고서의 합성 점수를 복사하지 않는다.
- **상관분석 결과는 현재 packet을 소급 차단할 수 없다.**
- worker는 batch 또는 publication tick마다 mutable builder에서 `CorrelationSnapshot(generation, published_at_monotonic, expires_at_monotonic, frozen_entries)`를 새로 만든다. builder에서 새 private `dict`로 복사하고 그 alias를 남기지 않은 채 `types.MappingProxyType`으로 감싸며, entry는 `@dataclass(frozen=True)`와 tuple만 가진다. publication 후 snapshot 내부를 수정하는 경로가 없다.
- publication은 `current_snapshot = next_snapshot`이라는 **참조 하나의 원자적 교체**로 끝낸다. Python 3.12 CPython의 GIL 아래 reference assignment를 publication primitive로 사용하고, publisher는 단일 worker로 제한한다. writer queue·socket writer lock과 correlation publication을 공유하지 않는다.
- 이후 packet의 `Score`는 함수 시작에서 `snapshot = current_snapshot`을 **정확히 한 번** 지역 변수로 읽고, 그 세대 안에서 최대 한 번의 `FlowKey` dictionary lookup만 수행한다. 처리 중 global reference를 다시 읽거나 mutable builder를 참조하거나 lock을 획득하지 않는다.
- snapshot이 `None`, `monotonic_now >= expires_at_monotonic`, key 미존재, generation 오류이면 `Score`는 즉시 `ACCEPT`한다. stale snapshot의 점수를 이전 값으로 계속 사용하지 않는다.
- snapshot score가 있어도 해당 lookup과 DROP 조건은 bounded이며 사전 승인된 rule에만 연결한다.
- online state만으로 새 실행 가능한 rule을 생성하지 않는다.

"개별 요청은 정상 같지만 누적하면 공격"이라는 예선 논지는 유효하고 anchor + 누적 점수 구조도 재사용 가능하다. 다만 **판정 시점이 예선의 배치 처리에서 본선의 verdict 이후 경로로 바뀐다.**

---

## 12. LLM 사용 경계

LLM은 선택적 비동기 조언자다. 환경변수는 `LLM_BASE_URL`과 `LLM_API_KEY`이며 대회 LiteLLM Proxy만 접근 가능하다(제9조). 호출은 `POST {LLM_BASE_URL}/v1/chat/completions`, Bearer 인증이고, 서버 호스팅 tools(`web_search`·`code_interpreter`·`file_search`·`mcp`)는 차단된다.

- 원격 LLM 호출을 packet별 동기 verdict 경로에 넣지 않는다.
- LLM timeout, quota 소진, invalid response, proxy 장애가 HEARTBEAT·verdict에 영향을 주지 않는다.
- raw packet payload, secret, token, **flag**, 전체 PCAP, 인증 header를 prompt에 보내지 않는다.
- parser가 만든 redacted feature, aggregate metric, `rule_id`, 비민감 reason만 입력 후보로 쓴다.
- LLM 출력은 현재 또는 이후 packet을 직접 `ACCEPT`/`DROP`하지 않는다.
- LLM이 작성한 signature나 코드를 실행 중 이미지에 자동 반영하지 않는다.
- 조언은 사람이 공식 PCAP·정상 fixture와 대조해 **다음 Round policy file의 `SHADOW` 후보로만** 사용한다. raw PCAP, 전체 payload, flag, credential은 prompt에 직접 넣지 않고 redacted evidence와 논리 ID만 전달한다.

### 12.1 model 선택과 증빙

제22조상 최종 점수 동점 시 **LLM token 비용 총합이 적은 팀이 우선**하므로 비동기 조언에도 예산을 관리한다. 전체 트래픽을 넣지 않고 의심 세션 상위 K개만 요약해 보낸다.

기본 모델은 팀별 쿼터가 가장 넉넉한 `gpt-4o-mini`(팀별 6.5M TPM / 65K RPM)로 한다. `gpt-4.1-mini`는 TPM이 11.5M로 더 크지만 RPM이 11.5K로 작으므로, 호출 빈도가 높은 용도에는 부적합하다. 실제 목록과 쿼터는 본선 당일 증감될 수 있으므로 오리엔테이션 공지를 우선한다.

제23조 진위 검증에 대비해 model ID, 호출 수, token 사용량, 실패율을 **비민감 형태로 상시 기록**한다. 세칙은 "외부 API 사용 내역 및 호출 증빙"과 "에이전트의 동작 원리 및 소스코드 설명"을 요구하며, 정당한 사유 없이 거부할 수 없다.

---

## 13. 오류 처리와 복구

| 오류 | hot-path verdict | 조치 |
|---|---|---|
| `AGENT_SOCKET` 누락·경로 없음·permission denied | 해당 없음 | 기동 실패를 명시적으로 종료 |
| connect 실패, Broker 미준비 startup race | 해당 없음 | **bounded backoff 재시도.** 종료하지 않음 |
| Broker orderly close, socket reset, EOF | 해당 없음 | **재연결.** 이전 session의 verdict를 새 session에 보내지 않음 |
| unknown message type | 해당 없음 | 프레임 폐기, metric 기록, 루프 계속 |
| PACKET short header(`type=0x01`, 총 길이 `<11`) | `pkt_id`를 알 수 없어 verdict 생성 안 함 | protocol desync로 간주해 socket close·재연결. 존재하지 않는 ID를 만들지 않으며 disconnect 동안 Broker fail-open에 맡김 |
| `pkt_len`과 실제 길이 불일치 | `ACCEPT` | reason code 기록 |
| duplicate·out-of-order `pkt_id` | 최초 verdict 유지 | metric 기록 |
| raw IP malformed·fragmented·unknown version | `ACCEPT` | bounded fallback |
| parser·policy 예외 | `ACCEPT` | 예외 metric, 로그 |
| send failure·partial send | 해당 없음 | 재연결, latency metric |
| HEARTBEAT 지연·스레드 사망 | 해당 없음 | 스레드 재기동. 3초 접근 전 경보 |
| 비동기 queue overflow, worker crash | 영향 없음 | event 폐기, worker 재기동 |
| state capacity 초과, clock 불연속 | 영향 없음 | eviction, monotonic 사용으로 불연속 회피 |
| LLM timeout·429·invalid JSON·quota 소진 | 영향 없음 | advisory 비활성화 |
| SIGTERM·SIGINT, Round 종료 | 해당 없음 | 종료 이벤트 설정 → 스레드 join → 소켓 정리 |

재시도에는 bounded backoff와 shutdown interrupt를 둔다. **재연결 실패가 곧 fail-open이므로 재시도를 포기하지 않는다.**

short-header 정책은 하나로 고정한다. `SOCK_SEQPACKET`에서 `0x01` PACKET frame이 11-byte header보다 짧으면 같은 session의 다음 frame으로 이어 붙이지 않고 즉시 session fault로 처리한다. 반대로 11-byte header가 완전해 `pkt_id`를 얻었지만 `pkt_len`과 payload가 맞지 않으면 현재 표의 length-mismatch 정책대로 그 ID에 `ACCEPT`를 보낸다.

---

## 14. 향후 파일 구조

실제 파일은 승인 후 구현 브랜치에서 만든다. **서드파티 의존성 없이 표준 라이브러리만 사용한다.**

```text
agents/defender/
├── policy/
│   ├── active.json        다음 이미지에 고정할 versioned PolicyBundle
│   ├── fallback.json      직전 Round의 검증된 PolicyBundle
│   └── README.md          field 의미, review·승격·rollback 절차
├── src/aegis_defender/
│   ├── __init__.py
│   ├── main.py            entrypoint와 lifecycle
│   ├── config.py          RuntimeConfig
│   ├── protocol.py        FrameCodec, 미리 컴파일된 struct
│   ├── session.py         BrokerSession(재연결), SocketWriter
│   ├── heartbeat.py       HeartbeatScheduler
│   ├── packet.py          PacketParser
│   ├── policy.py          HotPolicy (Gate·Sig·Score)
│   ├── anomaly.py         alert-only AnomalyMonitor
│   ├── rules.py           PolicyLoader, schema 검증, matcher 사전 컴파일
│   ├── state.py           FlowTable, CorrelationBuilder, CorrelationSnapshotRef
│   ├── events.py          EventAdapter, bounded queue
│   ├── correlation/
│   │   ├── __init__.py
│   │   ├── window.py      시간 윈도우
│   │   ├── causal.py      CausalMatcher (S4ChainStage)
│   │   └── risk.py        RiskModel
│   ├── advisory.py        AdvisoryWorker
│   ├── logging.py         AuditLogger
│   └── metrics.py         Metrics
└── tests/
    ├── test_protocol.py
    ├── test_session.py
    ├── test_heartbeat.py
    ├── test_packet.py
    ├── test_policy.py
    ├── test_anomaly.py
    ├── test_policy_audit.py
    ├── test_state.py
    ├── test_correlation.py
    ├── test_advisory.py
    ├── test_timing.py
    └── test_round_lifecycle.py
```

파일 수를 늘리는 것이 목표가 아니다. 책임이 겹치면 합치고, HEARTBEAT·verdict·비동기 분석의 failure domain이 섞이면 분리한다. 실제 dependency와 entrypoint는 Docker 담당자와 검토하되 **Dockerfile은 방어 담당자가 단독 확정하지 않는다.**

---

## 15. 테스트 전략과 승인 기준

테스트를 코드보다 먼저 작성한다.

### 15.1 Broker protocol

PACKET fixture에서 type, `pkt_id`, `pkt_len`, `raw_ip`를 big-endian으로 정확히 해석 / `ACCEPT`·`DROP` VERDICT byte 일치 / HEARTBEAT가 정확히 1 byte `0x05` / unknown type과 trailing bytes 처리 / `SOCK_SEQPACKET` message boundary 보존 / `recv` 버퍼가 `1+8+2+65535`를 수용. `type=0x01`이지만 11 byte보다 짧은 frame은 verdict를 만들지 않고 socket close·재연결하며, 완전한 header 뒤 length mismatch는 해당 `pkt_id`에 `ACCEPT`를 보낸다.

### 15.2 HEARTBEAT와 session

정상 부하와 비동기 부하에서 cadence 약 1초 유지 / gap이 3초에 접근하기 전 metric·failure handling 작동 / connect race, disconnect, **재연결 후 정상 판정 재개** / 반복 reconnect 중에도 active `SocketWriter`·correlation worker·HEARTBEAT scheduler가 각각 정확히 하나이고 이전 writer가 socket을 보유하지 않음 / SIGTERM에서 2초 내 정리 종료.

### 15.3 parser와 policy

IPv4·관측된 protocol positive fixture / 정상 traffic negative fixture / truncated·fragment·unknown protocol·unsupported version에서 빠른 `ACCEPT` / **NAT source IP만 바뀌어도 verdict가 달라지지 않음** / 각 DROP rule의 positive·negative·boundary fixture / rule conflict에서 `ACCEPT`와 metric / 정규식 최악 입력에서 backtracking 폭발 없음.

PolicyBundle 검증: 지원하지 않는 schema version / 중복 `rule_id` / 존재하지 않는 parser·profile 참조 / 잘못된 승격 상태·canary 비율 / 누락되거나 모순된 promotion cohort / 만료된 rule / review 미승인 ACTIVE / 과도한 정규식과 금지 패턴. `active.json`이 유효하지 않으면 검증된 `fallback.json`을 선택하고, 둘 다 유효하지 않을 때만 DROP rule 0개로 기동하며 HEARTBEAT·ACCEPT 경로는 정상이어야 한다. `hashlib.blake2s(rule_id + FlowKey + canary_seed)`는 프로세스를 재시작해도 같은 bucket을 선택하고 packet별 random DROP을 사용하지 않는다. packet-derived metric 변화로 PolicyBundle이나 effective promotion state가 바뀌지 않는다.

### 15.4 timing과 load

monotonic timing 사용 / **1, 100, 550, 1100 packet/s 부하 프로파일 측정**(§5.1 추정 부하 기준) / hot path p50·p95·p99·max 기록 / **목표: p50 150μs 이하, p99 500μs 이하, 300ms 초과 verdict 0건** / `Gate 25 + Sig 100 + Score 25 = policy 150μs`, 전체 `50+150+150+50+100=500μs`를 같은 benchmark에서 검증 / 큐가 가득 차거나 LLM이 30초 멈춰도 latency 기준 유지 / 1100 pkt/s에서 처리 지연이 누적되지 않음.

fake clock·fake socket 기반 송신 모델 검증(§4.2):

- HEARTBEAT service deadline이 두 VERDICT absolute send deadline 사이에 오도록 enqueue하면 **이른 VERDICT → HEARTBEAT → 늦은 VERDICT** 순서로 전송되어 type-first priority가 없다
- HEARTBEAT와 VERDICT의 absolute send deadline이 같으면 tie-break로 VERDICT가 먼저 나가며, 단일 writer만 fake socket에 써 frame byte가 섞이지 않는다
- fake clock의 최초 연결 시각을 `t=0`으로 두면 `last_successful_heartbeat=None`이어도 최초 HEARTBEAT due는 `t=1s`, service deadline은 `t=2s`이고 그 전에는 송신 성공 시각을 가장하지 않는다
- 최초 HEARTBEAT 전부터 verdict backlog를 계속 nonempty로 유지해도 connection epoch 기준 최초 HEARTBEAT는 `t=2s` 전에 전송되고, 만료되지 않은 verdict는 모두 packet receipt 후 300ms 안에 전송된다
- fake clock에서 이전 session HEARTBEAT가 `t=0.75s`에 성공한 뒤 reconnect가 `t=10s`에 완료되면 새 due/deadline은 `t=11s`/`t=12s`이며, 이전 `0.75s` timestamp와 pending HEARTBEAT item은 폐기되어 재사용되지 않는다
- fake clock에서 verdict queue를 지속적으로 nonempty로 유지해도 HEARTBEAT는 마지막 성공 후 2초 service deadline 전에 전송되고, 만료되지 않은 모든 VERDICT는 packet receipt 후 300ms 안에 전송된다
- fake socket send를 block시키면 VERDICT timeout은 `min(50ms, broker_remaining-100ms)`, HEARTBEAT timeout은 `min(50ms, heartbeat_service_deadline-now)`이며, 어느 쪽이든 timeout 뒤 socket close·queue 폐기·재연결이 일어난다
- fake clock을 200ms internal hard cutoff까지 전진시키면 해당 verdict는 로컬 폐기되고 새 session에 재전송되지 않는다. 300ms Broker deadline과 50ms fault timeout은 서로 다른 metric으로 기록된다
- 경과 시간이 **큐 진입 시각이 아니라 PACKET 수신 시각 기준**으로 계산되고, 5ms soft cutoff에서는 판단을 멈춰 `ACCEPT`를 enqueue한다
- `BrokenPipe`, `ConnectionReset`, partial send에서 같은 session의 item을 폐기하고 재연결한다
- HEARTBEAT 또는 VERDICT의 absolute send deadline을 넘기면 stale frame을 송신하지 않고 session-unhealthy metric, queue 폐기, 재연결이 발생하며 이전 session verdict를 replay하지 않는다
- fake writer를 `SENDING`에 멈춘 채 producer가 outbound in-flight 256건까지 채우면 성공한 enqueue마다 다음 `recv`로 진행하지만 257번째 `put_nowait`은 즉시 실패하고 추가 `recv` 없이 session fault·queue 폐기·reconnect한다
- fake socket write 호출자는 항상 하나의 `SocketWriter`뿐이고 `VerdictSender`는 frame·metadata enqueue와 `SendResult` 계측 외 socket·timeout API를 호출하지 않는다

측정 환경이 공식 컨테이너와 다르면 환경 차이를 기록한다. **성능을 측정하지 않고 예상치만 적지 않는다.** §5.3의 producer 추가 또는 inbound queue가 필요하다는 결과가 나오면 구현하지 않고 새 설계 승인 대상으로 보고한다.

### 15.5 bounded state와 상관분석

TTL expiry, max key eviction, per-key cap / duplicate·late·out-of-order event / `S4ChainStage`가 `FinalsPhase`와 섞이지 않음 / 관측되지 않은 `session_id`·`vehicle_id`·`MissionState`를 요구하지 않음 / 예선 합성 score를 threshold로 사용하지 않음 / 20분 연속 부하에서 메모리 상한 유지.

- 기본 용량 1,024의 async queue를 정확히 1,024개의 compact event로 채운 뒤 하나를 더 넣으면 새 event만 O(1)로 drop되고 length는 1,024, 기존 FIFO 순서, verdict latency, writer queue가 변하지 않는다
- 포화 queue에 반복해서 event를 넣어도 queue가 1,024건을 넘지 않고 dropped-newest counter만 결정론적으로 증가하며, event가 원본 payload나 packet 객체를 참조하지 않아 queue 보유 메모리가 capacity와 record 상한으로 제한된다
- correlation worker가 fake clock으로 snapshot을 연속 publish하는 동안 hot path가 반복 조회해도 각 read는 한 generation의 완전한 frozen 값만 보며 builder의 부분 갱신을 보지 않는다
- snapshot reference read에서 socket writer lock 또는 publication lock을 획득하지 않으며, `None`, stale, key miss는 모두 즉시 `ACCEPT`한다

### 15.6 SLA와 FinalsPhase 회귀

각 관측 profile의 정상 요청이 `ACCEPT`되고 application response가 유지됨 / **각 새 DROP rule마다 100회 SLA pattern 성격의 정상 fixture 회귀** / `FinalsPhase N` fixture set이 `L1`~`LN`을 모두 포함 / `FinalsPhase 4`에서 `L1`~`L4` 정상 회귀와 rule 회귀 모두 실행 / **UAV fixture에 맞춘 rule이 근거 없이 UGV fixture에 적용되지 않음** / 새 rule 활성화 전후 false positive count와 rollback 조건 기록.

packet-derived anomaly 조작 저항 검증(§10.3) — **가장 중요한 회귀 테스트다**:

- 공격 signature에 일치하면서 정상 profile 형태를 흉내 내는 poisoned traffic을 고율 주입해 `raw_drop_rate`, `baseline_violation_rate`, `rule_concentration`, `promotion_cohort_conflict`를 모두 임계 이상으로 올린다
- 지표별 경보와 구조화 metric은 기록되지만 같은 Round의 PolicyBundle, `SHADOW`·`CANARY`·`ACTIVE`, canary 비율, rule scope, verdict 결과는 전혀 바뀌지 않는다
- 일시적 spike, 최소 표본 충족, 장시간 지속, 여러 지표 동시 상승 어느 경우에도 runtime rollback·승격·전체 관찰 모드 전환이 없다
- rollback은 fake runtime API로 호출할 수 없고, Break에서 사람이 새 bundle을 승인해 다음 image를 기동한 경우에만 상태가 달라진다
- 정상 profile이 비어 있는 상태에서는 `DROP` rule이 활성화되지 않는다

### 15.7 비동기·로그·보안

LLM disabled·timeout·429·malformed response에서 verdict와 HEARTBEAT 정상 / LLM 출력이 policy를 직접 변경하지 않음 / token·API key·raw payload·**`FLAG{...}` 문자열**·credential이 로그와 prompt에 없음 / queue drop, parser failure, rule match, latency가 비민감 reason code로 관측 가능 / PCAP·로그·cache·생성 결과가 Git에 추가되지 않음.

### 15.8 공식 스켈레톤 통합

`scripts/validate-skeleton.ps1` 통과 / 공식 Broker에 연결해 HEARTBEAT·PACKET·VERDICT 왕복 검증 / 에이전트 미기동·kill 시 Broker fail-open 관측 / 300ms 초과 시 Broker DROP 관측 / Round 재시작을 모사해 in-memory state 초기화 확인 / **스켈레톤 파일을 수정하지 않고** Compose override 또는 Docker 담당 경계에서만 연결.

---

## 16. FinalsPhase 1~4 적응 전략

본선은 4개 `FinalsPhase`, 총 14개 Round다(제2조 3항, 제4조 1항). `FinalsPhase N`이 개시되면 `Layer N`이 개방되고 이전 레이어는 계속 유지되는 **누적 개방** 구조다(제5조 1항).

| `FinalsPhase` | 시각 | Round | 새 레이어 | 누적 | 세그먼트 | 방어 초기 목표 |
|---|---|---|---|---|---|---|
| 1 | 10:00–11:00 | R1–R2 | 위성망 게이트웨이 | L1 | `10.{N}.1.0/24` | 정상 트래픽 기준선, parser 안전성, HEARTBEAT·latency 안정화 |
| 2 | 11:00–13:00 | R3–R6 | 임무 통제 서버(MCS) | L1~L2 | `10.{N}.2.0/24` | MCS 트래픽 fingerprint, 세션·명령 패턴 후보 검증 |
| 3 | 13:00–15:00 | R7–R10 | 무인이동체(UAV) | L1~L3 | `10.{N}.3.0/24` | UAV telemetry·command 후보를 별도 parser로 검증 |
| 4 | 15:00–17:00 | R11–R14 | 사족보행 로봇(UGV) | L1~L4 | `10.{N}.4.0/24` | UGV를 UAV와 별도 profile로 식별, 전체 레이어 회귀 |

팀 네트워크는 `10.{N}.0.0/16`, 진입 IP는 `10.{N}.0.4`이고, 진입 IP로 들어온 트래픽이 목적지 포트에 따라 대상 레이어로 포워딩된다(제12조 1항). 각 레이어의 진입 컨테이너는 `10.{N}.{L}.4`다.

이 표는 프로토콜이나 취약점 목록이 아니다. 위성망 게이트웨이를 예선 Communication 세그먼트와 동일시하거나 MCS를 GCS와 동일시하지 않는다. **UAV parser와 threshold를 UGV에 복사하지 않는다.**

### 16.1 하나의 누적 적응형 런타임

`FinalsPhase`별로 네 개의 이미지나 독립 프로그램을 만들지 않는다.

- 방어 환경변수는 `AGENT_SOCKET`, `LLM_BASE_URL`, `LLM_API_KEY`뿐이다(제16조 2항).
- 공식 계약에 없는 `PHASE`, `LAYER`, `ROUND`, `TEAM_ID` 환경변수를 요구하지 않는다.
- 제7조 2항에 따라 주소·토큰·키를 소스코드에 하드코딩하지 않는다.
- `raw_ip`의 검증된 field로 `ObservedTrafficProfile`을 만들어 레이어를 추정한다. **목적지 IP 세 번째 옥텟이 레이어와 대응할 가능성이 높지만, Broker가 전달하는 `raw_ip`가 포워딩 전인지 후인지 확인되지 않았다.** 실제 패킷과 fixture로 일치를 증명하기 전까지 profile을 확정하지 않는다.
- 새 레이어가 열려도 이전 레이어의 정상 fixture와 검증된 rule을 계속 회귀 테스트한다.
- protocol을 식별하지 못한 패킷은 공격으로 간주하지 않고 빠르게 `ACCEPT`한다.

### 16.2 Round별 목표

초기 운영 가설이며, 실제 로그·PCAP·flag 탈취 결과·SLA 결과가 다르면 관측 증거를 우선해 순서를 바꾼다.

승격 상태는 Round 전체가 아니라 **rule + observed profile + layer evidence**의 조합에 붙는다. 새 `FinalsPhase`에서 레이어가 누적 개방되면 이전 레이어의 검증된 ACTIVE rule은 유지할 수 있지만, 새 레이어와 새 protocol은 같은 이름의 rule이 있어도 `SHADOW`부터 시작한다. 절대 Round 기준의 세부 투입안과 A~H 전략 판정은 `research/defense-mapping.md`의 「A~H 전략 대안 검토」를 따른다.

| `FinalsPhase` | Round 1 | Round 2 | Round 3 | Round 4 |
|---|---|---|---|---|
| 1 | L1 정상 packet inventory, 포트 인벤토리, latency 기준선, 전량 로깅 | 고신뢰 rule 후보 검증, 정상 SLA fixture 회귀, parser 오류 제거 | 해당 없음 | 해당 없음 |
| 2 | 새 MCS traffic fingerprint와 L1 회귀 | 검증된 protocol에서만 S1 명령·세션 패턴 후보 분석 | L1↔L2 온라인 상관 키 검증과 오탐 측정 | 효과 없는 rule 제거, 검증된 최소 rule 안정화 |
| 3 | 새 UAV protocol 식별과 L1~L2 회귀 | 실제 파라미터 field가 보일 때만 S2 후보 검증 | telemetry·상태 field가 충분할 때만 S3 후보 검증 | 관측된 key가 이어질 때만 L1~L3 `S4ChainStage` 상관 후보 검증 |
| 4 | UGV를 UAV와 다른 profile로 식별, L1~L3 회귀 | UGV 증거로 S2·S3 후보 독립 재검증 | L1~L4 bounded correlation과 `S4ChainStage` 후보 검증 | 고신뢰 rule만 유지, 오탐·latency·메모리 안정화 |

`FinalsPhase 1`의 2개 Round는 관측에 쓴다. 포트 목록을 런타임이 받지 못하므로(§9.2) 여기서 인벤토리를 확보하지 못하면 이후 게이트를 켤 근거가 없다.

---

## 17. Round·Break 운영 루프

Round는 20분, Round 사이 Break는 10분이다(제6조 1·2항). 컨테이너는 매 Round 새로 생성되고 종료 시 삭제되며 기동 시간도 Round 시간에 포함된다(제6조 3항, 제15조 4항). **런타임 메모리의 학습 내용은 전부 사라진다.**

```text
현재 Round 20분
  → 에이전트 상태·HEARTBEAT·verdict latency·SLA 관찰
  → 10분 간격 제공 pcap·에이전트 로그에서 오탐·미탐·protocol 근거 분석 (제6조 4항)
  → 다음 버전 parser·rule·threshold와 정상 fixture 수정
  → Break 시작 시 최종 테스트와 이미지 빌드
  → Break 전반 5분 안에 Registry push 완료
  → 운영 측 pull 상태 확인
  → 다음 Round에서 새 이미지·SLA 회귀 검증
```

- 운영 측은 다음 Round 시작 5분 전에 `latest` 이미지를 pull한다(제15조 2항). pull 미완료 시 해당 팀은 **에이전트 없이 Round를 시작**하며 pull timeout은 20분이다(제15조 3항).
- **Break 후반까지 코드를 작성하는 계획을 세우지 않는다.**
- 실행 중인 컨테이너는 새 push의 영향을 받지 않으며 다음 Round부터 반영된다.
- SLA 급락 시 새 공격 탐지율보다 정상 서비스 복구를 우선하고 직전 검증 이미지로 되돌릴 수 있어야 한다.
- 같은 날 운영진이 일정을 변경하면 현장 공지를 우선한다(제4조 1항, 부칙 제4조).

### 17.1 Docker 담당자에게 전달할 정보

이미지 빌드·태그·push는 Docker 담당자 소유다(제14조). 방어 담당자는 Break마다 다음을 즉시 전달한다.

- 변경한 parser와 `rule_id` 목록, 각 rule의 승격 상태(`SHADOW`/`CANARY`/`ACTIVE`)
- policy `bundle_id`, schema version, profile별 alert threshold·reviewer runbook과 이전 bundle 대비 diff
- 측정된 verdict latency 분포와 HEARTBEAT cadence
- 추가·변경된 정상 fixture와 회귀 결과
- rollback 조건과 직전 안전 이미지
- 실행 명령, 환경변수, 런타임 의존성(현재 표준 라이브러리만), 테스트 명령
- 정상 시작 로그와 종료 코드, `/run/agent.sock` mount 요구사항, 비밀값 비출력 검증 결과

제16조 1항의 방어 컨테이너 실행 옵션(`--cap-drop ALL`, `no-new-privileges`, memory reservation 2g, cpu-shares 2048, pids-limit 512, socket mount, `--add-host litellm.lig.internal`)을 전제로 검증한다. 레지스트리 주소와 팀 식별자, 팀별 토큰은 Docker 담당자가 운영 자료로 확인해 확정하며 소스코드에 하드코딩하지 않는다.

### 17.2 다음 Round로 가져갈 수 있는 것

protocol·field parser 개선, 검토된 versioned policy file, 고신뢰 rule과 reason code, 민감 내용을 제거한 최소 fixture, false-positive 재현 regression fixture, bounded state의 TTL·capacity 조정, latency·cadence 측정 결과, 실패한 가설과 rollback 기준.

**PCAP 원본, 전체 payload, 자격증명, 토큰, `FLAG{...}` 값, 상대 팀 정보를 이미지나 저장소에 넣지 않는다.** Round 간 상관은 숨은 영속 상태가 아니라 코드·테스트·검토된 설정의 새 버전으로 구현한다.

### 17.3 금지 행위 확인

제24조가 금지하는 항목 중 방어 설계에 직접 걸리는 것은 다음이다. 설계 어디에도 이를 유발하는 요소가 없음을 확인했다.

- 1호 통신통로 오남용 — Broker 소켓을 판정 외 목적으로 쓰지 않는다.
- 5호 클라우드 자원 악용·DoS성 행위 — 비동기 분석과 LLM 호출에 bounded 예산을 둔다.
- 6호 AI API 키 보호 — 키를 로그·prompt·이미지에 남기지 않는다.
- 8호 Rate limit 우회 — 제12조 3항 제한을 회피하거나 상쇄하려 시도하지 않는다.

---

## 18. 차단 요소와 확인 항목

### 18.1 미검증 자료

다음이 확보되기 전까지 해당 부분은 가설이며, 이를 근거로 `DROP` rule을 활성화하지 않는다.

| 자료 | 상태 | 영향받는 설계 |
|---|---|---|
| 본선 운영세칙 | **검증 완료** — SHA-256 `FFE8E6BE…` 일치, 11쪽 전문 확인 | — |
| 공식 스켈레톤 `deploy/` | **검증 완료** — 34파일, `validate-skeleton.ps1` 필수 5경로 확인 | — |
| 예선 보고서 PDF | **검증 완료** — SHA-256 `1DD42B99…` 일치, 물리 페이지 54쪽 전수 검토 | — |
| 본선 당일 진행 안내 | 팀장 환경에서 SHA-256 `AA704A25…` 확인. 방어 담당 환경 미보유 | §17 타임라인의 현장 세부 |
| 예선 소스 스냅샷 | 팀장 환경에서 tree hash `62320D21…` 확인. 방어 담당 환경 미보유 | 프로토타입 코드 직접 검증 |

예선 보고서 54쪽 전수 매핑은 `docs/references/preliminary-report-defender-map.md`에, S1~S5별 방어 재분류는 `research/defense-mapping.md`에 기록했다. 본 문서 §3의 `예선 보고서 페이지` 열은 그 매핑을 참조한다. 세 문서는 서로 모순되지 않아야 하며, 상충이 생기면 상위 근거를 우선하고 차이를 기록한다.

**예선 소스 스냅샷 미보유의 영향**: 보고서 §4.8이 기술한 `config.py` 점수표, `schema.py` 검증기, `correlation/` 모듈 구현을 직접 읽지 못했다. 본 설계는 보고서 본문에 기술된 **개념과 구조**만 근거로 삼고, 프로토타입 코드의 상수·임계값을 인용하지 않는다. 보고서 §4.6이 이 값들을 "보정되지 않은 설계값"으로 명시하므로 본선 임계값으로 사용해서는 안 되며(§5.2 한계), 이 제약은 스냅샷을 확보하더라도 유지된다.

### 18.2 오리엔테이션(09:00–10:00)에서 확인할 항목

세칙과 스켈레톤으로 해소되지 않은 항목만 남겼다.

- **Broker가 전달하는 `raw_ip`의 목적지 주소가 포워딩 전인가 후인가** — 레이어 식별 가능 여부를 결정한다
- **SLA check 트래픽이 진입 IP를 통해 오는가, 별도 경로인가** — 정상 baseline 정의를 결정한다
- 각 레이어에 열려 있는 실제 포트·프로토콜 목록 — 포트 게이트 활성화 조건
- `pkt_len`과 실제 payload 길이가 다른 프레임의 공식 처리 정책
- IPv6 패킷이 전달되는가
- 300ms 시한의 기준점이 Broker send 시점인가 agent recv 시점인가
- LiteLLM Proxy 모델 목록과 팀별 쿼터의 당일 확정치
- 팀 번호 `{N}`과 레지스트리 접근 정보

### 18.3 상위 자료 충돌 처리

공식 계약의 오류를 발견하면 이번 브랜치에서 조용히 수정하지 않는다. 충돌 내용, 근거 경로, 설계 영향만 기록하고 팀장 이경준에게 확인을 요청한다.

현재까지 세칙·스켈레톤·`contracts/defender/README.md` 사이에 모순은 발견되지 않았다.

---

## 19. 구현 우선순위

```text
1순위  절대 안 죽는 골격 — connect·재연결, HEARTBEAT 분리, Deadline Guard, 예외 시 ACCEPT
2순위  전량 로깅과 latency 측정 — 모든 rule의 원재료
3순위  PolicyLoader + alert-only AnomalyMonitor
4순위  Gate 구조 검증 + Sig 기본 시그니처 + 결정론적 CANARY
5순위  Break 운영 루프와 Docker 담당자 인계 절차
6순위  Score 세션 행위 + 비동기 Corr
7순위  Advisory LLM rule 후보 생성 (SHADOW 전제)
```

**1~3순위가 없으면 4순위 이하는 전부 무의미하다.** 화려한 탐지보다 죽지 않는 것이 먼저다. 다만 §0.2의 산식 분석에 따라, 1~3순위가 확보된 뒤에는 **고신뢰 rule 활성화를 오탐 우려로 지연시키지 않는다.**

구현은 승인 후 `feat/defender-runtime-foundation` 브랜치에서 테스트 우선으로 진행한다. 첫 순서는 Broker frame codec, session·재연결·HEARTBEAT, `ACCEPT` 전용 timing baseline, bounded parser, 결정론적 policy, 비동기 event 경계다. 고신뢰 `DROP` rule과 application parser는 정상 negative fixture와 SLA 회귀가 확보된 뒤 별도 짧은 브랜치로 추가한다.
