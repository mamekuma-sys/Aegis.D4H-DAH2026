# DAH 2026 본선 방어 런타임 설계

- 작성: 방어 담당자
- 브랜치: `docs/defender-runtime-design`
- 상위 근거: 본선 운영세칙, 같은 날 운영사무국 안내, 공식 스켈레톤 `deploy/docs/agent-guide.md`, `contracts/defender/README.md`
- 목표: **뚫기 어렵되 우리가 먼저 죽지 않는** 다층 필터

---

## 0. 설계 전제

### 0.1 "복잡하게 만들면 뚫기 어렵다"는 이 대회에선 반만 맞다

공격 에이전트가 도달 가능한 곳은 타 팀 진입점과 운영 서버뿐이고(제11조 2항), 방어 에이전트는 라우터 안쪽에서 Broker와 Unix socket으로만 통신한다. **에이전트 자체는 공격 표면이 아니다.**

따라서 목표는 "복잡해서 못 뚫게"가 아니라 "정확해서 못 통과하게"다. 코드 복잡도는 방어력을 올리지 않고 우리 쪽 버그와 지연 위험만 올린다.

### 0.2 "아예 안 뚫리는 게 최고"가 아니다

전부 DROP하면 flag는 안 뺏기지만 SLA가 0이 되어 라운드 점수가 통째로 0이다(제17조 2항). Round 점수는 `(공격 점수 + 방어 점수) × SLA`이고, 방어 점수는 `10 × (배치된 flag 수 − 탈취당한 고유 flag 수)`이다. **고신뢰 공격 하나를 더 막는 것보다 넓은 DROP rule로 정상 요청을 막는 쪽이 총점 손실이 크다.**

### 0.3 진짜 위험은 공격자가 아니라 우리 자신

본선에서 방어 점수를 날리는 3대 원인:

1. 에이전트가 **죽음** → Broker fail-open → 전 패킷 통과 → 무방비
2. 판정이 **느림** → 300ms 초과 → Broker가 해당 패킷을 DROP → SLA 붕괴
3. rule을 잘못 넣어 **정상 트래픽 차단** → SLA 붕괴

설계의 절반은 이 셋을 막는 데 쓴다. 구현 우선순위도 여기서 나온다(§19).

### 0.4 "이중 방화벽"의 올바른 형태 — 직교하는 3축

같은 것을 두 번 검사하는 것은 심층방어가 아니다. **서로 다른 것을 보는 축**을 겹쳐야 한다.

| 축 | 무엇을 보나 | 뚫리는 조건 | 본 설계에서의 상태 |
|---|---|---|---|
| **축 A — 인바운드 내용** | 들어오는 요청 payload에 공격 패턴이 있나 | 우리가 모르는 새 payload | 채택. 동기 `Sig` 단계 |
| **축 B — 세션 행위 누적** | 이 flow가 얼마나 비정상적으로 굴었나 | 느리고 조용한 공격 | 채택. 계산은 비동기, 조회만 동기 |
| **축 C — 아웃바운드 응답** | 나가는 데이터에 flag가 섞여 있나 | 응답 경로 자체가 관측 불가 | **조건부 보류.** §9.4 참조 |

축 A가 뚫려도 축 C에서 막히는 구조가 이론적으로 가장 강하다. 공격자 입장에서는 "취약점을 뚫었는데 flag가 안 나온다"가 되어 대응 난이도가 급상승한다.

**다만 축 C에는 자폭 함정이 두 개 있다.**

1. **Broker가 아웃바운드 패킷을 전달하는지 확인되지 않았다.** 제13조 1항은 "각 레이어로 **들어온** 패킷을 전달한다"이고, `contracts/defender/README.md`도 계약된 판정 입력을 PACKET frame의 `raw_ip`뿐이라고 못박는다. 문자 그대로면 인바운드 전용이고 축 C는 성립하지 않는다.
2. **SLA 체커가 flag를 읽어가는 방식일 수 있다.** A&D 대회의 SLA 체크는 통상 서비스에 flag를 심고(put) 다시 읽어(get) 정상 동작을 확인한다. 그렇다면 flag 정규식을 무조건 아웃바운드 차단하는 순간 **100회 SLA check가 전부 실패해 라운드 0점**이다.

이 두 가지가 오리엔테이션에서 유리하게 확인되기 전까지, 축 C는 본 설계의 런타임 기능에서 **제외**한다. 확인 후 활성화할 때도 무조건 차단이 아니라 "정상 취득 경로로 온 요청의 응답만 허용"하는 형태로만 도입하고, 최소 2개 Round는 관찰 전용(SHADOW)으로 돌린다.

### 0.5 AI는 패킷 경로에 넣을 수 없다

300ms 시한(레이어당 30ms 지연 차감 시 실효 예산은 더 짧다)에 원격 LLM 호출은 물리적으로 불가능하다. `contracts/defender/README.md`도 "원격 LLM 호출을 패킷별 동기 판정 경로에 넣지 않는다"를 계약으로 명시한다.

따라서 LLM은 **별도 프로세스에서 redacted feature를 분석해 다음 이미지의 rule 후보를 뽑는 용도**로만 쓴다. 예선 보고서의 결정론적 판단과 AI 판단을 분리한 이중판단 구조가 여기서 우연이 아니라 **시간 계약상 필연**이 된다. 진위 검증(제23조) 때 "예선 설계 원칙이 본선 인프라에서 그대로 강제된다"고 설명할 수 있는 지점이다.

---

## 1. 범위와 비범위

### 1.1 범위

Broker session 관리, PACKET parser, 사전 승인된 결정론적 policy, VERDICT 반환, HEARTBEAT 송신, bounded online state, verdict 이후 비동기 상관분석, 선택적 LLM advisory, 비밀 없는 structured logging, metrics, shutdown.

### 1.2 비범위

Dockerfile 확정, 공통 계약(`contracts/**`) 수정, 공식 스켈레톤 복사·수정, 원격 LLM의 packet별 동기 호출, 실제 기체 제어, RTL·Land·rollback·HITL 실행, 자동 rule 생성과 실시간 self-modification, 영속 packet 저장.

이번 브랜치에서는 실제 방어 런타임 코드를 작성하지 않는다. 아래 코드 조각은 불변조건을 설명하기 위한 예시이며 구현은 승인 후 별도 브랜치에서 테스트 우선으로 진행한다.

---

## 2. 용어 분리

문서와 향후 코드에서 아래 개념을 서로 다른 이름과 타입으로 취급한다. 문맥 없는 `Phase 1`, `P1` 같은 표현을 쓰지 않는다.

| 이름 | 범위 | 의미 | 사용 제한 |
|---|---|---|---|
| `FinalsPhase` | 1~4 | 본선에서 레이어가 **누적 개방**되는 경기 단계 | 운영 일정 설명에만 사용. 런타임 환경변수로 주어진다고 가정하지 않음 |
| `S4ChainStage` | 1~5 | 예선 보고서 S4의 다단계 공격 체인 국면 | `FinalsPhase` 번호와 대응한다고 가정하지 않음 |
| `MissionState` | 구현 보류 | 이륙 전·순항·임무·복귀 같은 기체 상태 | parser와 fixture로 존재가 증명될 때만 사용. 현재 설계에서는 제외 |

### 2.1 본선 레이어 vs 내부 처리 단계 — 이름 충돌 방지

**`L1`~`L4`는 본선 네트워크 레이어 전용 표기다.** 내부 파이프라인 단계에는 절대 `L` 표기를 쓰지 않는다.

| 표기 | 대상 |
|---|---|
| `L1`~`L4` | 본선 네트워크 레이어 (위성망 게이트웨이 / MCS / UAV / UGV) |
| `Gate` | 내부 동기 1단계 — 구조 sanity와 포트 게이트 |
| `Sig` | 내부 동기 2단계 — 스트림 재조립 후 시그니처 매칭 |
| `Score` | 내부 동기 3단계 — flow 위험도 조회 |
| `Corr` | 비동기 상관분석 worker |
| `Advisory` | 비동기 LLM 조언 worker |

---

## 3. 근거 추적표

| 결정 | 상위 근거 | 예선 보고서 페이지 | 관측 증거·fixture | 동기/비동기/제외 | 실패 시 동작 | 테스트 |
|---|---|---|---|---|---|---|
| 300ms 내 VERDICT 반환, 내부 cutoff 200ms | 세칙 제13조, `contracts/defender/README.md` 시간 계약 | 해당 없음 | 공식 Broker 왕복 측정 | 동기 | cutoff 도달 시 즉시 `ACCEPT` | `test_timing.py` |
| 약 1초 HEARTBEAT, 3초 무응답 시 fail-open | 세칙 제13조 2항, 계약 시간 절 | 해당 없음 | Broker 사망 판정 관측 | 동기 | 별도 스레드 유지, 재연결 | `test_heartbeat.py` |
| 판정 입력은 `raw_ip`뿐 | 계약 입력 경계 절 | 해당 없음 | PACKET frame fixture | 동기 | 파싱 실패 시 `ACCEPT` | `test_packet.py` |
| source IP 단독 식별 금지 | 세칙 제12조 2항(NAT), 계약 네트워크 절 | 미확인 | NAT 정규화 관측 | 제외 | source IP만 바꾼 fixture로 verdict 불변 검증 | `test_policy.py` |
| 원격 LLM을 동기 경로에서 배제 | 계약 입력 경계·동시성 절 | 미확인 | LiteLLM Proxy 지연 측정 | 비동기 | LLM 장애가 verdict·HEARTBEAT에 영향 없음 | `test_advisory.py` |
| 세션 행위 누적 점수(축 B) | 예선 Correlation Engine 원칙 | 미확인 | 인바운드 요청 field parser | 비동기 계산 + 동기 조회 | state 없으면 `ACCEPT` | `test_correlation.py` |
| 아웃바운드 flag 필터(축 C) | 세칙 제13조 1항 해석 미확정 | 미확인 | 아웃바운드 PACKET 관측 없음 | **제외** | 관측 증거 확보 전까지 미구현 | 해당 없음 |
| 응답 코드 분포 신호 | 아웃바운드 가시성 전제 | 미확인 | 관측 증거 없음 | **제외** | 축 C와 함께 재검토 | 해당 없음 |
| `MissionState`·파라미터 해시·물리 상태 | 계약 입력 경계 절 | 미확인 | field 존재 미증명 | **제외** | 판정 입력으로 사용하지 않음 | 해당 없음 |
| SLA 서킷 브레이커 | 세칙 제17·20조, 예선 Availability-Aware Response | 미확인 | DROP율 슬라이딩 윈도우 | 동기 | 임계 초과 시 관찰 모드 | `test_policy.py` |
| Round 간 상태 소실 허용 | 세칙 제15조 4항, `rules-checklist.md` | 해당 없음 | 컨테이너 재생성 관측 | 해당 없음 | disk persistence 요구하지 않음 | `test_round_lifecycle.py` |

`예선 보고서 페이지` 열의 `미확인`은 원본 PDF 54쪽 전수 매핑(`docs/references/preliminary-report-defender-map.md`)이 완료되면 실제 페이지 번호로 채운다. 그 매핑 없이는 예선 개념을 본 설계의 근거로 인용하지 않는다(§18).

---

## 4. 런타임 흐름

```text
startup validation
  → AGENT_SOCKET 연결·재연결
  → 독립 HEARTBEAT 스케줄러 기동
  → PACKET frame 수신과 header 검증
  → bounded raw IP parser
  → 사전 승인된 결정론적 policy (Gate → Sig → Score)
  → ACCEPT/DROP VERDICT 송신
  → latency 기록
  → bounded 비동기 event enqueue
  → Corr / Advisory / 로그 분석
```

### 4.1 동기 경로 — 직렬 다단이 아니라 예산 분리

"필터 A 통과하면 B, 그다음 C" 식으로 쌓으면 지연이 누적되어 300ms를 잡아먹는다. 대신 **각 단계가 자기 예산을 가지고, 예산을 넘으면 즉시 `ACCEPT`로 빠져나온다.**

```text
                    [ Broker ]
                        │ 0x01 PACKET (raw_ip)
                        ▼
┌────────────────────────────────────────────────────────┐
│  Gate   구조 sanity · 목적지 포트 게이트   p99 2ms 이하  │
│         명백한 malformed → DROP, 나머지 통과            │
├────────────────────────────────────────────────────────┤
│  Sig    TCP 재조립 → payload 다중패턴 매칭  p99 20ms    │
│         rule set은 외부 파일, 이미지 빌드 시 고정        │
├────────────────────────────────────────────────────────┤
│  Score  flow 누적 위험도 조회 (읽기 전용)   p99 20ms    │
│         임계 초과 시 DROP                               │
└────────────────────────────────────────────────────────┘
                        │ 0x02 VERDICT
                        ▼
       ★ 어느 단계든 내부 cutoff 초과 시 즉시 ACCEPT ★

──────── 여기서부터 패킷 경로 밖 (비동기) ────────

  Corr      상관분석 worker (초 단위, 별도 스레드)
            지나간 트래픽 재분석 → flow risk 갱신 → Score가 읽음

  Advisory  LLM 조언 worker (분 단위, 별도 프로세스)
            redacted feature 요약 → rule 후보 제안 → 사람 검토 → 다음 이미지
```

### 4.2 동시성 경계

- PACKET 수신, VERDICT 송신, HEARTBEAT 스케줄링, 비동기 분석의 책임을 분리한다.
- HEARTBEAT와 VERDICT가 같은 socket을 쓰므로 **송신 lock으로 message boundary와 write ordering을 보존**한다. `SOCK_SEQPACKET`이라도 두 스레드가 lock 없이 `send`하면 프레임 인터리빙 위험이 있다.
- **lock 안에서는 frame packing과 짧은 socket send만 수행한다.** parsing, logging, correlation, LLM 호출을 lock 안에서 실행하지 않는다.
- shutdown과 reconnect 중 중복 HEARTBEAT 스레드, orphan queue, stale socket이 남지 않게 한다.

```python
# 불변조건 예시 — 실제 구현은 승인 후 별도 브랜치
class SocketWriter:
    """HEARTBEAT와 VERDICT가 같은 소켓을 공유한다. lock 안에서는 send만."""
    def __init__(self, sock):
        self._sock = sock
        self._lock = threading.Lock()

    def send_frame(self, frame: bytes) -> None:
        with self._lock:
            self._sock.send(frame)
```

---

## 5. 300ms hot path 예산

Broker의 300ms를 구현 목표로 삼지 않는다. 내부 deadline과 여유 시간을 별도로 둔다.

| 구간 | 초기 목표 |
|---|---:|
| frame header 검증·unpack | p99 2ms 이하 |
| bounded IP/L4/application parse | p99 20ms 이하 |
| 결정론적 policy·bounded state lookup | p99 20ms 이하 |
| VERDICT pack·send | p99 8ms 이하 |
| **hot path 합계** | **p99 50ms 이하** |
| **내부 emergency cutoff** | **PACKET 수신 후 200ms** |
| Broker hard deadline | 300ms 미만 |

- **모든 시간은 벽시계가 아니라 monotonic clock으로 측정한다.** NTP 보정이 들어오면 벽시계 기반 예산 계산이 깨진다.
- `pkt_id`를 읽은 직후부터 cutoff를 감시하고, 도달하면 안전한 fallback verdict `ACCEPT`를 즉시 시도한다.
- parsing failure, unknown protocol, 비동기 queue full, LLM 장애를 이유로 300ms timeout DROP을 유발하지 않는다.
- 실측이 초기 목표를 충족하지 못하면 rule 또는 parser를 hot path 밖으로 옮긴다. 문서의 숫자를 조용히 완화하지 않는다.

```python
# 불변조건 예시
t0 = time.monotonic()                      # 벽시계 금지
...
def over_budget() -> bool:
    return (time.monotonic() - t0) * 1000 > INTERNAL_CUTOFF_MS   # 200
```

---

## 6. 기본 verdict 정책

기본 원칙은 **불확실하면 빠르게 `ACCEPT`, 고신뢰 증거가 있을 때만 `DROP`**이다.

### 6.1 DROP에 필요한 조건 (전부 충족)

1. packet 구조가 성공적으로 파싱됐다.
2. rule이 참조하는 모든 field의 존재와 encoding이 fixture로 증명됐다.
3. `rule_id`, protocol scope, layer/profile scope, match reason이 결정론적이다.
4. 동일 protocol의 정상 negative fixture를 통과한다.
5. latency와 bounded state 조건을 통과한다.
6. rollback 조건과 owner가 기록돼 있다.

### 6.2 DROP 사유가 아닌 것

- parser exception 또는 지원하지 않는 protocol
- source IP가 특정 값이라는 사실만으로 내린 판단
- LLM의 공격 의심 문장 또는 confidence 값
- 예선 synthetic Risk Score threshold 초과
- state가 없거나 상관분석 queue가 가득 찬 상태
- HEARTBEAT 또는 분석 worker 장애
- 새 레이어를 아직 식별하지 못한 상태

### 6.3 header 손상 시 처리

header가 유효해 `pkt_id`를 알지만 `raw_ip`가 잘렸거나 비정상이면 `ACCEPT`와 비민감 reason code를 반환한다. header 자체가 짧아 `pkt_id`를 알 수 없으면 **존재하지 않는 ID로 verdict를 만들지 않고** session 오류로 기록한 뒤 재연결 또는 종료한다.

---

## 7. 구성요소 경계

| 구성요소 | 책임 | 실패 격리 |
|---|---|---|
| `RuntimeConfig` | 환경변수 검증과 안전한 기본값 | 기동 실패를 명시적 종료로 |
| `BrokerSession` | Unix socket 연결, 재연결, 수신 lifecycle | 재연결이 HEARTBEAT를 중복 생성하지 않음 |
| `FrameCodec` | PACKET 검증, VERDICT·HEARTBEAT 직렬화 | 인코딩 오류가 session을 죽이지 않음 |
| `HeartbeatScheduler` | 약 1초 cadence와 지연 감시 | 판정 로직과 완전 분리. 무거운 작업 금지 |
| `PacketParser` | bounded IP/L4 및 증명된 application parser dispatch | 예외를 밖으로 던지지 않음 |
| `HotPolicy` | 사전 승인 rule과 bounded read-only state 조회 | 예외 시 `ACCEPT` |
| `VerdictSender` | deadline 인식 송신과 latency 측정 | 송신 실패를 metric으로 기록 |
| `EventAdapter` | verdict 이후 관측 field를 최소 event로 변환 | 변환 실패 시 event 폐기 |
| `CorrelationStore` | TTL·capacity가 있는 flow/event state | 용량 초과 시 eviction |
| `CausalMatcher` | 관측된 key만 사용하는 비동기 chain match | 실패해도 hot path 무영향 |
| `RiskModel` | 본선 fixture로 보정된 비동기 우선순위 | 예선 합성 점수 미사용 |
| `AdvisoryWorker` | redacted feature만 사용하는 LLM 조언 | 장애·quota 소진이 verdict에 무영향 |
| `AuditLogger` | payload·secret 없는 reason·latency·health 기록 | 로그 I/O가 hot path를 막지 않음 |
| `Metrics` | verdict count, accept/drop, parser failure, queue drop, heartbeat gap, latency 분포 | — |

한 구성요소의 예외가 HEARTBEAT 또는 이미 수신한 PACKET의 verdict를 막지 않게 한다.

---

## 8. 상태와 데이터 모델

| 타입 | 최소 필드 | 불변조건 |
|---|---|---|
| `PacketEnvelope` | `pkt_id`, `declared_len`, `raw_ip`, `received_at_monotonic` | monotonic 기준 시각 필수 |
| `ParsedPacket` | IP version, protocol, src/dst, ports, bounded payload view, parser status | payload는 복사가 아니라 상한 있는 view |
| `FlowKey` | `(src_ip, src_port, dst_ip, dst_port, protocol)` | **protocol 포함 5-tuple.** NAT source identity를 신뢰 신호로 쓰지 않음 |
| `ObservedTrafficProfile` | protocol, port, parser version, 정상 증거 | 레이어 식별에 쓰려면 fixture 일치 선증명 |
| `RuleMatch` | `rule_id`, confidence class, evidence fields, profile scope, reason code | — |
| `VerdictDecision` | `pkt_id`, ACCEPT/DROP, `rule_id`, reason code, elapsed | elapsed는 monotonic 차이 |
| `CorrelationEvent` | redacted field, timestamp, flow key, event type, evidence source | 원본 payload 미포함 |
| `CorrelationState` | TTL, last update, bounded counters, matched stages | per-key cap 필수 |
| `AsyncAdvisory` | input feature IDs, recommendation, model ID, token usage, expiration | **runtime authority 없음** |

### 8.1 용량 상한

| 대상 | 상한 | 초과 시 |
|---|---|---|
| flow당 재조립 버퍼 | 16KB 링버퍼 | 오래된 앞부분 폐기 |
| 전체 flow 수 | 5000 | 신규 flow 상태추적 포기, `ACCEPT` |
| flow TTL | 120초 | 주기 스윕으로 제거 |
| 비동기 event queue | 고정 길이 | 최신 또는 최저 우선순위 event 폐기 |

컨테이너 메모리 예약은 2GB이고 20분 Round 동안 무한 증가하면 OOM이다. 모든 collection에 max capacity와 eviction 정책을 둔다. **Round 종료 후 상태가 사라지는 것을 정상으로 취급하고 disk persistence를 요구하지 않는다.**

---

## 9. parser와 관측 증명

### 9.1 parser별 문서화 항목

protocol/version 식별 byte와 최소 길이, variable length·options·checksum·fragment·truncation 처리, 암호화 또는 unknown payload 처리, 추출 field의 byte offset 또는 decode rule, positive fixture와 정상 negative fixture, malformed fixture와 기대 `ACCEPT` fallback, parser 시간·메모리 상한, 지원하지 않는 variant에서의 동작.

**IPv4만 지원한다고 가정하지 않는다.** 공식 스켈레톤에서 IPv4만 관측됐다면 그 사실과 fixture를 기록하고, IPv6 또는 unknown version은 bounded fallback으로 처리한다.

### 9.2 Gate 단계 — 오탐이 나면 안 되는 것만

판단이 애매하면 `Sig`로 넘긴다.

- IP header sanity (version, IHL, 길이 불일치)
- `pkt_len`과 실제 payload 길이 불일치, trailing bytes
- 비정상적으로 큰 패킷, fragmentation 이상
- 알려진 스캔 패턴 (TCP NULL/FIN/Xmas 플래그 조합)
- 목적지 포트 게이트

포트 게이트는 강력하지만 위험하다. **어떤 포트가 열려 있어야 하는지 오리엔테이션에서 확인하기 전까지 관찰 전용으로 둔다**(§18).

### 9.3 Sig 단계 — TCP 스트림 재조립

핵심 난제: Broker가 주는 것은 raw IP 패킷이다. HTTP 요청 하나가 여러 패킷에 쪼개져 오면 **패킷 하나만 봐서는 payload 판단이 불가능**하다.

- 매칭은 미리 컴파일된 다중패턴(Aho-Corasick 계열)으로 한다. 정규식 수십 개를 순차 실행하면 20ms 예산이 날아간다.
- rule set은 코드가 아니라 데이터로 둔다. 다만 **런타임 자동 재적재는 하지 않는다** — 새 rule은 PCAP·로그 근거, 양성·정상 fixture, 리뷰를 거쳐 다음 이미지에 포함한다(§16).

시그니처 카테고리 후보:

```text
경로 탐색      ../  ..%2f  %2e%2e  ....//
SQL 인젝션      ' OR   UNION SELECT   ; DROP   sleep(   benchmark(
명령 주입      ; ls   | cat   $(   `   && curl   nc -e
템플릿 인젝션   {{   ${   <%=
역직렬화       언어별 매직 바이트
LFI/파일읽기   /etc/passwd  /proc/self  file://
경로 특이성    /flag  flag.txt  .git/  .env  backup
```

이 목록은 **가설이다.** 각 항목은 해당 protocol parser가 field를 실제로 추출할 수 있음이 fixture로 증명되고 정상 negative fixture를 통과한 뒤에만 `DROP` rule이 된다. 그 전까지는 관찰 전용이다.

### 9.4 Score 단계 — NAT 대응 세션 행위 (축 B)

NAT로 source IP가 정규화되므로 소스 IP로는 공격자를 가릴 수 없다(제12조 2항). 대신 행위 특징으로 판단한다.

| 신호 | 필요한 관측 | 상태 |
|---|---|---|
| 짧은 시간에 서로 다른 경로·엔드포인트 다수 시도 | 인바운드 요청 경로 parser | 채택 후보 |
| 요청 간격이 기계적으로 균일 | 인바운드 도착 시각 | 채택 후보 |
| 인코딩 중첩 (`%252e` 등) | 인바운드 payload | 채택 후보 |
| 비정상적으로 긴 URI·헤더 | 인바운드 payload | 채택 후보 |
| `Sig`에 걸린 이력이 있는 flow | 내부 상태 | 채택 후보 |
| **4xx/5xx 응답 코드 분포** | **아웃바운드 응답 관측** | **제외 (§0.4)** |

응답 코드 신호는 아웃바운드 가시성을 전제하는데 그것이 증명되지 않았다. 축 C와 함께 재검토한다.

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

### 10.3 자멸 방지 3단 안전장치

**① Deadline Guard (300ms 방어)** — §5. `pkt_id` 확보 직후부터 monotonic 경과를 감시하고 200ms 초과 시 판단을 포기하고 `ACCEPT`.

**② Never-Die Wrapper (fail-open 방어)** — 모든 패킷 처리를 예외 포착으로 감싸고 예외 시 `ACCEPT`. HEARTBEAT는 별도 스레드에서 약 1초마다, 판정 로직과 완전 분리. 3초간 HEARTBEAT가 없으면 Broker가 사망 판정하고 **전 패킷이 통과한다(fail-open)**. HEARTBEAT 스레드는 절대 무거운 일을 하지 않는다.

**③ SLA 서킷 브레이커 (과잉 차단 방어)**

```text
슬라이딩 윈도우로 DROP 비율을 실시간 추적
DROP율 > 경고 임계  → 경고 metric + 가장 최근 활성화된 rule 비활성화
DROP율 > 위험 임계  → 전체 정책을 관찰 모드로 강제 전환 (전부 ACCEPT)
복구는 DROP율이 경고 임계의 절반 아래로 내려간 뒤에만
```

rule 하나를 잘못 넣어 라운드가 통째로 0점 나는 것을 막는 장치다. 예선 보고서의 Availability-Aware Response와 Graceful Degradation 원칙에 대응한다.

임계값은 정상 트래픽 baseline을 측정한 뒤 `FinalsPhase 1`에서 확정한다. 비율 계산은 hot path에서 O(1) 증분 갱신으로 수행하고 매 패킷 전체 윈도우를 합산하지 않는다.

### 10.4 rule 승격 단계

```text
SHADOW (로그만) → CANARY (제한 범위만 차단) → ACTIVE (전면 차단)
```

신규 rule은 무조건 `SHADOW`로 투입하고, 한 Round 관찰해 정상 트래픽에 걸린 흔적이 없을 때만 승격한다. **LLM이 제안한 rule을 `SHADOW` 없이 `ACTIVE`로 넣는 것은 SLA 자살이다.** 승격은 사람이 판단하며 런타임이 자동으로 하지 않는다.

---

## 11. 온라인 비동기 상관분석

예선 Correlation Engine을 verdict 이후 경로로 재설계한다.

- 현재 packet의 verdict를 기다리게 하지 않는다.
- queue는 bounded이며 full이면 최신 또는 최저 우선순위 event를 버린다.
- state는 `monotonic timestamp + TTL + max keys + per-key cap`으로 제한한다.
- out-of-order, duplicate, late event 처리 규칙을 정한다.
- `session_id`, `vehicle_id`, `MissionState`는 실제 parser가 생성한 경우에만 correlation key로 쓴다. 현재는 어느 것도 증명되지 않아 사용하지 않는다.
- `S4ChainStage` matcher는 관측된 event와 key만 사용하며 예선 보고서의 합성 점수를 복사하지 않는다.
- **상관분석 결과는 현재 packet을 소급 차단할 수 없다.**
- 이후 packet의 `Score`가 상관 state를 읽으려면 lookup이 bounded이고 rule이 사전 승인돼 있어야 한다.
- online state만으로 새 실행 가능한 rule을 생성하지 않는다.

"개별 요청은 정상 같지만 누적하면 공격"이라는 예선 논지는 그대로 유효하고, anchor + 누적 점수 구조도 재사용 가능하다. 다만 **판정 시점이 예선의 배치 처리에서 본선의 verdict 이후 경로로 바뀐다.**

---

## 12. LLM 사용 경계

LLM은 선택적 비동기 조언자다. 환경변수는 `LLM_BASE_URL`과 `LLM_API_KEY`뿐이며 대회 LiteLLM Proxy만 접근 가능하다.

- 원격 LLM 호출을 packet별 동기 verdict 경로에 넣지 않는다.
- LLM timeout, quota 소진, invalid response, proxy 장애가 HEARTBEAT·verdict에 영향을 주지 않는다.
- raw packet payload, secret, token, flag, 전체 PCAP, 인증 header를 prompt에 보내지 않는다.
- parser가 만든 redacted feature, aggregate metric, `rule_id`, 비민감 reason만 입력 후보로 쓴다.
- LLM 출력은 현재 또는 이후 packet을 직접 `ACCEPT`/`DROP`하지 않는다.
- LLM이 작성한 signature나 코드를 실행 중 이미지에 자동 반영하지 않는다.
- 조언은 사람이 PCAP·정상 fixture와 대조해 **다음 Round rule 후보로만** 사용한다.
- model ID, 호출 수, token 사용량, 실패율을 증빙 가능한 비민감 형태로 기록한다.

### 12.1 model 선택

동점 시 LLM token 비용이 적은 팀이 우선하므로(제22조) 비동기 조언에도 예산과 근거를 관리한다. rule 후보 생성 수준의 작업에는 Proxy가 제공하는 소형 모델로 충분하며, 전체 트래픽을 넣지 않고 의심 세션 상위 K개만 요약해 보낸다. 운영 자료 기준 소형 모델의 팀별 쿼터가 대형 모델보다 크므로 기본값으로 채택하되, 실제 모델 목록과 쿼터는 오리엔테이션에서 확인한다.

---

## 13. 오류 처리와 복구

각 오류에 대해 탐지, hot-path verdict, HEARTBEAT 영향, 재연결, 로그, 종료 조건을 정한다.

| 오류 | hot-path verdict | 조치 |
|---|---|---|
| `AGENT_SOCKET` 누락·경로 없음·permission denied | 해당 없음 | 기동 실패를 명시적으로 종료 |
| connect 실패, Broker 미준비 startup race | 해당 없음 | bounded backoff 재시도 |
| Broker orderly close, socket reset | 해당 없음 | 재연결. **이전 session의 verdict를 새 session에 보내지 않음** |
| unknown message type | 해당 없음 | 무시하고 metric 기록 |
| PACKET header truncation | verdict 생성 안 함 | session 오류 기록 |
| `pkt_len`과 실제 길이 불일치 | `ACCEPT` | reason code 기록 |
| duplicate·out-of-order `pkt_id` | 최초 verdict 유지 | metric 기록 |
| raw IP malformed·fragmented·unknown version | `ACCEPT` | bounded fallback |
| parser·policy 예외 | `ACCEPT` | 예외 metric, 로그 |
| send failure·partial send | 해당 없음 | 재연결, latency metric |
| HEARTBEAT 지연·스레드 사망 | 해당 없음 | 스레드 재기동. 3초 접근 전 경보 |
| 비동기 queue overflow, worker crash | 영향 없음 | event 폐기, worker 재기동 |
| state capacity 초과, clock 불연속 | 영향 없음 | eviction, monotonic 사용으로 불연속 회피 |
| LLM timeout·429·invalid JSON·quota 소진 | 영향 없음 | advisory 비활성화 |
| SIGTERM, Round 종료 | 해당 없음 | 진행 중 verdict 마무리 후 정리 종료 |

재시도에는 bounded backoff와 shutdown interrupt를 둔다.

---

## 14. 향후 파일 구조

실제 파일은 승인 후 구현 브랜치에서 만든다.

```text
agents/defender/
├── src/aegis_defender/
│   ├── __init__.py
│   ├── main.py            entrypoint와 lifecycle
│   ├── config.py          RuntimeConfig
│   ├── protocol.py        FrameCodec
│   ├── session.py         BrokerSession, SocketWriter
│   ├── heartbeat.py       HeartbeatScheduler
│   ├── packet.py          PacketParser
│   ├── policy.py          HotPolicy (Gate·Sig·Score), 서킷 브레이커
│   ├── rules.py           rule 정의·로딩·승격 상태
│   ├── state.py           FlowTable, CorrelationStore
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

PACKET fixture에서 type, `pkt_id`, `pkt_len`, `raw_ip`를 big-endian으로 정확히 해석 / `ACCEPT`·`DROP` VERDICT byte가 공식 fixture와 일치 / HEARTBEAT가 정확히 1 byte `0x05` / unknown type, short header, length mismatch, trailing bytes 처리 / `SOCK_SEQPACKET` message boundary 보존.

### 15.2 HEARTBEAT와 session

정상 부하와 비동기 부하에서 cadence 약 1초 유지 / gap이 3초에 접근하기 전 metric·failure handling 작동 / connect race, disconnect, reconnect, shutdown / **재연결 후 worker와 HEARTBEAT 스레드가 각각 하나씩만 존재**.

### 15.3 parser와 policy

IPv4·관측된 protocol positive fixture / 정상 traffic negative fixture / truncated·fragment·unknown protocol·unsupported version에서 빠른 `ACCEPT` / **NAT source IP만 바뀌어도 verdict가 달라지지 않음** / 각 DROP rule의 positive·negative·boundary fixture / rule conflict에서 `ACCEPT`와 metric.

### 15.4 timing과 load

monotonic timing 사용 / 최소 1, 100, 500, 1000 packet/s load profile 측정 / hot path p50·p95·p99·max 기록 / **목표 환경에서 p99 50ms 이하, max 200ms 미만, 300ms 초과 verdict 0건** / queue가 가득 차거나 LLM이 30초 멈춰도 latency 기준 유지 / HEARTBEAT와 verdict가 같은 socket writer를 쓸 때 starvation 없음.

측정 환경이 공식 컨테이너와 다르면 환경 차이를 기록한다. **성능을 측정하지 않고 예상치만 적지 않는다.**

### 15.5 bounded state와 상관분석

TTL expiry, max key eviction, per-key cap / duplicate·late·out-of-order event / queue overflow가 verdict를 지연하지 않음 / `S4ChainStage`가 `FinalsPhase`와 섞이지 않음 / 관측되지 않은 `session_id`·`vehicle_id`·`MissionState`를 요구하지 않음 / 예선 합성 score를 threshold로 사용하지 않음.

### 15.6 SLA와 FinalsPhase 회귀

각 관측 profile의 정상 요청이 `ACCEPT`되고 application response가 유지됨 / **각 새 DROP rule마다 100회 SLA pattern 성격의 정상 fixture 회귀** / `FinalsPhase N` fixture set이 `L1`~`LN`을 모두 포함 / `FinalsPhase 4`에서 `L1`~`L4` 정상 회귀와 rule 회귀 모두 실행 / **UAV fixture에 맞춘 rule이 근거 없이 UGV fixture에 적용되지 않음** / 새 rule 활성화 전후 false positive count와 rollback 조건 기록.

### 15.7 비동기·로그·보안

LLM disabled·timeout·429·malformed response에서 verdict와 HEARTBEAT 정상 / LLM 출력이 policy를 직접 변경하지 않음 / token·API key·raw payload·flag·credential이 로그와 prompt에 없음 / queue drop, parser failure, rule match, latency가 비민감 reason code로 관측 가능 / PCAP·로그·cache·생성 결과가 Git에 추가되지 않음.

### 15.8 공식 스켈레톤 통합

`scripts/validate-skeleton.ps1` 통과 / 공식 Broker에 연결해 HEARTBEAT·PACKET·VERDICT 왕복 검증 / 에이전트 미기동·kill 시 Broker fail-open 관측 / 300ms 초과 시 Broker DROP 관측 / Round 재시작을 모사해 in-memory state 초기화 확인 / 스켈레톤 파일을 수정하지 않고 Compose override 또는 Docker 담당 경계에서만 연결.

---

## 16. FinalsPhase 1~4 적응 전략

본선은 4개 `FinalsPhase`, 총 14개 Round다. 새 레이어가 열려도 이전 레이어는 닫히지 않는 **누적 개방** 구조다.

| `FinalsPhase` | Round | 새 레이어 | 누적 개방 | 방어 초기 목표 |
|---|---|---|---|---|
| 1 | R1–R2 | Layer 1 위성망 게이트웨이 | L1 | 정상 트래픽 기준선, parser 안전성, HEARTBEAT·latency 안정화 |
| 2 | R3–R6 | Layer 2 임무 통제 서버(MCS) | L1~L2 | MCS 트래픽 fingerprint, 세션·명령 패턴 후보 검증 |
| 3 | R7–R10 | Layer 3 무인이동체(UAV) | L1~L3 | UAV telemetry·command 후보를 별도 parser로 검증 |
| 4 | R11–R14 | Layer 4 사족보행 로봇(UGV) | L1~L4 | UGV를 UAV와 별도 profile로 식별, 전체 레이어 회귀 |

이 표는 프로토콜이나 취약점 목록이 아니다. 위성망 게이트웨이를 예선 Communication 세그먼트와 동일시하거나 MCS를 GCS와 동일시하지 않는다. **UAV parser와 threshold를 UGV에 복사하지 않는다.**

### 16.1 하나의 누적 적응형 런타임

`FinalsPhase`별로 네 개의 이미지나 독립 프로그램을 만들지 않는다.

- 공식 환경변수는 `AGENT_SOCKET`, `LLM_BASE_URL`, `LLM_API_KEY`뿐이다.
- 공식 계약에 없는 `PHASE`, `LAYER`, `ROUND`, `TEAM_ID` 환경변수를 요구하지 않는다.
- `raw_ip`의 검증된 field로 `ObservedTrafficProfile`을 만들어 레이어를 추정한다.
- destination subnet·port·protocol을 레이어 식별에 쓰려면 실제 Broker packet과 fixture로 일치를 먼저 증명한다.
- 새 레이어가 열려도 이전 레이어의 정상 fixture와 검증된 rule을 계속 회귀 테스트한다.
- protocol을 식별하지 못한 패킷은 공격으로 간주하지 않고 빠르게 `ACCEPT`한다.

### 16.2 Round별 목표

초기 운영 가설이며, 실제 로그·PCAP·flag 탈취 결과·SLA 결과가 다르면 관측 증거를 우선해 순서를 바꾼다.

| `FinalsPhase` | Round 1 | Round 2 | Round 3 | Round 4 |
|---|---|---|---|---|
| 1 | L1 정상 packet inventory, HEARTBEAT·verdict latency 기준선 측정, 전량 로깅 | 고신뢰 rule 후보 검증, 정상 SLA fixture 회귀, parser 오류 제거 | 해당 없음 | 해당 없음 |
| 2 | 새 MCS traffic fingerprint와 L1 회귀 | 검증된 protocol에서만 S1 명령·세션 패턴 후보 분석 | L1↔L2 온라인 상관 키 검증과 오탐 측정 | 효과 없는 rule 제거, 검증된 최소 rule 안정화 |
| 3 | 새 UAV protocol 식별과 L1~L2 회귀 | 실제 파라미터 field가 보일 때만 S2 후보 검증 | telemetry·상태 field가 충분할 때만 S3 후보 검증 | 관측된 key가 이어질 때만 L1~L3 `S4ChainStage` 상관 후보 검증 |
| 4 | UGV를 UAV와 다른 profile로 식별, L1~L3 회귀 | UGV 증거로 S2·S3 후보 독립 재검증 | L1~L4 bounded correlation과 `S4ChainStage` 후보 검증 | 고신뢰 rule만 유지, 오탐·latency·메모리 안정화 |

**초반에 욕심내지 않는다.** `FinalsPhase 1`에서 rule을 왕창 넣었다가 SLA가 무너지면 그 Round는 0점이고, 무엇이 문제인지 파악할 데이터도 못 얻는다. 관찰 → rule화 → 검증이 정석이다.

---

## 17. Round·Break 운영 루프

컨테이너와 런타임 메모리는 Round마다 초기화된다(제15조 4항). **학습한 내용은 메모리에서 전부 사라진다.**

```text
현재 Round 20분
  → 에이전트 상태·HEARTBEAT·verdict latency·SLA 관찰
  → 로그·PCAP에서 오탐·미탐·protocol 근거 분석
  → 다음 버전 parser·rule·threshold와 정상 fixture 수정
  → Break 시작 시 최종 테스트와 이미지 빌드
  → Break 전반 5분 안에 Registry push 완료
  → 운영 측 pull 상태 확인
  → 다음 Round에서 새 이미지·SLA 회귀 검증
```

- 운영 측은 다음 Round 시작 5분 전에 `latest` 이미지를 가져간다.
- **Break 후반까지 코드를 작성하는 계획을 세우지 않는다.**
- 실행 중인 컨테이너는 새 push의 영향을 받지 않으며 다음 Round부터 반영된다.
- SLA 급락 시 새 공격 탐지율보다 정상 서비스 복구를 우선하고 직전 검증 이미지로 되돌릴 수 있어야 한다.
- 같은 날 운영진이 일정을 변경하면 현장 공지를 우선한다.

### 17.1 Docker 담당자에게 전달할 정보

빌드와 push는 Docker 담당자 소유다. 방어 담당자는 Break마다 다음을 즉시 전달한다.

- 변경한 parser와 `rule_id` 목록, 각 rule의 승격 상태(`SHADOW`/`CANARY`/`ACTIVE`)
- 측정된 verdict latency 분포와 HEARTBEAT cadence
- 추가·변경된 정상 fixture와 회귀 결과
- rollback 조건과 직전 안전 이미지 태그
- 실행 명령, 필수·선택 환경변수, 런타임 의존성, 테스트 명령
- 정상 시작 로그와 종료 코드, 소켓 mount 요구사항, 비밀값 비출력 검증 결과

빌드·태그·push 자동화 스크립트는 Docker 담당자가 `integration/**` 또는 `scripts/**`에서 소유한다. Registry 주소와 팀 식별자는 운영 자료를 Docker 담당자가 확인해 확정한다.

### 17.2 다음 Round로 가져갈 수 있는 것

protocol·field parser 개선, 고신뢰 rule과 reason code, 민감 내용을 제거한 최소 fixture, false-positive 재현 regression fixture, bounded state의 TTL·capacity 조정, latency·cadence 측정 결과, 실패한 가설과 rollback 기준.

**PCAP 원본, 전체 payload, 자격증명, 토큰, 상대 팀 정보, flag를 이미지나 저장소에 넣지 않는다.** Round 간 상관은 숨은 영속 상태가 아니라 코드·테스트·검토된 설정의 새 버전으로 구현한다.

---

## 18. 차단 요소와 확인 항목

### 18.1 현재 확인되지 않은 자료

다음이 확보되기 전까지 본 설계의 해당 부분은 가설이며, 이를 근거로 `DROP` rule을 활성화하지 않는다.

| 자료 | 상태 | 영향받는 설계 |
|---|---|---|
| 본선 운영세칙 원본 SHA-256 대조 | 미완료 | 조문 인용 전반 |
| 당일 진행 안내 원본 SHA-256 대조 | 미완료 | §17 타임라인 |
| 공식 스켈레톤 `deploy/docs/agent-guide.md` | 미확인 | socket 연결 방향, frame 세부, fail-open 관측 |
| 예선 보고서 PDF 54쪽 전수 매핑 | 미작성 | §3 근거 추적표의 페이지 열, 예선 개념 재분류 |
| 예선 소스 snapshot | 미제공 | Correlation Engine·Det-AI 구조 직접 검증 |

`docs/references/preliminary-report-defender-map.md`와 `research/defense-mapping.md`는 이 자료가 확보된 뒤 별도로 작성한다. 본 문서는 그 두 산출물과 모순되지 않아야 하며, 상충이 생기면 상위 근거를 우선하고 차이를 기록한다.

### 18.2 오리엔테이션에서 확인할 항목

- Broker socket에 에이전트가 `connect`하는가, 에이전트가 bind하고 Broker가 붙는가
- **아웃바운드 패킷도 Broker가 전달하는가** (축 C 가능 여부 결정)
- **SLA 체커가 flag를 읽어가는 방식인가** (아웃바운드 필터 자폭 여부 결정)
- SLA check 트래픽이 진입 IP를 통해 오는가, 별도 경로인가
- 각 레이어에 열려 있는 실제 포트·프로토콜 목록 (포트 게이트 활성화 조건)
- flag 형식과 정규식 사용 가능 여부
- 300ms 시한의 기준점이 Broker send 시점인가 agent recv 시점인가
- `pkt_len`과 실제 payload 길이가 다른 프레임의 공식 처리 정책
- IPv6 패킷이 전달되는가
- LiteLLM Proxy가 제공하는 모델 목록과 팀별 쿼터

### 18.3 상위 자료 충돌 처리

공식 계약의 오류를 발견하면 이번 브랜치에서 조용히 수정하지 않는다. 충돌 내용, 근거 경로, 설계 영향만 기록하고 팀장 이경준에게 확인을 요청한다.

---

## 19. 구현 우선순위

```text
1순위  절대 안 죽는 골격 — 소켓 재연결, HEARTBEAT 분리, Deadline Guard, 예외 시 ACCEPT
2순위  전량 로깅과 latency 측정 — 모든 rule의 원재료
3순위  SLA 서킷 브레이커
4순위  Gate 구조 검증 + Sig 기본 시그니처 (관찰 전용으로 시작)
5순위  Break 운영 루프와 Docker 담당자 인계 절차
6순위  Score 세션 행위 + 비동기 Corr
7순위  Advisory LLM rule 후보 생성 (SHADOW 전제)
8순위  축 C 아웃바운드 필터 (§18.2 확인 후에만)
```

**1~3순위가 없으면 4순위 이하는 전부 무의미하다.** 화려한 탐지보다 죽지 않는 것이 먼저다.

구현 순서는 승인 후 `feat/defender-runtime-foundation` 브랜치에서 테스트 우선으로 진행한다. 첫 순서는 Broker frame codec, session·HEARTBEAT, `ACCEPT` 전용 timing baseline, bounded parser, 결정론적 policy, 비동기 event 경계다. 고신뢰 `DROP` rule과 application parser는 정상 negative fixture와 SLA 회귀가 확보된 뒤 별도 짧은 브랜치로 추가한다.
