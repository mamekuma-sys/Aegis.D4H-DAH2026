# 본선 방어 에이전트 한눈에 이해하기

이 문서는 코드를 처음 보는 팀원도 방어 에이전트의 역할과 실행 흐름을 설명할 수 있도록 만든 입문용 문서다. 상세 설계는 [`2026-08-11-defender-runtime-design.md`](superpowers/specs/2026-08-11-defender-runtime-design.md), 실제 코드는 [`agents/defender`](../agents/defender)에서 확인한다.

## 30초 설명

방어 에이전트는 공식 Broker가 보내는 네트워크 패킷을 받아 **300ms 안에 `ACCEPT` 또는 `DROP`**을 돌려주는 독립 Docker 프로그램이다. 빠른 판정 경로에서는 관측으로 검증된 규칙만 사용한다. 여러 패킷을 모아 보는 상관분석, 로그, 이상 징후 감시, LLM 조언은 판정을 보낸 뒤 별도 worker에서 처리한다.

한 문장으로 줄이면 다음과 같다.

> **빠르고 보수적인 패킷 판정과 느린 보조 분석을 분리한 실시간 네트워크 경비원**이다.

## 쉬운 비유

공항 보안 검색대라고 생각하면 쉽다.

1. Broker가 승객 한 명, 즉 패킷 하나를 검색대로 보낸다.
2. 검색대는 신분 확인과 검증된 위험 물품 규칙을 빠르게 검사한다.
3. 위험이 정확히 확인되면 `DROP`, 아니면 `ACCEPT`를 보낸다.
4. 관찰 기록은 뒤쪽 분석실로 전달해 여러 사건의 연관성을 본다.
5. 분석실과 LLM이 느려지거나 멈춰도 앞쪽 검색대는 계속 동작한다.

핵심은 **판정에 필요한 짧은 길과 연구·분석을 위한 긴 길을 섞지 않는 것**이다.

## 입력과 출력

| 구분 | 내용 | 초보자용 설명 |
|---|---|---|
| 입력 | `AGENT_SOCKET` | 공식 Broker와 통신하는 Unix 소켓 경로 |
| 입력 | `PACKET` frame | 패킷 번호와 raw IP packet |
| 선택 입력 | `LLM_BASE_URL`, `LLM_API_KEY` | 판정이 아닌 다음 규칙 후보를 위한 비동기 조언 |
| 출력 | `VERDICT` frame | 패킷 번호와 `ACCEPT(0)` 또는 `DROP(1)` |
| 출력 | `HEARTBEAT` | 에이전트가 살아 있음을 약 1초마다 Broker에 알림 |
| 출력 | 메트릭·감사 로그 | 지연, 규칙 hit, 재연결, worker 상태를 비민감 형태로 기록 |

방어 에이전트는 `PORTS`, `TARGETS`, `PHASE`, `LAYER`, `ROUND`, `TEAM_ID`를 입력으로 받지 않는다. 실제로 들어온 raw IP packet에서 보이는 정보만 사용한다.

## 전체 실행 흐름

```text
네트워크 패킷
      │
      ▼
공식 Router / Broker
      │ PACKET
      ▼
제한된 IP·TCP·UDP 파싱
      │
      ▼
Gate → Sig → Score
      │
      ▼
ACCEPT 또는 DROP 결정
      │
      ▼
단일 SocketWriter가 VERDICT 전송
      │
      └──────────── 판정 이후 ────────────┐
                                          ▼
                            상관분석·이상감시·로그·LLM 조언
```

### 1. Broker 연결과 생존 신호

컨테이너는 `/run/agent.sock`의 `AF_UNIX/SOCK_SEQPACKET` 소켓으로 공식 Broker에 연결한다. Broker는 패킷을 보내고 방어 에이전트는 verdict와 heartbeat를 돌려준다.

처음 연결할 때는 startup 무방비 시간을 줄이기 위해 2ms 간격으로 최대 2초 동안 빠르게 소켓을 확인한다. 연결이 끊긴 뒤에는 Broker를 과도하게 두드리지 않도록 최대 1초의 지수 backoff로 계속 재연결한다.

### 2. 제한된 파싱

`PACKET` frame에서 IPv4·IPv6와 필요한 TCP·UDP 필드만 상한을 두고 파싱한다. 계약되지 않은 차량 상태, 임무 의미, 파라미터 hash 같은 정보는 사용하지 않는다. frame이나 packet을 해석하지 못해도 그것만으로 공격이라고 판단하지 않는다.

HTTP 요청이 여러 TCP segment로 나뉜 경우에는 단일 producer가 최대 4KiB, 2,048 flows, 5초 TTL 범위에서 header만 이어 붙인다. 순서가 비거나 너무 크거나 완성되지 않으면 상태를 버리고 `ACCEPT`한다. 범용 TCP 재조립으로 확대하지 않아 지연과 메모리를 제한한다.

### 3. 300ms 안의 빠른 판정

실제 판정은 세 단계다.

| 단계 | 하는 일 | 기본 태도 |
|---|---|---|
| Gate | frame·파싱 상태, 명시적 TCP flag 규칙, 검증된 allow 조건 확인 | 불확실하면 `ACCEPT` |
| Sig | 사전 컴파일된 정규식과 HTTP 의미 규칙으로 확인된 공격 형태 검사 | `ACTIVE` 규칙만 차단 |
| Score | 별도 worker가 발행한 만료되지 않은 상관분석 snapshot을 한 번 조회 | snapshot이 없거나 오래되면 넘어감 |

판정 도중 내부 soft cutoff를 넘으면 더 분석하지 않고 `ACCEPT`한다. 정책 예외도 밖으로 퍼뜨리지 않고 `ACCEPT`한다. verdict 전송의 내부 hard cutoff는 200ms이며 공식 Broker deadline은 300ms다.

이런 보수적 처리를 **fail-open**이라고 부른다. 잘못된 파싱이나 내부 장애로 정상 트래픽 전체가 막히는 상황을 피하기 위한 선택이다. 단, Broker가 verdict를 300ms 안에 받지 못하면 공식 동작에 따라 해당 패킷은 `DROP`된다.

### 4. 검증된 규칙만 차단

정책은 이미지에 포함된 versioned `PolicyBundle`에서 읽는다. 현재 실제 차단이 가능한 `ACTIVE` 규칙은 관측 PCAP에서 플래그 탈취와 연결이 확인된 형태다.

| 레이어 | 현재 `ACTIVE`로 다루는 주요 형태 |
|---|---|
| L1 | helper secret SSRF, config flag traversal |
| L2 | 위조된 admin session, loopback secret·registry SSRF |
| L3 | `app_meta` 대상 SQL injection |
| L4·기타 | 관측 근거가 생기기 전에는 자동 차단하지 않음 |

휴리스틱 규칙은 `SHADOW`로 두어 “탐지됐음”만 기록하고 패킷은 통과시킨다. allow 규칙과 차단 규칙이 동시에 맞는 conflict에서도 서비스 가용성을 위해 `ACCEPT`한다. 규칙의 승격·강등은 라운드 중 트래픽이 자동으로 바꾸지 못하며, 검증과 사람 승인을 거쳐 다음 이미지에 반영한다.

### 5. verdict는 한 writer만 전송

패킷 판정 worker, heartbeat worker, 로그 worker가 같은 소켓에 직접 쓰면 frame이 섞이거나 순서가 깨질 수 있다. 그래서 모든 출력은 bounded 우선순위 queue에 넣고 `SocketWriter` 한 스레드만 실제 소켓에 쓴다.

각 연결에는 session generation 번호를 붙인다. 이전 연결에서 늦게 도착한 성공·실패 결과가 새 연결을 끊거나 오래된 verdict를 재전송하지 못하게 한다. queue가 가득 차거나 전송 deadline을 넘기면 해당 session을 폐기하고 새로 연결한다.

### 6. 판정 뒤의 비동기 상관분석

verdict를 queue에 넣은 뒤, 필요한 특징만 bounded event queue에 기록한다. correlation worker는 flow별 짧은 이력을 모아 점수를 계산하고 **변경할 수 없는 snapshot**을 새로 발행한다. 빠른 판정 경로는 함수 시작 때 snapshot을 한 번만 읽으므로 분석 도중 데이터가 바뀌는 경합을 피한다.

event queue가 가득 차면 최신 분석 event를 버릴 뿐 현재 패킷을 차단하지 않는다. 상관분석은 방어를 보조하지만 300ms verdict보다 우선하지 않는다.

### 7. LLM은 판정 권한이 없는 조언자

원격 LLM은 패킷별 동기 경로에 절대 들어가지 않는다. 상관분석 snapshot의 상위 5개 flow를 protocol, port, score 같은 집계값으로만 요약해 다음 `SHADOW` 규칙 후보를 요청한다.

- raw payload, 플래그, token, 전체 PCAP, 인증 header를 보내지 않는다.
- 최소 60초 간격, 라운드당 최대 20회만 호출한다.
- LLM 결과는 현재나 다음 packet의 verdict를 바꿀 수 없다.
- 사람이 Break 시간에 검토하고 검증해야만 다음 이미지의 정책 후보가 된다.
- LLM 키가 없거나 호출이 실패해도 verdict와 heartbeat에는 영향이 없다.

### 8. 감시와 자동 복구

`WorkerWatchdog`은 writer, heartbeat, correlation, audit, 선택적 advisory worker가 살아 있는지 확인한다. worker가 죽으면 bounded worker를 다시 시작한다. writer나 heartbeat처럼 연결에 중요한 worker가 재시작되면 기존 session을 버리고 새 generation으로 연결해 상태 혼합을 막는다.

이상 징후 monitor는 drop 비율, parser 실패, 특정 규칙 집중 등을 알림으로만 남긴다. 공격자가 트래픽을 조작해 정책을 자동 승격·롤백하도록 만들 수 없게 runtime policy를 수정할 권한이 없다.

## 주요 코드 지도

| 파일 | 역할 |
|---|---|
| `protocol.py` | PACKET·VERDICT·HEARTBEAT frame 형식 |
| `session.py` | Broker 연결·재연결, 출력 queue, 단일 writer |
| `heartbeat.py` | session별 생존 신호 관리 |
| `packet.py` | 상한 있는 IP·TCP·UDP 파싱 |
| `stream.py`, `http_semantics.py` | bounded HTTP header 연결과 의미 기반 검사 |
| `rules.py` | `PolicyBundle` 검증, 규칙 사전 컴파일, 안전한 강등 |
| `policy.py` | Gate → Sig → Score와 최종 verdict |
| `state.py`, `correlation/` | 비동기 flow 상관분석과 immutable snapshot |
| `advisory.py` | 권한 없는 비동기 LLM 조언 |
| `anomaly.py`, `metrics.py` | alert-only 이상 감시와 지연·상태 측정 |
| `watchdog.py` | helper worker 상태 확인과 재기동 |
| `main.py` | 모든 구성요소를 배선한 `DefenderRuntime` |
| `__main__.py` | 컨테이너 진입점 `python -m aegis_defender` |

## 왜 이렇게 설계했나

- **시간 계약 준수:** 패킷별 verdict는 300ms 안에 돌아가야 한다.
- **가용성 우선:** 파싱 오류나 내부 예외를 공격으로 오인해 정상 서비스를 막지 않는다.
- **검증된 차단:** PCAP과 정상 fixture로 확인된 규칙만 `ACTIVE`로 집행한다.
- **느린 작업 분리:** 상관분석, 로그, LLM 장애가 packet 처리를 기다리게 하지 않는다.
- **상태 경합 방지:** 단일 writer와 session generation으로 오래된 결과를 격리한다.
- **정책 오염 방지:** 트래픽과 LLM은 runtime policy를 자동 변경할 권한이 없다.

## 현재 한계와 당일 확인 사항

- 에이전트가 Broker에 연결되기 전에는 Broker가 fail-open으로 패킷을 통과시킨다. 리허설의 A1D1 seed 404에서는 session 준비 17ms 전에 플래그 3개의 startup capture가 남았다. 연결 전 패킷은 에이전트가 볼 수 없으므로 초기 연결을 최대한 빠르게 하는 방향으로만 줄일 수 있다.
- L4의 실제 공격 인터페이스가 관측되지 않았으므로 근거 없는 L4 차단 규칙을 활성화하지 않았다.
- 리허설 결과와 로컬 검증은 양호하지만, 현재 최종 판정은 `NOT_READY/HOLD`를 유지한다. 현장에서 계약된 socket·LLM 값을 주입하고 공식 환경의 연결, blind traffic, score, SLA를 확인한 뒤 이미지를 승격·push한다. 팀 번호와 제출 토큰은 공격 이미지 쪽 입력이며 방어 판정에는 사용하지 않는다.
- Docker 이미지는 `linux/amd64`, Python 3.12, 비특권 UID 65534로 실행한다.

## 자주 받을 질문과 답변

### “왜 의심스러우면 전부 막지 않나요?”

오탐으로 정상 서비스를 막으면 가용성 점수가 무너지고, 공격자가 malformed packet으로 우리 방어를 장애물로 만들 수도 있다. 그래서 관측으로 확인된 공격만 막고 불확실한 경우는 기록한 뒤 통과시킨다.

### “300ms 동안 LLM이 판단하나요?”

아니다. 패킷 판정은 사전 컴파일된 결정론 규칙과 이미 발행된 snapshot만 사용한다. LLM은 verdict 이후 집계 정보로 다음 규칙 후보만 제안한다.

### “패킷이 여러 조각으로 나뉘면 우회되지 않나요?”

HTTP header는 제한된 범위에서 TCP segment를 이어 붙여 검사한다. 다만 gap, 과대, 미완성 흐름을 무리하게 추측하지 않고 `ACCEPT`해 지연과 오탐을 제한한다.

### “방어 프로세스가 죽거나 소켓이 끊기면요?”

watchdog과 재연결 루프가 worker와 session을 복구한다. 이전 session의 늦은 결과는 generation 검사로 새 연결에 영향을 주지 못한다.

### “규칙은 경기 중 자동으로 학습해서 바로 차단하나요?”

아니다. runtime은 관측과 후보만 기록한다. 새 규칙은 `SHADOW`에서 PCAP, 정상 fixture, 지연 검증과 사람 승인을 거친 뒤 다음 이미지에 반영한다.

### “현재 완전히 준비된 상태인가요?”

코드와 리허설 검증은 완료했지만 startup pre-session 위험과 현장 공식 환경 확인이 남아 있어 문서상 `NOT_READY/HOLD`다. 현장 값 주입과 최종 검증 후 승격하는 것이 정확한 답이다.

## 발표할 때 그대로 말할 수 있는 설명

> 저희 방어 에이전트는 공식 Broker의 raw IP packet을 받아 300ms 안에 ACCEPT 또는 DROP을 돌려주는 독립 Docker 이미지입니다. 빠른 경로는 제한된 파서와 Gate, 사전 컴파일된 signature, 이미 발행된 correlation snapshot만 사용합니다. 관측 PCAP으로 검증된 ACTIVE 규칙만 차단하고 불확실하거나 오류가 나면 가용성을 위해 ACCEPT합니다. 여러 패킷을 모으는 상관분석, 이상 감시, 로그, LLM 조언은 verdict 이후 별도 worker에서 실행해 300ms 경로를 막지 않습니다. LLM은 정책을 직접 바꿀 권한이 없고 새 SHADOW 후보만 제안합니다.
