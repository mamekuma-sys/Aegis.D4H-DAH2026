# Defender

방어 담당자 작업 영역입니다. 설계 근거는 `docs/superpowers/specs/2026-08-11-defender-runtime-design.md`이며, 아래 §는 모두 그 문서를 가리킵니다.

PACKET 수신 → 제한된 파싱 → 300ms 이내 결정론적 판정 → VERDICT 송신 → 비동기 상관분석.

## 설계의 세 가지 불변조건

1. **불확실하면 빠르게 `ACCEPT`한다.** parser 예외, 미지원 protocol, queue full, LLM 장애는 어느 것도 `DROP` 사유가 아닙니다(§6.2). 파싱 실패를 차단으로 바꾸는 순간 공격자는 malformed 패킷만 보내서 우리가 정상 트래픽을 막게 만들 수 있습니다.
2. **소켓에 쓰는 주체는 `SocketWriter` 단일 스레드 하나뿐입니다**(§4.2). 판정 스레드와 HEARTBEAT 스케줄러는 불변 item을 만들어 우선순위 큐에 `put_nowait`할 뿐 `socket.send`를 직접 호출하지 않습니다.

   여기에 따라오는 불변조건이 하나 더 있습니다 — **send 결과는 그 `(transport, session_id)`가 아직 현재 generation일 때만 반영하며, 확인과 상태 전이는 하나의 임계구역에서 원자적으로 수행합니다.** `send`는 lock 밖에서 일어나므로 반환할 때쯤이면 수신 쪽이 EOF를 받아 이미 재연결했을 수 있습니다. 확인과 전이를 나누면 그 사이가 그대로 경합 구간이 되어, 확인은 통과했지만 전이 시점에는 이미 다른 generation인 상태가 됩니다.

   `_claim_fault()`가 "아직 현재인가"와 "그렇다면 지금 소유권을 뺏는다"를 한 lock 안에서 끝내고, `_claim_ready()`가 성공 경로에 같은 규칙을 적용합니다. claim 이후의 통보에는 회수한 session id를 함께 실어, `BrokerSession.request_reconnect()`와 `HeartbeatScheduler.on_sent()`가 각자의 lock 안에서 generation을 다시 확인합니다. 이 통보 경로를 막지 않으면 이전 session의 실패가 새 session의 수신 루프를 중단시켜 그 구간이 fail-open이 됩니다.

   같은 규칙이 HEARTBEAT를 **만드는** 쪽에도 적용됩니다. `HeartbeatScheduler.tick()`은 epoch와 session id를 한 번의 lock hold 안에서 함께 snapshot하고, item에는 큐의 현재 session이 아니라 그 snapshot한 id를 붙입니다. 둘을 따로 읽으면 "이전 epoch에서 계산한 deadline"과 "새 session의 id"가 결합된 item이 만들어지는데, 그 item은 session 검사를 전부 통과하지만 deadline이 이미 지나 있어 writer가 방금 연 소켓을 만료로 닫아버립니다.

   `tests/test_session.py`의 `TestStaleSessionResults`(claim 전후 삽입 포함)·`TestReconnectNotificationScoping`과 `tests/test_heartbeat.py`의 `TestTickGenerationRace`가 회귀 검증합니다.
3. **원격 LLM은 packet별 동기 판정 경로에 들어가지 않습니다**(§0.5, §12). 300ms 시한에 물리적으로 불가능하며, `contracts/defender/README.md`가 이를 계약으로 못박습니다.

진짜 위험은 공격자가 아니라 우리 자신입니다(§0.3). 에이전트가 죽거나 연결이 끊기면 Broker는 fail-open으로 전 패킷을 통과시키고, 판정이 300ms를 넘으면 Broker가 그 패킷을 DROP하며, rule을 잘못 넣으면 SLA가 붕괴합니다. 구조의 절반이 이 셋을 막는 데 쓰입니다.

## 구조

```text
agents/defender/
├── policy/
│   ├── active.json      이번 이미지의 versioned PolicyBundle
│   ├── fallback.json    직전 Round의 검증된 bundle
│   └── README.md        필드 의미, 강등/거부 규칙, Break 승격 절차
├── src/aegis_defender/
│   ├── main.py          DefenderRuntime — lifecycle과 배선
│   ├── __main__.py      python -m aegis_defender
│   ├── config.py        RuntimeConfig (환경변수 3개만)
│   ├── protocol.py      FrameCodec, 미리 컴파일된 struct
│   ├── session.py       BrokerSession(재연결), SocketWriter, VerdictSender, OutboundQueue
│   ├── heartbeat.py     HeartbeatScheduler (세션별 epoch)
│   ├── packet.py        PacketParser (상한 있는 IP/L4)
│   ├── policy.py        HotPolicy (Gate · Sig · Score)
│   ├── rules.py         PolicyLoader, schema 검증, matcher 사전 컴파일
│   ├── anomaly.py       AnomalyMonitor (alert-only)
│   ├── state.py         CorrelationBuilder, SnapshotRef, CorrelationWorker
│   ├── events.py        EventAdapter, drop-newest bounded queue
│   ├── correlation/     window.py · causal.py · risk.py
│   ├── advisory.py      AdvisoryWorker (비동기 LLM 조언)
│   ├── logging.py       AuditLogger (비밀 없는 구조화 로그)
│   └── metrics.py       Metrics
├── tests/               unittest 12개 모듈 + fakes.py
├── Dockerfile           **초안 — Docker 담당자 확정 필요**
└── requirements.txt     표준 라이브러리 전용(비어 있음)
```

스레드는 다섯 개입니다. 수신·판정 producer(메인), `SocketWriter`, HEARTBEAT scheduler, correlation worker, 선택적 advisory. §5.3의 승인된 실행 모델대로 **producer는 하나이고 inbound queue는 없습니다.** producer를 늘리거나 inbound queue를 추가하는 것은 packet ordering·memory 상한·deadline backpressure를 바꾸는 변경이므로 별도 설계 승인이 필요합니다.

## 시간 예산 (§5.2)

| 구간 | 목표 | 실측(개발 머신) |
|---|---:|---:|
| Gate | p99 25μs | p99 ~0.6μs |
| Sig | p99 100μs | p99 ~17μs |
| Score | p99 25μs | p99 ~0.1μs |
| policy 합계 | p99 150μs | p99 ~20μs |
| **hot path 합계** | **p50 150μs, p99 500μs** | **p50 ~17μs, p99 ~28μs** |
| 판정 soft cutoff | 5ms — 분석 포기하고 `ACCEPT` | — |
| 내부 send hard cutoff | 200ms — 로컬 만료·재연결 | — |
| Broker deadline | 300ms | 초과 0건 |
| socket fault timeout | 최대 50ms(정상 예산 아님) | — |

실측은 `python -m unittest tests.test_timing`이 1·100·550·1100 pkt/s 프로파일로 측정해 출력합니다. **측정 환경이 공식 컨테이너와 다르므로**(macOS / Python 3.13 개발 머신), 공식 이미지(`python:3.12-slim`, cpu-shares 2048)에서 다시 측정해 Docker 담당자 인계 자료에 넣어야 합니다(§15.4).

모든 시간은 벽시계가 아니라 monotonic clock으로 잽니다. NTP 보정 한 번이면 "수신 후 300ms" 계산이 통째로 어긋납니다.

## 현재 정책 상태

**모든 rule이 `SHADOW`이고 `baseline_profiles`가 비어 있어 현재 이미지는 어떤 패킷도 차단하지 않습니다.**

의도된 상태입니다. §16.2에 따라 `FinalsPhase 1`의 2개 Round는 관측에 씁니다. 정상 트래픽 baseline과 포트 인벤토리를 확보하기 전에 켠 DROP rule은 오탐 여부조차 판정할 수 없습니다. 로더가 이를 구조적으로도 강제합니다 — `baseline_profiles`가 비면 차단 권한을 가진 rule을 기동 시 전부 `SHADOW`로 강등합니다.

승격 절차와 필드 의미는 `policy/README.md`를 보십시오.

## 테스트

표준 라이브러리 `unittest`만 사용합니다(외부 설치 불필요).

```powershell
cd agents/defender
python -m unittest discover -s tests -t .
```

CI의 `defender-tests` job이 `ubuntu-latest` + Python 3.12(= 이미지와 같은 플랫폼·버전)에서 같은 명령을 실행합니다.

실제 `AF_UNIX`/`SOCK_SEQPACKET` 소켓을 쓰지 않고 fake clock·fake transport로 검증합니다. macOS는 `AF_UNIX`에서 `SOCK_SEQPACKET`을 지원하지 않고 Windows도 마찬가지라, 실제 소켓 기반 테스트는 개발 환경 어디에서도 돌지 않기 때문입니다. 설계 §15.4가 fake 기반 검증을 명시한 것도 같은 이유입니다.

Windows에서도 그대로 돌아갑니다. `AGENT_SOCKET` 검증은 호스트 OS 규칙이 아니라 `posixpath`로 하고(컨테이너 안 Linux 경로이므로), 측정값 출력은 ASCII만 씁니다(CP949 콘솔에서 `µ`가 `UnicodeEncodeError`를 냅니다).

가장 중요한 회귀는 `tests/test_anomaly.py`의 `TestPoisonedTrafficChangesNothing`입니다. 다섯 개 packet-derived 지표를 전부 임계 위로 올려도 promotion state, canary 비율, rule scope, verdict가 하나도 바뀌지 않음을 검증합니다(§15.6).

## 로컬 실행 (환경변수 주입)

```powershell
$env:AGENT_SOCKET="/run/agent.sock"
$env:LLM_BASE_URL="http://litellm.lig.internal:4000"
$env:PYTHONPATH="src"; python -m aegis_defender
```

`LLM_API_KEY`가 없으면 advisory worker를 아예 기동하지 않습니다. 장애가 아니라 정상 동작이며 HEARTBEAT·verdict에 영향이 없습니다.

## 알려진 설계 간극

**flow별 재조립 `Sig` 매칭이 아직 배선되지 않았습니다.**

§9.3은 여러 패킷에 걸친 요청을 잡기 위해 flow별 재조립 버퍼를 두라고 하지만, §8은 `CorrelationEvent`가 원본 payload를 참조하는 것을 금지합니다. 두 조건을 동시에 만족하려면 재조립을 hot path의 공유 상태에 두어야 하는데, 그것은 "builder state를 hot path에 노출하지 않는다"는 §11 경계를 깹니다.

현재는 §8.1의 16KB 상한을 지키는 `FlowReassemblyBuffer`를 검증된 자료구조로만 제공하고 판정 경로에 연결하지 않았습니다. 어느 쪽으로 해결할지는 설계 보완 사항이며, §19 우선순위상 이 브랜치의 범위가 아닙니다(재조립은 1~3순위에 없고, 현재 차단 rule이 하나도 활성화되지 않아 실효 손실도 없습니다). 팀장 검토 시 이 항목을 함께 결정해 주십시오.

`CausalMatcher`의 단계 이름도 관련 결정입니다. 예선 보고서 S4의 1~5 번호를 관측된 증거에 임의로 붙이지 않기 위해(§2), 단계를 `observed-*`로만 명명했습니다. 보고서 단계와의 대응은 본선 PCAP과 fixture 확보 후 `research/defense-mapping.md`에 기록합니다.

## Docker 담당자에게 전달할 정보 (§17.1)

- 실행 명령: `python -u -m aegis_defender` (WORKDIR `/app`, `PYTHONPATH` 불필요)
- 런타임 의존성: **없음**(표준 라이브러리 전용)
- 이미지에 포함해야 할 경로: `src/aegis_defender/` → `/app/aegis_defender`, `policy/` → `/policy`
- 환경변수: `AGENT_SOCKET`(기본 `/run/agent.sock`), `LLM_BASE_URL`, `LLM_API_KEY`
- mount: `/run/agent.sock` (`AF_UNIX`/`SOCK_SEQPACKET`)
- 실행 옵션 전제: `--cap-drop ALL`, `no-new-privileges`, memory reservation 2g, cpu-shares 2048, pids-limit 512, `--add-host litellm.lig.internal`
- 정상 시작 로그: `{"event":"startup", "policy_source":"active", "drop_capable_rules":0, ...}`
- 종료: SIGTERM에서 2초 내 정리 종료, 종료 코드 0
- 비밀 비출력: `FLAG{...}`, API key, Bearer 토큰, raw payload가 로그에 나오지 않음을 `tests/test_advisory.py`의 `TestAuditRedaction`이 검증
