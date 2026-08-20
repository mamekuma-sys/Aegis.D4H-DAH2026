# Defender owner 리뷰 — PR #12, PR #13

- 리뷰어: Defender owner
- 날짜: 2026-08-20
- 대상: PR #12 `feat/finals-evidence-candidate`, PR #13 `feat/break-copilot`
- 근거 문서: `docs/validation/2026-08-20-finals-candidate-verdict.md`,
  `docs/reviews/2026-08-20-capture-log-forensics.md`

## 0. 결론 요약

| 항목 | 판정 |
|---|---|
| PR #12 P0 `MATCH-A1D1-S404`·`S405` startup fail-open | 근본 원인 규명, 코드 수정·회귀 테스트 완료. **실측 재현은 미완** |
| PR #12 P1 `PCAP-001`–`104` 일반화 | Broker E2E mutation 테스트 12건 추가, 전부 PASS |
| PR #12 defender 파일 4건 (junny048) | 방향 타당, 수정 없이 승인. 테스트 1건 보강 |
| PR #13 단일-side patch 범위 | 기계적으로 강제됨. 승인 |
| PR #13 테스트·replay gate | 강제됨. 승인 |
| PR #13 defender 300ms 동기 LLM 미추가 | 강제되나 **간접적**. 조건부 승인 |

## 1. P0 `MATCH-A1D1-S404`·`S405` — startup fail-open

### 1.1 fail-open은 우리 코드가 아니다

공식 스켈레톤 `router/entrypoint.sh`가 NFQUEUE를 다음과 같이 건다.

```
iptables -A FORWARD -d "$LAB_SUBNET" -j NFQUEUE --queue-num 0 --queue-bypass
```

`--queue-bypass`는 큐에 바인딩된 프로세스가 없을 때 패킷을 **ACCEPT**한다.
Broker는 운영진이 제공하는 정적 링크 ELF 바이너리(9.8MB)이고 설정 표면은
`broker.yaml`의 소켓 경로·권한·`metrics_reset_on_connect`뿐이다. 바이너리 문자열에도
fail-closed나 "agent 연결까지 대기" 옵션은 없다.

→ **fail-open 동작 자체는 우리가 끌 수 없다.** 인수인계 4번의 "fail-closed 변경
금지"는 정책 선택이 아니라 물리적 제약이다. 창을 줄이는 유일한 수단은 socket이
열리자마자 붙는 것이다.

### 1.2 근본 원인 — 지수 backoff의 과다 대기

`session.py`의 최초 연결이 재연결과 같은 지수 backoff를 썼다.

```
BACKOFF_INITIAL = 0.05, BACKOFF_FACTOR = 2.0
→ 시도 시각 0, 50, 150, 350, 750ms
```

socket이 시도와 시도 사이에 열리면 그 간격 전체가 fail-open이 된다. 최악은
socket이 360ms에 열릴 때로, 750ms까지 **390ms**를 더 잔다.

관측치(D1 victim session 연결 offset 399–518ms)는 起動 비용만으로 설명되지 않는다.
로컬 계측상 defender 起動은 65ms다.

| 단계 | 누적 |
|---|---|
| 인터프리터 기동 | 18.5ms |
| import 완료 | 60.8ms |
| config | 60.9ms |
| `DefenderRuntime.__init__` (policy load) | 64.6ms |
| `start_workers()` | 64.9ms |
| 첫 connect 호출 | 64.9ms |

`start_workers()`는 0.3ms로 起動 순서 문제가 아니다. 남는 것은 backoff 대기이며,
관측된 399–518ms는 시도 일정의 4번째 지점(t0+350ms)과 정합한다.

### 1.3 수정

`_connect_with_backoff`가 최초 연결과 재연결을 구분한다.

- 아직 한 번도 붙지 않았고 `STARTUP_FAST_WINDOW`(2.0s) 안이면 `STARTUP_POLL_INTERVAL`
  (2ms) 고정 간격으로 폴링한다.
- 그 창을 넘기거나 이미 붙은 적이 있으면 기존 지수 backoff를 그대로 쓴다. 장애 중
  broker를 두드리지 않기 위해서다(§4.2 유지).
- 2ms 폴링 중 audit은 첫 실패만 남긴다. 나머지는 `connect_attempts`로 관찰한다.

**verdict·policy 의미는 바꾸지 않았고, fail-open을 fail-closed로 바꾸지도 않았다.**
붙는 시점만 앞당긴다. 따라서 인수인계 4번의 3인 승인 조항에 해당하지 않는다.

### 1.4 회귀 테스트

`agents/defender/tests/test_session.py::TestStartupConnectRace`

- `test_startup_connect_does_not_overshoot_the_fail_open_window`
  socket이 50·120·300·360·500ms에 열리는 각 경우에 overshoot ≤ 10ms를 요구한다.
  수정 전에는 4/5 subTest 실패(최대 390ms), 수정 후 전부 PASS.
- `test_reconnect_keeps_exponential_backoff`
  재연결은 `[0.05, 0.1, 0.2, 0.4, 0.8]`을 그대로 유지하는지 고정한다.

### 1.5 남은 검증 — **이 PR의 P0를 아직 해제하지 못한다**

해제 조건은 "fresh 5 seed에서 pre-session capture 0"이다. 그 확인은 실제 Broker와
NFQUEUE가 필요하고 `nfnetlink_queue`를 지원하는 Linux x86-64 호스트에서만 돌아간다.
현재 리뷰 환경(macOS)에서는 실행할 수 없었다.

**따라서 P0는 "원인 규명·수정 완료, 실측 미검증" 상태로 남긴다.** Docker owner가
Linux 호스트에서 fresh 5 seed 매트릭스를 재실행해 pre-session capture 0을 확인해야
비로소 해제된다.

## 2. P1 `PCAP-001`–`104` — TCP·부하 일반화

해제 조건인 "encoding·TCP split·retransmit·worker death·reconnect mutation 통과"를
Broker E2E 수준에서 덮는 테스트를 추가했다.

`agents/defender/tests/test_broker_mutation.py` (12건, 전부 PASS)

| 분류 | 테스트 |
|---|---|
| encoding | 등가 표기(percent-decoding, query 순서·추가 파라미터) 차단 |
| encoding (negative) | 정상 트래픽 오탐 없음, 대소문자 변형 확장 금지 가드 |
| split | 분할 exploit을 완성 패킷에서 차단 |
| retransmit | 정확한 재전송·겹치는 재전송 뒤에도 차단 |
| 순서 뒤바뀜 | 모든 패킷이 verdict를 받음(가용성) |
| reconnect | 세션 경계를 넘는 분할, 재연결 후 exploit 차단 |
| worker death | 비critical·critical worker 사망 후 watchdog 재시작, 재시작 뒤 차단 유지 |

기존 replay 테스트는 policy만, stitcher 테스트는 `HotPolicy`만 본다. 이 파일은 frame
수신 → parser → stitcher → policy → verdict queue → writer 전 구간을 실제 세션 위에서
돌린다. **새 ACTIVE rule은 추가하지 않았다.**

### 2.1 열린 질문 — L2 경로 대소문자

`/ADMIN?`은 현재 ACCEPT된다. HTTP path는 대소문자를 구분하고(RFC 9110 §4.2.3,
RFC 3986 §6.2.2.1) 공식 스켈레톤 L2도 Flask `@app.route("/admin")`이라 `/ADMIN`은
admin 핸들러에 닿지 않는다. 즉 현재 동작이 옳고, 막으면 근거 없는 확장이다
(GAP-005). 오탐 가드로 고정해 두었다.

다만 운영진이 "데모 문제는 본선과 무관"이라고 명시했으므로 본선 L2가 실제로
대소문자를 구분하는지는 확정할 수 없다. **당일 첫 capture로 확인이 필요하고,
대소문자 무시로 밝혀지면 가드와 rule을 함께 바꿔야 한다 — 방어자 owner + 팀장
승인 사항이다.**

## 3. junny048의 defender 파일 변경 4건

`AGENTS.md`상 defender Python·tests는 Defender owner 소유이고 "Docker owner must not
change strategy code unilaterally"가 적용된다. 4건 모두 확인했고 **verdict 로직은
건드리지 않는다.** 수정 요구 없이 승인한다.

| 파일 | 변경 | 판정 |
|---|---|---|
| `src/aegis_defender/advisory.py` | `urllib.request`·`urllib.error`를 함수 지역 import로 이동 | 타당. 두 곳 모두 사용 지점과 같은 스코프에서 import되며 다른 진입 경로 없음 |
| `Dockerfile` | `RUN python -m compileall -q -f /app/aegis_defender` | 타당. `CMD`가 `-O` 없이 실행하므로 최적화 레벨이 일치한다 |
| `tests/test_startup_imports.py` | 신규 | 방향 타당, 아래 보강 |
| `tests/test_round_lifecycle.py` | 16줄 | 문제 없음 |

`compileall`은 load-bearing이다. `USER 65534`가 뒤에 오므로 `__pycache__`는 root
소유가 되고, 만약 bytecode가 없거나 무효하면 런타임 사용자는 캐시를 쓸 수 없어 매
기동마다 컴파일 비용을 다시 낸다.

### 3.1 보강한 것

`test_startup_imports.py`가 `urllib.request`만 검사해 `urllib.error`는 무방비였다.
둘 다 검사하도록 넓히고 실패 시 어떤 모듈이 올라왔는지 출력하게 했다.

### 3.2 효과 크기에 대한 단서

두 perf 변경의 실측 이득은 cold 72ms → warm 44ms, 즉 **28ms**다. 방향은 맞지만
390ms 문제에는 한 자릿수 부족하다. §1.3의 backoff 수정이 본체다.

## 4. PR #13 — 단일-side patch 범위

`scripts/break_copilot/patching.py`가 기계적으로 강제한다.

- `side`는 `attacker`·`defender`만 허용
- `_allowed_patch_path`: 절대경로 거부, `..` 거부, **`.py`만 허용**,
  `agents/{side}/src` 또는 `agents/{side}/tests` 하위만 허용
- 양쪽 동시 변경을 별도로 재차 거부
- rename·delete·mode·submodule 변경 거부, 새 파일은 `100644`만
- 크기·파일 수·추가 라인 상한, 추가 라인 비밀정보 스캔

`.py` 한정이 중요하다. 그 결과 copilot은 `agents/defender/policy/*.json`,
`contracts/**`, Dockerfile을 **패치할 수 없다.** "LLM 판단만으로 ACTIVE 방어 규칙
승격 금지"가 프롬프트가 아니라 코드로 막힌다. 승인한다.

## 5. PR #13 — 테스트·replay gate

`scripts/break_copilot/evaluate.py`가 고정된 비-LLM 검사를 돌리고 하나라도 실패하면
전체 `status`가 `FAIL`이 된다.

`patch_scope`, `image_check`, `{side}_unit_tests`, `git_diff_check`,
`repository_layout`, `skeleton_contract`(선택), `defender_pcap_replay`(defender 전용).

PCAP replay를 attacker candidate에서 요청하면 거부한다. 승인한다.

## 6. PR #13 — defender 300ms 동기 verdict 경로 LLM 미추가

PR #13은 `agents/defender/**`를 **0건** 변경한다. 추가된 것은
`contracts/break-copilot/**` 스키마 6개와 `contracts/README.md` 뿐이다.

런타임 도입 가능성도 막혀 있다. 다만 경로가 간접적이라 조건부 승인이다.

- copilot은 `agents/defender/src/**/*.py`를 패치할 수 있고 여기에는 `policy.py`·
  `session.py` 등 hot path가 포함된다.
- `evaluate.py`에는 "hot path에 LLM 없음"을 직접 보는 검사가 **없다.**
  `llm.py`의 `defender_safety` hard gate는 모델에게 주는 프롬프트 지시일 뿐이다.
- 실질 차단은 `{side}_unit_tests`가 defender 자체 테스트를 돌리는 데서 나온다.
  `test_timing.py::test_load_profiles_stay_within_budget`이 hot path p99 < 500µs를
  단언하므로, 동기 네트워크 호출이 들어오면 밀리초 단위로 초과해 반드시 실패한다.

### 6.1 지적

`BUDGET_HOT_PATH_P99`는 `test_timing.py` 지역 상수이고
`test_budget_constants_match_the_design`이 고정하는 대상에 **포함되지 않는다.**
누군가 이 값을 완화하면 동기 LLM 차단이 조용히 사라진다. 설계 상수와 같은 급으로
고정하거나, `evaluate.py`에 hot path 모듈 대상의 명시적 검사를 두는 편이 낫다.

이 지적은 PR #13의 머지 조건이 아니라 후속 항목으로 제안한다.

## 7. 검증 실행 결과

- `agents/defender` unittest: **355 PASS**, 환경 capability skip 2
  (기존 341 + startup race 2 + Broker mutation 12)
- hot path p99: 1/100/550/1100 pkt/s 전 구간 48.9–54.8µs, 300ms 초과 0
- policy p99: 37.8µs
- `bash scripts/check-layout.sh`: PASS

## 8. 승인 상태

| 대상 | 상태 |
|---|---|
| PR #13 | **승인** (§6.1은 후속 제안) |
| PR #12 | **조건부** — §1.5의 Linux 실측(fresh 5 seed, pre-session capture 0)이 남았다 |

PR #12의 판정은 여전히 `NOT_READY / HOLD`이며, 이 리뷰는 P0 두 건 중 방어자 몫의
원인·수정·회귀만 해소한다. `MATCH-A1D0-S404` 공격 효과 회귀는 Attacker owner 몫으로
남아 있다.
