# DAH 2026 공식 스켈레톤 호환성 감사 피드백

> 감사 기준 시점: 2026-08-14, `main` commit `aa1c4b57b885a9bfa4fbd6921ac6a88a4f67e2ea`
>
> 이 문서는 **수정 전 감사 결과**다. 후속 구현 상태는
> `docs/superpowers/handoffs/2026-08-14-rehearsal-audit-remediation.md`를 따른다.

## 한 문장 결론

**NOT_READY** — 공식 스켈레톤 연결 계약은 대부분 통과했지만, 같은 20분 Round 안에서 동일 flag가 반복 제출되는 P1 결함이 재현되어 리허설 투입 전 수정과 이미지 재검증이 필요하다.

## 감사 입력

| 항목 | 확인값 |
|---|---|
| OUR_REPO | 팀 개발 저장소 checkout |
| OFFICIAL_SKELETON | 운영진이 배포한 외부 스켈레톤 폴더 |
| TEAM_NUMBER | `UNKNOWN`; 스켈레톤의 `team1`은 예시값이지 실제 팀 번호 증거가 아님 |
| REHEARSAL_NOTICE | 일반 일정 안내만 제공됨; 접속 URL과 Registry 상세 없음 |
| ATTACKER_IMAGE | `aegis/attacker:latest` |
| DEFENDER_IMAGE | `aegis/defender:latest` |

저장소는 `main`, local/origin/GitHub HEAD가 모두 `aa1c4b57b885a9bfa4fbd6921ac6a88a4f67e2ea`였고 submodule은 없었다. 사용자 소유 미추적 계획 파일 한 개가 있어 감사 중 수정하지 않았다.

## 판정표

| 영역 | 판정 | 핵심 증거 | 리허설 영향 |
|---|---|---|---|
| 공식 스켈레톤 출처/해시 | PASS | 운영세칙 PDF SHA-256과 `deploy/` 34개 파일 tree hash가 inventory와 일치 | 배포본 변조 증거 없음 |
| 공격 인터페이스 | PASS | 공식 환경변수, TARGETS x PORTS, LiteLLM URL/Bearer, redirect 차단, exact-host egress 확인 | 기본 연결 가능; 자기 팀 제외와 DNS 재해석은 보강 필요 |
| flag 제출 프로토콜 | **FAIL** | JSON·상태·rate limit은 통과했으나 `run_once()` 두 번에서 같은 flag 제출 수가 1→2로 증가 | 30회/분 예산 소진 및 신규 flag 제출 지연 가능 |
| heartbeat | PASS | 1초 scheduler, 단일 writer, 보존 로그 HEARTBEAT 6회 | 기본 연결 정상; worker liveness 감시 부족 |
| 300ms latency | BLOCKED | hot path는 매우 빠르지만 packet receipt→socket send 완료 계측이 runtime에 연결되지 않음 | 공식 E2E SLA를 완전히 입증하지 못함 |
| flow 재조립 연결 | FAIL | `FlowReassemblyBuffer`가 `state.py`와 테스트에만 있고 verdict 경로에서 호출되지 않음 | 방어 효과성 간극; 프로토콜 실패는 아님 |
| SHADOW/CANARY/ACTIVE | PASS | 독립 테스트에서 SHADOW=ACCEPT, CANARY=조건부, ACTIVE=DROP 확인; 현재 11개 모두 SHADOW | 현재 DROP 0은 의도된 상태이나 방어 효과성 미검증 |
| 공격 이미지 | BLOCKED | 기존 이미지 `linux/amd64`, 약 41.31MiB, 자동 CMD 확인; current HEAD provenance label 없음 | P1 수정 후 재빌드 필요 |
| 방어 이미지 | BLOCKED | 기존 이미지 `linux/amd64`, 약 41.36MiB, `USER=65534`, 자동 CMD 확인 | current HEAD clean build 재검증 필요 |
| 공식 30초 라운드 | BLOCKED | PCAP는 34초 이상이나 defender 참여 로그는 6.626초뿐 | 두 팀 이미지의 새 30초 전체 실행 증거가 아님 |
| 리허설 접속 정보 | BLOCKED | URL, 팀 번호, Registry token, pull 마감 정보 없음 | 실제 접속·push·accepted 제출 불가 |

## 세부 분류

| 분류 | 결과 |
|---|---|
| ATTACK_INTERFACE | PASS |
| ATTACK_DISCOVERY | PASS |
| ATTACK_LLM_PATH | 프로토콜 PASS / 실제 상류 LLM BLOCKED |
| ATTACK_FLAG_EXTRACTION | 통제된 fake 환경 PASS |
| ATTACK_SUBMISSION | **FAIL — Round 안의 반복 cycle에서 중복 제출** |
| ATTACK_END_TO_END | `ATTACK_E2E_BLOCKED` |
| DEFENDER_PROTOCOL | PASS |
| DEFENDER_HEARTBEAT | PASS |
| DEFENDER_LATENCY | 완전한 E2E 측정 BLOCKED |
| DEFENDER_RECONNECT | 단위 테스트 PASS / 이번 실기 broker 재시작 BLOCKED |
| DEFENDER_PACKET_PARSING | PASS |
| DEFENDER_FLOW_INTEGRATION | `DEFENSE_EFFECTIVENESS_GAP` |
| DEFENDER_POLICY_STATE | 상태 전이 로직 PASS / 현재 효과성 미검증 |
| DEFENDER_SLA_RISK | 현재 전부 SHADOW라 과차단 위험 낮음 |

## 출처와 해시

| 비교 대상 | 기록값 | 실제 계산값 | 결과 |
|---|---|---|---|
| 본선 운영세칙 PDF | `FFE8E6BEECB628F93F20A9F5D0F41203CADBF28EE7E56C9A91FDAB87A1655A5F` | 동일 | PASS |
| 공식 `deploy/` 파일 수 | 34 | 34 | PASS |
| 공식 `deploy/` tree hash | `8B7552FB285C3DBB75285BB083F09A5B72322B867F2472A873C2C738C20C73CE` | 동일 | PASS |
| `deploy/docs/agent-guide.md` | 개별 inventory 없음 | `8E7AC90ABB3186DEC73DC0AAF556F21B0A96E18F2532CFF59CB8D7A31FE9BCDB` | 참고값 |
| `deploy/docker-compose.yml` | 개별 inventory 없음 | `5F4ABE70556E15EDCBAF9D73BBED0A38338FA55C552EFB4C515E4C2D24539B21` | 참고값 |
| `deploy/router/broker` | 개별 inventory 없음 | `DDA8A4C5E2678635080F377C93C6FC3FE3E7AA3448B91B0FA8E4C8564D43E857` | 참고값 |

공식 스켈레톤은 저장소에 복사하거나 수정하지 않았다. 팀 저장소는 외부 Compose를 override하고 attacker/defender 통신 계층을 재구현한다.

## 실행한 검사

```text
Repository layout check passed.
Skeleton validator tests passed: 2 cases.
Agent Compose override tests passed: 29 cases.
Official skeleton validation passed.

Attacker: Ran 159 tests in 0.011s — OK
Defender: Ran 275 tests in 9.689s — OK
skip=0, expected failure/xfail=0
```

Defender in-process hot-path 결과:

| 부하 | p50 | p99 | max |
|---:|---:|---:|---:|
| 1 pkt/s | 21.7us | 42.9us | 47.9us |
| 100 pkt/s | 21.0us | 31.0us | 50.5us |
| 550 pkt/s | 22.5us | 112.3us | 443.6us |
| 1100 pkt/s | 25.5us | 112.2us | 315.5us |

이 결과는 Python hot path 측정이며 broker 수신부터 verdict socket 송신 완료까지의 E2E 지연은 아니다.

## Findings

P0 finding은 발견되지 않았다.

### P1-01 — 같은 공식 Round에서 동일 flag 반복 제출

**증거**

- 공식 Round는 20분이다.
- `agents/attacker/src/aegis_attacker/runtime.py`의 `run_forever()`는 약 4초마다 `run_once()`를 반복한다.
- `run_once()`가 호출할 때마다 `_build_round()`가 새 `FlagStore`, secret store, pipeline과 playbook을 만든다.
- 따라서 같은 공식 Round 안에서도 약 4초 전 제출한 flag의 resolved state가 사라진다.

**재현 명령**

```powershell
Set-Location agents/attacker
wsl env PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. python3 -c "from tests.test_runtime import FakeArena,make_runtime; a=FakeArena('FLAG{dup_probe}','/x','irrelevant'); r=make_runtime(a); r.run_once(); print(f'submits_after_first={len(a.submits)}'); r.run_once(); print(f'submits_after_second={len(a.submits)}')"
```

**재현 결과**

```text
submits_after_first=1
submits_after_second=2
```

**실제 영향**

같은 flag가 반복 관측되면 제출 제한 30회/분을 소비하고 신규 flag 제출을 지연시킬 수 있다.

**최소 수정 방향**

공식 Round 상태와 4초 scan cycle을 분리한다. `FlagStore`, secret store, budget과 playbook은 공식 Round 전체에서 유지하고 실제 Round 종료에만 폐기한다. 서로 다른 Round에서는 상태가 새로 시작되어야 한다.

**시점:** 리허설 전 필수.

### P2-01 — 완전한 300ms E2E latency 계측 미연결

**증거:** `VerdictSender.record_result()`는 존재하지만 `SocketWriter` 결과가 이 함수로 전달되지 않는다.

**영향:** hot path는 빠르지만 broker 수신→Python 처리→socket send 완료의 p50/p95/p99/max와 timeout 수를 입증할 수 없다.

**최소 수정 방향:** 모든 terminal `SendResult`를 callback으로 발행하고 runtime에서 `record_result()`에 연결한다. shutdown 로그에 E2E 분포와 outcome count를 남긴다.

**시점:** 리허설 전 계측 연결, 실제 분포는 리허설에서 확인.

### P2-02 — flow 재조립이 verdict 경로에 연결되지 않음

**증거:** `FlowReassemblyBuffer` 참조는 `state.py`와 테스트에만 있고 runtime은 단일 packet을 바로 policy에 전달한다.

**영향:** 여러 TCP segment에 나뉜 공격을 상관 탐지할 수 없다. PACKET/VERDICT 계약 자체에는 영향이 없다.

**최소 수정 방향:** verdict enqueue 이후 bounded async worker에서 flow를 재조립하고 payload 없이 matching rule ID만 immutable snapshot에 게시한다. 다음 packet부터 기존 정책 상태를 적용한다.

**시점:** 리허설 중 SHADOW 관측, baseline 확보 후 다음 Round 승격 가능.

### P2-03 — 현재 policy는 전부 SHADOW이며 baseline이 비어 있음

**증거:** `agents/defender/policy/active.json`의 `baseline_profiles`가 비어 있고 11개 rule 모두 `SHADOW`다.

**영향:** `PACKET 33 → ACCEPT 33`, `DROP 0`은 연결 실패가 아니라 의도된 무차단 상태다. 현재 실질 방어 효과는 없다.

**최소 수정 방향:** 리허설 정상 traffic baseline 수집 후 rule별 SHADOW→CANARY→ACTIVE 승격과 rollback 기준을 적용한다.

**시점:** 리허설 중 검증 및 승격 가능. 근거 없는 일괄 ACTIVE는 금지.

### P2-04 — 필수 worker의 조용한 사망 감시 부족

**증거:** thread start/stop은 있으나 main/session loop에서 writer, heartbeat, correlation의 `is_alive()`를 지속 확인하지 않는다.

**영향:** worker만 종료되면 컨테이너는 살아 있어도 broker heartbeat timeout 또는 무방어 상태가 발생할 수 있다.

**최소 수정 방향:** 필수 worker watchdog을 추가하고 조용한 사망 시 비민감 로그와 non-zero process 종료로 container supervisor 재기동을 유도한다.

**시점:** 리허설 전 권고.

### P2-05 — 자기 팀 제외와 DNS 재해석 방어가 외부 입력을 신뢰함

**증거:** attacker egress는 exact hostname:port allowlist를 적용하지만 IP resolve/pinning은 하지 않는다. 자기 팀 제외는 caller 책임이다.

**영향:** 운영진 TARGETS가 정확하면 정상이나 잘못된 TARGETS 또는 DNS answer 변경에는 자체 방어가 없다.

**최소 수정 방향:** 선택적 `TEAM_NUMBER`로 정확한 자기 팀 hostname을 제외하고 연결 직전 DNS answer 변경과 위험 IP를 fail-closed 처리한다.

**시점:** 팀 번호와 실제 TARGETS 확인 후 적용·검증.

### P2-06 — current HEAD 이미지와 30초 전체 Round 증거 부족

**증거**

- 기존 이미지에 VCS revision label이 없어 `aa1c4b57...`에서 생성됐는지 입증할 수 없다.
- PCAP는 34초 이상이나 defender 로그 참여 구간은 6.626초다.
- 감사 중에는 상태 변경 금지 조건 때문에 clean build와 새 container 실행을 하지 않았다.

**영향:** 기존 이미지의 구조와 architecture는 확인됐지만 source와 artifact의 동일성이 완결되지 않았다.

**최소 수정 방향:** 수정 commit을 OCI revision label로 기록해 두 이미지를 clean build하고 공식 스켈레톤에서 30초 이상 함께 실행한다.

**시점:** 리허설 전 필수.

### P3-01 — CI가 attacker와 Docker image build를 검증하지 않음

**증거:** `.github/workflows/ci.yml`에는 repository foundation과 defender tests만 있다.

**영향:** attacker 회귀나 Dockerfile 파손이 main CI 성공 표시로 탐지되지 않는다.

**최소 수정 방향:** Python 3.12 attacker tests, Compose contract, 두 `linux/amd64` image build/inspect job을 추가한다.

### P3-02 — root README가 현재 구현과 충돌

**증거:** root README는 Dockerfile과 agent runtime이 아직 없다고 설명하지만 이미 모두 존재한다.

**영향:** 팀원이 현재 상태와 남은 작업을 오해할 수 있다.

**최소 수정 방향:** 구현 완료 영역, 현재 SHADOW 상태, 실제 리허설에서 확인할 gate로 갱신한다.

### P3-03 — 공식 배포본 README와 실제 파일 충돌

**증거:** 공식 `deploy/README.md`는 `.env.example` 복사를 지시하지만 배포 폴더에 해당 파일이 없다.

**영향:** 새 환경에서 공식 문서대로만 설치하면 환경파일 준비 단계가 실패한다.

**최소 수정 방향:** 운영진에게 누락 여부를 확인하고 값을 임의로 추측하지 않는다.

## 알려진 상태의 재판정

> 공격·방어 이미지의 기본 구조와 공식 스켈레톤 연결 프로토콜은 대부분 검증되었다. 다만 공격 에이전트가 실제 20분 Round 안의 반복 실행을 새 Round로 처리하여 동일 flag를 재제출하는 P1 결함이 재현되었다. 또한 실제 LLM을 사용한 flag 획득·accepted 제출, defender의 완전한 300ms E2E latency, CANARY/ACTIVE 정책, flow 재조립 탐지는 아직 검증되지 않았다. 따라서 감사 시점의 상태는 본선 최종 완성본이나 조건부 리허설 준비 완료가 아니라 NOT_READY이며, 중복 제출 수정과 image·30초 Round 재검증 후 CONDITIONALLY_READY로 승격할 수 있다.

## 리허설 전에 반드시 고칠 것

- 공식 Round 동안 `FlagStore`를 유지해 동일 flag 재제출 방지
- cross-cycle 중복 방지 회귀 테스트 추가
- 수정된 SHA에서 attacker/defender clean build 및 image revision 확인
- 공식 스켈레톤에서 두 이미지를 30초 이상 함께 재실행
- 팀 번호, 접속 URL, Registry 인증·push 방식, pull 마감 확보

## 리허설에서 확인할 것

- 실제 LiteLLM quota·model로 flag 추출 및 실제 submit 상태
- defender packet receipt→verdict send E2E p50/p95/p99/max와 timeout 수
- broker 재시작·BrokenPipe·필수 worker 장애 후 복구
- 운영진 TARGETS에서 자기 팀 제외와 실제 환경변수·port 차이
- Registry `latest` pull 및 pull 시간

## 리허설 후 다음 Round 전에 승격할 것

- 정상 traffic baseline 기반 SHADOW→CANARY→ACTIVE 단계 승격
- bounded flow 재조립을 online-correlation/verdict snapshot 경로에 연결
- 필수 worker watchdog 적용 결과 재검증
- DNS·자기 팀 제외 방어 검증
- attacker·Docker image CI와 문서 상태 갱신
