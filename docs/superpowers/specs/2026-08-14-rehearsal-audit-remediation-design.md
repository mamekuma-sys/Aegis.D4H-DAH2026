# DAH 2026 리허설 감사 후속 보강 설계

- 작성: 팀장 최종 감사 후속
- 기준 브랜치: `main` @ `aa1c4b57b885a9bfa4fbd6921ac6a88a4f67e2ea`
- 공식 근거: 해시가 재검증된 본선 운영세칙과 외부 공식 스켈레톤
- 목표: 새로운 공격·방어 전략을 추가하지 않고, 감사에서 확인된 연결·수명주기·계측·운영 결함을 제거한다.

## 1. 범위와 안전 경계

이번 변경은 다음 감사 finding을 다룬다.

1. 공격 에이전트의 scan cycle마다 `FlagStore`가 초기화되어 같은 공식 Round 안에서 동일 flag가 재제출되는 결함
2. defender의 `SendResult`가 `VerdictSender.record_result()`에 전달되지 않아 물리 송신 완료 기준 E2E latency가 기록되지 않는 결함
3. flow 재조립 자료구조가 실제 상관분석과 verdict 조회 경로에 연결되지 않은 결함
4. HEARTBEAT 등 필수 worker가 조용히 종료되어도 컨테이너가 계속 살아 있을 수 있는 결함
5. attacker가 문자열 host allowlist만 확인하고 자기 팀 제외와 DNS 재해석을 별도로 검증하지 않는 결함
6. CI가 attacker 테스트와 Docker build를 검증하지 않고, README가 현재 구현과 충돌하며, 이미지와 commit의 provenance가 약한 문제
7. 리허설 전 clean build, 30초 공식 스켈레톤 round, SIGTERM·재연결·latency 통합 증거 부족

다음은 이번 변경에서 하지 않는다.

- 정상 traffic baseline 없이 현재 11개 `SHADOW` rule을 `CANARY` 또는 `ACTIVE`로 승격
- 운영진이 주지 않은 팀 번호, Registry token, rehearsal URL 추측
- 실제 리허설 대상에 대한 네트워크 요청
- 공식 스켈레톤 파일 수정 또는 저장소 내부 복사

정책 승격은 실제 리허설 baseline과 두 담당자 review가 있어야 한다. 이번 변경은 승격 메커니즘과 관측 증거를 완성하지만 현재 policy state는 그대로 유지한다.

## 2. 공격 Round 수명주기

공식 Round는 컨테이너 수명인 20분이고, 현재 `run_once()`는 그 안에서 반복되는 scan cycle이다. 런타임은 다음 두 계층을 분리한다.

- `start_round()`: Round ID, secret store, 제출 token/key handle, `FlagStore`, submit deadline, LLM budget, playbook을 한 번 만든다.
- `run_cycle()`: 기존 TARGETS x PORTS 관측·계획·실행을 반복하되 Round state를 재사용한다.
- `finish_round()`: 모든 secret을 폐기한다.
- `run_once()`: 테스트와 통제된 단발 실행을 위한 편의 API로 독립 Round 하나를 열고 cycle 하나를 실행한 뒤 닫는다.
- `run_forever()`: 프로세스 기동 시 Round를 한 번 열고, 20분 deadline 또는 종료까지 cycle을 반복한 뒤 닫는다.

따라서 동일 flag의 resolved state는 scan cycle 사이에 유지되고, 다른 프로세스/Round에는 남지 않는다. 제출 rate limiter도 계속 전역으로 유지된다.

## 3. 공격 egress 경계

공식 `TARGETS`가 권한의 원천인 점은 유지한다. 추가 방어는 다음처럼 제한한다.

- `TEAM_NUMBER`가 제공되면 공식 hostname 형식 `team{N}.lig.internal`을 TARGETS에서 제거한다. 이 환경변수는 선택 안전 입력이며 없다고 공격 런타임을 막지 않는다.
- target, submit, LLM URL의 hostname을 연결 직전에 해석하고, 같은 요청에서 사용할 resolved IP 집합을 검증한다.
- target hostname은 최초 allowlist 확정 시 얻은 IP 집합과 연결 직전 집합이 달라지면 거부한다. loopback, link-local, multicast, unspecified IP도 거부한다.
- 실제 socket을 특정 IP에 pinning하는 변경은 `urllib` 전송 계층과 TLS hostname 검증을 함께 바꾸므로 이번 범위에서 하지 않는다. 대신 변경 탐지와 fail-closed를 명시적으로 테스트하고 운영 arena DNS를 신뢰 경계로 기록한다.

## 4. defender 물리 송신 E2E 계측

`SocketWriter`는 모든 `SendResult`를 선택 callback으로 발행한다. runtime은 callback을 `VerdictSender.record_result()`에 연결한다.

- 성공한 VERDICT는 `PACKET received_at`부터 전체 seqpacket send 완료까지 `latency.verdict_end_to_end`에 기록한다.
- timeout, expired, error, partial send는 기존 outcome counter로 기록한다.
- shutdown 로그는 hot-path와 verdict E2E의 `count`, `p50_us`, `p95_us`, `p99_us`, `max_us`를 함께 남긴다.
- callback 예외는 socket writer를 죽이지 않고 별도 metric/audit로 격리한다.

## 5. bounded 비동기 TCP flow 재조립

기존 설계의 단일 producer, 300ms soft cutoff, immutable snapshot 경계를 유지한다. 원본 packet을 hot path shared mutable state에 넣지 않는다.

1. parser가 TCP sequence와 FIN/RST 여부를 bounded scalar로 제공한다.
2. verdict enqueue 뒤 만드는 `CorrelationEvent`에는 최대 2KB의 독립 payload fragment 복사본과 TCP sequence만 담는다. 원본 `PacketEnvelope`나 `ParsedPacket` 객체는 참조하지 않는다.
3. single correlation worker가 flow별 16KB, 전체 5,000 flow, TTL 120초 상한 안에서 segment를 조립한다. 중복·overlap·제한된 out-of-order segment를 처리하고 FIN/RST에서 state를 닫는다.
4. 재조립된 byte view는 worker 내부에서만 policy regex와 비교한다. 로그, metric label, advisory prompt, disk에는 원문을 내보내지 않는다.
5. 새 cross-segment match가 생기면 worker가 immutable snapshot을 즉시 발행한다. snapshot에는 `rule_id`만 있고 payload는 없다.
6. `HotPolicy`는 다음 packet부터 snapshot의 `reassembled_rule_ids`를 읽고 해당 rule의 SHADOW/CANARY/ACTIVE 집행 상태를 그대로 적용한다.

이 구조는 현재 packet의 verdict를 늦추지 않는다. 따라서 마지막 segment 하나로 끝나는 단발 요청을 즉시 막는다고 주장하지 않는다. 현재 모든 rule이 SHADOW이므로 리허설에서는 cross-segment hit 관측만 수행하고, 실제 승격은 baseline 검증 뒤에 한다.

## 6. 필수 worker liveness

필수 worker는 writer, heartbeat, correlation이며 advisory는 활성화됐을 때만 필수다.

- 각 worker는 `is_alive()`를 제공한다.
- `BrokerSession`은 recv poll마다 injected health check를 호출한다.
- 필수 worker 하나가 죽으면 `worker-failed`를 비민감 로그로 남기고 shared stop event를 설정해 process를 non-zero로 종료한다.
- 조용히 방어가 사라진 채 컨테이너만 살아 있는 상태보다 container supervisor가 재기동할 수 있는 명시적 실패를 선택한다.
- 정상 shutdown 중 thread가 내려가는 것은 failure로 세지 않는다.

## 7. CI, 이미지와 운영 문서

- CI에 Python 3.12 attacker 159+ tests를 추가한다.
- Docker build job은 두 이미지를 `linux/amd64`로 build하고 Dockerfile의 자동 CMD, defender `USER 65534`, secret 미포함을 검사한다.
- Dockerfile에 OCI source revision build arg/label을 추가하고 build script가 현재 Git SHA를 전달한다.
- root README를 현재 attacker/defender/Docker 통합 상태와 remaining rehearsal gates에 맞게 갱신한다.
- 리허설 preflight runbook은 팀 번호·Registry·URL을 필수 외부 입력으로 명시하고 값이 없으면 추측하지 않고 중단한다.
- 검증 스크립트는 clean build, image inspect, 공식 skeleton compose config, 30초 실행, PACKET/VERDICT/HEARTBEAT/E2E latency, SIGTERM, broker reconnect를 한 흐름으로 수집하되 Registry push나 cleanup은 별도 명시 옵션 없이는 하지 않는다.

## 8. 검증 기준

- attacker regression은 두 scan cycle에서 동일 flag submit transport 호출이 한 번뿐이어야 한다.
- 새 프로세스/Round에서는 같은 합성 flag를 다시 제출할 수 있어야 한다.
- E2E sent 표본 수는 성공적으로 송신된 VERDICT 수와 같아야 한다.
- timeout fixture는 E2E sent 표본을 만들지 않고 timeout counter를 증가시켜야 한다.
- split signature fixture는 단일 segment에서는 match하지 않고, worker 재조립 후 snapshot을 통해 다음 packet의 SHADOW hit 또는 승격 상태에 맞는 verdict를 만들어야 한다.
- worker 사망 fixture는 runtime이 non-zero로 종료되고 session이 계속 살아 있지 않아야 한다.
- attacker와 defender 전체 unit tests, layout, skeleton validator, compose contract가 통과해야 한다.
- 수정된 commit에서 두 이미지를 clean build하고 `linux/amd64`, CMD, user, revision label, secret absence를 확인해야 한다.
- 공식 skeleton에서 최소 30초 동안 두 이미지를 함께 실행하고 실제 E2E latency distribution과 timeout count를 기록해야 한다.
