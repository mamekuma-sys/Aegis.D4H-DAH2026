# L4 미지 서비스 adaptive transport 설계 delta

## 문제와 근거

본선 규칙은 Phase 4에서 L1–L4가 누적 개방되고, `TARGETS × PORTS`의 한 레이어에 여러 서비스와
프로토콜·flag가 있을 수 있음을 보장한다. 반면 현재 공격자는 모든 포트를 평문 HTTP로만 관측하므로
HTTPS 또는 서버 주도 TCP banner 서비스는 `status=0` 뒤 즉시 버린다. 실제 L4 port·protocol·취약점은
알 수 없으므로 특정 UGV protocol이나 command를 가정하지 않는다.

## 승인 범위

미확인 endpoint의 bootstrap observation을 다음 세 단계로 제한한다.

1. `http://host:port/`에 `GET /` 한 번.
2. 응답이 없을 때만 `https://host:port/`에 `GET /` 한 번.
3. 양쪽 모두 응답이 없을 때만 같은 host·port에 TCP connect 후 서버가 먼저 보내는 banner를 최대
   4KiB, 최대 750ms 동안 한 번 읽는다. 클라이언트 application byte는 보내지 않는다.

성공한 HTTP scheme은 해당 Round·endpoint에만 결속한다. 이후 route discovery와 실행 계획은 기존의
읽기 전용 GET evidence gate, TTL, `TARGETS × PORTS` allowlist, 10 req/s·burst 20 limiter를 그대로
통과한다. passive TCP banner에서 flag가 직접 보이면 기존 flag pipeline으로 제출하되 원문을 로그나
artifact에 남기지 않는다.

대상 HTTPS의 인증서는 경기용 self-signed 가능성을 고려해 `ATTACK_TARGET` capability에서만 검증을
완화한다. `SUBMIT`과 `LLM` capability는 기존 인증서 검증을 유지한다.

## 명시적 비범위

- UDP probe와 protocol별 payload·command를 보내지 않는다.
- MQTT·CoAP·Modbus·로봇 제어 protocol이 존재한다고 가정하지 않는다.
- TCP banner가 없으면 LLM이 raw payload를 발명해 실행하지 않는다.
- 방어 ACTIVE rule과 300ms hot path는 변경하지 않는다.
- HTTP/HTTPS/TCP 시도는 rate limit 우회나 별도 source로 실행하지 않는다.

## 성공 조건과 rollback

- 평문 HTTP의 기존 L1–L3 요청 순서와 결과가 변하지 않는다.
- HTTPS-only 합성 endpoint에서 관측된 GET route로 복수 flag를 회수한다.
- HTTP·HTTPS 무응답 TCP banner에서 flag를 회수하며 client application write는 0이다.
- out-of-scope host·port의 HTTPS와 TCP banner는 transport 전에 거부한다.
- LLM·제출 TLS 경계와 비밀 redaction이 변하지 않는다.

회귀 시 이 delta commit을 revert하고 현재 HTTP-only A1 digest로 rollback한다. 이 변경은 공격 runtime과
shared egress 설계에 영향을 주므로 공격자 owner와 팀장 이경준 검토가 필요하다.

## 2026-08-21 R11 무배너 L4 probe 승인 delta

R11 관측에서 `8410`·`8420`은 HTTP·HTTPS root 및 passive TCP banner에 응답하지 않았지만 두 port의
L4 트래픽은 존재했다. 따라서 이 두 port에 한해서만 기존 `no-http-https-or-passive-banner` 조기 종료를
해제한다.

- 관측: 기존 HTTP → HTTPS → passive TCP 순서와 evidence binding을 그대로 유지한다.
- 계획: 세 관측이 모두 무응답이면 이미 정의된 `observed_attempts(8410|8420)` 목록을 선택한다.
- 실행: 해당 목록은 평문 HTTP로 복원해 기존 `ATTACK_TARGET` allowlist, Round·endpoint·TTL evidence
  binding 및 rate limit을 통과시킨다. 이 예외는 다른 port에 적용하지 않는다.

이 delta는 신규 경로나 신규 protocol payload를 추가하지 않고, 이미 있던 L4 시도가 조기 gate 뒤에서
실제로 실행되게 하는 데만 한정한다.

## 2026-08-21 R13 G2DDS 전용 전송 승인 delta

R13 공격 로그에서 위 HTTP 예외는 `8410`·`8420` accepted를 만들지 못했고, LLM도 두 port에
HTTP GraphQL 계획을 반복했다. 반면 R11 L4 PCAP은 두 port가 h2c/gRPC
`g2dds.v1.Layer4Service/{GetCatalog,Exchange}`임을 증명했다. 이 최신 wire 근거가 바로 위
무배너 HTTP delta를 대체한다.

- 관측: 두 port는 빈 `GetCatalog` unary 요청으로 protocol을 bootstrap한다.
- 계획: 응답이 있을 때만 R11에서 관측한 diagnostic topic/type과 `MAP_SNAPSHOT` action을
  base64-protobuf·JSON-protobuf 두 encoding으로 구성한다.
- 실행: 두 시도는 읽기 전용이며 고정된 port·RPC allowlist, endpoint evidence, TTL, rate limit을
  모두 통과한다. calibration apply, programming STORE/RUN, 임의 raw payload는 만들지 않는다.
- 격리: `9000`·`1883`·`8554`·`8410`·`8420`은 native protocol 전송 뒤 HTTP/GraphQL LLM으로
  fallback하지 않는다. 무응답은 audit 후 다음 bounded retry wave로 넘긴다.
- 성공 조건: 각 L4 port에서 `GetCatalog → Exchange` 순서를 지키고, HTTP·LLM 호출 0으로
  응답 flag를 기존 제출 파이프라인에 전달한다. RPC와 port의 교차 사용은 전송 전에 거부한다.
