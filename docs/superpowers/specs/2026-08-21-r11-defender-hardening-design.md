# P4 R11 방어 6개 결함 보완 설계

## 상태와 근거

2026-08-21 P4 R11 L4 PCAP에서 `8410`·`8420`의 h2c/gRPC와
`g2dds.v1.Layer4Service/{GetCatalog,Exchange}`가 관측됐다. `ExchangeRequest`는
raw protobuf, base64 protobuf, JSON protobuf 세 encoding을 사용한다. 내부 Envelope의
`topicId`, `typeId`, `sample`은 packet 입력에서 직접 복원할 수 있다. 이 관측은 기존
L4 observation-only 결정을 대체한다.

승인 범위는 방어 런타임, 테스트, policy, 방어 매핑 문서다. Dockerfile, shared
contract, 공식 skeleton은 변경하지 않는다. 원격 LLM에는 판정 권한을 주지 않는다.

## 300ms 경로와 온라인 상관분석 경계

동기 경로는 기존 `Gate → Sig → Score → VERDICT enqueue`를 유지한다. `Sig`에 추가하는
작업은 고정 상한만 허용한다.

- flow 최대 2,048개, flow당 wire 최대 16KiB, gRPC message 최대 4KiB
- TCP reorder 최대 8조각, HTTP request 최대 4KiB, 고정 TTL
- protobuf는 varint와 length-delimited field만 해석
- pickle은 `pickletools.genops`로 opcode만 검사하고 절대 역직렬화하지 않음
- port별 사전 계산 집합으로 HTTP/gRPC parser를 불필요한 packet에서 실행하지 않음
- malformed, cap 초과, 미지원 encoding, 압축 gRPC는 빠른 `ACCEPT`

비동기 상관분석, anomaly 집계, LLM advisory, JSON 로그는 VERDICT enqueue 뒤에 둔다.
이 경로는 현재 packet을 소급 차단하지 않고 runtime policy를 변경하지 않는다.

## ACTIVE 판정 경계

L4 gRPC는 다음 exact 조합만 차단한다.

1. diagnostic `(topicId=65536, typeId=4097, action=4)`
2. calibration `(393216, 16384)`에서 `apply=true`, pickle format이며 실행 opcode가 존재
3. programming `(655360, 28672, apiId=1002 STORE)` source에 명시적 비밀·파일 실행 표식 존재

정상 diagnostic action 1~3, 정상 calibration dictionary, 정상 STORE source와 RUN,
GetCatalog, reflection, health는 negative/SLA fixture다. HTTP 계열은 R11에서 관측된
ROS secret parameter 이름과 mission flag 명령의 field/value 결합만 차단한다.

## 재조립과 egress

HTTP/H2는 최대 8개의 sparse segment를 병합한다. 미래 segment를 저장해도 verdict를
기다리지 않으며, 현재 packet까지 연속 구간이 완성된 경우에만 의미 검사를 한다.
egress marker는 raw `FLAG{hex}`, URL escape, JSON unicode escape를 source-port scope로
검사한다. state는 TTL·flow·segment·tail 상한을 초과하면 폐기하고 fail-open한다.

## SHADOW와 AI의 Break 산출물

SHADOW는 자동 승격하지 않는다. 대신 health/shutdown 로그에 payload 없는 rule별
DROP·SHADOW 상위 집계를 남긴다. advisory는 round당 최대 4회, 최소 300초 간격과
2회 연속 실패 circuit break를 유지한다. 출력은 `protocol`, `port`, `field`,
`pattern_family`, `evidence_needed`, `false_positive_risk` JSON schema로만 구조화하며,
현재/후속 packet에 적용하는 API는 만들지 않는다. Break에서 positive·negative·SLA
fixture와 두 review를 통과한 새 bundle만 권한을 가진다.

## 검증 기준

- 8410/8420 및 세 encoding의 positive fixture가 정확한 rule로 DROP
- 정상 L4 fixture 100회와 기존 L1~L3 회귀가 ACCEPT
- HTTP/H2/egress의 2개 이상 out-of-order 조각과 suffix-before-prefix 복원
- state cap, TTL, SYN/FIN/RST, malformed input fail-open
- shipped R11 전체 policy 정상 mix p99 500µs 미만, 300ms 초과 0건
- 전체 defender unit test와 `scripts/check-layout.sh` 통과
