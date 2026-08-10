# 방어 에이전트 계약

## 연결

- 환경변수: `AGENT_SOCKET`
- 기본 경로: `/run/agent.sock`
- 소켓: `AF_UNIX` / `SOCK_SEQPACKET`
- `router/broker.yaml`의 `agent-event.sock`은 사용하지 않습니다.

## 메시지

모든 정수는 big-endian입니다.

| 타입 | 방향 | 프레임 |
|---|---|---|
| `0x01` PACKET | Broker → Agent | `type(1) + pkt_id(8) + pkt_len(2) + raw_ip(pkt_len)` |
| `0x02` VERDICT | Agent → Broker | `type(1) + pkt_id(8) + verdict(1)` |
| `0x05` HEARTBEAT | Agent → Broker | `type(1)` |

Verdict 값은 `0x00` ACCEPT, `0x01` DROP입니다.

## 시간 계약

- 패킷 수신 후 300ms 안에 verdict를 반환합니다.
- 약 1초마다 heartbeat를 보냅니다.
- Broker는 약 3초 동안 heartbeat가 없으면 에이전트 연결을 죽은 것으로 판단합니다.
- 원격 LLM 호출을 패킷별 동기 판정 경로에 넣지 않습니다.

## Broker 실패와 네트워크 의미

- NAT로 소스 IP가 정규화되므로 소스 IP만으로 공격자나 팀을 식별하지 않습니다.
- 각 레이어의 30ms 지연과 0.3% 손실을 고려하되 에이전트 내부에서 운영진 제한을 상쇄하려 하지 않습니다.
- 에이전트가 연결되지 않았거나 죽으면 Broker는 fail-open으로 패킷을 통과시킵니다.
- 300ms 안에 verdict가 도착하지 않으면 Broker는 해당 패킷을 DROP합니다.

## 입력 경계와 동시성

- 계약된 판정 입력은 PACKET 프레임의 `raw_ip`뿐입니다.
- 차량 상태, 임무 의미, 파라미터 해시, 물리 상태는 파서와 fixture로 필드 존재가 증명되기 전까지 사용하지 않습니다.
- heartbeat 송신, PACKET 수신, VERDICT 송신은 하나의 느린 분석 작업이 서로를 막지 않도록 분리합니다.
- 비동기 상관분석과 원격 LLM은 동기 verdict 반환 이후의 보조 경로에서만 실행합니다.
