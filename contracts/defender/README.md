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
