# Broker 프레임 고정 예시

공백과 줄바꿈을 제거한 뒤 hex 문자열을 바이트로 변환합니다.

- `packet-frame.hex`: packet id 42, 20바이트 IPv4 예시
- `accept-verdict.hex`: packet id 42에 대한 ACCEPT
- `heartbeat.hex`: HEARTBEAT 한 바이트

이 예시는 향후 `struct.pack`/`struct.unpack` 계약 테스트의 고정 입력으로 사용합니다.
