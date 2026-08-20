# 본선 준비 검증 기록

기준 commit: `a307af07806bf0cf435df4a7978a3f0cded578aa`에서 시작해 본 문서와 함께 반영한 변경

## 결론

공식 x86-64 Broker와 현재 Defender의 실제 NFQUEUE `PACKET → VERDICT` 경로는 통과했다.
공격자는 104개 리허설 PCAP 회귀와 단위·이미지 검증을 통과했지만, 공식 demo challenge
전체 기동은 외부 skeleton의 의존성 drift 때문에 이번 검증 범위에 포함하지 못했다.

L1~L4 전체의 증거 기반 자기 적용 절차와 현재 레이어별 판정은
[`2026-08-19-all-layer-promotion-meta-prompt.md`](../superpowers/specs/2026-08-19-all-layer-promotion-meta-prompt.md)에
고정했다. 현재 검증된 ACTIVE는 L1 3개, L2 4개, L3 2개이고 L4는 실제 interface 증거가 없어
observation-only다.

## 입력 동일성

- 공식 ZIP: `C7C67CFB10CF6D1FA0997D19EAF1DF0D7347E2C66E4F417637D866B6CCA6DF2C`
- `deploy/` 34개 파일 tree: `8B7552FB285C3DBB75285BB083F09A5B72322B867F2472A873C2C738C20C73CE`
- agent guide: `8E7AC90ABB3186DEC73DC0AAF556F21B0A96E18F2532CFF59CB8D7A31FE9BCDB`
- Compose: `5F4ABE70556E15EDCBAF9D73BBED0A38338FA55C552EFB4C515E4C2D24539B21`
- Broker: `DDA8A4C5E2678635080F377C93C6FC3FE3E7AA3448B91B0FA8E4C8564D43E857`

공식 파일은 저장소에 복사하거나 수정하지 않았다.

## 공식 Broker 실기

x86_64 QEMU Linux VM에서 공식 Router 이미지와 Broker 바이너리를 그대로 빌드하고,
현재 Defender와 외부 임시 HTTP fixture를 연결했다. 테스트 컨테이너·네트워크·볼륨은
검증 후 제거했다.

| 항목 | 결과 |
|---|---:|
| 연결 유지 | 65초 |
| session | 1 |
| heartbeat | 65 |
| PACKET | 116 |
| ACCEPT / DROP | 80 / 36 |
| hot path p95 / p99 / max | 6.21 / 7.19 / 7.97ms |
| verdict send E2E p50 | 3.05ms |
| verdict send E2E p95 / p99 / max | 9.41 / 13.41 / 14.12ms |
| 300ms 초과 | 0 |

정상 외부 fetch 세 건은 표적까지 도달했고, 리허설 PCAP 근거로 ACTIVE 승격된 L2
loopback-secret SSRF 세 건은 모두 클라이언트 timeout이 발생했으며 표적 접근 기록이 없었다.
Defender 종료 후 Broker가 agent disconnect를 감지하고 다음 연결 대기 상태로 돌아가는 것도 확인했다.

## 공식 가이드 반영

공식 agent guide는 공지표에서 Responses 유형인 모델도 LiteLLM Proxy가
`/v1/chat/completions` 요청으로 투명 변환한다고 명시한다. 따라서 제공된 21개 모델을
모두 허용하고, 요청 상한 필드는 공식 예제의 `max_completion_tokens`를 사용한다.

## 남은 게이트

1. L4는 수신 PCAP과 parser로 증명된 interface가 없어 observation-only 상태를 유지한다.
2. 팀 총 `$1360`의 모델별 가격·과금 상한은 본선 당일 공지가 없어 ledger 금액 배분을 확정할 수 없다.
3. 공식 challenge Dockerfile의 비고정 `gunicorn`/`gevent` 조합은 현재 빌드에서
   `ModuleNotFoundError: packaging`으로 종료됐다. 공식 수정본에서는 공격·방어 전체 demo
   stack을 다시 실행해야 한다. 이 문제를 우회하기 위해 공식 challenge 소스를 저장소에
   복사하거나 수정하지 않는다.

다음 세션은 [본선 준비 후속 작업 인계](../superpowers/handoffs/2026-08-19-finals-readiness-continuation.md)의
재개 순서에서 계속한다.
