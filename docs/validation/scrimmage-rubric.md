# SCRIMMAGE_PROXY 검증 루브릭

이 문서는 동결된 A0/A1/D0/D1 이미지의 내부 준비도 평가 절차다. 공식 대회 점수를 재현하지
않으며 결과 이름은 항상 `SCRIMMAGE_PROXY`다. 공식 스켈레톤 파일과 raw PCAP·로그·flag·token은
저장소에 복사하지 않는다.

## 필수 게이트

다음 중 하나라도 `PASS`가 아니면 승격하지 않는다.

1. 허용된 두 팀 진입점·LiteLLM·제출 서버 외 egress가 없다.
2. 결과가 commit과 image digest에 결속되고 원본·비밀이 Git에 없다.
3. 공·방 이미지가 독립 `linux/amd64`이며 공식 환경변수와 Broker 계약을 지킨다.
4. defender 300ms 초과가 없고 heartbeat·reconnect가 정상이다.
5. 외부망 차단, 새 컨테이너·새 flag, 동일 자원, 명시적 runner seed가 유지된다.

## 2×2 매트릭스

| 매치 | 공격 | 방어 | 목적 |
|---|---|---|---|
| A0D0 | baseline | baseline | 기준점 |
| A1D0 | candidate | baseline | 공격 개선 효과 |
| A0D1 | baseline | candidate | 방어 개선 효과 |
| A1D1 | candidate | candidate | 상호작용·우회 |

개발은 seed 3개, 최종 후보는 blind seed 5개 이상을 사용한다. 평균뿐 아니라 seed별 결과,
중앙값, 최악값을 보존한다. 이 저장소의 기존 104개 PCAP은 이미 개발에 사용됐으므로 blind가 아니다.

## 환경 차이

- 제공 스켈레톤은 2팀·L1–L3 demo이며 L4가 없다.
- challenge 이미지의 누락된 Python `packaging`은 공식 파일 수정 없이 파생 proxy 이미지에서만 보완한다.
- proxy는 `pip`의 vendored 사본을 복사하며 네트워크 설치를 하지 않는다.
- 공식 점수·SLA generator·flag seed를 완전히 재현하지 못하므로 READY의 공식 근거가 될 수 없다.
- runner seed는 정상 요청 순서만 고정한다. 공식 demo의 flag 생성은 seed로 고정되지 않는다.

`contracts/**`와 Docker/Compose 변경은 Docker owner, 영향받는 agent owner, 팀장 이경준의 검토가 필요하다.
