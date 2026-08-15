# L1 SSRF 정밀 차단 설계

## 상태와 범위

이 설계는 2026-08-15 Phase 1 Round 4의 L1 PCAP과 Defender 로그에서 확인된 SSRF만 다음 이미지에서 차단한다. 사용자는 로컬 `main` 직접 수정을 지시했고, 방어 담당자와 팀장 이경준의 승인을 모두 받은 것으로 기록하도록 승인했다.

이번 변경은 L1 정책 hotfix에 한정한다. Python hot path, TCP 재조립, URL 정규화, L2~L4 정책은 바꾸지 않는다. L2~L4는 각 레이어가 개방된 뒤 제공되는 PCAP과 로그를 근거로 별도 설계·fixture·승격 절차를 밟는다.

## 관측 근거

- L1 실측 목적지는 TCP `10.1.0.4:8082`였다. 공식 세그먼트 주소를 런타임 패킷이 그대로 보존한다고 가정하지 않고, 정책 범위는 관측된 protocol/port인 `6/8082`로 둔다.
- Round 4의 성공 요청 8건은 모두 `GET /fetch?url=...helper-box:8080/secret` 계열이었다.
- 성공 요청은 평문 1건, URL 값 인코딩 6건, 요청 경로·파라미터·대상 전체 퍼센트 인코딩 1건이었다.
- 8개 요청은 각각 161~261바이트의 단일 TCP payload였고, 8개 모두 flag 포함 HTTP 200 응답과 1:1로 대응했다.
- 첫 성공 요청은 캡처 시작 약 0.48초 뒤에 도착했다.
- Round 1 두 PCAP의 HTTP 요청 1,000건에는 `helper-box:8080/secret`이 0건이었고 flag 포함 응답도 0건이었다.
- Round 4 Defender는 Broker에 연결됐지만 `drop_capable_rules=0`으로 기동했다. 이번 누락은 재조립이나 연결 장애가 아니라 활성 규칙 부재다.

원본 PCAP과 로그는 `captures/` 아래의 Git 제외 파일로만 유지한다. 저장소에는 flag, payload 원문, PCAP, 로그를 커밋하지 않는다.

## 검토한 접근

1. **관측 exploit 정밀 차단 — 채택.** `TCP/8082`에서 성공에 필요했던 내부 대상 문자열의 관측 인코딩만 차단한다. 코드 변경 없이 기존 사전 컴파일 matcher를 사용하므로 SLA와 300ms hot path 위험이 가장 낮다.
2. **bounded URL 정규화 파서 — 보류.** percent-decode 후 의미 기반 SSRF 판정을 하면 우회 저항성이 높지만, Python hot path 변경과 별도 latency·오탐 검증이 필요하다.
3. **`/fetch` 전체 차단 — 제외.** 정상 기능과 SLA checker를 함께 막을 수 있고 관측된 공격보다 범위가 넓다.

## PolicyBundle 변경

`agents/defender/policy/active.json`을 다음 원칙으로 갱신한다.

- `bundle_id`: `defender-2026-08-15-l1-ssrf-hotfix`
- `baseline_profiles`: `['6/8082']`
- 기존 11개 규칙: 모두 `SHADOW` 유지
- 새 규칙 ID: `sig-l1-helper-secret-001`
- `kind`: `payload_regex`
- `category`: `ssrf`
- `reason_code`: `sig-l1-helper-secret`
- `protocol`: `tcp`
- `ports`: `[8082]`
- `promotion_state`: `ACTIVE`
- `profile_scope`: `['6/8082']`
- `ignore_case`: `true`
- `promotion_cohort`: `p1-r4-l1-helper-ssrf`
- `promoted_in_bundle`: `defender-2026-08-15-l1-ssrf-hotfix`
- `evidence_id`: `PCAP-P1-R4-L1-20260815-030005`
- `positive_fixture_id`: `P1-R4-L1-HELPER-SECRET-POS-001`
- `negative_fixture_id`: `P1-R1-L1-HTTP-NEG-001`
- `sla_fixture_id`: `P1-R1-L1-SLA-100-001`
- `owner_review`, `lead_review`: `approved`
- 만료: 대회 종료 뒤인 `2026-08-15T10:00:00Z`
- rollback: 공식 SLA가 직전 Round보다 하락하거나 정상 negative fixture 한 건이라도 실패하면 직전 검증 이미지로 복귀

정규식은 raw TCP payload에서 다음 두 target 형태만 찾는다.

```text
helper-box(?::|%3a)8080(?:/|%2f)secret|%68%65%6c%70%65%72%2d%62%6f%78%3a%38%30%38%30%2f%73%65%63%72%65%74
```

첫 항은 평문 hostname과 colon/slash 인코딩을, 둘째 항은 target 전체 퍼센트 인코딩을 잡는다. `ignore_case=true`로 퍼센트 인코딩의 대소문자 차이를 흡수한다. `/fetch`, User-Agent, NAT source IP만으로는 차단하지 않는다.

`fallback.json`은 현재의 무차단 안전 bundle로 유지한다. Round 중 자동 rollback은 추가하지 않는다.

## 판정 흐름

1. Broker가 전달한 inbound raw IP를 기존 parser가 최대 2KB payload view로 제한한다.
2. 기존 `HotPolicy`가 `TCP/8082` matcher를 한 번 실행한다.
3. 새 규칙이 plain 또는 percent-encoded target을 찾으면 `sig-l1-helper-secret` 사유로 `DROP`한다.
4. 다른 `/fetch` 요청, 다른 내부 경로, 다른 port, parser 실패는 기존 정책대로 `ACCEPT`한다.
5. 런타임은 승격 상태를 변경하지 않는다.

## 테스트 설계

새 테스트는 shipped `active.json`을 실제 로더로 읽으므로 정책 변경 전 반드시 실패해야 한다.

Positive fixture:

- `/fetch?url=http://helper-box:8080/secret`
- `/fetch?url=http%3A%2F%2Fhelper-box%3A8080%2Fsecret`
- `/%66%65%74%63%68?%75%72%6C=%68%74%74%70%3A%2F%2F%68%65%6C%70%65%72%2D%62%6F%78%3A%38%30%38%30%2F%73%65%63%72%65%74`

모두 TCP/8082에서 `DROP`, 새 rule ID와 reason code를 반환해야 한다.

Negative/SLA fixture:

- `/`
- `/fetch`
- `/fetch?url=http://127.0.0.1:5000/registry`
- `/fetch?url=http://127.0.0.1:5000/health`
- `/fetch?url=http://example.invalid/`
- 성공 exploit와 같은 payload를 TCP/8083으로 보낸 요청

이 fixture를 합쳐 최소 100회 반복해 전부 `ACCEPT`임을 검증한다. 이어서 shipped bundle이 `drop_capable_rules=1`, baseline이 `6/8082`, 새 규칙이 `ACTIVE`, 나머지 규칙이 `SHADOW`임을 검증한다.

최종 검증은 Defender 전체 단위 테스트, timing 테스트, `scripts/check-layout.ps1` 순서로 실행한다. 공식 skeleton 경로가 현재 환경에 있으면 `scripts/validate-skeleton.ps1`도 실행한다.

## 배포와 관찰

다음 이미지의 시작 로그에서 다음을 확인한다.

- `policy_source=active`
- `bundle_id=defender-2026-08-15-l1-ssrf-hotfix`
- `drop_capable_rules=1`
- `demotions=[]`

다음 Round에서는 Broker의 차단 수가 0보다 커지고 공식 SLA가 100%를 유지하는지를 함께 본다. flag 탈취가 계속되면 새 PCAP에서 우회 표현을 확인하고, 검증되지 않은 포괄 차단으로 확대하지 않는다.

## L1~L4 후속 개발 원칙

레이어는 누적 개방되므로 검증된 이전 레이어 규칙은 유지한다. 새 레이어는 PCAP·로그 수집, positive/negative fixture 작성, protocol/port scope 증명, SHADOW 또는 고신뢰 exact rule 승인, timing/SLA 회귀, 다음 이미지 반영 순서로 개발한다. 레이어 명칭이나 공식 세그먼트 표만으로 runtime field를 가정하지 않고 실제 Broker 패킷에서 확인한다.
