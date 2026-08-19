# L1~L4 증거 기반 적용·승격 메타 프롬프트

## 목적

이 프롬프트는 본선 L1~L4 전체에 대해 공격 동작과 방어 규칙을 관측 가능한 인터페이스에만
결속하고, 규칙별 검증이 끝난 경우에만 `SHADOW`에서 `ACTIVE`로 승격하기 위한 자기 점검 절차다.
레이어가 열렸다는 사실, 데모 문제, 예선 시나리오 또는 LLM의 추측만으로 포트·경로·프로토콜·신호를
만들지 않는다.

## 권위 입력

다음 순서로 사실을 결정한다.

1. 같은 날 운영진 직접 안내와 최신 본선 운영세칙
2. 공식 스켈레톤 `deploy/docs/agent-guide.md`
3. 공식 스켈레톤과 Broker의 직접 관측 동작
4. 운영진이 제공한 실제 Round PCAP·로그·SLA 결과
5. 예선 보고서·예선 소스
6. 팀 작성 문서와 합성 fixture

원본을 현재 작업 환경에서 직접 열 수 없으면 체크리스트나 과거 매핑을 원본을 읽은 것처럼
대체하지 않는다. 해시와 파생 조항 매핑은 입력의 동일성을 추적하는 자료일 뿐이다.

## 자기 적용용 프롬프트

```text
너는 DAH 2026 본선 공격·방어 이미지의 증거 감사자다. L1~L4를 각각 독립된 profile로 다루고,
아래 절차를 순서대로 수행하라.

1. 모든 입력의 파일 ID, SHA-256, 관측 시각과 권위를 표로 만든다. 원본 부재와 파생 자료를
   명시적으로 구분한다.
2. `FinalsPhase`, 문제 레이어 L1~L4, OSI transport layer를 혼동하지 않는다.
3. 공격 인터페이스는 운영 측 `TARGETS × PORTS`와 해당 endpoint의 실제 응답에서만 만든다.
   root, bounded probe, robots.txt 또는 OpenAPI가 명시한 읽기 전용 GET route·parameter만 미확인
   endpoint의 첫 후보로 사용한다. 다른 레이어의 playbook은 현재 endpoint의 독립 관측을 대신하지
   못한다.
4. 방어 인터페이스는 Broker가 전달한 raw IP에서 parser가 증명한 필드만 사용한다. vehicle state,
   parameter hash, mission 의미, outbound response 또는 레이어 번호를 패킷에 있다고 가정하지 않는다.
5. 후보 규칙마다 protocol, port/profile, parser version, exact match 의미, positive fixture,
   동일 profile 정상 negative fixture, SLA fixture, 만료, rollback 조건, owner review와 lead review를
   요구한다. 하나라도 없거나 `pending`이면 SHADOW다.
6. positive는 해당 레이어의 실제 공격 또는 flag 획득과 논리적으로 연결되어야 한다. 데모 문제와
   합성 fixture는 parser·결속 단위 테스트에는 쓸 수 있지만 본선 레이어 승격 증거로 쓰지 않는다.
7. 전체 누적 레이어 PCAP을 실제 HotPolicy로 재생한다. 관측된 positive 누락 0, 독립 정상 요청의
   예상 밖 DROP 0을 요구하고, 같은 패킷에 병합된 요청은 별도 수치로 남긴다.
8. 공식 Broker의 PACKET→VERDICT 물리 송신 경로에서 300ms 초과 0, heartbeat·재연결 정상,
   bounded memory를 확인한다. 단위 hot-path 시간만으로 E2E를 통과했다고 쓰지 않는다.
9. 원격 LLM은 방어 packet별 동기 verdict 경로에 넣지 않는다. packet-derived metric이나 LLM 제안이
   runtime 중 정책 상태를 바꾸지 못하게 한다.
10. 승격은 규칙별 새 정적 bundle로만 수행한다. 모든 gate를 통과한 규칙만 ACTIVE로 바꾸고,
    근거가 넓거나 레이어 귀속이 불명확한 규칙은 기존 승격 이력이 있어도 SHADOW로 둔다.
11. 출력은 레이어별 `GO`, `NO-GO`, `NOT-APPLICABLE` 중 하나와 근거·결손·변경·검증 명령을 제시한다.
    `NO-GO`이면 상태 문자열을 바꾸지 말고 관측 기능과 다음 Break 입력 목록만 갱신한다.
12. 마지막에 policy의 실제 ACTIVE ID 목록과 개수, 남은 SHADOW ID 목록, PCAP 범위,
    Broker E2E 범위, 아직 증명되지 않은 주장을 다시 대조한다.
```

## 현재 입력에 대한 자기 적용

### 입력 동일성

| 입력 | 현재 증거 | 판정 |
|---|---|---|
| 본선 운영세칙 | 기대 SHA-256 `FFE8E6BEECB628F93F20A9F5D0F41203CADBF28EE7E56C9A91FDAB87A1655A5F`; 저장소에는 해시·조항 매핑만 있고 현재 로컬 원본은 없음 | 원본 재열람 gate 미완료 |
| 공식 스켈레톤 ZIP | SHA-256 `C7C67CFB10CF6D1FA0997D19EAF1DF0D7347E2C66E4F417637D866B6CCA6DF2C` | 일치 |
| 공식 `deploy/` 34개 파일 | tree SHA-256 `8B7552FB285C3DBB75285BB083F09A5B72322B867F2472A873C2C738C20C73CE` | 일치·전체 고유 텍스트 재검토 |
| 공식 agent guide | SHA-256 `8E7AC90ABB3186DEC73DC0AAF556F21B0A96E18F2532CFF59CB8D7A31FE9BCDB` | 일치 |
| 공식 Compose | SHA-256 `5F4ABE70556E15EDCBAF9D73BBED0A38338FA55C552EFB4C515E4C2D24539B21` | 일치 |
| 공식 Broker | SHA-256 `DDA8A4C5E2678635080F377C93C6FC3FE3E7AA3448B91B0FA8E4C8564D43E857` | 일치·x86-64 실기 완료 |
| TEAM1 전체 PCAP snapshot | 104개, tree SHA-256 `98F87267ADD41B441B125F2919F53DB98F867ED6FB590A7B53C6896F976BF909` | L1~L3만 관측 |

공식 스켈레톤의 데모 문제는 본선 문제와 무관하다고 README가 명시한다. Compose·backend·capture는
L1~L3과 TCP `8082`~`8084`만 구성한다. Router entrypoint의 기본 `LAYERS=1,2,3,4`와
`ENTRY_L4`·`CHAL_L4` 확장 슬롯은 L4 챌린지의 실제 port·route·protocol 증거가 아니다.

### 레이어별 판정

| 레이어 | 관측 범위 | 승격 결과 | 자기 적용 판정 |
|---|---|---|---|
| L1 / TCP 8082 | 실제 flag 응답 1,017건과 helper secret SSRF·config flag traversal; 동일 profile 정상 traffic | exact request-line 2개와 canonical HTTP 의미 1개, 합계 3개 ACTIVE | `GO` |
| L2 / TCP 8083 | 실제 flag 응답 941건과 forged admin cookie·loopback secret/registry SSRF; 동일 profile 정상 traffic | exact request-line 1개와 canonical HTTP 의미 3개, 합계 4개 ACTIVE | `GO` |
| L3 / TCP 8084 | 실제 flag 응답 176건과 `app_meta` SQLi; 직접 노출 route는 차단 근거에서 제외 | exact request-line 1개와 canonical HTTP 의미 1개, 합계 2개 ACTIVE | `GO` |
| L4 / UGV | phase 명칭과 누적 개방만 확인; 실제 PCAP·port·route·normal traffic 없음 | ACTIVE 0, observation-only | `NO-GO` |

현재 ACTIVE 9개는 `agents/defender/policy/active.json`의 다음 규칙이다.

- L1: `sig-l1-helper-secret-001`, `http-l1-helper-secret-canonical-001`,
  `sig-l1-config-flag-traversal-001`
- L2: `http-l2-forged-admin-session-001`, `sig-l2-loopback-secret-001`,
  `http-l2-loopback-secret-canonical-001`, `http-l2-loopback-registry-canonical-001`
- L3: `sig-l3-app-meta-union-001`, `http-l3-app-meta-canonical-001`

기존 13개 광범위 규칙은 특정 본선 공격 형태에 대한 exact 의미와 정상 negative 범위가 부족하므로
레이어 수와 무관하게 SHADOW를 유지한다. 이 중 과거 L2 PCAP ID가 기록된 규칙도 넓은 정규식 자체가
승격 gate를 통과한 것은 아니다.

### 누적 검증 판정

- 실제 HotPolicy로 104개 PCAP을 재생했을 때 관측 공격 형태 14,407/14,407 차단,
  독립 기타 요청의 예상 밖 DROP 0, 병합 요청 21건이었다.
- 공식 x86-64 Broker 실기에서 PACKET 116건, ACCEPT 80, DROP 36, heartbeat 65,
  verdict E2E p99 13.41ms, max 14.12ms, 300ms 초과 0이었다.
- 공격·방어 단위 테스트와 linux/amd64 이미지·CI는 현재 bundle의 L1~L3 ACTIVE 9개와
  미확인 L4 observation-only 경계를 검증한다.
- 이 결과는 L1~L3의 현 규칙을 증명하지만 L4 승격을 증명하지 않는다.

## 적용 결과와 다음 입력

현재 자료로 정당한 최종 상태는 `L1=ACTIVE`, `L2=ACTIVE`, `L3=ACTIVE`,
`L4=observation-only`다. L4를 ACTIVE로 만들려면 다음 Break에서 실제 L4에 대해 protocol·port·route
inventory, flag-linked positive, 동일 profile 정상 negative, SLA fixture와 공식 Broker 누적 재검증을
먼저 확보해야 한다. 원본 운영세칙도 기대 해시와 일치하는 파일을 다시 열어 이 문서의 규칙 조항과
새 공지가 충돌하지 않는지 확인해야 한다.
