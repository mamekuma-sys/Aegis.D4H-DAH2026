# 2026-08-20 본선 후보 독립 검증 판정

## 1. 한 줄 결론

최종 후보는 미지 포트에서 HTTP→HTTPS→무송신 TCP 관측으로 자동 적응하는 L4 폴백을
구현했고, known L1–L3 proxy에서 정상 요청 실패 0·300ms 초과 0을 달성했다. 다만 seed 404의
공격 효과 회귀와 A1D1 2개 seed의 startup fail-open 탈취, blind holdout·공식 SLA·사람 점수
부재가 남아 **NOT_READY / HOLD**다.

이 판정은 공식 점수가 아닌 `SCRIMMAGE_PROXY`다. 예선 보고서와 예선 소스는 사용하지 않았다.

## 2. 분석 범위

- 실제 PCAP: 104개, `2026-08-15T01:00:14.748452Z`–`2026-08-15T12:40:17.443263Z`.
- 실제 agent log: 공격자 10개, 방어자 11개.
- fresh filename audit에서 canonical `capture/`는 P1–P3/L1–L3, `log/`는 P2–P3이며
  P4/L4 파일은 0개였다. 제외 대상인 기존 `captures/` generated/history tree도 P1–P3/L1–L3뿐이고,
  그 안의 PCAP 70개 SHA-256은 모두 canonical 104개 중 하나와 일치했다.
- 최종 proxy: L1–L3, 2팀, 2×2 matrix, seed 404–408, 경기당 10초, route당 정상 요청 6개.
  총 20경기·정상 요청 720개다.
- 사용자 제공 최신 본선 조건 중 총 LLM 예산 1,360달러, `FLAG{...}` 형식, 레이어별 복수
  서비스·포트·flag, `linux/amd64`, 10 req/s burst 20, 제출 30/min, Broker 300ms 계약을 적용했다.
- L4 실 capture/log는 제공되지 않았으며, 이는 대기 사유가 아니라 당일 트래픽으로 폴백을
  튜닝할 제약이다. blind holdout, 공식 SLA generator, 모델별 USD 단가도 없다.
- `tshark`, `capinfos`, `tcpdump`은 사용할 수 없어 설치하지 않았다. 저장소의 aggregate-only
  Python replay를 사용했다.

## 3. Evidence inventory와 hash

원본별 Evidence ID·상대 파일명·크기·SHA-256·시간 범위·round·파싱 상태는
`docs/reviews/2026-08-20-capture-log-forensics.md` §3에 있다. 문서 SHA-256은
`15dc7fab4dab5241aed1396f8dc77abfb5d107fe9aef29364e8727cc02fe7e6b`다.

### 3.1 고정 이미지

image manifest SHA-256:
`906ea8dccf2a5a4c21f344dc494165b673bec606b9fe85761245fcf77574dde9`

| ID | Runtime commit | Linux/amd64 image digest |
|---|---|---|
| A0 | `4931ce955c3f6401b74f5857e0bfee1b3e182369` | `sha256:261e014897b547bc218ef21d40257b4508eab413a35befa4e25cc904f6f7e4b2` |
| A1 | `5b29b9538d83e4214bdaff0ce14285c81b040cb7` | `sha256:4c56e5ce80b843c22ef3fa42b27f21c7ccc7a8d5dc2d969c31217062886befa7` |
| D0 | `4931ce955c3f6401b74f5857e0bfee1b3e182369` | `sha256:d9c6361aba12b79c9a449e6b9b4dd7620ee6dafae5018ed4594f8b483098ac48` |
| D1 | `503332f92843316fb7d9c85ad604eea0c09ce3b9` | `sha256:08fb5675ea3ce7ef39c4cf0d6055b2f1352a5c8d5a6681a5aa947208fc189aba` |

네 이미지에서 대회용 제출 토큰, LLM 키, flag, cookie, session 환경변수는 0건이었다. D1은
UID 65534이고 네 이미지 모두 `linux/amd64`다.

### 3.2 최종 match

- matrix index Evidence: `MATCH-INDEX-FINAL-404-408`
- matrix index SHA-256:
  `d76fd761d9e30c491412706135ea60a9bb96b0198a48ed912e0774dfbb43f4a4`
- judgement Evidence: `JUDGE-FINAL-404-408`
- deterministic judgement SHA-256:
  `dd8456ebb9eb806c83cade44d31401a85282e03f5e3847bb86a642a5e40c343c`

| Evidence ID | SHA-256 |
|---|---|
| `MATCH-A0D0-S404` | `ed202798ae88edb54065620f82c454be266198c66446d2f870768df42cf72675` |
| `MATCH-A0D0-S405` | `d46fa8ed1252838ff6883dcda6f3490cef45986b4b3b79811c52ac4f4609330a` |
| `MATCH-A0D0-S406` | `313649ddb33c9a3c5eed521b7fb1f849312a69a5308cd24dc25281d44120c0ab` |
| `MATCH-A0D0-S407` | `a29c7743f712a2ccb692c0d540d9f11da9be5ed8870ba8ccbcd9db716982ce4f` |
| `MATCH-A0D0-S408` | `660713277a13194cd5f0b0344dc664852378f9b83a9ce1500c341d073c6d009b` |
| `MATCH-A1D0-S404` | `17f780b75aa3276a89f9162a1140225be5426a71e2119aa154e438d966b614d6` |
| `MATCH-A1D0-S405` | `5aceb985b4a163e5db46878932609d12cbc14acdfbddb6e57511d3d51563503a` |
| `MATCH-A1D0-S406` | `1cc52cffdbd33f51307993d8f185b299632471ac99e26e244083f14ceedc8bed` |
| `MATCH-A1D0-S407` | `24f2698be4c45cc3120c7f3c753d2196cbd496783f2802c4e71dcbbe129e555e` |
| `MATCH-A1D0-S408` | `05c5138fd9ead3ff088b601255d024b55bdab90d2a24ca57b134102f0995c4b5` |
| `MATCH-A0D1-S404` | `d9ff57417856234b8801cfb2c5b0ae11536c63c2791c9f6db2067573096f9c47` |
| `MATCH-A0D1-S405` | `23a84c77a16bfcff5da39ecddd914731f9cfbd1fd7498a370dfe2fb6cdfc0c00` |
| `MATCH-A0D1-S406` | `a6b0401a4f7220f305dcc605a562e0ccdb31a9f9021150d9cbca103b94e25107` |
| `MATCH-A0D1-S407` | `b9022798460a5b123d824b6c6f4b959307ae4154ac56192ef73917b9c3900ee9` |
| `MATCH-A0D1-S408` | `a57928b91af6ae324a7ef04dc41c7977d23830c3d6e223216ba344f75dcb6e0b` |
| `MATCH-A1D1-S404` | `9d5369e108daffcbbf4e3c1fb12e967e3d0667815a49519bec84eac57deec09b` |
| `MATCH-A1D1-S405` | `937d350fcf68af0415f725283d6a4a76a913d13ad1e421f056e0ac02d1a73857` |
| `MATCH-A1D1-S406` | `d0606e7a2c513a1e015ecace103a63c352be6b6abab079bde4dec3fbc0bae090` |
| `MATCH-A1D1-S407` | `edaf9585b6370bebf43613b6215b76b8c1c60e433a15cd4b05d7b509d0b2f0a7` |
| `MATCH-A1D1-S408` | `e261054f64e53c3025cf19ad4a8f8e0f439e18a08b623d308e30db96c9906343` |

20개 result는 schema를 통과했고 index의 20개 SHA-256과 모두 일치했다. result·index·judgement는
OS 임시 폴더에 있으며 Git에 포함하지 않았다.

## 4. PCAP·log 상관분석 결과

| 판단 | 분류 | Evidence | 결과 |
|---|---|---|---|
| known L1–L3 exploit shape와 flag-linked response | `OBSERVED` | `PCAP-001`–`PCAP-104` | exploit shape 14,407개, flag-linked request 2,133개를 직접 관측했다. |
| 현재 D1 policy의 known-shape 차단 | `OBSERVED` | `PCAP-001`–`PCAP-104` | 14,407/14,407 차단, other 65,067개 중 unexpected DROP 0. 공식 SLA 오탐률은 아니다. |
| 과거 attacker accepted 결과 | `OBSERVED` | `LOG-A-P2-R09`–`LOG-A-P3-R18` | 로그 10개에서 accepted 18개. timestamp 부재로 exact flow 연결은 불가능하다. |
| 방어 lifecycle와 capture round | `CONFIRMED` | `LOG-D-*`, 동일 round PCAP | startup·policy 상태와 round 수준 exploit/flag response가 양쪽에 있다. 과거 packet별 verdict는 없다. |
| A1의 D0 상대 효과 | `OBSERVED` (`PROXY`) | `MATCH-A0D0-*`, `MATCH-A1D0-*` | capture delta seed별 -3/+3/0/+6/0, median 0, 최악 -3으로 seed 404에서 회귀했다. |
| D1의 known proxy 보호 | `OBSERVED` (`PROXY`) | `MATCH-A0D1-*`, `MATCH-A1D1-*` | A0D1은 5/5 capture 0, A1D1은 seed 404·405에서 3개씩 탈취됐다. D0 대비 seed 404는 회귀했고 나머지는 비퇴행이며 정상 실패는 0이다. |
| startup fail-open 탈취 | `OBSERVED` (`PROXY`) | `MATCH-A1D1-S404`, `S405` | accepted capture가 피해 defender session 연결보다 각각 17ms·12ms 앞섰다. |
| L4 readiness branch 상태 | `OBSERVED` | `d1107ca`, `e2e8200` | `fix/finals-multiflag-l4-readiness` 변경은 main과 후보에 이미 포함됐다. 공격은 응답이 명시한 GET route로 제한되고 방어는 service observation만 기록하며 verdict를 바꾸지 않는다. |
| L4 다중 서비스 안전 경계 | `OBSERVED` (`PROXY`) | `TEST-L4-MULTIPORT`, `TEST-L4-MUTATION`, `TEST-L4-NEGATIVE` | 서로 다른 두 포트의 route·parameter와 복수 flag를 분리하고, query 순서·encoding을 정규화하며, traversal·파괴 route를 거부했다. action-like TCP/UDP는 방어에서 ACCEPT했다. |
| L4 적응형 전송 폴백 | `OBSERVED` (`PROXY`) | `TEST-L4-HTTPS-ADAPTIVE`, `TEST-L4-PASSIVE-TCP`, `TEST-L4-LOOPBACK-INTEGRATION` | HTTP 무응답 후 HTTPS, 둘 다 무응답이면 4KiB/750ms 한계의 무송신 TCP banner로 적응했다. 실 socket 통합에서 두 서비스의 합성 flag 3개를 LLM 0으로 회수했다. |
| L4 TLS 정상 트래픽 안전성 | `OBSERVED` (`PROXY`) | `TEST-L4-TLS-NEGATIVE` | TLS-like 패킷에 새 ACTIVE rule을 적용하지 않고 ACCEPT했다. |
| P4/L4 실전 공격·방어 효과 | `UNKNOWN` | 해당 capture/log 없음 | 런타임 폴백은 구현했지만 실전 효과는 당일 트래픽에서 검증해야 한다. |

테스트의 `8085`, UGV banner, 합성 route와 합성 flag는 parser·계약 회귀용이며 실제 L4 interface
Evidence로 승격하지 않았다.

## 5. 확인된 실제 공격 성공·실패 패턴

실제 PCAP에서 확인한 구조 fingerprint는 다음뿐이다.

| Exploit-shape ID | Layer | 구조 | 시도 | flag-linked |
|---|---:|---|---:|---:|
| `EXP-L1-HELPER-SSRF` | L1 | bounded fetch route + helper service + secret path | 5,814 | 1,016 |
| `EXP-L1-CONFIG-TRAVERSAL` | L1 | bounded config route + traversal depth | 1,944 | 1 |
| `EXP-L2-FORGED-ADMIN` | L2 | Base64 JSON session + bounded admin claim | 3,857 | 932 |
| `EXP-L2-SECRET-SSRF` | L2 | bounded fetch route + loopback service + secret path | 835 | 1 |
| `EXP-L2-REGISTRY-SSRF` | L2 | bounded fetch host parameter + loopback registry path | 876 | 1 |
| `EXP-L3-APP-META-SQLI` | L3 | bounded metadata query + UNION shape | 1,081 | 171 |

새 취약점이나 L4 프로토콜은 가정하지 않았다. flag-linked이지만 fingerprint 밖인 12개 요청은 FIFO
귀속 오차 가능성이 있어 새 ACTIVE rule 근거로 사용하지 않았다.

## 6. 공격자가 놓친 기회와 예산 낭비

- 실제 과거 로그는 accepted 정체 뒤에도 요청과 token이 계속 증가한 round를 보여 준다.
- 최종 proxy에서 A1은 D0 상대 seed별 0/6/3/6/6, A0는 3/3/3/0/6을 획득했다.
  capture delta median은 0이지만 seed 404에서 -3 회귀했고, 양쪽 모두 성공한 3개 seed의 first flag
  delta median은 -108ms다.
- A1D0의 양 팀 합산 요청은 seed별 30/145/89/145/145, A1D1은 87/89/30/30/30이었다.
  증거가 없거나 D1에 차단된 seed에서 30회로 중단했고, 성공 seed에서만 추가 flag를 회수했다.
- A1의 LLM call·token은 모든 경기에서 0으로 zero-token fast path가 동작했다.
- A0는 종료 summary가 없어 baseline 요청·token 비교는 `UNKNOWN`이다. A0 조합에는 경기당
  non-zero container exit 2개가 있으나 A1 조합은 0이다.
- 1,360달러 총예산은 확인했지만 모델별 단가가 없어 정확한 USD ledger는 만들지 않았다. A1은
  redaction 뒤 LLM user content를 8KiB로 제한하나 이를 달러 상한으로 표현하지 않는다.

## 7. 방어자의 미탐·오탐·가용성 위험

- 최종 matrix 정상 요청은 720/720 성공했고 최대 latency는 17.809ms, GC DROP은 0이었다.
- D1 verdict-send E2E max는 1,873.128us이며 300ms 초과는 0이었다.
- D1 10경기 모두 session 1개, heartbeat 최소 7개, defender non-zero exit 0이었다.
- D1 victim session 연결 offset은 399–518ms다. A1D1의 seed 404·405에서 연결보다 17ms·12ms 앞선
  accepted capture가 직접 관측되어 Broker startup fail-open이 해소되지 않았다.
- D1은 A0에는 seed 5개 모두 탈취 0, A1에는 seed 404·405에서 3개씩 탈취를 허용했다.
  D0 대비 seed 404의 stolen delta는 +3 회귀였고, 나머지 seed는 개선·비퇴행이었다.
- known capture replay의 오탐 대리값은 0이지만 공식 정상 SLA corpus와 L4 negative corpus가 없어
  실제 오탐률은 `UNKNOWN`이다.
- source IP 의존, 동기 LLM, parser-failure DROP을 새로 추가하지 않았다.

## 8. 증거 등급과 공동 루브릭

필수 게이트는 proxy 범위에서 모두 PASS했다.

| 게이트 | 판정 | 한계 |
|---|---|---|
| 규칙·범위 | PASS | 내부 proxy network와 허용 endpoint만 사용 |
| 증거 무결성 | PASS | 20/20 hash 일치, raw·비밀 Git 미포함 |
| 공식 인터페이스 | PASS (`PROXY`) | 공식 skeleton control·환경변수·Broker 계약 사용, 공식 채점 아님 |
| 방어 안전성 | PASS (`PROXY`) | 동기 LLM 0, 300ms 초과 0, session·heartbeat 정상 |
| 격리·재현성 | PASS | 고정 digest·seed·초기화, 잔존 container·runtime dir 0 |

| 영역 | 가중치 | AI 점수(0–4) | 사람 점수 | 가중 점수 | 판정 근거 |
|---|---:|---:|---|---:|---|
| 증거·추적성 | 15 | 2 | PENDING | 7.50 | known evidence와 match hash만 있음 |
| 공격 효과성 | 20 | 1 | PENDING | 5.00 | known seed 404 회귀, blind·실 L4 없음 |
| 방어 효과·가용성 | 25 | 1 | PENDING | 6.25 | 정상 실패 0이나 seed 404 회귀·startup 전 탈취 존재 |
| 일반화·적응성 | 15 | 2 | PENDING | 7.50 | known proxy seed 5개, blind 없음 |
| 성능·복원력 | 15 | 2 | PENDING | 7.50 | proxy timing·heartbeat·graceful exit 통과 |
| 운영 재현성 | 5 | 2 | PENDING | 2.50 | digest·seed·초기화·deterministic judge 검증 |
| LLM 비용·관측성 | 5 | 2 | PENDING | 2.50 | A1/D1 LLM 0, 종료 summary 확보 |

AI 가중 점수는 **38.75/100**이다. known evidence만 있고 회귀 seed가 있으므로 공격·방어는 1점, 나머지는
최대 2점으로 제한했다. 사람 점수가
`PENDING`이므로 최종 합의 점수와 승인은 없다.

## 9. P0/P1/P2 개선 로드맵

| 우선순위 | Evidence | 단일 문제 | 성공 조건 | 첫 실패 테스트·예상 파일 | 위험·rollback | 소유자·reviewer |
|---|---|---|---|---|---|---|
| P0 | `MATCH-A1D1-S404`, `S405` | startup 연결 전 탈취 | fresh 5 seed에서 pre-session capture 0 | startup ordering 실패 회귀; defender/Arena 설계 delta 먼저 | fail-closed·지연은 SLA 위험; 현 D1 digest rollback | 방어자 + Docker owner + 팀장 |
| P0 완료(PROXY) | `TEST-L4-*` | 미지 L4 transport에서 HTTP만 시도 | HTTP→HTTPS→무송신 TCP, 4KiB/750ms, 파괴 요청 0, 합성 다중 flag 3/3 | adaptive transport·실 socket integration·TLS negative tests | 실 L4 효과는 당일 검증; 이전 A1 digest rollback | 공격자 owner + 팀장, Docker owner review |
| P0 | `MATCH-A1D0-S404` | 공격 효과 seed 회귀 | fresh known 5 seed 최악 delta 0 이상 | scheduler/bootstrap deterministic regression | 과탐색·지연; 현 A1 digest rollback | 공격자 owner + 팀장 |
| P0 | `JUDGE-FINAL-404-408` | 사람 점수 부재 | 구조화된 독립 사람 채점과 2단계 이상 차이 arbitration 완료 | human score 유효·범위 초과·누락 파일 회귀 | 부정확 승인; HOLD 유지 | 팀장 |
| P1 | final known seed 5개 | blind·공식 SLA 미검증 | blind 5개 중 4개 이상 baseline 이상, 정상 가용성 비퇴행 | official Arena lifecycle/SLA test | known-data 과적합; HOLD | Arena operator + Judge |
| P1 | `MATCH-A1D0-*` | 요청 효율의 baseline 비교 불완전 | A0/A1 모두 graceful summary, accepted/request 직접 비교 | baseline-compatible summary reader | baseline 의미 변경; 기존 A0 digest 유지 | 공격자 owner + Judge |
| P1 | `PCAP-001`–`104` | TCP·부하 일반화 미검증 | encoding·TCP split·retransmit·worker death·reconnect mutation 통과 | Broker E2E mutation tests | 오탐·deadline 위험; D1 rollback | 방어자 + Docker owner + 팀장 |
| P2 | 1,360달러 공지 | USD 비용 산정 불가 | 운영진 모델별 단가로 round·model ledger 생성 | cost parser tests | 잘못된 단가; token-only ledger rollback | 공격자 owner + 팀장 |
| P2 | tool 부재 | TCP expert 분류 미확정 | tshark 제공 환경에서 retransmission/out-of-order 재검증 | 분석 문서만 변경 | runtime 영향 없음 | 팀장 |

`contracts/**`의 timing 필드 변경은 팀장 이경준 검토가 필요하다. 두 Dockerfile의 bytecode 변경은
Docker owner, 각 agent owner, 팀장 검토 없이는 승격하지 않는다.

## 10. 실제 구현한 P0 한 건

구현한 P0는 **미지 L4의 관측 기반 adaptive transport discovery** 한 건이다.

- `c220a64`: 미확인 포트의 recon을 상태·문서용 GET 6개로 제한하고 `/flag`, `/admin`,
  `/.git/config` 같은 범용 경로 추측을 제거했다.
- plaintext·OpenAPI의 읽기 전용 GET route와 query parameter를 정확한 route별로 결속한다.
- query 순서와 percent-encoded parameter 이름은 정규화하지만 traversal·파괴적 action route는 거부한다.
- `5b29b95`: 미지 endpoint에서 HTTP GET `/`을 먼저 시도하고 무응답일 때만 HTTPS로 재시도한다.
  둘 다 무응답일 때만 TCP 연결 후 client application byte를 0바이트로 유지하며 서버 banner를
  최대 4KiB, 750ms만 읽는다. UDP probe와 UGV 전용 명령은 추가하지 않았다.
- 실 loopback socket에서 HTTP L4 서비스와 passive TCP 서비스를 동시에 실행해 합성 flag 3개를
  LLM 0으로 회수했고, passive connection의 client application byte는 0이었다.
- 자체 서명 TLS 허용은 `ATTACK_TARGET`에만 제한했고 submit·LLM의 인증서 정책은 바꾸지 않았다.
- 방어는 action-like L4 TCP/UDP를 observation-only로 기록하고 ACCEPT한다. 새 ACTIVE rule은 없다.
- 새 A1은 `linux/amd64` digest
  `sha256:4c56e5ce80b843c22ef3fa42b27f21c7ccc7a8d5dc2d969c31217062886befa7`로 동결했다.

이는 승인된 관측→계획→실행 경계 안의 discovery 제한이며 구체 L4 취약점·protocol을 추가하지 않는다.
rollback은 이전 A1 digest 또는 `5b29b95` revert다. 실제 L4 효과는 `UNKNOWN`이지만 미지
transport에 대한 안전한 런타임 대응은 완료했다.

## 11. 추가·수정한 테스트

- `TEST-L4-MULTIPORT`: 두 L4 포트의 서로 다른 route·parameter와 복수 flag 상태 격리.
- `TEST-L4-MUTATION`: query 순서·percent encoding 정규화와 unobserved parameter 거부.
- `TEST-L4-NEGATIVE`: destructive/traversal GET 거부, action-like TCP/UDP ACCEPT.
- `TEST-L4-HTTPS-ADAPTIVE`: HTTP 무응답 후 target-local HTTPS fallback과 endpoint 정체성 유지.
- `TEST-L4-PASSIVE-TCP`: 정확한 host·port scope, 4KiB/750ms 한계, client application byte 0.
- `TEST-L4-LOOPBACK-INTEGRATION`: 실 HTTP/TCP socket·submit server에서 합성 flag 3개 accepted, LLM 0.
- `TEST-L4-TLS-NEGATIVE`: TLS-like 정상 패킷의 방어 ACCEPT.
- unknown L4에서 범용 `/flag`·`/admin`·`/.git/config` probe가 0인지 검증.
- 기존 container timing, image bytecode, judge 결정성, human-score schema, cooldown, capture-derived
  parser·policy 회귀는 계속 유지했다.

## 12. 실행 검증과 실제 결과

- attacker unittest: 246개 PASS. 실 loopback adaptive L4 integration 포함.
- defender unittest: 341개 PASS, Windows capability skip 2. timing 포함; 측정 hot-path p99 최대
  53.7us, max 125.2us.
- capture-derived replay: 104 files, HTTP 79,474, known exploit 14,407/14,407 차단,
  other 65,046 pass + 21 coalesced, unexpected other DROP 0.
- scrimmage unittest: Python 2개 PASS; seed·log timing·attacker bytecode·defender bytecode·judge
  determinism PASS.
- 실제 20-match judgement를 연속 두 번 생성해 SHA-256
  `dd8456ebb9eb806c83cade44d31401a85282e03f5e3847bb86a642a5e40c343c` 일치.
- `scripts/check-layout.ps1`: PASS.
- `scripts/validate-skeleton.ps1`: PASS.
- final matrix: 20/20 schema PASS, hash mismatch 0, 정상 720/720, GC DROP 0, D1 300ms 초과 0,
  candidate container non-zero exit 0. D1 session당 heartbeat 최소 7, A1D1 pre-session capture seed는 2개다.
- `git diff --check`: PASS.
- `git ls-files -- '*.pdf' '*.pcap' '*.pcapng' '*.log'`: 출력 없음.

L4 회귀 작성 중 route 간 parameter 교차, destructive route 허용, unknown 포트의 범용 경로 probe를
각각 실패로 재현한 뒤 최소 변경으로 수정했다. 재대전에서는 startup fail-open을 다시 관측했으며 이
turn에서 방어 설계·Docker를 추가 변경하지 않고 P0 blocker로 남겼다.

## 13. 원본·비밀정보 Git 미포함 확인

- raw PCAP/log/PDF/gzip 파일은 이동·수정·복사·staging하지 않았다.
- result·index·judgement는 Git 밖 임시 폴더에만 있다.
- Git diff에 raw evidence 확장자 0, 실제 flag 0이고 flag 문자열은 합성 fixture에만 있으며,
  추적된 금지 파일은 0이다.
- 결과 artifact의 raw 비밀 패턴 탐지는 0이며 image에 대회 credential 환경변수는 없다.
- 루트 worktree의 기존 사용자 미추적 문서 두 개는 그대로 보존했다.

## 14. 남은 위험

- P4/L4 실전 효과는 당일 검증 필요. 단, HTTP→HTTPS→무송신 TCP 폴백은 이미 구현·합성 검증됨.
- 공식 SLA generator·공식 점수 산식·12팀·20분 round와 다른 2팀 10초 proxy다.
- blind holdout과 사람 점수가 없다.
- startup fail-open이 known proxy A1D1 2/5 seed에서 직접 재현됐다.
- A1이 D0 상대 seed 404에서 baseline보다 flag 3개 적게 획득했다.
- 공식 정상 corpus, peak memory, forced worker death/reconnect의 최종 5-seed 증거가 없다.
- A0 종료 summary가 없어 요청·token 효율 baseline 비교가 불완전하다.
- 모델별 가격표가 없어 1,360달러 예산의 USD 집행 증명은 없다.
- contracts 및 Docker 변경은 필수 reviewer 승인이 없다.

## 15. 다음 한 가지 행동

팀장·공격자·Docker owner가 `5b29b95` 설계 delta와
`sha256:4c56e5ce80b843c22ef3fa42b27f21c7ccc7a8d5dc2d969c31217062886befa7`을 검토한 뒤 승인 시에만
승격한다. 당일 첫 L4 트래픽은 새 폴백이 즉시 관측하고, 10분 제공 capture/log로
service fingerprint·cooldown을 갱신하되 미확인 전용 명령은 보내지 않는다.
