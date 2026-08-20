# 2026-08-20 본선 후보 독립 검증 판정

## 1. 한 줄 결론

최종 후보는 안정성·300ms proxy·known-capture 회귀는 통과했지만 공격 효과 퇴행, 방어 초기
fail-open 편차, L4·blind·공식 SLA·사람 점수 부재 때문에 **NOT_READY / HOLD**다.

이 판정은 공식 점수가 아닌 `SCRIMMAGE_PROXY`다. 예선 보고서와 예선 소스는 사용하지 않았다.

## 2. 분석 범위

- 실제 PCAP: 104개, `2026-08-15T01:00:14.748452Z`–`2026-08-15T12:40:17.443263Z`.
- 실제 agent log: 공격자 10개, 방어자 11개.
- capture/log 원본 inventory와 개별 SHA-256: `docs/reviews/2026-08-20-capture-log-forensics.md`
  §3. 이 inventory 문서의 SHA-256은
  `15dc7fab4dab5241aed1396f8dc77abfb5d107fe9aef29364e8727cc02fe7e6b`다.
- 최종 proxy: L1–L3, 2팀, 2×2 matrix, seed 301·302·303, 경기당 10초, 정상 요청
  12개. L4, 공식 SLA generator, blind holdout은 포함하지 못했다.
- `tshark`, `capinfos`, `tcpdump`은 사용할 수 없어 설치하지 않았다. 저장소의 aggregate-only
  Python replay를 사용했다.

## 3. Evidence inventory와 hash

### 3.1 고정 이미지

image manifest SHA-256:
`e18debb71a8ec4334a5902db38997a3e92ffdf46c5c7c3d07f2a05e440311595`

| ID | Runtime commit | Linux/amd64 image digest |
|---|---|---|
| A0 | `4931ce955c3f6401b74f5857e0bfee1b3e182369` | `sha256:261e014897b547bc218ef21d40257b4508eab413a35befa4e25cc904f6f7e4b2` |
| A1 | `dcda2e25ca9a2acb56f0827d9a6eafa1ec3f00b5` | `sha256:2fdef03092dd4b93ad41999921e449eaffa475e2940bbe7f3d70d9d130bcf6cc` |
| D0 | `4931ce955c3f6401b74f5857e0bfee1b3e182369` | `sha256:d9c6361aba12b79c9a449e6b9b4dd7620ee6dafae5018ed4594f8b483098ac48` |
| D1 | `da1c922c9fb947526fb9dc7503be6f4ea1dc0e9a` | `sha256:a548bcfd6b40a3180332e2a617bb9f45e5f971c20a4954a175e06498b04b58ee` |

네 이미지에서 대회용 제출 토큰, LLM 키, flag, cookie, session 환경변수는 0건이었다.

### 3.2 최종 match

- matrix index Evidence: `MATCH-INDEX-FINAL-301-303`
- matrix index SHA-256:
  `f499c6a44e34ab6ebf69bfb15908b7812d61b30acbef79520d30b30c6b8a475a`
- judgement Evidence: `JUDGE-FINAL-301-303`
- judgement SHA-256:
  `22883438f555b21c3dea5cb54083a4ac7901af9ccdfe3f4a2cc45c1d48fc59a4`

| Evidence ID | SHA-256 |
|---|---|
| `MATCH-A0D0-S301` | `b5ae4464480fc569dabc875428869c39043be862b99466196a022b71def2b48e` |
| `MATCH-A0D0-S302` | `1feac614b7a6fa73cba7b04548bb275d1671bc09b2ce2af60e9809f1ae5ab495` |
| `MATCH-A0D0-S303` | `48343df3c3affe6453782a62332c9b39e6cfcd0e16395c7aa46aff36403e4dbf` |
| `MATCH-A1D0-S301` | `81f35b07e8abcc221c5cdf7718d9c718119a8dbace6df736da15d81f21bd7380` |
| `MATCH-A1D0-S302` | `805e6fd0f2307a4ea114d5a17bccfeed95348bf070b53f6b24cf66bb4de04698` |
| `MATCH-A1D0-S303` | `4482a37b2554c287b53bd4dd3249a822dcf5adebef5b505c4eb6fc27ee5a0555` |
| `MATCH-A0D1-S301` | `400fe473738d213b9b069ddbe2faac3d0e2f2e63c6d5c9ed89576f906fd8c2c6` |
| `MATCH-A0D1-S302` | `f933766c20995e9213186f475328022070b28274b56f1bad347b19d5360953ce` |
| `MATCH-A0D1-S303` | `7a7d778094b26017dae08bade30e322a561a915b64362ac639b50ac5c84d5aa3` |
| `MATCH-A1D1-S301` | `0bb7f9485f0681b72d815635d87bd33fcff0c2130c6b8fe72fda623991f1cf21` |
| `MATCH-A1D1-S302` | `8cede46d3d86992f2f7cd72a076f9854e7f0221c279b2ae568daed4b98150864` |
| `MATCH-A1D1-S303` | `c4de06dbeea14e1bddbf8749a4a51c45cbdf1a22344b53f7636d82cb70980949` |

12개 result는 schema를 통과했고 index의 12개 SHA-256과 모두 일치했다. 결과와 judgement는
OS 임시 폴더에 있으며 Git에 포함하지 않았다.

## 4. PCAP·log 상관분석

| 판단 | 분류 | Evidence | 결과 |
|---|---|---|---|
| known L1–L3 exploit shape와 flag-linked response | `OBSERVED` | `PCAP-001`–`PCAP-104` | exploit shape 14,407개와 flag-linked request 2,133개를 직접 관측했다. |
| 현재 D1 policy의 known-shape 차단 | `OBSERVED` | `PCAP-001`–`PCAP-104` | 14,407/14,407 차단, other 65,067개 중 unexpected DROP 0. 공식 SLA 오탐률은 아니다. |
| 과거 attacker accepted 결과 | `OBSERVED` | `LOG-A-P2-R09`–`LOG-A-P3-R18` | 로그 10개에서 accepted 18개. timestamp 부재로 exact flow 연결은 불가능하다. |
| 방어 policy lifecycle와 capture round | `CONFIRMED` | `LOG-D-*`, 동일 round PCAP | startup·policy 상태와 round 수준의 exploit/flag response가 양쪽에 존재한다. exact packet verdict는 과거 로그에 없다. |
| proxy의 초기 fail-open 편차 | `INFERRED` | `MATCH-A0D1-S303`, `MATCH-A1D1-S303` | 한 방향은 초기 소수 요청으로 3개를 획득했고 반대 방향 D1은 DROP을 수행했다. 동시 startup 순서의 영향을 받았다고 추론하나 packet별 연결 시각은 없다. |
| P4/L4 공격·방어 효과 | `UNKNOWN` | 해당 capture/log 없음 | 공식 개방 사실 외에 실트래픽 근거가 없다. |

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
- 최종 proxy에서 A1은 D0 상대 seed별 0/0/0, A0는 3/0/3이었다. A1의 known-service
  first-success 경로가 startup 경쟁에서 느리거나 비결정적인 가능성이 있으나 first-flag timestamp가 없어
  원인은 `UNKNOWN`이다.
- A1 요청 합계는 A1D0에서 seed마다 30, A1D1에서 30/30/89였다. LLM call·token은 모두 0으로
  zero-token fallback은 동작했다.
- A0가 비정상 종료해 baseline 요청·token summary가 없어 정확한 요청 효율 비교는 `UNKNOWN`이다.
- 팀 총 예산 1,360달러는 확인했지만 모델별 가격표가 제공되지 않아 정확한 USD ledger를 만들지
  않았다. A1은 LLM 관측 입력을 redaction 후 8KiB로 제한하지만 이 제한을 달러 상한으로 표현하지 않는다.

## 7. 방어자의 미탐·오탐·가용성 위험

- final matrix 정상 요청은 144/144 성공했고 GC DROP은 0이었다.
- D1 verdict-send E2E max는 2,178.01us이며 300ms 초과는 0이었다.
- D1 경기마다 defender session 최소 1, heartbeat 최소 6, defender non-zero exit 0이었다.
- A0D1 대 A0D0의 stolen delta는 seed별 -3/0/0이었지만, A1D1 대 A1D0은 0/0/+3이었다.
  최악 seed에서 자기 flag 3개 추가 탈취를 허용했으므로 방어 효과 승격 조건을 충족하지 못했다.
- known capture replay의 오탐 대리값은 0이지만 공식 정상 SLA corpus와 L4 negative corpus가 없어
  실제 오탐률은 `UNKNOWN`이다.
- source IP 의존, 동기 LLM, parser-failure DROP을 새로 추가하지 않았다.

## 8. 증거 등급과 공동 루브릭

필수 게이트는 proxy 범위에서 모두 PASS했다.

| 게이트 | 판정 | 한계 |
|---|---|---|
| 규칙·범위 | PASS | 내부 proxy network와 허용 endpoint만 사용 |
| 증거 무결성 | PASS | 12/12 hash 일치, raw·비밀 Git 미포함 |
| 공식 인터페이스 | PASS (`PROXY`) | 공식 skeleton control·환경변수·Broker 계약 사용, 공식 채점 아님 |
| 방어 안전성 | PASS (`PROXY`) | 동기 LLM 0, 300ms 초과 0, session·heartbeat 정상 |
| 격리·재현성 | PASS | 고정 digest·seed·초기화, 잔존 container·runtime dir 0 |

| 영역 | 가중치 | AI 점수(0–4) | 사람 점수 | 가중 점수 | 판정 근거 |
|---|---:|---:|---|---:|---|
| 증거·추적성 | 15 | 2 | PENDING | 7.50 | known evidence와 match hash만 있음 |
| 공격 효과성 | 20 | 1 | PENDING | 5.00 | D0 상대 퇴행 |
| 방어 효과·가용성 | 25 | 1 | PENDING | 6.25 | 최악 seed stolen +3 |
| 일반화·적응성 | 15 | 2 | PENDING | 7.50 | known proxy seed 3개, blind 없음 |
| 성능·복원력 | 15 | 2 | PENDING | 7.50 | proxy timing·graceful exit 통과 |
| 운영 재현성 | 5 | 2 | PENDING | 2.50 | digest·seed·초기화 검증 |
| LLM 비용·관측성 | 5 | 2 | PENDING | 2.50 | A1 LLM 0, 종료 summary 확보 |

AI 가중 점수는 **38.75/100**이다. 사람 점수가 `PENDING`이므로 최종 합의 점수와 승인은 없다.

## 9. P0/P1/P2 개선 로드맵

| 우선순위 | Evidence | 단일 문제 | 성공 조건 | 첫 실패 테스트·예상 파일 | 위험·rollback | 소유자·reviewer |
|---|---|---|---|---|---|---|
| P0 | `MATCH-A1D1-S303` | 초기 fail-open에서 D1 보호 비결정 | 공식 start에서 startup→session→첫 공격 시각을 계측하고 blind 5개 중 4개 이상 stolen 비퇴행 | 공식 Arena lifecycle test; defender entrypoint/integration은 design delta 승인 후만 변경 | startup 지연·SLA 위험; 현재 image digest로 rollback | 방어자 + Docker owner; 팀장 필수 |
| P0 | L4 evidence 없음 | L4 효과 미검증 | 실 L4 capture/log inventory와 negative corpus 확보 | 먼저 분석 fixture ID만 추가, ACTIVE behavior 금지 | 추측 rule 오탐; 변경 없음이 rollback | 팀장 + 양 agent owner |
| P0 | `JUDGE-FINAL-301-303` | 사람 점수 부재 | 독립 사람 채점과 2단계 이상 차이 arbitration 완료 | score file validation | 부정확 승인; HOLD 유지 | 팀장 |
| P1 | `MATCH-A1D0-S301`–`S303` | A1 first-success 퇴행 | D0 상대 모든 blind seed에서 A0 이상, 요청 상한 유지 | sanitized first-request/first-accepted timing test; attacker runtime/result schema | startup 최적화가 탐색 공정성 훼손 가능; A0 rollback | 공격자 owner; contracts는 팀장 |
| P1 | `PCAP-001`–`104` | official SLA·DROP 부하 미검증 | 정상·공격 동시 부하에서 300ms 초과 0, 정상 실패 의미 있는 증가 0 | Broker E2E load/mutation tests | 과부하·오탐; D1 rollback | 방어자 + Docker owner + 팀장 |
| P1 | final seed 3개 | blind·mutation 부족 | blind seed 5개, encoding·TCP split·worker death·reconnect mutation 통과 | integration/scrimmage tests | known-data 과적합; HOLD | Arena operator + Judge |
| P2 | 1,360달러 공지 | USD 비용 산정 불가 | 운영진 모델별 단가표로 round·model ledger 생성 | cost parser tests | 잘못된 단가; token-only ledger로 rollback | 공격자 owner + 팀장 |
| P2 | tool 부재 | TCP expert 분류 미확정 | tshark 제공 환경에서 retransmission/out-of-order 재검증 | 분석 문서만 변경 | runtime 영향 없음 | 팀장 |

## 10. 실제 구현한 P0

- `1f9b20b`: redaction 뒤 LLM user content를 8KiB로 제한. 가격표 없는 달러 상한은 만들지 않았다.
- `cd503ce`: SIGTERM 시 새 공격 요청을 중단하고 single-flight waiter를 깨움.
- `95665d7`: 즉시 interrupt 대신 자연 종료해 최종 `round-summary`를 보존.
- `dcda2e2`: stop 뒤 cycle sleep을 건너뛰어 Docker stop timeout 내 exit 0 보장.
- `ea24ea7`: 공식 backend가 고정 combatant를 정확히 한 번 생성하도록 임시 read-only controller를
  사용해 runner의 이중 startup race를 제거.
- `b8593b6`: comma-separated seed를 정확히 세 개로 파싱.

새 공격 delivery, 새 방어 ACTIVE rule, contracts 의미, Dockerfile은 변경하지 않았다.

## 11. 추가·수정한 테스트

- LLM prompt cap과 redaction 후 길이 회귀.
- signal→stop request, in-flight waiter cancel, stop 이후 새 요청 금지.
- graceful signal이 예외를 올리지 않고 final summary를 남기는 경로.
- cycle 중 stop 이후 sleep 0회와 secret store cleanup.
- comma-separated seed 파싱과 정상 traffic generator.
- 공식 skeleton 기반 A1D1 smoke 및 2×2×3 matrix.

## 12. 실행 검증과 실제 결과

- attacker unittest: 234개, PASS.
- defender unittest: 340개 PASS, Windows capability skip 2. timing 포함; 측정 hot-path p99 최대
  117.1us, max 293.1us.
- scrimmage unittest: 2개 PASS; seed argument test PASS; 모든 scrimmage PowerShell parse PASS.
- capture-derived replay: 104 files, ingress 434,334, known exploit 14,407/14,407 차단,
  unexpected other DROP 0.
- `scripts/check-layout.ps1`: PASS.
- `scripts/validate-skeleton.ps1`: PASS.
- final smoke: 두 A1 모두 signal 1, round-summary 1, exit 0, 각 15요청, LLM 0.
- final matrix: 12/12 schema PASS, hash mismatch 0, 정상 실패 0, GC DROP 0, D1 300ms 초과 0,
  A1/D1 non-zero exit 0.
- `git diff --check`: PASS.
- `git ls-files -- '*.pdf' '*.pcap' '*.pcapng' '*.log'`: 출력 없음.

한 차례 방어 test 명령에서 `unittest discover`의 top-level 옵션을 빠뜨려 상대 import error 14개가
발생했다. 코드 failure가 아니며 `-t .`로 재실행해 340개를 통과했다.

## 13. 원본·비밀정보 Git 미포함 확인

- raw PCAP/log/PDF/gzip 파일은 이동·수정·복사·staging하지 않았다.
- result와 judgement는 Git 밖 임시 폴더에만 있다.
- Git diff에 raw evidence 확장자 0, 긴 flag 형태 추가 0, 추적된 금지 파일 0이다.
- 결과 artifact의 raw 비밀 패턴 탐지는 0이며 image에 대회 credential 환경변수는 없다.
- 루트 worktree의 기존 사용자 미추적 문서 두 개는 그대로 보존했다.

## 14. 남은 위험

- P4/L4 실증 없음.
- 공식 SLA generator·공식 점수 산식·12팀·20분 round와 다른 proxy다.
- blind holdout 5 seed와 사람 점수가 없다.
- D1 startup 초기 fail-open 편차가 있다.
- A1은 D0 상대 효과가 baseline보다 나빴다.
- baseline attacker가 SIGTERM exit 137로 요청·token·first-flag 비교가 불완전하다.
- first flag 획득 시각, peak memory, forced worker death/reconnect는 final matrix에 없다.
- 모델별 가격표가 없어 1,360달러 예산의 USD 집행 증명은 없다.

## 15. 다음 한 가지 행동

공식 Arena에서 defender session 연결 전후의 첫 공격·첫 verdict 시각을 비식별 계측한 blind seed
5개 대전을 실행하고, `MATCH-A1D1-S303`의 초기 3-flag 탈취가 재현되는지 먼저 판정한다. 재현 전에는
D1 승격이나 300ms hot-path 변경을 하지 않는다.
