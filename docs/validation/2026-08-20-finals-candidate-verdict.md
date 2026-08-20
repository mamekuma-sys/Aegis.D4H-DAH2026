# 2026-08-20 본선 후보 독립 검증 판정

## 1. 한 줄 결론

최종 후보는 known L1–L3 proxy 5개 seed에서 공격 효과 비퇴행, 정상 요청 실패 0, 300ms 초과 0을
달성했지만 A1D1 3개 seed의 startup fail-open 탈취와 L4 실증·blind holdout·공식 SLA·사람 점수
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
- L4 실 capture/log, blind holdout, 공식 SLA generator, 모델별 USD 단가는 제공되지 않았다.
- `tshark`, `capinfos`, `tcpdump`은 사용할 수 없어 설치하지 않았다. 저장소의 aggregate-only
  Python replay를 사용했다.

## 3. Evidence inventory와 hash

원본별 Evidence ID·상대 파일명·크기·SHA-256·시간 범위·round·파싱 상태는
`docs/reviews/2026-08-20-capture-log-forensics.md` §3에 있다. 문서 SHA-256은
`15dc7fab4dab5241aed1396f8dc77abfb5d107fe9aef29364e8727cc02fe7e6b`다.

### 3.1 고정 이미지

image manifest SHA-256:
`5192629e66b26acac17fc859281d1bade4a8c571c0d78eea3bc4cf3c747b8faa`

| ID | Runtime commit | Linux/amd64 image digest |
|---|---|---|
| A0 | `4931ce955c3f6401b74f5857e0bfee1b3e182369` | `sha256:261e014897b547bc218ef21d40257b4508eab413a35befa4e25cc904f6f7e4b2` |
| A1 | `c220a648aa1534d43ceb1c086ccd9dd04915d6d7` | `sha256:a6921bd03e3d7babad9b52b9a6d8e02caf90d96c859922416ae74b109c496d2e` |
| D0 | `4931ce955c3f6401b74f5857e0bfee1b3e182369` | `sha256:d9c6361aba12b79c9a449e6b9b4dd7620ee6dafae5018ed4594f8b483098ac48` |
| D1 | `503332f92843316fb7d9c85ad604eea0c09ce3b9` | `sha256:08fb5675ea3ce7ef39c4cf0d6055b2f1352a5c8d5a6681a5aa947208fc189aba` |

네 이미지에서 대회용 제출 토큰, LLM 키, flag, cookie, session 환경변수는 0건이었다. D1은
UID 65534이고 네 이미지 모두 `linux/amd64`다.

### 3.2 최종 match

- matrix index Evidence: `MATCH-INDEX-FINAL-404-408`
- matrix index SHA-256:
  `7d098601973f19f29ccff93906851faa982ee2b92b8508651976721d0795e809`
- judgement Evidence: `JUDGE-FINAL-404-408`
- deterministic judgement SHA-256:
  `c85c84b6d8fdbed29dbab6bd364c452ce166f5bd62ef425249febde0b723b1d1`

| Evidence ID | SHA-256 |
|---|---|
| `MATCH-A0D0-S404` | `b5ef6270ea3a6d30e523bac251e7e749ac81fc532e1f258f5e44522f0b665fd7` |
| `MATCH-A0D0-S405` | `524532c9debbe745d586838d15ccd82c23d6be7cd5638002af4d6c6e84862f2c` |
| `MATCH-A0D0-S406` | `9fe5d63d8224cff09e5826ab8882a406c390494b3f2f86deff363f7591a718d6` |
| `MATCH-A0D0-S407` | `19f9c505d545f0263444abd084bd32e8b45c0269cb39c20847661ccd1d2254f9` |
| `MATCH-A0D0-S408` | `64ad538f266daebd2f572a04a147406e22ef36f0ac19bfed873e6c556c0a28fc` |
| `MATCH-A1D0-S404` | `424b48927b2fa96acd9e5bdc06622e20ada19bc8629f64bcc4cad7d39b4eaada` |
| `MATCH-A1D0-S405` | `3cec66c0b4b233929f5e542d9f503beb57df0863df83556bfb676265455453ac` |
| `MATCH-A1D0-S406` | `cf2434bbd8e60b1cde68c8423040b29c5cc47a6a53d2fb2e27e313a55a04b9ae` |
| `MATCH-A1D0-S407` | `5e011edc824aeb4ab5ff2910a10e61bb5be2d8eeb8795835af2067f8a1ac804d` |
| `MATCH-A1D0-S408` | `a78bd938a7b440e30e532690247d4f626754fd7500a490c30a621349c396fe4e` |
| `MATCH-A0D1-S404` | `a0244a51ee554fbfec506d787537c2fb531ea364e3a92dd9e3bd47628e5829d1` |
| `MATCH-A0D1-S405` | `10c8de6fbcd04fdcdb58741c51ce458e9161986674e611ae60fe8a6bd3549cd6` |
| `MATCH-A0D1-S406` | `daa3e26f54b1f60ca144535c4d9f46f6dc7cbaf3715ea95374c181d7f8b29c7f` |
| `MATCH-A0D1-S407` | `4ddf550511b5a823edd62ff76439d0c46eb7721779d5f29e8f04cb30aed84ca8` |
| `MATCH-A0D1-S408` | `416a6f69697df4b3489c0b8531df43959a9f4c9a8fcc4cae01df83ad3ba16589` |
| `MATCH-A1D1-S404` | `de085b725e175bfed01a1a2b421715b37d3b5212a0d1e02f525dd6114fea52ea` |
| `MATCH-A1D1-S405` | `863629c309fb67e2249d2841b4ad58bd2cd17303c9cf5728bc9b5bcf49d13434` |
| `MATCH-A1D1-S406` | `e4c8a0298d4c5f28ba3dd63ca4d797f1ec3b33357603c76d9b95aa6c45561fc0` |
| `MATCH-A1D1-S407` | `bbde0d0d6abce4ae8ccb6fcadcf0b029169c748be68d6e9251f2882771aedf98` |
| `MATCH-A1D1-S408` | `3e991a302e6f075753555a1dd9c6924a5ac222f546a1e7122927c7a81904bb19` |

20개 result는 schema를 통과했고 index의 20개 SHA-256과 모두 일치했다. result·index·judgement는
OS 임시 폴더에 있으며 Git에 포함하지 않았다.

## 4. PCAP·log 상관분석 결과

| 판단 | 분류 | Evidence | 결과 |
|---|---|---|---|
| known L1–L3 exploit shape와 flag-linked response | `OBSERVED` | `PCAP-001`–`PCAP-104` | exploit shape 14,407개, flag-linked request 2,133개를 직접 관측했다. |
| 현재 D1 policy의 known-shape 차단 | `OBSERVED` | `PCAP-001`–`PCAP-104` | 14,407/14,407 차단, other 65,067개 중 unexpected DROP 0. 공식 SLA 오탐률은 아니다. |
| 과거 attacker accepted 결과 | `OBSERVED` | `LOG-A-P2-R09`–`LOG-A-P3-R18` | 로그 10개에서 accepted 18개. timestamp 부재로 exact flow 연결은 불가능하다. |
| 방어 lifecycle와 capture round | `CONFIRMED` | `LOG-D-*`, 동일 round PCAP | startup·policy 상태와 round 수준 exploit/flag response가 양쪽에 있다. 과거 packet별 verdict는 없다. |
| A1의 D0 상대 효과 비퇴행 | `OBSERVED` (`PROXY`) | `MATCH-A0D0-*`, `MATCH-A1D0-*` | capture delta seed별 +6/0/+3/+3/+3, median +3, 최악 0이다. |
| D1의 known proxy 보호 | `OBSERVED` (`PROXY`) | `MATCH-A0D1-*`, `MATCH-A1D1-*` | A0D1은 5/5 capture 0, A1D1은 3개 seed에서 3개씩 탈취됐다. D0 대비 비퇴행이나 완전 보호가 아니며 정상 실패는 0이다. |
| startup fail-open 탈취 | `OBSERVED` (`PROXY`) | `MATCH-A1D1-S404`, `S405`, `S408` | accepted capture가 피해 defender session 연결보다 각각 12–58ms 앞섰다. |
| L4 readiness branch 상태 | `OBSERVED` | `d1107ca`, `e2e8200` | `fix/finals-multiflag-l4-readiness` 변경은 main과 후보에 이미 포함됐다. 공격은 응답이 명시한 GET route로 제한되고 방어는 service observation만 기록하며 verdict를 바꾸지 않는다. |
| L4 다중 서비스 안전 경계 | `OBSERVED` (`PROXY`) | `TEST-L4-MULTIPORT`, `TEST-L4-MUTATION`, `TEST-L4-NEGATIVE` | 서로 다른 두 포트의 route·parameter와 복수 flag를 분리하고, query 순서·encoding을 정규화하며, traversal·파괴 route를 거부했다. action-like TCP/UDP는 방어에서 ACCEPT했다. |
| P4/L4 공격·방어 효과 | `UNKNOWN` | 해당 capture/log 없음 | 공식 개방 사실 외에 실트래픽 근거가 없다. |

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
- 최종 proxy에서 A1은 D0 상대 seed별 6/3/6/6/6, A0는 0/3/3/3/3을 획득했다.
  모든 seed에서 비퇴행이고 4개 비교 가능 seed의 first flag delta median은 -67.5ms다.
- A1D0의 양 팀 합산 요청은 seed별 149/89/148/147/148, A1D1은 88/89/30/30/84였다.
  D1이 연결된 뒤 차단된 seed에서는 요청을 30회에서 중단했지만 startup 전 성공 seed에서는 추가 flag를
  회수하므로 요청 수가 늘었다.
- A1의 LLM call·token은 모든 경기에서 0으로 zero-token fast path가 동작했다.
- A0는 종료 summary가 없어 baseline 요청·token 비교는 `UNKNOWN`이다. A0 조합에는 경기당
  non-zero container exit 2개가 있으나 A1 조합은 0이다.
- 1,360달러 총예산은 확인했지만 모델별 단가가 없어 정확한 USD ledger는 만들지 않았다. A1은
  redaction 뒤 LLM user content를 8KiB로 제한하나 이를 달러 상한으로 표현하지 않는다.

## 7. 방어자의 미탐·오탐·가용성 위험

- 최종 matrix 정상 요청은 720/720 성공했고 최대 latency는 17.314ms, GC DROP은 0이었다.
- D1 verdict-send E2E max는 2,918.844us이며 300ms 초과는 0이었다.
- D1 10경기 모두 session 1개, heartbeat 최소 7개, defender non-zero exit 0이었다.
- D1 session 연결 offset은 380–577ms다. A1D1의 seed 404·405·408에서 연결보다 12–58ms 앞선
  accepted capture가 직접 관측되어 Broker startup fail-open이 해소되지 않았다.
- D1은 A0에는 seed 5개 모두 탈취 0, A1에는 2개 seed 탈취 0·3개 seed 탈취 3을 기록했다.
  D0 대비 stolen delta와 정상 실패 delta는 모든 seed에서 비퇴행이지만 완전 보호 조건은 실패했다.
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
| 공격 효과성 | 20 | 2 | PENDING | 10.00 | known 5 seed 비퇴행·일부 개선 |
| 방어 효과·가용성 | 25 | 2 | PENDING | 12.50 | D0 대비 비퇴행·정상 실패 0이나 startup 전 탈취 존재 |
| 일반화·적응성 | 15 | 2 | PENDING | 7.50 | known proxy seed 5개, blind 없음 |
| 성능·복원력 | 15 | 2 | PENDING | 7.50 | proxy timing·heartbeat·graceful exit 통과 |
| 운영 재현성 | 5 | 2 | PENDING | 2.50 | digest·seed·초기화·deterministic judge 검증 |
| LLM 비용·관측성 | 5 | 2 | PENDING | 2.50 | A1/D1 LLM 0, 종료 summary 확보 |

AI 가중 점수는 **50.00/100**이다. known evidence만 있으므로 각 영역 최대 2점이며, 사람 점수가
`PENDING`이므로 최종 합의 점수와 승인은 없다.

## 9. P0/P1/P2 개선 로드맵

| 우선순위 | Evidence | 단일 문제 | 성공 조건 | 첫 실패 테스트·예상 파일 | 위험·rollback | 소유자·reviewer |
|---|---|---|---|---|---|---|
| P0 | `MATCH-A1D1-S404`, `S405`, `S408` | startup 연결 전 탈취 | fresh 5 seed에서 pre-session capture 0 | startup ordering 실패 회귀; defender/Arena 설계 delta 먼저 | fail-closed·지연은 SLA 위험; 현 D1 digest rollback | 방어자 + Docker owner + 팀장 |
| P0 완료(PROXY) | `TEST-L4-*`, L4 evidence 없음 | 미지 L4를 범용 경로로 과탐색 | 포트별 관측 route만 실행, 파괴 route 0, 합성 다중 flag 회수 | attacker parser/runtime tests, defender negative test | 실제 L4 효과는 미검증; 이전 A1 digest rollback | 공격자·방어자 owner + 팀장 |
| P0 | L4 evidence 없음 | L4 효과 미검증 | 실 L4 capture/log inventory와 negative corpus 확보 | Evidence ID와 최소 비식별 fixture, ACTIVE behavior 금지 | 추측 rule 오탐; 변경 없음이 rollback | 팀장 + 양 agent owner |
| P0 | `JUDGE-FINAL-404-408` | 사람 점수 부재 | 구조화된 독립 사람 채점과 2단계 이상 차이 arbitration 완료 | human score 유효·범위 초과·누락 파일 회귀 | 부정확 승인; HOLD 유지 | 팀장 |
| P1 | final known seed 5개 | blind·공식 SLA 미검증 | blind 5개 중 4개 이상 baseline 이상, 정상 가용성 비퇴행 | official Arena lifecycle/SLA test | known-data 과적합; HOLD | Arena operator + Judge |
| P1 | `MATCH-A1D0-*` | 요청 효율의 baseline 비교 불완전 | A0/A1 모두 graceful summary, accepted/request 직접 비교 | baseline-compatible summary reader | baseline 의미 변경; 기존 A0 digest 유지 | 공격자 owner + Judge |
| P1 | `PCAP-001`–`104` | TCP·부하 일반화 미검증 | encoding·TCP split·retransmit·worker death·reconnect mutation 통과 | Broker E2E mutation tests | 오탐·deadline 위험; D1 rollback | 방어자 + Docker owner + 팀장 |
| P2 | 1,360달러 공지 | USD 비용 산정 불가 | 운영진 모델별 단가로 round·model ledger 생성 | cost parser tests | 잘못된 단가; token-only ledger rollback | 공격자 owner + 팀장 |
| P2 | tool 부재 | TCP expert 분류 미확정 | tshark 제공 환경에서 retransmission/out-of-order 재검증 | 분석 문서만 변경 | runtime 영향 없음 | 팀장 |

`contracts/**`의 timing 필드 변경은 팀장 이경준 검토가 필요하다. 두 Dockerfile의 bytecode 변경은
Docker owner, 각 agent owner, 팀장 검토 없이는 승격하지 않는다.

## 10. 실제 구현한 P0 한 건

구현한 P0는 **미지 L4의 관측 기반 bounded discovery** 한 건이다.

- `c220a64`: 미확인 포트의 recon을 상태·문서용 GET 6개로 제한하고 `/flag`, `/admin`,
  `/.git/config` 같은 범용 경로 추측을 제거했다.
- plaintext·OpenAPI의 읽기 전용 GET route와 query parameter를 정확한 route별로 결속한다.
- query 순서와 percent-encoded parameter 이름은 정규화하지만 traversal·파괴적 action route는 거부한다.
- 같은 레이어의 두 포트가 서로 다른 interface와 복수 flag를 갖는 합성 회귀에서 2/2를 LLM 0으로
  회수하고, 포트 간 route 교차 실행은 0이었다.
- 방어는 action-like L4 TCP/UDP를 observation-only로 기록하고 ACCEPT한다. 새 ACTIVE rule은 없다.
- 새 A1은 `linux/amd64` digest
  `sha256:a6921bd03e3d7babad9b52b9a6d8e02caf90d96c859922416ae74b109c496d2e`로 동결했다.

이는 승인된 관측→계획→실행 경계 안의 discovery 제한이며 구체 L4 취약점·protocol을 추가하지 않는다.
rollback은 이전 A1 digest 또는 `c220a64` revert다. 실제 L4 효과는 `UNKNOWN`이다.

## 11. 추가·수정한 테스트

- `TEST-L4-MULTIPORT`: 두 L4 포트의 서로 다른 route·parameter와 복수 flag 상태 격리.
- `TEST-L4-MUTATION`: query 순서·percent encoding 정규화와 unobserved parameter 거부.
- `TEST-L4-NEGATIVE`: destructive/traversal GET 거부, action-like TCP/UDP ACCEPT.
- unknown L4에서 범용 `/flag`·`/admin`·`/.git/config` probe가 0인지 검증.
- 기존 container timing, image bytecode, judge 결정성, human-score schema, cooldown, capture-derived
  parser·policy 회귀는 계속 유지했다.

## 12. 실행 검증과 실제 결과

- attacker unittest: 238개 PASS.
- defender unittest: 341개 PASS, Windows capability skip 2. timing 포함; 측정 hot-path p99 최대
  75.1us, max 146.0us.
- capture-derived replay: 104 files, HTTP 79,474, known exploit 14,407/14,407 차단,
  other 65,046 pass + 21 coalesced, unexpected other DROP 0.
- scrimmage unittest: Python 2개 PASS; seed·log timing·attacker bytecode·defender bytecode·judge
  determinism PASS.
- 실제 20-match judgement를 연속 두 번 생성해 SHA-256
  `c85c84b6d8fdbed29dbab6bd364c452ce166f5bd62ef425249febde0b723b1d1` 일치.
- `scripts/check-layout.ps1`: PASS.
- `scripts/validate-skeleton.ps1`: PASS.
- final matrix: 20/20 schema PASS, hash mismatch 0, 정상 720/720, GC DROP 0, D1 300ms 초과 0,
  candidate container non-zero exit 0. A1D1 pre-session capture seed는 3개다.
- `git diff --check`: PASS.
- `git ls-files -- '*.pdf' '*.pcap' '*.pcapng' '*.log'`: 출력 없음.

L4 회귀 작성 중 route 간 parameter 교차, destructive route 허용, unknown 포트의 범용 경로 probe를
각각 실패로 재현한 뒤 최소 변경으로 수정했다. 재대전에서는 startup fail-open을 다시 관측했으며 이
turn에서 방어 설계·Docker를 추가 변경하지 않고 P0 blocker로 남겼다.

## 13. 원본·비밀정보 Git 미포함 확인

- raw PCAP/log/PDF/gzip 파일은 이동·수정·복사·staging하지 않았다.
- result·index·judgement는 Git 밖 임시 폴더에만 있다.
- Git diff에 raw evidence 확장자 0, 실제 flag 0, 합성 flag fixture 2개, 추적된 금지 파일 0이다.
- 결과 artifact의 raw 비밀 패턴 탐지는 0이며 image에 대회 credential 환경변수는 없다.
- 루트 worktree의 기존 사용자 미추적 문서 두 개는 그대로 보존했다.

## 14. 남은 위험

- P4/L4 실증 없음.
- 공식 SLA generator·공식 점수 산식·12팀·20분 round와 다른 2팀 10초 proxy다.
- blind holdout과 사람 점수가 없다.
- startup fail-open이 known proxy A1D1 3/5 seed에서 직접 재현됐다.
- 공식 정상 corpus, peak memory, forced worker death/reconnect의 최종 5-seed 증거가 없다.
- A0 종료 summary가 없어 요청·token 효율 baseline 비교가 불완전하다.
- 모델별 가격표가 없어 1,360달러 예산의 USD 집행 증명은 없다.
- contracts 및 Docker 변경은 필수 reviewer 승인이 없다.

## 15. 다음 한 가지 행동

당일 L4 capture/log를 raw 상태로 Git 밖에서 inventory·hash한 뒤, L4 서비스·정상 baseline·flag-linked
delivery를 Evidence ID로 확정한다. 그 전에는 port별 fast path나 방어 ACTIVE rule을 추가하지 않는다.
