# 2026-08-20 본선 후보 독립 검증 판정

## 1. 한 줄 결론

최종 후보는 known L1–L3 proxy 5개 seed에서 공격 효과 비퇴행, 방어 탈취 0, 정상 요청 실패 0,
300ms 초과 0을 달성했지만 L4·blind holdout·공식 SLA·사람 점수가 없으므로
**NOT_READY / HOLD**다.

이 판정은 공식 점수가 아닌 `SCRIMMAGE_PROXY`다. 예선 보고서와 예선 소스는 사용하지 않았다.

## 2. 분석 범위

- 실제 PCAP: 104개, `2026-08-15T01:00:14.748452Z`–`2026-08-15T12:40:17.443263Z`.
- 실제 agent log: 공격자 10개, 방어자 11개.
- fresh filename audit에서 canonical `capture/`는 P1–P3/L1–L3, `log/`는 P2–P3이며
  P4/L4 파일은 0개였다. 제외 대상인 기존 `captures/` generated/history tree도 P1–P3/L1–L3뿐이고,
  그 안의 PCAP 70개 SHA-256은 모두 canonical 104개 중 하나와 일치했다.
- 최종 proxy: L1–L3, 2팀, 2×2 matrix, seed 404–408, 경기당 10초, 정상 요청 6개.
  총 20경기·정상 요청 120개다.
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
`341681028643e20d61d8f2c6a760887f250793812f3d001416ba46df1054b83f`

| ID | Runtime commit | Linux/amd64 image digest |
|---|---|---|
| A0 | `4931ce955c3f6401b74f5857e0bfee1b3e182369` | `sha256:261e014897b547bc218ef21d40257b4508eab413a35befa4e25cc904f6f7e4b2` |
| A1 | `29a78594cb545646335188577743a5c10cdda03a` | `sha256:e6a1e8462f86b0906a4f54f7fa640bbb979fa9b9951663c3564c177c1ee05452` |
| D0 | `4931ce955c3f6401b74f5857e0bfee1b3e182369` | `sha256:d9c6361aba12b79c9a449e6b9b4dd7620ee6dafae5018ed4594f8b483098ac48` |
| D1 | `503332f92843316fb7d9c85ad604eea0c09ce3b9` | `sha256:08fb5675ea3ce7ef39c4cf0d6055b2f1352a5c8d5a6681a5aa947208fc189aba` |

네 이미지에서 대회용 제출 토큰, LLM 키, flag, cookie, session 환경변수는 0건이었다. D1은
UID 65534이고 네 이미지 모두 `linux/amd64`다.

### 3.2 최종 match

- matrix index Evidence: `MATCH-INDEX-FINAL-404-408`
- matrix index SHA-256:
  `b6533e8eaed96769e53b19f60a1189ed7c0d795c4b1795ca2eb2025afe59ba0b`
- judgement Evidence: `JUDGE-FINAL-404-408`
- deterministic judgement SHA-256:
  `d49d57cdd378092ebfb8f1179a13bba492b9845c7a2ec7c657ec526684124dd8`

| Evidence ID | SHA-256 |
|---|---|
| `MATCH-A0D0-S404` | `db6a7c27dbaba25bc103b5f4ead8f68726e41b16220decfab06dc29680ae9078` |
| `MATCH-A0D0-S405` | `993ca90d29b8cdf038c021919a068a3b291f131352136d4d6447b89180fb3dbf` |
| `MATCH-A0D0-S406` | `132b0b1e052e09f54c24310cf7bd6286e9939c15c5d81259b6774b3cf3cc5a43` |
| `MATCH-A0D0-S407` | `af15479f0001592d33c5bef136a7331beb0f702d899720a4114d750d9eaf4c80` |
| `MATCH-A0D0-S408` | `9939b9027caa35e6b66c2d6c047c6e66bc8fa7dfd0f77d12697f002c8c10d4db` |
| `MATCH-A1D0-S404` | `b2c5316517b2db970f19a4a0b25fc3f112a19506d577395e25ae1b87c82ba340` |
| `MATCH-A1D0-S405` | `c31fd105ec0611ea0163b7c402ec5952a9619f8cf7ac0e5ae2af37826bcb716b` |
| `MATCH-A1D0-S406` | `85bb002905cd61e561ca6fb57bb5c739649be1a24f26445e6ec19c364cb21fcd` |
| `MATCH-A1D0-S407` | `560cfebed63f2e95f959e453dd9b69b137cb6e6addcf2822f492cab8ade6a9e7` |
| `MATCH-A1D0-S408` | `e3b3e64f2d8cf22198fa3e9424ce643d8ecef2f46e8ebcf839902f5b05aa57c2` |
| `MATCH-A0D1-S404` | `d33567138e47502ed4466f5c50b345f5aeaec6ef8ec0552f8c554452e1e43f87` |
| `MATCH-A0D1-S405` | `123b0a2b0ce7961ba97ef0e8ed30305272cdcebd24649a2e466416b1e038f8db` |
| `MATCH-A0D1-S406` | `239addb197465248042359e88b60f8f1b021a7e61d1b4b17fa387ea6f625ad06` |
| `MATCH-A0D1-S407` | `85e1621a872ba7b5807f96394a1c4a80a9a2487f46a06c4fed7af48a7bd094f4` |
| `MATCH-A0D1-S408` | `9c5920cc6acee6c41a7c88a69e75e3e2c7b4e4102f4988d97b03ae2373c84fb2` |
| `MATCH-A1D1-S404` | `472d5f419feff73ca296bea4af6fe4bd9a181da4eef017e7e3f5f68326e1801c` |
| `MATCH-A1D1-S405` | `522755822ca9123ad7b600205dbe17ded171448f9f2cfbf71d3596a76ad06363` |
| `MATCH-A1D1-S406` | `adcbfd1c3e5dd67a31aaabc3690e2b57703ef5fab93d0410868574ad51c6ef40` |
| `MATCH-A1D1-S407` | `fc279aeab82bae06c8b97e820ad6dd2f9060b2f4d14849d0e0a91922653e2ebc` |
| `MATCH-A1D1-S408` | `3328f2b487452dc906657a374e6f2d8d338495501f8c64b4862700cf24255b7d` |

20개 result는 schema를 통과했고 index의 20개 SHA-256과 모두 일치했다. result·index·judgement는
OS 임시 폴더에 있으며 Git에 포함하지 않았다.

## 4. PCAP·log 상관분석 결과

| 판단 | 분류 | Evidence | 결과 |
|---|---|---|---|
| known L1–L3 exploit shape와 flag-linked response | `OBSERVED` | `PCAP-001`–`PCAP-104` | exploit shape 14,407개, flag-linked request 2,133개를 직접 관측했다. |
| 현재 D1 policy의 known-shape 차단 | `OBSERVED` | `PCAP-001`–`PCAP-104` | 14,407/14,407 차단, other 65,067개 중 unexpected DROP 0. 공식 SLA 오탐률은 아니다. |
| 과거 attacker accepted 결과 | `OBSERVED` | `LOG-A-P2-R09`–`LOG-A-P3-R18` | 로그 10개에서 accepted 18개. timestamp 부재로 exact flow 연결은 불가능하다. |
| 방어 lifecycle와 capture round | `CONFIRMED` | `LOG-D-*`, 동일 round PCAP | startup·policy 상태와 round 수준 exploit/flag response가 양쪽에 있다. 과거 packet별 verdict는 없다. |
| A1의 D0 상대 효과 비퇴행 | `OBSERVED` (`PROXY`) | `MATCH-A0D0-*`, `MATCH-A1D0-*` | capture delta seed별 +3/+3/+6/+6/0, median +3, 최악 0이다. |
| D1의 known proxy 보호 | `OBSERVED` (`PROXY`) | `MATCH-A0D1-*`, `MATCH-A1D1-*` | 10경기 모두 capture 0, 정상 실패 0, 연결 전 capture 0이다. |
| bytecode·lazy import가 startup 보호를 개선한 원인 | `INFERRED` | startup timing regression, `MATCH-A*D1-*` | D1 session offset은 448–584ms이고 최종 탈취는 0이지만 blind 인과 검증은 없다. |
| L4 readiness branch 상태 | `OBSERVED` | `d1107ca`, `e2e8200` | `fix/finals-multiflag-l4-readiness` 변경은 main과 후보에 이미 포함됐다. 공격은 응답이 명시한 GET route로 제한되고 방어는 service observation만 기록하며 verdict를 바꾸지 않는다. |
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
- 최종 proxy에서 A1은 D0 상대 seed별 6/6/6/6/3, A0는 3/3/0/0/3을 획득했다.
  모든 seed에서 비퇴행이고 3개 비교 가능 seed의 first flag delta median은 -76ms다.
- A1D0의 양 팀 합산 요청은 seed별 146/149/150/147/88, A1D1은 모두 30이었다. D1이
  활성화된 뒤 실패 delivery를 불필요하게 반복하지 않았다.
- A1의 LLM call·token은 모든 경기에서 0으로 zero-token fast path가 동작했다.
- A0는 종료 summary가 없어 baseline 요청·token 비교는 `UNKNOWN`이다. A0 조합에는 경기당
  non-zero container exit 2개가 있으나 A1 조합은 0이다.
- 1,360달러 총예산은 확인했지만 모델별 단가가 없어 정확한 USD ledger는 만들지 않았다. A1은
  redaction 뒤 LLM user content를 8KiB로 제한하나 이를 달러 상한으로 표현하지 않는다.

## 7. 방어자의 미탐·오탐·가용성 위험

- 최종 matrix 정상 요청은 120/120 성공했고 최대 latency는 22.651ms, GC DROP은 0이었다.
- D1 verdict-send E2E max는 2,206.655us이며 300ms 초과는 0이었다.
- D1 10경기 모두 session 1개, heartbeat 최소 6개, defender non-zero exit 0이었다.
- D1 session 연결 offset은 448–584ms다. final 10경기에서 연결 전 accepted capture는 0이지만
  Broker의 본질적 startup fail-open은 공식 blind startup 순서에서 아직 검증되지 않았다.
- D1은 A0·A1 양쪽에 대해 seed 5개 모두 탈취 0을 유지했다. D0 대비 stolen delta는 모든 seed에서
  0 이하이고 정상 실패 delta는 0이다.
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
| 방어 효과·가용성 | 25 | 2 | PENDING | 12.50 | known 5 seed 탈취·정상 실패 0 |
| 일반화·적응성 | 15 | 2 | PENDING | 7.50 | known proxy seed 5개, blind 없음 |
| 성능·복원력 | 15 | 2 | PENDING | 7.50 | proxy timing·heartbeat·graceful exit 통과 |
| 운영 재현성 | 5 | 2 | PENDING | 2.50 | digest·seed·초기화·deterministic judge 검증 |
| LLM 비용·관측성 | 5 | 2 | PENDING | 2.50 | A1/D1 LLM 0, 종료 summary 확보 |

AI 가중 점수는 **50.00/100**이다. known evidence만 있으므로 각 영역 최대 2점이며, 사람 점수가
`PENDING`이므로 최종 합의 점수와 승인은 없다.

## 9. P0/P1/P2 개선 로드맵

| 우선순위 | Evidence | 단일 문제 | 성공 조건 | 첫 실패 테스트·예상 파일 | 위험·rollback | 소유자·reviewer |
|---|---|---|---|---|---|---|
| P0 완료(PROXY) | startup timing, `MATCH-A*D1-*` | startup 연결 전 보호 편차 | known 5 seed pre-session capture 0, D1 capture 0 | import·bytecode·timing tests; defender Dockerfile/advisory/scrimmage | import 지연·이미지 변경; 이전 digest rollback | 방어자 + Docker owner + 팀장 |
| P0 | L4 evidence 없음 | L4 효과 미검증 | 실 L4 capture/log inventory와 negative corpus 확보 | Evidence ID와 분석 fixture만 먼저 추가, ACTIVE behavior 금지 | 추측 rule 오탐; 변경 없음이 rollback | 팀장 + 양 agent owner |
| P0 | `JUDGE-FINAL-404-408` | 사람 점수 부재 | 구조화된 독립 사람 채점과 2단계 이상 차이 arbitration 완료 | human score 유효·범위 초과·누락 파일 회귀 | 부정확 승인; HOLD 유지 | 팀장 |
| P1 | final known seed 5개 | blind·공식 SLA 미검증 | blind 5개 중 4개 이상 baseline 이상, 정상 가용성 비퇴행 | official Arena lifecycle/SLA test | known-data 과적합; HOLD | Arena operator + Judge |
| P1 | `MATCH-A1D0-*` | 요청 효율의 baseline 비교 불완전 | A0/A1 모두 graceful summary, accepted/request 직접 비교 | baseline-compatible summary reader | baseline 의미 변경; 기존 A0 digest 유지 | 공격자 owner + Judge |
| P1 | `PCAP-001`–`104` | TCP·부하 일반화 미검증 | encoding·TCP split·retransmit·worker death·reconnect mutation 통과 | Broker E2E mutation tests | 오탐·deadline 위험; D1 rollback | 방어자 + Docker owner + 팀장 |
| P2 | 1,360달러 공지 | USD 비용 산정 불가 | 운영진 모델별 단가로 round·model ledger 생성 | cost parser tests | 잘못된 단가; token-only ledger rollback | 공격자 owner + 팀장 |
| P2 | tool 부재 | TCP expert 분류 미확정 | tshark 제공 환경에서 retransmission/out-of-order 재검증 | 분석 문서만 변경 | runtime 영향 없음 | 팀장 |

`contracts/**`의 timing 필드 변경은 팀장 이경준 검토가 필요하다. 두 Dockerfile의 bytecode 변경은
Docker owner, 각 agent owner, 팀장 검토 없이는 승격하지 않는다.

## 10. 실제 구현한 P0 한 건

구현한 P0는 **startup fail-open 관측·완화** 한 건이다.

- `44c18d7`: container start→첫 event와 attacker first hit→victim session을 비식별 상관분석.
- `a888fe4`, `29a7859`: defender·attacker Python bytecode를 이미지 build 시 precompile.
- `503332f`: defender startup hot path에서 advisory HTTP import를 첫 async 사용 시점까지 지연.
- old D1 import median 약 280ms → bytecode 약 188ms → lazy import 포함 약 130ms로 단축.
- `9858db4`: startup import 회귀를 실행 cwd와 독립적으로 고정.
- `a5d7a84`: 심판 입력 파일 정렬과 ordered rubric으로 동일 입력 judgement hash를 결정적으로 고정.

새 공격 delivery, 새 방어 ACTIVE rule, 동기 LLM, 300ms hot-path 의미 변경은 추가하지 않았다.

## 11. 추가·수정한 테스트

- container start와 `startup`, `session-connected`, `hit`의 sanitized offset 파서.
- old schema 호환을 유지하는 optional timing fields.
- attacker·defender 이미지의 `linux/amd64`와 precompiled bytecode 확인.
- defender main import가 `urllib.request`를 startup에 불러오지 않는 회귀.
- 동일 합성 2×2×3 결과를 별도 심판 프로세스에서 두 번 채점해 SHA-256이 같은 결정성 회귀.
- 사람 평가 7개 영역의 점수·확신도·Evidence ID·결손·판정을 schema로 검증하고 범위 초과,
  누락 필드와 잘못된 파일 경로를 거부하는 회귀.
- 기존 LLM prompt cap, graceful signal, cooldown stop, capture-derived parser·policy 회귀.

## 12. 실행 검증과 실제 결과

- attacker unittest: 234개 PASS.
- defender unittest: 341개 PASS, Windows capability skip 2. timing 포함; 측정 hot-path p99 최대
  93.6us, max 145.7us.
- capture-derived replay: 104 files, HTTP 79,474, known exploit 14,407/14,407 차단,
  other 65,046 pass + 21 coalesced, unexpected other DROP 0.
- scrimmage unittest: Python 2개 PASS; seed·log timing·attacker bytecode·defender bytecode·judge
  determinism PASS.
- 실제 20-match judgement를 연속 두 번 생성해 SHA-256
  `d49d57cdd378092ebfb8f1179a13bba492b9845c7a2ec7c657ec526684124dd8` 일치.
- `scripts/check-layout.ps1`: PASS.
- `scripts/validate-skeleton.ps1`: PASS.
- final matrix: 20/20 schema PASS, hash mismatch 0, 정상 실패 0, GC DROP 0, D1 300ms 초과 0,
  candidate container non-zero exit 0.
- `git diff --check`: PASS.
- `git ls-files -- '*.pdf' '*.pcap' '*.pcapng' '*.log'`: 출력 없음.

재검증 중 startup import test의 cwd 의존 failure와 judgement hash 비결정성을 발견했으며, 각각
실패를 재현한 뒤 위 회귀 테스트로 수정했다.

## 13. 원본·비밀정보 Git 미포함 확인

- raw PCAP/log/PDF/gzip 파일은 이동·수정·복사·staging하지 않았다.
- result·index·judgement는 Git 밖 임시 폴더에만 있다.
- Git diff에 raw evidence 확장자 0, 긴 flag 형태 추가 0, 추적된 금지 파일 0이다.
- 결과 artifact의 raw 비밀 패턴 탐지는 0이며 image에 대회 credential 환경변수는 없다.
- 루트 worktree의 기존 사용자 미추적 문서 두 개는 그대로 보존했다.

## 14. 남은 위험

- P4/L4 실증 없음.
- 공식 SLA generator·공식 점수 산식·12팀·20분 round와 다른 2팀 10초 proxy다.
- blind holdout과 사람 점수가 없다.
- startup fail-open은 known proxy에서는 해소됐지만 공식 startup 순서·pull 지연에서 미검증이다.
- 공식 정상 corpus, peak memory, forced worker death/reconnect의 최종 5-seed 증거가 없다.
- A0 종료 summary가 없어 요청·token 효율 baseline 비교가 불완전하다.
- 모델별 가격표가 없어 1,360달러 예산의 USD 집행 증명은 없다.
- contracts 및 Docker 변경은 필수 reviewer 승인이 없다.

## 15. 다음 한 가지 행동

당일 L4 capture/log를 raw 상태로 Git 밖에서 inventory·hash한 뒤, L4 서비스·정상 baseline·flag-linked
delivery를 Evidence ID로 확정한다. 그 전에는 L4 공격 runtime이나 방어 ACTIVE rule을 추가하지 않는다.
