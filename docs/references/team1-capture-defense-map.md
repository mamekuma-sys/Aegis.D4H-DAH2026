# TEAM1 본선 로그·PCAP 방어 매핑

## 자료 경계와 동일성

2026-08-15에 제공된 `TEAM1-P*-R*` 자료를 Git 제외 경로 `captures/team1/`에 보관했다. 원본 압축, 해제한 PCAP·로그, 분석 결과에는 flag·세션·운영 정보가 포함될 수 있으므로 Git에 넣지 않는다.

| 구분 | 파일 | 크기 | tree SHA-256 |
|---|---:|---:|---|
| gzip 원본 | 96개 | 13,650,363 bytes | `EFF271CD4428DD71E290B2CE76C95FFD50E7F03A543B1C004B07FDEC5449ECBE` |
| 해제본 | PCAP 66개 + 로그 30개 | 66,885,643 bytes | `3291315A1EABAB20D750415E39C8AF590191E7B4A83171ACD2659778C56AE8FF` |

tree hash는 `docs/references/README.md`의 상대경로·NUL·파일 SHA-256 방식으로 계산했다. 먼저 풀려 있던 `TEAM1-P3-R14-attacker.log` 사본은 해제본과 SHA-256이 같아 분석 입력에서는 중복 제외했다.

## 분석 방법

- PCAP link type은 Ethernet이었다. IPv4/TCP를 bounded parser로 읽고 목적지 포트 `8082`·`8083`·`8084`의 HTTP 요청과 응답을 연결했다.
- response body에서는 `FLAG{...}` 존재 여부만 확인하고 원문은 출력하거나 문서화하지 않았다.
- Base64-JSON cookie는 원문 대신 SHA-256과 비민감 claim 구조만 비교했다.
- 63개 PCAP에서 L1 26,908건, L2 13,278건, L3 3,394건, 합계 43,580개의 HTTP 요청을 분류했다.
- 이 분석은 PCAP 재생 기반 정책 검증이며 Broker 수신부터 실제 socket verdict 송신까지의 E2E 계측을 대신하지 않는다.

## 실제 flag 응답과 연결된 공격

| 레이어 | 성공 응답 | 관측된 필수 형태 | 방어 매핑 |
|---|---:|---|---|
| L1 / TCP 8082 | 816 | `helper-box:8080/secret` SSRF. 평문, percent encoding, 전체 target encoding, `helper-box.` trailing-dot 우회 | `sig-l1-helper-secret-001` |
| L2 / TCP 8083 | 758 | Base64-JSON `session` cookie의 `role=admin` 위조 11종과 loopback `127.0.0.1:8083/secret` SSRF | `http-l2-forged-admin-session-001`, `sig-l2-loopback-secret-001` |
| L3 / TCP 8084 | 49 | `/product?id=... UNION [ALL] SELECT ... FROM app_meta` | `sig-l3-app-meta-union-001` |

L2 cookie는 JSON key 순서, 공백, padding, 사용자 필드가 달라 raw Base64 문자열 목록으로 안전하게 일반화할 수 없었다. 따라서 packet payload 2KB 상한 안에서 완전한 HTTP header만 읽고 Base64-JSON scalar claim을 해석하는 `http_json_cookie_claim` 정책 종류를 추가했다. 불완전·과대·비정상 입력은 의미 규칙과 매치하지 않아 기존 fail-open 경계를 유지한다.

payload 정규식 세 개는 모두 HTTP request line에 한정했다. 같은 문자열이 정상 header나 body에 등장한 `/health` 요청까지 차단하는 초기 재생 결과를 발견해 범위를 좁힌 결과다.

## 전체 PCAP 재생 결과

bundle `defender-2026-08-15-team1-capture-enforce`를 63개 PCAP에 재생한 결과다.

| 항목 | 결과 |
|---|---:|
| 확인된 exploit-shape 요청 | 4,814 |
| 차단된 exploit-shape 요청 | 4,814 |
| 누락 그룹 | 0 |
| 독립적으로 통과한 기타 요청 | 38,745 |
| 공격과 같은 TCP payload에 병합되어 함께 차단되는 요청 | 21 |
| 공격이 없는 packet의 예상 밖 차단 그룹 | 0 |

`coalesced` 21건은 하나의 TCP payload에 여러 HTTP request line이 있고 그중 하나가 exact exploit인 경우다. Broker verdict는 IP packet 단위이므로 같은 packet의 일부만 통과시킬 수 없다. 이 수치는 rollback 판단 시 별도 관찰한다.

## R17 증분 관측과 재생

R17 원본 gzip SHA-256은 attacker log `C51F72D0...1C7F4`, defender log
`32EC4CD1...51FD2`, L1 PCAP `1CD38A9E...FC6DF`, L2 PCAP `223935C0...D6D9D`,
L3 PCAP `B30CAA67...F3603`이다. 공격 로그에는 33 endpoint·1,600 request·111 LLM call·93,427
token과 한 팀 L1/L2의 accepted flag 두 건이 기록됐다. 원문 flag는 문서화하지 않았다.

R17 성공 우회는 완전 request-target encoding·중첩/이중 인코딩 SSRF·trailing-dot 및 대소문자
host·0-padding port·repeated slash, `/admin?`·중복/분할 Cookie, SQL control whitespace·block
comment·`[app_meta]`였다. bundle `defender-2026-08-15-finals-validity`는 기존 exact rule 네
개와 canonical HTTP 의미 rule 세 개를 함께 사용한다.

세 R17 PCAP을 순서대로 재생한 packet verdict 결과는 L1 549, L2 625, L3 217 DROP이다. 관측된
성공 우회 형태가 모두 해당 계층 rule에 포함됐으며, 이는 packet-local offline replay 수치이지 flag
개수·공식 SLA·물리 socket E2E 결과가 아니다.

## 운영 경계

- 기존 및 원격에서 병합된 휴리스틱 13개는 계속 `SHADOW`다.
- ACTIVE rule 일곱 개는 protocol·port·request shape·logical evidence에 묶고 `2026-09-01T00:00:00Z`에 만료한다. 리허설 직후 bundle은 다음 주 시각에 일곱 규칙이 그대로 ACTIVE임을 로더 회귀로 검증한다.
- runtime은 packet-derived 지표로 rule을 승격·rollback하지 않는다.
- 실제 SLA 저하 또는 negative fixture 실패 시 직전 검증 이미지로 되돌린다.
- bounded HTTP header stitching은 연결했지만 일반 TCP/body 재조립과 물리 송신 E2E 계측은 범위 밖이다.
