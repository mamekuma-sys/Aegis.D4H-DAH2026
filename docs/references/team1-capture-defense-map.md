# TEAM1 본선 로그·PCAP 방어 매핑

## 자료 경계와 동일성

2026-08-15에 제공된 `TEAM1-P*-R*` 자료를 Git 제외 경로 `captures/team1/`에 보관했다. 원본 압축, 해제한 PCAP·로그, 분석 결과에는 flag·세션·운영 정보가 포함될 수 있으므로 Git에 넣지 않는다.

| 구분 | 파일 | 크기 | tree SHA-256 |
|---|---:|---:|---|
| gzip 원본 | 91개 | 12,133,321 bytes | `CC30BFED3D69600597A5E83EF0307F49AABCB6650CDDB2D71D0199A70A7875BE` |
| 해제본 | PCAP 63개 + 로그 28개 | 59,350,840 bytes | `DB00EA74F3ABB99B5C53C368F803ACA9C24F485A0AB0184FC626FAF975AE0952` |

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

## 운영 경계

- 기존 및 원격에서 병합된 휴리스틱 13개는 계속 `SHADOW`다.
- 새 ACTIVE rule 네 개는 protocol·port·request shape·logical evidence에 묶고 `2026-08-16T00:00:00Z`에 만료한다.
- runtime은 packet-derived 지표로 rule을 승격·rollback하지 않는다.
- 실제 SLA 저하 또는 negative fixture 실패 시 직전 검증 이미지로 되돌린다.
- flow 재조립 부재와 물리 송신 E2E 계측은 이번 변경으로 해결되지 않는다.
