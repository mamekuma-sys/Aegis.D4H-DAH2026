# TEAM1 본선 로그·PCAP 방어 매핑

## 자료 경계와 동일성

2026-08-15에 제공된 `TEAM1-P*-R*` 자료를 Git 제외 경로 `capture/`와 `captures/team1/`에 보관했다. 원본 압축, 해제한 PCAP·로그, 분석 결과에는 flag·세션·운영 정보가 포함될 수 있으므로 Git에 넣지 않는다.

| 구분 | 파일 | 크기 | tree SHA-256 |
|---|---:|---:|---|
| gzip 원본 | 96개 | 13,650,363 bytes | `EFF271CD4428DD71E290B2CE76C95FFD50E7F03A543B1C004B07FDEC5449ECBE` |
| 해제본 | PCAP 66개 + 로그 30개 | 66,885,643 bytes | `3291315A1EABAB20D750415E39C8AF590191E7B4A83171ACD2659778C56AE8FF` |
| 전체 고유 PCAP snapshot | PCAP 104개 | 105,148,605 bytes | `98F87267ADD41B441B125F2919F53DB98F867ED6FB590A7B53C6896F976BF909` |

tree hash는 `docs/references/README.md`의 상대경로·NUL·파일 SHA-256 방식으로 계산했다. 먼저 풀려 있던 `TEAM1-P3-R14-attacker.log` 사본은 해제본과 SHA-256이 같아 분석 입력에서는 중복 제외했다.

## 분석 방법

- PCAP link type은 Ethernet이었다. IPv4/TCP를 bounded parser로 읽고 목적지 포트 `8082`·`8083`·`8084`의 HTTP 요청과 응답을 연결했다.
- response body에서는 `FLAG{...}` 존재 여부만 확인하고 원문은 출력하거나 문서화하지 않았다.
- Base64-JSON cookie는 원문 대신 SHA-256과 비민감 claim 구조만 비교했다.
- 전체 104개 PCAP에서 L1 37,884건, L2 27,124건, L3 14,499건, 합계 79,507개의 HTTP 요청을 분류했다.
- 이 분석은 PCAP 재생 기반 정책 검증이며 Broker 수신부터 실제 socket verdict 송신까지의 E2E 계측을 대신하지 않는다.

## 실제 flag 응답과 연결된 공격

| 레이어 | 성공 응답 | 관측된 필수 형태 | 방어 매핑 |
|---|---:|---|---|
| L1 / TCP 8082 | 1,017 | helper/Docker-host의 여러 IP 표현을 사용한 `:8080/secret` SSRF와 `/config?file=../../../../flag` | L1 helper canonical, config traversal rule |
| L2 / TCP 8083 | 941 | Base64-JSON `session`의 `role=admin`, loopback `:8083/secret`·`/registry` SSRF | L2 admin, secret canonical, registry canonical rule |
| L3 / TCP 8084 | 176 | `/product?id=... FROM app_meta` SQLi와 소수의 직접 노출 route | L3 app_meta rule. 직접 route만으로는 차단하지 않음 |

L2 cookie는 JSON key 순서, 공백, padding, 사용자 필드가 달랐고 애플리케이션이 space·dot·asterisk·tilde를 무시하는 lenient Base64 형태도 수용했다. parser는 이 관측 noise만 제거한 뒤 strict Base64와 bounded JSON scalar claim을 해석한다. 불완전·과대·그 밖의 비정상 입력은 의미 규칙과 매치하지 않아 기존 fail-open 경계를 유지한다.

payload 정규식 세 개는 모두 HTTP request line에 한정했다. 같은 문자열이 정상 header나 body에 등장한 `/health` 요청까지 차단하는 초기 재생 결과를 발견해 범위를 좁힌 결과다.

## 전체 PCAP 재생 결과

bundle `defender-2026-08-15-full-corpus-hardening`을 104개 PCAP에 재생한 결과다.

| 항목 | 결과 |
|---|---:|
| 확인된 exploit-shape 요청 | 14,388 |
| 차단된 exploit-shape 요청 | 14,388 |
| 누락 그룹 | 0 |
| 독립적으로 통과한 기타 요청 | 65,098 |
| 공격과 같은 TCP payload에 병합되어 함께 차단되는 요청 | 21 |
| 공격이 없는 packet의 예상 밖 차단 그룹 | 0 |

`coalesced` 21건은 하나의 TCP payload에 여러 HTTP request line이 있고 그중 하나가 exact exploit인 경우다. Broker verdict는 IP packet 단위이므로 같은 packet의 일부만 통과시킬 수 없다. 이 수치는 rollback 판단 시 별도 관찰한다.

### 현재 정책 자동 재현

과거 표는 stream 연결을 포함한 당시 분석 결과다. 현재 저장소에는 같은 원본을 실제
`parse_ip`와 `HotPolicy`에 넣는 `agents/defender/tools/replay_pcaps.py`가 있으며, macOS/Linux에서는
`scripts/replay-defender-pcaps.sh`로 실행한다. `2026-08-18T00:00:00Z` 기준 104개 PCAP 재현 결과는
packet-local 완전 HTTP 요청 79,474건, 관측 공격 형태 14,407/14,407 차단, 기타 요청 65,046건
통과, 같은 packet에 병합된 기타 요청 21건, 예상 밖 기타 요청 차단 0건이었다. 실제 packet
verdict는 14,496 DROP이며 그중 89건은 현재 packet만으로 완전한 header를 세지 못했지만 runtime의
bounded TCP stitcher가 판정한 경우다. FLAG 응답 연계 대리값은 2,133건 중 2,121건 차단이다.

두 집계의 분모가 다르므로 79,507과 79,474를 회귀로 서로 동일하다고 가정하지 않는다. 자동 검사는
정책 source, ACTIVE rule 9개, 공격 형태 차단률 100%, 예상 밖 기타 요청 차단 0건을 실패 조건으로
사용한다. 이 값은 여전히 공식 SLA 또는 Broker 실제 송신 E2E가 아니다.

## R17 증분 관측과 재생

R17 원본 gzip SHA-256은 attacker log `C51F72D0...1C7F4`, defender log
`32EC4CD1...51FD2`, L1 PCAP `1CD38A9E...FC6DF`, L2 PCAP `223935C0...D6D9D`,
L3 PCAP `B30CAA67...F3603`이다. 공격 로그에는 33 endpoint·1,600 request·111 LLM call·93,427
token과 한 팀 L1/L2의 accepted flag 두 건이 기록됐다. 원문 flag는 문서화하지 않았다.

R17 성공 우회는 완전 request-target encoding·중첩/이중 인코딩 SSRF·trailing-dot 및 대소문자
host·0-padding port·repeated slash, `/admin?`·중복/분할 Cookie, SQL control whitespace·block
comment·`[app_meta]`였다. 최종 bundle `defender-2026-08-15-full-corpus-hardening`은 기존 R17
규칙을 유지하면서 전체 코퍼스의 L1 config와 L2 registry 증거를 추가한다.

세 R17 PCAP을 순서대로 재생한 packet verdict 결과는 L1 549, L2 625, L3 217 DROP이다. 관측된
성공 우회 형태가 모두 해당 계층 rule에 포함됐으며, 이는 packet-local offline replay 수치이지 flag
개수·공식 SLA·물리 socket E2E 결과가 아니다.

## 운영 경계

- 기존 및 원격에서 병합된 휴리스틱 13개는 계속 `SHADOW`다.
- ACTIVE rule 아홉 개는 protocol·port·request shape·logical evidence에 묶고 `2026-09-01T00:00:00Z`에 만료한다. 본선 주간 시각에 아홉 규칙이 그대로 ACTIVE임을 로더 회귀로 검증한다.
- runtime은 packet-derived 지표로 rule을 승격·rollback하지 않는다.
- 실제 SLA 저하 또는 negative fixture 실패 시 직전 검증 이미지로 되돌린다.
- bounded HTTP header stitching은 연결했지만 일반 TCP/body 재조립과 물리 송신 E2E 계측은 범위 밖이다.
