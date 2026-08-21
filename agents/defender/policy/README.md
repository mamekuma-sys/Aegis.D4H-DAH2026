# 방어 PolicyBundle

설계 근거: `docs/superpowers/specs/2026-08-11-defender-runtime-design.md` §10.2, §10.4, §15.3.

rule과 운영 임계값은 Python 분기문이 아니라 이 디렉터리의 versioned JSON에 있습니다. Break가 10분뿐이고 그 안에 사람이 검토·수정·빌드·push를 끝내야 하므로, 분기문에 흩어진 임계값은 그 시간 안에 안전하게 리뷰할 수 없기 때문입니다.

두 파일은 **이미지 build context에 포함**됩니다. host volume mount나 런타임 다운로드에 의존하지 않습니다.

| 파일 | 역할 |
|---|---|
| `active.json` | 이번 이미지에서 사용할 bundle |
| `fallback.json` | 직전 Round의 검증된 bundle |

로딩 순서는 `active.json` → `fallback.json` → **DROP rule 0개**입니다. 세 번째 단계에서도 프로세스를 종료하지 않습니다. 판정을 못 해도 HEARTBEAT와 `ACCEPT` 경로가 살아 있으면 SLA는 지켜지고, 그것이 Broker fail-open보다 낫기 때문입니다.

## 현재 상태

현재 bundle은 `defender-2026-08-21-p2r4-evidence-fix`입니다. 본선에서 확인한 TCP profile `6/8080`, `6/9000`, `6/8082`, `6/1883`, `6/8554`, `6/9090`, `6/8410`, `6/8420`을 등록했습니다. 증거·정상 negative·SLA fixture와 두 review가 있는 rule 14개가 `ACTIVE`이고 일반 휴리스틱 13개는 `SHADOW`입니다. ACTIVE 규칙은 `2026-09-01T00:00:00Z`에 만료합니다.

활성 범위는 L1 helper secret SSRF와 config-to-flag traversal, SatDiag Tail/Export 플래그 접근, `/svc/flag-*`, `service_id` query가 있는 portal feedback, L2 GraphQL `missionAudit`, Base64-JSON `session` 관리자 claim 위조와 loopback secret/registry SSRF, L3 `app_meta` 대상 UNION SQLi입니다. query 없는 `/portal/feedback`과 GraphQL `systemConfig`는 포함하지 않습니다. HTTP 의미 규칙은 완성된 bounded request prefix에만 적용하고 `/fetch`, `/admin`, `/product`, User-Agent, NAT source IP만으로는 차단하지 않습니다. SHADOW 일치가 뒤의 ACTIVE 의미 규칙을 가리지 않도록 ACTIVE→CANARY→SHADOW 순서로 평가합니다.

로더는 안전 조건을 구조적으로 강제합니다. `baseline_profiles`가 비거나 rule이 만료되거나 두 review 중 하나라도 미승인이면 차단 권한을 가진 rule을 기동 시 `SHADOW`로 강등합니다(§15.6 마지막 항목).

## 필드

### 최상위

| 필드 | 의미 |
|---|---|
| `schema_version` | 지원 버전은 `1`. 다르면 bundle 전체를 거부합니다 |
| `bundle_id` | 이미지 간 추적용 고유 ID. 로그와 Docker 인계 자료에 그대로 남습니다 |
| `generated_at` | 작성 시각 |
| `baseline_profiles` | 관측으로 확인된 정상 profile scope key(`"<protocol>/<port>"`) 목록. **분류·경보용이며 허가가 아닙니다** |
| `rules[]` | 아래 참조 |
| `alert_profiles[]` | alert-only anomaly monitor의 임계와 runbook |

### rule

| 필드 | 의미 |
|---|---|
| `rule_id` | 불변 ID. 중복이면 bundle 전체를 거부합니다 |
| `kind` | `payload_regex` / `http_json_cookie_claim` / `http_ssrf_target` / `http_sqli_source` / `tcp_flags` / `flow_score` / `allow_profile` |
| `category` | `Sig` 카테고리. `CausalMatcher`의 관측 단계 매핑에도 쓰입니다 |
| `reason_code` | 로그에 남는 비민감 사유. payload나 rule 내용을 드러내지 않아야 합니다 |
| `protocol`, `ports` | `ports`가 비면 해당 protocol 전체(포트 무관 matcher) |
| `pattern` | `payload_regex` 전용. 아래 「정규식 제약」 참조 |
| `ignore_case` | 같은 scope의 rule 중 하나라도 true면 그 scope의 결합 정규식 전체가 대소문자 무시로 컴파일됩니다 |
| `http_method`, `http_path` | `http_json_cookie_claim` 전용. percent-decoding과 absolute-form 정규화 뒤 정확히 일치해야 합니다 |
| `cookie_name`, `claim_key`, `claim_values` | `http_json_cookie_claim` 전용. 완전한 header 안의 bounded Base64-JSON scalar claim만 비교합니다 |
| `http_paths`, `query_names`, `target_hosts`, `target_ports`, `target_path` | `http_ssrf_target` 전용. bounded 반복 decoding·중첩 query URL 정규화 뒤 목적지를 비교합니다 |
| `http_paths`, `query_names`, `sql_source` | `http_sqli_source` 전용. bounded decoding·주석 제거·공백 정규화 뒤 `UNION SELECT FROM <source>` 순서를 비교합니다 |
| `tcp_flags_name` | `tcp_flags` 전용. `tcp-null` / `tcp-fin` / `tcp-xmas` |
| `min_score` | `flow_score` 전용. `CorrelationSnapshot`의 flow 점수 임계 |
| `promotion_state` | `SHADOW` → `CANARY` → `ACTIVE` |
| `canary_fraction`, `canary_seed` | `CANARY` 전용. `blake2s(seed+rule_id+FlowKey)` 결정론적 bucket |
| `promotion_cohort`, `promoted_in_bundle` | 같은 cohort의 `promoted_in_bundle`이 서로 다르면 bundle 전체를 거부합니다 |
| `parser_version` | 런타임 parser 버전보다 높으면 bundle 전체를 거부합니다 |
| `profile_scope` | `["*"]` 또는 scope key 목록 |
| `evidence_id` | 원본 PCAP·로그의 **논리 ID**. 원본은 비공개 팀 보관소에 두고 저장소에 넣지 않습니다 |
| `positive_fixture_id`, `negative_fixture_id`, `sla_fixture_id` | 공격 positive / 정상 negative / 100회 SLA 성격 fixture |
| `expires_at` | ISO-8601. 지나면 기동 시 `SHADOW`로 강등됩니다 |
| `rollback_condition` | 무엇을 보면 되돌리는가 |
| `owner_review`, `lead_review` | 둘 다 `approved`가 아니면 기동 시 `SHADOW`로 강등됩니다 |

### 정규식 제약

`Sig` 예산이 p99 100μs이므로 패킷마다 정규식 수십 개를 순차 실행할 수 없습니다. 같은 scope의 rule은 이름 있는 그룹 하나로 **합쳐서 미리 컴파일**되며, 그룹 이름으로 rule을 되찾기 위해 다음을 금지합니다.

- capturing group `(...)` — `(?:...)`를 씁니다
- 역참조 `\1`~`\9`
- 중첩 수량자 `(...+)*` — backtracking 폭발을 유발합니다
- 512자 초과, 반복 상한 1000 초과

### HTTP JSON cookie 제약

HTTP 의미 rule은 TCP와 명시적 port를 요구합니다. packet-local payload 또는 bounded in-order request-prefix
stitching으로 완성된 요청만 파싱합니다. stitcher는 4KB·2,048 flows·5초 TTL이고 gap·과대·불완전
요청은 버리고 `ACCEPT`합니다. cookie 값은 512 bytes, JSON text는 512 bytes, key는 16개로 제한합니다.
잘못된 Base64·JSON, 중첩 claim, 상한 초과는 매치하지 않습니다. percent decoding과 nested URL 순회는
각각 최대 3회/3단계입니다. cookie 원문이나 claim 값은 로그·snapshot·LLM에 전달하지 않습니다.

## 강등과 거부의 차이

| 처리 | 대상 | 결과 |
|---|---|---|
| **강등** (`SHADOW`로) | 만료된 rule, review 미승인 rule, `baseline_profiles`가 빈 상태의 차단 rule | 그 rule만 무력화, 나머지는 그대로 사용 |
| **거부** (bundle 전체) | schema version 불일치, 중복 `rule_id`, 깨진/금지 정규식, 모순된 promotion cohort, 알 수 없는 `kind`·`promotion_state`, 포트 범위 밖, 잘못된 HTTP cookie 필드, `CANARY`인데 seed/fraction 없음 | `fallback.json`으로 넘어감 |

기준은 "그 rule을 안전하게 무력화할 수 있는가"입니다. 만료된 rule은 `SHADOW`로 내리면 정상 트래픽에 무해하지만, 중복 `rule_id`나 깨진 정규식은 bundle 전체의 해석을 신뢰할 수 없게 만듭니다.

## 승격·rollback 절차

**런타임은 어떤 방향으로도 승격 상태를 바꾸지 않습니다.** packet-derived 지표(`raw_drop_rate` 등)는 공격자가 오염할 수 있는 관측값이므로, 그 값으로 자동 rollback하면 공격자가 패킷만 보내서 우리 방어를 끄게 만들 수 있습니다(§10.3).

상태 변경은 Break에서만, 다음 순서로 사람이 수행합니다.

```text
alert 확인
  → 방어 담당자가 비민감 로그, 공식 SLA 결과, 정상·공격 fixture를 대조
  → rollback 또는 승격 후보와 새 PolicyBundle diff 작성
  → 정상 negative·100회 SLA fixture·latency 회귀 실행
  → 방어 담당자와 팀장 이경준 승인
  → Docker 담당자가 다음 Round 이미지 build/push
```

`SHADOW` → `CANARY` → `ACTIVE` 승격에는 §6.1의 여섯 조건이 모두 필요합니다. 다만 §0.2의 산식 분석에 따라, 정상 negative fixture를 통과하고 한 Round 관찰에서 충돌이 없는 고신뢰 rule을 여러 Round에 걸쳐 `SHADOW`에 묶어두는 것은 손해입니다. LLM이 제안한 rule은 예외 없이 `SHADOW`부터 시작합니다.

## Break 체크리스트

1. `active.json`을 수정하기 전에 현재 파일을 `fallback.json`으로 복사했는가
2. 새 rule의 `evidence_id`가 실제 관측된 PCAP 논리 ID를 가리키는가
3. 정상 negative fixture와 100회 SLA 성격 fixture 회귀를 실행했는가
4. `python -m unittest discover -s tests -t .`가 통과하는가
5. `rollback_condition`과 직전 안전 이미지 태그를 적었는가
6. `owner_review`와 `lead_review`를 모두 `approved`로 바꿨는가 (아니면 `SHADOW`로 강등됩니다)
7. `bundle_id`를 갱신했는가 (로그 추적성)
