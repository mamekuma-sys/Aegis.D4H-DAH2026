# 공격 에이전트 계약

## 입력 환경변수

| 이름 | 의미 |
|---|---|
| `TARGETS` | 상대 팀 주소 CSV |
| `PORTS` | 상대 팀 공통 진입 포트 CSV |
| `SUBMIT_URL` | 플래그 제출 엔드포인트 |
| `SUBMIT_TOKEN` | 팀 제출 인증 토큰 |
| `LLM_BASE_URL` | OpenAI 호환 LiteLLM Proxy URL |
| `LLM_API_KEY` | LiteLLM 인증 키 |

공격 대상은 `TARGETS × PORTS`의 모든 조합입니다. 주소와 포트를 코드에 하드코딩하지 않습니다.

## 플래그 제출

```http
POST {SUBMIT_URL}
Content-Type: application/json

{"flag":"FLAG{...}","token":"{SUBMIT_TOKEN}"}
```

처리할 상태는 `accepted`, `own_team`, `duplicate`, `rejected`, `closed`이며, HTTP 429는 rate limit으로 처리합니다.

## 실행 제한

- 대상 방어망 요청은 공격 에이전트당 초당 10회, 버스트 20을 넘지 않습니다.
- flag 제출은 분당 30회를 넘지 않으며 HTTP 429에는 재시도 간격을 둡니다.
- `accepted`, `own_team`, `duplicate`, `rejected`, `closed` 결과를 구분하고 동일 flag의 불필요한 재제출을 막습니다.
- 라운드마다 컨테이너와 flag가 초기화되므로 캐시·중복 집합·관측 이력은 라운드 한정 임시 상태로 취급합니다.
- LiteLLM 호출에는 라운드별 예산을 두고 모델, 호출 목적, 토큰 사용량을 증빙할 수 있게 기록합니다. 인증 키와 flag 원문은 로그에 남기지 않습니다.

## 네트워크 제한

본선 에이전트는 운영진이 허용한 상대 팀 진입점, 제출 서버, 대회 LiteLLM Proxy만 사용합니다. 운영망과 외부 인터넷에 접근하지 않으며, rate limit 우회도 금지합니다.
