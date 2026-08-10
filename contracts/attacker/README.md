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

## 네트워크 제한

본선 에이전트는 상대 팀 서비스, 제출 엔드포인트, 대회 LiteLLM Proxy 등 운영진이 허용한 내부 경로만 사용합니다. 임의의 외부 인터넷 의존성을 두지 않습니다.
