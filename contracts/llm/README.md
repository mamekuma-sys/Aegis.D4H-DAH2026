# 본선 LLM API 계약

2026-08-18 팀에 전달된 최신 본선 안내를 구조화한 매핑입니다. 원본 공지 자체를
복사하지 않고 [`model-quotas.json`](model-quotas.json)에 모델 ID, 원래 모델 유형과
전체·팀별 TPM/RPM을 기록합니다.

- 제공 기반: Azure Foundry
- 접근 경계: OpenAI 호환 LiteLLM Proxy
- 인증: 팀별 가상 키가 `LLM_API_KEY`로 주입됨
- quota: 분당 TPM/RPM이며 당일 운영사무국 고지로 증가할 수 있음
- 팀 총 budget: `$1360`
- 비용 환산: 가격표와 구체적 비용 상한 기준이 본선 당일 공지되기 전에는 계산 불가

공식 skeleton guide에 따라 `api=chat`과 `api=responses`로 표기된 **모든 제공 모델을**
LiteLLM Proxy의 `/v1/chat/completions`로 호출합니다. `api`는 공지표의 원래 모델
유형을 보존하는 메타데이터이며, Proxy가 Responses 계열을 투명하게 변환합니다.
요청 토큰 상한은 공식 예제와 같은 `max_completion_tokens`를 사용합니다.

현재 기본 모델 `gpt-4o-mini`의 팀 quota는 6.5M TPM / 65K RPM입니다. 코드의
라운드별 호출 상한은 공격 48회, 방어 20회이므로 quota보다 훨씬 낮습니다. 이 호출
상한은 비용 상한이 아니며, 당일 가격·과금 기준이 나오면 팀 공용 비용 ledger를 별도로
승인해야 합니다.
