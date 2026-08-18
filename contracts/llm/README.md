# 본선 LLM API 계약

2026-08-18 팀에 전달된 최신 본선 안내를 구조화한 매핑입니다. 원본 공지 자체를
복사하지 않고 [`model-quotas.json`](model-quotas.json)에 모델 ID, API 종류와
전체·팀별 TPM/RPM만 기록합니다.

- 제공 기반: Azure Foundry
- 접근 경계: OpenAI 호환 LiteLLM Proxy
- 인증: 팀별 가상 키가 `LLM_API_KEY`로 주입됨
- quota: 분당 TPM/RPM이며 당일 운영사무국 고지로 증가할 수 있음
- 팀 총 budget: `$1360`
- 비용 환산: 가격표와 구체적 비용 상한 기준이 본선 당일 공지되기 전에는 계산 불가

`api=chat` 모델만 현재 에이전트의 `/v1/chat/completions` 호출에 사용할 수 있습니다.
`api=responses` 모델을 쓰려면 별도의 Responses API 어댑터와 계약 테스트를 먼저
추가해야 하며, 모델 이름만 바꿔서는 안 됩니다.

현재 기본 모델 `gpt-4o-mini`의 팀 quota는 6.5M TPM / 65K RPM입니다. 코드의
라운드별 호출 상한은 공격 48회, 방어 20회이므로 quota보다 훨씬 낮습니다. 이 호출
상한은 비용 상한이 아니며, 당일 가격·과금 기준이 나오면 팀 공용 비용 ledger를 별도로
승인해야 합니다.
