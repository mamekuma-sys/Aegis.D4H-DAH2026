# 리허설 공격 게이트 리뷰 (2026-08-15)

기준 커밋: `e31323f` (`main`). 리허설에서 Team 1 공격이 표적을 거의 찌르지 못한 원인을 코드와 대조한 결과다.

## 한 줄 결론

이미지가 늦게 올라간 것이 이번 라운드의 직접 원인이고, **다음 라운드에도 공격이 약할 수 있는 코드 결함 두 개**가 남아 있다. `can_attack`이 LLM 키에 묶여 있고, 상대가 성공한 `/fetch`가 기본 정찰 목록에 없다.

## P0 — LLM 키가 없으면 결정론 정찰도 시작하지 않는다

설계 §9.12·§9.13: LiteLLM 장애·키 부재는 조언만 멈추고, 관측·정찰·제출은 계속해야 한다.

현재 `AttackerConfig.can_attack`은 `llm_api_key and targets and ports`이다. `run_forever()`는 `can_attack`이 False면 `inert` 로그 후 즉시 반환한다. 공식 스켈레톤이 `TARGETS`·`PORTS`를 넣어도 `LLM_API_KEY`가 비거나 프록시가 키를 안 주면 **GET / 조차 안 나간다**.

수정: `can_attack`은 `targets and ports`만 본다. 키 없으면 `LLMAdvisor`가 이미 `None`을 반환하므로 planner는 멈추고 recon·playbook만 돈다.

## P0 — 기본 정찰 목록에 `/fetch`가 없다

`COMMON_PROBE_PATHS`는 `/flag`, `/registry` 등은 있으나 `/fetch`가 없다. 리허설 PCAP에서 상대 성공 경로로 확인된 `/fetch`를 결정론 GET으로 먼저 찔러야 한다. LLM 조언에만 맡기면 키·예산·승급에 다시 묶인다.

수정: 목록에 `/fetch`를 넣는다. query가 필요한 변형은 기존처럼 planner/playbook 경로에 남긴다.

## P1 — 자동 고비용 모델 승급

`escalated_model()`은 실패가 쌓이면 `gpt-4.1` → `gpt-5.2`로 올린다. 팀 한도 $20에서 `gpt-5.2` 출력 단가는 기본 `gpt-4o-mini`보다 훨씬 높다. 이번 P0와 별도로, 리허설 중에는 승급을 끄거나 호출 상한(현재 라운드당 200)을 낮추는 편이 안전하다. 이 문서는 승급 코드를 바꾸지 않는다.

## 이번 라운드 / 다음 라운드

| 항목 | 판정 |
|---|---|
| ACR `team1/attacker:latest` | linux/amd64 정상 이미지. 늦은 push가 이번 라운드 미반영 원인 |
| 다음 라운드 pull | 이미지만으로는 부족. 위 P0 두 개를 고친 이미지를 다시 push해야 함 |
| 방어 | 이 리뷰 범위 밖. 현재 policy는 SHADOW 유지 |

## 검증

공격 단위 테스트를 이 브랜치에서 다시 돌린다. Registry 토큰·리허설 계정은 이 문서에 적지 않는다.
