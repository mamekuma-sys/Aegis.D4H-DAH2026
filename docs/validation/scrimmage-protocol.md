# 교차 스크리미지 프로토콜

## 목적

단일 에이전트의 자기평가 편향을 줄이기 위해 baseline과 candidate 공격·방어 이미지를 2×2로 교차한다.
공식 스켈레톤과 동일한 환경이라는 주장은 하지 않으며, 문제·seed·상대·자원 조건을 고정해 후보 간
상대 변화만 본다.

| 경기 | 공격 | 방어 |
|---|---|---|
| BB | baseline | baseline |
| CB | candidate | baseline |
| BC | baseline | candidate |
| CC | candidate | candidate |

각 셀은 최소 3회 반복하고 순서를 무작위화한다. 공격 candidate 효과는 CB-BB와 CC-BC를 함께 보고,
방어 candidate 효과는 BC-BB와 CC-CB를 함께 본다. 한 상대에서만 좋아지면 일반화 통과로 보지 않는다.

입력은 `contracts/break-copilot/scrimmage.schema.json`을 따른다. valid run마다 네 셀에서 같은 seed
집합, 고정된 attacker/defender image digest, skeleton SHA-256, timezone이 있는 시작 시각,
공격 점수와 0~1 availability를 기록한다. 세 셀만 있거나 variant별 digest가 바뀐 matrix는 비교기가
거부한다.

## 분리 원칙

- 학습 evidence와 holdout은 packet/flow가 아니라 전체 round 또는 서비스 family로 나눈다.
- 상대 에이전트에게 상대 후보의 diff, prompt, 분석을 제공하지 않는다.
- 각 실행은 image digest, skeleton hash, seed, 시작·종료 시각, score, availability, timeout을 기록한다.
- 자체 점수는 official score가 아니며 `limitations`에 환경 차이를 적는다.
- 공식 스켈레톤 파일은 수정하지 않고 image-only Compose override를 사용한다.

## 실행

```powershell
pwsh -NoProfile -File integration/scrimmage/run-scrimmage.ps1 `
  -SkeletonPath <official-skeleton-root> `
  -AttackerImage <attacker-image> -DefenderImage <defender-image> -ConfigOnly

# macOS zsh
zsh integration/scrimmage/run-scrimmage.zsh \
  --skeleton <official-skeleton-root> \
  --attacker-image <attacker-image> --defender-image <defender-image> \
  --config-only

# 실제 경기 시작은 운영 페이지/공식 control interface에서 수행한다.
# 결과 4개를 한 JSON에 기록한 뒤 비교한다.
python integration/scrimmage/compare_results.py <matrix.json> --output <comparison.json>
```

challenge가 기동하지 않거나 official control contract가 달라지면 자동 우회하지 않는다. 그 셀을
`invalid`로 남기고 운영진 정정본에서 재실행한다.
