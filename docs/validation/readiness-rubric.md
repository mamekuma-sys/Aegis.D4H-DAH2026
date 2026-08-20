# 사람·AI 공동 Readiness 루브릭

## 판정 원칙

AI 평가자와 사람 평가자는 같은 evidence bundle을 독립적으로 0~4점으로 평가한다. 항목별 최종점은
둘 중 낮은 점수이며, 2점 이상 차이가 나면 제3자 중재 전까지 hard gate를 통과하지 못한다. 근거 ID가
없는 항목은 최대 1점이다.

### Hard gates

1. **범위·규칙**: 최신 공지와 공식 interface에 부합하고 한 candidate가 한 agent side만 바꾼다.
2. **증거 추적성**: 모든 주장이 SHA-256 evidence ID, 테스트 또는 관측 결과로 역추적된다.
3. **계약 보존**: 공식 skeleton, Broker, 환경변수, container lock을 바꾸거나 복사하지 않는다.
4. **Defender 안전성**: 원격 LLM이 동기 verdict 경로에 없고, 실제 Broker E2E 300ms 초과 0,
   heartbeat와 재연결을 검증했다. Defender가 아닌 후보는 `NOT_APPLICABLE`로 명시한다.
5. **격리·재현성**: 별도 worktree, clean commit, 고정 테스트, 평가 digest와 승인 commit이 일치한다.

하나라도 `FAIL` 또는 필요한데 `NOT_TESTED`이면 최종 판정은 `NOT_READY`다.

## 가중 항목

| 항목 | 가중치 | 4점의 기준 |
|---|---:|---|
| 증거 품질·추적성 | 15 | 실제 round/holdout 근거, 해시, 반증 가능 주장 |
| 공격 효과·계획 품질 | 20 | 허용 interface 안에서 재현되는 관측-계획-실행 개선 |
| 방어 정확도·가용성 | 25 | positive 누락 0, 정상 DROP 0, 300ms/heartbeat/reconnect 통과 |
| 일반화·holdout | 15 | 전체 round 또는 서비스 family 단위 holdout과 mutation 통과 |
| 성능·복원력 | 15 | 제한 자원·timeout·부분 입력에서도 bounded/fail-safe |
| 운영·rollback | 5 | 짧은 적용 시간, 명확한 owner, 되돌릴 commit/digest |
| LLM 비용·관측성 | 5 | 모델·호출·token ledger, quota 내 동작, 비밀 미기록 |

각 점수는 `가중치 × 점수 / 4`로 환산한다. 공격 후보에서 방어 항목처럼 직접 적용되지 않는 세부
기준은 해당 항목 안에서 관측·계약 보존과 상대 방어 회귀로 평가하며 가중치를 임의 제거하지 않는다.

### 등급

- 90~100: `READY` — 모든 hard gate 통과 시에만
- 75~89.99: `CONDITIONAL` — 사람의 명시적 위험 수용과 남은 검증 기한 필요
- 0~74.99 또는 hard gate 실패: `NOT_READY`

## 평가 입력 JSON

`contracts/break-copilot/readiness.schema.json` 형식을 사용한다. `evidence_ids`에는 ingest manifest의
ID 또는 테스트·scrimmage 결과 digest를 넣는다. official score가 아닌 자체 scrimmage 수치는
`limitations`에 반드시 명시한다.

## AI 평가 프롬프트

```text
너는 DAH 2026 Break candidate의 보수적 검증자다. 제공된 sanitized evidence, git diff, 고정 테스트,
replay, scrimmage 결과만 사용한다. 원본에 없는 포트·route·layer·vehicle 의미를 추측하지 않는다.

1. 다섯 hard gate를 PASS, FAIL, NOT_TESTED, NOT_APPLICABLE 중 하나로 판정하고 evidence ID를 붙인다.
2. 일곱 가중 항목을 0~4점으로 채점한다. evidence ID가 없으면 1점을 넘기지 않는다.
3. 보안 효과뿐 아니라 정상 traffic 회귀, 300ms E2E, heartbeat, 재연결, 자원 한도를 대칭적으로 본다.
4. 전체 round 또는 서비스 family가 holdout인지 확인한다. 같은 flow의 packet 분할은 holdout이 아니다.
5. 합성 fixture와 자체 scrimmage를 공식 본선 성능으로 표현하지 않는다.
6. 반증 가능한 실패 조건, rollback trigger, 아직 모르는 사실을 limitations에 기록한다.
7. JSON만 출력하고 readiness.schema.json을 정확히 따른다. 최종 등급은 계산하지 말고 raw score만 낸다.
```

## 사람 평가 체크

사람 평가자는 모델 분석을 먼저 읽지 않고 evidence와 diff를 우선 확인한다. 공격 owner 또는 방어
owner가 전략 변경을 검토하고, 팀장이 shared contract·최종 승격을 검토한다. Docker/Registry 단계는
Docker owner와 영향받는 agent owner, 팀장 검토가 모두 필요하다.

사람은 다음 질문에 명시적으로 답한다.

- 이 변경이 관측되지 않은 interface를 가정하는가?
- 정상 요청 하나로 우회·오탐·가용성 저하를 재현할 수 있는가?
- 새 규칙/동작의 만료와 rollback 조건은 무엇인가?
- 모델이 제시한 테스트가 아니라 우리가 고정한 테스트가 실제로 통과했는가?
- 이 commit과 evaluation digest가 approval JSON과 정확히 같은가?
