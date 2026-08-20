# SCRIMMAGE_PROXY 실행

공식 스켈레톤 파일을 수정·복사하지 않고 동결된 A0/A1/D0/D1 이미지를 2×2로 검증한다.
결과에는 집계 수치와 SHA-256만 저장하며 raw PCAP·로그·flag·token은 저장하지 않는다.

```powershell
pwsh -NoProfile -File integration/scrimmage/build-proxy-layers.ps1
pwsh -NoProfile -File integration/scrimmage/run-matrix.ps1 `
  -SkeletonPath C:\path\to\official-skeleton -Seeds 1,2,3
pwsh -NoProfile -File integration/scrimmage/judge-results.ps1 `
  -ResultRoot <temporary-result-root> -ExpectedSeeds 1,2,3 -HumanScoreFile PENDING
```

runner는 기존 `lig-demo` 컨테이너가 있으면 중단하고 사용자 상태를 보존한다. 결과 기본 위치는
OS 임시 폴더의 `Aegis.D4H-scrimmage`이며 Git 작업트리 밖이다. 각 경기 후 컨테이너는 제거하지만
공식 스켈레톤의 named volume과 raw archive는 삭제하지 않는다.

경기 시작은 공식 backend의 control API에 맡긴다. runner는 임시 combatant-only Compose
controller를 backend에 읽기 전용으로 연결하여 고정 이미지가 정확히 한 번 생성되게 한다. 이 임시
controller는 공식 스켈레톤을 수정하지 않으며, 정상 종료 시 OS 임시 폴더에서 삭제된다.

agent summary에는 Docker가 기록한 container 시작 Unix 시각과 event별 최초 상대시각(ms)만
저장한다. raw 로그는 저장하지 않는다. 공격자의 `hit`는 새 accepted flag가 나온 뒤 기록되므로,
피해 defender의 `session-connected`보다 이르면 초기 fail-open 성공의 보수적 직접 증거로 사용한다.
해당 optional 필드는 기존 schema version 1 result와 하위 호환된다.

Judge는 사람 점수가 `PENDING`이면 필수 게이트가 모두 통과해도 `NOT_READY`를 반환한다. 개발은
seed 3개, 최종 후보는 Arena/Judge만 접근하는 blind seed 5개 이상으로 다시 실행해야 한다.

사람 점수를 제공할 때는 `contracts/scrimmage/human-score.schema.json`을 만족하는 독립 파일을
사용한다. 7개 영역은 각각 0–4 정수 점수, 확신도, Evidence ID, 결손 코드, 판정을 가져야 한다.
누락·추가 필드·범위 밖 값은 Judge가 거부한다.
파일 경로 오타를 `PENDING`으로 조용히 처리하지 않으므로, 미채점 상태는 문자열 `PENDING`으로만
명시한다.

```json
{
  "schema_version": 1,
  "areas": {
    "evidence_traceability": {
      "score": 2,
      "confidence": "MEDIUM",
      "evidence_ids": ["MATCH-INDEX-FINAL-404-408"],
      "gaps": ["BLIND_HOLDOUT_MISSING"],
      "judgement": "CONCERN"
    },
    "attack_effectiveness": {
      "score": 2, "confidence": "MEDIUM", "evidence_ids": ["MATCH-A1D0-S404"],
      "gaps": ["L4_EVIDENCE_MISSING"], "judgement": "CONCERN"
    },
    "defense_effect_availability": {
      "score": 2, "confidence": "MEDIUM", "evidence_ids": ["MATCH-A1D1-S404"],
      "gaps": ["OFFICIAL_SLA_GENERATOR_MISSING"], "judgement": "CONCERN"
    },
    "generalization_adaptability": {
      "score": 2, "confidence": "LOW", "evidence_ids": ["MATCH-INDEX-FINAL-404-408"],
      "gaps": ["BLIND_HOLDOUT_MISSING"], "judgement": "UNKNOWN"
    },
    "performance_resilience": {
      "score": 2, "confidence": "MEDIUM", "evidence_ids": ["MATCH-A1D1-S404"],
      "gaps": ["OFFICIAL_20_MIN_LOAD_MISSING"], "judgement": "CONCERN"
    },
    "operational_reproducibility": {
      "score": 2, "confidence": "MEDIUM", "evidence_ids": ["MATCH-INDEX-FINAL-404-408"],
      "gaps": ["OFFICIAL_ARENA_REPRODUCIBILITY_MISSING"], "judgement": "CONCERN"
    },
    "llm_cost_observability": {
      "score": 2, "confidence": "LOW", "evidence_ids": ["MATCH-A1D0-S404"],
      "gaps": ["USD_PRICE_SCHEDULE_MISSING"], "judgement": "UNKNOWN"
    }
  }
}
```

예시 숫자는 사전 점수가 아니다. 사람 심판은 증거를 독립 검토한 뒤 값을 작성해야 한다.

이 디렉터리는 Docker/Compose 통합 영역이다. 변경 승격에는 Docker owner, 영향받는 agent owner,
팀장 이경준 검토가 필요하고 `contracts/scrimmage/**` 변경은 팀장 승인이 필요하다.
