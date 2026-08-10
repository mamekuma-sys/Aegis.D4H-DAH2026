# 예선 소스와 본선 구현 매핑

이 문서는 원본 코드 복사를 지시하지 않습니다. 담당자가 예선 아이디어를 본선 입력과 시간 제약에 맞게 이식할 때 근거와 검증 상태를 기록하는 기준입니다.

| 예선 모듈 | 분류 | 본선 대상 | 담당 | 검증 요구사항 |
|---|---|---|---|---|
| `src/schema.py`의 `CommonEvent` | 재구현 | `agents/defender/src/aegis_defender/events.py` | 방어 | 원시 패킷에서 실제 관측 가능한 필드만 허용 |
| `src/correlation/normalizer.py` | 선별 이식 | `agents/defender/src/aegis_defender/normalizer.py` | 방어 | 잘린·미지원 패킷에서도 예외가 hot path를 중단하지 않음 |
| `src/correlation/time_window.py` | 재구현 | `agents/defender/src/aegis_defender/correlation/window.py` | 방어 | 제한된 메모리와 시간 기반 만료 테스트 |
| `src/correlation/causal_matcher.py` | 재구현 | `agents/defender/src/aegis_defender/correlation/causal.py` | 방어 | 관측된 프로토콜 필드만으로 규칙 구성 |
| `src/correlation/risk_scorer.py` | 재보정 후 이식 | `agents/defender/src/aegis_defender/correlation/risk.py` | 방어 | 합성 점수를 그대로 사용하지 않고 본선 fixture로 검증 |
| `src/agents/deterministic.py` | 선별 이식 | 방어 hot-path 정책 모듈 | 방어 | 패킷별 동기 경로의 시간 예산 검증 |
| `src/agents/ai_module.py` | 직접 이식 금지 | 비동기 AI 조언 모듈 | 방어 | 예선 모듈이 실제 ML/LLM이 아니라 feature rule임을 명시 |
| `src/agents/comparator.py` | 재설계 | 결정론·AI 결과 비교 모듈 | 방어 | 독립 입력이 실제 수집 가능한지 먼저 확인 |
| `src/agents/defense_agent.py` | 분해 후 재구현 | Broker·parser·policy·correlation 모듈 | 방어 | 배치 API를 온라인 패킷 처리로 교체하고 300ms 계약 검증 |
| `src/agents/attack_agent.py` | 코드 이식 금지 | 공격 S1~S5 가설 문서 | 공격 | 실제 표적·네트워크·플래그를 다루지 않는 생성기임을 유지 |
| `src/data/recipes/` | 연구 자료 | 공격 플레이북 설계 입력 | 공격 | 본선 취약점 목록으로 하드코딩하지 않음 |
| `src/evaluation.py`, `src/reporting.py` | 런타임 제외 | 오프라인 평가 도구 검토 | 팀장 | 합성 수치와 실전 수치를 분리 |

## 이식 PR 기록

예선 아이디어를 사용하는 PR에는 다음을 기록합니다.

- 예선 원본 모듈과 관련 테스트
- 새 파일과 공개 인터페이스
- 복사, 수정, 재구현 또는 제외 중 선택한 방식
- 본선 입력·시간 제약 때문에 달라진 부분
- 새 테스트와 실행 결과
- 합성 데이터 외에 사용한 검증 fixture
