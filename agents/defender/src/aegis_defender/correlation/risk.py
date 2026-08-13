"""비동기 우선순위 점수 (`RiskModel`).

설계 §7 구성요소 표, §11, §3 마지막 행("예선 synthetic 지표·임계값 미사용").

**이 모듈의 가중치는 보정되지 않았다.** 예선 보고서 §4.6이 자기 점수표를
"보정되지 않은 설계값"으로 명시했고 §5.2가 그 값을 본선 threshold로 쓰지 말라고
못박았으므로, 보고서의 15→52→131→196→238을 복사하지 않았다. 아래 값들은 본선
fixture로 보정하기 전까지 **상대적 우선순위를 매기는 용도**일 뿐이다.

그래서 이 점수만으로는 어떤 패킷도 차단되지 않는다. 차단은 `min_score`를 가진
`flow_score` rule이 §6.1의 6조건을 충족하고 사람 승인으로 `ACTIVE`가 됐을 때만
일어나며, 현재 이미지의 `active.json`에는 그런 rule이 없다.
"""

from __future__ import annotations

from dataclasses import dataclass

MAX_SCORE = 100


@dataclass(frozen=True, slots=True)
class FlowFeatures:
    """비동기 worker가 관측한 flow 요약. 전부 bounded scalar다(§8 `CorrelationEvent`)."""

    packets: int = 0
    sig_hits: int = 0
    distinct_paths: int = 0
    distinct_paths_saturated: bool = False
    encoded_hits: int = 0
    long_uri_hits: int = 0
    scan_flag_hits: int = 0
    interval_regularity: float = 0.0
    duration: float = 0.0


@dataclass(frozen=True, slots=True)
class RiskWeights:
    """미보정 가중치. Break에서 fixture 대조 후 policy file로 옮기는 것이 목표다."""

    sig_hit: int = 12
    distinct_path: int = 3
    distinct_path_saturated_bonus: int = 10
    encoded_hit: int = 8
    long_uri_hit: int = 5
    scan_flag_hit: int = 6
    regularity: int = 15
    regularity_min: float = 0.8


DEFAULT_WEIGHTS = RiskWeights()


class RiskModel:
    """관측 feature를 0~100 정수로 축약한다. 상한이 있어 누적 폭주가 없다."""

    def __init__(self, weights: RiskWeights = DEFAULT_WEIGHTS) -> None:
        self._weights = weights

    def score(self, features: FlowFeatures) -> int:
        weights = self._weights
        total = 0
        total += weights.sig_hit * min(features.sig_hits, 8)
        total += weights.distinct_path * min(features.distinct_paths, 12)
        if features.distinct_paths_saturated:
            total += weights.distinct_path_saturated_bonus
        total += weights.encoded_hit * min(features.encoded_hits, 5)
        total += weights.long_uri_hit * min(features.long_uri_hits, 5)
        total += weights.scan_flag_hit * min(features.scan_flag_hits, 5)

        # 균일성은 "충분히 균일할 때만" 가산한다. 낮은 균일성에 비례 가산하면
        # 표본이 적은 정상 flow가 조용히 점수를 얻는다.
        if features.interval_regularity >= weights.regularity_min:
            total += weights.regularity

        return max(0, min(MAX_SCORE, total))
