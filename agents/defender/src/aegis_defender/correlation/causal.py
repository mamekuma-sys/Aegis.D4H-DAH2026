"""관측된 key만 사용하는 비동기 chain match (`CausalMatcher`).

설계 §11, §2 용어 분리, §15.5 `S4ChainStage`가 `FinalsPhase`와 섞이지 않음.

**여기서 다루는 단계는 관측 근거로 정의된 것이지 예선 보고서 S4의 1~5 번호가
아니다.** §2가 "`S4ChainStage`는 `FinalsPhase` 번호와 대응한다고 가정하지 않음"을
명시했고, 같은 이유로 보고서의 단계 번호를 관측된 증거에 임의로 붙이지 않는다.
보고서 단계와의 대응은 본선 PCAP과 fixture가 확보된 뒤 Break에서 사람이
`research/defense-mapping.md`에 기록하며, 그때까지 이 matcher는 **자기가 실제로
본 것만** 이름 붙인다.

예선 보고서의 누적 점수 15→52→131→196→238은 합성 데이터에서 나온 보정되지 않은
값이므로 복사하지 않는다(§3 마지막 행, §11).
"""

from __future__ import annotations

from dataclasses import dataclass

# 관측 가능한 증거로만 정의한 단계. 이름에 번호를 넣지 않는 것이 §2 제약의 핵심이다.
STAGE_SCAN = "observed-scan"
STAGE_PATH_PROBE = "observed-path-probe"
STAGE_INJECTION = "observed-injection"
STAGE_SENSITIVE_TARGET = "observed-sensitive-target"
STAGE_REPEAT_AFTER_HIT = "observed-repeat-after-hit"

OBSERVED_STAGES = (
    STAGE_SCAN,
    STAGE_PATH_PROBE,
    STAGE_INJECTION,
    STAGE_SENSITIVE_TARGET,
    STAGE_REPEAT_AFTER_HIT,
)

# `Sig` 카테고리 → 단계. 카테고리는 policy file의 `category` field에서 온다(§9.3).
_CATEGORY_STAGES = {
    "path-traversal": STAGE_PATH_PROBE,
    "file-read": STAGE_PATH_PROBE,
    "sql-injection": STAGE_INJECTION,
    "command-injection": STAGE_INJECTION,
    "template-injection": STAGE_INJECTION,
    "deserialization": STAGE_INJECTION,
    "sensitive-path": STAGE_SENSITIVE_TARGET,
}


@dataclass(frozen=True, slots=True)
class ChainEvidence:
    """matcher가 보는 관측 사실. 원본 payload나 packet 객체를 포함하지 않는다."""

    scan_flag_hits: int = 0
    sig_categories: tuple[str, ...] = ()
    sig_hits: int = 0
    packets_after_first_hit: int = 0


class CausalMatcher:
    """관측된 evidence에서 단계 집합을 만든다. 순서를 강요하지 않는다.

    체인 "순서"를 요구하지 않는 이유는 관측 경계 때문이다. Broker는 인바운드
    패킷만 전달하므로(§0.4) 각 단계의 성공 여부를 볼 수 없다. 실패한 시도와
    성공한 시도가 구분되지 않는 입력에서 순서를 강제하면 없는 확신을 만들어낸다.
    따라서 "무엇이 함께 관측됐는가"만 보고한다.
    """

    def match(self, evidence: ChainEvidence) -> tuple[str, ...]:
        stages: list[str] = []

        if evidence.scan_flag_hits > 0:
            stages.append(STAGE_SCAN)

        for category in evidence.sig_categories:
            stage = _CATEGORY_STAGES.get(category)
            if stage is not None and stage not in stages:
                stages.append(stage)

        if evidence.sig_hits > 0 and evidence.packets_after_first_hit > 0:
            stages.append(STAGE_REPEAT_AFTER_HIT)

        return tuple(stages)
