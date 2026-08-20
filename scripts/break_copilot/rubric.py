"""Combine independent human and AI readiness assessments conservatively."""

from __future__ import annotations

from dataclasses import dataclass


WEIGHTS = {
    "evidence": 15,
    "attacker": 20,
    "defender": 25,
    "generalization": 15,
    "performance": 15,
    "operations": 5,
    "llm": 5,
}
GATES = {
    "scope_rules",
    "evidence_traceability",
    "contract_preservation",
    "defender_safety",
    "isolation_reproducibility",
}


class RubricError(ValueError):
    pass


@dataclass(frozen=True)
class CombinedRubric:
    candidate_id: str
    score: float
    grade: str
    hard_gates_passed: bool
    arbitration_required: tuple[str, ...]
    score_values: dict[str, int]

    def to_dict(self) -> dict[str, object]:
        return {
            "candidate_id": self.candidate_id,
            "score": self.score,
            "grade": self.grade,
            "hard_gates_passed": self.hard_gates_passed,
            "arbitration_required": list(self.arbitration_required),
            "score_values": self.score_values,
        }


def validate_assessment(document: dict[str, object], evaluator: str) -> None:
    if document.get("schema_version") != 1 or document.get("evaluator") != evaluator:
        raise RubricError(f"{evaluator} assessment schema/evaluator가 잘못되었습니다")
    gates = document.get("hard_gates")
    scores = document.get("scores")
    if not isinstance(gates, dict) or set(gates) != GATES:
        raise RubricError(f"{evaluator} hard_gates가 완전하지 않습니다")
    if not isinstance(scores, dict) or set(scores) != set(WEIGHTS):
        raise RubricError(f"{evaluator} scores가 완전하지 않습니다")
    for name, item in gates.items():
        if not isinstance(item, dict) or item.get("status") not in {"PASS", "FAIL", "NOT_TESTED", "NOT_APPLICABLE"}:
            raise RubricError(f"{evaluator} gate {name} 형식이 잘못되었습니다")
        if not isinstance(item.get("evidence_ids"), list):
            raise RubricError(f"{evaluator} gate {name} evidence_ids가 없습니다")
    for name, item in scores.items():
        if not isinstance(item, dict) or not isinstance(item.get("value"), int) or not 0 <= item["value"] <= 4:
            raise RubricError(f"{evaluator} score {name} 형식이 잘못되었습니다")
        evidence = item.get("evidence_ids")
        if not isinstance(evidence, list):
            raise RubricError(f"{evaluator} score {name} evidence_ids가 없습니다")
        if not evidence and item["value"] > 1:
            raise RubricError(f"근거 없는 {evaluator} score {name}은 1점을 넘을 수 없습니다")


def combine_assessments(ai: dict[str, object], human: dict[str, object]) -> CombinedRubric:
    validate_assessment(ai, "ai")
    validate_assessment(human, "human")
    if ai.get("candidate_id") != human.get("candidate_id"):
        raise RubricError("AI와 사람 candidate_id가 다릅니다")
    ai_gates = ai["hard_gates"]
    human_gates = human["hard_gates"]
    ai_scores = ai["scores"]
    human_scores = human["scores"]
    assert isinstance(ai_gates, dict) and isinstance(human_gates, dict)
    assert isinstance(ai_scores, dict) and isinstance(human_scores, dict)

    hard_pass = True
    for gate in GATES:
        statuses = {ai_gates[gate]["status"], human_gates[gate]["status"]}  # type: ignore[index]
        if "FAIL" in statuses or "NOT_TESTED" in statuses:
            hard_pass = False
        if statuses == {"NOT_APPLICABLE"}:
            continue
        if "PASS" not in statuses:
            hard_pass = False

    conservative: dict[str, int] = {}
    arbitration: list[str] = []
    for name, weight in WEIGHTS.items():
        ai_value = int(ai_scores[name]["value"])  # type: ignore[index]
        human_value = int(human_scores[name]["value"])  # type: ignore[index]
        conservative[name] = min(ai_value, human_value)
        if abs(ai_value - human_value) >= 2:
            arbitration.append(name)
    if arbitration:
        hard_pass = False
    score = round(sum(WEIGHTS[name] * conservative[name] / 4 for name in WEIGHTS), 2)
    if not hard_pass or score < 75:
        grade = "NOT_READY"
    elif score < 90:
        grade = "CONDITIONAL"
    else:
        grade = "READY"
    return CombinedRubric(str(ai["candidate_id"]), score, grade, hard_pass, tuple(arbitration), conservative)


def assessment_template(*, evaluator: str, candidate_id: str) -> dict[str, object]:
    if evaluator not in {"ai", "human"}:
        raise RubricError("evaluator는 ai 또는 human이어야 합니다")
    gate = {"status": "NOT_TESTED", "evidence_ids": [], "reason": ""}
    score = {"value": 0, "evidence_ids": [], "reason": ""}
    return {
        "schema_version": 1,
        "evaluator": evaluator,
        "candidate_id": candidate_id,
        "hard_gates": {name: dict(gate) for name in sorted(GATES)},
        "scores": {name: dict(score) for name in WEIGHTS},
        "limitations": [],
    }
