from __future__ import annotations

import unittest

from integration.scrimmage.compare_results import ComparisonError, compare


def matrix(repetitions: int = 3) -> dict[str, object]:
    definitions = {
        "BB": ("baseline", "baseline", 10.0, 0.99),
        "CB": ("candidate", "baseline", 13.0, 0.99),
        "BC": ("baseline", "candidate", 7.0, 1.0),
        "CC": ("candidate", "candidate", 9.0, 1.0),
    }
    runs = []
    for cell, (attacker, defender, score, availability) in definitions.items():
        for repeat in range(repetitions):
            runs.append(
                {
                    "cell": cell,
                    "repeat": repeat,
                    "attacker_variant": attacker,
                    "defender_variant": defender,
                    "valid": True,
                    "attacker_score": score,
                    "availability": availability,
                    "seed": f"seed-{repeat}",
                    "started_at": f"2026-08-20T00:0{repeat}:00Z",
                    "attacker_image_digest": "sha256:" + ("a" if attacker == "baseline" else "b") * 64,
                    "defender_image_digest": "sha256:" + ("c" if defender == "baseline" else "d") * 64,
                    "skeleton_sha256": "e" * 64,
                }
            )
    return {"schema_version": 1, "runs": runs}


class ScrimmageComparisonTests(unittest.TestCase):
    def test_complete_matrix_computes_symmetric_deltas(self) -> None:
        result = compare(matrix())
        self.assertTrue(result["complete"])
        self.assertEqual(2.5, result["deltas"]["attacker_candidate_effect"])  # type: ignore[index]
        self.assertEqual(3.5, result["deltas"]["defender_candidate_score_reduction"])  # type: ignore[index]
        self.assertEqual(0.01, result["deltas"]["defender_candidate_availability_effect"])  # type: ignore[index]

    def test_two_repetitions_are_not_complete(self) -> None:
        self.assertFalse(compare(matrix(repetitions=2))["complete"])

    def test_rejects_mislabeled_cell(self) -> None:
        document = matrix()
        document["runs"][0]["attacker_variant"] = "candidate"  # type: ignore[index]
        with self.assertRaises(ComparisonError):
            compare(document)


if __name__ == "__main__":
    unittest.main()
