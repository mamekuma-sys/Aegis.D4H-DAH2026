#!/usr/bin/env python3
"""Compare a baseline/candidate attacker-defender 2x2 scrimmage matrix."""

from __future__ import annotations

import argparse
import json
import math
import re
import statistics
from collections import defaultdict
from datetime import datetime
from pathlib import Path


EXPECTED = {
    "BB": ("baseline", "baseline"),
    "CB": ("candidate", "baseline"),
    "BC": ("baseline", "candidate"),
    "CC": ("candidate", "candidate"),
}


class ComparisonError(ValueError):
    pass


def _mean(rows: list[dict[str, object]], field: str) -> float:
    values = [float(row[field]) for row in rows]
    return statistics.fmean(values)


def compare(document: dict[str, object]) -> dict[str, object]:
    if document.get("schema_version") != 1 or not isinstance(document.get("runs"), list):
        raise ComparisonError("schema_version=1과 runs 배열이 필요합니다")
    grouped: dict[str, list[dict[str, object]]] = defaultdict(list)
    attacker_digests: dict[str, set[str]] = defaultdict(set)
    defender_digests: dict[str, set[str]] = defaultdict(set)
    skeleton_hashes: set[str] = set()
    invalid = 0
    for item in document["runs"]:  # type: ignore[index]
        if not isinstance(item, dict):
            raise ComparisonError("run은 object여야 합니다")
        cell = str(item.get("cell", ""))
        if cell not in EXPECTED:
            raise ComparisonError(f"알 수 없는 cell: {cell}")
        attacker, defender = EXPECTED[cell]
        if item.get("attacker_variant") != attacker or item.get("defender_variant") != defender:
            raise ComparisonError(f"{cell} variant 조합이 잘못되었습니다")
        if item.get("valid") is not True:
            if not isinstance(item.get("invalid_reason"), str) or not str(item["invalid_reason"]).strip():
                raise ComparisonError("invalid run에는 invalid_reason이 필요합니다")
            invalid += 1
            continue
        for field in ("attacker_score", "availability"):
            if not isinstance(item.get(field), (int, float)):
                raise ComparisonError(f"valid run에는 숫자 {field}가 필요합니다")
            if not math.isfinite(float(item[field])):
                raise ComparisonError(f"{field}는 유한한 숫자여야 합니다")
        if not 0 <= float(item["availability"]) <= 1:
            raise ComparisonError("availability는 0..1이어야 합니다")
        for field in ("seed", "started_at", "attacker_image_digest", "defender_image_digest", "skeleton_sha256"):
            if not isinstance(item.get(field), (str, int)) or not str(item[field]).strip():
                raise ComparisonError(f"valid run에는 {field}가 필요합니다")
        attacker_digest = str(item["attacker_image_digest"])
        defender_digest = str(item["defender_image_digest"])
        skeleton_sha256 = str(item["skeleton_sha256"])
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", attacker_digest) or not re.fullmatch(
            r"sha256:[0-9a-f]{64}", defender_digest
        ):
            raise ComparisonError("image digest는 sha256:<64 lowercase hex> 형식이어야 합니다")
        if not re.fullmatch(r"[0-9a-f]{64}", skeleton_sha256):
            raise ComparisonError("skeleton_sha256 형식이 잘못되었습니다")
        try:
            started_at = datetime.fromisoformat(str(item["started_at"]).replace("Z", "+00:00"))
        except ValueError as exc:
            raise ComparisonError("started_at은 ISO-8601이어야 합니다") from exc
        if started_at.tzinfo is None:
            raise ComparisonError("started_at timezone이 필요합니다")
        attacker_digests[attacker].add(attacker_digest)
        defender_digests[defender].add(defender_digest)
        skeleton_hashes.add(skeleton_sha256)
        grouped[cell].append(item)

    if any(len(values) != 1 for values in attacker_digests.values()) or any(
        len(values) != 1 for values in defender_digests.values()
    ):
        raise ComparisonError("같은 variant가 서로 다른 image digest를 사용했습니다")
    if len(skeleton_hashes) > 1:
        raise ComparisonError("scrimmage run의 skeleton hash가 서로 다릅니다")

    missing = [cell for cell in EXPECTED if not grouped[cell]]
    summaries: dict[str, dict[str, object]] = {}
    for cell, variants in EXPECTED.items():
        rows = grouped[cell]
        summaries[cell] = {
            "attacker_variant": variants[0],
            "defender_variant": variants[1],
            "valid_runs": len(rows),
            "attacker_score_mean": round(_mean(rows, "attacker_score"), 6) if rows else None,
            "availability_mean": round(_mean(rows, "availability"), 6) if rows else None,
        }
    seed_sets = {cell: {str(row["seed"]) for row in grouped[cell]} for cell in EXPECTED}
    paired_seeds = not missing and len({frozenset(values) for values in seed_sets.values()}) == 1
    complete = not missing and paired_seeds and all(len(seed_sets[cell]) >= 3 for cell in EXPECTED)
    deltas: dict[str, float] | None = None
    if not missing:
        score = {cell: float(summaries[cell]["attacker_score_mean"]) for cell in EXPECTED}
        availability = {cell: float(summaries[cell]["availability_mean"]) for cell in EXPECTED}
        deltas = {
            "attacker_candidate_effect": round(((score["CB"] - score["BB"]) + (score["CC"] - score["BC"])) / 2, 6),
            "defender_candidate_score_reduction": round(((score["BB"] - score["BC"]) + (score["CB"] - score["CC"])) / 2, 6),
            "defender_candidate_availability_effect": round(
                ((availability["BC"] - availability["BB"]) + (availability["CC"] - availability["CB"])) / 2,
                6,
            ),
        }
    return {
        "schema_version": 1,
        "complete": complete,
        "minimum_repetitions_met": complete,
        "paired_seed_sets": paired_seeds,
        "invalid_runs": invalid,
        "missing_cells": missing,
        "cells": summaries,
        "deltas": deltas,
        "limitations": [
            "This comparison is not an official finals score.",
            "A complete matrix requires at least three valid runs per cell.",
        ],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    try:
        document = json.loads(args.input.read_text(encoding="utf-8"))
        result = compare(document)
    except (OSError, json.JSONDecodeError, ComparisonError) as exc:
        parser.error(str(exc))
    encoded = json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(encoded, encoding="utf-8")
    else:
        print(encoded)
    return 0 if result["complete"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
