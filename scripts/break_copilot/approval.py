"""Create and verify the human gate consumed by image promotion."""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path


class ApprovalError(ValueError):
    pass


def _assert_ready_rubric(rubric: dict[str, object], commit: str) -> None:
    if (
        rubric.get("schema_version") != 1
        or rubric.get("candidate_id") != commit
        or rubric.get("grade") != "READY"
        or rubric.get("hard_gates_passed") is not True
        or rubric.get("arbitration_required") != []
    ):
        raise ApprovalError("현재 commit에 결속된 중재 항목 없는 READY rubric이 필요합니다")
    for field in ("ai_assessment_sha256", "human_assessment_sha256"):
        if not re.fullmatch(r"[0-9a-f]{64}", str(rubric.get(field, ""))):
            raise ApprovalError(f"rubric {field}가 유효하지 않습니다")


def sha256_path(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _git(candidate: Path, *arguments: str) -> str:
    try:
        result = subprocess.run(
            ["git", *arguments], cwd=candidate, text=True, capture_output=True, timeout=30, check=False
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ApprovalError("git 실행 실패") from exc
    if result.returncode != 0:
        raise ApprovalError(f"git {' '.join(arguments)} 실패")
    return result.stdout.strip()


def make_template(
    candidate: Path,
    evaluation_path: Path,
    rubric_path: Path,
    *,
    side: str,
    agent_owner: str,
    team_lead: str,
    docker_owner: str,
) -> dict[str, object]:
    candidate = candidate.resolve()
    evaluation = json.loads(evaluation_path.read_text(encoding="utf-8"))
    rubric = json.loads(rubric_path.read_text(encoding="utf-8"))
    if not isinstance(evaluation, dict) or not isinstance(rubric, dict):
        raise ApprovalError("evaluation과 rubric은 JSON object여야 합니다")
    commit = _git(candidate, "rev-parse", "HEAD")
    if evaluation.get("candidate_commit") != commit:
        raise ApprovalError("evaluation candidate_commit이 현재 HEAD와 다릅니다. commit 후 재평가하십시오")
    if evaluation.get("side") != side or evaluation.get("status") != "PASS":
        raise ApprovalError("요청 side의 PASS evaluation만 승인 템플릿을 만들 수 있습니다")
    _assert_ready_rubric(rubric, commit)
    now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    return {
        "schema_version": 1,
        "decision": "PENDING",
        "candidate_commit": commit,
        "evaluation_sha256": sha256_path(evaluation_path),
        "rubric_sha256": sha256_path(rubric_path),
        "side": side,
        "reviews": [
            {"role": "agent_owner", "reviewer": agent_owner, "decision": "PENDING", "reviewed_at": now},
            {"role": "team_lead", "reviewer": team_lead, "decision": "PENDING", "reviewed_at": now},
            {"role": "docker_owner", "reviewer": docker_owner, "decision": "PENDING", "reviewed_at": now},
        ],
        "notes": "각 역할 검토자가 decision을 APPROVE 또는 REJECT로 확정한 뒤 최상위 decision을 변경",
    }


def verify_approval(
    candidate: Path,
    evaluation_path: Path,
    rubric_path: Path,
    approval_path: Path,
    *,
    side: str,
) -> dict[str, object]:
    candidate = candidate.resolve()
    evaluation = json.loads(evaluation_path.read_text(encoding="utf-8"))
    rubric = json.loads(rubric_path.read_text(encoding="utf-8"))
    approval = json.loads(approval_path.read_text(encoding="utf-8"))
    if not isinstance(evaluation, dict) or not isinstance(rubric, dict) or not isinstance(approval, dict):
        raise ApprovalError("evaluation, rubric, approval은 JSON object여야 합니다")
    allowed_keys = {
        "schema_version",
        "decision",
        "candidate_commit",
        "evaluation_sha256",
        "rubric_sha256",
        "side",
        "reviews",
        "notes",
    }
    if not set(approval).issubset(allowed_keys):
        raise ApprovalError("approval JSON 필드가 잘못되었습니다")
    required = allowed_keys - {"notes"}
    if not required.issubset(approval):
        raise ApprovalError("approval JSON 필수 필드가 없습니다")
    if approval.get("schema_version") != 1 or approval.get("decision") != "APPROVE":
        raise ApprovalError("사람이 decision=APPROVE로 확정한 승인만 사용할 수 있습니다")
    if approval.get("side") != side or evaluation.get("side") != side:
        raise ApprovalError("approval/evaluation side가 요청과 다릅니다")
    if evaluation.get("status") != "PASS":
        raise ApprovalError("PASS evaluation만 승격할 수 있습니다")
    if approval.get("evaluation_sha256") != sha256_path(evaluation_path):
        raise ApprovalError("evaluation digest가 승인 시점과 다릅니다")
    if approval.get("rubric_sha256") != sha256_path(rubric_path):
        raise ApprovalError("rubric digest가 승인 시점과 다릅니다")
    head = _git(candidate, "rev-parse", "HEAD")
    if approval.get("candidate_commit") != head or evaluation.get("candidate_commit") != head:
        raise ApprovalError("candidate HEAD, evaluation, approval commit이 일치하지 않습니다")
    _assert_ready_rubric(rubric, head)
    if _git(candidate, "status", "--porcelain"):
        raise ApprovalError("승격 전 candidate worktree는 clean 상태여야 합니다")
    branch = _git(candidate, "branch", "--show-current")
    if not branch or branch in {"main", "master"}:
        raise ApprovalError("main/master에서 직접 승격할 수 없습니다")
    reviews = approval.get("reviews")
    if not isinstance(reviews, list) or len(reviews) != 3:
        raise ApprovalError("agent_owner, team_lead, docker_owner 리뷰가 모두 필요합니다")
    roles: set[str] = set()
    reviewers: list[str] = []
    for review in reviews:
        if not isinstance(review, dict) or set(review) != {"role", "reviewer", "decision", "reviewed_at"}:
            raise ApprovalError("review 형식이 잘못되었습니다")
        role = str(review["role"])
        reviewer = str(review["reviewer"]).strip()
        if role not in {"agent_owner", "team_lead", "docker_owner"} or role in roles:
            raise ApprovalError("review role이 없거나 중복되었습니다")
        if review["decision"] != "APPROVE":
            raise ApprovalError(f"{role} review가 APPROVE가 아닙니다")
        if not reviewer or reviewer.lower() in {"ai", "llm", "model"}:
            raise ApprovalError(f"{role}에 사람 reviewer 이름이 필요합니다")
        try:
            reviewed_at = datetime.fromisoformat(str(review["reviewed_at"]).replace("Z", "+00:00"))
        except ValueError as exc:
            raise ApprovalError(f"{role} reviewed_at은 ISO-8601이어야 합니다") from exc
        if reviewed_at.tzinfo is None:
            raise ApprovalError(f"{role} reviewed_at timezone이 필요합니다")
        if reviewed_at > datetime.now(timezone.utc).astimezone(reviewed_at.tzinfo):
            raise ApprovalError(f"{role} reviewed_at이 미래 시각입니다")
        roles.add(role)
        reviewers.append(reviewer)
    return {
        "approved": True,
        "candidate_commit": head,
        "evaluation_sha256": approval["evaluation_sha256"],
        "rubric_sha256": approval["rubric_sha256"],
        "side": side,
        "reviewers": reviewers,
        "branch": branch,
    }
