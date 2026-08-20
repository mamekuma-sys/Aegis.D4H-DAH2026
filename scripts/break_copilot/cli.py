"""Command-line entrypoint for the break-time copilot."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

from .approval import ApprovalError, make_template, verify_approval
from .evaluate import EvaluationError, evaluate_candidate, write_evaluation
from .evaluate import DEFAULT_TEST_IMAGE
from .ingest import IngestError, ingest
from .llm import (
    DEFAULT_ANALYZER_MODEL,
    DEFAULT_PATCH_MODEL,
    LLMError,
    LiteLLMClient,
    analyze_manifest,
    append_usage,
    assess_readiness,
    completion_url,
    load_allowed_models,
    propose_patch,
)
from .patching import PatchError, apply_patch, prepare_candidate, validate_patch
from .rubric import RubricError, assessment_template, combine_assessments


def repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def load_object(path: Path) -> dict[str, object]:
    document = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(document, dict):
        raise ValueError(f"JSON 최상위는 object여야 합니다: {path}")
    return document


def write_object(path: Path, document: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(document, ensure_ascii=False, indent=2, sort_keys=True), encoding="utf-8")


def default_artifact_root() -> Path:
    return repo_root() / "captures/break-copilot"


def _assert_artifact_root(path: Path) -> None:
    resolved = path.resolve()
    try:
        relative = resolved.relative_to(repo_root().resolve())
    except ValueError:
        return
    if not relative.parts or relative.parts[0] != "captures":
        raise ValueError("저장소 내부 artifact는 gitignored captures/ 아래에만 쓸 수 있습니다")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="break-copilot",
        description="Sanitize round evidence and verify an isolated one-side candidate.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    preflight_parser = subparsers.add_parser("preflight", help="check break-station prerequisites without API calls")
    preflight_parser.add_argument("--require-llm", action="store_true")
    preflight_parser.add_argument("--require-docker", action="store_true")
    preflight_parser.add_argument("--require-tshark", action="store_true")

    ingest_parser = subparsers.add_parser("ingest", help="sanitize capture/log inputs")
    ingest_parser.add_argument("--input", nargs="+", required=True)
    ingest_parser.add_argument("--side", choices=("attacker", "defender"), required=True)
    ingest_parser.add_argument("--artifact-root", type=Path, default=default_artifact_root())
    ingest_parser.add_argument("--stability-seconds", type=float, default=1.0)
    ingest_parser.add_argument("--run-id")

    analyze_parser = subparsers.add_parser("analyze", help="analyze a sanitized manifest")
    analyze_parser.add_argument("--manifest", type=Path, required=True)
    analyze_parser.add_argument("--model", default=DEFAULT_ANALYZER_MODEL)
    analyze_parser.add_argument("--output", type=Path)

    propose_parser = subparsers.add_parser("propose", help="propose and locally validate a one-side diff")
    propose_parser.add_argument("--analysis", type=Path, required=True)
    propose_parser.add_argument("--side", choices=("attacker", "defender"), required=True)
    propose_parser.add_argument("--model", default=DEFAULT_PATCH_MODEL)
    propose_parser.add_argument("--output", type=Path)

    validate_parser = subparsers.add_parser("validate-patch", help="validate diff scope without applying it")
    validate_parser.add_argument("--patch", type=Path, required=True)
    validate_parser.add_argument("--side", choices=("attacker", "defender"), required=True)

    prepare_parser = subparsers.add_parser("prepare-candidate", help="create a short-lived candidate worktree")
    prepare_parser.add_argument("--candidate", type=Path, required=True)
    prepare_parser.add_argument("--base-ref", default="HEAD")
    prepare_parser.add_argument("--branch")

    apply_parser = subparsers.add_parser("apply", help="apply a validated diff to the candidate worktree")
    apply_parser.add_argument("--candidate", type=Path, required=True)
    apply_parser.add_argument("--patch", type=Path, required=True)
    apply_parser.add_argument("--side", choices=("attacker", "defender"), required=True)

    evaluate_parser = subparsers.add_parser("evaluate", help="run fixed candidate verification commands")
    evaluate_parser.add_argument("--candidate", type=Path, required=True)
    evaluate_parser.add_argument("--side", choices=("attacker", "defender"), required=True)
    evaluate_parser.add_argument("--base-ref", default="HEAD")
    evaluate_parser.add_argument("--pcap", action="append", type=Path, default=[])
    evaluate_parser.add_argument("--skeleton-path", type=Path)
    evaluate_parser.add_argument("--output", type=Path)

    approval_parser = subparsers.add_parser("approval-template", help="create a non-approved human gate template")
    approval_parser.add_argument("--candidate", type=Path, required=True)
    approval_parser.add_argument("--evaluation", type=Path, required=True)
    approval_parser.add_argument("--rubric", type=Path, required=True)
    approval_parser.add_argument("--side", choices=("attacker", "defender"), required=True)
    approval_parser.add_argument("--agent-owner", required=True)
    approval_parser.add_argument("--team-lead", required=True)
    approval_parser.add_argument("--docker-owner", required=True)
    approval_parser.add_argument("--output", type=Path)

    verify_parser = subparsers.add_parser("verify-approval", help="verify approval/evaluation/current HEAD binding")
    verify_parser.add_argument("--candidate", type=Path, required=True)
    verify_parser.add_argument("--evaluation", type=Path, required=True)
    verify_parser.add_argument("--rubric", type=Path, required=True)
    verify_parser.add_argument("--approval", type=Path, required=True)
    verify_parser.add_argument("--side", choices=("attacker", "defender"), required=True)

    rubric_parser = subparsers.add_parser("combine-rubric", help="combine independent AI and human ratings")
    rubric_parser.add_argument("--ai", type=Path, required=True)
    rubric_parser.add_argument("--human", type=Path, required=True)
    rubric_parser.add_argument("--output", type=Path)

    template_parser = subparsers.add_parser("rubric-template", help="create an unscored human or AI rubric")
    template_parser.add_argument("--candidate-id", required=True)
    template_parser.add_argument("--evaluator", choices=("ai", "human"), required=True)
    template_parser.add_argument("--output", type=Path, required=True)

    assess_parser = subparsers.add_parser("assess", help="apply the readiness rubric with an independent LLM call")
    assess_parser.add_argument("--candidate", type=Path, required=True)
    assess_parser.add_argument("--base-ref", required=True)
    assess_parser.add_argument("--side", choices=("attacker", "defender"), required=True)
    assess_parser.add_argument("--evaluation", type=Path, required=True)
    assess_parser.add_argument("--manifest", type=Path)
    assess_parser.add_argument("--scrimmage", type=Path)
    assess_parser.add_argument("--model", default=DEFAULT_ANALYZER_MODEL)
    assess_parser.add_argument("--output", type=Path)

    run_parser = subparsers.add_parser("run", help="ingest, analyze, patch, isolate, apply, and evaluate")
    run_parser.add_argument("--input", nargs="+", required=True)
    run_parser.add_argument("--side", choices=("attacker", "defender"), required=True)
    run_parser.add_argument("--candidate", type=Path, required=True)
    run_parser.add_argument("--base-ref", default="HEAD")
    run_parser.add_argument("--artifact-root", type=Path, default=default_artifact_root())
    run_parser.add_argument("--stability-seconds", type=float, default=1.0)
    run_parser.add_argument("--analyzer-model", default=DEFAULT_ANALYZER_MODEL)
    run_parser.add_argument("--patch-model", default=DEFAULT_PATCH_MODEL)
    run_parser.add_argument("--pcap", action="append", type=Path, default=[])
    run_parser.add_argument("--skeleton-path", type=Path)
    return parser


def _run_id() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def _client() -> LiteLLMClient:
    return LiteLLMClient.from_environment(repo_root())


def _preflight(*, require_llm: bool, require_docker: bool, require_tshark: bool) -> dict[str, object]:
    root = repo_root()
    checks: list[dict[str, object]] = []

    def add(name: str, passed: bool, required: bool, detail: str) -> None:
        checks.append(
            {"name": name, "status": "PASS" if passed else ("FAIL" if required else "WARN"), "detail": detail}
        )

    add("python_3_12", sys.version_info >= (3, 12), True, f"{sys.version_info.major}.{sys.version_info.minor}")
    add("git", shutil.which("git") is not None, True, "available" if shutil.which("git") else "missing")
    docker_cli = shutil.which("docker")
    add("docker_cli", docker_cli is not None, require_docker, "available" if docker_cli else "missing")
    if require_docker and docker_cli:
        try:
            docker_server = subprocess.run(
                [docker_cli, "version", "--format", "{{.Server.Os}}/{{.Server.Arch}}"],
                capture_output=True,
                text=True,
                timeout=20,
                check=False,
            )
            docker_ready = docker_server.returncode == 0 and docker_server.stdout.strip().startswith("linux/")
        except (OSError, subprocess.TimeoutExpired):
            docker_ready = False
        add("docker_linux_server", docker_ready, True, "ready" if docker_ready else "unavailable or not Linux")
        test_image = os.environ.get("BREAK_COPILOT_TEST_IMAGE", DEFAULT_TEST_IMAGE)
        try:
            image_result = subprocess.run(
                [docker_cli, "image", "inspect", test_image],
                capture_output=True,
                timeout=20,
                check=False,
            )
            image_ready = image_result.returncode == 0
        except (OSError, subprocess.TimeoutExpired):
            image_ready = False
        add("sandbox_test_image", image_ready, True, "available locally" if image_ready else "pre-pull required")
    add("tshark", shutil.which("tshark") is not None, require_tshark, "structural PCAP parsing" if shutil.which("tshark") else "metadata-only fallback")
    base_url = os.environ.get("LLM_BASE_URL", "")
    try:
        base_url_valid = bool(base_url) and bool(completion_url(base_url))
    except LLMError:
        base_url_valid = False
    add("llm_base_url", base_url_valid, require_llm, "configured" if base_url_valid else "missing or invalid")
    add("llm_api_key", bool(os.environ.get("LLM_API_KEY")), require_llm, "configured" if os.environ.get("LLM_API_KEY") else "missing")
    contracts = all(
        (root / relative).is_file()
        for relative in (
            "contracts/llm/model-quotas.json",
            "contracts/break-copilot/readiness.schema.json",
            "contracts/break-copilot/approval.schema.json",
            "contracts/break-copilot/combined-rubric.schema.json",
            "contracts/break-copilot/manifest.schema.json",
            "contracts/break-copilot/evaluation.schema.json",
            "contracts/break-copilot/scrimmage.schema.json",
        )
    )
    add("contracts", contracts, True, "present" if contracts else "missing")
    try:
        models = load_allowed_models(root)
        default_models_ready = {DEFAULT_ANALYZER_MODEL, DEFAULT_PATCH_MODEL}.issubset(models)
    except (OSError, ValueError, KeyError, json.JSONDecodeError):
        default_models_ready = False
    add("default_models", default_models_ready, True, "allowlisted" if default_models_ready else "missing from contract")
    try:
        ignored = subprocess.run(
            ["git", "check-ignore", "-q", "captures/break-copilot/probe.log"],
            cwd=root,
            capture_output=True,
            timeout=15,
            check=False,
        ).returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        ignored = False
    add("artifact_gitignore", ignored, True, "captures/break-copilot is ignored" if ignored else "not ignored")
    failed = any(item["status"] == "FAIL" for item in checks)
    return {"schema_version": 1, "status": "FAIL" if failed else "PASS", "checks": checks, "api_called": False}


def execute(args: argparse.Namespace) -> int:
    root = repo_root()
    if args.command == "preflight":
        result = _preflight(
            require_llm=args.require_llm,
            require_docker=args.require_docker,
            require_tshark=args.require_tshark,
        )
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0 if result["status"] == "PASS" else 2
    if args.command == "ingest":
        _assert_artifact_root(args.artifact_root)
        _, output = ingest(
            args.input,
            side=args.side,
            artifact_root=args.artifact_root,
            stability_seconds=args.stability_seconds,
            run_id=args.run_id,
        )
        print(output)
        return 0

    if args.command == "analyze":
        manifest = load_object(args.manifest)
        analysis, usage = analyze_manifest(_client(), manifest, model=args.model)
        output = args.output or args.manifest.with_name("analysis.json")
        write_object(output, analysis)
        append_usage(output.parent / "usage.jsonl", run_id=str(manifest.get("run_id", "unknown")), stage="analysis", model=args.model, usage=usage)
        print(output)
        return 0

    if args.command == "propose":
        analysis = load_object(args.analysis)
        proposal, usage = propose_patch(_client(), analysis=analysis, repo_root=root, side=args.side, model=args.model)
        patch = str(proposal["patch"])
        report = validate_patch(patch, side=args.side)
        output = args.output or args.analysis.with_name("proposal.diff")
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(patch, encoding="utf-8")
        metadata = {key: value for key, value in proposal.items() if key != "patch"}
        metadata["validation"] = report.to_dict()
        write_object(output.with_suffix(".json"), metadata)
        append_usage(output.parent / "usage.jsonl", run_id=output.parent.name, stage="patch", model=args.model, usage=usage)
        print(output)
        return 0

    if args.command == "validate-patch":
        report = validate_patch(args.patch.read_text(encoding="utf-8"), side=args.side)
        print(json.dumps(report.to_dict(), ensure_ascii=False, indent=2))
        return 0

    if args.command == "prepare-candidate":
        branch = args.branch or f"break/{_run_id().lower()}"
        commit = prepare_candidate(root, args.candidate, base_ref=args.base_ref, branch_name=branch)
        print(json.dumps({"candidate": str(args.candidate.resolve()), "branch": branch, "base_commit": commit}, indent=2))
        return 0

    if args.command == "apply":
        report = apply_patch(root, args.candidate, args.patch.read_text(encoding="utf-8"), side=args.side)
        print(json.dumps(report.to_dict(), ensure_ascii=False, indent=2))
        return 0

    if args.command == "evaluate":
        document = evaluate_candidate(
            args.candidate,
            side=args.side,
            base_ref=args.base_ref,
            pcaps=args.pcap,
            skeleton_path=args.skeleton_path,
        )
        output = args.output or default_artifact_root() / "evaluations" / f"{_run_id()}-{args.side}.json"
        digest = write_evaluation(document, output)
        print(json.dumps({"output": str(output), "sha256": digest, "status": document["status"]}, indent=2))
        return 0 if document["status"] == "PASS" else 2

    if args.command == "approval-template":
        document = make_template(
            args.candidate,
            args.evaluation,
            args.rubric,
            side=args.side,
            agent_owner=args.agent_owner,
            team_lead=args.team_lead,
            docker_owner=args.docker_owner,
        )
        output = args.output or args.evaluation.with_name("approval.json")
        write_object(output, document)
        print(output)
        return 0

    if args.command == "verify-approval":
        result = verify_approval(args.candidate, args.evaluation, args.rubric, args.approval, side=args.side)
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0

    if args.command == "combine-rubric":
        result = combine_assessments(load_object(args.ai), load_object(args.human)).to_dict()
        result["schema_version"] = 1
        result["ai_assessment_sha256"] = hashlib.sha256(args.ai.read_bytes()).hexdigest()
        result["human_assessment_sha256"] = hashlib.sha256(args.human.read_bytes()).hexdigest()
        if args.output:
            write_object(args.output, result)
            print(args.output)
        else:
            print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0 if result["grade"] in {"READY", "CONDITIONAL"} else 2

    if args.command == "rubric-template":
        write_object(args.output, assessment_template(evaluator=args.evaluator, candidate_id=args.candidate_id))
        print(args.output)
        return 0

    if args.command == "assess":
        candidate = args.candidate.resolve()
        head_result = subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=candidate, text=True, capture_output=True, timeout=30, check=False
        )
        diff_result = subprocess.run(
            ["git", "diff", "--no-ext-diff", "--binary", args.base_ref, "--"],
            cwd=candidate,
            text=True,
            capture_output=True,
            timeout=60,
            check=False,
        )
        if head_result.returncode != 0 or diff_result.returncode != 0:
            raise ValueError("candidate commit 또는 diff를 읽을 수 없습니다")
        status_result = subprocess.run(
            ["git", "status", "--porcelain"],
            cwd=candidate,
            text=True,
            capture_output=True,
            timeout=30,
            check=False,
        )
        if status_result.returncode != 0 or status_result.stdout.strip():
            raise ValueError("AI readiness 평가는 clean candidate commit에서만 실행합니다")
        candidate_id = head_result.stdout.strip()
        validate_patch(diff_result.stdout, side=args.side)
        evaluation = load_object(args.evaluation)
        if evaluation.get("candidate_commit") != candidate_id or evaluation.get("side") != args.side:
            raise ValueError("evaluation이 현재 candidate commit/side와 다릅니다")
        manifest = load_object(args.manifest) if args.manifest else None
        scrimmage = load_object(args.scrimmage) if args.scrimmage else None
        assessment, usage = assess_readiness(
            _client(),
            candidate_id=candidate_id,
            side=args.side,
            patch=diff_result.stdout,
            evaluation=evaluation,
            manifest=manifest,
            scrimmage=scrimmage,
            model=args.model,
        )
        output = args.output or args.evaluation.with_name("ai-readiness.json")
        write_object(output, assessment)
        append_usage(output.parent / "usage.jsonl", run_id=candidate_id[:12], stage="readiness", model=args.model, usage=usage)
        print(output)
        return 0

    if args.command == "run":
        _assert_artifact_root(args.artifact_root)
        run_id = _run_id()
        manifest, manifest_path = ingest(
            args.input,
            side=args.side,
            artifact_root=args.artifact_root,
            stability_seconds=args.stability_seconds,
            run_id=run_id,
        )
        run_dir = manifest_path.parent
        client = _client()
        analysis, analysis_usage = analyze_manifest(client, manifest, model=args.analyzer_model)
        analysis_path = run_dir / "analysis.json"
        write_object(analysis_path, analysis)
        append_usage(run_dir / "usage.jsonl", run_id=run_id, stage="analysis", model=args.analyzer_model, usage=analysis_usage)
        proposal, patch_usage = propose_patch(client, analysis=analysis, repo_root=root, side=args.side, model=args.patch_model)
        patch = str(proposal["patch"])
        patch_report = validate_patch(patch, side=args.side)
        patch_path = run_dir / "proposal.diff"
        patch_path.write_text(patch, encoding="utf-8")
        write_object(run_dir / "proposal.json", {**{key: value for key, value in proposal.items() if key != "patch"}, "validation": patch_report.to_dict()})
        append_usage(run_dir / "usage.jsonl", run_id=run_id, stage="patch", model=args.patch_model, usage=patch_usage)
        branch = f"break/{run_id.lower()}"
        prepare_candidate(root, args.candidate, base_ref=args.base_ref, branch_name=branch)
        apply_patch(root, args.candidate, patch, side=args.side)
        evaluation = evaluate_candidate(
            args.candidate,
            side=args.side,
            base_ref=args.base_ref,
            pcaps=args.pcap,
            skeleton_path=args.skeleton_path,
        )
        evaluation_path = run_dir / "evaluation.json"
        digest = write_evaluation(evaluation, evaluation_path)
        result = {
            "run_id": run_id,
            "candidate": str(args.candidate.resolve()),
            "branch": branch,
            "manifest": str(manifest_path),
            "analysis": str(analysis_path),
            "patch": str(patch_path),
            "evaluation": str(evaluation_path),
            "evaluation_sha256": digest,
            "status": evaluation["status"],
            "next": "review, commit, re-run evaluate with the same base-ref, then create approval-template",
        }
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0 if evaluation["status"] == "PASS" else 2
    raise AssertionError("unreachable command")


def main(argv: list[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    try:
        return execute(args)
    except (
        ApprovalError,
        EvaluationError,
        IngestError,
        LLMError,
        PatchError,
        RubricError,
        subprocess.TimeoutExpired,
        OSError,
        ValueError,
        json.JSONDecodeError,
    ) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
