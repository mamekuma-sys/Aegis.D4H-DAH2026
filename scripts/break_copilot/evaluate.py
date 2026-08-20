"""Run a fixed, non-LLM verification suite for a break candidate."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Sequence

from .patching import PatchError, validate_patch
from .redaction import redact_text


class EvaluationError(RuntimeError):
    pass


Runner = Callable[[Sequence[str], Path, int], subprocess.CompletedProcess[str]]
DEFAULT_TEST_IMAGE = "python:3.12-slim"


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _default_runner(command: Sequence[str], cwd: Path, timeout: int) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        list(command), cwd=cwd, text=True, capture_output=True, timeout=timeout, check=False
    )


def _run_check(
    name: str,
    command: Sequence[str],
    cwd: Path,
    *,
    runner: Runner,
    timeout: int,
) -> dict[str, object]:
    started = time.monotonic()
    try:
        result = runner(command, cwd, timeout)
        returncode = result.returncode
        output = f"{result.stdout}\n{result.stderr}".strip()
        status = "PASS" if returncode == 0 else "FAIL"
        error = None
    except (OSError, subprocess.TimeoutExpired) as exc:
        returncode = None
        output = ""
        status = "FAIL"
        error = type(exc).__name__
    duration = round(time.monotonic() - started, 3)
    return {
        "name": name,
        "status": status,
        "returncode": returncode,
        "duration_seconds": duration,
        "output_sha256": hashlib.sha256(output.encode("utf-8", "replace")).hexdigest(),
        "output_tail": redact_text(output[-1200:], limit=1200),
        "error": error,
    }


def _git_output(candidate: Path, arguments: Sequence[str], runner: Runner) -> str:
    result = runner(["git", *arguments], candidate, 60)
    if result.returncode != 0:
        raise EvaluationError(f"git {' '.join(arguments)} 실패")
    return result.stdout.strip()


def _layout_command(candidate: Path) -> list[str]:
    if os.name == "nt":
        executable = shutil.which("pwsh") or shutil.which("powershell")
        if not executable:
            raise EvaluationError("PowerShell 실행 파일을 찾을 수 없습니다")
        return [executable, "-NoProfile", "-File", str(candidate / "scripts/check-layout.ps1")]
    return ["bash", str(candidate / "scripts/check-layout.sh")]


def _container_base(candidate: Path, *, workdir: str) -> list[str]:
    image = os.environ.get("BREAK_COPILOT_TEST_IMAGE", DEFAULT_TEST_IMAGE)
    if not image or any(character.isspace() for character in image):
        raise EvaluationError("BREAK_COPILOT_TEST_IMAGE 형식이 잘못되었습니다")
    return [
        "docker",
        "run",
        "--rm",
        "--pull=never",
        "--network=none",
        "--read-only",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges=true",
        "--pids-limit=256",
        "--memory=2g",
        "--cpus=2",
        "--user=65534:65534",
        "--tmpfs=/tmp:rw,noexec,nosuid,size=128m,mode=1777",
        "--env=PYTHONDONTWRITEBYTECODE=1",
        "--mount",
        f"type=bind,source={candidate.as_posix()},target=/workspace,readonly",
        "--workdir",
        workdir,
        image,
    ]


def _container_unit_command(candidate: Path, side: str) -> list[str]:
    return [
        *_container_base(candidate, workdir=f"/workspace/agents/{side}"),
        "sh",
        "-c",
        "python -B -m unittest discover -s tests -t . -v >/tmp/unit.log 2>&1",
    ]


def _container_replay_command(candidate: Path, pcaps: Sequence[Path]) -> list[str]:
    command = _container_base(candidate, workdir="/workspace")
    container_inputs: list[str] = []
    for index, raw_path in enumerate(pcaps):
        path = raw_path.resolve()
        if not path.exists() or "," in str(path):
            raise EvaluationError("PCAP 경로가 없거나 Docker --mount에 안전하지 않습니다")
        target = f"/evidence/{index}"
        command[command.index("--workdir"):command.index("--workdir")] = [
            "--mount",
            f"type=bind,source={path.as_posix()},target={target},readonly",
        ]
        container_inputs.append(target)
    return [
        *command,
        "sh",
        "-c",
        (
            "python -B /workspace/agents/defender/tools/replay_pcaps.py \"$@\" "
            "--json --require-zero-unexpected-other-drops >/tmp/replay.log 2>&1"
        ),
        "replay",
        *container_inputs,
    ]


def evaluate_candidate(
    candidate: Path,
    *,
    side: str,
    base_ref: str = "HEAD",
    pcaps: Sequence[Path] = (),
    skeleton_path: Path | None = None,
    runner: Runner = _default_runner,
) -> dict[str, object]:
    candidate = candidate.resolve()
    if side not in {"attacker", "defender"}:
        raise EvaluationError("side는 attacker 또는 defender여야 합니다")
    if not (candidate / ".git").exists():
        raise EvaluationError("candidate가 git worktree가 아닙니다")
    branch = _git_output(candidate, ["branch", "--show-current"], runner)
    if not branch or branch in {"main", "master"}:
        raise EvaluationError("candidate는 short-lived branch여야 합니다")
    base_commit = _git_output(candidate, ["rev-parse", "--verify", f"{base_ref}^{{commit}}"], runner)
    candidate_commit = _git_output(candidate, ["rev-parse", "HEAD"], runner)
    diff_result = runner(["git", "diff", "--no-ext-diff", "--binary", base_ref, "--"], candidate, 60)
    if diff_result.returncode != 0:
        raise EvaluationError("candidate diff를 만들 수 없습니다")
    try:
        patch_report = validate_patch(diff_result.stdout, side=side)
        patch_scope = {"name": "patch_scope", "status": "PASS", "report": patch_report.to_dict()}
    except PatchError as exc:
        patch_scope = {"name": "patch_scope", "status": "FAIL", "error": str(exc)}

    sandbox_image = os.environ.get("BREAK_COPILOT_TEST_IMAGE", DEFAULT_TEST_IMAGE)
    try:
        image_result = runner(
            ["docker", "image", "inspect", "--format", "{{.Id}}", sandbox_image], candidate, 60
        )
        sandbox_image_id = image_result.stdout.strip()
        image_ready = image_result.returncode == 0 and bool(
            re.fullmatch(r"sha256:[0-9a-f]{64}", sandbox_image_id)
        )
    except (OSError, subprocess.TimeoutExpired):
        sandbox_image_id = ""
        image_ready = False
    image_check = {
        "name": "sandbox_test_image",
        "status": "PASS" if image_ready else "FAIL",
        "image": sandbox_image,
        "image_id": sandbox_image_id if image_ready else None,
    }

    checks: list[dict[str, object]] = [patch_scope, image_check]
    checks.append(
        _run_check(
            f"{side}_unit_tests",
            _container_unit_command(candidate, side),
            candidate,
            runner=runner,
            timeout=180,
        )
    )
    checks.append(
        _run_check(
            "git_diff_check",
            ["git", "diff", "--check", base_ref, "--"],
            candidate,
            runner=runner,
            timeout=60,
        )
    )
    checks.append(
        _run_check(
            "repository_layout",
            _layout_command(candidate),
            candidate,
            runner=runner,
            timeout=120,
        )
    )
    if skeleton_path is not None:
        if os.name == "nt":
            executable = shutil.which("pwsh") or shutil.which("powershell")
            if not executable:
                raise EvaluationError("PowerShell 실행 파일을 찾을 수 없습니다")
            skeleton_command = [
                executable,
                "-NoProfile",
                "-File",
                str(candidate / "scripts/validate-skeleton.ps1"),
                "-SkeletonPath",
                str(skeleton_path.resolve()),
            ]
        else:
            skeleton_command = ["bash", str(candidate / "scripts/validate-skeleton.sh"), str(skeleton_path.resolve())]
        checks.append(
            _run_check("skeleton_contract", skeleton_command, candidate, runner=runner, timeout=120)
        )
    if pcaps:
        if side != "defender":
            raise EvaluationError("PCAP replay는 defender candidate에서만 사용합니다")
        command = _container_replay_command(candidate, pcaps)
        checks.append(_run_check("defender_pcap_replay", command, candidate, runner=runner, timeout=300))

    status = "PASS" if all(item.get("status") == "PASS" for item in checks) else "FAIL"
    return {
        "schema_version": 1,
        "created_at": _utc_now(),
        "side": side,
        "candidate_branch": branch,
        "candidate_commit": candidate_commit,
        "base_ref": base_ref,
        "base_commit": base_commit,
        "sandbox_image": sandbox_image,
        "sandbox_image_id": sandbox_image_id if image_ready else None,
        "status": status,
        "checks": checks,
        "limitations": [
            "Unit/replay results are not an official finals score.",
            "Defender READY additionally requires official Broker E2E 300ms, heartbeat, and reconnect evidence.",
        ],
    }


def write_evaluation(document: dict[str, object], output: Path) -> str:
    output.parent.mkdir(parents=True, exist_ok=True)
    encoded = json.dumps(document, ensure_ascii=False, indent=2, sort_keys=True).encode("utf-8")
    output.write_bytes(encoded)
    return hashlib.sha256(encoded).hexdigest()
