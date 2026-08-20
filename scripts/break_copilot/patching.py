"""Validate and apply an LLM-produced unified diff inside an isolated worktree."""

from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from .redaction import contains_forbidden_secret


MAX_PATCH_BYTES = 200_000
MAX_PATCH_FILES = 8
MAX_ADDED_LINES = 4_000
TRUSTED_BASE_REFS = ("refs/remotes/origin/main", "refs/heads/main")


class PatchError(ValueError):
    pass


@dataclass(frozen=True)
class PatchReport:
    side: str
    files: tuple[str, ...]
    added_lines: int
    removed_lines: int
    bytes: int

    def to_dict(self) -> dict[str, object]:
        return {
            "side": self.side,
            "files": list(self.files),
            "added_lines": self.added_lines,
            "removed_lines": self.removed_lines,
            "bytes": self.bytes,
        }


def _allowed_patch_path(side: str, relative: str) -> bool:
    path = PurePosixPath(relative)
    if path.is_absolute() or ".." in path.parts or path.suffix != ".py":
        return False
    roots = (PurePosixPath(f"agents/{side}/src"), PurePosixPath(f"agents/{side}/tests"))
    return any(root in path.parents for root in roots)


def _validate_test_additions(patch: str, files: list[str], side: str) -> None:
    """기존 검증 테스트는 불변으로 두고 새 ``test_*.py``만 허용한다.

    후보가 런타임과 timing test를 한 patch에서 함께 완화하면 candidate suite가
    통과해도 아무 안전 의미가 없다. 기존 테스트는 trusted base의 gate이므로 LLM이
    수정할 수 없고, 새 회귀 테스트만 별도 파일로 추가할 수 있다.
    """
    test_root = PurePosixPath(f"agents/{side}/tests")
    test_files = {
        relative for relative in files if test_root in PurePosixPath(relative).parents
    }
    if not test_files:
        return

    chunks = re.split(r"(?=^diff --git )", patch, flags=re.MULTILINE)
    seen: set[str] = set()
    for chunk in chunks:
        if not chunk.startswith("diff --git "):
            continue
        first_line = chunk.splitlines()[0]
        match = re.fullmatch(r"diff --git a/([^\s]+) b/([^\s]+)", first_line)
        if not match:
            continue
        relative = match.group(1).replace("\\", "/")
        if relative not in test_files:
            continue
        path = PurePosixPath(relative)
        if not path.name.startswith("test_"):
            raise PatchError("추가 테스트 파일은 test_*.py 이름만 허용됩니다")
        if not re.search(r"^new file mode 100644$", chunk, re.MULTILINE):
            raise PatchError("기존 테스트는 수정할 수 없고 새 test_*.py만 추가할 수 있습니다")
        if not re.search(r"^--- /dev/null$", chunk, re.MULTILINE):
            raise PatchError("새 테스트는 /dev/null에서 생성된 diff여야 합니다")
        seen.add(relative)
    if seen != test_files:
        raise PatchError("테스트 patch의 신규 파일 경계를 확인할 수 없습니다")


def validate_patch(patch: str, *, side: str) -> PatchReport:
    if side not in {"attacker", "defender"}:
        raise PatchError("side는 attacker 또는 defender여야 합니다")
    patch_bytes = len(patch.encode("utf-8"))
    if patch_bytes == 0 or patch_bytes > MAX_PATCH_BYTES:
        raise PatchError(f"patch 크기는 1..{MAX_PATCH_BYTES} bytes여야 합니다")
    if "GIT binary patch" in patch or "Binary files " in patch:
        raise PatchError("binary patch는 허용되지 않습니다")
    forbidden_directives = (
        "rename from ",
        "rename to ",
        "deleted file mode ",
        "old mode ",
        "new mode ",
        "Subproject commit ",
        "similarity index ",
        "dissimilarity index ",
    )
    if any(directive in patch for directive in forbidden_directives):
        raise PatchError("rename, delete, mode 또는 submodule 변경은 허용되지 않습니다")
    for line in patch.splitlines():
        if line.startswith("new file mode ") and line != "new file mode 100644":
            raise PatchError("새 파일은 regular non-executable mode 100644만 허용됩니다")

    files: list[str] = []
    for line in patch.splitlines():
        if not line.startswith("diff --git "):
            continue
        match = re.fullmatch(r"diff --git a/([^\s]+) b/([^\s]+)", line)
        if not match or match.group(1) != match.group(2):
            raise PatchError("diff 경로 형식이 잘못되었거나 rename입니다")
        relative = match.group(1).replace("\\", "/")
        if not _allowed_patch_path(side, relative):
            raise PatchError(f"허용되지 않은 patch 경로입니다: {relative}")
        files.append(relative)
    if not files or len(files) != len(set(files)):
        raise PatchError("patch 파일 경로가 없거나 중복되었습니다")
    if len(files) > MAX_PATCH_FILES:
        raise PatchError(f"patch는 최대 {MAX_PATCH_FILES}개 파일만 변경할 수 있습니다")
    _validate_test_additions(patch, files, side)

    file_set = set(files)
    old_headers: list[str] = []
    new_headers: list[str] = []
    hunk_count = 0
    for line in patch.splitlines():
        if line.startswith("@@ "):
            hunk_count += 1
        if not (line.startswith("--- ") or line.startswith("+++ ")):
            continue
        marker, raw_path = line[:3], line[4:]
        if raw_path == "/dev/null" and marker == "---":
            old_headers.append(raw_path)
            continue
        prefix = "a/" if marker == "---" else "b/"
        if not raw_path.startswith(prefix) or any(character.isspace() for character in raw_path):
            raise PatchError("---/+++ diff 경로 형식이 잘못되었습니다")
        relative = raw_path[2:].replace("\\", "/")
        if relative not in file_set or not _allowed_patch_path(side, relative):
            raise PatchError(f"diff header가 허용되지 않은 경로를 가리킵니다: {relative}")
        (old_headers if marker == "---" else new_headers).append(relative)
    if len(old_headers) != len(files) or len(new_headers) != len(files) or hunk_count == 0:
        raise PatchError("각 diff 파일에는 일치하는 ---/+++ header와 hunk가 필요합니다")

    added: list[str] = []
    removed = 0
    for line in patch.splitlines():
        if line.startswith("+++") or line.startswith("---"):
            continue
        if line.startswith("+"):
            added.append(line[1:])
        elif line.startswith("-"):
            removed += 1
    if len(added) > MAX_ADDED_LINES:
        raise PatchError(f"추가 라인은 최대 {MAX_ADDED_LINES}줄입니다")
    if contains_forbidden_secret("\n".join(added)):
        raise PatchError("patch 추가 라인에서 비밀정보 형태를 탐지했습니다")

    touched_other_side = "agents/defender/" if side == "attacker" else "agents/attacker/"
    if touched_other_side in patch.replace("\\", "/"):
        raise PatchError("한 patch에서 양쪽 agent를 함께 변경할 수 없습니다")
    return PatchReport(side, tuple(files), len(added), removed, patch_bytes)


def _run_git(arguments: list[str], *, cwd: Path, input_text: str | None = None) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            ["git", *arguments],
            cwd=cwd,
            input=input_text,
            text=True,
            capture_output=True,
            timeout=60,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise PatchError("git 실행에 실패했습니다") from exc


def trusted_main_commit(repo_root: Path) -> str:
    """원격 main을 우선하는 검증 기준 commit을 돌려준다."""
    for reference in TRUSTED_BASE_REFS:
        result = _run_git(["rev-parse", "--verify", f"{reference}^{{commit}}"], cwd=repo_root)
        if result.returncode == 0:
            commit = result.stdout.strip()
            if re.fullmatch(r"[0-9a-f]{40}", commit):
                return commit
    raise PatchError("trusted main commit을 찾을 수 없습니다")


def resolve_trusted_base(repo_root: Path, base_ref: str) -> str:
    """사용자 ref가 현재 trusted main과 정확히 같은 commit인지 확인한다."""
    requested = _run_git(["rev-parse", "--verify", f"{base_ref}^{{commit}}"], cwd=repo_root)
    if requested.returncode != 0:
        raise PatchError("base-ref commit을 찾을 수 없습니다")
    requested_commit = requested.stdout.strip()
    trusted_commit = trusted_main_commit(repo_root)
    if requested_commit != trusted_commit:
        raise PatchError(
            "base-ref는 현재 origin/main(원격이 없으면 main) commit과 정확히 일치해야 합니다"
        )
    return requested_commit


def prepare_candidate(repo_root: Path, candidate: Path, *, base_ref: str, branch_name: str) -> str:
    repo_root = repo_root.resolve()
    candidate = candidate.resolve()
    if candidate.exists():
        raise PatchError(f"candidate 경로가 이미 존재합니다: {candidate}")
    try:
        relative_candidate = candidate.relative_to(repo_root)
    except ValueError:
        relative_candidate = None
    if relative_candidate is not None and (not relative_candidate.parts or relative_candidate.parts[0] != ".worktrees"):
        raise PatchError("저장소 내부 candidate는 ignored .worktrees/ 아래에만 만들 수 있습니다")
    if not re.fullmatch(r"break/[a-z0-9][a-z0-9._-]{2,63}", branch_name):
        raise PatchError("candidate branch는 break/<safe-id> 형식이어야 합니다")
    base_commit = resolve_trusted_base(repo_root, base_ref)
    branch = _run_git(["show-ref", "--verify", "--quiet", f"refs/heads/{branch_name}"], cwd=repo_root)
    if branch.returncode == 0:
        raise PatchError(f"candidate branch가 이미 존재합니다: {branch_name}")
    created = _run_git(
        ["worktree", "add", "-b", branch_name, str(candidate), base_commit],
        cwd=repo_root,
    )
    if created.returncode != 0:
        raise PatchError(f"candidate worktree 생성 실패: {created.stderr.strip()[:300]}")
    return base_commit


def _common_git_dir(path: Path) -> Path:
    result = _run_git(["rev-parse", "--path-format=absolute", "--git-common-dir"], cwd=path)
    if result.returncode != 0:
        raise PatchError("git worktree가 아닙니다")
    return Path(result.stdout.strip()).resolve()


def apply_patch(repo_root: Path, candidate: Path, patch: str, *, side: str) -> PatchReport:
    report = validate_patch(patch, side=side)
    repo_root = repo_root.resolve()
    candidate = candidate.resolve()
    if not candidate.is_dir() or _common_git_dir(candidate) != _common_git_dir(repo_root):
        raise PatchError("candidate가 이 저장소의 worktree가 아닙니다")
    status = _run_git(["status", "--porcelain"], cwd=candidate)
    if status.returncode != 0 or status.stdout.strip():
        raise PatchError("candidate worktree는 patch 적용 전에 clean 상태여야 합니다")
    checked = _run_git(["apply", "--check", "--whitespace=error-all", "-"], cwd=candidate, input_text=patch)
    if checked.returncode != 0:
        raise PatchError(f"git apply --check 실패: {checked.stderr.strip()[:300]}")
    applied = _run_git(["apply", "--whitespace=error-all", "-"], cwd=candidate, input_text=patch)
    if applied.returncode != 0:
        raise PatchError(f"git apply 실패: {applied.stderr.strip()[:300]}")
    return report
