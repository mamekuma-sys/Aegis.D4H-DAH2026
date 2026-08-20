#!/bin/zsh
set -eu
set -o pipefail

script_dir="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)"
repo_root="$(CDPATH= cd -- "$script_dir/.." && pwd -P)"

if [[ -n "${PYTHON_CMD:-}" ]]; then
    python_cmd="$PYTHON_CMD"
elif [[ -n "${PYTHON:-}" ]]; then
    python_cmd="$PYTHON"
elif command -v python3 >/dev/null 2>&1; then
    python_cmd='python3'
elif command -v python >/dev/null 2>&1; then
    python_cmd='python'
else
    print -u2 'ERROR: Python interpreter not found. Install Python 3.12+ or set PYTHON.'
    exit 1
fi

cd "$repo_root"
export PYTHONDONTWRITEBYTECODE=1
exec "$python_cmd" -B -m scripts.break_copilot "$@"
