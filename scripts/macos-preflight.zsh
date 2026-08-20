#!/bin/zsh
set -eu
set -o pipefail

usage() {
    print -u2 'Usage: zsh scripts/macos-preflight.zsh [--require-llm] [--skeleton <root>]'
    exit 2
}

require_llm=0
skeleton_root=''
while (( $# > 0 )); do
    case "$1" in
        --require-llm)
            require_llm=1
            shift
            ;;
        --skeleton)
            (( $# >= 2 )) || usage
            skeleton_root="$2"
            shift 2
            ;;
        *)
            usage
            ;;
    esac
done

script_dir="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)"
repo_root="$(CDPATH= cd -- "$script_dir/.." && pwd -P)"
failures=0
warnings=0

pass_check() { printf 'PASS  %s\n' "$1"; }
warn_check() { printf 'WARN  %s\n' "$1"; warnings=$((warnings + 1)); }
fail_check() { printf 'FAIL  %s\n' "$1"; failures=$((failures + 1)); }

if [[ "$(uname -s)" == 'Darwin' ]]; then
    pass_check "macOS $(sw_vers -productVersion) / $(uname -m)"
else
    warn_check "이 스크립트는 macOS용입니다: $(uname -s)"
fi

if [[ -n "${PYTHON_CMD:-}" ]]; then
    python_cmd="$PYTHON_CMD"
elif [[ -n "${PYTHON:-}" ]]; then
    python_cmd="$PYTHON"
elif command -v python3 >/dev/null 2>&1; then
    python_cmd='python3'
elif command -v python >/dev/null 2>&1; then
    python_cmd='python'
else
    python_cmd=''
fi

if [[ -n "$python_cmd" ]] && "$python_cmd" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 12) else 1)' >/dev/null 2>&1; then
    pass_check "Python $("$python_cmd" -c 'import platform; print(platform.python_version())')"
else
    fail_check 'Python 3.12+ 또는 PYTHON/PYTHON_CMD 설정이 필요합니다'
fi

if command -v pwsh >/dev/null 2>&1; then
    pass_check "PowerShell $(pwsh -NoProfile -Command '$PSVersionTable.PSVersion.ToString()')"
else
    fail_check 'PowerShell Core(pwsh)가 없습니다'
fi

if command -v git >/dev/null 2>&1; then
    pass_check "$(git --version)"
else
    fail_check 'git이 없습니다'
fi

if command -v docker >/dev/null 2>&1; then
    pass_check 'Docker CLI'
    if docker compose version >/dev/null 2>&1; then
        pass_check 'Docker Compose v2'
    else
        fail_check 'Docker Compose v2가 없습니다'
    fi
    if [[ "$(docker info --format '{{.OSType}}' 2>/dev/null || true)" == 'linux' ]]; then
        pass_check 'Docker Linux daemon'
    else
        fail_check 'Docker Desktop을 시작하고 Linux container daemon을 준비해야 합니다'
    fi
    if docker buildx version >/dev/null 2>&1; then
        pass_check 'Docker Buildx'
    else
        fail_check 'Docker Buildx가 없습니다'
    fi
    test_image="${BREAK_COPILOT_TEST_IMAGE:-python:3.12-slim}"
    if docker image inspect "$test_image" >/dev/null 2>&1; then
        pass_check "sandbox image: $test_image"
    else
        fail_check "sandbox image를 사전 pull해야 합니다: $test_image"
    fi
else
    fail_check 'Docker CLI가 없습니다'
fi

if command -v tshark >/dev/null 2>&1; then
    pass_check 'tshark'
else
    warn_check 'tshark가 없어 PCAP 구조 분석은 metadata-only로 제한됩니다'
fi

case "${LLM_BASE_URL:-}" in
    http://*|https://*) pass_check 'LLM_BASE_URL' ;;
    *)
        if (( require_llm )); then fail_check 'LLM_BASE_URL이 없습니다'; else warn_check 'LLM_BASE_URL이 없습니다'; fi
        ;;
esac
if [[ -n "${LLM_API_KEY:-}" ]]; then
    pass_check 'LLM_API_KEY present (value hidden)'
else
    if (( require_llm )); then fail_check 'LLM_API_KEY가 없습니다'; else warn_check 'LLM_API_KEY가 없습니다'; fi
fi

if [[ -n "$skeleton_root" ]]; then
    if bash "$repo_root/scripts/validate-skeleton.sh" "$skeleton_root" >/dev/null; then
        pass_check 'official skeleton structure'
    else
        fail_check 'official skeleton structure 검증 실패'
    fi
fi

printf 'SUMMARY failures=%d warnings=%d\n' "$failures" "$warnings"
(( failures == 0 ))
