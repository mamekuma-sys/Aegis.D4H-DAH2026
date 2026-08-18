#!/usr/bin/env bash
set -euo pipefail

usage() {
    printf 'Usage: bash scripts/validate-skeleton.sh <skeleton-root>\n' >&2
    exit 2
}

[[ $# -eq 1 ]] || usage
[[ -d "$1" ]] || {
    printf 'ERROR: Skeleton root does not exist: %s\n' "$1" >&2
    exit 1
}

skeleton_root="$(cd "$1" && pwd -P)"
required_paths=(
    'deploy/docker-compose.yml'
    'deploy/docs/agent-guide.md'
    'deploy/agents/team1/attacker/Dockerfile'
    'deploy/agents/team1/defender/Dockerfile'
    'deploy/router/broker'
)

missing=()
for relative_path in "${required_paths[@]}"; do
    [[ -f "$skeleton_root/$relative_path" ]] || missing+=("$relative_path")
done

if (( ${#missing[@]} > 0 )); then
    printf 'ERROR: Invalid DAH skeleton. Missing:\n' >&2
    printf -- '- %s\n' "${missing[@]}" >&2
    exit 1
fi

printf 'Validated DAH skeleton: %s\n' "$skeleton_root"
