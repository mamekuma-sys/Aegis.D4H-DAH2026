#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
fixture_root="$(mktemp -d "${TMPDIR:-/tmp}/aegis-shell-entrypoints.XXXXXX")"
cleanup() {
    rm -rf -- "$fixture_root"
}
trap cleanup EXIT

fail() {
    printf 'FAIL: %s\n' "$1" >&2
    exit 1
}

if python3 -c 'pass' >/dev/null 2>&1; then
    python_cmd='python3'
elif python -c 'pass' >/dev/null 2>&1; then
    python_cmd='python'
else
    fail 'python interpreter not available'
fi
export PYTHON_CMD="$python_cmd"

bash -n \
    "$repo_root/scripts/check-layout.sh" \
    "$repo_root/scripts/replay-defender-pcaps.sh" \
    "$repo_root/scripts/validate-skeleton.sh" \
    "$repo_root/integration/run-with-skeleton.sh"

for zsh_script in \
        "$repo_root/scripts/break-copilot.zsh" \
        "$repo_root/scripts/macos-preflight.zsh" \
        "$repo_root/integration/scrimmage/run-scrimmage.zsh" \
        "$repo_root/integration/promote-candidate.zsh"; do
    grep -q '^#!/bin/zsh$' "$zsh_script" \
        || fail "macOS entrypoint must use /bin/zsh: $zsh_script"
done

bash "$repo_root/scripts/check-layout.sh" >/dev/null \
    || fail 'portable layout check rejected the repository'

invalid="$fixture_root/invalid"
mkdir -p "$invalid"
if bash "$repo_root/scripts/validate-skeleton.sh" "$invalid" >/dev/null 2>&1; then
    fail 'validator accepted a skeleton with missing files'
fi

valid="$fixture_root/valid"
for relative_path in \
        deploy/docker-compose.yml \
        deploy/docs/agent-guide.md \
        deploy/agents/team1/attacker/Dockerfile \
        deploy/agents/team1/defender/Dockerfile \
        deploy/router/broker; do
    mkdir -p "$valid/$(dirname "$relative_path")"
    : >"$valid/$relative_path"
done

output="$(bash "$repo_root/scripts/validate-skeleton.sh" "$valid")" \
    || fail 'validator rejected a complete skeleton fixture'
[[ "$output" == *'Validated DAH skeleton:'* ]] \
    || fail 'validator success output is missing'

platform_count="$(grep -Ec '^[[:space:]]+platform: linux/amd64$' \
    "$repo_root/integration/compose.agents.yml")"
[[ "$platform_count" == '2' ]] \
    || fail 'compose override must force linux/amd64 for both agents'

fake_bin="$fixture_root/bin"
mkdir -p "$fake_bin"
cat >"$fake_bin/docker" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
if [[ "$*" == 'compose version' ]]; then
    [[ "${FAKE_DOCKER_COMPOSE_PLUGIN:-1}" == '1' ]] || exit 1
    printf '%s\n' 'Docker Compose version test'
    exit 0
fi
if [[ "$1" == 'compose' && "$*" == *' config --format json'* ]]; then
    "$PYTHON_CMD" -c '
import json, os
print(json.dumps({"services": {
    "team1-attacker": {
        "build": {"context": os.environ["AEGIS_ATTACKER_CONTEXT"]},
        "image": "aegis/attacker:latest",
    },
    "team1-defender": {
        "build": {"context": os.environ["AEGIS_DEFENDER_CONTEXT"]},
        "image": "aegis/defender:latest",
    },
}}))
'
    exit 0
fi
printf 'unexpected fake docker arguments: %s\n' "$*" >&2
exit 2
EOF
chmod +x "$fake_bin/docker"

cat >"$fake_bin/docker-compose" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
exec docker compose "$@"
EOF
chmod +x "$fake_bin/docker-compose"

PATH="$fake_bin:$PATH" \
    bash "$repo_root/integration/run-with-skeleton.sh" "$valid" --config-only \
    >/dev/null \
    || fail 'macOS/Linux skeleton runner rejected correct repository contexts'

FAKE_DOCKER_COMPOSE_PLUGIN=0 PATH="$fake_bin:$PATH" \
    bash "$repo_root/integration/run-with-skeleton.sh" "$valid" --config-only \
    >/dev/null \
    || fail 'macOS standalone docker-compose fallback rejected correct repository contexts'

printf '%s\n' 'test-shell-entrypoints.sh passed'
