#!/bin/zsh
set -eu
set -o pipefail

script_dir="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)"
repo_root="$(CDPATH= cd -- "$script_dir/../.." && pwd -P)"
fixture_root="$(mktemp -d "${TMPDIR:-/tmp}/aegis-macos-entrypoints.XXXXXX")"
trap 'rm -rf -- "$fixture_root"' EXIT

fail() {
    print -u2 "FAIL: $1"
    exit 1
}

for path in \
    "$repo_root/scripts/break-copilot.zsh" \
    "$repo_root/scripts/macos-preflight.zsh" \
    "$repo_root/integration/scrimmage/run-scrimmage.zsh" \
    "$repo_root/integration/promote-candidate.zsh"; do
    zsh -n "$path" || fail "zsh parse failed: $path"
done

zsh_output="$(zsh "$repo_root/scripts/break-copilot.zsh" preflight)" \
    || fail 'zsh Break Copilot wrapper failed'
[[ "$zsh_output" == *'"api_called": false'* ]] \
    || fail 'zsh preflight did not preserve the no-API-call contract'

command -v pwsh >/dev/null 2>&1 || fail 'pwsh is not installed on the macOS runner'
pwsh_output="$(pwsh -NoProfile -File "$repo_root/scripts/break-copilot.ps1" preflight)" \
    || fail 'PowerShell Break Copilot wrapper failed on macOS'
[[ "$pwsh_output" == *'"api_called": false'* ]] \
    || fail 'PowerShell preflight did not preserve the no-API-call contract'

valid="$fixture_root/official-skeleton"
mkdir -p "$valid/deploy"
: >"$valid/deploy/docker-compose.yml"

fake_bin="$fixture_root/bin"
mkdir -p "$fake_bin"
cat >"$fake_bin/docker" <<'EOF'
#!/bin/sh
set -eu
if [ "$*" = 'compose version' ]; then
    printf '%s\n' 'Docker Compose version test'
    exit 0
fi
case "$*" in
    *' config --format json'*)
        "$PYTHON_CMD" -c '
import json, os
print(json.dumps({"services": {
    "team1-attacker": {
        "image": os.environ["AEGIS_SCRIMMAGE_ATTACKER_IMAGE"],
        "platform": "linux/amd64",
    },
    "team1-defender": {
        "image": os.environ["AEGIS_SCRIMMAGE_DEFENDER_IMAGE"],
        "platform": "linux/amd64",
    },
}}))
'
        exit 0
        ;;
esac
printf 'unexpected fake docker arguments: %s\n' "$*" >&2
exit 2
EOF
chmod +x "$fake_bin/docker"

export PYTHON_CMD="$(command -v python3)"
PATH="$fake_bin:$PATH" zsh "$repo_root/integration/scrimmage/run-scrimmage.zsh" \
    --skeleton "$valid" \
    --attacker-image 'aegis/attacker:test' \
    --defender-image 'aegis/defender:test' \
    --config-only >/dev/null \
    || fail 'zsh scrimmage config validation failed'

print 'test-macos-entrypoints.zsh passed'
