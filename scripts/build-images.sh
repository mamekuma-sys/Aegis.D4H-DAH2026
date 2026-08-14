#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
git_bin="${GIT_BIN:-git}"
docker_bin="${DOCKER_BIN:-docker}"

fail() {
    printf 'ERROR: %s\n' "$1" >&2
    exit 1
}

command -v "$git_bin" >/dev/null 2>&1 || fail 'git executable not found'

revision="$("$git_bin" -C "$repo_root" rev-parse HEAD)"
[[ "$revision" =~ ^[0-9a-fA-F]{40}$ ]] || fail 'git HEAD is not a full commit SHA'

worktree_state="$("$git_bin" -C "$repo_root" status --porcelain)"
[[ -z "$worktree_state" ]] || fail 'working tree is not clean; commit or stash changes before building'

command -v "$docker_bin" >/dev/null 2>&1 || fail 'docker executable not found'

short_revision="${revision:0:12}"
attacker_image="aegis/attacker:verify-$short_revision"
defender_image="aegis/defender:verify-$short_revision"

build_image() {
    local image="$1"
    local context="$2"

    "$docker_bin" buildx build \
        --load \
        --no-cache \
        --platform linux/amd64 \
        --build-arg "VCS_REF=$revision" \
        --tag "$image" \
        "$context"
}

inspect_value() {
    local format="$1"
    local image="$2"
    "$docker_bin" image inspect --format "$format" "$image"
}

verify_no_secret_env() {
    local image="$1"
    local entry key value env_entries

    env_entries="$(inspect_value '{{range .Config.Env}}{{println .}}{{end}}' "$image")" \
        || fail "$image environment inspect failed"

    while IFS= read -r entry; do
        [[ -n "$entry" ]] || continue
        key="${entry%%=*}"
        value="${entry#*=}"
        case "$key" in
            SUBMIT_TOKEN|LLM_API_KEY)
                [[ -z "$value" ]] || fail "$image contains a competition secret environment value"
                ;;
        esac
    done <<<"$env_entries"
}

verify_image() {
    local image="$1"
    local expected_cmd="$2"
    local expected_user="$3"
    local actual_revision actual_platform actual_cmd actual_user

    actual_revision="$(inspect_value '{{ index .Config.Labels "org.opencontainers.image.revision" }}' "$image")"
    [[ "$actual_revision" == "$revision" ]] \
        || fail "$image revision mismatch"

    actual_platform="$(inspect_value '{{ .Os }}/{{ .Architecture }}' "$image")"
    [[ "$actual_platform" == 'linux/amd64' ]] \
        || fail "$image platform mismatch"

    actual_cmd="$(inspect_value '{{ json .Config.Cmd }}' "$image")"
    [[ "$actual_cmd" == "$expected_cmd" ]] \
        || fail "$image CMD mismatch"

    actual_user="$(inspect_value '{{ .Config.User }}' "$image")"
    [[ "$actual_user" == "$expected_user" ]] \
        || fail "$image user mismatch"

    verify_no_secret_env "$image"
    printf 'Verified %s revision=%s platform=%s\n' "$image" "$actual_revision" "$actual_platform"
}

build_image "$attacker_image" "$repo_root/agents/attacker"
build_image "$defender_image" "$repo_root/agents/defender"

verify_image "$attacker_image" '["python","-u","-m","aegis_attacker"]' ''
verify_image "$defender_image" '["python","-u","-m","aegis_defender"]' '65534'
