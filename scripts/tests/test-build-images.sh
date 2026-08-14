#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
build_script="$repo_root/scripts/build-images.sh"
fixture_dir="$(mktemp -d "${TMPDIR:-/tmp}/aegis-build-images.XXXXXX")"
trap 'rm -rf -- "$fixture_dir"' EXIT

revision="0123456789abcdef0123456789abcdef01234567"
short_revision="${revision:0:12}"
docker_log="$fixture_dir/docker.log"

fail() {
    printf 'FAIL: %s\n' "$1" >&2
    exit 1
}

cat >"$fixture_dir/git" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
if [[ "$*" == *"rev-parse HEAD"* ]]; then
    printf '%s\n' "$FAKE_GIT_REVISION"
elif [[ "$*" == *"status --porcelain"* ]]; then
    if [[ "${FAKE_GIT_DIRTY:-0}" == "1" ]]; then
        printf '%s\n' ' M agents/attacker/Dockerfile'
    fi
else
    printf 'unexpected git arguments: %s\n' "$*" >&2
    exit 2
fi
EOF

cat >"$fixture_dir/docker" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >>"$FAKE_DOCKER_LOG"

if [[ "$1" == "buildx" && "$2" == "build" ]]; then
    exit 0
fi

if [[ "$1" != "image" || "$2" != "inspect" ]]; then
    printf 'unexpected docker arguments: %s\n' "$*" >&2
    exit 2
fi

format="$4"
image="$5"
case "$format" in
    *org.opencontainers.image.revision*)
        printf '%s\n' "${FAKE_IMAGE_REVISION:-$FAKE_GIT_REVISION}"
        ;;
    *'.Os'*'.Architecture'*)
        printf '%s\n' 'linux/amd64'
        ;;
    *'.Config.Cmd'*)
        if [[ "$image" == *attacker* ]]; then
            printf '%s\n' '["python","-u","-m","aegis_attacker"]'
        else
            printf '%s\n' '["python","-u","-m","aegis_defender"]'
        fi
        ;;
    *'.Config.User'*)
        if [[ "$image" == *defender* ]]; then
            printf '%s\n' '65534'
        fi
        ;;
    *'.Config.Env'*)
        if [[ "${FAKE_ENV_INSPECT_FAIL:-0}" == "1" ]]; then
            exit 9
        fi
        printf '%s\n' 'PATH=/usr/local/bin:/usr/bin:/bin'
        ;;
    *)
        printf 'unexpected inspect format: %s\n' "$format" >&2
        exit 2
        ;;
esac
EOF

chmod +x "$fixture_dir/git" "$fixture_dir/docker"

run_build() {
    env \
        GIT_BIN="$fixture_dir/git" \
        DOCKER_BIN="$fixture_dir/docker" \
        FAKE_GIT_REVISION="$revision" \
        FAKE_DOCKER_LOG="$docker_log" \
        "$@" \
        bash "$build_script"
}

: >"$docker_log"
run_build >"$fixture_dir/stdout" 2>"$fixture_dir/stderr" \
    || fail 'matching revision build should pass'

[[ "$(grep -c '^buildx build ' "$docker_log")" == "2" ]] \
    || fail 'both images were not clean-built'
grep -F -- "--load --no-cache --platform linux/amd64 --build-arg VCS_REF=$revision" \
    "$docker_log" >/dev/null || fail 'clean build did not receive current SHA'
grep -F -- "--tag aegis/attacker:verify-$short_revision" "$docker_log" >/dev/null \
    || fail 'attacker verification tag is missing'
grep -F -- "--tag aegis/defender:verify-$short_revision" "$docker_log" >/dev/null \
    || fail 'defender verification tag is missing'
grep -F -- "Verified aegis/attacker:verify-$short_revision" "$fixture_dir/stdout" >/dev/null \
    || fail 'attacker inspect result was not reported'
grep -F -- "Verified aegis/defender:verify-$short_revision" "$fixture_dir/stdout" >/dev/null \
    || fail 'defender inspect result was not reported'

: >"$docker_log"
if run_build FAKE_GIT_DIRTY=1 >"$fixture_dir/stdout" 2>"$fixture_dir/stderr"; then
    fail 'dirty worktree must be rejected'
fi
[[ ! -s "$docker_log" ]] || fail 'dirty worktree invoked docker'
grep -F -- 'working tree is not clean' "$fixture_dir/stderr" >/dev/null \
    || fail 'dirty worktree rejection reason is missing'

: >"$docker_log"
if run_build FAKE_IMAGE_REVISION=wrong >"$fixture_dir/stdout" 2>"$fixture_dir/stderr"; then
    fail 'revision mismatch must fail verification'
fi
grep -F -- 'revision mismatch' "$fixture_dir/stderr" >/dev/null \
    || fail 'revision mismatch reason is missing'

: >"$docker_log"
if run_build FAKE_ENV_INSPECT_FAIL=1 >"$fixture_dir/stdout" 2>"$fixture_dir/stderr"; then
    fail 'environment inspect failure must fail verification'
fi

printf '%s\n' 'test-build-images.sh passed'
