#!/usr/bin/env bash
set -euo pipefail

usage() {
    cat >&2 <<'EOF'
Usage: bash integration/run-with-skeleton.sh <skeleton-root> [option]

Options (choose at most one):
  --config-only       Validate merged build contexts without starting containers
  --reapply-agents    Recreate team1 agents after /control/start
  --logs              Follow attacker logs
  --logs-defender     Follow defender logs
  --down              Stop the combat stack without deleting named volumes
EOF
    exit 2
}

[[ $# -ge 1 && $# -le 2 ]] || usage
skeleton_arg="$1"
action="${2:-up}"
case "$action" in
    up|--config-only|--reapply-agents|--logs|--logs-defender|--down) ;;
    *) usage ;;
esac

if [[ -n "${PYTHON_CMD:-}" ]]; then
    python_cmd="$PYTHON_CMD"
elif python3 -c 'pass' >/dev/null 2>&1; then
    python_cmd='python3'
elif python -c 'pass' >/dev/null 2>&1; then
    python_cmd='python'
else
    printf '%s\n' 'ERROR: Python interpreter not found.' >&2
    exit 1
fi

[[ -d "$skeleton_arg" ]] || {
    printf 'ERROR: Skeleton root does not exist: %s\n' "$skeleton_arg" >&2
    exit 1
}

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
repo_root="$(cd "$script_dir/.." && pwd -P)"
skeleton_root="$(cd "$skeleton_arg" && pwd -P)"
compose_file="$skeleton_root/deploy/docker-compose.yml"
override_file="$script_dir/compose.agents.yml"
export AEGIS_ATTACKER_CONTEXT="$repo_root/agents/attacker"
export AEGIS_DEFENDER_CONTEXT="$repo_root/agents/defender"

for required in \
        "$compose_file" \
        "$override_file" \
        "$AEGIS_ATTACKER_CONTEXT/Dockerfile" \
        "$AEGIS_DEFENDER_CONTEXT/Dockerfile"; do
    [[ -f "$required" ]] || {
        printf 'ERROR: Required integration file is missing: %s\n' "$required" >&2
        exit 1
    }
done

if docker compose version >/dev/null 2>&1; then
    compose_command=(docker compose)
elif command -v docker-compose >/dev/null 2>&1; then
    compose_command=(docker-compose)
else
    printf '%s\n' \
        'ERROR: Docker Compose not found. Install the Compose plugin or docker-compose.' >&2
    exit 1
fi

compose() {
    "${compose_command[@]}" \
        -f "$compose_file" -f "$override_file" --profile combat "$@"
}

config_value() {
    local service="$1"
    local field="$2"
    compose config --format json | "$python_cmd" -c '
import json, sys
document = json.load(sys.stdin)
service, field = sys.argv[1:]
value = document.get("services", {}).get(service, {})
for part in field.split("."):
    value = value.get(part) if isinstance(value, dict) else None
if not isinstance(value, str) or not value.strip():
    raise SystemExit(f"missing {service}.{field}")
print(value.strip())
' "$service" "$field"
}

normalize_context() {
    local value="${1//\\//}"
    if [[ "$value" =~ ^([A-Za-z]):/(.*)$ ]]; then
        local drive
        drive="$(printf '%s' "${BASH_REMATCH[1]}" | tr '[:upper:]' '[:lower:]')"
        printf '/%s/%s\n' "$drive" "${BASH_REMATCH[2]}"
    else
        printf '%s\n' "$value"
    fi
}

assert_build_context() {
    local service="$1"
    local expected="$2"
    local actual
    actual="$(config_value "$service" 'build.context')"
    actual="${actual%/}"
    expected="${expected%/}"
    [[ "$(normalize_context "$actual")" == "$(normalize_context "$expected")" ]] || {
        printf "ERROR: %s.build.context is '%s', expected '%s'\n" \
            "$service" "$actual" "$expected" >&2
        exit 1
    }
    printf '%s.build.context=%s\n' "$service" "$actual"
}

assert_running_image() {
    local service="$1"
    local expected container_id actual
    expected="$(config_value "$service" 'image')"
    container_id="$(compose ps -q "$service" | sed -n '1p')"
    [[ -n "$container_id" ]] || {
        printf 'ERROR: %s is not running\n' "$service" >&2
        exit 1
    }
    actual="$(docker inspect --format '{{.Config.Image}}' "$container_id")"
    [[ "$actual" == "$expected" ]] || {
        printf "ERROR: %s is running image '%s', expected '%s'. Run --reapply-agents after /control/start.\n" \
            "$service" "$actual" "$expected" >&2
        exit 1
    }
    printf '%s.image=%s\n' "$service" "$actual"
}

if [[ "$action" == '--down' ]]; then
    compose down
    exit 0
fi

assert_build_context 'team1-attacker' "$AEGIS_ATTACKER_CONTEXT"
assert_build_context 'team1-defender' "$AEGIS_DEFENDER_CONTEXT"

case "$action" in
    --config-only)
        exit 0
        ;;
    --reapply-agents)
        compose up -d --no-deps --no-build --force-recreate team1-attacker team1-defender
        assert_running_image 'team1-attacker'
        assert_running_image 'team1-defender'
        exit 0
        ;;
    --logs)
        compose logs -f team1-attacker
        exit 0
        ;;
    --logs-defender)
        compose logs -f team1-defender
        exit 0
        ;;
esac

compose up -d --build
printf '%s\n' '운영 페이지: http://localhost:4100'
printf '%s\n' '라운드 시작 후: bash integration/run-with-skeleton.sh <스켈레톤-루트> --reapply-agents'
printf '%s\n' '공격 로그: bash integration/run-with-skeleton.sh <스켈레톤-루트> --logs'
printf '%s\n' '방어 로그: bash integration/run-with-skeleton.sh <스켈레톤-루트> --logs-defender'
printf '%s\n' '정리: bash integration/run-with-skeleton.sh <스켈레톤-루트> --down'
