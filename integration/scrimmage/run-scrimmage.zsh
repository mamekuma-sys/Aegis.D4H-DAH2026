#!/bin/zsh
set -eu
set -o pipefail

usage() {
    print -u2 'Usage: zsh integration/scrimmage/run-scrimmage.zsh --skeleton <root> --attacker-image <image> --defender-image <image> [--config-only|--reapply-agents|--logs|--down]'
    exit 2
}

skeleton_root=''
attacker_image=''
defender_image=''
action='up'
while (( $# > 0 )); do
    case "$1" in
        --skeleton)
            (( $# >= 2 )) || usage
            skeleton_root="$2"
            shift 2
            ;;
        --attacker-image)
            (( $# >= 2 )) || usage
            attacker_image="$2"
            shift 2
            ;;
        --defender-image)
            (( $# >= 2 )) || usage
            defender_image="$2"
            shift 2
            ;;
        --config-only|--reapply-agents|--logs|--down)
            [[ "$action" == 'up' ]] || usage
            action="$1"
            shift
            ;;
        *)
            usage
            ;;
    esac
done

[[ -n "$skeleton_root" && -n "$attacker_image" && -n "$defender_image" ]] || usage
[[ -d "$skeleton_root" ]] || { print -u2 "ERROR: Skeleton root does not exist: $skeleton_root"; exit 1; }

script_dir="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)"
skeleton_root="$(CDPATH= cd -- "$skeleton_root" && pwd -P)"
compose_file="$skeleton_root/deploy/docker-compose.yml"
override_file="$script_dir/compose.images.yml"
[[ -f "$compose_file" ]] || { print -u2 "ERROR: Official compose not found: $compose_file"; exit 1; }
[[ -f "$override_file" ]] || { print -u2 "ERROR: Scrimmage override not found: $override_file"; exit 1; }

if [[ -n "${PYTHON_CMD:-}" ]]; then
    python_cmd="$PYTHON_CMD"
elif [[ -n "${PYTHON:-}" ]]; then
    python_cmd="$PYTHON"
elif command -v python3 >/dev/null 2>&1; then
    python_cmd='python3'
elif command -v python >/dev/null 2>&1; then
    python_cmd='python'
else
    print -u2 'ERROR: Python interpreter not found.'
    exit 1
fi

if docker compose version >/dev/null 2>&1; then
    compose_mode='plugin'
elif command -v docker-compose >/dev/null 2>&1; then
    compose_mode='standalone'
else
    print -u2 'ERROR: Docker Compose not found.'
    exit 1
fi

export AEGIS_SCRIMMAGE_ATTACKER_IMAGE="$attacker_image"
export AEGIS_SCRIMMAGE_DEFENDER_IMAGE="$defender_image"

compose() {
    if [[ "$compose_mode" == 'plugin' ]]; then
        docker compose --progress quiet -f "$compose_file" -f "$override_file" --profile combat "$@"
    else
        docker-compose -f "$compose_file" -f "$override_file" --profile combat "$@"
    fi
}

assert_service_image() {
    local service="$1"
    local expected="$2"
    local config_json
    config_json="$(compose config --format json)"
    print -r -- "$config_json" | "$python_cmd" -c '
import json, sys
document = json.load(sys.stdin)
service, expected = sys.argv[1:]
value = document.get("services", {}).get(service)
if not isinstance(value, dict):
    raise SystemExit(f"missing service: {service}")
actual_image = value.get("image")
if actual_image != expected:
    raise SystemExit(f"{service} image mismatch: {actual_image}")
if value.get("platform") != "linux/amd64":
    raise SystemExit(f"{service} platform is not linux/amd64")
' "$service" "$expected"
    printf '%s.image=%s\n' "$service" "$expected"
}

assert_service_image 'team1-attacker' "$attacker_image"
assert_service_image 'team1-defender' "$defender_image"

case "$action" in
    --config-only)
        exit 0
        ;;
    --down)
        compose down
        exit 0
        ;;
    --logs)
        compose logs -f team1-attacker team1-defender
        exit 0
        ;;
    --reapply-agents)
        compose up -d --no-deps --no-build --force-recreate team1-attacker team1-defender
        exit 0
        ;;
esac

compose up -d --no-build
print 'Scrimmage infrastructure is running. Start the round through the official UI/control interface.'
print 'If round start recreates agent containers, rerun with --reapply-agents.'
