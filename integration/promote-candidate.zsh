#!/bin/zsh
set -eu
set -o pipefail

usage() {
    print -u2 'Usage: zsh integration/promote-candidate.zsh --candidate <path> --evaluation <json> --rubric <json> --approval <json> --agent <attacker|defender> --team-number <N> [--push]'
    exit 2
}

candidate=''
evaluation=''
rubric=''
approval=''
agent=''
team_number=''
push_image=0
while (( $# > 0 )); do
    case "$1" in
        --candidate|--evaluation|--rubric|--approval|--agent|--team-number)
            (( $# >= 2 )) || usage
            case "$1" in
                --candidate) candidate="$2" ;;
                --evaluation) evaluation="$2" ;;
                --rubric) rubric="$2" ;;
                --approval) approval="$2" ;;
                --agent) agent="$2" ;;
                --team-number) team_number="$2" ;;
            esac
            shift 2
            ;;
        --push)
            push_image=1
            shift
            ;;
        *)
            usage
            ;;
    esac
done

[[ -n "$candidate" && -n "$evaluation" && -n "$rubric" && -n "$approval" ]] || usage
[[ "$agent" == 'attacker' || "$agent" == 'defender' ]] || usage
case "$team_number" in
    ''|*[!0-9]*) usage ;;
esac
(( team_number >= 1 && team_number <= 999 )) || usage

for path in "$candidate" "$evaluation" "$rubric" "$approval"; do
    [[ -e "$path" ]] || { print -u2 "ERROR: Required path not found: $path"; exit 1; }
done

script_dir="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)"
repo_root="$(CDPATH= cd -- "$script_dir/.." && pwd -P)"
candidate="$(CDPATH= cd -- "$candidate" && pwd -P)"
absolute_file() {
    local directory base
    directory="$(dirname -- "$1")"
    base="$(basename -- "$1")"
    printf '%s/%s\n' "$(CDPATH= cd -- "$directory" && pwd -P)" "$base"
}
evaluation="$(absolute_file "$evaluation")"
rubric="$(absolute_file "$rubric")"
approval="$(absolute_file "$approval")"

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

(
    cd "$repo_root"
    "$python_cmd" -B -m scripts.break_copilot verify-approval \
        --candidate "$candidate" --evaluation "$evaluation" \
        --rubric "$rubric" --approval "$approval" --side "$agent"
)

commit="$(git -C "$candidate" rev-parse HEAD)"
printf '%s' "$commit" | grep -Eq '^[0-9a-f]{40}$' \
    || { print -u2 'ERROR: Candidate commit verification failed.'; exit 1; }
[[ -z "$(git -C "$candidate" status --porcelain)" ]] \
    || { print -u2 'ERROR: Candidate worktree is not clean.'; exit 1; }

(
    cd "$candidate"
    bash scripts/build-images.sh
)

short_commit="${commit[1,12]}"
local_image="aegis/${agent}:verify-${short_commit}"
platform="$(docker image inspect "$local_image" --format '{{.Os}}/{{.Architecture}}')"
[[ "$platform" == 'linux/amd64' ]] \
    || { print -u2 "ERROR: Verified image platform mismatch: $platform"; exit 1; }

registry_image="ligacr.azurecr.io/team${team_number}/${agent}:latest"
printf 'Approved local image: %s\n' "$local_image"
if (( ! push_image )); then
    print 'Registry was not changed. Add --push to the same command to publish latest.'
    exit 0
fi

docker tag "$local_image" "$registry_image"
docker push "$registry_image"
printf 'Pushed %s\n' "$registry_image"
docker image inspect "$registry_image" --format '{{join .RepoDigests "\n"}}'
