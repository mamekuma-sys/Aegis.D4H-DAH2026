#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"

fail() {
    printf 'ERROR: %s\n' "$1" >&2
    exit 1
}

required_files=(
    '.gitattributes'
    '.gitignore'
    '.env.example'
    '.github/workflows/ci.yml'
    '.github/pull_request_template.md'
    'AGENTS.md'
    'CONTRIBUTING.md'
    'README.md'
    'agents/README.md'
    'agents/attacker/README.md'
    'agents/attacker/src/aegis_attacker/.gitkeep'
    'agents/attacker/tests/.gitkeep'
    'agents/defender/README.md'
    'agents/defender/src/aegis_defender/.gitkeep'
    'agents/defender/tests/.gitkeep'
    'contracts/README.md'
    'contracts/attacker/README.md'
    'contracts/defender/README.md'
    'contracts/llm/README.md'
    'contracts/llm/model-quotas.json'
    'contracts/break-copilot/readiness.schema.json'
    'contracts/break-copilot/approval.schema.json'
    'contracts/break-copilot/combined-rubric.schema.json'
    'contracts/break-copilot/manifest.schema.json'
    'contracts/break-copilot/evaluation.schema.json'
    'contracts/break-copilot/scrimmage.schema.json'
    'contracts/fixtures/README.md'
    'docs/architecture.md'
    'docs/development-setup.md'
    'docs/decisions/0001-external-skeleton.md'
    'docs/meeting-notes/.gitkeep'
    'docs/ownership.md'
    'docs/references/README.md'
    'docs/references/source-inventory.md'
    'docs/references/rules-checklist.md'
    'docs/references/preliminary-code-map.md'
    'integration/README.md'
    'research/preliminary-strategy.md'
    'research/attack-scenarios.md'
    'research/defense-mapping.md'
    'scripts/check-layout.sh'
    'scripts/replay-defender-pcaps.sh'
    'scripts/break-copilot.ps1'
    'scripts/break-copilot.zsh'
    'scripts/macos-preflight.zsh'
    'scripts/break_copilot/__main__.py'
    'scripts/break_copilot/cli.py'
    'scripts/validate-skeleton.sh'
    'scripts/validate-skeleton.ps1'
    'scripts/tests/test-shell-entrypoints.sh'
    'scripts/tests/test-validate-skeleton.ps1'
    'scripts/tests/test-compose-agents-override.ps1'
    'scripts/tests/test-break-copilot-powershell.ps1'
    'scripts/tests/test-macos-entrypoints.zsh'
    'integration/compose.agents.yml'
    'integration/run-with-skeleton.sh'
    'integration/run-with-skeleton.ps1'
    'integration/attacker-deploy.md'
    'integration/defender-deploy.md'
    'integration/promote-candidate.ps1'
    'integration/promote-candidate.zsh'
    'integration/scrimmage/compose.images.yml'
    'integration/scrimmage/run-scrimmage.ps1'
    'integration/scrimmage/run-scrimmage.zsh'
    'integration/scrimmage/compare_results.py'
    'docs/validation/break-copilot-protocol.md'
    'docs/validation/readiness-rubric.md'
    'docs/validation/scrimmage-protocol.md'
    'docs/validation/macos-finals-runbook.md'
)

missing=()
for relative_path in "${required_files[@]}"; do
    [[ -f "$repo_root/$relative_path" ]] || missing+=("$relative_path")
done
if (( ${#missing[@]} > 0 )); then
    printf 'ERROR: Missing repository files:\n' >&2
    printf -- '- %s\n' "${missing[@]}" >&2
    exit 1
fi

for relative_path in deploy tmp output __pycache__; do
    [[ ! -e "$repo_root/$relative_path" ]] \
        || fail "Forbidden repository path exists: $relative_path"
done

tracked_artifacts=()
path_leaks=()
slash='/'
mac_segment='Users'
linux_segment='home'
mac_home_pattern="${slash}${mac_segment}${slash}[^${slash}[:space:]]+${slash}"
linux_home_pattern="${slash}${linux_segment}${slash}[^${slash}[:space:]]+${slash}"
windows_home_pattern='[A-Z]:\\Users\\[^\\[:space:]]+\\'

while IFS= read -r -d '' relative_path; do
    basename="${relative_path##*/}"
    case "$relative_path" in
        *.pdf|*.zip|*.tar|*.gz|*.pcap|*.pcapng|*.log|capture/*|captures/*|log/*|logs/*|output/*|tmp/*)
            tracked_artifacts+=("$relative_path")
            ;;
    esac
    case "$basename" in
        'DAH2026_본선_당일_진행_안내.md'|'DAH2026_스켈레톤코드_상세_설명.md')
            tracked_artifacts+=("$relative_path")
            ;;
    esac

    case "$relative_path" in
        *.md|*.ps1|*.py|*.yml|*.yaml|*.json|*.toml|*.txt|*.example)
            if LC_ALL=C grep -Eiq \
                    "${windows_home_pattern}|${mac_home_pattern}|${linux_home_pattern}" \
                    "$repo_root/$relative_path"; then
                path_leaks+=("$relative_path")
            fi
            ;;
    esac
done < <(git -C "$repo_root" -c core.quotePath=false ls-files -z)

if (( ${#tracked_artifacts[@]} > 0 )); then
    printf 'ERROR: Raw or generated artifacts are tracked:\n' >&2
    printf -- '- %s\n' "${tracked_artifacts[@]}" | sort -u >&2
    exit 1
fi

if (( ${#path_leaks[@]} > 0 )); then
    printf 'ERROR: User-specific absolute paths found:\n' >&2
    printf -- '- %s\n' "${path_leaks[@]}" | sort -u >&2
    exit 1
fi

printf '%s\n' 'Repository layout check passed.'
