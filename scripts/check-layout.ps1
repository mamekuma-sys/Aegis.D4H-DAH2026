$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot

$requiredFiles = @(
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

$missing = @()
foreach ($relativePath in $requiredFiles) {
    $fullPath = Join-Path $repoRoot $relativePath
    if (-not (Test-Path -LiteralPath $fullPath -PathType Leaf)) {
        $missing += $relativePath
    }
}

if ($missing.Count -gt 0) {
    Write-Error ("Missing repository files:`n- " + ($missing -join "`n- "))
    exit 1
}

$forbiddenDirectories = @('deploy', 'tmp', 'output', '__pycache__')
foreach ($relativePath in $forbiddenDirectories) {
    $fullPath = Join-Path $repoRoot $relativePath
    if (Test-Path -LiteralPath $fullPath) {
        Write-Error "Forbidden repository path exists: $relativePath"
        exit 1
    }
}

$portableTextExtensions = @('.md', '.ps1', '.py', '.yml', '.yaml', '.json', '.toml', '.txt', '.example')
$escapedBackslash = [regex]::Escape([string][char]92)
$escapedSlash = [regex]::Escape([string][char]47)
$forbiddenHomePatterns = @(
    "(?i)[A-Z]:${escapedBackslash}Users${escapedBackslash}[^${escapedBackslash}\r\n]+${escapedBackslash}"
    "${escapedSlash}Users${escapedSlash}[^${escapedSlash}\s]+${escapedSlash}"
    "${escapedSlash}home${escapedSlash}[^${escapedSlash}\s]+${escapedSlash}"
)

$pathLeaks = @()
$trackedFiles = git -C $repoRoot -c core.quotePath=false ls-files
$forbiddenTrackedExtensions = @('.pdf', '.zip', '.tar', '.gz', '.pcap', '.pcapng', '.log')
$forbiddenTrackedBasenames = @(
    'DAH2026_본선_당일_진행_안내.md',
    'DAH2026_스켈레톤코드_상세_설명.md'
)
$trackedArtifacts = @()
foreach ($relativePath in $trackedFiles) {
    $normalizedPath = $relativePath -replace '\\', '/'
    $extension = [System.IO.Path]::GetExtension($relativePath).ToLowerInvariant()
    $basename = [System.IO.Path]::GetFileName($relativePath)
    if (($forbiddenTrackedExtensions -contains $extension) -or
        ($forbiddenTrackedBasenames -contains $basename) -or
        ($normalizedPath -match '^(capture|captures|log|logs|output|tmp)/')) {
        $trackedArtifacts += $relativePath
    }
}

if ($trackedArtifacts.Count -gt 0) {
    Write-Error ("Raw or generated artifacts are tracked:`n- " + (($trackedArtifacts | Sort-Object -Unique) -join "`n- "))
    exit 1
}

foreach ($relativePath in $trackedFiles) {
    $extension = [System.IO.Path]::GetExtension($relativePath)
    if ($portableTextExtensions -notcontains $extension) {
        continue
    }

    $fullPath = Join-Path $repoRoot $relativePath
    $content = [System.IO.File]::ReadAllText($fullPath)
    foreach ($pattern in $forbiddenHomePatterns) {
        if ($content -match $pattern) {
            $pathLeaks += $relativePath
            break
        }
    }
}

if ($pathLeaks.Count -gt 0) {
    Write-Error ("User-specific absolute paths found:`n- " + (($pathLeaks | Sort-Object -Unique) -join "`n- "))
    exit 1
}

Write-Output 'Repository layout check passed.'
