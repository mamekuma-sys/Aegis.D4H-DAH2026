$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot

$requiredFiles = @(
    '.gitattributes'
    '.gitignore'
    '.env.example'
    '.github/workflows/ci.yml'
    'AGENTS.md'
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
    'contracts/fixtures/README.md'
    'docs/architecture.md'
    'docs/development-setup.md'
    'docs/decisions/0001-external-skeleton.md'
    'docs/meeting-notes/.gitkeep'
    'docs/ownership.md'
    'integration/README.md'
    'research/preliminary-strategy.md'
    'research/attack-scenarios.md'
    'research/defense-mapping.md'
    'scripts/validate-skeleton.ps1'
    'scripts/tests/test-validate-skeleton.ps1'
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

Write-Output 'Repository layout check passed.'
