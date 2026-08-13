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
    'scripts/validate-skeleton.ps1'
    'scripts/tests/test-validate-skeleton.ps1'
    'scripts/tests/test-compose-agents-override.ps1'
    'integration/compose.agents.yml'
    'integration/run-with-skeleton.ps1'
    'integration/attacker-deploy.md'
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
$forbiddenTrackedExtensions = @('.pdf', '.zip', '.tar', '.gz', '.pcap', '.pcapng')
$forbiddenTrackedBasenames = @(
    'DAH2026_본선_당일_진행_안내.md',
    'DAH2026_스켈레톤코드_상세_설명.md'
)
$trackedArtifacts = @()
foreach ($relativePath in $trackedFiles) {
    $extension = [System.IO.Path]::GetExtension($relativePath).ToLowerInvariant()
    $basename = [System.IO.Path]::GetFileName($relativePath)
    if (($forbiddenTrackedExtensions -contains $extension) -or
        ($forbiddenTrackedBasenames -contains $basename)) {
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
