$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$files = @(
    'scripts/break-copilot.ps1'
    'integration/promote-candidate.ps1'
    'integration/scrimmage/run-scrimmage.ps1'
)

foreach ($relativePath in $files) {
    $tokens = $null
    $errors = $null
    $fullPath = Join-Path $repoRoot $relativePath
    [void][System.Management.Automation.Language.Parser]::ParseFile(
        $fullPath,
        [ref]$tokens,
        [ref]$errors
    )
    if ($errors.Count -gt 0) {
        throw "PowerShell parse failed for $relativePath`: $($errors[0].Message)"
    }
}

$composePath = Join-Path $repoRoot 'integration/scrimmage/compose.images.yml'
$compose = Get-Content -LiteralPath $composePath -Raw
foreach ($forbiddenKey in @('build:', 'environment:', 'volumes:', 'command:', 'entrypoint:', 'privileged:')) {
    if ($compose -match "(?m)^\s+$([regex]::Escape($forbiddenKey))") {
        throw "Scrimmage image override must not set $forbiddenKey"
    }
}

Write-Output 'test-break-copilot-powershell.ps1 passed'
