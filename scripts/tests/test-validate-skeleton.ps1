$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$validator = Join-Path $repoRoot 'scripts/validate-skeleton.ps1'

if (-not (Test-Path -LiteralPath $validator -PathType Leaf)) {
    Write-Error 'Validator not implemented: scripts/validate-skeleton.ps1'
    exit 1
}

$tempBase = [System.IO.Path]::GetTempPath()
$testRoot = Join-Path $tempBase ("aegis-skeleton-test-" + [guid]::NewGuid().ToString('N'))

try {
    $invalidRoot = Join-Path $testRoot 'invalid'
    New-Item -ItemType Directory -Path $invalidRoot -Force | Out-Null

    & pwsh -NoProfile -File $validator -SkeletonPath $invalidRoot *> $null
    if ($LASTEXITCODE -eq 0) {
        throw 'Validator accepted a skeleton with all required files missing.'
    }

    $validRoot = Join-Path $testRoot 'valid'
    $requiredPaths = @(
        'deploy/docker-compose.yml'
        'deploy/docs/agent-guide.md'
        'deploy/agents/team1/attacker/Dockerfile'
        'deploy/agents/team1/defender/Dockerfile'
        'deploy/router/broker'
    )

    foreach ($relativePath in $requiredPaths) {
        $fullPath = Join-Path $validRoot $relativePath
        New-Item -ItemType Directory -Path (Split-Path -Parent $fullPath) -Force | Out-Null
        New-Item -ItemType File -Path $fullPath -Force | Out-Null
    }

    $output = & pwsh -NoProfile -File $validator -SkeletonPath $validRoot
    if ($LASTEXITCODE -ne 0) {
        throw 'Validator rejected a skeleton containing every required file.'
    }
    if (($output -join "`n") -notmatch 'Validated DAH skeleton') {
        throw 'Validator success output did not identify the validated skeleton.'
    }

    Write-Output 'Skeleton validator tests passed: 2 cases.'
}
finally {
    $resolvedTemp = [System.IO.Path]::GetFullPath($tempBase)
    $resolvedTest = [System.IO.Path]::GetFullPath($testRoot)
    if ($resolvedTest.StartsWith($resolvedTemp, [System.StringComparison]::OrdinalIgnoreCase) -and
        (Test-Path -LiteralPath $resolvedTest)) {
        Remove-Item -LiteralPath $resolvedTest -Recurse -Force
    }
}
