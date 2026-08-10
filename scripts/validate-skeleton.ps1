param(
    [Parameter(Mandatory = $true)]
    [string]$SkeletonPath
)

$ErrorActionPreference = 'Stop'
$resolvedSkeleton = (Resolve-Path -LiteralPath $SkeletonPath).Path

$requiredPaths = @(
    'deploy/docker-compose.yml'
    'deploy/docs/agent-guide.md'
    'deploy/agents/team1/attacker/Dockerfile'
    'deploy/agents/team1/defender/Dockerfile'
    'deploy/router/broker'
)

$missing = @()
foreach ($relativePath in $requiredPaths) {
    $fullPath = Join-Path $resolvedSkeleton $relativePath
    if (-not (Test-Path -LiteralPath $fullPath -PathType Leaf)) {
        $missing += $relativePath
    }
}

if ($missing.Count -gt 0) {
    Write-Error ("Invalid DAH skeleton. Missing:`n- " + ($missing -join "`n- "))
    exit 1
}

Write-Output "Validated DAH skeleton: $resolvedSkeleton"
