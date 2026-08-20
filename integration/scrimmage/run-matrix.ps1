[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$SkeletonPath,
    [string[]]$Seeds = @('1', '2', '3'),
    [ValidateRange(10, 1200)][int]$RoundSeconds = 30,
    [ValidateRange(1, 100)][int]$SamplesPerRoute = 5,
    [string]$OutputRoot = ''
)

$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$seedModule = Join-Path $here 'SeedArguments.psm1'
Import-Module $seedModule -Force
$runner = Join-Path $here 'run-match.ps1'
if (-not (Test-Path -LiteralPath $runner -PathType Leaf)) {
    throw "match runner missing: $runner"
}
$Seeds = @(ConvertFrom-ScrimmageSeedArguments -SeedArguments $Seeds -Label 'Seeds')
if ([string]::IsNullOrWhiteSpace($OutputRoot)) {
    $batch = 'matrix-{0}' -f ([DateTime]::UtcNow.ToString('yyyyMMddTHHmmssZ'))
    $OutputRoot = Join-Path (Join-Path ([IO.Path]::GetTempPath()) 'Aegis.D4H-scrimmage') $batch
}
New-Item -ItemType Directory -Force -Path $OutputRoot | Out-Null

$entries = @()
foreach ($matrix in @('A0D0', 'A1D0', 'A0D1', 'A1D1')) {
    foreach ($seed in $Seeds) {
        Write-Output "running=$matrix seed=$seed"
        $lines = @(& $runner -SkeletonPath $SkeletonPath -Matrix $matrix -Seed $seed `
            -RoundSeconds $RoundSeconds -SamplesPerRoute $SamplesPerRoute `
            -OutputRoot $OutputRoot)
        $resultLine = @($lines | Where-Object { $_ -like 'result=*' } | Select-Object -Last 1)
        $hashLine = @($lines | Where-Object { $_ -like 'sha256=*' } | Select-Object -Last 1)
        if ($resultLine.Count -ne 1 -or $hashLine.Count -ne 1) {
            throw "runner did not report a result for $matrix seed $seed"
        }
        $resultPath = ([string]$resultLine[0]).Substring(7)
        $hash = ([string]$hashLine[0]).Substring(7)
        $entries += [ordered]@{
            evidence_id = "MATCH-$matrix-S$seed"
            matrix = $matrix
            seed = $seed
            result = [IO.Path]::GetRelativePath($OutputRoot, $resultPath).Replace('\', '/')
            sha256 = $hash
        }
    }
}

$index = [ordered]@{
    schema_version = 1
    score_name = 'SCRIMMAGE_PROXY'
    seeds = @($Seeds)
    matches = $entries
}
$indexPath = Join-Path $OutputRoot 'matrix-index.json'
$index | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $indexPath -Encoding utf8NoBOM
$indexHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $indexPath).Hash.ToLowerInvariant()
Write-Output "index=$indexPath"
Write-Output "sha256=$indexHash"
