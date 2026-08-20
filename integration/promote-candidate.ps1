<#
.SYNOPSIS
  Build and optionally push a clean candidate bound to human approval.

.DESCRIPTION
  This script does not accept or persist registry credentials. Docker login must
  already be complete. Without -Push it only builds verified linux/amd64 images.
#>
param(
    [Parameter(Mandatory = $true)][string]$CandidatePath,
    [Parameter(Mandatory = $true)][string]$EvaluationPath,
    [Parameter(Mandatory = $true)][string]$RubricPath,
    [Parameter(Mandatory = $true)][string]$ApprovalPath,
    [Parameter(Mandatory = $true)][ValidateSet('attacker', 'defender')][string]$Agent,
    [Parameter(Mandatory = $true)][ValidateRange(1, 999)][int]$TeamNumber,
    [switch]$Push
)

$ErrorActionPreference = 'Stop'
$controllerRoot = Split-Path -Parent $PSScriptRoot
$candidate = (Resolve-Path -LiteralPath $CandidatePath).Path
$evaluation = (Resolve-Path -LiteralPath $EvaluationPath).Path
$rubric = (Resolve-Path -LiteralPath $RubricPath).Path
$approval = (Resolve-Path -LiteralPath $ApprovalPath).Path

function Resolve-PythonCommand {
    if ($env:PYTHON) {
        return $env:PYTHON
    }
    $isUnix = [System.Environment]::OSVersion.Platform -eq [System.PlatformID]::Unix
    $candidates = if ($isUnix) { @('python3', 'python') } else { @('python', 'python3') }
    foreach ($candidate in $candidates) {
        if (Get-Command $candidate -ErrorAction SilentlyContinue) {
            return $candidate
        }
    }
    throw 'Python interpreter not found. Install Python 3.12+ or set PYTHON.'
}

$python = Resolve-PythonCommand

Push-Location $controllerRoot
try {
    & $python -B -m scripts.break_copilot verify-approval --candidate $candidate `
        --evaluation $evaluation --rubric $rubric --approval $approval --side $Agent
    if ($LASTEXITCODE -ne 0) { throw 'candidate approval verification failed' }
} finally {
    Pop-Location
}

$commit = (& git -C $candidate rev-parse HEAD).Trim()
if ($LASTEXITCODE -ne 0 -or $commit -notmatch '^[0-9a-f]{40}$') { throw 'Candidate commit verification failed' }
$status = & git -C $candidate status --porcelain
if ($LASTEXITCODE -ne 0 -or $status) { throw 'Candidate worktree is not clean' }

Push-Location $candidate
try {
    $gitBash = if ($env:ProgramFiles) { Join-Path $env:ProgramFiles 'Git/bin/bash.exe' } else { $null }
    $bash = if ($gitBash -and (Test-Path -LiteralPath $gitBash -PathType Leaf)) { $gitBash } else { 'bash' }
    & $bash --login scripts/build-images.sh
    if ($LASTEXITCODE -ne 0) { throw 'immutable image build failed' }
} finally {
    Pop-Location
}

$shortCommit = $commit.Substring(0, 12)
$localImage = "aegis/${Agent}:verify-${shortCommit}"
$platform = (& docker image inspect $localImage --format '{{.Os}}/{{.Architecture}}').Trim()
if ($LASTEXITCODE -ne 0 -or $platform -ne 'linux/amd64') { throw 'Verified image platform mismatch' }

$registryImage = "ligacr.azurecr.io/team${TeamNumber}/${Agent}:latest"
Write-Host "Approved local image: $localImage"
if (-not $Push) {
    Write-Host 'Registry was not changed. Add -Push to the same command to publish latest.'
    return
}

& docker tag $localImage $registryImage
if ($LASTEXITCODE -ne 0) { throw 'docker tag failed' }
& docker push $registryImage
if ($LASTEXITCODE -ne 0) { throw 'docker push failed' }
$repoDigests = & docker image inspect $registryImage --format '{{join .RepoDigests "\n"}}'
if ($LASTEXITCODE -ne 0) { throw 'pushed image digest inspect failed' }
Write-Host "Pushed $registryImage"
Write-Host $repoDigests
