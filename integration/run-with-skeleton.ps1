<#
.SYNOPSIS
  스켈레톤 데모 위에서 팀 공격·방어 이미지를 교체 실행한다.

.DESCRIPTION
  공식 스켈레톤 docker-compose.yml 과 integration/compose.agents.yml override를 함께 적용해,
  team1-attacker 와 team1-defender 를 팀 저장소 패키지로 빌드·기동한다. 공식 파일은 수정하지 않는다.
  개인 절대경로는 저장소에 기록하지 않으므로 스켈레톤 루트를 인자로 전달한다.

  병합 Compose의 상대경로는 첫 번째 -f 파일 기준이므로, 빌드 컨텍스트는
  AEGIS_ATTACKER_CONTEXT 와 AEGIS_DEFENDER_CONTEXT 로 저장소 절대경로를 주입한다.

.PARAMETER SkeletonPath
  공식 스켈레톤 루트(=deploy/ 의 부모).

.PARAMETER Down
  combat 프로필 스택을 종료한다. named volume은 유지하며 -v 를 쓰지 않는다.

.PARAMETER ConfigOnly
  up 하지 않고 병합 Compose를 검증한 뒤 team1-attacker·team1-defender build.context 를 출력한다.

.PARAMETER Logs
  team1-attacker 로그를 follow한다.

.PARAMETER LogsDefender
  team1-defender 로그를 follow한다.

.EXAMPLE
  pwsh -File integration/run-with-skeleton.ps1 -SkeletonPath <스켈레톤-루트>
#>
param(
    [Parameter(Mandatory = $true)][string]$SkeletonPath,
    [switch]$Down,
    [switch]$ConfigOnly,
    [switch]$Logs,
    [switch]$LogsDefender
)

$ErrorActionPreference = "Stop"

function ConvertTo-ForwardSlashPath([string]$Path) {
    return (($Path -replace '\\', '/').TrimEnd('/'))
}

function ConvertFrom-ComposeContext([string]$Path) {
    $normalized = ConvertTo-ForwardSlashPath ($Path.Trim().Trim('"'))
    if ($normalized -match '^/run/desktop/mnt/host/([A-Za-z])/(.*)$') {
        return ('{0}:/{1}' -f $Matches[1].ToUpperInvariant(), $Matches[2])
    }
    return $normalized
}

$repoRoot = Split-Path -Parent $PSScriptRoot
$compose = Join-Path $SkeletonPath "deploy/docker-compose.yml"
$override = Join-Path $PSScriptRoot "compose.agents.yml"
$attackerDir = Join-Path $repoRoot "agents/attacker"
$defenderDir = Join-Path $repoRoot "agents/defender"

if (-not (Test-Path -LiteralPath $compose -PathType Leaf)) { throw "스켈레톤 compose 없음: $compose" }
if (-not (Test-Path -LiteralPath $override -PathType Leaf)) { throw "override 없음: $override" }
if (-not (Test-Path -LiteralPath (Join-Path $attackerDir "Dockerfile") -PathType Leaf)) {
    throw "저장소 공격 Dockerfile 없음: $attackerDir"
}
if (-not (Test-Path -LiteralPath (Join-Path $defenderDir "Dockerfile") -PathType Leaf)) {
    throw "저장소 방어 Dockerfile 없음: $defenderDir"
}

$env:AEGIS_ATTACKER_CONTEXT = ConvertTo-ForwardSlashPath ((Resolve-Path -LiteralPath $attackerDir).Path)
$env:AEGIS_DEFENDER_CONTEXT = ConvertTo-ForwardSlashPath ((Resolve-Path -LiteralPath $defenderDir).Path)

function Invoke-AgentCompose([string[]]$ComposeArgs) {
    & docker compose --progress quiet -f $compose -f $override --profile combat @ComposeArgs
    if ($LASTEXITCODE -ne 0) {
        throw "docker compose failed: $($ComposeArgs -join ' ')"
    }
}

function Get-MergedComposeConfig {
    $raw = & docker compose --progress quiet -f $compose -f $override --profile combat config --format json
    if ($LASTEXITCODE -ne 0) {
        throw "docker compose config failed"
    }
    return ($raw | ConvertFrom-Json)
}

function Assert-Team1BuildContext {
    param(
        [string]$ServiceName,
        [string]$ExpectedContext,
        [string]$SkeletonPathValue,
        [string]$RepoLeaf
    )
    $cfg = Get-MergedComposeConfig
    $service = $cfg.services.psobject.Properties[$ServiceName]
    if ($null -eq $service) {
        throw "merged compose is missing service $ServiceName"
    }
    $context = $service.Value.build.context
    if ([string]::IsNullOrWhiteSpace($context)) {
        throw "merged compose has empty $ServiceName.build.context"
    }
    $actualNorm = (ConvertFrom-ComposeContext $context).ToLowerInvariant()
    $expectedNorm = $ExpectedContext.ToLowerInvariant()
    $wrongNorm = (ConvertTo-ForwardSlashPath (
        [System.IO.Path]::GetFullPath((Join-Path $SkeletonPathValue "agents/$RepoLeaf"))
    )).ToLowerInvariant()
    $relative = ($context -replace '\\', '/').Trim()
    $relativeWrong = "../agents/$RepoLeaf"

    if ($relative -eq $relativeWrong -or $relative -eq "$relativeWrong/") {
        throw "$ServiceName.build.context is still relative: $context"
    }
    if ($actualNorm -eq $wrongNorm) {
        throw "$ServiceName.build.context points at the skeleton, not the repo: $context"
    }
    if ($actualNorm -ne $expectedNorm -and -not $actualNorm.EndsWith("/agents/$RepoLeaf")) {
        throw "$ServiceName.build.context is '$context', expected repo path '$ExpectedContext'"
    }
    Write-Host "$ServiceName.build.context=$context"
}

if ($Down) {
    Invoke-AgentCompose @('down')
    return
}

Assert-Team1BuildContext -ServiceName 'team1-attacker' -ExpectedContext $env:AEGIS_ATTACKER_CONTEXT -SkeletonPathValue $SkeletonPath -RepoLeaf 'attacker'
Assert-Team1BuildContext -ServiceName 'team1-defender' -ExpectedContext $env:AEGIS_DEFENDER_CONTEXT -SkeletonPathValue $SkeletonPath -RepoLeaf 'defender'

if ($ConfigOnly) {
    return
}

if ($LogsDefender) {
    Invoke-AgentCompose @('logs', '-f', 'team1-defender')
    return
}

if ($Logs) {
    Invoke-AgentCompose @('logs', '-f', 'team1-attacker')
    return
}

# 공/방 이미지 빌드 + 인프라 기동. LLM 키는 스켈레톤 .env(LLM_UPSTREAM_*)로 주입한다.
Invoke-AgentCompose @('up', '-d', '--build')
Write-Host "→ 운영 페이지: http://localhost:4100 (게임 길이 설정 후 시작)"
Write-Host "→ 공격 로그:  pwsh -File integration/run-with-skeleton.ps1 -SkeletonPath <스켈레톤-루트> -Logs"
Write-Host "→ 방어 로그:  pwsh -File integration/run-with-skeleton.ps1 -SkeletonPath <스켈레톤-루트> -LogsDefender"
Write-Host "→ 정리:       pwsh -File integration/run-with-skeleton.ps1 -SkeletonPath <스켈레톤-루트> -Down"
