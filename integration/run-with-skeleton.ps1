<#
.SYNOPSIS
  스켈레톤 데모 위에서 팀 공격 이미지(team1-attacker)를 교체 실행한다.

.DESCRIPTION
  공식 스켈레톤 docker-compose.yml 과 integration/compose.agents.yml override를 함께 적용해,
  team1-attacker 만 팀 저장소의 aegis_attacker 패키지로 빌드·기동한다. 공식 파일은 수정하지 않는다.
  개인 절대경로는 저장소에 기록하지 않으므로 스켈레톤 루트를 인자로 전달한다.

  병합 Compose의 상대경로는 첫 번째 -f 파일 기준이므로, 빌드 컨텍스트는
  AEGIS_ATTACKER_CONTEXT 환경변수로 저장소 agents/attacker 절대경로를 주입한다.

.PARAMETER SkeletonPath
  공식 스켈레톤 루트(=deploy/ 의 부모).

.PARAMETER Down
  combat 프로필 스택을 종료한다. named volume은 유지하며 -v 를 쓰지 않는다.

.PARAMETER ConfigOnly
  up 하지 않고 병합 Compose를 검증한 뒤 team1-attacker.build.context 를 출력한다.

.PARAMETER Logs
  team1-attacker 로그를 follow한다.

.EXAMPLE
  pwsh -File integration/run-with-skeleton.ps1 -SkeletonPath <스켈레톤-루트>
#>
param(
    [Parameter(Mandatory = $true)][string]$SkeletonPath,
    [switch]$Down,
    [switch]$ConfigOnly,
    [switch]$Logs
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

if (-not (Test-Path -LiteralPath $compose -PathType Leaf)) { throw "스켈레톤 compose 없음: $compose" }
if (-not (Test-Path -LiteralPath $override -PathType Leaf)) { throw "override 없음: $override" }
if (-not (Test-Path -LiteralPath (Join-Path $attackerDir "Dockerfile") -PathType Leaf)) {
    throw "저장소 공격 Dockerfile 없음: $attackerDir"
}

$env:AEGIS_ATTACKER_CONTEXT = ConvertTo-ForwardSlashPath ((Resolve-Path -LiteralPath $attackerDir).Path)
$expectedContext = $env:AEGIS_ATTACKER_CONTEXT
$wrongSkeletonContext = ConvertTo-ForwardSlashPath (
    [System.IO.Path]::GetFullPath((Join-Path $SkeletonPath "agents/attacker"))
)

function Invoke-AgentCompose([string[]]$ComposeArgs) {
    & docker compose --progress quiet -f $compose -f $override --profile combat @ComposeArgs
    if ($LASTEXITCODE -ne 0) {
        throw "docker compose failed: $($ComposeArgs -join ' ')"
    }
}

function Get-Team1AttackerBuildContext {
    $raw = & docker compose --progress quiet -f $compose -f $override --profile combat config --format json
    if ($LASTEXITCODE -ne 0) {
        throw "docker compose config failed"
    }
    $cfg = $raw | ConvertFrom-Json
    $context = $cfg.services.'team1-attacker'.build.context
    if ([string]::IsNullOrWhiteSpace($context)) {
        throw "merged compose has empty team1-attacker.build.context"
    }
    return [string]$context
}

function Assert-Team1AttackerBuildContext {
    $actual = Get-Team1AttackerBuildContext
    $actualNorm = (ConvertFrom-ComposeContext $actual).ToLowerInvariant()
    $expectedNorm = $expectedContext.ToLowerInvariant()
    $wrongNorm = $wrongSkeletonContext.ToLowerInvariant()
    $relative = ($actual -replace '\\', '/').Trim()

    if ($relative -eq '../agents/attacker' -or $relative -eq '../agents/attacker/') {
        throw "team1-attacker.build.context is still relative: $actual"
    }
    if ($actualNorm -eq $wrongNorm) {
        throw "team1-attacker.build.context points at the skeleton, not the repo: $actual"
    }
    if ($actualNorm -ne $expectedNorm -and -not $actualNorm.EndsWith('/agents/attacker')) {
        throw "team1-attacker.build.context is '$actual', expected repo path '$expectedContext'"
    }
    Write-Host "team1-attacker.build.context=$actual"
}

if ($Down) {
    Invoke-AgentCompose @('down')
    return
}

Assert-Team1AttackerBuildContext

if ($ConfigOnly) {
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
Write-Host "→ 정리:       pwsh -File integration/run-with-skeleton.ps1 -SkeletonPath <스켈레톤-루트> -Down"
