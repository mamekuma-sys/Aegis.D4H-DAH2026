<#
.SYNOPSIS
  Run an attacker and defender image pair on the external official skeleton.

.DESCRIPTION
  Merge an image-only override without modifying the official docker-compose.yml.
  --no-build prevents source contexts from being built. Use the official UI/control
  contract to start rounds and export scores.
#>
param(
    [Parameter(Mandatory = $true)][string]$SkeletonPath,
    [Parameter(Mandatory = $true)][string]$AttackerImage,
    [Parameter(Mandatory = $true)][string]$DefenderImage,
    [switch]$ConfigOnly,
    [switch]$ReapplyAgents,
    [switch]$Logs,
    [switch]$Down
)

$ErrorActionPreference = 'Stop'
$compose = Join-Path $SkeletonPath 'deploy/docker-compose.yml'
$override = Join-Path $PSScriptRoot 'compose.images.yml'
if (-not (Test-Path -LiteralPath $compose -PathType Leaf)) { throw "Official compose not found: $compose" }
if (-not (Test-Path -LiteralPath $override -PathType Leaf)) { throw "Scrimmage override not found: $override" }
if ([string]::IsNullOrWhiteSpace($AttackerImage) -or [string]::IsNullOrWhiteSpace($DefenderImage)) {
    throw 'Both attacker and defender image tags or digests are required'
}

$env:AEGIS_SCRIMMAGE_ATTACKER_IMAGE = $AttackerImage
$env:AEGIS_SCRIMMAGE_DEFENDER_IMAGE = $DefenderImage

function Invoke-ScrimmageCompose([string[]]$ComposeArgs) {
    & docker compose --progress quiet -f $compose -f $override --profile combat @ComposeArgs
    if ($LASTEXITCODE -ne 0) { throw "docker compose failed: $($ComposeArgs -join ' ')" }
}

function Get-ScrimmageConfig {
    $raw = & docker compose --progress quiet -f $compose -f $override --profile combat config --format json
    if ($LASTEXITCODE -ne 0) { throw 'docker compose config failed' }
    return ($raw | ConvertFrom-Json)
}

function Assert-ServiceImage([string]$ServiceName, [string]$ExpectedImage) {
    $config = Get-ScrimmageConfig
    $property = $config.services.psobject.Properties[$ServiceName]
    if ($null -eq $property) { throw "Merged compose does not contain $ServiceName" }
    $service = $property.Value
    if ([string]$service.image -ne $ExpectedImage) {
        throw "$ServiceName image mismatch: $($service.image)"
    }
    if ([string]$service.platform -ne 'linux/amd64') {
        throw "$ServiceName platform is not linux/amd64"
    }
    Write-Host "$ServiceName.image=$($service.image)"
}

Assert-ServiceImage 'team1-attacker' $AttackerImage
Assert-ServiceImage 'team1-defender' $DefenderImage

if ($ConfigOnly) { return }
if ($Down) {
    Invoke-ScrimmageCompose @('down')
    return
}
if ($Logs) {
    Invoke-ScrimmageCompose @('logs', '-f', 'team1-attacker', 'team1-defender')
    return
}
if ($ReapplyAgents) {
    Invoke-ScrimmageCompose @('up', '-d', '--no-deps', '--no-build', '--force-recreate', 'team1-attacker', 'team1-defender')
    return
}

Invoke-ScrimmageCompose @('up', '-d', '--no-build')
Write-Host 'Scrimmage infrastructure is running. Start the round through the official UI/control interface.'
Write-Host 'If round start recreates agent containers, run the same command with -ReapplyAgents.'
