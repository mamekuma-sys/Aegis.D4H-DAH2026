[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$ResultRoot,
    [int[]]$ExpectedSeeds = @(1, 2, 3),
    [string]$HumanScoreFile = 'PENDING',
    [string]$OutputPath = ''
)

$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = Split-Path -Parent (Split-Path -Parent $here)
$resultSchemaPath = Join-Path $repoRoot 'contracts/scrimmage/match-result.schema.json'
if (-not (Test-Path -LiteralPath $resultSchemaPath -PathType Leaf)) {
    throw "result schema missing: $resultSchemaPath"
}
$matrices = @('A0D0', 'A1D0', 'A0D1', 'A1D1')
$forbidden = @('FLAG{', 'tok-team', 'sk-local', 'SUBMIT_TOKEN', 'LLM_API_KEY')
$files = @(Get-ChildItem -LiteralPath $ResultRoot -Recurse -Filter result.json -File)
if ($files.Count -eq 0) { throw 'no result.json files found' }

function Get-NumericProperty($value, [string]$name) {
    if ($null -eq $value) { return $null }
    $property = $value.PSObject.Properties[$name]
    if ($null -eq $property -or $null -eq $property.Value) { return $null }
    try { return [double]$property.Value } catch { return $null }
}

$records = @()
$integrityOk = $true
foreach ($file in $files) {
    $raw = Get-Content -Raw -LiteralPath $file.FullName
    foreach ($needle in $forbidden) {
        if ($raw.Contains($needle)) { $integrityOk = $false }
    }
    if (-not ($raw | Test-Json -SchemaFile $resultSchemaPath)) {
        $integrityOk = $false
    }
    try { $result = $raw | ConvertFrom-Json -ErrorAction Stop } catch {
        $integrityOk = $false
        continue
    }
    $records += [ordered]@{
        evidence_id = "MATCH-$($result.matrix)-S$($result.seed)"
        sha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $file.FullName).Hash.ToLowerInvariant()
        result = $result
    }
}

$coverageOk = $true
foreach ($matrix in $matrices) {
    foreach ($seed in $ExpectedSeeds) {
        if (@($records | Where-Object {
            $_.result.matrix -eq $matrix -and [int]$_.result.seed -eq $seed
        }).Count -ne 1) { $coverageOk = $false }
    }
}
if ($records.Count -ne ($matrices.Count * $ExpectedSeeds.Count)) { $coverageOk = $false }

$scopeOk = $records.Count -gt 0
$interfaceOk = $records.Count -gt 0
$isolationOk = $records.Count -gt 0
foreach ($record in $records) {
    $result = $record.result
    if ($result.score_name -ne 'SCRIMMAGE_PROXY' -or
        -not [bool]$result.environment_checks.agent_networks_internal) { $scopeOk = $false }
    if ([bool]$result.secret_leak_detected -or
        [bool]$result.environment_checks.raw_artifacts_exported) { $integrityOk = $false }
    if (-not [bool]$result.environment_checks.frozen_images_verified -or
        $result.images.attacker.platform -ne 'linux/amd64' -or
        $result.images.defender.platform -ne 'linux/amd64') { $interfaceOk = $false }
    foreach ($service in @('team1-attacker', 'team1-defender', 'team2-attacker', 'team2-defender')) {
        if ([bool]$result.agent_summaries.$service.missing -or
            $null -eq $result.agent_summaries.$service.events.startup) { $interfaceOk = $false }
    }
    if (-not [bool]$result.environment_checks.fresh_containers -or
        -not [bool]$result.environment_checks.agent_networks_internal -or
        -not [bool]$result.environment_checks.llm_keys_blank) { $isolationOk = $false }
}

$defenseOk = $true
$candidateDefense = @($records | Where-Object { $_.result.matrix -in @('A0D1', 'A1D1') })
if ($candidateDefense.Count -eq 0) { $defenseOk = $false }
foreach ($record in $candidateDefense) {
    foreach ($service in @('team1-defender', 'team2-defender')) {
        $summary = $record.result.agent_summaries.$service.shutdown_metrics
        $count = Get-NumericProperty $summary.verdict_send_e2e 'count'
        $maxUs = Get-NumericProperty $summary.verdict_send_e2e 'max_us'
        $heartbeats = Get-NumericProperty $summary 'heartbeats'
        $expired = Get-NumericProperty $summary.counters 'heartbeat.expired'
        $workerUnhealthy = Get-NumericProperty $summary.counters 'worker.unhealthy'
        if ($null -eq $count -or $count -lt 1 -or $null -eq $maxUs -or $maxUs -gt 300000 -or
            $null -eq $heartbeats -or $heartbeats -lt 1 -or
            ($null -ne $expired -and $expired -gt 0) -or
            ($null -ne $workerUnhealthy -and $workerUnhealthy -gt 0)) { $defenseOk = $false }
    }
    foreach ($team in @('1', '2')) {
        if ([int]$record.result.router_metrics.$team.gc_dropped -ne 0) { $defenseOk = $false }
    }
}

$gates = [ordered]@{
    rules_and_scope = $(if ($scopeOk) { 'PASS' } else { 'FAIL' })
    evidence_integrity = $(if ($integrityOk -and $coverageOk) { 'PASS' } else { 'FAIL' })
    official_interface_proxy = $(if ($interfaceOk) { 'PASS' } else { 'FAIL' })
    defense_300ms_heartbeat_reconnect = $(if ($defenseOk) { 'PASS' } else { 'FAIL' })
    isolation_and_reproducibility = $(if ($isolationOk -and $coverageOk) { 'PASS' } else { 'FAIL' })
}

$areas = [ordered]@{
    evidence_traceability = @{ weight = 15; ai = $(if ($coverageOk -and $integrityOk) { 2 } else { 1 }) }
    attack_effectiveness = @{ weight = 20; ai = $(if (@($records | Where-Object { @($_.result.captures).Count -gt 0 }).Count) { 2 } else { 1 }) }
    defense_effect_availability = @{ weight = 25; ai = $(if ($defenseOk) { 2 } else { 1 }) }
    generalization_adaptability = @{ weight = 15; ai = $(if ($coverageOk -and $ExpectedSeeds.Count -ge 3) { 2 } else { 1 }) }
    performance_resilience = @{ weight = 15; ai = $(if ($defenseOk) { 2 } else { 1 }) }
    operational_reproducibility = @{ weight = 5; ai = $(if ($isolationOk -and $coverageOk) { 2 } else { 1 }) }
    llm_cost_observability = @{ weight = 5; ai = $(if ($isolationOk -and $integrityOk) { 2 } else { 1 }) }
}

$humanPending = $HumanScoreFile -eq 'PENDING' -or -not (Test-Path -LiteralPath $HumanScoreFile -PathType Leaf)
$human = $null
if (-not $humanPending) { $human = Get-Content -Raw -LiteralPath $HumanScoreFile | ConvertFrom-Json }
$aiTotal = 0.0
$finalTotal = 0.0
foreach ($areaName in $areas.Keys) {
    $area = $areas[$areaName]
    $aiTotal += [double]$area.weight * [double]$area.ai / 4.0
    if (-not $humanPending) {
        $humanScore = [int]$human.scores.$areaName
        $area['human'] = $humanScore
        $area['final'] = [Math]::Min([int]$area.ai, $humanScore)
        $area['arbitration'] = [Math]::Abs([int]$area.ai - $humanScore) -ge 2
        $finalTotal += [double]$area.weight * [double]$area['final'] / 4.0
    } else {
        $area['human'] = $null
        $area['final'] = $null
        $area['arbitration'] = $false
    }
}

$allGatesPass = @($gates.Values | Where-Object { $_ -ne 'PASS' }).Count -eq 0
$verdict = 'NOT_READY'
if ($allGatesPass -and -not $humanPending) {
    if ($finalTotal -ge 90) { $verdict = 'READY' }
    elseif ($finalTotal -ge 75) { $verdict = 'CONDITIONALLY_READY' }
}
$evidence = @($records | ForEach-Object {
    [ordered]@{ evidence_id = $_.evidence_id; sha256 = $_.sha256 }
})
$judgement = [ordered]@{
    schema_version = 1
    score_name = 'SCRIMMAGE_PROXY'
    verdict = $verdict
    gates = $gates
    rubric = $areas
    ai_weighted_score = [Math]::Round($aiTotal, 2)
    final_weighted_score = $(if ($humanPending) { $null } else { [Math]::Round($finalTotal, 2) })
    human_score = $(if ($humanPending) { 'PENDING' } else { 'PROVIDED' })
    evidence = $evidence
    limitations = @(
        'official final scoring is not reproduced',
        'two-team L1-L3 proxy only; L4 and blind holdout are not evaluated',
        'AI scores are capped at known-proxy evidence level'
    )
}
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $OutputPath = Join-Path $ResultRoot 'judgement.json'
}
$judgement | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $OutputPath -Encoding utf8NoBOM
Write-Output "verdict=$verdict"
Write-Output "judgement=$OutputPath"
Write-Output "sha256=$((Get-FileHash -Algorithm SHA256 -LiteralPath $OutputPath).Hash.ToLowerInvariant())"
