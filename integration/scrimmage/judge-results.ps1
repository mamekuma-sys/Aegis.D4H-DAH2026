[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$ResultRoot,
    [string[]]$ExpectedSeeds = @('1', '2', '3'),
    [string]$HumanScoreFile = 'PENDING',
    [string]$OutputPath = ''
)

$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$seedModule = Join-Path $here 'SeedArguments.psm1'
Import-Module $seedModule -Force
$ExpectedSeeds = @(
    ConvertFrom-ScrimmageSeedArguments -SeedArguments $ExpectedSeeds -Label 'ExpectedSeeds'
)
$repoRoot = Split-Path -Parent (Split-Path -Parent $here)
$resultSchemaPath = Join-Path $repoRoot 'contracts/scrimmage/match-result.schema.json'
$humanScoreSchemaPath = Join-Path $repoRoot 'contracts/scrimmage/human-score.schema.json'
if (-not (Test-Path -LiteralPath $resultSchemaPath -PathType Leaf)) {
    throw "result schema missing: $resultSchemaPath"
}
if (-not (Test-Path -LiteralPath $humanScoreSchemaPath -PathType Leaf)) {
    throw "human score schema missing: $humanScoreSchemaPath"
}
$matrices = @('A0D0', 'A1D0', 'A0D1', 'A1D1')
$forbidden = @('FLAG{', 'tok-team', 'sk-local', 'SUBMIT_TOKEN', 'LLM_API_KEY')
$files = @(Get-ChildItem -LiteralPath $ResultRoot -Recurse -Filter result.json -File |
    Sort-Object FullName)
if ($files.Count -eq 0) { throw 'no result.json files found' }

function Get-NumericProperty($value, [string]$name) {
    if ($null -eq $value) { return $null }
    $property = $value.PSObject.Properties[$name]
    if ($null -eq $property -or $null -eq $property.Value) { return $null }
    try { return [double]$property.Value } catch { return $null }
}

function Get-Median($values) {
    $ordered = @($values | Where-Object { $null -ne $_ } | ForEach-Object {
        [double]$_
    } | Sort-Object)
    if ($ordered.Count -eq 0) { return $null }
    $middle = [int][Math]::Floor($ordered.Count / 2)
    if ($ordered.Count % 2 -eq 1) { return $ordered[$middle] }
    return ($ordered[$middle - 1] + $ordered[$middle]) / 2.0
}

function Get-EventUnixMs($summary, [string]$eventName) {
    if ($null -eq $summary) { return $null }
    $startedProperty = $summary.PSObject.Properties['container_started_unix_ms']
    if ($null -eq $startedProperty -or $null -eq $startedProperty.Value) { return $null }
    $offset = Get-NumericProperty $summary.event_first_offset_ms $eventName
    if ($null -eq $offset) { return $null }
    return [double]$startedProperty.Value + [double]$offset
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

$seedResults = @()
foreach ($record in $records) {
    $result = $record.result
    $e2eValues = @()
    $defenderCalls = @()
    $defenderSessionOffsets = @()
    foreach ($service in @('team1-defender', 'team2-defender')) {
        $agentSummary = $result.agent_summaries.$service
        $shutdown = $agentSummary.shutdown_metrics
        $e2e = Get-NumericProperty $shutdown.verdict_send_e2e 'max_us'
        if ($null -ne $e2e) { $e2eValues += $e2e }
        $calls = Get-NumericProperty $shutdown.advisory 'calls'
        if ($null -ne $calls) { $defenderCalls += $calls }
        $sessionOffset = Get-NumericProperty `
            $agentSummary.event_first_offset_ms 'session-connected'
        if ($null -ne $sessionOffset) { $defenderSessionOffsets += $sessionOffset }
    }
    $requestValues = @()
    $attackerCalls = @()
    $attackerTokens = @()
    $attackerFirstHitOffsets = @()
    foreach ($service in @('team1-attacker', 'team2-attacker')) {
        $agentSummary = $result.agent_summaries.$service
        $round = $agentSummary.round_metrics
        $requests = Get-NumericProperty $round 'requests_made'
        $calls = Get-NumericProperty $round 'llm_calls'
        $tokens = Get-NumericProperty $round 'llm_tokens'
        if ($null -ne $requests) { $requestValues += $requests }
        if ($null -ne $calls) { $attackerCalls += $calls }
        if ($null -ne $tokens) { $attackerTokens += $tokens }
        $hitOffset = Get-NumericProperty $agentSummary.event_first_offset_ms 'hit'
        if ($null -ne $hitOffset) { $attackerFirstHitOffsets += $hitOffset }
    }
    $hitVsSession = @()
    foreach ($capture in @($result.captures)) {
        $attackerSummary = $result.agent_summaries.("team$($capture.by)-attacker")
        $defenderSummary = $result.agent_summaries.("team$($capture.victim)-defender")
        $hitUnixMs = Get-EventUnixMs $attackerSummary 'hit'
        $sessionUnixMs = Get-EventUnixMs $defenderSummary 'session-connected'
        if ($null -ne $hitUnixMs -and $null -ne $sessionUnixMs) {
            $hitVsSession += [double]($hitUnixMs - $sessionUnixMs)
        }
    }
    $containerFailures = @(
        $result.agent_summaries.PSObject.Properties.Value | Where-Object {
            [bool]$_.missing -or [bool]$_.oom_killed -or [int]$_.exit_code -ne 0
        }
    ).Count
    $seedResults += [pscustomobject][ordered]@{
        evidence_id = $record.evidence_id
        matrix = [string]$result.matrix
        seed = [int]$result.seed
        captures = @($result.captures).Count
        normal_requests = [int]$result.normal_traffic.requests
        normal_failures = [int]$result.normal_traffic.failures
        normal_latency_max_ms = [double]$result.normal_traffic.latency_ms.max
        attacker_first_hit_offset_ms = $(if ($attackerFirstHitOffsets.Count) {
            ($attackerFirstHitOffsets | Measure-Object -Minimum).Minimum
        } else { $null })
        defender_session_connected_max_offset_ms = $(if ($defenderSessionOffsets.Count) {
            ($defenderSessionOffsets | Measure-Object -Maximum).Maximum
        } else { $null })
        first_hit_vs_victim_session_ms = $(if ($hitVsSession.Count) {
            ($hitVsSession | Measure-Object -Minimum).Minimum
        } else { $null })
        capture_before_session_observed =
            @($hitVsSession | Where-Object { $_ -lt 0 }).Count -gt 0
        attack_requests = $(if ($requestValues.Count -eq 2) {
            [double](($requestValues | Measure-Object -Sum).Sum)
        } else { $null })
        attacker_llm_calls = $(if ($attackerCalls.Count -eq 2) {
            [double](($attackerCalls | Measure-Object -Sum).Sum)
        } else { $null })
        attacker_llm_tokens = $(if ($attackerTokens.Count -eq 2) {
            [double](($attackerTokens | Measure-Object -Sum).Sum)
        } else { $null })
        defender_llm_calls = $(if ($defenderCalls.Count -eq 2) {
            [double](($defenderCalls | Measure-Object -Sum).Sum)
        } else { $null })
        defender_e2e_max_us = $(if ($e2eValues.Count -gt 0) {
            [double](($e2eValues | Measure-Object -Maximum).Maximum)
        } else { $null })
        gc_dropped = [int]$result.router_metrics.'1'.gc_dropped +
            [int]$result.router_metrics.'2'.gc_dropped
        container_failures = $containerFailures
    }
}

$matrixAggregates = [ordered]@{}
foreach ($matrix in $matrices) {
    $rows = @($seedResults | Where-Object { $_.matrix -eq $matrix })
    $captures = @($rows.captures)
    $normalFailures = @($rows.normal_failures)
    $e2e = @($rows.defender_e2e_max_us | Where-Object { $null -ne $_ })
    $hitVsSession = @($rows.first_hit_vs_victim_session_ms | Where-Object { $null -ne $_ })
    $matrixAggregates[$matrix] = [ordered]@{
        seeds = @($rows.seed | Sort-Object)
        capture_count = [ordered]@{
            median = Get-Median $captures
            min = $(if ($captures.Count) { ($captures | Measure-Object -Minimum).Minimum } else { $null })
            max = $(if ($captures.Count) { ($captures | Measure-Object -Maximum).Maximum } else { $null })
        }
        normal_failures = [ordered]@{
            median = Get-Median $normalFailures
            max = $(if ($normalFailures.Count) {
                ($normalFailures | Measure-Object -Maximum).Maximum
            } else { $null })
        }
        defender_e2e_max_us = $(if ($e2e.Count) {
            ($e2e | Measure-Object -Maximum).Maximum
        } else { $null })
        pre_session_capture_seeds = @(
            $rows | Where-Object { $_.capture_before_session_observed }
        ).Count
        first_hit_vs_victim_session_min_ms = $(if ($hitVsSession.Count) {
            ($hitVsSession | Measure-Object -Minimum).Minimum
        } else { $null })
        gc_dropped_max = $(if ($rows.Count) {
            ($rows.gc_dropped | Measure-Object -Maximum).Maximum
        } else { $null })
        container_failures_max = $(if ($rows.Count) {
            ($rows.container_failures | Measure-Object -Maximum).Maximum
        } else { $null })
    }
}

function Get-SeedResult([string]$matrix, [int]$seed) {
    return @($seedResults | Where-Object {
        $_.matrix -eq $matrix -and $_.seed -eq $seed
    } | Select-Object -First 1)[0]
}

$seedComparisons = @()
foreach ($seed in $ExpectedSeeds) {
    $a0d0 = Get-SeedResult 'A0D0' $seed
    $a1d0 = Get-SeedResult 'A1D0' $seed
    $a0d1 = Get-SeedResult 'A0D1' $seed
    $a1d1 = Get-SeedResult 'A1D1' $seed
    if ($null -in @($a0d0, $a1d0, $a0d1, $a1d1)) { continue }
    $seedComparisons += [pscustomobject][ordered]@{
        seed = $seed
        attacker_capture_delta = $a1d0.captures - $a0d0.captures
        attacker_first_hit_delta_ms = $(if (
            $null -ne $a0d0.attacker_first_hit_offset_ms -and
            $null -ne $a1d0.attacker_first_hit_offset_ms
        ) {
            $a1d0.attacker_first_hit_offset_ms - $a0d0.attacker_first_hit_offset_ms
        } else { $null })
        defender_stolen_delta_with_a0 = $a0d1.captures - $a0d0.captures
        defender_stolen_delta_with_a1 = $a1d1.captures - $a1d0.captures
        defender_normal_failure_delta_with_a0 =
            $a0d1.normal_failures - $a0d0.normal_failures
        defender_normal_failure_delta_with_a1 =
            $a1d1.normal_failures - $a1d0.normal_failures
    }
}
$attackDeltas = @($seedComparisons.attacker_capture_delta)
$defenseDeltas = @(
    $seedComparisons.defender_stolen_delta_with_a0
    $seedComparisons.defender_stolen_delta_with_a1
)
$defenseNormalDeltas = @(
    $seedComparisons.defender_normal_failure_delta_with_a0
    $seedComparisons.defender_normal_failure_delta_with_a1
)
$firstHitDeltas = @(
    $seedComparisons.attacker_first_hit_delta_ms | Where-Object { $null -ne $_ }
)
$candidatePreSessionCaptures = @(
    $seedResults | Where-Object {
        $_.matrix -in @('A0D1', 'A1D1') -and $_.capture_before_session_observed
    }
).Count
$attackNoRegression = $seedComparisons.Count -eq $ExpectedSeeds.Count -and
    @($attackDeltas | Where-Object { $_ -lt 0 }).Count -eq 0
$attackAnyGain = @($attackDeltas | Where-Object { $_ -gt 0 }).Count -gt 0
$defenseNoRegression = $seedComparisons.Count -eq $ExpectedSeeds.Count -and
    @($defenseDeltas | Where-Object { $_ -gt 0 }).Count -eq 0 -and
    @($defenseNormalDeltas | Where-Object { $_ -gt 0 }).Count -eq 0
$comparison = [ordered]@{
    per_seed = $seedComparisons
    attacker_capture_delta = [ordered]@{
        median = Get-Median $attackDeltas
        worst = $(if ($attackDeltas.Count) {
            ($attackDeltas | Measure-Object -Minimum).Minimum
        } else { $null })
        any_gain = $attackAnyGain
        no_regression = $attackNoRegression
    }
    defender_stolen_delta = [ordered]@{
        median = Get-Median $defenseDeltas
        worst = $(if ($defenseDeltas.Count) {
            ($defenseDeltas | Measure-Object -Maximum).Maximum
        } else { $null })
        no_regression = $defenseNoRegression
    }
    first_flag_time_delta = [ordered]@{
        median_ms = Get-Median $firstHitDeltas
        samples = $firstHitDeltas.Count
    }
    request_and_token_delta = $null
}

$gates = [ordered]@{
    rules_and_scope = $(if ($scopeOk) { 'PASS' } else { 'FAIL' })
    evidence_integrity = $(if ($integrityOk -and $coverageOk) { 'PASS' } else { 'FAIL' })
    official_interface_proxy = $(if ($interfaceOk) { 'PASS' } else { 'FAIL' })
    defense_300ms_heartbeat_reconnect = $(if ($defenseOk) { 'PASS' } else { 'FAIL' })
    isolation_and_reproducibility = $(if ($isolationOk -and $coverageOk) { 'PASS' } else { 'FAIL' })
}

$areas = [ordered]@{
    evidence_traceability = [ordered]@{ weight = 15; ai = $(if ($coverageOk -and $integrityOk) { 2 } else { 1 }) }
    attack_effectiveness = [ordered]@{ weight = 20; ai = $(if ($attackAnyGain -and $attackNoRegression) { 2 } else { 1 }) }
    defense_effect_availability = [ordered]@{ weight = 25; ai = $(if ($defenseOk -and $defenseNoRegression) { 2 } else { 1 }) }
    generalization_adaptability = [ordered]@{ weight = 15; ai = $(if ($coverageOk -and $ExpectedSeeds.Count -ge 3) { 2 } else { 1 }) }
    performance_resilience = [ordered]@{ weight = 15; ai = $(if ($defenseOk) { 2 } else { 1 }) }
    operational_reproducibility = [ordered]@{ weight = 5; ai = $(if ($isolationOk -and $coverageOk) { 2 } else { 1 }) }
    llm_cost_observability = [ordered]@{ weight = 5; ai = $(if ($isolationOk -and $integrityOk) { 2 } else { 1 }) }
}

$allEvidenceIds = @($records | ForEach-Object { $_.evidence_id })
$areaEvidence = [ordered]@{
    evidence_traceability = $allEvidenceIds
    attack_effectiveness = @($records | Where-Object {
        $_.result.matrix -in 'A0D0', 'A1D0'
    } | ForEach-Object { $_.evidence_id })
    defense_effect_availability = $allEvidenceIds
    generalization_adaptability = $allEvidenceIds
    performance_resilience = @($records | Where-Object {
        $_.result.matrix -in 'A0D1', 'A1D1'
    } | ForEach-Object { $_.evidence_id })
    operational_reproducibility = $allEvidenceIds
    llm_cost_observability = @($records | Where-Object {
        $_.result.matrix -in 'A1D0', 'A1D1'
    } | ForEach-Object { $_.evidence_id })
}
$areaGaps = [ordered]@{
    evidence_traceability = @('BLIND_HOLDOUT_MISSING', 'L4_EVIDENCE_MISSING')
    attack_effectiveness = @(
        'BLIND_HOLDOUT_MISSING', 'L4_EVIDENCE_MISSING', 'BASELINE_REQUEST_SUMMARY_MISSING'
    )
    defense_effect_availability = @(
        'BLIND_HOLDOUT_MISSING', 'L4_EVIDENCE_MISSING', 'OFFICIAL_SLA_GENERATOR_MISSING'
    )
    generalization_adaptability = @('BLIND_HOLDOUT_MISSING', 'L4_EVIDENCE_MISSING')
    performance_resilience = @(
        'OFFICIAL_20_MIN_LOAD_MISSING', 'FORCED_WORKER_RECONNECT_FINAL_MISSING'
    )
    operational_reproducibility = @('OFFICIAL_ARENA_REPRODUCIBILITY_MISSING')
    llm_cost_observability = @(
        'USD_PRICE_SCHEDULE_MISSING', 'BASELINE_TOKEN_SUMMARY_MISSING'
    )
}
foreach ($areaName in $areas.Keys) {
    $area = $areas[$areaName]
    $area['ai_confidence'] = $(if ([int]$area.ai -ge 2) { 'MEDIUM' } else { 'LOW' })
    $area['ai_evidence_ids'] = @($areaEvidence[$areaName])
    $area['ai_gaps'] = @($areaGaps[$areaName])
    $area['ai_judgement'] = $(if ([int]$area.ai -ge 2) { 'PROXY_PASS' } else { 'CONCERN' })
}

$humanPending = $HumanScoreFile -eq 'PENDING'
$human = $null
if (-not $humanPending) {
    if (-not (Test-Path -LiteralPath $HumanScoreFile -PathType Leaf)) {
        throw "human score file missing: $HumanScoreFile"
    }
    $humanRaw = Get-Content -Raw -LiteralPath $HumanScoreFile
    $humanValid = $humanRaw | Test-Json -SchemaFile $humanScoreSchemaPath -ErrorAction SilentlyContinue
    if (-not $humanValid) {
        throw 'human score file does not satisfy contracts/scrimmage/human-score.schema.json'
    }
    $human = $humanRaw | ConvertFrom-Json -ErrorAction Stop
}
$aiTotal = 0.0
$finalTotal = 0.0
foreach ($areaName in $areas.Keys) {
    $area = $areas[$areaName]
    $aiTotal += [double]$area.weight * [double]$area.ai / 4.0
    if (-not $humanPending) {
        $humanArea = $human.areas.$areaName
        $humanScore = [int]$humanArea.score
        $area['human'] = $humanScore
        $area['final'] = [Math]::Min([int]$area.ai, $humanScore)
        $area['arbitration'] = [Math]::Abs([int]$area.ai - $humanScore) -ge 2
        $area['human_confidence'] = [string]$humanArea.confidence
        $area['human_evidence_ids'] = @($humanArea.evidence_ids)
        $area['human_gaps'] = @($humanArea.gaps)
        $area['human_judgement'] = [string]$humanArea.judgement
        $area['final_judgement'] = $(if ($area['arbitration']) {
            'ARBITRATION'
        } else {
            [string]$humanArea.judgement
        })
        $finalTotal += [double]$area.weight * [double]$area['final'] / 4.0
    } else {
        $area['human'] = $null
        $area['final'] = $null
        $area['arbitration'] = $false
        $area['human_confidence'] = $null
        $area['human_evidence_ids'] = @()
        $area['human_gaps'] = @()
        $area['human_judgement'] = 'PENDING'
        $area['final_judgement'] = 'PENDING'
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
$promotionBlockers = @(
    if (-not $attackAnyGain) { 'candidate attacker has no measured capture gain over A0 against D0' }
    if (-not $attackNoRegression) { 'candidate attacker regressed against D0 in at least one seed' }
    if (-not $defenseNoRegression) { 'candidate defender increased stolen flags or normal failures' }
    if ($candidatePreSessionCaptures -gt 0) {
        'accepted capture observed before the victim defender session connected'
    }
    if ($humanPending) { 'human score is pending' }
    'blind holdout, L4, and official SLA generator remain unavailable'
)
$judgement = [ordered]@{
    schema_version = 1
    score_name = 'SCRIMMAGE_PROXY'
    verdict = $verdict
    gates = $gates
    rubric = $areas
    ai_weighted_score = [Math]::Round($aiTotal, 2)
    final_weighted_score = $(if ($humanPending) { $null } else { [Math]::Round($finalTotal, 2) })
    human_score = $(if ($humanPending) { 'PENDING' } else { 'PROVIDED' })
    seed_results = $seedResults
    matrix_aggregates = $matrixAggregates
    baseline_candidate_comparison = $comparison
    promotion_blockers = $promotionBlockers
    recommendation = $(if ($verdict -eq 'READY') { 'PROMOTE' } else { 'HOLD' })
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
