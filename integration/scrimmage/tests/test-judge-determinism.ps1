[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..\..')).Path
$judge = Join-Path $repoRoot 'integration\scrimmage\judge-results.ps1'
$tempRoot = Join-Path ([IO.Path]::GetTempPath()) ("aegis-judge-determinism-{0}" -f [guid]::NewGuid())

New-Item -ItemType Directory -Path $tempRoot | Out-Null
try {
    foreach ($matrix in 'A0D0', 'A1D0', 'A0D1', 'A1D1') {
        foreach ($seed in 1, 2, 3) {
            $matchRoot = Join-Path $tempRoot ("{0}-{1}" -f $matrix, $seed)
            New-Item -ItemType Directory -Path $matchRoot | Out-Null
            $image = [ordered]@{
                commit = '0000000000000000000000000000000000000000'
                reference = 'fixture/agent@sha256:' + ('0' * 64)
                platform = 'linux/amd64'
            }
            $attacker = [ordered]@{
                missing = $false
                events = [ordered]@{ startup = 1 }
                round_metrics = [ordered]@{
                    endpoints_observed = 0
                    requests_made = 0
                    submit_states = [ordered]@{}
                    accepted_count = 0
                    llm_calls = 0
                    llm_tokens = 0
                }
                shutdown_metrics = $null
                exit_code = 0
                oom_killed = $false
                secret_leak_detected = $false
            }
            $defender = [ordered]@{
                missing = $false
                events = [ordered]@{ 'session-connected' = 1 }
                round_metrics = $null
                shutdown_metrics = [ordered]@{
                    sessions = 1
                    heartbeats = 1
                    advisory = [ordered]@{}
                    counters = [ordered]@{}
                    hot_path = [ordered]@{}
                    verdict_send_e2e = [ordered]@{}
                }
                exit_code = 0
                oom_killed = $false
                secret_leak_detected = $false
            }
            $result = [ordered]@{
                schema_version = 1
                score_name = 'SCRIMMAGE_PROXY'
                matrix = $matrix
                seed = $seed
                round_seconds = 10
                images = [ordered]@{ attacker = $image; defender = $image }
                arena_images = [ordered]@{
                    L1 = [ordered]@{ reference = 'aegis/scrimmage-layer-1:proxy'; image_id = 'sha256:' + ('1' * 64); platform = 'linux/amd64' }
                    L2 = [ordered]@{ reference = 'aegis/scrimmage-layer-2:proxy'; image_id = 'sha256:' + ('2' * 64); platform = 'linux/amd64' }
                    L3 = [ordered]@{ reference = 'aegis/scrimmage-layer-3:proxy'; image_id = 'sha256:' + ('3' * 64); platform = 'linux/amd64' }
                }
                environment_checks = [ordered]@{
                    frozen_images_verified = $true
                    agent_networks_internal = $true
                    llm_keys_blank = $true
                    fresh_containers = $true
                    raw_artifacts_exported = $false
                }
                captures = @()
                normal_traffic = [ordered]@{
                    seed = $seed
                    requests = 1
                    successes = 1
                    failures = 0
                    status_counts = [ordered]@{ '200' = 1 }
                    latency_ms = [ordered]@{ p50 = 0; p95 = 0; p99 = 0; max = 0 }
                }
                router_metrics = [ordered]@{
                    '1' = [ordered]@{ accept = 1; drop = 0; gc_dropped = 0 }
                    '2' = [ordered]@{ accept = 1; drop = 0; gc_dropped = 0 }
                }
                agent_summaries = [ordered]@{
                    'team1-attacker' = $attacker
                    'team1-defender' = $defender
                    'team2-attacker' = $attacker
                    'team2-defender' = $defender
                }
                secret_leak_detected = $false
                limitations = @('synthetic determinism fixture')
            }
            $result | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath (Join-Path $matchRoot 'result.json') -Encoding utf8NoBOM
        }
    }

    $outputs = @(
        Join-Path $tempRoot 'judgement-1.json'
        Join-Path $tempRoot 'judgement-2.json'
    )
    foreach ($output in $outputs) {
        & pwsh -NoProfile -File $judge `
            -ResultRoot $tempRoot `
            -ExpectedSeeds 1,2,3 `
            -HumanScoreFile PENDING `
            -OutputPath $output | Out-Null
        if ($LASTEXITCODE -ne 0) { throw 'judge execution failed' }
    }

    $hashes = @($outputs | ForEach-Object {
        (Get-FileHash -Algorithm SHA256 -LiteralPath $_).Hash
    })
    if ($hashes[0] -cne $hashes[1]) {
        throw "judge output is not deterministic: $($hashes -join ', ')"
    }
} finally {
    if ($tempRoot.StartsWith([IO.Path]::GetTempPath(), [StringComparison]::OrdinalIgnoreCase)) {
        Remove-Item -LiteralPath $tempRoot -Recurse -Force
    }
}

Write-Output 'judge determinism tests: PASS'
