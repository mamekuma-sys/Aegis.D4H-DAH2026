[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$SkeletonPath,
    [ValidateSet('A0D0', 'A1D0', 'A0D1', 'A1D1')][string]$Matrix = 'A0D0',
    [int]$Seed = 1,
    [ValidateRange(10, 1200)][int]$RoundSeconds = 30,
    [ValidateRange(1, 100)][int]$SamplesPerRoute = 5,
    [string]$OutputRoot = '',
    [switch]$KeepStack
)

$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = Split-Path -Parent (Split-Path -Parent $here)
$manifestPath = Join-Path $here 'frozen-images.json'
$overridePath = Join-Path $here 'compose.proxy.yml'
$normalTrafficPath = Join-Path $here 'normal_traffic.py'
$manifestSchemaPath = Join-Path $repoRoot 'contracts/scrimmage/image-manifest.schema.json'
$resultSchemaPath = Join-Path $repoRoot 'contracts/scrimmage/match-result.schema.json'
$baseCompose = Join-Path $SkeletonPath 'deploy/docker-compose.yml'

foreach ($path in @(
    $manifestPath, $overridePath, $normalTrafficPath, $manifestSchemaPath,
    $resultSchemaPath, $baseCompose
)) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "required file missing: $path"
    }
}

$existing = @(& docker ps -aq --filter 'label=com.docker.compose.project=lig-demo')
$existing = @($existing | Where-Object { ([string]$_).Trim().Length -gt 0 })
if ($existing.Count -gt 0) {
    throw 'existing lig-demo containers found; preserve them and stop explicitly before scrimmage'
}

$manifestRaw = Get-Content -Raw -LiteralPath $manifestPath
if (-not ($manifestRaw | Test-Json -SchemaFile $manifestSchemaPath)) {
    throw 'frozen image manifest schema validation failed'
}
$manifest = $manifestRaw | ConvertFrom-Json
$attackKey = $Matrix.Substring(0, 2)
$defenseKey = $Matrix.Substring(2, 2)
$attack = $manifest.images.psobject.Properties[$attackKey].Value
$defense = $manifest.images.psobject.Properties[$defenseKey].Value

function Assert-FrozenImage($entry, [string]$label) {
    $raw = & docker image inspect $entry.reference --format '{{json .}}'
    if ($LASTEXITCODE -ne 0) { throw "$label image missing: $($entry.reference)" }
    $image = $raw | ConvertFrom-Json
    if ("$($image.Os)/$($image.Architecture)" -ne 'linux/amd64') {
        throw "$label platform mismatch"
    }
    if ($image.Config.Labels.'org.opencontainers.image.revision' -ne $entry.commit) {
        throw "$label commit label mismatch"
    }
}

Assert-FrozenImage $attack $attackKey
Assert-FrozenImage $defense $defenseKey
$proxyImages = [ordered]@{}
foreach ($proxy in 1..3) {
    $ref = "aegis/scrimmage-layer-$proxy`:proxy"
    $raw = & docker image inspect $ref --format '{{json .}}'
    if ($LASTEXITCODE -ne 0) { throw "proxy challenge image missing: $ref" }
    $image = $raw | ConvertFrom-Json
    if ("$($image.Os)/$($image.Architecture)" -ne 'linux/amd64') {
        throw "proxy challenge platform mismatch: $ref"
    }
    $proxyImages["L$proxy"] = [ordered]@{
        reference = $ref
        image_id = [string]$image.Id
        platform = 'linux/amd64'
    }
}

$env:SCRIMMAGE_ATTACKER_IMAGE = $attack.reference
$env:SCRIMMAGE_DEFENDER_IMAGE = $defense.reference
$baseComposePrefix = @('--progress', 'quiet', '-f', $baseCompose, '-f', $overridePath, '--profile', 'combat')
$composePrefix = $baseComposePrefix

function Invoke-Compose([string[]]$Arguments) {
    & docker compose @composePrefix @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "docker compose failed: $($Arguments -join ' ')"
    }
}

function Get-ServiceContainer([string]$service) {
    $ids = @(& docker ps -aq `
        --filter 'label=com.docker.compose.project=lig-demo' `
        --filter "label=com.docker.compose.service=$service")
    return @($ids | Where-Object { ([string]$_).Trim().Length -gt 0 } | Select-Object -First 1)[0]
}

function Assert-RunningImage([string]$service, [string]$expectedReference) {
    $id = Get-ServiceContainer $service
    if ([string]::IsNullOrWhiteSpace($id)) { throw "$service container missing" }
    $actualId = (& docker inspect --format '{{.Image}}' $id).Trim()
    $expectedId = (& docker image inspect --format '{{.Id}}' $expectedReference).Trim()
    if ($actualId -ne $expectedId) {
        throw "$service image mismatch: $actualId != $expectedId"
    }
}

function Wait-Backend([int]$seconds) {
    $deadline = [DateTime]::UtcNow.AddSeconds($seconds)
    while ([DateTime]::UtcNow -lt $deadline) {
        try {
            $health = Invoke-WebRequest -UseBasicParsing -TimeoutSec 2 'http://127.0.0.1:4100/healthz'
            if ($health.StatusCode -eq 200) { return }
        } catch {}
        Start-Sleep -Milliseconds 500
    }
    throw 'backend health timeout'
}

function Wait-ServicesStopped([string[]]$services, [int]$seconds) {
    $deadline = [DateTime]::UtcNow.AddSeconds($seconds)
    while ([DateTime]::UtcNow -lt $deadline) {
        $running = 0
        foreach ($service in $services) {
            $id = Get-ServiceContainer $service
            if (-not [string]::IsNullOrWhiteSpace($id)) {
                $isRunning = (& docker inspect --format '{{.State.Running}}' $id).Trim()
                if ($isRunning -eq 'true') { $running += 1 }
            }
        }
        if ($running -eq 0) { return }
        Start-Sleep -Milliseconds 250
    }
    throw 'combatant shutdown timeout'
}

function Convert-NumericMap($value) {
    $safe = [ordered]@{}
    if ($null -eq $value) { return $safe }
    foreach ($property in $value.PSObject.Properties) {
        if ($property.Value -is [byte] -or
            $property.Value -is [int16] -or
            $property.Value -is [int32] -or
            $property.Value -is [int64] -or
            $property.Value -is [single] -or
            $property.Value -is [double] -or
            $property.Value -is [decimal]) {
            $safe[$property.Name] = $property.Value
        }
    }
    return $safe
}

function Get-AgentSummary([string]$service) {
    $id = Get-ServiceContainer $service
    if ([string]::IsNullOrWhiteSpace($id)) {
        return [ordered]@{ missing = $true; secret_leak_detected = $false }
    }
    $lines = @(& docker logs $id 2>&1 | ForEach-Object { [string]$_ })
    $joined = $lines -join "`n"
    $leak = ($joined -match 'FLAG\{[^}\r\n]+\}') -or
            ($joined -match 'tok-team[12]') -or
            ($joined -match 'sk-local')
    $events = @{}
    $lastRound = $null
    $lastShutdown = $null
    foreach ($line in $lines) {
        try { $entry = $line | ConvertFrom-Json -ErrorAction Stop } catch { continue }
        if ($entry.event) {
            $name = [string]$entry.event
            $events[$name] = 1 + [int]($events[$name] -as [int])
            if ($name -eq 'round-summary') { $lastRound = $entry }
            if ($name -eq 'shutdown') { $lastShutdown = $entry }
        }
    }
    $state = (& docker inspect --format '{{json .State}}' $id) | ConvertFrom-Json
    $roundMetrics = $null
    if ($null -ne $lastRound) {
        $roundMetrics = [ordered]@{
            endpoints_observed = [int]$lastRound.endpoints_observed
            requests_made = [int]$lastRound.requests_made
            submit_states = Convert-NumericMap $lastRound.submit_states
            accepted_count = [int]$lastRound.accepted_count
            llm_calls = [int]$lastRound.llm_calls
            llm_tokens = [int]$lastRound.llm_tokens
        }
    }
    $shutdownMetrics = $null
    if ($null -ne $lastShutdown) {
        $shutdownMetrics = [ordered]@{
            sessions = [int]$lastShutdown.sessions
            heartbeats = [int]$lastShutdown.heartbeats
            advisory = Convert-NumericMap $lastShutdown.advisory
            counters = Convert-NumericMap $lastShutdown.counters
            hot_path = Convert-NumericMap $lastShutdown.hot_path
            verdict_send_e2e = Convert-NumericMap $lastShutdown.verdict_send_e2e
        }
    }
    return [ordered]@{
        missing = $false
        events = $events
        round_metrics = $roundMetrics
        shutdown_metrics = $shutdownMetrics
        exit_code = [int]$state.ExitCode
        oom_killed = [bool]$state.OOMKilled
        secret_leak_detected = [bool]$leak
    }
}

if ([string]::IsNullOrWhiteSpace($OutputRoot)) {
    $OutputRoot = Join-Path ([IO.Path]::GetTempPath()) 'Aegis.D4H-scrimmage'
}
$runId = '{0}-seed{1}-{2}' -f $Matrix, $Seed, ([DateTime]::UtcNow.ToString('yyyyMMddTHHmmssZ'))
$outputDir = Join-Path $OutputRoot $runId
New-Item -ItemType Directory -Force -Path $outputDir | Out-Null
$runtimeDir = Join-Path ([IO.Path]::GetTempPath()) (
    'Aegis.D4H-scrimmage-runtime-{0}' -f ([guid]::NewGuid().ToString('N'))
)
New-Item -ItemType Directory -Path $runtimeDir | Out-Null
$controllerComposePath = Join-Path $runtimeDir 'combat-controller.json'
$backendOverridePath = Join-Path $runtimeDir 'backend-controller.yml'
$stackStarted = $false

try {
    $merged = & docker compose @baseComposePrefix config --format json
    if ($LASTEXITCODE -ne 0) { throw 'merged compose validation failed' }
    $config = $merged | ConvertFrom-Json
    if ($config.services.'team1-attacker'.image -ne $attack.reference -or
        $config.services.'team1-defender'.image -ne $defense.reference) {
        throw 'merged compose does not bind frozen images'
    }
    $agentNetworksInternal = [bool]$config.networks.arena.internal
    $llmKeysBlank = $true
    foreach ($service in @('team1-attacker', 'team1-defender', 'team2-attacker', 'team2-defender')) {
        $networkNames = @($config.services.$service.networks.PSObject.Properties.Name)
        if ($networkNames.Count -eq 0) { $agentNetworksInternal = $false }
        foreach ($networkName in $networkNames) {
            if (-not [bool]$config.networks.$networkName.internal) {
                $agentNetworksInternal = $false
            }
        }
        if ([string]$config.services.$service.environment.LLM_API_KEY -ne '') {
            $llmKeysBlank = $false
        }
    }
    if (-not $agentNetworksInternal) { throw 'combatant network is not internal' }
    if (-not $llmKeysBlank) { throw 'LLM_API_KEY must be blank in proxy matches' }

    # 공식 backend의 combat start/stop 동작은 유지하되, 그 내부 compose가 frozen
    # 이미지로 한 번만 생성하도록 combatant-only controller를 임시 bind mount한다.
    # 그렇지 않으면 backend가 base agent를 만든 직후 runner가 다시 생성해 fail-open
    # startup window가 두 번 발생한다.
    $combatants = @('team1-attacker', 'team1-defender', 'team2-attacker', 'team2-defender')
    $controllerServices = [ordered]@{}
    foreach ($service in $combatants) {
        $serviceConfig = $config.services.$service | ConvertTo-Json -Depth 20 | ConvertFrom-Json
        $serviceConfig.PSObject.Properties.Remove('build')
        $serviceConfig.PSObject.Properties.Remove('depends_on')
        $controllerServices[$service] = $serviceConfig
    }
    $controllerConfig = [ordered]@{
        name = 'lig-demo'
        services = $controllerServices
        networks = [ordered]@{
            arena = [ordered]@{
                external = $true
                name = [string]$config.networks.arena.name
            }
        }
        volumes = [ordered]@{
            broker1 = [ordered]@{
                external = $true
                name = [string]$config.volumes.broker1.name
            }
            broker2 = [ordered]@{
                external = $true
                name = [string]$config.volumes.broker2.name
            }
        }
    }
    $controllerConfig | ConvertTo-Json -Depth 20 | Set-Content `
        -LiteralPath $controllerComposePath -Encoding utf8NoBOM
    & docker compose -f $controllerComposePath config --format json *> $null
    if ($LASTEXITCODE -ne 0) { throw 'combat controller compose validation failed' }

    $controllerMountPath = $controllerComposePath.Replace('\', '/')
    @"
services:
  backend:
    volumes:
      - type: bind
        source: "$controllerMountPath"
        target: /proj/docker-compose.yml
        read_only: true
"@ | Set-Content -LiteralPath $backendOverridePath -Encoding utf8NoBOM
    $composePrefix = @(
        '--progress', 'quiet', '-f', $baseCompose, '-f', $overridePath,
        '-f', $backendOverridePath, '--profile', 'combat'
    )
    & docker compose @composePrefix config --format json *> $null
    if ($LASTEXITCODE -ne 0) { throw 'controller-mounted compose validation failed' }

    $infra = @(
        'backend', 'litellm-gw',
        't1-layer-1', 't1-layer-2', 't1-layer-3', 't1-helper-1',
        't2-layer-1', 't2-layer-2', 't2-layer-3', 't2-helper-1',
        'team1-router', 'team2-router'
    )
    Invoke-Compose (@('up', '-d', '--no-build') + $infra)
    $stackStarted = $true
    Wait-Backend 45
    foreach ($layer in 1..3) {
        foreach ($team in 1..2) {
            Assert-RunningImage "t$team-layer-$layer" $proxyImages["L$layer"].reference
        }
    }

    $startBody = @{ seconds = $RoundSeconds } | ConvertTo-Json -Compress
    $started = Invoke-RestMethod -Method Post -ContentType 'application/json' `
        -Body $startBody -Uri 'http://127.0.0.1:4100/control/start'
    if (-not $started.ok) { throw 'backend refused game start' }

    foreach ($service in @('team1-attacker', 'team2-attacker')) {
        Assert-RunningImage $service $attack.reference
    }
    foreach ($service in @('team1-defender', 'team2-defender')) {
        Assert-RunningImage $service $defense.reference
    }

    Start-Sleep -Seconds 2
    $mountPath = ($normalTrafficPath -replace '\\', '/')
    $normalRaw = & docker run --rm --network lig-demo_arena `
        -v "${mountPath}:/runner/normal_traffic.py:ro" `
        --entrypoint python $attack.reference /runner/normal_traffic.py `
        --seed $Seed --samples-per-route $SamplesPerRoute
    if ($LASTEXITCODE -ne 0) { throw 'normal traffic generator failed' }
    $normal = ($normalRaw | Select-Object -Last 1) | ConvertFrom-Json

    $deadline = [DateTime]::UtcNow.AddSeconds($RoundSeconds + 60)
    do {
        Start-Sleep -Seconds 1
        $state = Invoke-RestMethod -Uri 'http://127.0.0.1:4100/api'
    } while ($state.phase -eq 'running' -and [DateTime]::UtcNow -lt $deadline)
    if ($state.phase -eq 'running') {
        Invoke-RestMethod -Method Post -ContentType 'application/json' -Body '{}' `
            -Uri 'http://127.0.0.1:4100/control/stop' | Out-Null
        throw 'round exceeded runner deadline'
    }
    Wait-ServicesStopped $combatants 30
    $state = Invoke-RestMethod -Uri 'http://127.0.0.1:4100/api'

    $summaries = [ordered]@{}
    foreach ($service in $combatants) {
        $summaries[$service] = Get-AgentSummary $service
    }
    $secretLeak = @($summaries.Values | Where-Object { $_.secret_leak_detected }).Count -gt 0
    $captures = @($state.captured | ForEach-Object {
        [ordered]@{ by = [string]$_.by; victim = [string]$_.victim; layer = [int]$_.layer }
    })

    $result = [ordered]@{
        schema_version = 1
        score_name = 'SCRIMMAGE_PROXY'
        matrix = $Matrix
        seed = $Seed
        round_seconds = $RoundSeconds
        images = [ordered]@{ attacker = $attack; defender = $defense }
        arena_images = $proxyImages
        environment_checks = [ordered]@{
            frozen_images_verified = $true
            agent_networks_internal = $agentNetworksInternal
            llm_keys_blank = $llmKeysBlank
            fresh_containers = $true
            raw_artifacts_exported = $false
        }
        captures = $captures
        normal_traffic = $normal
        router_metrics = $state.metrics
        agent_summaries = $summaries
        secret_leak_detected = $secretLeak
        limitations = @(
            'two-team L1-L3 demo; L4 unavailable',
            'challenge packaging repaired only in derived proxy images',
            'normal traffic is a proxy, not the official SLA generator',
            'seed controls request order only; official flag generation is not seedable',
            'raw PCAP and logs remain outside the result artifact'
        )
    }
    $resultPath = Join-Path $outputDir 'result.json'
    $resultJson = $result | ConvertTo-Json -Depth 12
    if (-not ($resultJson | Test-Json -SchemaFile $resultSchemaPath)) {
        throw 'sanitized result schema validation failed'
    }
    $resultJson | Set-Content -LiteralPath $resultPath -Encoding utf8NoBOM
    $hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $resultPath).Hash.ToLowerInvariant()
    Write-Output "result=$resultPath"
    Write-Output "sha256=$hash"
} finally {
    if ($stackStarted -and -not $KeepStack) {
        try { Invoke-Compose @('down') } catch { Write-Warning $_ }
    }
    if ((-not $KeepStack -or -not $stackStarted) -and
        (Test-Path -LiteralPath $runtimeDir -PathType Container)) {
        Remove-Item -LiteralPath $runtimeDir -Recurse -Force
    }
}
