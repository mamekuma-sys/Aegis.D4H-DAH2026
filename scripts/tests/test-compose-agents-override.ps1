$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$composeOverride = Join-Path $repoRoot 'integration/compose.agents.yml'
$runner = Join-Path $repoRoot 'integration/run-with-skeleton.ps1'
$attackerRunbook = Join-Path $repoRoot 'integration/attacker-deploy.md'
$defenderRunbook = Join-Path $repoRoot 'integration/defender-deploy.md'
$dockerfile = Join-Path $repoRoot 'agents/defender/Dockerfile'

foreach ($path in @($composeOverride, $runner, $attackerRunbook, $defenderRunbook, $dockerfile)) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        Write-Error "Missing required file: $path"
        exit 1
    }
}

$overrideText = [System.IO.File]::ReadAllText($composeOverride)
if ($overrideText -match '(?m)^\s*context:\s*\.\./agents/(attacker|defender)\s*$') {
    throw 'compose.agents.yml still uses a relative context resolved against the skeleton.'
}
if ($overrideText -notmatch 'AEGIS_ATTACKER_CONTEXT') {
    throw 'compose.agents.yml does not inject AEGIS_ATTACKER_CONTEXT.'
}
if ($overrideText -notmatch 'AEGIS_DEFENDER_CONTEXT') {
    throw 'compose.agents.yml does not inject AEGIS_DEFENDER_CONTEXT.'
}
if ($overrideText -notmatch 'team1-defender:') {
    throw 'compose.agents.yml does not override team1-defender.'
}

$runnerText = [System.IO.File]::ReadAllText($runner)
if ($runnerText -notmatch 'AEGIS_ATTACKER_CONTEXT' -or $runnerText -notmatch 'AEGIS_DEFENDER_CONTEXT') {
    throw 'run-with-skeleton.ps1 does not set both agent context variables.'
}
if ($runnerText -notmatch 'config --format json') {
    throw 'run-with-skeleton.ps1 does not verify merged Compose config before up.'
}
if ($runnerText -notmatch 'ConfigOnly') {
    throw 'run-with-skeleton.ps1 is missing -ConfigOnly for preflight context checks.'
}
if ($runnerText -notmatch 'LogsDefender') {
    throw 'run-with-skeleton.ps1 is missing -LogsDefender.'
}
if ($runnerText -match "'down',\s*'-v'" -or $runnerText -match 'down -v') {
    throw 'run-with-skeleton.ps1 still uses docker compose down -v.'
}

$dockerfileText = [System.IO.File]::ReadAllText($dockerfile)
if ($dockerfileText -match '(?m)^COPY policy /app/policy\s*$') {
    throw 'defender Dockerfile still copies policy to /app/policy.'
}
if ($dockerfileText -notmatch '(?m)^COPY policy /policy\s*$') {
    throw 'defender Dockerfile does not copy policy to /policy.'
}

$attackerText = [System.IO.File]::ReadAllText($attackerRunbook)
if ($attackerText -match '2026-08-13') {
    throw 'attacker-deploy.md still pins dated verification results.'
}
if ($attackerText -notmatch 'python -m unittest discover') {
    throw 'attacker-deploy.md does not rerun attacker unit tests before deploy.'
}
if ($attackerText -notmatch 'check-layout\.ps1' -or $attackerText -notmatch 'validate-skeleton\.ps1') {
    throw 'attacker-deploy.md does not rerun layout and skeleton validators before deploy.'
}
if ($attackerText -notmatch 'ConfigOnly') {
    throw 'attacker-deploy.md does not verify merged Compose context before live smoke.'
}
if ($attackerText -match 'LLM_MODEL\(gpt-4o-mini\)') {
    throw 'attacker-deploy.md still lists LLM_MODEL as an official injected contract.'
}
if ($attackerText -notmatch '(?s)LLM_MODEL.*gpt-4o-mini') {
    throw 'attacker-deploy.md does not document LLM_MODEL as an optional default.'
}
if ($attackerText -notmatch "throw 'docker build failed'") {
    throw 'attacker-deploy.md does not stop when docker build fails.'
}
if ($attackerText -notmatch "throw 'docker push failed'") {
    throw 'attacker-deploy.md does not stop when docker push fails.'
}

$defenderText = [System.IO.File]::ReadAllText($defenderRunbook)
if ($defenderText -notmatch 'python -m unittest discover') {
    throw 'defender-deploy.md does not rerun defender unit tests before deploy.'
}
if ($defenderText -notmatch 'check-layout\.ps1' -or $defenderText -notmatch 'validate-skeleton\.ps1') {
    throw 'defender-deploy.md does not rerun layout and skeleton validators before deploy.'
}
if ($defenderText -notmatch 'ConfigOnly') {
    throw 'defender-deploy.md does not verify merged Compose context before live smoke.'
}
if ($defenderText -notmatch 'policy_source=active') {
    throw 'defender-deploy.md does not require policy_source=active.'
}
if ($defenderText -notmatch 'drop_capable_rules=0') {
    throw 'defender-deploy.md does not require drop_capable_rules=0.'
}
if ($defenderText -notmatch 'COPY policy /policy') {
    throw 'defender-deploy.md does not document the /policy image path.'
}
if ($defenderText -notmatch "throw 'docker build failed'") {
    throw 'defender-deploy.md does not stop when docker build fails.'
}
if ($defenderText -notmatch "throw 'docker push failed'") {
    throw 'defender-deploy.md does not stop when docker push fails.'
}
if ($defenderText -notmatch 'team\{N\}/defender:latest') {
    throw 'defender-deploy.md does not use the official defender Registry name.'
}
if ($defenderText -notmatch 'force-recreate') {
    throw 'defender-deploy.md does not document POST /control/start image restore.'
}

Write-Output 'Agent Compose override tests passed: 21 cases.'
