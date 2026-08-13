$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$composeOverride = Join-Path $repoRoot 'integration/compose.agents.yml'
$runner = Join-Path $repoRoot 'integration/run-with-skeleton.ps1'
$runbook = Join-Path $repoRoot 'integration/attacker-deploy.md'

foreach ($path in @($composeOverride, $runner, $runbook)) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        Write-Error "Missing required file: $path"
        exit 1
    }
}

$overrideText = [System.IO.File]::ReadAllText($composeOverride)
if ($overrideText -match '(?m)^\s*context:\s*\.\./agents/attacker\s*$') {
    throw 'compose.agents.yml still uses a relative context resolved against the skeleton.'
}
if ($overrideText -notmatch 'AEGIS_ATTACKER_CONTEXT') {
    throw 'compose.agents.yml does not inject AEGIS_ATTACKER_CONTEXT.'
}

$runnerText = [System.IO.File]::ReadAllText($runner)
if ($runnerText -notmatch 'AEGIS_ATTACKER_CONTEXT') {
    throw 'run-with-skeleton.ps1 does not set AEGIS_ATTACKER_CONTEXT.'
}
if ($runnerText -notmatch 'config --format json') {
    throw 'run-with-skeleton.ps1 does not verify merged Compose config before up.'
}
if ($runnerText -notmatch 'ConfigOnly') {
    throw 'run-with-skeleton.ps1 is missing -ConfigOnly for preflight context checks.'
}

$runbookText = [System.IO.File]::ReadAllText($runbook)
if ($runbookText -match '2026-08-13') {
    throw 'attacker-deploy.md still pins dated verification results.'
}
if ($runbookText -notmatch 'python -m unittest discover') {
    throw 'attacker-deploy.md does not rerun attacker unit tests before deploy.'
}
if ($runbookText -notmatch 'check-layout\.ps1' -or $runbookText -notmatch 'validate-skeleton\.ps1') {
    throw 'attacker-deploy.md does not rerun layout and skeleton validators before deploy.'
}
if ($runbookText -notmatch 'ConfigOnly') {
    throw 'attacker-deploy.md does not verify merged Compose context before live smoke.'
}
if ($runbookText -match 'LLM_MODEL\(gpt-4o-mini\)') {
    throw 'attacker-deploy.md still lists LLM_MODEL as an official injected contract.'
}
if ($runbookText -notmatch '(?s)LLM_MODEL.*gpt-4o-mini') {
    throw 'attacker-deploy.md does not document LLM_MODEL as an optional default.'
}

Write-Output 'Attacker Compose override tests passed: 9 cases.'
