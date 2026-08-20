$ErrorActionPreference = 'Stop'

$modulePath = Join-Path (Split-Path -Parent $PSScriptRoot) 'ScrimmageLogSummary.psm1'
Import-Module $modulePath -Force

function Assert-Equal($actual, $expected, [string]$label) {
    if ($actual -ne $expected) {
        throw "$label expected=$expected actual=$actual"
    }
}

$lines = @(
    '2026-08-20T07:00:00.100000000Z {"event":"startup","targets":2}',
    'not-json',
    '2026-08-20T07:00:00.500000000Z {"event":"hit","reason":"synthetic"}',
    '2026-08-20T07:00:00.800000000Z {"event":"hit","reason":"synthetic-2"}',
    '2026-08-20T07:00:01.000000000Z {"event":"round-summary","requests_made":3}'
)
$summary = ConvertFrom-ScrimmageTimestampedLogs `
    -Lines $lines -ContainerStartedAt '2026-08-20T07:00:00.000000000Z'

Assert-Equal $summary.entries.Count 4 'parsed entries'
Assert-Equal $summary.events.startup 1 'startup count'
Assert-Equal $summary.events.hit 2 'hit count'
Assert-Equal $summary.events.'round-summary' 1 'round summary count'
Assert-Equal $summary.event_first_offset_ms.startup 100.0 'startup offset'
Assert-Equal $summary.event_first_offset_ms.hit 500.0 'first hit offset'
Assert-Equal $summary.event_first_offset_ms.'round-summary' 1000.0 'summary offset'
Assert-Equal $summary.container_started_unix_ms 1787209200000.0 'container epoch'

Write-Output 'scrimmage log summary tests: PASS'
