$ErrorActionPreference = 'Stop'
$module = Join-Path (Split-Path -Parent $PSScriptRoot) 'SeedArguments.psm1'
Import-Module $module -Force

$actual = @(ConvertFrom-ScrimmageSeedArguments `
    -SeedArguments @('101,102', '103') -Label 'Seeds')
if (($actual -join ',') -ne '101,102,103') {
    throw "comma seed parsing failed: $($actual -join ',')"
}

foreach ($invalid in @(@('1', '1'), @('-1'), @('not-a-seed'))) {
    $threw = $false
    try {
        ConvertFrom-ScrimmageSeedArguments -SeedArguments $invalid -Label 'Seeds'
    } catch {
        $threw = $true
    }
    if (-not $threw) { throw "invalid seeds accepted: $($invalid -join ',')" }
}

Write-Output 'seed argument tests: PASS'
