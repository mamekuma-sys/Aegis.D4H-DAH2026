<#
.SYNOPSIS
  Run the DAH 2026 Break Copilot Python CLI from the repository root.

.DESCRIPTION
  Pass all arguments to python -m scripts.break_copilot. The wrapper does not
  copy raw capture/log inputs into the repository or print the LLM key.
#>
param(
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$Arguments
)

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot

function Resolve-PythonCommand {
    if ($env:PYTHON) {
        return $env:PYTHON
    }
    $isUnix = [System.Environment]::OSVersion.Platform -eq [System.PlatformID]::Unix
    $candidates = if ($isUnix) { @('python3', 'python') } else { @('python', 'python3') }
    foreach ($candidate in $candidates) {
        if (Get-Command $candidate -ErrorAction SilentlyContinue) {
            return $candidate
        }
    }
    throw 'Python interpreter not found. Install Python 3.12+ or set PYTHON.'
}

$python = Resolve-PythonCommand

Push-Location $repoRoot
try {
    & $python -B -m scripts.break_copilot @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "Break Copilot failed with exit code $LASTEXITCODE"
    }
} finally {
    Pop-Location
}
