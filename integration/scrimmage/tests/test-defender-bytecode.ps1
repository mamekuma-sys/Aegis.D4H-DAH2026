[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$Image
)

$ErrorActionPreference = 'Stop'
$raw = & docker image inspect $Image --format '{{json .}}'
if ($LASTEXITCODE -ne 0) { throw "image not found: $Image" }
$inspect = $raw | ConvertFrom-Json
if ("$($inspect.Os)/$($inspect.Architecture)" -ne 'linux/amd64') {
    throw 'defender image must be linux/amd64'
}
if ([string]$inspect.Config.User -ne '65534') {
    throw "defender image must use uid 65534, got: $($inspect.Config.User)"
}
$pyc = & docker run --rm --network none --entrypoint sh $Image `
    -c "find /app/aegis_defender -type f -name '*.pyc' -print -quit"
if ($LASTEXITCODE -ne 0) { throw 'bytecode inspection container failed' }
if ([string]::IsNullOrWhiteSpace(($pyc | Select-Object -First 1))) {
    throw 'defender image has no precompiled bytecode'
}

Write-Output 'defender bytecode image test: PASS'
