[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$dockerfile = Join-Path $here 'Dockerfile.challenge-proxy'

$layers = @(
    @{ Base = 'lig-demo/layer-1:latest'; Tag = 'aegis/scrimmage-layer-1:proxy' },
    @{ Base = 'lig-demo/layer-2:latest'; Tag = 'aegis/scrimmage-layer-2:proxy' },
    @{ Base = 'lig-demo/layer-3:latest'; Tag = 'aegis/scrimmage-layer-3:proxy' }
)

foreach ($layer in $layers) {
    & docker buildx build --platform linux/amd64 --provenance=false --sbom=false --load `
        --build-arg "BASE_IMAGE=$($layer.Base)" `
        --file $dockerfile --tag $layer.Tag $here
    if ($LASTEXITCODE -ne 0) {
        throw "proxy layer build failed: $($layer.Tag)"
    }
    $probe = & docker run --rm --entrypoint python $layer.Tag -c 'import packaging; print("ok")'
    if ($LASTEXITCODE -ne 0 -or ($probe -join '').Trim() -ne 'ok') {
        throw "proxy layer import probe failed: $($layer.Tag)"
    }
}

Write-Output 'SCRIMMAGE_PROXY challenge images built: 3'
