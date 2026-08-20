function ConvertFrom-ScrimmageSeedArguments {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string[]]$SeedArguments,
        [string]$Label = 'Seeds'
    )

    $parsed = @()
    foreach ($seedArgument in $SeedArguments) {
        foreach ($part in ([string]$seedArgument -split ',')) {
            $seed = 0
            if (-not [int]::TryParse($part.Trim(), [ref]$seed) -or $seed -lt 0) {
                throw "invalid $Label value: $part"
            }
            $parsed += $seed
        }
    }
    if ($parsed.Count -eq 0) { throw "$Label must not be empty" }
    if (@($parsed | Select-Object -Unique).Count -ne $parsed.Count) {
        throw "$Label must be unique"
    }
    return $parsed
}

Export-ModuleMember -Function ConvertFrom-ScrimmageSeedArguments
