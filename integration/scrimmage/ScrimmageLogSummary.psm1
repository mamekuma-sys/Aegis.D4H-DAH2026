function ConvertFrom-ScrimmageTimestampedLogs {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string[]]$Lines,
        [Parameter(Mandatory = $true)][string]$ContainerStartedAt
    )

    $culture = [Globalization.CultureInfo]::InvariantCulture
    $styles = [Globalization.DateTimeStyles]::AssumeUniversal
    $started = [DateTimeOffset]::Parse($ContainerStartedAt, $culture, $styles)
    $startedUnixMs = [double]$started.ToUnixTimeMilliseconds()
    $events = [ordered]@{}
    $eventFirstOffsets = [ordered]@{}
    $entries = [System.Collections.Generic.List[object]]::new()

    foreach ($lineValue in $Lines) {
        $line = [string]$lineValue
        $separator = $line.IndexOf(' ')
        if ($separator -le 0) { continue }
        $timestampText = $line.Substring(0, $separator)
        $payload = $line.Substring($separator + 1).Trim()
        try {
            $timestamp = [DateTimeOffset]::Parse($timestampText, $culture, $styles)
            $entry = $payload | ConvertFrom-Json -ErrorAction Stop
        } catch {
            continue
        }
        $timestampUnixMs = [double]$timestamp.ToUnixTimeMilliseconds()
        $entries.Add([pscustomobject]@{
            timestamp_unix_ms = $timestampUnixMs
            value = $entry
        })
        if (-not $entry.event) { continue }
        $name = [string]$entry.event
        $events[$name] = 1 + [int]($events[$name] -as [int])
        if (-not $eventFirstOffsets.Contains($name)) {
            $offset = [Math]::Max(0.0, $timestampUnixMs - $startedUnixMs)
            $eventFirstOffsets[$name] = [Math]::Round($offset, 3)
        }
    }

    return [pscustomobject]@{
        container_started_unix_ms = $startedUnixMs
        events = $events
        event_first_offset_ms = $eventFirstOffsets
        entries = @($entries)
    }
}

Export-ModuleMember -Function ConvertFrom-ScrimmageTimestampedLogs
