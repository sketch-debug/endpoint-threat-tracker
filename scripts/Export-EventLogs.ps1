# Export-EventLogs.ps1 — export Windows Event Log entries as CSV (never XML).
#
# CSV export is a deliberate security decision: no XML parser is involved on
# either side, so XXE-style attacks on log data are structurally impossible
# (see ADMIN_GUIDE "Why no XML").
#
# Event IDs collected (detection-relevant subset):
#   Security: 4688 (process create), 4624/4625 (logon/failed), 4720/4732
#             (account/group change), 1102 (log cleared)
#   System:   7045 (service installed)
#   TaskScheduler: 4698 (scheduled task created)
#   Defender: 5001 (RTP disabled), 5007 (config changed)
[CmdletBinding()]
param(
    [string]$InboxDir = (Join-Path (Split-Path $PSScriptRoot -Parent) 'inbox'),
    [int]$Hours = 24
)
$ErrorActionPreference = 'Stop'
$stamp = Get-Date -Format 'yyyyMMdd'
$outDir = Join-Path $InboxDir "events_$stamp"
New-Item -ItemType Directory -Force -Path $outDir | Out-Null
$start = (Get-Date).AddHours(-$Hours)

$logs = @(
    @{ LogName = 'Security';    Ids = @(4688, 4624, 4625, 4720, 4732, 1102) }
    @{ LogName = 'System';      Ids = @(7045, 1102) }
    @{ LogName = 'Microsoft-Windows-TaskScheduler/Operational'; Ids = @(4698) }
    @{ LogName = 'Microsoft-Windows-Windows Defender/Operational'; Ids = @(5001, 5007) }
)

foreach ($log in $logs) {
    try {
        $events = Get-WinEvent -FilterHashtable @{ LogName = $log.LogName; Id = $log.Ids; StartTime = $start } -ErrorAction SilentlyContinue
    } catch {
        Write-Warning "Could not read $($log.LogName): $($_.Exception.Message)"
        continue
    }
    if (-not $events) { continue }
    $rows = foreach ($e in $events) {
        $data = @{}
        if ($e.Message) { } # message is display text; EventData comes from properties
        # Rehydrate EventData fields from the raw XML string without an XML parser:
        # regex extraction of <Data Name="X">Y</Data> pairs (values only, no entities
        # are expanded, no external references are resolved).
        $pairs = [regex]::Matches($e.ToXml(), '<Data Name="([^"]+)">([^<]*)</Data>')
        foreach ($p in $pairs) { $data[$p.Groups[1].Value] = $p.Groups[2].Value }
        [pscustomobject]@{
            timestamp = $e.TimeCreated.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
            event_id  = $e.Id
            computer  = $e.MachineName
            provider  = $e.ProviderName
            level     = $e.LevelDisplayName
            data_json = ($data | ConvertTo-Json -Compress)
        }
    }
    $file = Join-Path $outDir "events_$($log.LogName -replace '[^A-Za-z0-9]', '')_$stamp.csv"
    $rows | Export-Csv -Path $file -NoTypeInformation -Encoding UTF8
    Write-Host "$($log.LogName): $($rows.Count) events -> $file"
}
