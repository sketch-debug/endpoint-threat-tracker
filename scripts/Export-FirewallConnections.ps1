# Export-FirewallConnections.ps1 — export recent connection events (metadata
# only: IPs, ports, outcomes) to the tracker inbox. Read-only.
#
# Sources Windows Filtering Platform event log (5156 = permitted connection,
# 5157 = blocked). Requires an elevated scheduled task; if the log is not
# enabled, this script reports that and exits without error.
[CmdletBinding()]
param(
    [string]$InboxDir = (Join-Path (Split-Path $PSScriptRoot -Parent) 'inbox'),
    [int]$Hours = 24
)
$ErrorActionPreference = 'Stop'
$stamp = Get-Date -Format 'yyyyMMdd'
$out = Join-Path $InboxDir "fw_connections_$stamp.csv"
New-Item -ItemType Directory -Force -Path $InboxDir | Out-Null
$start = (Get-Date).AddHours(-$Hours)

try {
    $events = Get-WinEvent -FilterHashtable @{
        LogName = 'Microsoft-Windows-Windows Firewall With Advanced Security/Firewall'
        Id = @(5156, 5157); StartTime = $start
    } -ErrorAction SilentlyContinue
} catch {
    Write-Warning "WFP log unavailable (audit policy not enabled?): $($_.Exception.Message)"
    exit 0
}
if (-not $events) {
    Write-Host "No 5156/5157 events in the last $Hours hours."
    exit 0
}

$rows = foreach ($e in $events) {
    $data = @{}
    foreach ($p in [regex]::Matches($e.ToXml(), '<Data Name="([^"]+)">([^<]*)</Data>')) {
        $data[$p.Groups[1].Value] = $p.Groups[2].Value
    }
    [pscustomobject]@{
        timestamp = $e.TimeCreated.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
        hostname  = $env:COMPUTERNAME
        client_ip = $data['SourceAddress']
        src_ip    = $data['SourceAddress']
        dst_ip    = $data['DestAddr']
        port      = $data['DestPort']
        protocol  = $data['Protocol']
        action    = if ($e.Id -eq 5156) { 'allow' } else { 'block' }
        process   = $data['Application']
        duration  = ''
    }
}
$rows | Export-Csv -Path $out -NoTypeInformation -Encoding UTF8
Write-Host "Exported $($rows.Count) connection events -> $out"
