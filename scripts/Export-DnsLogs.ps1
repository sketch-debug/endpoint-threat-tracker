# Export-DnsLogs.ps1 — export DNS query logs to the tracker inbox (read-only).
#
# Supported sources:
#   -Technitium <apiUrl>   Technitium DNS Server CSV export (API)
#   -AdGuard <path>        AdGuard Home querylog.json (copied as-is, JSONL)
#   -Generic <path>        Plain CSV already: timestamp,client_ip,domain[,query_type]
#
# Run from Task Scheduler daily, or manually. Nothing is modified on the DNS
# server: reads only, then drops a timestamped file into the inbox folder.
[CmdletBinding()]
param(
    [ValidateSet('Technitium', 'AdGuard', 'Generic')]
    [string]$Source = 'Generic',
    [string]$ApiUrl = 'http://dns-server:5380',
    [string]$TokenFile = "$PSScriptRoot\technitium.token",
    [string]$QueryLogPath = 'C:\ProgramData\AdGuardHome\data\querylog.json',
    [string]$GenericPath = '',
    [string]$InboxDir = (Join-Path (Split-Path $PSScriptRoot -Parent) 'inbox'),
    [int]$Days = 1
)
$ErrorActionPreference = 'Stop'
$stamp = Get-Date -Format 'yyyyMMdd'
New-Item -ItemType Directory -Force -Path $InboxDir | Out-Null

switch ($Source) {
    'Technitium' {
        if (-not (Test-Path $TokenFile)) { throw "Token file not found: $TokenFile" }
        $token = (Get-Content $TokenFile -Raw).Trim()
        $since = (Get-Date).ToUniversalTime().AddDays(-$Days).ToString('yyyy-MM-ddTHH:mm:ssZ')
        $url = "$ApiUrl/api/logs/query/export?token=$token&type=csv&since=$since"
        $out = Join-Path $InboxDir "dns_technitium_$stamp.csv"
        Invoke-WebRequest -Uri $url -OutFile $out -UseBasicParsing
        Write-Host "Exported Technitium query log -> $out"
    }
    'AdGuard' {
        if (-not (Test-Path $QueryLogPath)) { throw "AdGuard querylog not found: $QueryLogPath" }
        $out = Join-Path $InboxDir "dns_adguard_$stamp.jsonl"
        Copy-Item $QueryLogPath $out -Force
        Write-Host "Copied AdGuard querylog -> $out"
    }
    'Generic' {
        if (-not $GenericPath -or -not (Test-Path $GenericPath)) {
            throw "Provide -GenericPath pointing at a CSV with timestamp,client_ip,domain columns"
        }
        $out = Join-Path $InboxDir "dns_generic_$stamp.csv"
        Copy-Item $GenericPath $out -Force
        Write-Host "Copied generic DNS CSV -> $out"
    }
}
