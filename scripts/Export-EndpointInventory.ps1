# Export-EndpointInventory.ps1 — snapshot process/task/persistence/Defender
# state to the tracker inbox (metadata only: names, paths, hashes, statuses).
#
# Run daily via Task Scheduler on each endpoint (or from a remote management
# tool that can run commands as SYSTEM). Read-only: collects and writes files,
# changes nothing on the endpoint.
[CmdletBinding()]
param(
    [string]$InboxDir = (Join-Path (Split-Path $PSScriptRoot -Parent) 'inbox'),
    [switch]$IncludeFileHashes
)
$ErrorActionPreference = 'Stop'
$stamp = Get-Date -Format 'yyyyMMdd_HHmm'
$hostName = $env:COMPUTERNAME
$ip = (Get-NetIPAddress -AddressFamily IPv4 |
    Where-Object { $_.IPAddress -notlike '127.*' } |
    Select-Object -First 1).IPAddress
if (-not $ip) { $ip = '' }
New-Item -ItemType Directory -Force -Path $InboxDir | Out-Null
$ts = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')

# --- running processes (with Authenticode signature status) ---------------
$procs = Get-Process | ForEach-Object {
    $sig = 'unknown'
    try {
        $exe = $_.Path
        if ($exe) {
            $s = Get-AuthenticodeSignature -FilePath $exe -ErrorAction Stop
            $sig = switch ($s.Status) {
                'Valid' { 'valid' } default { $s.Status.ToString().ToLower() }
            }
        }
    } catch { $exe = ''; $sig = 'unknown' }
    $cpu = 0.0
    try { $cpu = [math]::Round($_.CPU, 1) } catch { }
    # approximate percent processor time: cumulative CPU seconds / process age
    $pct = 0.0
    try {
        $age = ((Get-Date) - $_.StartTime).TotalSeconds
        if ($age -gt 0) { $pct = [math]::Round(($cpu / $age) * 100, 1) }
    } catch { }
    [pscustomobject]@{
        timestamp = $ts; hostname = $hostName; ip = $ip
        pid = $_.Id; ppid = 0; name = $_.ProcessName + '.exe'
        path = $exe; signature_status = $sig
        cpu_percent = $pct; memory_mb = [math]::Round($_.WorkingSet64 / 1MB, 1)
    }
}
$procs | Export-Csv -Path (Join-Path $InboxDir "process_inv_${stamp}_$hostName.csv") -NoTypeInformation -Encoding UTF8

# --- scheduled tasks -------------------------------------------------------
$tasks = Get-ScheduledTask | ForEach-Object {
    [pscustomobject]@{
        timestamp = $ts; hostname = $hostName; ip = $ip
        task_name = $_.TaskName; task_path = $_.TaskPath
        state = $_.State.ToString()
        command = ($_.Actions | Select-Object -First 1).Execute
        arguments = ($_.Actions | Select-Object -First 1).Arguments
    }
}
$tasks | Export-Csv -Path (Join-Path $InboxDir "tasks_inv_${stamp}_$hostName.csv") -NoTypeInformation -Encoding UTF8

# --- persistence inventory (Run keys + services) --------------------------
$persist = @()
foreach ($hive in 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run',
                  'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run',
                  'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run') {
    try {
        $props = Get-ItemProperty -Path $hive -ErrorAction Stop
        foreach ($p in $props.PSObject.Properties) {
            if ($p.Name -in @('PSPath', 'PSParentPath', 'PSChildName', 'PSDrive', 'PSProvider')) { continue }
            $persist += [pscustomobject]@{
                timestamp = $ts; hostname = $hostName; ip = $ip
                category = 'run_key'; item_name = $p.Name; details = [string]$p.Value
            }
        }
    } catch { }
}
Get-CimInstance Win32_Service | ForEach-Object {
    $persist += [pscustomobject]@{
        timestamp = $ts; hostname = $hostName; ip = $ip
        category = 'service'; item_name = $_.Name
        details = "$($_.PathName) [start=$($_.StartMode)]"
    }
}
$persist | Export-Csv -Path (Join-Path $InboxDir "persistence_inv_${stamp}_$hostName.csv") -NoTypeInformation -Encoding UTF8

# --- Defender status -------------------------------------------------------
$excl = @()
try {
    $mp = Get-MpPreference -ErrorAction Stop
    $excl += $mp.ExclusionPath; $excl += $mp.ExclusionProcess; $excl += $mp.ExclusionExtension
} catch { }
$mpStatus = $null
try { $mpStatus = Get-MpComputerStatus -ErrorAction Stop } catch { }
$status = [pscustomobject]@{
    timestamp = $ts; hostname = $hostName; ip = $ip
    real_time_protection = if ($mpStatus) { if ($mpStatus.RealTimeProtectionEnabled) { 'enabled' } else { 'disabled' } } else { 'unknown' }
    service_status = if ($mpStatus) { $mpStatus.AMServiceEnabled.ToString().ToLower() } else { 'unknown' }
    antivirus_signature_age = if ($mpStatus) { $mpStatus.AntivirusSignatureAge } else { '' }
    exclusions = (@($excl) | Where-Object { $_ }) -join ';'
}
$status | Export-Csv -Path (Join-Path $InboxDir "defender_status_${stamp}_$hostName.csv") -NoTypeInformation -Encoding UTF8

# --- optional: recently executed binaries with hashes (metadata only) -----
if ($IncludeFileHashes) {
    $hashes = $procs | Where-Object path | Sort-Object path -Unique | ForEach-Object {
        try {
            $h = Get-FileHash -Path $_.path -Algorithm SHA256 -ErrorAction Stop
            [pscustomobject]@{
                timestamp = $ts; hostname = $hostName; ip = $ip
                pid = $_.pid; name = $_.name; path = $_.path; sha256 = $h.Hash.ToLower()
            }
        } catch { }
    }
    $hashes | Export-Csv -Path (Join-Path $InboxDir "file_activity_${stamp}_$hostName.csv") -NoTypeInformation -Encoding UTF8
}

Write-Host "Inventory exported for $hostName ($($procs.Count) processes, $($tasks.Count) tasks, $($persist.Count) persistence items)"
