# Install-Service.ps1 — register the tracker as a Windows service via NSSM.
#
# Run elevated from the project root:
#   powershell -ExecutionPolicy Bypass -File scripts\Install-Service.ps1
#
# Requires nssm.exe in the project root or on PATH (https://nssm.cc, MIT).
# The service runs the app with the venv Python; logs go to logs\service*.log.
[CmdletBinding()]
param(
    [string]$ServiceName = 'EndpointThreatTracker',
    [string]$Python = '',
    [string]$Nssm = 'nssm'
)
$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent

if (-not $Python) {
    $venvPy = Join-Path $root '.venv\Scripts\python.exe'
    $Python = if (Test-Path $venvPy) { $venvPy } else { (Get-Command python.exe).Source }
}
$nssmExe = if (Test-Path (Join-Path $root 'nssm.exe')) { Join-Path $root 'nssm.exe' } else { $Nssm }
if (-not (Get-Command $nssmExe -ErrorAction SilentlyContinue)) {
    throw "nssm.exe not found. Download it from https://nssm.cc and place it in $root"
}

$logs = Join-Path $root 'logs'
New-Item -ItemType Directory -Force -Path $logs | Out-Null

& $nssmExe stop $ServiceName 2>$null | Out-Null
& $nssmExe remove $ServiceName confirm 2>$null | Out-Null

& $nssmExe install $ServiceName $Python "-m" "app.main"
& $nssmExe set $ServiceName AppDirectory $root
& $nssmExe set $ServiceName Start SERVICE_AUTO_START
& $nssmExe set $ServiceName AppStdout (Join-Path $logs 'service.out.log')
& $nssmExe set $ServiceName AppStderr (Join-Path $logs 'service.err.log')
& $nssmExe set $ServiceName AppRotateFiles 1
& $nssmExe set $ServiceName AppRotateBytes 10485760

Write-Host "Service '$ServiceName' installed."
Write-Host "Start it with:  Start-Service $ServiceName"
Write-Host "Dashboard:      http://127.0.0.1:8043/"
