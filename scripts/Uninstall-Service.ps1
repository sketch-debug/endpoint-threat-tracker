# Uninstall-Service.ps1 — stop and remove the tracker service.
[CmdletBinding()]
param([string]$ServiceName = 'EndpointThreatTracker',
      [string]$Nssm = 'nssm')
$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
$nssmExe = if (Test-Path (Join-Path $root 'nssm.exe')) { Join-Path $root 'nssm.exe' } else { $Nssm }

& $nssmExe stop $ServiceName 2>$null | Out-Null
& $nssmExe remove $ServiceName confirm
Write-Host "Service '$ServiceName' removed (data and config kept)."
