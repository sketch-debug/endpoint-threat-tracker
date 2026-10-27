# Uninstall-Service.ps1 — stop and remove the tracker service.
[CmdletBinding()]
param([string]$ServiceName = 'EndpointThreatTracker',
      [string]$Nssm = 'nssm')
$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
$nssmExe = if (Test-Path (Join-Path $root 'nssm.exe')) { Join-Path $root 'nssm.exe' } else { $Nssm }

# Best-effort stop + remove. nssm writes to stderr when the service is
# missing/stopped; under $ErrorActionPreference='Stop' that becomes a
# terminating NativeCommandError, so relax EAP across both calls.
$prevEap = $ErrorActionPreference
$ErrorActionPreference = 'Continue'
& $nssmExe stop $ServiceName 2>$null | Out-Null
& $nssmExe remove $ServiceName confirm 2>$null | Out-Null
$ErrorActionPreference = $prevEap
Write-Host "Service '$ServiceName' removed (data and config kept)."
