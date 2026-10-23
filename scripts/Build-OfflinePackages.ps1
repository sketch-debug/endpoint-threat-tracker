# Build-OfflinePackages.ps1 — download all pinned dependencies into packages\
# so the target machine can install with NO internet access.
#
# Run on any Windows machine with internet (same Python version as target):
#   powershell -ExecutionPolicy Bypass -File scripts\Build-OfflinePackages.ps1
#
# On the target (see README "Offline install"):
#   .venv\Scripts\python -m pip install --no-index --find-links packages -r requirements.txt
[CmdletBinding()]
param(
    [string]$Python = 'python',
    [string]$OutDir = ''
)
$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
if (-not $OutDir) { $OutDir = Join-Path $root 'packages' }
$requirements = Join-Path $root 'requirements.txt'

$version = & $Python --version
Write-Host "Using $version (target machine must run the SAME major.minor)"
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

& $Python -m pip download --requirement $requirements --dest $OutDir
if ($LASTEXITCODE -ne 0) { throw "pip download failed" }

$count = (Get-ChildItem $OutDir -File).Count
Write-Host "Downloaded $count files to $OutDir"
Write-Host "Copy the whole project folder (including packages\) to the target machine."
