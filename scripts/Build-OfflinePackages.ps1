# Build-OfflinePackages.ps1 — build every pinned dependency into a wheel in
# packages\ so the target machine can install with NO internet access.
#
# Run on any Windows machine with internet (same Python version as target):
#   powershell -ExecutionPolicy Bypass -File scripts\Build-OfflinePackages.ps1
#
# Wheels only, never sdists: whenever the index has no wheel for this Python,
# `pip download` would leave an sdist behind, and an sdist cannot be installed
# offline (building it needs setuptools from an index). Running the target's
# install with --no-index then fails, so we resolve everything while still
# online with `pip wheel` instead.
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

& $Python -m pip wheel --requirement $requirements --wheel-dir $OutDir
if ($LASTEXITCODE -ne 0) { throw "pip wheel failed" }

$count = (Get-ChildItem $OutDir -File).Count
Write-Host "Built $count wheel files in $OutDir"
Write-Host "Copy the whole project folder (including packages\) to the target machine."
