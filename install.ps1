#Requires -Version 5.1
<#
.SYNOPSIS
    One-command installer for the Endpoint Threat Detection & Incident Tracker.

.DESCRIPTION
    Verifies Python 3.10+, creates or repairs .venv, installs the pinned
    dependencies (from packages\ when present, otherwise from PyPI), creates
    .env with a generated SECRET_KEY and a dashboard admin password, then
    starts the dashboard.

    Rerunning is safe: a healthy .venv and an existing .env are reused, and
    pip is skipped when requirements.txt has not changed. No administrator
    rights are needed for this foreground setup; for the Windows service run
    install.bat -NoStart first, then scripts\Install-Service.ps1 elevated.

.PARAMETER AdminPassword
    Dashboard password for the first login. When omitted on a fresh .env the
    installer prompts in an interactive console, or generates a random one
    (printed once) when input is redirected.

.PARAMETER NoStart
    Set everything up but do not start the dashboard.

.PARAMETER Offline
    Require packages\ and never contact PyPI.

.PARAMETER Force
    Reinstall dependencies even when requirements.txt is unchanged.

.EXAMPLE
    install.bat

.EXAMPLE
    install.bat -NoStart

.EXAMPLE
    install.bat -Offline -NoStart
#>
[CmdletBinding()]
param(
    [string]$AdminPassword = '',
    [switch]$NoStart,
    [switch]$Offline,
    [switch]$Force
)

$ErrorActionPreference = 'Stop'
$Root = $PSScriptRoot
Set-Location -LiteralPath $Root

$VenvDir = Join-Path $Root '.venv'
$VenvPy = Join-Path $VenvDir 'Scripts\python.exe'
$ReqFile = Join-Path $Root 'requirements.txt'
$EnvFile = Join-Path $Root '.env'
$EnvExample = Join-Path $Root '.env.example'
$PackagesDir = Join-Path $Root 'packages'
$MinPython = 310

trap {
    Write-Host ''
    Write-Host "ERROR: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host '       Installation stopped. Fix the problem above and rerun install.bat.' -ForegroundColor Yellow
    exit 1
}

function Write-Step {
    param([string]$Message)
    Write-Host ''
    Write-Host "==> $Message" -ForegroundColor Cyan
}

function Fail {
    param([string]$Message, [string]$Hint = '')
    Write-Host ''
    Write-Host "ERROR: $Message" -ForegroundColor Red
    if ($Hint) {
        Write-Host "       $Hint" -ForegroundColor Yellow
    }
    exit 1
}

function Invoke-External {
    param(
        [Parameter(Mandatory = $true)][string]$FilePath,
        [string[]]$Arguments = @()
    )
    $previous = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        & $FilePath @Arguments | Out-Host
        return $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $previous
    }
}

function Get-PythonVersion {
    param(
        [Parameter(Mandatory = $true)][string]$FilePath,
        [string[]]$Arguments = @()
    )
    $argList = @($Arguments) + @('-c', 'import sys; print(sys.version_info[0] * 100 + sys.version_info[1])')
    $previous = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $output = & $FilePath @argList 2>$null
        $code = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $previous
    }
    if ($code -ne 0) {
        return 0
    }
    $value = $output | Where-Object { "$_" -match '^\d+$' } | Select-Object -Last 1
    if (-not $value) {
        return 0
    }
    return [int]$value
}

function Find-BasePython {
    $candidates = @()
    $py = Get-Command py -ErrorAction SilentlyContinue
    if ($py) {
        $candidates += [pscustomobject]@{ Exe = $py.Source; Prefix = @('-3') }
    }
    $python = Get-Command python -ErrorAction SilentlyContinue
    if ($python) {
        $candidates += [pscustomobject]@{ Exe = $python.Source; Prefix = @() }
    }
    foreach ($candidate in $candidates) {
        $version = Get-PythonVersion -FilePath $candidate.Exe -Arguments $candidate.Prefix
        if ($version -ge $MinPython) {
            return [pscustomobject]@{
                Exe = $candidate.Exe
                Prefix = $candidate.Prefix
                Version = $version
            }
        }
    }
    return $null
}

function Test-VenvPython {
    if (-not (Test-Path -LiteralPath $VenvPy)) {
        return $false
    }
    return (Get-PythonVersion -FilePath $VenvPy) -ge $MinPython
}

function ConvertFrom-SecureStringPlain {
    param([Parameter(Mandatory = $true)][securestring]$SecureString)
    if ($SecureString.Length -eq 0) {
        return ''
    }
    $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecureString)
    try {
        return [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
    } finally {
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
    }
}

Write-Host ''
Write-Host 'Endpoint Threat Detection & Incident Tracker - installer' -ForegroundColor Green
Write-Host "Project: $Root"

# ---- Python ---------------------------------------------------------------
Write-Step 'Checking Python'
$basePython = Find-BasePython
if ($null -eq $basePython) {
    Fail 'Python 3.10 or newer was not found.' "Install it from https://www.python.org/downloads/ (tick 'Add python.exe to PATH'), then rerun install.bat."
}
$versionText = '{0}.{1}' -f ([math]::Floor($basePython.Version / 100)), ($basePython.Version % 100)
Write-Host "Using Python $versionText ($($basePython.Exe))"

# ---- Virtual environment --------------------------------------------------
Write-Step 'Preparing the virtual environment'
if (Test-VenvPython) {
    Write-Host 'Reusing the existing .venv'
} else {
    if (Test-Path -LiteralPath $VenvDir) {
        Write-Host 'Existing .venv is missing or broken; recreating it.'
        Remove-Item -LiteralPath $VenvDir -Recurse -Force
    }
    Write-Host 'Creating .venv ...'
    $argList = @($basePython.Prefix) + @('-m', 'venv', $VenvDir)
    $code = Invoke-External -FilePath $basePython.Exe -Arguments $argList
    if ($code -ne 0 -or -not (Test-Path -LiteralPath $VenvPy)) {
        Fail 'Could not create the virtual environment.' "Try manually: $($basePython.Exe) $($basePython.Prefix -join ' ') -m venv .venv"
    }
}

# ---- Dependencies ---------------------------------------------------------
Write-Step 'Installing pinned dependencies'
if (-not (Test-Path -LiteralPath $ReqFile)) {
    Fail 'requirements.txt is missing.' 'The project copy is incomplete.'
}

$requirementsHash = (Get-FileHash -LiteralPath $ReqFile -Algorithm SHA256).Hash
$markerFile = Join-Path $VenvDir 'requirements.sha256'
$installedHash = ''
if (Test-Path -LiteralPath $markerFile) {
    $installedHash = (Get-Content -LiteralPath $markerFile -Raw).Trim()
}

$hasPackages = $false
if (Test-Path -LiteralPath $PackagesDir) {
    $packageFiles = Get-ChildItem -LiteralPath $PackagesDir -File -ErrorAction SilentlyContinue
    $hasPackages = ($packageFiles | Measure-Object).Count -gt 0
}

if ($Offline -and -not $hasPackages) {
    Fail 'Offline install requested, but packages\ is missing or empty.' 'On a connected machine run: powershell -ExecutionPolicy Bypass -File scripts\Build-OfflinePackages.ps1, copy the packages\ folder here, then rerun install.bat -Offline.'
}

if ($installedHash -eq $requirementsHash -and -not $Force) {
    Write-Host 'Dependencies already match requirements.txt; skipping pip.'
} else {
    $installed = $false
    if ($hasPackages) {
        Write-Host 'Installing from packages\ (offline) ...'
        $argList = @('-m', 'pip', 'install', '--no-index', '--find-links', $PackagesDir,
                     '--no-input', '--disable-pip-version-check', '-r', $ReqFile)
        $code = Invoke-External -FilePath $VenvPy -Arguments $argList
        if ($code -eq 0) {
            $installed = $true
        } elseif ($Offline) {
            Fail 'Offline dependency installation failed.' 'Make sure packages\ was built with the same Python major.minor as this machine.'
        } else {
            Write-Host 'Offline install failed; falling back to the online package index ...' -ForegroundColor Yellow
        }
    }
    if (-not $installed -and -not $Offline) {
        if (-not $hasPackages) {
            Write-Host 'Installing from the online package index ...'
        }
        $argList = @('-m', 'pip', 'install', '--no-input', '--disable-pip-version-check', '-r', $ReqFile)
        $code = Invoke-External -FilePath $VenvPy -Arguments $argList
        if ($code -eq 0) {
            $installed = $true
        }
    }
    if (-not $installed) {
        Fail 'Dependency installation failed.' 'Check access to pypi.org (or your proxy), then rerun. For isolated machines, build packages\ with scripts\Build-OfflinePackages.ps1.'
    }
    Set-Content -LiteralPath $markerFile -Value $requirementsHash -NoNewline
}

Write-Step 'Verifying the installation'
$importOk = $false
$previous = $ErrorActionPreference
$ErrorActionPreference = 'Continue'
try {
    & $VenvPy -c 'import app.main' 2>$null
    $importOk = ($LASTEXITCODE -eq 0)
} finally {
    $ErrorActionPreference = $previous
}
if (-not $importOk) {
    Write-Host 'The application could not be imported. Python reported:' -ForegroundColor Red
    Invoke-External -FilePath $VenvPy -Arguments @('-c', 'import app.main')
    Fail 'The installed dependencies cannot run the application.' 'Fix the error above (a mismatch between packages\ and this Python version is common), then rerun install.bat -Force.'
}
Write-Host 'Application imports cleanly.'

# ---- .env -----------------------------------------------------------------
Write-Step 'Preparing .env'
if (-not (Test-Path -LiteralPath $EnvExample)) {
    Fail '.env.example is missing.' 'The project copy is incomplete.'
}

$envExists = Test-Path -LiteralPath $EnvFile
$generatedPassword = ''
$newPassword = ''

if (-not $envExists) {
    $newPassword = $AdminPassword
    if (-not $newPassword) {
        $interactive = $false
        try {
            $interactive = -not [Console]::IsInputRedirected
        } catch {
            $interactive = $false
        }
        if ($interactive) {
            Write-Host 'Choose the dashboard admin password (used for the first login).'
            $secure = Read-Host -AsSecureString 'Admin password (leave blank to generate one)'
            $newPassword = ConvertFrom-SecureStringPlain -SecureString $secure
        }
    }
    if (-not $newPassword) {
        $newPassword = [guid]::NewGuid().ToString('N').Substring(0, 16)
        $generatedPassword = $newPassword
    }
    $newPassword = $newPassword.Trim()
    if ($newPassword.Length -lt 8) {
        Fail 'The admin password must be at least 8 characters.' 'Rerun install.bat -AdminPassword "<longer password>" or enter one at the prompt.'
    }
}

if (-not $envExists) {
    Copy-Item -LiteralPath $EnvExample -Destination $EnvFile
    Write-Host 'Created .env from .env.example'
} else {
    Write-Host 'Using the existing .env'
}

$lines = [System.IO.File]::ReadAllLines($EnvFile)
$changed = $false

for ($i = 0; $i -lt $lines.Count; $i++) {
    if ($lines[$i] -match '^SECRET_KEY=' -and $lines[$i] -match 'change-me') {
        $secret = [guid]::NewGuid().ToString('N') + [guid]::NewGuid().ToString('N')
        $lines[$i] = "SECRET_KEY=$secret"
        $changed = $true
        Write-Host 'Generated a random SECRET_KEY in .env'
    }
}

$adminIndex = -1
$currentPassword = ''
for ($i = 0; $i -lt $lines.Count; $i++) {
    if ($lines[$i] -match '^TRACKER_ADMIN_PASSWORD=') {
        $adminIndex = $i
        $currentPassword = $lines[$i].Substring($lines[$i].IndexOf('=') + 1)
        break
    }
}

$defaultPasswordInUse = $envExists -and ($currentPassword -eq 'admin1234')
$shouldSetAdmin = $false

if (-not $envExists) {
    $shouldSetAdmin = $true
} elseif ($AdminPassword) {
    $candidate = $AdminPassword.Trim()
    if ($candidate.Length -lt 8) {
        Fail 'The admin password must be at least 8 characters.' 'Pass a longer value to -AdminPassword.'
    }
    if ($currentPassword -eq 'admin1234') {
        $shouldSetAdmin = $true
        $newPassword = $candidate
    } else {
        Write-Host 'Note: .env already has an admin password; -AdminPassword was ignored.' -ForegroundColor Yellow
    }
}

if ($shouldSetAdmin) {
    if ($adminIndex -ge 0) {
        $lines[$adminIndex] = "TRACKER_ADMIN_PASSWORD=$newPassword"
    } else {
        $lines += "TRACKER_ADMIN_PASSWORD=$newPassword"
    }
    $changed = $true
    $defaultPasswordInUse = $false
}

if ($changed) {
    [System.IO.File]::WriteAllLines($EnvFile, $lines)
}

if ($generatedPassword) {
    Write-Host ''
    Write-Host "Generated admin password: $generatedPassword" -ForegroundColor Yellow
    Write-Host 'It is stored in .env as TRACKER_ADMIN_PASSWORD; change it after the first login.'
}
if ($defaultPasswordInUse) {
    Write-Host ''
    Write-Host 'WARNING: .env still uses the default admin password (admin1234).' -ForegroundColor Yellow
    Write-Host '         Change it on the Users page after the first login.'
}

# ---- Launch ---------------------------------------------------------------
$port = 8043
$previous = $ErrorActionPreference
$ErrorActionPreference = 'Continue'
try {
    $portOutput = & $VenvPy -c 'from app.config import Settings; print(Settings().port)' 2>$null
    if ($LASTEXITCODE -eq 0 -and $portOutput) {
        $candidate = ($portOutput | Select-Object -Last 1).Trim()
        if ($candidate -match '^\d+$') {
            $port = [int]$candidate
        }
    }
} finally {
    $ErrorActionPreference = $previous
}

Write-Host ''
Write-Host 'Setup complete.' -ForegroundColor Green
Write-Host "Dashboard:  http://127.0.0.1:$port/"
Write-Host 'First login: admin / the password in .env (TRACKER_ADMIN_PASSWORD)'
Write-Host 'Demo data:  .venv\Scripts\python generator\generate_fake_data.py --into-inbox'
Write-Host 'Docs:       README.md and ADMIN_GUIDE.md'

if ($NoStart) {
    Write-Host ''
    Write-Host 'Setup only (-NoStart). Start later with start.bat or .venv\Scripts\python -m app.main'
    exit 0
}

Write-Host ''
Write-Host 'Starting the dashboard (Ctrl+C to stop) ...' -ForegroundColor Cyan
$code = Invoke-External -FilePath $VenvPy -Arguments @('-m', 'app.main')
exit $code
