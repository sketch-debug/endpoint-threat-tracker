# smoke_test.ps1 - end-to-end smoke test with fake data.
# Starts or reuses the app, logs in as each role, feeds fake files through
# the pipeline, and checks detection -> incident -> alert -> report.
# Prints PASS/FAIL per step; exits non-zero if any step fails.
#
# Usage:  powershell -NoProfile -ExecutionPolicy Bypass -File smoke_test.ps1
#      or: smoke_test.bat
[CmdletBinding()]
param(
    [int]$StartTimeoutSec = 120,
    [int]$ParseTimeoutSec = 180,
    [int]$StageTimeoutSec = 120
)
$ErrorActionPreference = 'Continue'
$root = $PSScriptRoot
$venvPy = Join-Path $root '.venv\Scripts\python.exe'
$dbPath = Join-Path $root 'data\tracker.db'
$inbox = Join-Path $root 'inbox'
$smokeUserPw = 'SmokeTest123!'

$results = New-Object System.Collections.ArrayList

function Report([string]$name, [bool]$ok, [string]$detail = '') {
    $tag = if ($ok) { 'PASS' } else { 'FAIL' }
    $line = '{0}  {1}' -f $tag, $name
    if ($detail) { $line = $line + ' - ' + $detail }
    Write-Host $line
    [void]$results.Add([pscustomobject]@{ Name = $name; Ok = $ok })
}

function Get-DbCount([string]$sql) {
    $code = @'
import sqlite3, sys
con = sqlite3.connect(sys.argv[1])
print(con.execute(sys.argv[2]).fetchone()[0])
'@
    $out = & $venvPy -c $code $dbPath $sql 2>$null
    $n = 0
    if ("$out" -match '^\s*(\d+)') { $n = [int]$Matches[1] }
    return $n
}

function Get-StatusCode([string]$url) {
    $code = & curl.exe -s -o NUL -w "%{http_code}" --max-time 10 $url 2>$null
    return "$code"
}

# ---- resolve config -------------------------------------------------------
if (-not (Test-Path $venvPy)) {
    Report 'virtual environment present' $false '.venv missing - run install.bat first'
    Write-Host ''
    Write-Host 'SMOKE: 0/1 steps passed'
    exit 1
}

# A .venv older than requirements.txt will launch python, then die deep in a
# traceback with ModuleNotFoundError (seen here when `requests` was added),
# which reads like an app bug. Fail first, plainly, and say how to fix it.
# The checker uses only single quotes: Windows PowerShell mangles embedded
# double quotes when passing a -c script to a native process.
$depCheck = @'
import importlib.metadata as md, sys
missing = []
for line in open(sys.argv[1], encoding='utf-8'):
    line = line.split('#')[0].strip()
    if not line or '==' not in line:
        continue
    name = line.split('==')[0].strip()
    try:
        md.version(name)
    except md.PackageNotFoundError:
        missing.append(name)
print('; '.join(missing))
'@
$missingDeps = ((& $venvPy -c $depCheck (Join-Path $root 'requirements.txt') 2>$null) -join '').Trim()
if ($missingDeps) {
    Report 'virtual environment up to date' $false "missing from .venv: $missingDeps - run install.bat (or .venv\Scripts\python.exe -m pip install -r requirements.txt), then rerun this script"
    Write-Host ''
    Write-Host 'SMOKE: 0/1 steps passed'
    exit 1
}
Report 'virtual environment up to date' $true 'all requirements.txt packages installed'

$adminPw = $env:TRACKER_ADMIN_PASSWORD
$port = 8043
$envFile = Join-Path $root '.env'
if (Test-Path $envFile) {
    foreach ($line in Get-Content $envFile) {
        if (-not $adminPw -and $line -match '^\s*TRACKER_ADMIN_PASSWORD\s*=\s*(.+)$') {
            $adminPw = $Matches[1].Trim().Trim('"').Trim("'")
        }
    }
}
if (-not $adminPw) { $adminPw = 'admin1234' }
$cfgFile = Join-Path $root 'config\app_config.yaml'
if (Test-Path $cfgFile) {
    $cfgText = Get-Content $cfgFile -Raw
    if ($cfgText -match '(?m)^\s*port:\s*(\d+)') { $port = [int]$Matches[1] }
}
$base = 'http://127.0.0.1:{0}' -f $port

# Start-Process redirection silently yields a child that never serves when the
# target directory is missing (fresh installs have no logs\ yet), so create it.
New-Item -ItemType Directory -Force -Path (Join-Path $root 'logs') | Out-Null

# ---- step 1: app starts ---------------------------------------------------
$startedByUs = $false
$serverProc = $null
$code = Get-StatusCode "$base/login"
if ($code -eq '200') {
    Report 'app starts' $true 'reusing the running instance'
} else {
    $outLog = Join-Path $root 'logs\smoke-server.out.log'
    $errLog = Join-Path $root 'logs\smoke-server.err.log'
    $serverProc = Start-Process -FilePath $venvPy -ArgumentList '-m', 'app.main' `
        -WorkingDirectory $root -PassThru -NoNewWindow `
        -RedirectStandardOutput $outLog -RedirectStandardError $errLog
    $startedByUs = $true
    $deadline = (Get-Date).AddSeconds($StartTimeoutSec)
    while ((Get-Date) -lt $deadline) {
        if ($serverProc.HasExited) { break }
        if ((Get-StatusCode "$base/login") -eq '200') { break }
        Start-Sleep -Seconds 1
    }
    $code = Get-StatusCode "$base/login"
    if ($serverProc.HasExited) {
        Report 'app starts' $false "process exited with code $($serverProc.ExitCode); see logs\smoke-server.err.log"
    } elseif ($code -eq '200') {
        Report 'app starts' $true "pid $($serverProc.Id), /login=200"
    } else {
        Report 'app starts' $false "/login=$code after $StartTimeoutSec s; see logs\smoke-server.*.log"
    }
}

# ---- step 2: dashboard responds ------------------------------------------
$appUp = ($code -eq '200')
$rootCode = Get-StatusCode "$base/"
Report 'dashboard responds' ($code -eq '200' -and $rootCode -eq '303') "/login=$code /=$rootCode (expect 200/303)"

# ---- helper: login, returns WebRequestSession or $null --------------------
function Invoke-Login([string]$username, [string]$password) {
    $s = New-Object Microsoft.PowerShell.Commands.WebRequestSession
    try {
        $r = Invoke-WebRequest "$base/login" -Method Post `
            -Body @{ username = $username; password = $password } `
            -WebSession $s -UseBasicParsing -TimeoutSec 15
        if ($r.StatusCode -eq 200 -and $r.BaseResponse.ResponseUri.AbsolutePath -eq '/') {
            return $s
        }
    } catch { }
    return $null
}

# ---- step 3: admin login --------------------------------------------------
$adminS = Invoke-Login 'admin' $adminPw
Report 'login works (admin)' ($null -ne $adminS) $(if ($adminS) { 'session established' } else { 'check TRACKER_ADMIN_PASSWORD in .env' })

# ---- steps 4+5: analyst and viewer logins (create smoke users first) ------
function New-SmokeUser([string]$username, [string]$role) {
    # remove leftovers from an earlier run, then create fresh
    try {
        Invoke-WebRequest "$base/users/$username/delete" -Method Post `
            -WebSession $adminS -UseBasicParsing -TimeoutSec 15 | Out-Null
    } catch { }
    try {
        $r = Invoke-WebRequest "$base/users" -Method Post `
            -Body @{ username = $username; password = $smokeUserPw; role = $role } `
            -WebSession $adminS -UseBasicParsing -TimeoutSec 15
        return $true
    } catch { return $false }
}

$analystS = $null
$viewerS = $null
if ($adminS) {
    $madeAnalyst = New-SmokeUser 'smoke_analyst' 'analyst'
    $analystS = Invoke-Login 'smoke_analyst' $smokeUserPw
    Report 'login works (analyst)' ($null -ne $analystS) `
        $(if ($analystS) { 'smoke_analyst session established' } elseif (-not $madeAnalyst) { 'could not create smoke_analyst' } else { 'login failed for created user' })
} else {
    Report 'login works (analyst)' $false 'admin session unavailable'
}

if ($adminS) {
    $madeViewer = New-SmokeUser 'smoke_viewer' 'viewer'
    $viewerS = Invoke-Login 'smoke_viewer' $smokeUserPw
    Report 'login works (viewer)' ($null -ne $viewerS) `
        $(if ($viewerS) { 'smoke_viewer session established' } elseif (-not $madeViewer) { 'could not create smoke_viewer' } else { 'login failed for created user' })
} else {
    Report 'login works (viewer)' $false 'admin session unavailable'
}

# ---- step 6: sample files dropped in the inbox are parsed ------------------
$filesBefore = Get-DbCount 'SELECT COUNT(*) FROM files'
$genOk = $false
$genN = 0
if (-not $appUp) {
    Report 'sample files parsed' $false 'app is not serving - cannot ingest'
}
$genOut = if ($appUp) { & $venvPy (Join-Path $root 'generator\generate_fake_data.py') --into-inbox 2>&1 } else { '' }
$genOut = "$genOut"
if ($LASTEXITCODE -eq 0 -and $genOut -match 'generated (\d+) fake files') {
    $genOk = $true
    $genN = [int]$Matches[1]
}
if (-not $appUp) {
    # already reported above; skip the wait
} elseif (-not $genOk) {
    Report 'sample files parsed' $false "generator failed: $genOut"
} else {
    $deadline = (Get-Date).AddSeconds($ParseTimeoutSec)
    $parsedOk = $false
    while ((Get-Date) -lt $deadline) {
        $rootLeft = @(Get-ChildItem -LiteralPath $inbox -File -ErrorAction SilentlyContinue).Count
        $filesNow = Get-DbCount 'SELECT COUNT(*) FROM files'
        # Every path (ingest, duplicate, error) moves the file out of the inbox
        # root, and a working ingest also writes the files ledger.
        if ($rootLeft -eq 0 -and $filesNow -gt 0) { $parsedOk = $true; break }
        Start-Sleep -Seconds 3
    }
    $filesNow = Get-DbCount 'SELECT COUNT(*) FROM files'
    $rootLeft = @(Get-ChildItem -LiteralPath $inbox -File -ErrorAction SilentlyContinue).Count
    Report 'sample files parsed' $parsedOk "$genN files dropped, files table $filesBefore -> $filesNow, inbox root left=$rootLeft"
}

# ---- step 7: a detection fires -------------------------------------------
function Wait-DbCount([string]$name, [string]$sql, [string]$expectDesc) {
    if (-not $appUp) {
        Report $name $false 'app is not serving - skipped waiting'
        return 0
    }
    $deadline = (Get-Date).AddSeconds($StageTimeoutSec)
    $n = Get-DbCount $sql
    while ((Get-Date) -lt $deadline -and $n -le 0) {
        Start-Sleep -Seconds 3
        $n = Get-DbCount $sql
    }
    Report $name ($n -gt 0) "$expectDesc = $n"
    return $n
}

$signals = Wait-DbCount 'detection fires' 'SELECT COUNT(*) FROM signals' 'signals'

# ---- step 8: an incident opens -------------------------------------------
$incidents = Wait-DbCount 'incident opens' 'SELECT COUNT(*) FROM incidents' 'incidents'

# ---- step 9: an alert is attempted ---------------------------------------
$alerts = Wait-DbCount 'alert attempted' 'SELECT COUNT(*) FROM alerts_log' 'alerts_log'

# ---- step 10: a report generates -----------------------------------------
$reportOk = $false
$reportDetail = 'no incident to report on'
if ($incidents -gt 0 -and $analystS) {
    $lastId = 0
    $idOut = & $venvPy -c "import sqlite3,sys;print(sqlite3.connect(sys.argv[1]).execute('SELECT id FROM incidents ORDER BY id DESC LIMIT 1').fetchone()[0])" $dbPath 2>$null
    if ("$idOut" -match '^\s*(\d+)') { $lastId = [int]$Matches[1] }
    if ($lastId -gt 0) {
        try {
            $r = Invoke-WebRequest "$base/incidents/$lastId/report" -WebSession $analystS -UseBasicParsing -TimeoutSec 20
            $reportOk = ($r.StatusCode -eq 200 -and $r.Content -match '<html')
            $reportDetail = "GET /incidents/$lastId/report -> $($r.StatusCode), html=$($r.Content -match '<html')"
        } catch {
            $reportDetail = $_.Exception.Message
        }
    }
} elseif (-not $analystS) {
    $reportDetail = 'analyst session unavailable'
}
Report 'report generates' $reportOk $reportDetail

# ---- cleanup: remove smoke users, stop the app if we started it -----------
if ($adminS) {
    foreach ($u in @('smoke_analyst', 'smoke_viewer')) {
        try {
            Invoke-WebRequest "$base/users/$u/delete" -Method Post `
                -WebSession $adminS -UseBasicParsing -TimeoutSec 15 | Out-Null
        } catch { Write-Host "note: could not remove smoke user $u" }
    }
}
if ($startedByUs -and $serverProc -and -not $serverProc.HasExited) {
    Stop-Process -Id $serverProc.Id -Force
    Write-Host 'note: stopped the app instance this script started'
}

# ---- summary --------------------------------------------------------------
$failed = @($results | Where-Object { -not $_.Ok })
Write-Host ''
Write-Host ('SMOKE: {0}/{1} steps passed' -f ($results.Count - $failed.Count), $results.Count)
if ($failed.Count -gt 0) {
    Write-Host ('FAILED: ' + (($failed | ForEach-Object { $_.Name }) -join ', '))
    exit 1
}
exit 0
