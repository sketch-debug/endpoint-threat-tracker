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
# default only: paths.db_path in config/app_config.yaml overrides it below,
# because that is the database the running instance actually writes to
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

# Report a failure that makes every remaining step meaningless, print the same
# summary the script prints at the end, and exit non-zero.
function Abort([string]$name, [string]$detail) {
    Report $name $false $detail
    # the normal end-of-script cleanup never runs once we exit here, so stop an
    # instance this run started instead of leaving it behind
    if ($startedByUs -and $serverProc -and -not $serverProc.HasExited) {
        Stop-Process -Id $serverProc.Id -Force
        Write-Host 'note: stopped the app instance this script started'
    }
    $bad = @($results | Where-Object { -not $_.Ok })
    Write-Host ''
    Write-Host ('SMOKE: {0}/{1} steps passed' -f ($results.Count - $bad.Count), $results.Count)
    Write-Host ('FAILED: ' + (($bad | ForEach-Object { $_.Name }) -join ', '))
    exit 1
}

function Get-DbCount([string]$sql) {
    $code = @'
import sqlite3, sys
con = sqlite3.connect(sys.argv[1])
print(con.execute(sys.argv[2]).fetchone()[0])
'@
    $out = & $venvPy -c $code $dbPath $sql 2>$null
    # -1 means "could not count" (python crashed, database locked). A failed
    # read must never be mistaken for an empty table: a baseline of 0 read from
    # an unreadable database would make every later count look like growth.
    $n = -1
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
try:
    lines = open(sys.argv[1], encoding='utf-8').read().splitlines()
except OSError as exc:
    print('CHECK-FAILED cannot read requirements: ' + str(exc))
    raise SystemExit(3)
missing = []
for line in lines:
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
# The check must not be able to pass by failing. An empty stdout used to be
# read as "nothing missing", so a crashed interpreter or a missing
# requirements.txt reported all packages installed; stderr was discarded and
# $LASTEXITCODE was never looked at. Keep both and fail closed.
$reqFile = Join-Path $root 'requirements.txt'
$depFailed = $false
$depWhy = ''
if (-not (Test-Path $reqFile)) {
    $depFailed = $true
    $depWhy = 'requirements.txt not found next to smoke_test.ps1 - nothing to check the .venv against'
} else {
    $depOut = @(& $venvPy -c $depCheck $reqFile 2>&1)
    $depExit = $LASTEXITCODE
    $depText = (($depOut | ForEach-Object { "$_" }) -join ' ').Trim()
    if ($depExit -ne 0) {
        $depFailed = $true
        $depWhy = "the dependency check itself failed (python exit $depExit): $depText"
    } elseif ($depText) {
        $depFailed = $true
        $depWhy = "missing from .venv: $depText - run install.bat (or .venv\Scripts\python.exe -m pip install -r requirements.txt), then rerun this script"
    }
}
if ($depFailed) {
    Report 'virtual environment up to date' $false $depWhy
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
    # Same file the app resolves its paths from: counting against a hardcoded
    # data\tracker.db would measure a different database once paths.db_path
    # is repointed (a second site, a mounted volume, a renamed file).
    if ($cfgText -match '(?m)^\s*db_path:\s*(.+?)\s*$') {
        $dbRel = $Matches[1].Trim().Trim('"').Trim("'")
        if ([System.IO.Path]::IsPathRooted($dbRel)) {
            $dbPath = $dbRel
        } else {
            $dbPath = Join-Path $root ($dbRel -replace '/', '\')
        }
    }
}
$base = 'http://127.0.0.1:{0}' -f $port

# Start-Process redirection silently yields a child that never serves when the
# target directory is missing (fresh installs have no logs\ yet), so create it.
New-Item -ItemType Directory -Force -Path (Join-Path $root 'logs') | Out-Null

# ---- step 1: app starts ---------------------------------------------------
$startedByUs = $false
$serverProc = $null
$code = Get-StatusCode "$base/login"
$reused = ($code -eq '200')
if (-not $reused) {
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
}

# Reusing is decided by /login=200 alone, which ANY process bound to the port
# answers - including a stale build. Old code then serves steps 2-5 while the
# database rows left by an earlier run carry steps 6-9, and the whole smoke
# passes without this checkout ever executing. /health reports the version of
# the code actually serving, so require it to match VERSION first.
$wantVersion = ''
$verFile = Join-Path $root 'VERSION'
if (Test-Path $verFile) { $wantVersion = ((Get-Content $verFile -Raw)).Trim() }
$servedVersion = ''
$healthErr = ''
if ($code -eq '200') {
    # curl, not Invoke-RestMethod: /health answers 503 while the instance is
    # degraded (stale data, low disk, failed cycle), and PowerShell raises on
    # any 5xx before the body - which is where `version` lives - can be read.
    $healthBody = (& curl.exe -s --max-time 10 "$base/health" 2>&1) -join "`n"
    if (-not "$healthBody".Trim()) {
        $healthErr = 'GET /health returned no body (curl.exe missing, or the instance is not answering)'
    } else {
        try {
            $servedVersion = ("$healthBody" | ConvertFrom-Json).version
            $servedVersion = "$servedVersion".Trim()
        } catch {
            $healthErr = "cannot parse the /health payload: $($_.Exception.Message)"
        }
        if (-not $servedVersion -and -not $healthErr) {
            $healthErr = 'the /health payload has no version field'
        }
    }
}
if ($code -ne '200') {
    if ($serverProc -and $serverProc.HasExited) {
        Report 'app starts' $false "process exited with code $($serverProc.ExitCode); see logs\smoke-server.err.log"
    } else {
        Report 'app starts' $false "/login=$code after $StartTimeoutSec s; see logs\smoke-server.*.log"
    }
} elseif (-not $wantVersion) {
    Abort 'app starts' 'this checkout has no VERSION file, so the running build cannot be identified'
} elseif ($servedVersion -ne $wantVersion) {
    $why = if ($servedVersion) {
        "instance on $base serves version $servedVersion but this checkout is $wantVersion - a stale or foreign process is using port ${port}; stop it (Stop-Service EndpointThreatTracker, or Stop-Process -Id <pid>) and rerun"
    } else {
        "instance on $base did not report a version over GET /health ($healthErr) - it is not a current build of this checkout"
    }
    Abort 'app starts' $why
} elseif ($reused) {
    Report 'app starts' $true "reusing the running instance, version $servedVersion"
} else {
    Report 'app starts' $true "pid $($serverProc.Id), /login=200, version $servedVersion"
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
# All baselines are read BEFORE this run drops anything. On a reused instance
# (the default: step 1 reuses by default) every table below already holds rows
# from an earlier run, so steps 6-9 must measure what THIS run adds - counting
# rows that already existed is what let a completely broken pipeline pass.
$filesBefore       = Get-DbCount 'SELECT COUNT(*) FROM files'
$ingestedBefore    = Get-DbCount "SELECT COUNT(*) FROM files WHERE status = 'ingested'"
$quarantinedBefore = Get-DbCount "SELECT COUNT(*) FROM files WHERE status = 'error'"
$sigBase           = Get-DbCount 'SELECT COUNT(*) FROM signals'
$incBase           = Get-DbCount 'SELECT COUNT(*) FROM incidents'
$linkedBase        = Get-DbCount 'SELECT COUNT(*) FROM signals WHERE incident_id IS NOT NULL'
$alertBase         = Get-DbCount "SELECT COUNT(*) FROM alerts_log WHERE incident_id IS NOT NULL"
if (@($filesBefore, $ingestedBefore, $quarantinedBefore, $sigBase, $incBase, $linkedBase, $alertBase) -contains -1) {
    Abort 'sample files parsed' "could not read baseline counts from $dbPath, so no later count can be trusted - check the database and logs, then rerun"
}
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
    # Canary: one drop the generator never produces - a unique PC and a unique
    # ransom-note filename, so it always opens a brand-new incident. Steps 7-9
    # wait for rows THIS run created; without a guaranteed fresh row a rerun
    # would sit waiting on data that only the first run can produce.
    $runId = (Get-Date).ToString('HHmmss') + '-' + [guid]::NewGuid().ToString('N').Substring(0, 6)
    $noteName = "README_RESTORE_$runId.txt"
    $canaryPc = "SMOKE-$runId"
    $canaryPath = Join-Path $inbox "file_activity_$runId.csv"
    $canaryCsv = @'
timestamp,hostname,file_path,action,process_name,sha256
__TS__,__PC__,C:\Users\Public\Desktop\__NOTE__,created,smoke_canary.exe,
'@
    $canaryTs = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    $canaryBody = $canaryCsv.Replace('__TS__', $canaryTs).Replace('__PC__', $canaryPc).Replace('__NOTE__', $noteName)
    try {
        Set-Content -LiteralPath $canaryPath -Value $canaryBody -Encoding ASCII -ErrorAction Stop
    } catch {
        Abort 'sample files parsed' "could not write the canary file $canaryPath - $($_.Exception.Message)"
    }

    $deadline = (Get-Date).AddSeconds($ParseTimeoutSec)
    $parsedOk = $false
    $ingestedNow = $ingestedBefore
    $quarantinedNow = $quarantinedBefore
    $rootLeft = -1
    while ((Get-Date) -lt $deadline) {
        $rootLeft = @(Get-ChildItem -LiteralPath $inbox -File -ErrorAction SilentlyContinue).Count
        $ingestedNow = Get-DbCount "SELECT COUNT(*) FROM files WHERE status = 'ingested'"
        $quarantinedNow = Get-DbCount "SELECT COUNT(*) FROM files WHERE status = 'error'"
        # PASS only when the root drained AND nothing was quarantined AND new
        # rows were ingested. "root empty and the files table is not empty"
        # used to be enough, which passes even when every file of this run was
        # rejected (all three paths move the file out of the root, and a table
        # with history is never empty).
        if ($rootLeft -eq 0 -and
            $quarantinedNow -le $quarantinedBefore -and
            $ingestedNow -gt $ingestedBefore) {
            $parsedOk = $true
            break
        }
        Start-Sleep -Seconds 3
    }
    $rootLeft = @(Get-ChildItem -LiteralPath $inbox -File -ErrorAction SilentlyContinue).Count
    $ingestedNow = Get-DbCount "SELECT COUNT(*) FROM files WHERE status = 'ingested'"
    $quarantinedNow = Get-DbCount "SELECT COUNT(*) FROM files WHERE status = 'error'"
    Report 'sample files parsed' $parsedOk "$genN generated + 1 canary file(s) dropped, ingested $ingestedBefore -> $ingestedNow, quarantined $quarantinedBefore -> $quarantinedNow, inbox root left=$rootLeft"
}

# ---- steps 7-9: this run's data reached each downstream stage -------------
# Each wait requires a count ABOVE its pre-run baseline; a bare "greater than
# zero" returned instantly on a database that already had rows.
function Wait-DbGrowth([string]$name, [string]$sql, [int]$base, [string]$expectDesc) {
    if (-not $appUp) {
        Report $name $false 'app is not serving - skipped waiting'
        return 0
    }
    $deadline = (Get-Date).AddSeconds($StageTimeoutSec)
    $n = Get-DbCount $sql
    while ((Get-Date) -lt $deadline -and $n -le $base) {
        Start-Sleep -Seconds 3
        $n = Get-DbCount $sql
    }
    Report $name ($n -gt $base) "$expectDesc $base -> $n"
    return $n
}

$signals = Wait-DbGrowth 'detection fires' 'SELECT COUNT(*) FROM signals' $sigBase 'signals'

# ---- step 8: an incident opens -------------------------------------------
# Correlation may also JOIN a new signal into an incident that is already open
# for the same PC instead of creating a row, so either growth counts: a fresh
# incident, or a signal attached to an incident by this run.
$linkedSql = 'SELECT COUNT(*) FROM signals WHERE incident_id IS NOT NULL'
$incidents = Get-DbCount 'SELECT COUNT(*) FROM incidents'
$linked = Get-DbCount $linkedSql
if (-not $appUp) {
    Report 'incident opens' $false 'app is not serving - skipped waiting'
} else {
    $deadline = (Get-Date).AddSeconds($StageTimeoutSec)
    while ((Get-Date) -lt $deadline -and $incidents -le $incBase -and $linked -le $linkedBase) {
        Start-Sleep -Seconds 3
        $incidents = Get-DbCount 'SELECT COUNT(*) FROM incidents'
        $linked = Get-DbCount $linkedSql
    }
    Report 'incident opens' (($incidents -gt $incBase) -or ($linked -gt $linkedBase)) `
        "incidents $incBase -> $incidents, signals attached to an incident $linkedBase -> $linked"
}

# ---- step 9: an alert is attempted ---------------------------------------
# Heartbeat/indicator rows carry no incident_id, so they cannot stand in for an
# attempt made by this run's incident.
$alerts = Wait-DbGrowth 'alert attempted' 'SELECT COUNT(*) FROM alerts_log WHERE incident_id IS NOT NULL' $alertBase 'incident alerts in alerts_log'

# ---- step 10: a report generates -----------------------------------------
$reportOk = $false
$reportDetail = 'no incident to report on'
if ($incidents -gt 0 -and $analystS) {
    $lastId = 0
    $incKey = ''
    $incCode = @'
import sqlite3, sys
row = sqlite3.connect(sys.argv[1]).execute(
    'SELECT id, incident_key FROM incidents ORDER BY id DESC LIMIT 1').fetchone()
print('' if row is None else '%d %s' % (row[0], row[1]))
'@
    $incOut = & $venvPy -c $incCode $dbPath 2>$null
    if ("$incOut" -match '^\s*(\d+)\s+(\S+)') {
        $lastId = [int]$Matches[1]
        $incKey = $Matches[2]
    }
    if ($lastId -gt 0) {
        $wantPath = "/incidents/$lastId/report"
        try {
            $r = Invoke-WebRequest "$base$wantPath" -WebSession $analystS -UseBasicParsing -TimeoutSec 20
            # `<html` on its own also matches the login page a bounced session
            # is redirected to, so require the request to still be standing on
            # this incident's report URL and the body to carry that incident's
            # own key plus the report heading.
            $landed = $r.BaseResponse.ResponseUri.AbsolutePath
            $body = "$($r.Content)"
            $hasKey = [bool]$incKey -and $body.Contains($incKey)
            $hasHeading = $body -match '<h1>Incident report:'
            $reportOk = ($r.StatusCode -eq 200 -and $landed -eq $wantPath -and
                         $hasKey -and $hasHeading)
            $reportDetail = "$wantPath -> $($r.StatusCode), landed=$landed, key $incKey present=$hasKey, heading=$hasHeading"
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
