# Backup-Database.ps1 - encrypted, verified backups of the tracker database,
# config folder and .env (P14). Restore and verification are built in.
#
#   Backup (default):      powershell -File scripts\Backup-Database.ps1
#   Verify one archive:    ... -Verify -Archive backups\tracker-backup-....enc
#   Restore to a folder:   ... -Restore -Archive backups\...enc -Target C:\restore
#
# Passphrase: -Passphrase, else $env:BACKUP_PASSPHRASE (put it in .env for
# unattended nightly runs), else an interactive prompt. The database is
# copied with SQLite's online .backup API, so it is safe while the service
# runs. Archives are AES-256-CBC + HMAC-SHA256 (encrypt-then-MAC, PBKDF2
# 600k iterations); every backup is verified by decrypting it again and
# running PRAGMA integrity_check plus a row-count comparison before the
# script reports success. Kept archives: last -Keep (default 14).
[CmdletBinding(DefaultParameterSetName = "Backup")]
param(
    [Parameter(ParameterSetName = "Verify")] [switch]$Verify,
    [Parameter(ParameterSetName = "Restore")] [switch]$Restore,
    [string]$Archive = "",
    [string]$Target = "",
    [string]$Destination = "",
    [string]$DatabasePath = "",
    [string]$Passphrase = $env:BACKUP_PASSPHRASE,
    [int]$Keep = 14,
    [string]$ProjectRoot = ""
)
$ErrorActionPreference = "Stop"

$root = if ($ProjectRoot) { $ProjectRoot } else { Split-Path $PSScriptRoot -Parent }
if (-not $Destination) { $Destination = Join-Path $root "backups" }
if (-not $DatabasePath) { $DatabasePath = Join-Path $root "data\tracker.db" }
$venvPy = Join-Path $root ".venv\Scripts\python.exe"
$python = if (Test-Path $venvPy) { $venvPy } else { "python" }
$MAGIC = [System.Text.Encoding]::ASCII.GetBytes("TTBK1")

function Get-PlainPassphrase {
    if ($Passphrase) { return $Passphrase }
    $envPass = $env:BACKUP_PASSPHRASE
    if ($envPass) { return $envPass }
    if ([Environment]::UserInteractive) {
        $sec = Read-Host -Prompt "Backup passphrase (stored as BACKUP_PASSPHRASE in .env for unattended runs)"
        return [System.Net.NetworkCredential]::new("", $sec).Password
    }
    throw "No passphrase: pass -Passphrase, set BACKUP_PASSPHRASE, or run interactively."
}

function Get-Keys([string]$pass, [byte[]]$salt) {
    $pbk = [System.Security.Cryptography.Rfc2898DeriveBytes]::new(
        $pass, $salt, 600000, [System.Security.Cryptography.HashAlgorithmName]::SHA256)
    try {
        $material = $pbk.GetBytes(64)
    } finally { $pbk.Dispose() }
    ,@($material[0..31], $material[32..63])
}

function Protect-Bytes([byte[]]$plain, [string]$pass) {
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $salt = New-Object byte[] 16; $rng.GetBytes($salt)
    $iv = New-Object byte[] 16; $rng.GetBytes($iv)
    $keys = Get-Keys $pass $salt
    $aes = [System.Security.Cryptography.Aes]::Create()
    try {
        $aes.Mode = "CBC"; $aes.Padding = "PKCS7"; $aes.Key = $keys[0]; $aes.IV = $iv
        $ct = $aes.CreateEncryptor().TransformFinalBlock($plain, 0, $plain.Length)
    } finally { $aes.Dispose() }
    $body = $MAGIC + $salt + $iv + $ct
    $hmac = [System.Security.Cryptography.HMACSHA256]::new($keys[1])
    try { $tag = $hmac.ComputeHash($body) } finally { $hmac.Dispose() }
    return ($body + $tag)
}

function Unprotect-Bytes([byte[]]$blob, [string]$pass) {
    if ($blob.Length -lt $MAGIC.Length + 16 + 16 + 32) { throw "archive too short/truncated" }
    for ($i = 0; $i -lt $MAGIC.Length; $i++) {
        if ($blob[$i] -ne $MAGIC[$i]) { throw "not a tracker backup (bad header)" }
    }
    $o = $MAGIC.Length
    $salt = $blob[$o..($o + 15)]; $o += 16
    $iv = $blob[$o..($o + 15)]; $o += 16
    $ct = $blob[$o..($blob.Length - 33)]
    $tag = $blob[($blob.Length - 32)..($blob.Length - 1)]
    $keys = Get-Keys $pass $salt
    $hmac = [System.Security.Cryptography.HMACSHA256]::new($keys[1])
    try { $expect = $hmac.ComputeHash($blob[0..($blob.Length - 33)]) } finally { $hmac.Dispose() }
    $diff = 0
    for ($i = 0; $i -lt 32; $i++) { $diff = $diff -bor ($tag[$i] -bxor $expect[$i]) }
    if ($diff -ne 0) { throw "integrity check failed (wrong passphrase or corrupt archive)" }
    $aes = [System.Security.Cryptography.Aes]::Create()
    try {
        $aes.Mode = "CBC"; $aes.Padding = "PKCS7"; $aes.Key = $keys[0]; $aes.IV = $iv
        return $aes.CreateDecryptor().TransformFinalBlock($ct, 0, $ct.Length)
    } finally { $aes.Dispose() }
}

# SQLite online snapshot + integrity + row counts (JSON on stdout)
$SNAPSHOT_PY = @'
import json, sqlite3, sys
src, dst = sys.argv[1], sys.argv[2]
s = sqlite3.connect(src)
d = sqlite3.connect(dst)
s.backup(d)
d.row_factory = sqlite3.Row
integrity = d.execute("PRAGMA integrity_check").fetchone()[0]
tables = ("incidents", "observations", "signals", "files", "users",
          "audit_log", "alerts_log")
counts = {t: d.execute("SELECT COUNT(*) AS n FROM " + t).fetchone()["n"]
          for t in tables}
print(json.dumps({"integrity": integrity, "counts": counts}))
d.close(); s.close()
'@

$INSPECT_PY = @'
import json, sqlite3, sys
c = sqlite3.connect(sys.argv[1])
c.row_factory = sqlite3.Row
integrity = c.execute("PRAGMA integrity_check").fetchone()[0]
tables = ("incidents", "observations", "signals", "files", "users",
          "audit_log", "alerts_log")
counts = {t: c.execute("SELECT COUNT(*) AS n FROM " + t).fetchone()["n"]
          for t in tables}
print(json.dumps({"integrity": integrity, "counts": counts}))
c.close()
'@

# Runs a python helper from a temp file: Windows PowerShell mangles embedded
# double quotes when passing a -c script to a native process (the PRAGMA
# quotes vanished), so the code always travels as a file argument.
function Invoke-Py([string]$code, [string]$a1, [string]$a2 = "") {
    $tmpPy = Join-Path ([IO.Path]::GetTempPath()) ("ttpy_" + [guid]::NewGuid().ToString("N") + ".py")
    Set-Content -LiteralPath $tmpPy -Value $code -Encoding UTF8
    try {
        $argList = @($tmpPy)
        if ($a1) { $argList += $a1 }
        if ($a2) { $argList += $a2 }
        $out = & $python @argList
        if ($LASTEXITCODE -ne 0) {
            throw "python helper failed: $($out -join ' ')"
        }
        return ($out -join "")
    } finally {
        Remove-Item -Force $tmpPy -ErrorAction SilentlyContinue
    }
}

function Invoke-Inspect([string]$dbPath) {
    $json = Invoke-Py $INSPECT_PY $dbPath
    return $json | ConvertFrom-Json
}

function Expand-ArchiveTo([byte[]]$blob, [string]$pass, [string]$dir) {
    $work = Join-Path ([IO.Path]::GetTempPath()) ("ttbak_" + [guid]::NewGuid().ToString("N"))
    New-Item -ItemType Directory -Force -Path $work | Out-Null
    try {
        $zip = Join-Path $work "a.zip"
        [IO.File]::WriteAllBytes($zip, (Unprotect-Bytes $blob $pass))
        $ex = Join-Path $work "x"
        Expand-Archive -LiteralPath $zip -DestinationPath $ex -Force
        Copy-Item -Recurse -Force (Join-Path $ex "*") $dir
    } finally {
        Remove-Item -Recurse -Force $work -ErrorAction SilentlyContinue
    }
}

function Assert-Verified([string]$dir, $manifest) {
    $info = Invoke-Inspect (Join-Path $dir "data\tracker.db")
    if ($info.integrity -ne "ok") { throw "integrity_check failed: $($info.integrity)" }
    foreach ($t in $manifest.counts.PSObject.Properties.Name) {
        if ([int]$info.counts.$t -ne [int]$manifest.counts.$t) {
            throw "count mismatch for ${t}: $($info.counts.$t) != $($manifest.counts.$t)"
        }
    }
    return $info
}

try {
    if ($Verify -or $Restore) {
        if (-not $Archive -or -not (Test-Path $Archive)) { throw "-Archive file required" }
        $pass = Get-PlainPassphrase
        $work = Join-Path ([IO.Path]::GetTempPath()) ("ttout_" + [guid]::NewGuid().ToString("N"))
        New-Item -ItemType Directory -Force -Path $work | Out-Null
        try {
            $blob = [IO.File]::ReadAllBytes($Archive)
            Expand-ArchiveTo $blob $pass $work
            $manifest = Get-Content (Join-Path $work "manifest.json") -Raw | ConvertFrom-Json
            $info = Assert-Verified $work $manifest
            if ($Verify) {
                Write-Host "VERIFY_OK $Archive integrity=$($info.integrity) counts=$($manifest.counts | ConvertTo-Json -Compress)"
                exit 0
            }
            # Restore
            if (-not $Target) { throw "-Target directory required for -Restore" }
            New-Item -ItemType Directory -Force -Path $Target | Out-Null
            Copy-Item -Recurse -Force (Join-Path $work "*") $Target
            Write-Host "RESTORE_OK target=$Target integrity=$($info.integrity) counts=$($manifest.counts | ConvertTo-Json -Compress)"
            Write-Host "Next: point the app's data/config at this folder (or copy data\ and config\ over the install) and start it."
            exit 0
        } finally {
            Remove-Item -Recurse -Force $work -ErrorAction SilentlyContinue
        }
    }

    # ---- default: backup + immediate verify ----
    if (-not (Test-Path $DatabasePath)) { throw "database not found: $DatabasePath" }
    $pass = Get-PlainPassphrase
    New-Item -ItemType Directory -Force -Path $Destination | Out-Null
    $stage = Join-Path ([IO.Path]::GetTempPath()) ("ttstage_" + [guid]::NewGuid().ToString("N"))
    $zipPath = Join-Path ([IO.Path]::GetTempPath()) ("tt_" + [guid]::NewGuid().ToString("N") + ".zip")
    try {
        New-Item -ItemType Directory -Force -Path (Join-Path $stage "data") | Out-Null
        $snap = Join-Path $stage "data\tracker.db"
        $info = (Invoke-Py $SNAPSHOT_PY $DatabasePath $snap) | ConvertFrom-Json
        if ($info.integrity -ne "ok") { throw "source database failed integrity_check: $($info.integrity)" }

        Copy-Item -Recurse -Force (Join-Path $root "config") (Join-Path $stage "config")
        $envFile = Join-Path $root ".env"
        if (Test-Path $envFile) { Copy-Item -Force $envFile $stage }
        $verFile = Join-Path $root "VERSION"
        if (Test-Path $verFile) { Copy-Item -Force $verFile $stage }
        $info | Add-Member -NotePropertyName created -NotePropertyValue (Get-Date).ToUniversalTime().ToString("o")
        $info | Add-Member -NotePropertyName source -NotePropertyValue $DatabasePath
        $info | ConvertTo-Json -Depth 5 | Set-Content -Path (Join-Path $stage "manifest.json") -Encoding UTF8

        Compress-Archive -Path (Join-Path $stage "*") -DestinationPath $zipPath -Force
        $enc = Protect-Bytes ([IO.File]::ReadAllBytes($zipPath)) $pass
        $stamp = Get-Date -Format "yyyyMMdd-HHmmss"
        $outPath = Join-Path $Destination "tracker-backup-$stamp.enc"
        [IO.File]::WriteAllBytes($outPath, $enc)

        # verify what we just wrote (decrypt + integrity + counts)
        $vwork = Join-Path ([IO.Path]::GetTempPath()) ("ttv_" + [guid]::NewGuid().ToString("N"))
        New-Item -ItemType Directory -Force -Path $vwork | Out-Null
        try {
            Expand-ArchiveTo ([IO.File]::ReadAllBytes($outPath)) $pass $vwork
            $vm = Get-Content (Join-Path $vwork "manifest.json") -Raw | ConvertFrom-Json
            $vinfo = Assert-Verified $vwork $vm
        } finally {
            Remove-Item -Recurse -Force $vwork -ErrorAction SilentlyContinue
        }

        # retention: keep the newest -Keep archives
        Get-ChildItem -Path $Destination -Filter "tracker-backup-*.enc" |
            Sort-Object LastWriteTime -Descending |
            Select-Object -Skip $Keep |
            Remove-Item -Force -ErrorAction SilentlyContinue

        $sizeMb = [math]::Round((Get-Item $outPath).Length / 1MB, 2)
        Write-Host "BACKUP_OK path=$outPath size_mb=$sizeMb verified=integrity:$($vinfo.integrity),counts:$($info.counts | ConvertTo-Json -Compress)"
        exit 0
    } finally {
        Remove-Item -Recurse -Force $stage -ErrorAction SilentlyContinue
        Remove-Item -Force $zipPath -ErrorAction SilentlyContinue
    }
} catch {
    Write-Host "BACKUP_FAILED $($_.Exception.Message)"
    exit 1
}
