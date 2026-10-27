# First-day runbook — office server

One page, ~20 minutes. Run **every command from one elevated cmd prompt**,
`C:\tracker` = wherever you copied the project. Every step prints PASS-style
evidence; if a step's expected line does not appear, stop and read
`logs\service.err.log` / `logs\tracker.log` before continuing.

**Before you start (preflight):**

```bat
python --version         :: must print 3.10 or newer
dir packages\            :: offline wheels for requirements.txt (30 files with
                          :: the tested Python 3.13); build on a connected
                          :: machine with scripts\Build-OfflinePackages.ps1
dir nssm.exe             :: REQUIRED for step 4, not shipped with the app
```

If `nssm.exe` is missing: copy `data_test\cleanroom\nssm.exe`, or extract
`data_test\nssm.zip` → `nssm-2.24\win64\nssm.exe` into `C:\tracker`, or fetch
it from https://nssm.cc on a connected machine first.

---

## 1. Offline install

```bat
cd /d C:\tracker
install.bat -Offline -NoStart
```

**Expected:**

```
Setup complete.
Dashboard:  http://127.0.0.1:8043/
First login: admin / the password in .env (TRACKER_ADMIN_PASSWORD)
Setup only (-NoStart). Start later with start.bat or .venv\Scripts\python -m app.main
```

`-NoStart` matters: without it the dashboard starts in *this* console and
blocks everything below. (Also works when launched from a PowerShell 7
prompt — `install.bat` clears `PSModulePath` for that case.)

## 2. Test suite on the server

```bat
.venv\Scripts\python.exe -m pytest -q
```

**Expected:** last line ends `passed` with exit code 0 (~1–2 min); any
failing test makes pytest exit non-zero. (The exact count grows with the
suite - what matters is zero failures.)

## 3. Smoke test (fake data, 11 checks)

```bat
smoke_test.bat
```

**Expected:** one `PASS` line per step, then

```
SMOKE: 11/11 steps passed

Next: open the dashboard at http://127.0.0.1:8043/
      login: admin / the password in .env (TRACKER_ADMIN_PASSWORD)
      this run stopped the app it started - run start.bat (or the service, if installed)
```

Exit code 0. If it prints `FAIL`, the failing step's hint names the fix
(e.g. "missing from .venv: … run install.bat"). It starts the app itself
and stops it again when done — step 4 starts it for good.

## 4. Install and start the service

```bat
powershell -ExecutionPolicy Bypass -File scripts\Install-Service.ps1
net start EndpointThreatTracker
sc query EndpointThreatTracker
```

**Expected:**

```
Service 'EndpointThreatTracker' installed.
The EndpointThreatTracker service was started successfully.
STATE              : 4  RUNNING
```

## 5. Health + first login

```bat
curl http://127.0.0.1:8043/health
start http://127.0.0.1:8043/
```

No curl? Use `powershell -c "irm http://127.0.0.1:8043/health"`.

**Expected:** JSON with `"status": "ok"`, `"scheduler_running": true`,
`"pending_alerts": 0`, `"problems": []`. Log in as `admin` with the password
from `.env`, then **change it on the Users page**.

## 6. First real file through the pipeline

```bat
:: drop today's export into inbox\, wait one 30 s cycle, then:
dir inbox\processed
curl http://127.0.0.1:8043/health
```

**Expected:** the file listed under `inbox\processed\` (not `errors\`);
`"last_ingest_at"` is current, `"ingest_age_hours"` near 0, `"status": "ok"`.
A file that failed parsing instead lands in `inbox\errors\` — check the page
or `logs\tracker.log`, the tool keeps running either way.

## 7. Backups: take one, then schedule and prove the task

```bat
:: 7a) passphrase for the manual run AND the 02:30 task: a scheduled task
::     does not load .env, and the script reads $env:BACKUP_PASSPHRASE
setx BACKUP_PASSPHRASE "<a long random string>"
::    also add BACKUP_PASSPHRASE=<same string> to .env so it is archived
::    with the config - then open a NEW prompt and continue:
powershell -ExecutionPolicy Bypass -File scripts\Backup-Database.ps1
```

**Expected:**

```
BACKUP_OK path=C:\tracker\backups\tracker-backup-<stamp>.enc size_mb=… verified=integrity:ok,counts:{…}
```

```bat
schtasks /Create /TN "ThreatTracker-Backup" /SC DAILY /ST 02:30 /F /TR "powershell.exe -NoProfile -ExecutionPolicy Bypass -File \"C:\tracker\scripts\Backup-Database.ps1\""
schtasks /Run /TN "ThreatTracker-Backup"
timeout /t 30 >nul
dir backups\tracker-backup-*.enc
```

**Expected:** `SUCCESS: The scheduled task "ThreatTracker-Backup" has been created successfully.`,
then a fresh `.enc` dated today proves the unattended path works — do not
wait for 02:30 to find out.

## 8. Verify + real restore drill

```bat
powershell -ExecutionPolicy Bypass -File scripts\Backup-Database.ps1 -Verify -Archive backups\<newest>.enc
powershell -ExecutionPolicy Bypass -File scripts\Backup-Database.ps1 -Restore -Archive backups\<newest>.enc -Target C:\tracker-restored
sc stop EndpointThreatTracker
:: copy data\, config\ and .env from C:\tracker-restored over C:\tracker, then:
sc start EndpointThreatTracker
start http://127.0.0.1:8043/
```

**Expected:** `VERIFY_OK … integrity=ok counts={…}` and
`RESTORE_OK target=C:\tracker-restored …`; after the swap the dashboard
shows the **same** incidents/files as before (safe on day 1 — the DB is new).

## 9. Reboot drill (auto-return)

```bat
shutdown /r /t 0
:: after the reboot:
sc query EndpointThreatTracker        :: STATE : 4 RUNNING
curl http://127.0.0.1:8043/health     :: "status": "ok"
```

**Expected:** `RUNNING` + `ok` within ~1 minute of boot (auto-start, no
admin action).

## 10. Crash drill (NSSM restart)

```bat
powershell -NoProfile -Command "Get-CimInstance Win32_Process -Filter \"Name='python.exe'\" | Where-Object CommandLine -like '*app.main*' | Stop-Process -Force"
timeout /t 15 >nul
curl -s -o nul -w "login=%{http_code}\n" http://127.0.0.1:8043/login
```

**Expected:** `login=200` — NSSM restarts the app within ~10 s.

## 11. Firewall (only if you deliberately want LAN viewing)

Loopback access needs **no** rule. To open the port on the private profile
(elevated): `powershell -ExecutionPolicy Bypass -File scripts\Set-FirewallRule.ps1 -AllowRemote`

---

**Done when:** steps 2, 3, 4, 5, 7, 9 and 10 all showed their expected
lines, the admin password is changed, and `backups\` holds a verified
archive. If `curl` is unavailable on your Windows version, substitute
`powershell -c "irm <url>"` everywhere.
