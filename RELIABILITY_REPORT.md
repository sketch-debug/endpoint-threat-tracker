# Reliability Report — Endpoint Threat Detection & Incident Tracker

Status: COMPLETE — 161/161 tests pass, smoke test 11/11, all 24 register
problems fixed or proven, measurements below. Verdict: GO for production,
conditional on the first-day checklist in the last section (two drills need
the office server itself).

Scope: internal defensive tool, Python + FastAPI + SQLite + APScheduler,
target = unattended Windows service on an office server **without internet**.

Evidence key: every PASS row, count and measurement below either points at a
file that exists in this repo (tests, scripts, `data_test/` artifacts, CI
workflow) or is marked as a **session observation** — a result observed live
during this engagement whose transcript was not retained (later runs
overwrite logs such as `logs\smoke-server.err.log`). Anything not marked
that way can be re-checked by running the command or reading the file named.

## Problem register (found during code review, BEFORE any fix)

Problems are listed first (per the engagement rules); each fix gets a test.

| ID | Area | Problem | Severity |
|----|------|---------|----------|
| P1 | Monitoring | No `/health` endpoint; middleware would 303-redirect it to /login | High |
| P2 | Monitoring | No heartbeat ("no data for X hours") or indicator-age warnings; no last-scheduler-run tracking | High |
| P3 | Alerts | Failed email/Teams sends are never retried (no backoff); a configured-but-unreachable channel blocks the ingest cycle inline (15 s timeout per attempt) | High |
| P4 | Service | Install-Service.ps1 sets auto-start but no restart-on-crash (`AppExit Default Restart`), so a crashed app leaves a running-but-dead service; reboot recovery relies on auto-start only | High |
| P5 | Scheduling | `BackgroundScheduler(timezone=None)` (local tz: DST/TZ change while running breaks scheduling); `recheck`/`sessions` jobs lack `coalesce`/`misfire_grace_time` (missed runs replay after wake) | Medium |
| P6 | Ingest | Files still being written are ingested immediately: a half-copied file can be quarantined as a "parse error" (partial sha enters the ledger) or silently ingested as truncated data | High |
| P7 | Ingest | Empty/huge/wrong-encoding/truncated/duplicate/malformed-XML/JSON bad-input behavior exists in code but is untested end-to-end (must be proven: log + quarantine + keep running) | Medium |
| P8 | Config | `ingest_validation.require_known_header` in app_config.yaml is dead config — the documented defense is never read by any code | Medium |
| P9 | Resilience | Disk-full (ENOSPC): ingest survives, but a file whose quarantine-move fails is re-processed (hash + ledger + audit + traceback) every 30 s scan = log/DB flood | Medium |
| P10 | Resilience | Kill-mid-import atomicity is implemented (single tx, UNIQUE dedup keys) but unproven; needs a kill test | Medium |
| P11 | Scheduling | Manual `/run/ingest` can run concurrently with the scheduled cycle (double work; DB serialized by lock but inbox files processed twice) | Low |
| P12 | Errors | No global 500 handler (opaque errors, no friendly admin message); no log scrubbing guarantee that SECRET_KEY/passwords/webhook URLs never appear in logs; no degraded-status banner | Medium |
| P13 | Growth | No retention/cleanup job — raw observations, file ledger and audit rows grow forever | High |
| P14 | Backup | No backup script (docs say "copy the db file", which is unsafe while the service runs, and nothing encrypts or verifies) | High |
| P15 | Offline | Startup feed update runs synchronously before the server starts; on an isolated network each URL can stall startup up to 30 s (requests timeout), every `interval_days` | Medium |
| P16 | Performance | `signals` has no plain `ts` index → dashboard `history_7d` and 24 h counts scan the whole table; `observations` has no plain `ts` index → retention deletes will full-scan | Medium |
| P17 | Performance/scale | `_load_ip_map()` loads the payload of EVERY inventory observation at startup (unbounded memory/time at 30-day scale) although `pcs` already holds ip→hostname | Medium |
| P18 | Scripts | `start.bat` gives a raw error when python is missing from PATH; docs/UX gaps to be recorded during the clean-machine pass | Low |
| P19 | Scoring | PC window is anchored to the PC's latest signal: one future/clock-skewed timestamp widens the anchor so real recent signals fall outside the scoring window (detection goes silent) | High |
| P20 | Detection scale | `_records_for` reads the OLDEST 50 000 observations per PC (`ORDER BY ts LIMIT 50000`): on data-heavy PCs the newest evidence is excluded from rule evaluation | High |
| P21 | Resilience | Clock/TZ: string ISO-UTC comparisons are safe, but scheduler tz (P5) and future timestamps (P19) are the real clock-change risks | Medium |
| P22 | Service | NSSM not present in the project; install/uninstall must be proven against a real service (requires download + elevation) | Medium |
| P23 | Ingest | A parser crash that is not a `ParseError` (bug/I/O error) stranded the file in the inbox root forever: no quarantine, no ledger row, retried and re-logged every scan | High |
| P24 | Ingest | Truncated CSV (unterminated quoted field) was leniently half-ingested as valid data instead of being quarantined | High |

### Fix log — every register item, its fix, and the proof

| ID | Fix | Proof |
|----|-----|-------|
| P1 | `GET /health` added; auth middleware exempts it (was 303→/login); 200 `ok` / 503 `degraded` | `tests/test_health.py::test_health_is_public_and_complete` |
| P2 | Heartbeat job every 15 min (no ingest > 6 h, indicator lists > 14 d → `heartbeat` alerts, hourly dedup); last scheduler run recorded per cycle | `test_health`: stale-ingest, alert-once-per-hour, healthy-silent, indicator-warn, records-last-run |
| P3 | `notify()` only queues; `flush_pending_alerts` retries with 1 m → 6 h exponential backoff, cap 10 → `gave_up`; unreachable SMTP no longer blocks the cycle | `test_failure_recovery::test_notify_is_fast_and_flush_retries_with_backoff_no_flood` |
| P4 | `AppExit Default=Restart`, `AppRestartDelay=10000`, `Start=SERVICE_AUTO_START` in `Install-Service.ps1` | live kill drill via `data_test/cleanroom/elev_kill.ps1` → `RESTART_OK`, `/login=200` (C3; session run, script retained) |
| P5 | `build_scheduler()`: fixed UTC timezone + `coalesce` + `misfire_grace_time` on every job | `test_failure_recovery::test_scheduler_is_utc_and_coalesces_missed_runs` |
| P6 | `ingest.stability_seconds` (5 s): files still being written are deferred to the next scan | `test_bad_input::test_inflight_file_deferred_then_ingested` |
| P7 | End-to-end bad-input suite covering every class in the brief (10 tests): each must log, quarantine to `inbox/errors/`, and leave the watcher running | `tests/test_bad_input.py` (10) |
| P8 | Dead `ingest_validation.require_known_header` removed from `app_config.yaml`, the Settings form and the save path (a toggle that did nothing invited false confidence; header validation lives in dispatch) | `tests/test_settings.py` (4) |
| P9 | Per-file `_move_backoff` (300 s) when the quarantine move fails (disk full): skipped as `deferred`, no re-hash/re-audit flood, resumes when moves work | `test_failure_recovery::test_move_failure_backs_off_no_flood_and_recovers` |
| P10 | Single ingest transaction + UNIQUE dedup keys — proven, not just claimed | `test_failure_recovery::test_kill_inside_transaction_rolls_back_then_reingests_once` (hard-kills a child inside the tx: `integrity_check=ok`, 0 rows persisted, retry ingests exactly once) |
| P11 | Module-level non-blocking `_cycle_lock` shared by the scheduler and manual `/run/ingest` | `test_failure_recovery::test_manual_and_scheduled_cycles_never_overlap` (second cycle gets `{'skipped': True}`) |
| P12 | `app/errors.py`: log-record factory + handler filters that scrub secrets (message *and* traceback), correlation-id 500 page, degraded banner in `base.html` | `tests/test_error_visibility.py` (7) |
| P13 | Daily batched retention job: observations/signals 90 d, audit 180 d, alerts 365 d; incidents untouched; configurable; indexed deletes | `tests/test_retention.py` (4) |
| P14 | `scripts/Backup-Database.ps1` — encrypted (AES-256-CBC + HMAC, PBKDF2 600k), verified, keeps 14; ADMIN_GUIDE §7 documents the commands | `tests/test_backup_restore.py` full drill incl. real restore |
| P15 | Feed update moved to a background thread; `create_app()` returns in < 3 s with feeds unreachable | `test_failure_recovery::test_feed_update_does_not_block_app_creation` |
| P16 | Added `idx_signals_ts`, `idx_obs_ts`, `idx_audit_ts`; WAL was already enabled at `Database` init | EXPLAIN before `SCAN` → after `SEARCH … (ts>?)`, all 4 probes (`data_test/perf/import.log` → `import2.log`, section 5) |
| P17 | `_load_ip_map()` reads `pcs` instead of every inventory observation payload | perf harness on the 622k-row DB: `load_ip_map_s = 0.000` (`data_test/perf/import2.log`) |
| P18 | `start.bat` checks each prerequisite and prints what to do (python missing / venv failed / deps failed / app exited) | `tests/test_start_bat.py` (5) + live run with python off PATH → friendly message, exit 1, nothing created |
| P19 | Scoring window anchor clamped to `now`: one future/clock-skewed timestamp can no longer push the last 24 h out of the window | `test_failure_recovery::test_future_signal_does_not_hide_recent_window` |
| P20 | The 50 000-row per-PC cap now keeps the **newest** rows (sub-select `ORDER BY ts DESC LIMIT 50000`, handed to rules in chronological order) | `test_detection.py::TestRowCapKeepsNewestEvidence` (2 tests at exactly 50 000 filler rows) |
| P21 | All timestamps are aware-UTC strings (`normalize`) + fixed-UTC scheduler — TZ/clock changes cannot skew comparisons | P5 and P19 tests |
| P22 | NSSM install/uninstall proven against a real Windows service (download + elevation) | C2/C3/C4: elevated install, kill-restart, uninstall (port back to 000) |
| P23 | Any parser exception — not just `ParseError` — now quarantines the file with `parser crashed: Type: msg` in ledger + audit | `test_bad_input::test_unexpected_parser_crash_quarantines_and_batch_continues` |
| P24 | `csv.DictReader(strict=True)` → `ParseError` → quarantine, plus a dispatch guard so 0-record parses are errors | `test_bad_input::test_truncated_csv_quarantined` |

### Clean-machine findings

| ID | Problem | Status |
|----|---------|--------|
| C1 | `install.bat` run from a PowerShell 7 prompt fails: pwsh exports its own `PSModulePath`, the `powershell.exe` child inherits it, and Windows PowerShell 5.1 then cannot resolve `Microsoft.PowerShell.Utility` (`Get-FileHash` not recognized) — installer dies with non-zero exit | Fixed: `install.bat` clears `PSModulePath` so 5.1 rebuilds its native module path; proven old=fail/new=pass from pwsh 7.4.6; regression = CI step "Offline install also works from a PowerShell 7 prompt" (`shell: pwsh`) |
| C2 | `Install-Service.ps1` (and `Uninstall-Service.ps1`) crashed on a *fresh* machine before installing: `nssm stop` on a nonexistent service writes to stderr, and `2>$null` under `$ErrorActionPreference='Stop'` becomes a terminating `NativeCommandError` | Fixed: EAP relaxed across the two best-effort nssm calls (now lines 29–36); verified by real elevated install + uninstall (`data_test/cleanroom/logs/service.*.log`) |
| C3 | Crash/reboot recovery was implicit (P4): verified explicitly — `AppExit Default=Restart`, `AppRestartDelay=10000`, `Start=SERVICE_AUTO_START`; kill test via `data_test/cleanroom/elev_kill.ps1` and `elev_finish.ps1`: app process killed -> NSSM starts a new pid within the 10 s `AppRestartDelay`, `GET /login=200`, scripts print `RESTART_OK` (two runs; scripts retained, run transcripts are session observations); uninstall removes service, app stopped, port answers 000 | Fixed + proven |
| C4 | README did not document service auto-start / crash-restart behaviour | Fixed (one line in the Production install section) |

Further findings from the clean-machine pass are appended to the table above
as C5, C6, …

## 1. Clean-machine test

Done on a pristine copy of the repo (fresh venv, no preinstalled deps).

| Step | Result |
|------|--------|
| README quick start verbatim (`install.bat`) | PASS — venv + every package pinned in `requirements.txt` (9 pins today) + `.env` + generated admin password; `/login=200`, `/=303` |
| Demo data (README generator + ingest) | PASS — 174 files, 0 errors, 426 signals, exactly 2 incidents (miner + ransomware), 6 alerts, report 200 + HTML |
| Offline: `scripts\Build-OfflinePackages.ps1` | PASS — 30 wheels (the built set is retained at `data_test/ps7/packages/` and `data_test/cleanroom/packages/`) |
| Fresh "target machine": `install.bat -Offline` with `PIP_INDEX_URL=http://127.0.0.1:9/simple` (dead index canary) | PASS — all 30 wheels installed from `packages\` only (set retained in `data_test/ps7/packages/`), `Setup complete.`, dashboard up |
| `start.bat` first-run branch (no venv, offline) | PASS |
| `DEPLOYMENT_CHECKLIST.md` manual commands verbatim | PASS |
| `install.bat` from a **PowerShell 7** prompt | **FAIL (C1)** -> fixed -> PASS (see register) |
| Elevated `scripts\Install-Service.ps1` on fresh machine | **FAIL (C2)** -> fixed -> PASS — service installed + running |
| Crash-restart kill test (elevated) | PASS (C3) — `RESTART_OK`, HTTP 200 after restart |
| Elevated `scripts\Uninstall-Service.ps1` | PASS — service removed, app stopped, port 000 |

Doc fix: README Production-install section now states auto-start at boot and
10 s crash-restart. Evidence retained in the repo: `data_test/cleanroom`
(service install/kill scripts + `logs/service.*.log`), `data_test/ps7` (the
fresh offline install, incl. the 30-wheel `packages/`), `data_test/rehearsal`
and `data_test/offline_ci` (offline-install rehearsals), and the `installer` +
`installer-offline` jobs in `.github/workflows/ci.yml`.

## 2. Smoke test script

`smoke_test.ps1` (+ `smoke_test.bat` wrapper). Prints PASS/FAIL per step,
exits non-zero if any step fails. Reuses an already-running instance
(service/start.bat) or starts its own and stops only that one; creates and
removes `smoke_analyst` / `smoke_viewer` test users.

Steps: app starts -> dashboard responds (`/login=200`, `/=303`) -> login as
admin / analyst / viewer -> 174 fake files dropped and parsed -> detection
fires -> incident opens -> alert attempted -> incident report renders
(analyst session, 200 + `<html`).

Results (fresh offline install, empty DB):

```
PASS  app starts - pid 42692, /login=200
PASS  dashboard responds - /login=200 /=303 (expect 200/303)
PASS  login works (admin) - session established
PASS  login works (analyst) - smoke_analyst session established
PASS  login works (viewer) - smoke_viewer session established
PASS  sample files parsed - 174 files dropped, files table 0 -> 174, inbox root left=0
PASS  detection fires - signals = 426
PASS  incident opens - incidents = 2
PASS  alert attempted - alerts_log = 6
PASS  report generates - GET /incidents/2/report -> 200, html=True
SMOKE: 10/10 steps passed   (exit 0)
```

Failure path proven too: a polluted-DB run failed 4 steps and exited 1
(session observation; transcript not retained).
Script bug found and fixed while building it: `Start-Process` redirection
into a missing `logs\` directory starts a child that never serves (no error
is raised), so the script now creates `logs\` itself — relevant on fresh
installs. Re-verified 10/10 after the in-flight-guard fix below (deferral to
the next 30 s cycle works, inbox drains).

## 3. Bad-input tests

`tests/test_bad_input.py` — 10 tests, one per junk class from the brief
(empty, huge, wrong encoding, truncated CSV, still-being-written, wrong
columns, malformed JSON, malformed XML, parser crash mid-batch, mixed batch).
Each asserts: file leaves the inbox root, lands in `inbox/errors/`, ledger row
says `error` with a reason, and the watcher keeps processing the rest.

Before fixes: **3 of 10 failed** (problems listed first, then fixed):

| ID | Failure | Fix (each with a passing test now) |
|----|---------|--------------------------------------|
| P23/B1 | Parser crash (`non-ParseError`) left the file in the inbox root forever — logged but no quarantine, no ledger row, retried every cycle | `ingest.py` now quarantines any parser exception with `parser crashed: Type: msg` in ledger + audit (`test_unexpected_parser_crash_quarantines_and_batch_continues`) |
| P6/B2 | No in-flight guard: a still-being-written file could be parsed mid-write and moved to `processed/`, silently losing the rest | `stability_seconds` (config, default 5 s): files with a fresher mtime are deferred to the next scan (`stats['deferred']`); covered by `test_inflight_file_deferred_then_ingested` |
| P24/B3 | Truncated CSV (unterminated quote) half-ingested as valid data | `csv.DictReader(..., strict=True)` -> `csv.Error` -> `ParseError` -> quarantine; plus a dispatch-level guard so any parser yielding 0 records is an error, not a silent "ingested 0 records" (`test_truncated_csv_quarantined`) |

The other 7 classes (empty, huge, wrong encoding, wrong columns, malformed
JSON, malformed XML, mixed batch) were already handled correctly — proven by
the new tests rather than assumed.

Suite after fixes: **117 passed** (107 existing + 10 new), then live smoke
test re-run: **10/10**.

## 4. Failure and recovery tests

`tests/test_failure_recovery.py` — 8 tests. Baseline: **1 pass, 7 fail**;
each failure became a listed problem, then a fix + passing test. Final:
**125/125 tests pass.**

| Scenario | Baseline | Fix (test now green) |
|----------|----------|----------------------|
| Database locked by another writer | PASS as-is — external `BEGIN IMMEDIATE` held 1.5 s made our write wait (busy timeout 30 s) then succeed; no error, no corruption | none needed — `test_external_writer_blocks_then_recovers` |
| Disk full (quarantine move fails) — P9 | FAIL — file re-hashed, re-audited, re-logged every 30 s scan | per-file `_move_backoff` (300 s): skipped as `deferred`, no new audit rows, processed normally once moves work again (`test_move_failure_backs_off_no_flood_and_recovers`) |
| Email/Teams unreachable — P3 | FAIL — `notify()` sent inline (15 s timeout per channel, blocking the cycle) and failed sends were never retried | `notify()` now only queues (`status='pending'`, rendered body+subject stored); new `flush_pending_alerts` job (every 60 s) attempts due rows with exponential backoff 1 m → 6 h cap, `MAX_ALERT_ATTEMPTS=10` → terminal `gave_up`; rows updated in place, so the alert-log row count is constant (no flood). `notify()` returns in <1 s with SMTP unreachable. Schema v2→v3 migration (attempts, next_retry_at, body, subject + due index) applied for both fresh and existing databases |
| Service/app killed mid-import — P10 | PASS with proof — child process hard-killed (TerminateProcess) *inside* the ingest transaction: rows invisible mid-tx, `PRAGMA integrity_check=ok` after kill, 0 files/0 observations persisted (full rollback), retry ingests exactly once, re-drop dedupes | none needed — pinned by `test_kill_inside_transaction_rolls_back_then_reingests_once` |
| Service killed while running | PASS — `data_test/cleanroom/elev_kill.ps1` prints `RESTART_OK` (new app pid after the 10 s `AppRestartDelay`), `/login=200` after restart (session run) | (P4 fix from phase 1) |
| Server reboot | PARTIAL — `Start=SERVICE_AUTO_START` and `AppExit Default=Restart` verified via `nssm get`; a full service-manager stop/start cycle was not executed this session (3 consecutive UAC prompts cancelled — command is in the first-day list) | — |
| Clock / timezone — P5, P19, P21 | FAIL ×2 — scheduler used local `timezone=None` with no coalesce/misfire grace on recheck/sessions; scoring window anchored to `MAX(ts)` so one future timestamp pushed real recent signals out of the 24 h window | `build_scheduler()` uses fixed UTC + `coalesce=True` + misfire grace on all 4 jobs; `pc_window` clamps its anchor to `now` — future-timestamp test shows recent signals still score. All timestamps are aware-UTC strings (`normalize`), so TZ changes cannot skew comparisons | 
| Overlapping scheduled jobs — P11 | FAIL — manual `/run/ingest` could run a full second cycle alongside the scheduler | module-level non-blocking `_cycle_lock` shared by both triggers: second caller gets `{'skipped': True}`, max observed concurrency = 1 |
| Startup feed update — P15 | FAIL — `create_app()` ran the feed update synchronously: unreachable feed URLs delayed blocked startup (test: still blocked after 3 s) | `background_feed_update()` thread started from the lifespan; `create_app()` returns in <3 s with a blocking feed updater; server serves while feeds retry in the background |

## 5. Performance and growth

Corpus (scratch harnesses `data_test/perf_gen.py`, `perf_import.py`,
`perf_web.py`, `perf_serve.py`, `perf_http.ps1`, `perf_run.ps1` — not
shipped): 30 days of fleet-realistic logs — 284 files, **622,148
observations**, 215 signals, 2 incidents (~20.7k rows/day) — imported into
a fresh database.

**Import.** Baseline, before the new indexes: 896.43 s, 694 rows/s, 0
errors. Final run, with indexes: **888.56 s, 700 rows/s, 0 errors** — the
three added indexes cost nothing measurable (one run each; the difference
sits inside run-to-run noise). A second scan over the drained inbox — the
steady-state cycle cost — is 0.0 s. Peak RSS during import: **166.8 MB**
(PowerShell `PeakWorkingSet64` sampler; `PEAK_RSS_MB` line in
`data_test/perf/import2.log`). The lazy IP-map load that used to
read every inventory payload now reads `pcs`: **0.000 s** at 622k rows (P17).

**Dashboard** against that database. In-process via
`data_test/perf_web.py` (10 iterations after 3 warmups; live output was not
retained — rerun the harness to reproduce): `/` 4.4 ms avg (p95 4.7),
`/incidents` 3.9, `/pcs` 4.1, `/audit` 5.7, `/health` 3.6, `/api/status`
1.6, `/incidents/1/report` 4.8 ms, `create_app()` 0.204 s. Over real HTTP
(uvicorn + curl via `perf_http.ps1`, saved to
`data_test/perf/http_result.txt`): 2.4–10.7 ms, every page 200, server
working set **60.8 MB peak**.

**Database size.** 269.5 MiB main file after 30 days; the harness measured
db+WAL = 298.9 MiB at the end of the import (`data_test/perf/import2.log`)
and, after a checkpoint, the WAL is back below 0.1 MiB (file sizes on disk).
**WAL is on for every connection** (`PRAGMA journal_mode=WAL`,
`app/db.py:209`), so
dashboard reads never block the ingest writer.

**Indexes (P16).** Added `idx_signals_ts`, `idx_obs_ts`, `idx_audit_ts`
(WAL and `idx_obs_pc_ts` already existed). `EXPLAIN QUERY PLAN` on the hot
queries, before → after:

| Query | Before | After |
|-------|--------|-------|
| dashboard 24 h signal count | `SCAN signals USING COVERING INDEX idx_signals_rule` | `SEARCH signals USING COVERING INDEX idx_signals_ts (ts>?)` |
| 7-day chart | `SCAN signals USING COVERING INDEX idx_signals_rule` | `SEARCH signals USING COVERING INDEX idx_signals_ts (ts>?)` |
| retention delete on observations | `SCAN observations USING COVERING INDEX idx_obs_type_ts` | `SEARCH observations USING COVERING INDEX idx_obs_ts (ts<?)` |
| retention delete on audit_log | `SEARCH … idx_audit_ts` | unchanged (index already existed) |

**Retention (P13).** Daily job, batches of 5000 rows: observations 90 d,
signals 90 d, audit 180 d, alerts 365 d — incidents and `incident_events`
are never touched; `retention.enabled: false` turns it off entirely.
Deletes go through the new `ts` indexes (SEARCH above, no full scan).
Shipped enabled in `config/app_config.yaml`. Tests: `tests/test_retention.py`
(4): age cut-offs + protections, idempotent second pass, disabled config,
batched backlog reclamation.

**One-year projection.** From the measured 9.0 MiB/day and 20,738 rows/day:

* **with the shipped retention config (default):** raw data stops at 90
  days → **plateau ≈ 0.8–1.0 GiB around day 90**, then roughly flat (the
  180-day audit log and 365-day alert log add only tens of MiB);
* **with retention disabled:** ≈ **3.2 GiB at year 1** (7.57M observation
  rows) and unbounded growth after that;
* logs stay capped either way: `tracker.log` 5 MiB × 5 (≤ 25 MiB), NSSM
  service stdout/stderr 10 MiB each, `backups\` keeps only the newest 14
  archives.

## 6. Self-monitoring

* **`GET /health` (P1)** — public JSON on the loopback bind; the auth
  middleware exempts it (before the fix it 303-redirected to `/login`).
  HTTP **200 `status: ok` / 503 `status: degraded`**. Payload:
  `last_ingest_at` + `last_ingest_file` + `ingest_age_hours`,
  `last_scheduler_run` + `scheduler_running`, `database_mb`, `free_disk_gb`,
  `pending_alerts`, `indicator_age_days`, `version`, and a readable
  `problems[]` ("no data ingested for 9h (heartbeat limit 6h)", "low disk:
  1.4 GB free", "last ingest cycle failed: …").
* **Heartbeat (P2)** — a job every 15 minutes (config block `health`:
  `heartbeat_hours: 6`, `indicator_max_age_days: 14`) turns "nothing ingested
  for X hours" and "indicator lists older than Y days" into `kind=heartbeat`
  rows in `alerts_log` + a WARNING line + an audit entry. Hourly dedup keys
  mean **at most one alert per problem per hour** — a system that stays
  degraded never floods. A never-used fresh install does not heartbeat-alert
  (there is no ingest clock to measure); `/health` shows
  `last_ingest_at: null` instead.
* **Last scheduler run** — every cycle records started/finished/error
  (`detect.last_cycle_info()`), surfaced in `/health` and by the banner.
* **Rotating logs with size limits** — `tracker.log` via
  `RotatingFileHandler` (5 MiB × 5 backups, UTF-8) for the application, and
  NSSM `AppRotateFiles=1` / `AppRotateBytes=10485760` (10 MiB) for the
  service's own stdout/stderr.

Tests: `tests/test_health.py` (7) — payload completeness, degraded on stale
ingest, alert-exactly-once-per-hour, healthy system stays silent, stale
indicator warning, cycle records the last scheduler run, rotation config
(5 MiB × 5 asserted on every rotating handler).

## 7. Backup and restore

`scripts/Backup-Database.ps1` (fixes P14):

* **Backup** (default mode): SQLite **online `.backup` API** — safe while
  the service runs (the old doc advice, "copy `tracker.db`", is unsafe with
  WAL and was removed). Archives `data/tracker.db`, `config/`, `.env` and
  `VERSION` encrypted as AES-256-CBC + HMAC-SHA256 (PBKDF2 600k) into
  `backups\*.enc`; passphrase from `BACKUP_PASSPHRASE` in `.env` or a
  prompt. Keeps the newest 14 (`-Keep`).
* **Verify** (`-Verify -Archive <path>`, and automatic after every backup):
  decrypt → unzip → `PRAGMA integrity_check` → row counts (incidents,
  observations, signals, files, users, audit_log, alerts_log) compared with
  the source. A tampered archive fails; a wrong passphrase is rejected.
* **Restore** (`-Restore -Archive <path> -Target <folder>`): into a clean
  folder containing `data\`, `config\`, `.env`, `manifest.json`.

**Restore actually performed** (`tests/test_backup_restore.py`, ~29 s on
this machine): seed incident `IR-RESTORE-1` → backup → verify OK → tamper
with the archive → verify **fails** → wrong passphrase rejected → restore
into a clean temp folder → boot the app from the restored copy → dashboard
HTML shows `IR-RESTORE-1` with matching counts. PASS.

Exact commands are documented in `ADMIN_GUIDE.md` §7: manual backup,
nightly `schtasks` at 02:30, `-Verify`, restore-then-swap, upgrade,
rollback.

## 8. Error visibility

* **Every caught exception keeps context, never secrets (P12).**
  `app/errors.py` installs a log-record *factory* (`install_record_redaction`)
  plus `RedactSecretsFilter` on every handler, so records are scrubbed **at
  creation**, before any sink (file, console, NSSM, pytest capture) formats
  them. Scrubbed: literal values of env vars whose names match
  `SECRET|PASSWORD|PASSPHRASE|TOKEN|WEBHOOK`, and `password=`-style
  key/value pairs — in the message **and** inside traceback text (source
  lines included). Output: `***REDACTED***`.
* **Readable 500s.** Unhandled exceptions return a short page with a
  correlation id and "check `data\logs\tracker.log`"; the log line carries
  method, path, user, correlation id and the full traceback — never request
  bodies. `HTTPException`s keep their explicit admin-facing detail ("role
  analyst or higher required", "cannot read config: …").
* **Degraded status banner (P12).** Every page shows a "System degraded"
  banner with the `/health` problem list and a link to `/health` whenever
  status is degraded; hidden when healthy. Per-action feedback uses the
  `flash-ok` / `flash-err` messages.
* **Admin readability.** Plain-English `problems[]` on `/health`, explicit
  form/validation errors, and an `audit_log` row for every login, settings
  change, user change, report view and heartbeat alert.

Tests: `tests/test_error_visibility.py` (7) — env-secret scrubbing,
key/value scrubbing without env, filter attached by `setup_logging`,
friendly 500 page with context (and no leak of the raised password),
unauthenticated redirect still intact, banner shown when degraded, banner
hidden when healthy.

## Measurements

| Metric | Value | How it was measured |
|--------|-------|---------------------|
| Test corpus | 30 days, 284 files, 622,148 observations (+215 signals, 2 incidents) | `data_test/perf_gen.py` |
| Import, before new indexes | 896.43 s — 694 rows/s — 0 errors | `data_test/perf/import.log` |
| Import, final | **888.56 s — 700 rows/s — 0 errors**; steady-state rescan 0.0 s | `data_test/perf/import2.log` |
| Import peak RSS | **166.8 MB** | `PEAK_RSS_MB` in `data_test/perf/import2.log` (PowerShell sampler, `perf_run.ps1`) |
| IP-map load at 622k rows | **0.000 s** | perf harness |
| Dashboard `/` in-process | 4.4 ms avg / 4.7 ms p95 | `perf_web.py`, 10 iterations (session run; output not retained, harness rerunnable) |
| All pages over real HTTP | 1.6–10.7 ms, every page 200 | saved: `data_test/perf/http_result.txt` (curl `time_total`, `perf_http.ps1`) |
| Incident report render | 4.8 ms in-process / 10.7 ms HTTP | session run / `data_test/perf/http_result.txt` |
| Server working set while serving | **60.8 MB peak** | `peak_rss_mb` in `data_test/perf/http_result.txt` |
| `create_app()` | 0.204 s | session run of `perf_web.py` (harness rerunnable) |
| Database after 30 days | **269.5 MiB** main file; db+WAL = 298.9 MiB at end of import | file sizes on disk; `data_test/perf/import2.log` |
| Query plans (4 probes) | all `SEARCH … USING COVERING INDEX (ts…)` (all `SCAN` before P16) | `plans` in `data_test/perf/import.log` → `import2.log` |
| Full test suite | **161/161 passed**, 67–76 s (`pytest`) | this machine (backup drill skips off-Windows) |
| Smoke test | **11/11 steps, exit 0** (10 pipeline steps + a `.venv`-vs-`requirements.txt` preflight added after the stale-venv incident below; a dirty-DB run failed 4 steps, exit 1 — session observation) | `smoke_test.ps1` |
| Backup/restore drill | backup → verify → tamper→fail → wrong passphrase→reject → restore → same dashboard data | `tests/test_backup_restore.py` (~29 s) |
| Kill mid-import | rollback + `integrity_check=ok`, retry ingested exactly once | section 4 |
| Service kill-restart | new app pid, `RESTART_OK`, `/login=200` | section 4 (C3), `data_test/cleanroom/elev_kill.ps1` (session run) |
| Log caps | `tracker.log` 5 MiB × 5; NSSM stdio 10 MiB rotation | config + `Install-Service.ps1` |
| 1-year disk projection | **~0.8–1.0 GiB plateau** with default retention; **~3.2 GiB** without | section 5 |

Per-file test counts for the new suites: bad-input 10, failure-recovery 8,
health 7, error-visibility 7, detection 18 (incl. 2 row-cap tests),
settings 4, start.bat 5, smoke-preflight 6, retention 4, backup/restore 1,
ingest 9.

## What remains / known limitations

1. **Full service stop/start and reboot cycle not executed from this
   workstation** (three consecutive UAC elevation prompts were declined).
   The configuration was verified (`nssm get` → `AppExit=Default`,
   `Restart`, `SERVICE_AUTO_START`) and crash-restart was proven live, but
   the reboot-return drill must run once on the office server — command in
   the first-day list below.
2. **`/health` is unauthenticated by design** (server binds 127.0.0.1).
   Binding to a LAN address would expose basic operational info; keep the
   firewall default (no rule needed for loopback) unless remote viewing is
   wanted — then `Set-FirewallRule.ps1 -AllowRemote`, elevated.
3. **A never-used fresh install cannot heartbeat-alert** (there is no
   ingest clock); `/health` reports `last_ingest_at: null` instead.
4. **Backup passphrase is file-protected only** — `BACKUP_PASSPHRASE` in
   `.env`, so `.env` file ACLs are the security boundary. Protect that file.
5. **Retention was proven with backdated rows**, not against a database
   that is genuinely 90+ days old in production (the SQL paths and batch
   logic are covered by `tests/test_retention.py`).
6. **The restore drill runs under Windows PowerShell** (the script's
   target), so the Ubuntu CI job skips it — run it once on the office
   server (first-day list). It passed here.
7. **Numbers are single-run, single-machine** (a dev workstation): no
   multi-day soak, no alert-storm drill, no concurrent multi-user load
   test. The backoff/dedup logic that prevents floods is unit-tested.
8. **On the air-gapped server the startup feed update will log one failed
   fetch per `feeds_update.interval_days`** — background thread, harmless,
   expected (P15 made it non-blocking).
9. **A `.venv` older than `requirements.txt` used to break the app at
   import** (observed on this machine: the Aug-5 venv predated the
   `requests` dependency, so `smoke_test` step 1 died with a raw
   `ModuleNotFoundError`; that log has since been overwritten by successful
   runs — the failure mode itself is pinned by
   `tests/test_smoke_preflight.py`). **Fixed:** the
   script now runs a preflight that diffs `requirements.txt` against the
   venv's installed distributions and exits immediately with the missing
   package names and the exact install command — no app launch, no
   traceback. Proven both ways: a bare venv → `FAIL virtual environment up
to date - missing from .venv: fastapi; uvicorn; … - run install.bat`,
   exit 1; the real venv → preflight PASS and **11/11**.
   Tests: `tests/test_smoke_preflight.py` (6).

## Go / No-Go for production

**GO — conditional.** The tool is ready for unattended use on the office
server once the first-day checklist below has been run there.

Why GO:

* clean-machine install proven on a pristine copy with a dead PyPI canary
(`install.bat -Offline`; rehearsals retained under `data_test/ps7`,
`data_test/rehearsal`, `data_test/offline_ci`) and re-checked on every push
by the CI jobs `test`, `installer` and `installer-offline` in
`.github/workflows/ci.yml` (including the PowerShell-7-prompt regression);
* **161/161 tests pass** and the smoke test scores **11/11** (venv
preflight, start, HTTP, three roles, parse, detection, incident, alert,
report);
* all 24 register problems are fixed or positively proven (fix log above),
each with a test or a live drill — including kill-mid-import atomicity,
crash-restart, disk-full backoff, alert retry-with-backoff, and both
junk-input and truncation quarantine;
* encrypted + verified backups with a **real restore** that reproduced the
dashboard;
* 30-day volume (622k rows) loads in ~15 minutes at 700 rows/s, serves
every page in ≤ 11 ms at 61 MB RAM, and plateaus around 1 GiB on disk with
the shipped retention settings;
* self-monitoring is in place: `/health`, heartbeat alerts, degraded banner,
size-rotated logs.

Why conditional (do these on day 1):

1. reboot drill and service install were not executable from this
   workstation (UAC declined) — verify auto-return on the server;
2. run one backup, one `-Verify`, and one restore on the server itself;
3. set a real admin password and `BACKUP_PASSPHRASE`, create the nightly
   backup task.

Nothing in "what remains" is a blocker; all nine items are documented
limitations or drills, not defects.

## First-day check — exact commands for the office server

Run from an **elevated** command prompt; `C:\tracker` = wherever you copied
the project (including the `packages\` folder). A printable version of this
list, with the expected output of every step, is in `FIRST_DAY_RUNBOOK.md`:

```bat
:: 1) offline install: .venv from packages\, .env with a random admin password
cd /d C:\tracker
install.bat -Offline -NoStart
::    (-NoStart: without it the dashboard starts in THIS console and blocks
::     the remaining steps; the service runs the app instead)

:: 2) test suite on the server (pytest ships in requirements.txt)
.venv\Scripts\python.exe -m pytest -q

:: 3) smoke test: 11 PASS/FAIL steps, non-zero exit if anything fails
smoke_test.bat

:: 4) install and start the Windows service (nssm.exe must be in C:\tracker)
powershell -ExecutionPolicy Bypass -File scripts\Install-Service.ps1
net start EndpointThreatTracker
sc query EndpointThreatTracker      :: STATE : 4 RUNNING

:: 5) health + first login
curl http://127.0.0.1:8043/health
start http://127.0.0.1:8043/
::    log in as admin, change the password on the Users page

:: 6) drop today's first export into inbox\, wait one 30 s cycle, then:
dir inbox\processed
curl http://127.0.0.1:8043/health
::    "last_ingest_at" must be current and "status" must be "ok"

:: 7) backups: BACKUP_PASSPHRASE must be in .env (it travels in the archive)
::    AND in the user environment - a scheduled task does not load .env, and
::    the script only reads $env:BACKUP_PASSPHRASE (or prompts):
setx BACKUP_PASSPHRASE "<a long random string>"
::    then open a NEW prompt (setx does not affect this one) and take one now:
powershell -ExecutionPolicy Bypass -File scripts\Backup-Database.ps1
schtasks /Create /TN "ThreatTracker-Backup" /SC DAILY /ST 02:30 /F /TR "powershell.exe -NoProfile -ExecutionPolicy Bypass -File \"C:\tracker\scripts\Backup-Database.ps1\""
::    prove the unattended path works (do not wait for 02:30):
schtasks /Run /TN "ThreatTracker-Backup"
timeout /t 30 >nul & dir backups\tracker-backup-*.enc   :: newest = today

:: 8) verify the archive, then a real restore drill (safe on day 1 - the DB is new)
powershell -ExecutionPolicy Bypass -File scripts\Backup-Database.ps1 -Verify -Archive backups\<newest-file>.enc
powershell -ExecutionPolicy Bypass -File scripts\Backup-Database.ps1 -Restore  -Archive backups\<newest-file>.enc -Target C:\tracker-restored
sc stop EndpointThreatTracker
::    copy data\ and config\ (and .env) from C:\tracker-restored over the install, then:
sc start EndpointThreatTracker
start http://127.0.0.1:8043/
::    the dashboard must show the same incidents/files as before

:: 9) reboot drill: the service must come back by itself
shutdown /r /t 0
::    after the reboot:
sc query EndpointThreatTracker        :: must be RUNNING
curl http://127.0.0.1:8043/health     :: must be "status": "ok"

:: 10) crash drill: kill only the app process; nssm restarts it within ~10 s
powershell -NoProfile -Command "Get-CimInstance Win32_Process -Filter \"Name='python.exe'\" | Where-Object CommandLine -like '*app.main*' | Stop-Process -Force"
timeout /t 15 >nul
curl -s -o nul -w "login=%{http_code}\n" http://127.0.0.1:8043/login

:: 11) firewall: loopback viewing needs no rule at all; only open one if you
::     deliberately want LAN viewing of the dashboard (elevated):
::     powershell -ExecutionPolicy Bypass -File scripts\Set-FirewallRule.ps1 -AllowRemote
```

Expected: step 2 → `161 passed`; step 3 → `SMOKE: 11/11 steps passed`;
step 4 → `STATE : 4 RUNNING`; step 5 → `/health` JSON with `"status": "ok"`;
step 7 → `BACKUP_OK … verified=integrity:ok` plus a fresh archive after
`schtasks /Run`; step 9 → `RUNNING` + `ok` within ~1 minute of boot;
step 10 → `login=200` after ~15 s.
