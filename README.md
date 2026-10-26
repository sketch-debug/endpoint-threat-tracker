# Endpoint Threat Detection & Incident Tracker

A **defensive, read-only** Windows endpoint threat detection and incident
tracking tool. Export scripts collect metadata-only logs (hostnames, process
names, domains, IPs, ports, timestamps — never file contents or keystrokes),
the tracker parses them from a local inbox folder, scores PCs against editable
indicator lists, groups correlated signals into incidents, and guides the
response through per-type checklists, per-PC workflow states, and a 14-day
post-cleanup re-check.

Detection families shipped out of the box:

| Family | Examples |
|---|---|
| Cryptomining | mining-pool DNS, long-lived flows on mining ports, miner process names, off-hours high CPU |
| Ransomware | ransom extensions, ransom notes, mass file changes, shadow-copy tamper (vssadmin/wmic) |
| Remote access / backdoor | unapproved remote-control tools, C2/malware DNS |
| Unknown / suspicious | suspicious command lines, Office spawning interpreters, unsigned/temp-path processes, Defender detections and disabled protection, persistence diffs, failed-login bursts, log cleared |

**Read-only by construction:** the tool only ever reads files dropped into
`inbox/`. It never scans, probes, blocks, deletes, or modifies anything else,
on any machine.

## Architecture

```
PowerShell export scripts ──> inbox/*.csv|jsonl ──> Ingestor ──> observations
                                (drop-only)          │  validate, hash, dedup,
                                                     │  parse, resolve PC
                                                     v
                                              Detector (rules/*)
                                                     │ signals (deduped,
                                                     │ weighted from scoring.yaml)
                                                     v
                                         Scoring ──> Correlation ──> Incidents
                                                                    │ checklist,
                                                                    │ workflow,
                                                                    v
                                    Alerts (log/email/Teams)   HTML reports
                                    Auth (PBKDF2, sessions)    Dashboard (FastAPI)
```

* **No XML anywhere.** Event logs are exported as CSV with a JSON `data_json`
  column (see `scripts/Export-EventLogs.ps1`), which structurally eliminates
  XXE-style attacks against the parser. See ADMIN_GUIDE §"Why no XML".
* **All SQL is parameterized** (stdlib `sqlite3`, single serialized
  connection, schema tracked in `schema_meta`).
* **Every path, threshold, weight, and indicator list is a config file** —
  nothing to edit in code to tune the tool.

## Quick start (Windows)

From a fresh copy of the project folder:

```
install.bat
```

The installer checks for Python 3.10+, creates or repairs `.venv`, installs
the pinned dependencies (from `packages\` when present, otherwise from PyPI),
creates `.env` with a random `SECRET_KEY`, asks for the dashboard admin
password (or generates one and prints it), and starts the dashboard at
http://127.0.0.1:8043/.

First login: `admin` / the password you chose. Create analyst/viewer accounts
on the Users page. `install.bat -NoStart` sets up without starting;
`install.bat -Offline` requires the offline `packages\` folder. `start.bat`
still works without PowerShell and reuses the same `.venv` and `.env`.

To see it work immediately with generated demo data (no endpoints needed):

```
.venv\Scripts\python generator\generate_fake_data.py --into-inbox
```

Within a minute the dashboard shows a miner incident spanning three PCs, a
ransomware incident, and a below-threshold weak signal that correctly does
**not** open an incident.

## Offline install

1. On a connected machine with the same Python major.minor:
   `powershell -File scripts\Build-OfflinePackages.ps1`
2. Copy the whole project folder (including the new `packages\`) to the target.
3. Run `install.bat -Offline` (plain `install.bat` also uses `packages\`
   automatically when it is present).

## Production install (Windows service)

```
install.bat -NoStart
powershell -ExecutionPolicy Bypass -File scripts\Install-Service.ps1
Start-Service EndpointThreatTracker
```

Uses [NSSM](https://nssm.cc) to run the tracker as a service with rotated
logs in `logs\`. The service starts automatically at boot and restarts the
app if it crashes (10 s delay), so it recovers from crashes and reboots
without an admin. `scripts\Uninstall-Service.ps1` removes it (keeps data).
`scripts\Set-FirewallRule.ps1` documents the only firewall change this tool
ever suggests — and only with an explicit `-AllowRemote` switch; the default
bind is `127.0.0.1` and needs no rule at all.

## Collecting data from endpoints

Schedule these on endpoints (Task Scheduler, or your RMM tool) — all read-only:

| Script | Writes to inbox | Contents |
|---|---|---|
| `Export-EndpointInventory.ps1` | `process_inv_*`, `tasks_inv_*`, `persistence_inv_*`, `defender_status_*` | processes + signature status, scheduled tasks, Run keys/services, Defender RTP/exclusions |
| `Export-EventLogs.ps1` | `events_<date>/*.csv` | 4688/4624/4625/4720/4732/1102/7045/4698/5001/5007 |
| `Export-FirewallConnections.ps1` | `fw_connections_*` | WFP permitted/blocked connections |
| `Export-DnsLogs.ps1` | `dns_technitium_*` / `dns_adguard_*` / `dns_generic_*` | DNS queries from Technitium, AdGuard, or any CSV |

Filenames are the primary format hint (prefixes documented in
`app/parsers/dispatch.py`); headers are a fallback. Unknown files are parked
in `inbox/errors/` untouched and reported, never deleted.

Network-only logs (DNS/firewall) carry IPs, not hostnames: the tracker
resolves them via `config/ip_map.txt` (one `IP=HOSTNAME` per line) and learns
new mappings automatically from inventory files that carry both.

## Scoring model

* PC score over the rolling window (`scoring_window_hours`, default 24h) =
  sum over **distinct rule ids** of that rule's weight from
  `config/scoring.yaml` (repeats of the same rule do not stack).
* score < `alert_score` (40) → the signal is logged only; **no incident**.
* score ≥ `alert_score` → the PC gets an incident.
* Severity = score band (`severity_medium` 60 / `severity_high` 80), then the
  escalation matrix raises it (≥2 distinct categories → at least medium,
  ≥3 → high; explicit combinations like `[ransomware, evasion]` → high).

Weights, thresholds, bands, and escalation are all in
`config/scoring.yaml` — tune them there, never in code.

## Incidents

Signals are grouped by correlation keys (PC, domain, hash, task, command
line, account, source IP). A signal joining two open incidents **merges**
them. The type (miner / ransomware / remote-access-backdoor / unknown) is
suggested from the categories and rules involved; an analyst override always
wins and is remembered. Per-PC workflow: `detected → isolated → reimaged →
verified`, and verified PCs are re-checked for 14 days — a new signal during
the window reopens the incident; a clean window auto-closes it.

Each incident gets a **self-contained HTML report** (`reports/`) with the
summary, affected machines, checklist, timeline, and evidence — safe to
email or archive.

## Adding a detection rule

See `ADMIN_GUIDE.md` §"Adding a rule". Short version: subclass `ObsRule`
(or `PCRule`) in `app/rules/`, append it to that module's `OBS_RULES`
(`PC_RULES`), add its id to `KNOWN_RULE_IDS` in `app/rules/__init__.py`,
give it a weight in `config/scoring.yaml`, and (optionally) reference it from
`config/incident_types.yaml`. Startup validates that every rule id has a
weight and warns about drift.

## Tests

```
.venv\Scripts\python -m pytest
```

Covers timestamp normalization, every parser, indicator matching, the rule
families, scoring/escalation, incident correlation/merge/override,
re-check lifecycle, ingest validation/dedup, and auth (PBKDF2, rate limit,
sessions). Tests run against the **shipped config files**, so the default
weights and indicator lists are themselves under test.

## Layout

```
app/            core application (config, db, ingest, detect, rules/, web/)
config/         app_config.yaml, scoring.yaml, incident_types.yaml, indicators/
scripts/        PowerShell export scripts, service install, offline packaging
generator/      scenario-driven fake data generator (demo + tests)
tests/          pytest suite
inbox/          drop zone (processed/ and errors/ subfolders are created)
reports/        generated HTML incident reports
```

## Security notes

* Secrets only in `.env` (never committed; `.env.example` is the template).
* Session cookies are HMAC-signed; passwords are PBKDF2-SHA256 (390k
  iterations, unique salt); login is rate-limited (5 attempts / 5 min).
* Roles: admin (config, indicators, users), analyst (work incidents),
  viewer (read-only). Every mutating route is role-checked and audited.
* The tool stores **metadata only** — no file contents, no keystrokes, no
  screenshots, no credentials.
