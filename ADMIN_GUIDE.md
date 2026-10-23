# Administrator Guide

Operational guide for running the Endpoint Threat Detection & Incident
Tracker. For install and architecture see `README.md`.

## 1. Daily operations

### Inbox hygiene

The tracker watches `inbox/` every `poll_seconds` (default 30s). Files are
**moved**, never modified in place:

* `inbox/processed/` — ingested successfully (or exact-duplicate content).
* `inbox/errors/` — rejected (too large, bad extension, unparsable). The file
  is kept byte-for-byte; fix the exporter and re-drop a corrected copy. The
  ledger keys on content hash (SHA-256), so re-dropping identical content is
  a no-op, and a corrected file is ingested as new content.

Check the dashboard's ingest panel weekly for a growing `errors/` folder —
it usually means an exporter needs a column fix.

### What an alert threshold means

A signal below `alert_score` (sum of distinct rule weights on that PC within
the window) is **logged but not an incident**. This is intentional: the
office-spawn or single-unsigned-process signals are context, not alarms. If a
rule feels too noisy, lower its weight in `config/scoring.yaml`; if a real
family is missed, raise the weights of its rules or add indicators.

### Alert channels

`config/app_config.yaml` → `alerts.channels`:

* `log` — always (database + `logs/tracker.log`).
* `email` — needs `SMTP_HOST/PORT/USER/PASSWORD/ALERT_FROM/ALERT_TO` in `.env`.
* `teams` — needs `TEAMS_WEBHOOK_URL` in `.env` (Power Automate "Post to
  channel" webhook).

Alerts fire on **state changes only** (incident opened, PC added, severity
raised, type changed, merge, reopen, recovery) — not per signal — so the same
problem is never emailed 50 times. Unconfigured channels are skipped with a
logged notice; they never crash the watcher.

## 2. Why no XML

Windows event logs are natively XML. Collecting them as XML would force every
deployment to run an XML parser over attacker-influenceable content, bringing
the whole XXE/billion-laughs/external-entity class of bugs into a security
tool.

`scripts/Export-EventLogs.ps1` therefore exports CSV with a `data_json`
column: EventData name/value pairs extracted from the raw event with a
non-expanding regex and serialized as JSON. No DTDs, no external references,
no entity expansion — on either side. Parsers additionally cap field lengths
(8 KB) and row counts (200k), and unknown columns are ignored, never fatal.

If you write your own exporter, keep this contract: **CSV + JSON column, no
XML leaves the endpoint.**

## 3. Adding a detection rule

1. Pick the module in `app/rules/` (or create one and register it in
   `_MODULES` in `app/rules/__init__.py`).
2. Subclass `ObsRule` (per-observation) or `PCRule` (per-PC aggregate) and
   return `SignalDraft`s. Rules are pure: they read via `Ctx` and never write.
3. Add the rule id to `KNOWN_RULE_IDS` in `app/rules/__init__.py`.
4. Add its weight to `config/scoring.yaml` → `rule_weights`. Startup warns
   if a rule has no weight or a weight has no rule.
5. Optionally add the id/category to `config/incident_types.yaml` so the
   right type gets suggested.
6. Add a test in `tests/test_detection.py` following the existing pattern
   (`_obs(...)` + `Detector.run(...)` + assert on `signals`).

Anchors matter: the `anchor` field is the dedup identity for rules without an
observation id (PC rules). Use something stable (item name + day), not a
timestamp, or every ingest will re-fire.

## 4. Indicator lists (`config/indicators/`)

Format: one entry per line, `#` starts a comment, blank lines ignored,
matching is case-insensitive.

| File | Format | Matched by |
|---|---|---|
| `mining_pool_domains.txt` | domain per line | DNS queries (subdomains included) |
| `c2_domains.txt` | domain per line | DNS queries |
| `mining_ports.txt` | TCP port per line | long-lived firewall connections |
| `miner_process_names.txt` | image name per line | process inventory / 4688 |
| `suspicious_paths.txt` | path fragment per line | process image paths |
| `bad_hashes.txt` | SHA-256 per line | process/file hashes, Defender resources |
| `ransomware_extensions.txt` | extension per line (`.` optional) | renamed file paths |
| `ransom_note_filenames.txt` | glob per line (`*` allowed) | created file names |
| `suspicious_command_patterns.txt` | **PCRE** per line | process command lines (4688) |
| `shadow_copy_tamper_patterns.txt` | **PCRE** per line | command lines (routes to ransomware) |
| `remote_access_tool_names.txt` | image name per line | process inventory / 4688 |
| `approved_remote_tools.txt` | image name per line | wins over the unapproved list |

Invalid regex lines are **skipped with a warning** (dashboard shows load
errors), never a crash. Shipped lists contain `.test`/example placeholders —
replace them with your downloaded threat lists before production use.

Edit lists from the dashboard (admin role) or directly on disk; the watcher
reloads after each scan.

## 5. Incident response workflow

Per-PC states (order is enforced): `detected → isolated → reimaged → verified`.

1. **Open incident** — auto-created, type suggested, checklist seeded from
   `config/incident_types.yaml`. Ransomware checklists start with isolation +
   backup verification for a reason: don't power off, verify offline copies.
2. **Record entry point / containment** — analyst fields on the incident page.
3. **Reimage** — mark `reimaged` when done; the PC must pass through it
   before `verified` makes sense, but the tool records what you tell it.
4. **Verify** — sets `recheck_until` (default 14 days). New signal during the
   window → **automatic reopen** + recovery alert superseded by a REOPENED
   alert. Clean window → PC marked passed, incident auto-closes when all PCs
   passed.

Analyst type overrides always win over auto-suggestion and are remembered
across later signal joins.

## 6. Users and roles

* `admin` — everything, including config/indicator editing and user management.
* `analyst` — incidents: workflow, notes, checklist, type override, reports.
* `viewer` — read-only.

First startup with an empty user table creates `admin` with
`TRACKER_ADMIN_PASSWORD` from `.env` (default `admin1234`). **Change it in
`.env` before first start on any shared machine**, then change the password
again after first login. Sessions last 12 hours; login is limited to 5
attempts per 5 minutes per username.

LDAP/AD integration is intentionally not bundled (no external deps); the
user store is a small interface in `app/auth.py` if you need it later.

## 7. Backup and upgrade

* **Back up**: `data/tracker.db` (+ `-wal`/`-shm` if present), `config/`,
  `.env`, `reports/`. Nothing else is state.
* **Upgrade**: stop the service, replace code, `pip install -r
  requirements.txt`, start. The schema is created idempotently and versioned
  in `schema_meta`; migrations apply in order on startup.
* **Rollback**: restore the backup folder; config files are backward
  compatible within a major version (extra keys are ignored).

## 8. Troubleshooting

| Symptom | Likely cause |
|---|---|
| No signals after dropping files | filename prefix missing (see README table); check `inbox/errors/` |
| Everything shows as one PC named by IP | `config/ip_map.txt` lacks the IP and no inventory file carries it |
| DNS rows ingested, no miner signals | indicator list still contains placeholder domains |
| Signals but no incident | sum of distinct rule weights below `alert_score` — expected for weak singles |
| Alert email not arriving | `alerts.channels` lacks `email`, or SMTP vars missing in `.env` (log shows "skipped_unconfigured") |
| Service starts then stops | check `logs/service.err.log`; usually venv path or `.env` syntax |
| Duplicate-looking signals | they are distinct evidence (different anchors); repeats of the same rule don't stack in score anyway |
