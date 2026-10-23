# Changelog

All notable changes to the Endpoint Threat Detection & Incident Tracker.
Format loosely follows Keep a Changelog; versions are semantic.

## [1.1.0] - 2026-10-23

First complete release of the unified architecture (miner functionality is
the first rule family on a shared engine, not a separate product).

### Added

- **Unified signal model**: every rule emits `SignalDraft`s (timestamp, PC,
  category, rule id, correlation keys); weights and thresholds live in
  `config/scoring.yaml`, incident types in `config/incident_types.yaml`.
- **Rule families**: miner (pool DNS, mining ports, miner processes,
  off-hours CPU), network (C2 DNS, unapproved remote-access tools), execution
  (suspicious paths/signatures/hashes/commands, Office spawning interpreters,
  Defender detections), persistence (4698/7045/4720/4732 + snapshot diffs of
  tasks/services/Run keys/startup/WMI), account (failed-login bursts,
  burst-then-success, off-hours logins, unusual sources), evasion (5001/5007,
  1102, Defender status diffs), ransomware (extensions, notes, mass changes,
  shadow-copy tamper).
- **Scoring**: distinct-rule weights over a rolling window, alert threshold,
  severity bands, category-count escalation matrix.
- **Incident correlation**: key-based join/merge across open incidents,
  auto type suggestion with analyst override, per-PC workflow
  (`detected → isolated → reimaged → verified`), response checklists,
  timeline, 14-day post-cleanup re-check with auto-reopen and auto-close.
- **Ingest pipeline**: inbox watcher with size/extension validation,
  SHA-256 dedup ledger, safe parsers (CSV/JSONL only — no XML anywhere),
  automatic IP→hostname learning, per-file error parking.
- **Web dashboard** (FastAPI + Jinja2): dashboard, incidents, PCs, config
  and indicator editors, users, audit log; PBKDF2-SHA256 passwords, signed
  session cookies, login rate limiting, admin/analyst/viewer roles.
- **Alerts**: log / email (SMTP) / Teams webhook, deduplicated by state
  change, per-type response checklists included.
- **HTML incident reports**: self-contained, no external assets, safe to
  email or archive.
- **Export scripts** (PowerShell, read-only): endpoint inventory (processes
  with signature status, tasks, persistence, Defender status), Windows event
  logs as CSV+JSON (XXE structurally eliminated), WFP connections, DNS logs
  (Technitium / AdGuard / generic CSV).
- **Operations**: NSSM service install/uninstall, `start.bat`, firewall
  helper (loopback by default; remote only with an explicit switch),
  offline dependency packaging (`pip download` → `packages/`), fake-data
  generator with a multi-PC scenario fleet.
- **Tests**: 101 pytest cases covering parsers, indicators, rules, scoring,
  correlation, re-check, ingest, and auth — running against the shipped
  configuration files.

## [1.0.0] - 2026-10-15

Internal prototype: miner-only detection over DNS CSVs with hardcoded
weights, flat incident list, no correlation or re-check. Superseded by the
unified architecture in 1.1.0.
