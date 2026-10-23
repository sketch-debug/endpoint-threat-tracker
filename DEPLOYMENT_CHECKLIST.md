# Deployment Checklist

Work through this top to bottom for a production rollout. Every item is
doable by one admin on one Windows server plus scheduled export tasks.

## Before install

- [ ] Read `README.md` and `ADMIN_GUIDE.md` §1 (daily operations).
- [ ] Confirm the server matches: Windows, Python 3.13 (or the version you
      package against), no internet needed if using `packages\`.
- [ ] Decide the bind address. Default `127.0.0.1` (dashboard only reachable
      via RDP/tunnel). Remote access requires editing `config/app_config.yaml`
      AND an explicit `scripts\Set-FirewallRule.ps1 -AllowRemote`.
- [ ] Collect your real indicator lists (mining pools, C2 domains, hashes).
      Shipped lists are `.test` placeholders.
- [ ] Choose the alert channels; gather SMTP credentials or a Teams webhook
      URL. These go in `.env` only — never in config files or chat.

## Install

- [ ] Copy the project folder to the server (include `packages\` for offline).
- [ ] `python -m venv .venv`
- [ ] `.venv\Scripts\python -m pip install --no-index --find-links packages -r requirements.txt`
      (drop `--no-index --find-links packages` when online)
- [ ] `copy .env.example .env`, then edit:
  - [ ] `TRACKER_ADMIN_PASSWORD` — set a strong unique value **now**
  - [ ] SMTP_* / TEAMS_WEBHOOK_URL if using those channels
  - [ ] `SECRET_KEY` — generate: `python -c "import secrets; print(secrets.token_hex(32))"`
- [ ] Edit `config/app_config.yaml`: port, off-hours windows to match your
      shift pattern, `scoring_window_hours` if needed.
- [ ] Replace `config/indicators/*.txt` placeholders with real lists.
- [ ] Fill `config/ip_map.txt` with your DHCP reservations / static IPs
      (inventory files will learn the rest automatically).

## First run

- [ ] Start via `scripts\Install-Service.ps1` + `Start-Service EndpointThreatTracker`
      (or `start.bat` for a foreground trial).
- [ ] Open `http://127.0.0.1:8043/`, log in as `admin`, **change the password**
      (Users page) even though `.env` was set — defense in depth.
- [ ] Create analyst and viewer accounts; give the SOC the analyst role.
- [ ] Sanity test with demo data: `generator\generate_fake_data.py`, copy
      `samples\*.csv` to `inbox\`, confirm the miner and ransomware incidents
      appear, then delete them from the dashboard and clear `data\tracker.db`
      if you want a clean start.
- [ ] Confirm an alert reaches each configured channel (open one test
      incident by dropping demo data again).

## Endpoint collection

- [ ] Deploy the export scripts to endpoints (Task Scheduler via GPO/Intune,
      or your RMM):
  - [ ] `Export-EndpointInventory.ps1` — daily, SYSTEM
  - [ ] `Export-EventLogs.ps1` — daily, elevated (Security log needs it)
  - [ ] `Export-FirewallConnections.ps1` — daily, elevated; enable the WFP
        audit policy (5156/5157) if not already on
  - [ ] `Export-DnsLogs.ps1 -Source Technitium|AdGuard|Generic` — daily
- [ ] Point every script's `-InboxDir` at the server share that maps to
      `inbox\`, or copy files there via your transfer mechanism.
- [ ] Drop one real file per format; confirm each ingests without errors.

## Hardening

- [ ] `inbox\`, `data\`, `reports\`, `logs\` ACLs: write access for the
      service account and the transfer share only; read for admins.
- [ ] Confirm `.env` is not readable by non-admins and not in any backup that
      leaves the building unencrypted.
- [ ] Verify the service runs under a dedicated low-privilege account if your
      policy requires it (NSSM `set ObjectName`).
- [ ] Set log rotation expectations (NSSM rotates at 10 MB by default in the
      install script).
- [ ] Add `data\tracker.db` to the nightly backup job (with `-wal`/`-shm`).
- [ ] Run `.venv\Scripts\python -m pytest` once on the server as a smoke test.

## Sign-off

- [ ] One incident driven end-to-end by hand: detected → isolated → reimaged
      → verified, checklist items ticked, HTML report generated and reviewed.
- [ ] Trigger a re-check reopen (drop a matching file for a verified PC) and
      confirm the REOPENED alert.
- [ ] Document who is on call for tracker alerts and where `logs\` lives.
- [ ] Record the rollout date and the indicator-list snapshot in your change
      log (this folder's `CHANGELOG.md` covers code; your ops log covers
      configuration).
