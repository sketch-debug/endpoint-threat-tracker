"""Retention/cleanup: delete aged raw data in small, safe batches (P13).

Configured in config/app_config.yaml under `retention`. Only an explicit
allowlist of append-only tables is ever touched:

  * observations  - raw events (default 90 days)
  * signals       - only signals NOT attached to an incident (default 90 days)
  * audit_log     - default 180 days
  * alerts_log    - default 365 days

Incidents, incident_pcs/incident_events/incident_keys/checklist_state, pcs
and the files dedup ledger are NEVER deleted here: case history must
outlive every retention window, and dropping ledger rows would let old
content be re-ingested as "new".

Deletion happens in short batched transactions (`batch_size`) so the
dashboard keeps working while a large backlog is reclaimed.
"""
from __future__ import annotations

import logging
from datetime import timedelta

from .audit import audit
from .config import Settings
from .db import Database
from .normalize import iso, now_iso, utcnow

log = logging.getLogger("tracker.retention")

_DEFAULTS = {
    "observations_days": 90,
    "signals_days": 90,
    "audit_days": 180,
    "alerts_days": 365,
    "batch_size": 5000,
}


def _purge(db: Database, table: str, where: str, params: tuple, batch: int) -> int:
    """Delete matching rows `batch` at a time; each batch is its own
    short transaction. `table` is an internal literal, never user input."""
    total = 0
    while True:
        with db.tx():
            db.execute(
                f"DELETE FROM {table} WHERE id IN "
                f"(SELECT id FROM {table} WHERE {where} LIMIT {batch})",
                params)
            n = int((db.one("SELECT changes() AS n") or {"n": 0})["n"] or 0)
        total += n
        if n < batch:
            break
    return total


def run_retention(db: Database, settings: Settings, now=None) -> dict:
    """One retention pass. Returns rows deleted per table (or
    {"skipped": "disabled"}). Never raises past its caller."""
    cfg = settings.retention_cfg
    if not cfg.get("enabled", True):
        return {"skipped": "disabled"}

    now = now or utcnow()
    days = {k: int(cfg.get(k, v)) for k, v in _DEFAULTS.items()
            if k.endswith("_days")}
    batch = max(1, int(cfg.get("batch_size", _DEFAULTS["batch_size"])))

    obs_cut = iso(now - timedelta(days=days["observations_days"]))
    sig_cut = iso(now - timedelta(days=days["signals_days"]))
    aud_cut = iso(now - timedelta(days=days["audit_days"]))
    alr_cut = iso(now - timedelta(days=days["alerts_days"]))

    deleted = {
        "observations": _purge(db, "observations", "ts < ?", (obs_cut,), batch),
        # incident-linked signals stay as long as their incident does
        "signals": _purge(db, "signals", "ts < ? AND incident_id IS NULL",
                          (sig_cut,), batch),
        "audit_log": _purge(db, "audit_log", "ts < ?", (aud_cut,), batch),
        "alerts_log": _purge(db, "alerts_log", "ts < ?", (alr_cut,), batch),
    }
    total = sum(deleted.values())
    if total:
        detail = ", ".join(f"{k}={v}" for k, v in deleted.items() if v)
        log.info("retention cleanup removed %s", detail)
        audit(db, "system", "retention_cleanup", "", detail)
    return deleted
