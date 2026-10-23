"""14-day post-cleanup re-check.

After a PC reaches 'verified' it is watched for `recheck.days` (default 14).
Any NEW signal on that PC during the window reopens its incident (recovery
alert is superseded by a REOPENED alert). If the window expires with no new
signals the PC is marked passed and the incident auto-closes when every PC
has passed. Runs on the scheduler; nothing here contacts the PC itself.
"""
from __future__ import annotations

import logging

from . import alerts, incidents
from .audit import audit
from .config import Settings
from .db import Database
from .normalize import now_iso

log = logging.getLogger("tracker.recheck")


def check_signal_against_recheck(db: Database, settings: Settings, sig: dict,
                                 severity: str) -> list[dict]:
    """Called for each new signal. Reopens any verified PC in re-check.

    Returns the incidents that were reopened (so the caller can alert once
    per incident rather than per PC).
    """
    pc = str(sig.get("pc") or "")
    if not pc:
        return []
    if not settings.recheck_enabled:
        return []
    rows = db.query(
        "SELECT ip.incident_id, ip.state, ip.recheck_until FROM incident_pcs ip "
        "JOIN incidents i ON i.id = ip.incident_id "
        "WHERE ip.pc=? AND ip.state='verified' AND ip.recheck_until IS NOT NULL "
        "AND i.status='open'", (pc,))
    reopened: list[dict] = []
    seen: set[int] = set()
    for row in rows:
        incident_id = int(row["incident_id"])
        if incident_id in seen:
            continue
        seen.add(incident_id)
        with db.tx():
            db.execute(
                "UPDATE incident_pcs SET state='detected', state_ts=?, verified_at=NULL, "
                "recheck_passed=0, recheck_until=NULL WHERE incident_id=? AND pc=?",
                (now_iso(), incident_id, pc))
            incidents._event(  # noqa: SLF001 - same package
                db, incident_id, "reopened",
                f"PC {pc} had a NEW signal during re-check: "
                f"{sig.get('rule_id') or sig.get('category')} - re-opened",
                "reopened", "system")
            db.execute("UPDATE incidents SET status='open', closed_at=NULL, "
                       "state_version = state_version + 1 WHERE id=?", (incident_id,))
            audit(db, "system", "incident_reopen", str(incident_id),
                  f"auto-reopen: new signal on {pc} during re-check")
        inc = incidents.get(db, incident_id)
        reopened.append(inc)
        alerts.notify(db, settings, inc, "reopened",
                      f"New signal on re-checked PC {pc}: "
                      f"{sig.get('rule_id') or sig.get('category')}. "
                      f"Re-verification required.")
    return reopened


def run_recheck_sweep(db: Database, settings: Settings) -> dict:
    """Expire finished re-check windows: mark pass, auto-close incidents."""
    if not settings.recheck_enabled:
        return {"rechecks_passed": 0, "incidents_closed": 0, "closed_ids": [],
                "swept_at": now_iso(), "disabled": True}
    now = now_iso()
    rows = db.query(
        "SELECT ip.incident_id, ip.pc, ip.recheck_until FROM incident_pcs ip "
        "JOIN incidents i ON i.id = ip.incident_id "
        "WHERE ip.state='verified' AND ip.recheck_passed=0 "
        "AND ip.recheck_until IS NOT NULL AND i.status='open'")
    passed = 0
    closed: list[int] = []
    for row in rows:
        until = str(row["recheck_until"] or "")
        if until > now:
            continue
        with db.tx():
            db.execute("UPDATE incident_pcs SET recheck_passed=1 WHERE incident_id=? AND pc=?",
                       (int(row["incident_id"]), row["pc"]))
            incidents._event(  # noqa: SLF001 - same package
                db, int(row["incident_id"]), "recheck_passed",
                f"PC {row['pc']} stayed clean for the full re-check window", "", "system")
        passed += 1
    # close incidents whose every PC passed re-check
    open_rows = incidents.open_incidents(db)
    for inc in open_rows:
        pcs = incidents.pcs_of(db, int(inc["id"]))
        if pcs and all(int(p["recheck_passed"] or 0) == 1 for p in pcs):
            closed_inc = incidents.close_incident(
                db, settings, int(inc["id"]), actor="system",
                note="all PCs passed the 14-day re-check")
            alerts.notify(db, settings, closed_inc, "recovered",
                          "All affected PCs stayed clean for the full re-check window; "
                          "incident auto-closed.")
            closed.append(int(inc["id"]))
    result = {"rechecks_passed": passed, "incidents_closed": len(closed),
              "closed_ids": closed, "swept_at": now}
    if passed or closed:
        log.info("recheck sweep: %s", result)
    return result
