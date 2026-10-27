"""Self-monitoring: /health payload + heartbeat checks (P1, P2).

The payload answers "is this thing actually working?" for an unattended
service: when data last arrived, when the scheduler last ran, how big the
database is, how much disk is left, whether alerts are stuck, and how old
the indicator lists are. `run_heartbeat` turns "no data for X hours" and
"indicator lists older than Y days" into hourly-deduplicated log alerts.
"""
from __future__ import annotations

import logging
import shutil
import time

from . import detect
from .audit import audit
from .config import Settings
from .db import Database
from .normalize import now_iso, parse_ts, utcnow

log = logging.getLogger("tracker.health")

DEFAULTS = {
    "heartbeat_hours": 6,            # alert when nothing ingested this long
    "indicator_max_age_days": 14,    # warn when indicator lists are stale
}


def _cfg(settings: Settings) -> dict:
    return {**DEFAULTS, **(settings.app.get("health", {}) or {})}


def indicator_age_days(settings: Settings) -> float | None:
    """Age of the newest shipped/updated indicator list, in days."""
    ind_dir = settings.config_dir / "indicators"
    if not ind_dir.is_dir():
        return None
    mtimes = [p.stat().st_mtime for p in ind_dir.glob("*.txt") if p.is_file()]
    if not mtimes:
        return None
    return round((time.time() - max(mtimes)) / 86400.0, 2)


def _last_ingest(db: Database):
    row = db.one("SELECT filename, ingested_at, record_count FROM files "
                 "WHERE status='ingested' ORDER BY id DESC LIMIT 1")
    return row


def _ingest_age_hours(db: Database) -> float | None:
    row = _last_ingest(db)
    if not row or not row["ingested_at"]:
        return None
    dt = parse_ts(row["ingested_at"])
    if not dt:
        return None
    return round((utcnow() - dt).total_seconds() / 3600.0, 2)


def health_payload(db: Database, settings: Settings) -> dict:
    """GET /health body. Unauthenticated by design (bind is 127.0.0.1)."""
    cfg = _cfg(settings)
    last = _last_ingest(db)
    pending = db.one(
        "SELECT COUNT(*) AS n FROM alerts_log WHERE status IN ('pending','failed')")
    db_path = settings.db_path
    db_mb = 0.0
    try:
        db_mb = round(sum(p.stat().st_size
                          for p in db_path.parent.glob(db_path.name + "*"))
                      / 1048576, 1)
    except OSError:
        pass
    free_gb = None
    try:
        free_gb = round(shutil.disk_usage(str(db_path.parent)).free
                        / (1024 ** 3), 2)
    except OSError:
        pass
    cycle = detect.last_cycle_info()
    ind_age = indicator_age_days(settings)
    ingest_age_h = _ingest_age_hours(db)

    problems: list[str] = []
    if ingest_age_h is not None and ingest_age_h > cfg["heartbeat_hours"]:
        problems.append(
            f"no data ingested for {ingest_age_h:.0f}h "
            f"(heartbeat limit {cfg['heartbeat_hours']}h)")
    if ind_age is not None and ind_age > cfg["indicator_max_age_days"]:
        problems.append(
            f"indicator lists are {ind_age:.1f} days old "
            f"(max {cfg['indicator_max_age_days']}d)")
    if free_gb is not None and free_gb < 2:
        problems.append(f"low disk: {free_gb} GB free")
    if cycle.get("error"):
        problems.append(f"last ingest cycle failed: {cycle['error']}")

    return {
        "status": "degraded" if problems else "ok",
        "now": now_iso(),
        "version": settings.version,
        "last_ingest_at": last["ingested_at"] if last else None,
        "last_ingest_file": last["filename"] if last else None,
        "ingest_age_hours": ingest_age_h,
        "last_scheduler_run": cycle.get("finished"),
        "scheduler_running": cycle.get("started") is not None
                             and cycle.get("started") == cycle.get("finished"),
        "database_mb": db_mb,
        "free_disk_gb": free_gb,
        "pending_alerts": int(pending["n"]) if pending else 0,
        "indicator_age_days": ind_age,
        "problems": problems,
    }


def run_heartbeat(db: Database, settings: Settings, now=None) -> dict:
    """Scheduled check: alert (log channel) on stale data / stale indicators.

    Alerts are deduplicated per hour via alerts_log.dedup_key, so a system
    that stays degraded emits at most one row per problem per hour - never a
    flood. A brand-new install that has never received a file does not alert
    (there is no ingest clock to measure yet); /health reports it instead.
    """
    cfg = _cfg(settings)
    now = now or utcnow()
    problems: list[tuple[str, str]] = []

    age_h = _ingest_age_hours(db)
    if age_h is not None and age_h > cfg["heartbeat_hours"]:
        problems.append((
            f"ingest:{now.strftime('%Y-%m-%dT%H')}",
            f"no data ingested for {age_h:.0f}h "
            f"(heartbeat limit {cfg['heartbeat_hours']}h)"))
    ind_age = indicator_age_days(settings)
    if ind_age is not None and ind_age > cfg["indicator_max_age_days"]:
        problems.append((
            f"indicator:{now.strftime('%Y-%m-%dT%H')}",
            f"indicator lists are {ind_age:.1f} days old "
            f"(max {cfg['indicator_max_age_days']}d)"))

    alerted = 0
    for bucket, message in problems:
        cur = db.execute(
            "INSERT INTO alerts_log(ts, incident_id, kind, channel, dedup_key, "
            "status, detail) VALUES(?,?, 'heartbeat', 'log', ?, 'logged', ?) "
            "ON CONFLICT(dedup_key) DO NOTHING",
            (now_iso(), None, f"heartbeat:{bucket}", message))
        if cur:
            alerted += 1
            log.warning("heartbeat: %s", message)
            audit(db, "system", "heartbeat_alert", "", message)
    return {"problems": [m for _, m in problems], "alerted": alerted}
