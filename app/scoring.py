"""Scoring and severity.

Model (documented in README):
  * PC score over the rolling window = sum over DISTINCT rule ids of that
    rule's weight (repeats of the same rule do not stack).
  * score < alert threshold  -> the signal is logged only (no incident)
  * score >= alert threshold -> alert / incident for the PC
  * severity = score band, then escalation rules (distinct categories on one
    PC, explicit category combinations) raise it; ransomware type is critical.
"""
from __future__ import annotations

import json
import logging

from .config import Settings
from .db import Database
from .normalize import now_iso, parse_ts, iso
from datetime import timedelta
from .rules.base import CATEGORIES

log = logging.getLogger("tracker.scoring")

_ORDER = ["low", "medium", "high", "critical"]


def _max_severity(a: str, b: str) -> str:
    return a if _ORDER.index(a) >= _ORDER.index(b) else b


def severity_rank(s: str) -> int:
    return _ORDER.index(s) if s in _ORDER else 0


def pc_window(db: Database, pc: str, hours: int) -> list:
    """Signals for a PC in the rolling window, anchored to the PC's most
    recent signal so historical test data scores deterministically."""
    latest = db.one("SELECT MAX(ts) AS ts FROM signals WHERE pc=?", (pc,))
    if not latest or not latest["ts"]:
        return []
    dt = parse_ts(latest["ts"])
    if not dt:
        return []
    from datetime import timedelta
    since = iso(dt - timedelta(hours=hours))
    return db.query(
        "SELECT * FROM signals WHERE pc=? AND ts>=? ORDER BY ts", (pc, since))


def score_pc(db: Database, settings: Settings, pc: str) -> dict | None:
    """Compute score/severity/categories for a PC. None when below threshold."""
    rows = pc_window(db, pc, settings.window_hours)
    if not rows:
        return None

    weights = settings.rule_weights
    per_rule: dict[str, int] = {}
    categories: set[str] = set()
    for row in rows:
        rid = row["rule_id"]
        weight = int(row["weight"]) or int(weights.get(rid, 0))
        per_rule[rid] = max(per_rule.get(rid, 0), weight)
        categories.add(row["category"])

    score = sum(per_rule.values())
    thresholds = settings.thresholds
    alert_score = int(thresholds.get("alert_score", 40))
    if score < alert_score:
        return {"score": score, "severity": None, "categories": sorted(categories),
                "rules": sorted(per_rule), "signals": len(rows), "alert": False}

    severity = "low"
    if score >= int(thresholds.get("severity_high", 80)):
        severity = "high"
    elif score >= int(thresholds.get("severity_medium", 60)):
        severity = "medium"

    severity = _escalate(settings, severity, categories)
    return {"score": score, "severity": severity, "categories": sorted(categories),
            "rules": sorted(per_rule), "signals": len(rows), "alert": True}


def _escalate(settings: Settings, severity: str, categories: set[str]) -> str:
    esc = settings.escalation
    n = len(categories & set(CATEGORIES)) or len(categories)
    if n >= int(esc.get("min_severity_with_categories_3", 3)):
        severity = _max_severity(severity, "high")
    elif n >= int(esc.get("min_severity_with_categories", 2)):
        severity = _max_severity(severity, "medium")
    for combo in esc.get("category_combinations", []) or []:
        if set(combo) <= categories:
            severity = _max_severity(severity, "high")
    return severity


def signal_categories(db: Database, incident_id: int) -> set[str]:
    rows = db.query("SELECT DISTINCT category FROM signals WHERE incident_id=?", (incident_id,))
    return {r["category"] for r in rows}


def _sig_get(sig, key: str, default: str = "") -> str:
    """Field access that works for dicts and sqlite3.Row alike."""
    try:
        value = sig[key] if not isinstance(sig, dict) else sig.get(key, default)
    except (IndexError, KeyError, TypeError):
        return default
    return str(value) if value is not None else default


def summarize_signal(settings: Settings, sig) -> str:
    """Human-readable evidence summary for a signal row (report/dashboard)."""
    title = _sig_get(sig, "title")
    detail = _sig_get(sig, "detail")
    text = f"{title} - {detail}" if detail else title
    return text[:400]


def history_7d(db: Database) -> list[dict]:
    """Daily signal counts for the last 7 days (dashboard chart)."""
    rows = db.query(
        "SELECT DATE(ts) AS day, COUNT(*) AS n FROM signals "
        "WHERE ts >= ? GROUP BY DATE(ts) ORDER BY day",
        ((parse_ts(now_iso()) - timedelta(days=6)).strftime("%Y-%m-%d"),))
    by_day = {r["day"]: int(r["n"]) for r in rows}
    out = []
    base = parse_ts(now_iso())
    for i in range(6, -1, -1):
        day = (base - timedelta(days=i)).strftime("%Y-%m-%d")
        out.append({"day": day, "count": by_day.get(day, 0)})
    return out


def signal_rules(db: Database, incident_id: int) -> set[str]:
    rows = db.query("SELECT DISTINCT rule_id FROM signals WHERE incident_id=?", (incident_id,))
    return {r["rule_id"] for r in rows}
