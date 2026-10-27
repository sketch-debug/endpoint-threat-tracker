"""Incidents: correlation, creation/join/merge, type suggestion, severity
escalation, per-PC workflow, analyst edits, checklists, timeline.

Correlation model: every signal carries correlation keys (pc, hash, domain,
task name, command pattern, source file). When a new signal arrives, all of
its keys are looked up against incident_keys of OPEN incidents. Signals join
the matching incident; if they match several open incidents they are all
merged into one. Incident types are suggested from the signal categories /
rule ids involved, but an analyst override always wins and is remembered.
"""
from __future__ import annotations

import json
import logging
from typing import Iterable

from .audit import audit
from .config import Settings
from .db import Database
from .normalize import now_iso

log = logging.getLogger("tracker.incidents")

# Per-PC workflow. Order matters: verified is the end state.
PC_STATES = ("detected", "isolated", "reimaged", "verified")
STATE_RANK = {s: i for i, s in enumerate(PC_STATES)}


def suggest_type(settings: Settings, categories: Iterable[str],
                 rules: Iterable[str], counts: dict | None = None) -> str:
    """Suggest an incident type. `counts` maps category/rule -> occurrences;
    the type matching the most signal evidence wins (ties: config order).
    Without counts, first config match wins."""
    cats = set(categories or ())
    rids = set(rules or ())
    counts = counts or {}
    best_type, best_score = "unknown", 0
    for type_id, cfg in settings.types.items():  # yaml order breaks ties
        want_cats = set(cfg.get("suggest_categories") or ())
        want_rules = set(cfg.get("suggest_rules") or ())
        if counts:
            score = sum(int(counts.get(f"cat:{c}", 0)) for c in (cats & want_cats))
            score += sum(int(counts.get(f"rule:{r}", 0)) * 2 for r in (rids & want_rules))
        else:
            score = len(cats & want_cats) + 2 * len(rids & want_rules)
        if score > best_score:
            best_type, best_score = type_id, score
    return best_type


def _bump(db: Database, incident_id: int) -> int:
    db.execute("UPDATE incidents SET state_version = state_version + 1 WHERE id=?",
               (incident_id,))
    row = db.one("SELECT state_version FROM incidents WHERE id=?", (incident_id,))
    return int(row["state_version"]) if row else 0


def _event(db: Database, incident_id: int, action: str, detail: str = "",
           transition: str = "", actor: str = "system") -> None:
    db.execute(
        "INSERT INTO incident_events(incident_id, ts, action, detail, transition, actor) "
        "VALUES(?,?,?,?,?,?)",
        (incident_id, now_iso(), action, detail, transition, actor))


def _load(db: Database, incident_id: int) -> dict:
    row = db.one("SELECT * FROM incidents WHERE id=?", (incident_id,))
    if row is None:
        raise LookupError(f"incident {incident_id} not found")
    inc = dict(row)
    inc["pcs"] = [r["pc"] for r in db.query(
        "SELECT pc FROM incident_pcs WHERE incident_id=? ORDER BY pc", (incident_id,))]
    return inc


def get(db: Database, incident_id: int) -> dict:
    return _load(db, incident_id)


def _signal_keys(sig: dict) -> list[tuple[str, str]]:
    keys = [("pc", str(sig.get("pc") or ""))]
    raw = sig.get("correlation")
    parsed: list[list[str]] = []
    if isinstance(raw, str) and raw:
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError:
            parsed = []
    elif isinstance(raw, list):
        parsed = raw
    for entry in parsed:
        if isinstance(entry, (list, tuple)) and len(entry) == 2 and entry[1]:
            keys.append((str(entry[0]), str(entry[1])))
    return [(k, v) for k, v in keys if v]


def _find_matching(db: Database, keys: list[tuple[str, str]]) -> set[int]:
    """Open incidents referenced by any correlation key, plus any open
    incident that already contains this PC."""
    ids: set[int] = set()
    for key_type, key_value in keys:
        rows = db.query(
            "SELECT ik.incident_id FROM incident_keys ik "
            "JOIN incidents i ON i.id = ik.incident_id "
            "WHERE ik.key_type=? AND ik.key_value=? AND i.status != 'closed'",
            (key_type, key_value))
        ids.update(int(r["incident_id"]) for r in rows)
    return ids


def _merge(db: Database, settings: Settings, keep_id: int, drop_ids: set[int],
           actor: str) -> dict:
    for drop_id in sorted(drop_ids):
        if drop_id == keep_id:
            continue
        db.execute(
            "DELETE FROM incident_keys WHERE incident_id=? AND (key_type, key_value) IN "
            "(SELECT key_type, key_value FROM incident_keys WHERE incident_id=?)",
            (keep_id, drop_id))
        for table, col in (("incident_pcs", "incident_id"), ("incident_keys", "incident_id"),
                           ("signals", "incident_id"), ("incident_events", "incident_id"),
                           ("checklist_state", "incident_id")):
            if table == "incident_pcs":
                # avoid PK clashes on (incident_id, pc): delete duplicates first
                db.execute(
                    "DELETE FROM incident_pcs WHERE incident_id=? AND pc IN "
                    "(SELECT pc FROM incident_pcs WHERE incident_id=?)", (keep_id, drop_id))
            if table == "checklist_state":
                db.execute(
                    "DELETE FROM checklist_state WHERE incident_id=? AND item IN "
                    "(SELECT item FROM checklist_state WHERE incident_id=?)", (keep_id, drop_id))
            db.execute(f"UPDATE {table} SET {col}=? WHERE {col}=?", (keep_id, drop_id))
        db.execute("DELETE FROM incidents WHERE id=?", (drop_id,))
        _bump(db, keep_id)
        _event(db, keep_id, "incident_merged", f"merged {drop_id} into this incident",
               "merged", actor)
        audit(db, actor, "incident_merge", str(keep_id), f"merged incident {drop_id}")
    return _load(db, keep_id)


def _refresh_type(db: Database, settings: Settings, incident_id: int,
                  actor: str = "system") -> tuple[dict, bool]:
    """Re-suggest type when it was auto-chosen; analyst overrides are kept."""
    inc = db.one("SELECT * FROM incidents WHERE id=?", (incident_id,))
    if inc is None:
        return {}, False
    if inc["type_source"] == "analyst":
        return dict(inc), False
    rows = db.query("SELECT category, rule_id, COUNT(*) AS n FROM signals "
                    "WHERE incident_id=? GROUP BY category, rule_id", (incident_id,))
    counts: dict[str, int] = {}
    cats: set[str] = set()
    rids: set[str] = set()
    for r in rows:
        n = int(r["n"])
        if r["category"]:
            cats.add(str(r["category"]))
            counts[f"cat:{r['category']}"] = counts.get(f"cat:{r['category']}", 0) + n
        if r["rule_id"]:
            rids.add(str(r["rule_id"]))
            counts[f"rule:{r['rule_id']}"] = counts.get(f"rule:{r['rule_id']}", 0) + n
    suggestion = suggest_type(settings, cats, rids, counts)
    if suggestion != inc["type"]:
        db.execute("UPDATE incidents SET type=?, type_source='auto' WHERE id=?",
                   (suggestion, incident_id))
        _event(db, incident_id, "incident_type",
               f"type changed {inc['type']} -> {suggestion} (auto)", "type_changed", actor)
        _init_checklist(db, settings, incident_id, suggestion)
        _bump(db, incident_id)
        return _load(db, incident_id), True
    return _load(db, incident_id), False


def _recompute_severity(db: Database, settings: Settings, incident_id: int,
                        incoming_severity: str, actor: str) -> tuple[dict, bool]:
    """Incident severity = worst severity across its PCs / signals."""
    order = ["low", "medium", "high", "critical"]
    inc = db.one("SELECT severity FROM incidents WHERE id=?", (incident_id,))
    current = (inc["severity"] if inc else None) or "low"
    if current not in order:
        current = "low"
    incoming = incoming_severity if incoming_severity in order else "low"
    if order.index(incoming) > order.index(current):
        db.execute("UPDATE incidents SET severity=? WHERE id=?",
                   (incoming, incident_id))
        _event(db, incident_id, "severity_raised",
               f"severity {current} -> {incoming}", "severity_raised", actor)
        _bump(db, incident_id)
        return _load(db, incident_id), True
    return _load(db, incident_id), False


def _create(db: Database, settings: Settings, sig: dict, severity: str,
            categories: list[str], rules: list[str], keys: list[tuple[str, str]],
            actor: str) -> int:
    n_row = db.one("SELECT COALESCE(MAX(id), 0) + 1 AS n FROM incidents")
    n = int(n_row["n"]) if n_row else 1
    incident_key = f"INC-{n:04d}"
    itype = suggest_type(settings, categories, rules)
    priority = str((settings.types.get(itype) or {}).get("priority", "medium") or "medium")
    title = f"{itype} suspected on {sig.get('pc')}"
    ts = now_iso()
    incident_id = int(db.execute(
        "INSERT INTO incidents(incident_key, title, type, type_source, status, severity, "
        "priority, created_at, state_version) VALUES(?,?,?,?,?,?,?,?,0)",
        (incident_key, title, itype, "auto", "open", severity, priority, ts)))
    db.execute("INSERT INTO incident_pcs(incident_id, pc, first_seen, state, state_ts, "
               "recheck_passed) VALUES(?,?,?,?,?,0)",
               (incident_id, str(sig.get("pc")), ts, "detected", ts))
    for key_type, key_value in keys:
        db.execute("INSERT OR IGNORE INTO incident_keys(incident_id, key_type, key_value, "
                   "created_at) VALUES(?,?,?,?)", (incident_id, key_type, key_value, ts))
    _event(db, incident_id, "opened",
           f"auto-created from signal {sig.get('id')}; suggested type {itype}; "
           f"severity {severity}", "opened", actor)
    _init_checklist(db, settings, incident_id, itype)
    audit(db, actor, "incident_open", incident_key, f"type={itype} severity={severity}")
    return incident_id


def _join(db: Database, settings: Settings, incident_id: int, sig: dict, severity: str,
          categories: list[str], rules: list[str], keys: list[tuple[str, str]],
          actor: str) -> None:
    ts = now_iso()
    pc = str(sig.get("pc"))
    db.execute("UPDATE signals SET incident_id=? WHERE id=?", (incident_id, sig.get("id")))
    existing = db.one("SELECT pc FROM incident_pcs WHERE incident_id=? AND pc=?",
                      (incident_id, pc))
    if existing is None:
        db.execute("INSERT INTO incident_pcs(incident_id, pc, first_seen, state, state_ts, "
                   "recheck_passed) VALUES(?,?,?,?,?,0)",
                   (incident_id, pc, ts, "detected", ts))
        _event(db, incident_id, "pc_added", f"PC {pc} added to incident", "pc_added", actor)
        _bump(db, incident_id)
    for key_type, key_value in keys:
        db.execute("INSERT OR IGNORE INTO incident_keys(incident_id, key_type, key_value, "
                   "created_at) VALUES(?,?,?,?)", (incident_id, key_type, key_value, ts))


def correlate_and_record(db: Database, settings: Settings, sig: dict, severity: str,
                         categories: list[str], rules: list[str],
                         actor: str = "system") -> tuple[dict, list[str]]:
    """Attach a signal to an incident (joining, creating, or merging).

    Returns (incident, transitions) where transitions is a list of the state
    changes that happened: opened / pc_added / severity_raised / type_changed /
    incident_merged. The caller alerts once per transition.
    """
    keys = _signal_keys(sig)
    with db.tx():
        matches = _find_matching(db, keys)
        incident_id: int | None
        transitions: list[str] = []
        if len(matches) > 1:
            keep = min(matches)
            merged = _merge(db, settings, keep, matches - {keep}, actor)
            incident_id = int(merged["id"])
            transitions.append("incident_merged")
        elif len(matches) == 1:
            incident_id = next(iter(matches))
        else:
            incident_id = _create(db, settings, sig, severity, categories, rules, keys, actor)
            inc = _load(db, incident_id)
            db.execute("UPDATE signals SET incident_id=? WHERE id=?", (incident_id, sig.get("id")))
            return inc, ["opened"]
        pc = str(sig.get("pc"))
        had_pc = db.one("SELECT pc FROM incident_pcs WHERE incident_id=? AND pc=?",
                        (incident_id, pc)) is not None
        _join(db, settings, incident_id, sig, severity, categories, rules, keys, actor)
        if not had_pc:
            transitions.append("pc_added")
        inc, type_changed = _refresh_type(db, settings, incident_id, actor)
        if type_changed:
            transitions.append("type_changed")
        inc, raised = _recompute_severity(db, settings, incident_id, severity, actor)
        if raised:
            transitions.append("severity_raised")
        return inc, transitions


def _recheck_for(settings: Settings) -> int:
    return int(settings.recheck_days)


def transition_pc(db: Database, settings: Settings, incident_id: int, pc: str, new_state: str,
                  actor: str, note: str = "", owner: str = "") -> dict:
    """Move one PC through detected -> isolated -> reimaged -> verified."""
    if new_state not in PC_STATES:
        raise ValueError(f"invalid state {new_state!r}; must be one of {PC_STATES}")
    with db.tx():
        row = db.one("SELECT * FROM incident_pcs WHERE incident_id=? AND pc=?",
                     (incident_id, pc))
        if row is None:
            raise LookupError(f"PC {pc} is not part of incident {incident_id}")
        old_state = row["state"]
        ts = now_iso()
        recheck_until = None
        if new_state == "verified":
            days = _recheck_for(settings)
            recheck_until = _plus_days(days)
            db.execute(
                "UPDATE incident_pcs SET state=?, state_ts=?, note=?, owner=?, "
                "verified_at=?, recheck_until=?, recheck_passed=0 WHERE incident_id=? AND pc=?",
                (new_state, ts, note, owner, ts, recheck_until, incident_id, pc))
        else:
            db.execute(
                "UPDATE incident_pcs SET state=?, state_ts=?, note=?, owner=?, "
                "verified_at=NULL, recheck_until=NULL, recheck_passed=0 "
                "WHERE incident_id=? AND pc=?",
                (new_state, ts, note, owner, incident_id, pc))
        _event(db, incident_id, "pc_workflow",
               f"PC {pc}: {old_state} -> {new_state}" + (f" ({note})" if note else ""),
               transition=f"{old_state}->{new_state}", actor=actor)
        audit(db, actor, "incident_transition", str(incident_id),
              f"{pc} {old_state}->{new_state}")
        return _load(db, incident_id)


def _plus_days(days: int) -> str:
    from datetime import timedelta
    from .normalize import iso, utcnow
    # UTC (Z-suffixed): recheck.py compares this against now_iso(). Naive
    # local time skewed the 14-day re-check window by the host's UTC offset.
    return iso(utcnow() + timedelta(days=days))


def set_entry_point(db: Database, incident_id: int, entry_point: str, actor: str) -> dict:
    with db.tx():
        db.execute("UPDATE incidents SET entry_point=? WHERE id=?", (entry_point, incident_id))
        _event(db, incident_id, "entry_point", f"entry point set: {entry_point}", "", actor)
        audit(db, actor, "incident_edit", str(incident_id), "entry point updated")
        return _load(db, incident_id)


def set_actions(db: Database, incident_id: int, actions: str, actor: str) -> dict:
    with db.tx():
        db.execute("UPDATE incidents SET containment_actions=? WHERE id=?",
                   (actions, incident_id))
        _event(db, incident_id, "containment_actions", "containment actions updated", "", actor)
        audit(db, actor, "incident_edit", str(incident_id), "containment actions updated")
        return _load(db, incident_id)


def set_reimaged(db: Database, incident_id: int, reimaged: bool, actor: str) -> dict:
    with db.tx():
        db.execute("UPDATE incidents SET reimaged=? WHERE id=?", (1 if reimaged else 0,
                                                                  incident_id))
        _event(db, incident_id, "reimaged_flag", f"reimaged={reimaged}", "", actor)
        audit(db, actor, "incident_edit", str(incident_id), f"reimaged={reimaged}")
        return _load(db, incident_id)


def set_type(db: Database, settings: Settings, incident_id: int, new_type: str,
             actor: str) -> dict:
    if new_type not in settings.types:
        raise ValueError(f"unknown incident type {new_type!r}")
    with db.tx():
        old = db.one("SELECT type FROM incidents WHERE id=?", (incident_id,))
        priority = str((settings.types.get(new_type) or {}).get("priority", "medium") or "medium")
        db.execute("UPDATE incidents SET type=?, type_source='analyst', priority=? WHERE id=?",
                   (new_type, priority, incident_id))
        old_type = old["type"] if old else ""
        _event(db, incident_id, "incident_type",
               f"type changed {old_type} -> {new_type} (analyst)",
               "type_changed", actor)
        _init_checklist(db, settings, incident_id, new_type)
        _bump(db, incident_id)
        audit(db, actor, "incident_type", str(incident_id), f"type={new_type}")
        return _load(db, incident_id)


def _init_checklist(db: Database, settings: Settings, incident_id: int, itype: str) -> None:
    items = checklist_for(settings, itype)
    ts = now_iso()
    for item in items:
        db.execute("INSERT OR IGNORE INTO checklist_state(incident_id, item, done, ts) "
                   "VALUES(?,?,0,?)", (incident_id, item, ts))


def checklist_for(settings: Settings, itype: str) -> list[str]:
    return list((settings.types.get(itype) or {}).get("checklist") or [])


def toggle_checklist(db: Database, incident_id: int, item: str, done: bool,
                     actor: str) -> dict:
    with db.tx():
        db.execute("INSERT OR IGNORE INTO checklist_state(incident_id, item, done, ts) "
                   "VALUES(?,?,0,?)", (incident_id, item, ""))
        db.execute("UPDATE checklist_state SET done=?, ts=? WHERE incident_id=? AND item=?",
                   (1 if done else 0, now_iso(), incident_id, item))
        audit(db, actor, "checklist", str(incident_id), f"{item!r} -> {done}")
        return _load(db, incident_id)


def close_incident(db: Database, settings: Settings, incident_id: int, actor: str,
                   note: str = "") -> dict:
    with db.tx():
        db.execute("UPDATE incidents SET status='closed', closed_at=? WHERE id=?",
                   (now_iso(), incident_id))
        _event(db, incident_id, "closed", f"incident closed ({note})", "closed", actor)
        audit(db, actor, "incident_close", str(incident_id), note)
        return _load(db, incident_id)


def reopen_incident(db: Database, settings: Settings, incident_id: int, actor: str,
                    reason: str = "") -> dict:
    with db.tx():
        db.execute("UPDATE incidents SET status='open', closed_at=NULL WHERE id=?",
                   (incident_id,))
        _event(db, incident_id, "reopened", f"incident reopened ({reason})", "reopened", actor)
        _bump(db, incident_id)
        audit(db, actor, "incident_reopen", str(incident_id), reason)
        return _load(db, incident_id)


def open_incidents(db: Database) -> list:
    return db.query("SELECT * FROM incidents WHERE status='open' ORDER BY id DESC")


def list_incidents(db: Database, status: str | None = None, severity: str | None = None,
                   itype: str | None = None, limit: int = 200) -> list:
    sql = "SELECT * FROM incidents WHERE 1=1"
    args: list = []
    if status:
        sql += " AND status=?"
        args.append(status)
    if severity:
        sql += " AND severity=?"
        args.append(severity)
    if itype:
        sql += " AND type=?"
        args.append(itype)
    sql += " ORDER BY id DESC LIMIT ?"
    args.append(limit)
    return db.query(sql, args)


def timeline(db: Database, incident_id: int) -> list:
    return db.query("SELECT * FROM incident_events WHERE incident_id=? ORDER BY ts, id",
                    (incident_id,))


def checklist_state(db: Database, incident_id: int) -> list:
    return db.query("SELECT item, done, ts FROM checklist_state WHERE incident_id=? "
                    "ORDER BY item", (incident_id,))


def incident_signals(db: Database, incident_id: int) -> list:
    return db.query(
        "SELECT s.*, o.record_type AS source_type FROM signals s "
        "LEFT JOIN observations o ON o.id = s.observation_id "
        "WHERE s.incident_id=? ORDER BY s.ts DESC", (incident_id,))


def pcs_of(db: Database, incident_id: int) -> list:
    return db.query("SELECT * FROM incident_pcs WHERE incident_id=? ORDER BY pc",
                    (incident_id,))


def ensure_checklist(db: Database, settings: Settings, incident_id: int) -> None:
    """Seed checklist items when auto type suggestion changed the type."""
    inc = db.one("SELECT type FROM incidents WHERE id=?", (incident_id,))
    if inc is None:
        return
    with db.tx():
        _init_checklist(db, settings, incident_id, str(inc["type"]))
