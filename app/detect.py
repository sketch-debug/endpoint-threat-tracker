"""The Detector: runs rules over stored observations, persists signals,
scores PCs, correlates incidents. Called by the Ingestor inside its ingest
transaction (DB-only work); alerts it queues are flushed by run_cycle after
the transaction commits.
"""
from __future__ import annotations

import json
import logging
import threading

from .normalize import now_iso

from . import alerts, incidents, recheck, scoring
from .config import Settings
from .db import Database
from .indicators import Indicators
from .rules import all_obs_rules, all_pc_rules
from .rules.base import Ctx, SignalDraft, payload

log = logging.getLogger("tracker.detect")

_TRANSITION_ALERT = {
    "opened": "incident_opened",
    "pc_added": "pc_added",
    "severity_raised": "severity_raised",
    "type_changed": "type_changed",
    "incident_merged": "incident_merged",
}


class Detector:
    """Rule evaluation + signal persistence + incident correlation.

    Detection is deterministic and idempotent: signal dedup keys make re-runs
    no-ops, so re-scanning a PC after every ingest never duplicates signals.
    """

    def __init__(self, db: Database, settings: Settings, indicators: Indicators):
        self.db = db
        self.settings = settings
        self.indicators = indicators
        self.ctx = Ctx(db, settings, indicators)
        self._obs_rules = all_obs_rules()
        self._pc_rules = all_pc_rules()
        self._pending: list[tuple[dict, str, str]] = []

    # ---- pending alerts (flushed after the ingest tx commits) -----------
    def take_pending(self) -> list[tuple[dict, str, str]]:
        pending, self._pending = self._pending, []
        return pending

    # ---- rule evaluation -------------------------------------------------
    def _records_for(self, pc: str) -> list[dict]:
        """The most recent 50 000 observations for a PC, oldest first.

        The cap protects rule evaluation at scale, so it must keep the NEWEST
        evidence (P20): on a data-heavy PC the oldest 50 000 rows are months
        old and today's activity never reaches the rules. The sub-select picks
        by recency via idx_obs_pc_ts; the outer ORDER BY hands rules the same
        chronological order they had before the cap.
        """
        out: list[dict] = []
        for row in self.db.query(
                "SELECT id, ts, record_type, payload FROM ("
                "SELECT id, ts, record_type, payload FROM observations "
                "WHERE pc=? ORDER BY ts DESC, id DESC LIMIT 50000) "
                "ORDER BY ts, id", (pc,)):
            rec = payload(row["payload"])
            rec["_obs_id"] = int(row["id"])
            rec["_record_type"] = row["record_type"]
            out.append(rec)
        return out

    def _drafts_for(self, pc: str, records: list[dict]) -> list[SignalDraft]:
        drafts: list[SignalDraft] = []
        for rule in self._obs_rules:
            for rec in records:
                if rec.get("_record_type") not in rule.record_types:
                    continue
                try:
                    drafts.extend(rule.eval(self.ctx, rec) or [])
                except Exception:  # noqa: BLE001 - a bad rule must not stop ingest
                    log.exception("rule %s failed on %s", type(rule).__name__, pc)
        for rule in self._pc_rules:
            try:
                drafts.extend(rule.eval_pc(self.ctx, pc, records) or [])
            except Exception:  # noqa: BLE001
                log.exception("rule %s failed on %s", type(rule).__name__, pc)
        return drafts

    # ---- persistence -----------------------------------------------------
    def _dedup_key(self, draft: SignalDraft) -> str:
        if draft.observation_id:
            return f"{draft.rule_id}|obs|{draft.observation_id}"
        anchor = draft.anchor or draft.detail
        return f"{draft.rule_id}|pc|{draft.pc}|{anchor}"

    def _store(self, draft: SignalDraft) -> int | None:
        """Insert a signal; returns its row id, or None when it was a dup."""
        weight = int(self.settings.rule_weights.get(draft.rule_id, 0))
        correlation = json.dumps([list(pair) for pair in (draft.correlation or [])])
        rowid = self.db.execute(
            "INSERT OR IGNORE INTO signals(ts, pc, rule_id, category, weight, title, "
            "detail, observation_id, correlation, incident_id, dedup_key) "
            "VALUES(?,?,?,?,?,?,?,?,?,NULL,?)",
            (draft.ts, draft.pc, draft.rule_id, draft.category, weight, draft.title,
             draft.detail, draft.observation_id, correlation, self._dedup_key(draft)))
        return rowid or None

    # ---- main entry point ------------------------------------------------
    def run(self, pcs: set[str]) -> dict:
        stored = 0
        incidents_touched: set[int] = set()
        for pc in sorted(pcs):
            records = self._records_for(pc)
            if not records:
                continue
            for draft in self._drafts_for(pc, records):
                if self._store(draft):
                    stored += 1
            self._correlate_pc(pc, incidents_touched)
        return {"signals": stored, "incidents_touched": len(incidents_touched)}

    def _correlate_pc(self, pc: str, touched: set[int]) -> None:
        """If the PC is now above the alert threshold, attach its new signals
        to an incident (joining/creating/merging) and queue alerts."""
        score = scoring.score_pc(self.db, self.settings, pc)
        if not score or not score.get("alert"):
            return
        severity = str(score.get("severity") or "low")
        categories = list(score.get("categories") or [])
        rules = list(score.get("rules") or [])
        # every signal for this PC that is not yet part of an incident
        rows = self.db.query(
            "SELECT * FROM signals WHERE pc=? AND incident_id IS NULL ORDER BY ts, id", (pc,))
        for row in rows:
            sig = dict(row)
            try:
                inc, transitions = incidents.correlate_and_record(
                    self.db, self.settings, sig, severity, categories, rules,
                    actor="system")
            except Exception:  # noqa: BLE001 - correlation must never lose the ingest
                log.exception("correlation failed for %s", pc)
                continue
            incidents.ensure_checklist(self.db, self.settings, int(inc["id"]))
            touched.add(int(inc["id"]))
            message = (f"New {severity} signal on {pc}: "
                       f"{', '.join(rules[:4])} [{', '.join(categories)}]")
            for transition in transitions:
                kind = _TRANSITION_ALERT.get(transition)
                if kind:
                    self._pending.append((inc, kind, message))

    def flush_alerts(self) -> int:
        """Send queued state-change alerts (call AFTER the ingest tx commits)."""
        sent = 0
        for inc, kind, message in self.take_pending():
            try:
                alerts.notify(self.db, self.settings, inc, kind, message, actor="system")
                sent += 1
            except Exception:  # noqa: BLE001 - alert failure must not crash the watcher
                log.exception("alert failed for incident %s kind %s",
                              inc.get("incident_key"), kind)
        return sent


# Process-local record of the last ingest cycle, read by /health so an
# unattended service can prove its scheduler is alive (P2).
_last_cycle: dict = {"started": None, "finished": None, "error": None}


def last_cycle_info() -> dict:
    return dict(_last_cycle)


# One cycle at a time: the scheduled job and the manual /run/ingest button
# share this lock, so a manual trigger can never run a second full cycle
# (inbox files processed twice, alerts double-queued) alongside the scheduler.
_cycle_lock = threading.Lock()


def run_cycle(ingestor, detector: Detector) -> dict:
    """One full cycle: ingest inbox, detect, correlate, alert, re-check sweep.

    Alerts are flushed after the ingest transaction commits; the re-check
    sweep expires finished 14-day windows and auto-closes clean incidents.
    Returns stats with `skipped: True` when another cycle is still running.
    """
    if not _cycle_lock.acquire(blocking=False):
        log.info("ingest cycle already running; skipping this trigger")
        return {"skipped": True, "files": 0, "ingested": 0, "duplicates": 0,
                "errors": 0, "deferred": 0, "observations": 0, "signals": 0,
                "incidents_touched": 0, "alerts_sent": 0, "recheck": {}}
    try:
        _last_cycle["started"] = now_iso()
        _last_cycle["error"] = None
        stats = ingestor.scan_once()
        stats["alerts_sent"] = detector.flush_alerts()
        try:
            stats["recheck"] = recheck.run_recheck_sweep(ingestor.db, ingestor.settings)
        except Exception:  # noqa: BLE001
            log.exception("recheck sweep failed")
            stats["recheck"] = {"error": "sweep failed; see logs"}
        return stats
    except Exception as exc:
        _last_cycle["error"] = f"{type(exc).__name__}: {exc}"
        raise
    finally:
        _last_cycle["finished"] = now_iso()
        _cycle_lock.release()
