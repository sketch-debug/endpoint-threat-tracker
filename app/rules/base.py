"""Rule engine primitives.

Two rule shapes:
  * ObsRule  - evaluates a single normalized observation (event, DNS row, ...)
  * PCRule   - evaluates aggregate state for one PC (snapshots, bursts, windows)

Rules never write anything: they return SignalDrafts. The detector assigns
weights (config/scoring.yaml), persists signals, then scoring/incidents run.
Rule ids and their weights/categories live in config, not hard-coded weights.
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field

from ..config import Settings
from ..db import Database
from ..indicators import Indicators
from ..normalize import parse_ts

CATEGORIES = ("miner", "network", "execution", "persistence",
              "account", "evasion", "ransomware")


@dataclass
class SignalDraft:
    ts: str
    pc: str
    rule_id: str
    category: str
    title: str
    detail: str = ""
    correlation: list[tuple[str, str]] = field(default_factory=list)
    anchor: str = ""          # identity for dedup; defaults to observation payload hash
    observation_id: int | None = None


class ObsRule:
    """Per-observation rule."""
    record_types: frozenset[str] = frozenset()

    def eval(self, ctx: "Ctx", rec: dict) -> list[SignalDraft]:  # pragma: no cover
        raise NotImplementedError


class PCRule:
    """Per-PC aggregate rule (runs after each ingest for affected PCs)."""

    def eval_pc(self, ctx: "Ctx", pc: str, new_recs: list[dict]) -> list[SignalDraft]:  # pragma: no cover
        raise NotImplementedError


class Ctx:
    """Shared query helpers for rules (all parameterized)."""

    def __init__(self, db: Database, settings: Settings, indicators: Indicators):
        self.db = db
        self.settings = settings
        self.indicators = indicators

    # ---- time helpers ----------------------------------------------------
    def offhours(self, ts_iso: str) -> bool:
        dt = parse_ts(ts_iso)
        if not dt:
            return False
        local = dt.astimezone()
        minutes = local.hour * 60 + local.minute
        for start, end in self.settings.off_hours_minutes():
            if start <= end:
                if start <= minutes < end:
                    return True
            elif minutes >= start or minutes < end:  # window wraps midnight
                return True
        return False

    # ---- observation queries --------------------------------------------
    def rows(self, pc: str, record_type: str, since: str,
             until: str | None = None, limit: int = 20000) -> list:
        if until:
            return self.db.query(
                "SELECT ts, payload FROM observations WHERE pc=? AND record_type=? "
                "AND ts>=? AND ts<=? ORDER BY ts LIMIT ?",
                (pc, record_type, since, until, limit))
        return self.db.query(
            "SELECT ts, payload FROM observations WHERE pc=? AND record_type=? "
            "AND ts>=? ORDER BY ts LIMIT ?",
            (pc, record_type, since, limit))

    def count(self, pc: str, record_type: str, since: str, until: str | None = None) -> int:
        if until:
            row = self.db.one(
                "SELECT COUNT(*) AS n FROM observations WHERE pc=? AND record_type=? "
                "AND ts>=? AND ts<=?", (pc, record_type, since, until))
        else:
            row = self.db.one(
                "SELECT COUNT(*) AS n FROM observations WHERE pc=? AND record_type=? AND ts>=?",
                (pc, record_type, since))
        return int(row["n"]) if row else 0

    def snapshot_before(self, pc: str, record_type: str, ts: str) -> str | None:
        row = self.db.one(
            "SELECT MAX(ts) AS ts FROM observations WHERE pc=? AND record_type=? AND ts < ?",
            (pc, record_type, ts))
        return row["ts"] if row and row["ts"] else None

    def snapshot_payloads(self, pc: str, record_type: str, ts: str, limit: int = 5000) -> list[dict]:
        out = []
        for row in self.db.query(
                "SELECT payload FROM observations WHERE pc=? AND record_type=? AND ts=? LIMIT ?",
                (pc, record_type, ts, limit)):
            out.append(payload(row["payload"]))
        return out

    def payloads_between(self, pc: str, record_type: str, since: str, until: str,
                         limit: int = 20000) -> list[dict]:
        return [payload(r["payload"]) for r in
                self.rows(pc, record_type, since, until, limit)]

    def field_values(self, pc: str, record_type: str, field: str, since: str,
                     limit: int = 5000) -> set[str]:
        """Distinct values of one payload field seen since `since`."""
        out: set[str] = set()
        for row in self.rows(pc, record_type, since, limit=limit):
            val = row and payload(row["payload"]).get(field)
            if val:
                out.add(str(val).lower())
        return out


# ---- shared helpers -------------------------------------------------------
def payload(raw) -> dict:
    if isinstance(raw, dict):
        return raw
    try:
        obj = json.loads(raw or "{}")
    except (ValueError, TypeError):
        return {}
    return obj if isinstance(obj, dict) else {}


def fnum(value) -> float | None:
    try:
        if value is None or value == "":
            return None
        m = re.search(r"-?\d+(?:\.\d+)?", str(value))
        return float(m.group(0)) if m else None
    except (TypeError, ValueError):
        return None


def day_bucket(ts: str) -> str:
    return ts[:10]


def hour_bucket(ts: str) -> str:
    return ts[:13]


def short_hash(value: str) -> str:
    return hashlib.sha1((value or "").encode("utf-8", "replace")).hexdigest()[:16]


def basename(path: str) -> str:
    p = (path or "").replace("/", "\\")
    return p.rsplit("\\", 1)[-1].lower()
