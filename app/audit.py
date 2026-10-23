"""Audit log: logins, incident changes, config edits, automated actions.

Every write here is append-only; the dashboard shows it to admins.
"""
from __future__ import annotations

import logging

from .db import Database
from .normalize import now_iso

log = logging.getLogger("tracker.audit")


def audit(db: Database, actor: str, action: str, entity: str = "",
          detail: str = "", ip: str = "") -> None:
    db.execute(
        "INSERT INTO audit_log(ts, actor, action, entity, detail, ip) VALUES(?,?,?,?,?,?)",
        (now_iso(), actor, action, entity, detail, ip),
    )
    log.info("audit actor=%s action=%s entity=%s detail=%s ip=%s",
             actor, action, entity, detail, ip)


def recent(db: Database, limit: int = 200) -> list:
    return db.query("SELECT * FROM audit_log ORDER BY id DESC LIMIT ?", (int(limit),))
