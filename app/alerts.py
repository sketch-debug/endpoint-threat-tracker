"""Alert delivery: email + Teams webhook + always-on database/log record.

One alert per incident STATE CHANGE (opened, severity raised, pc added, type
changed, recovered, reopened) — never repeats for the same state, so there is
no alert spam. Every send attempt is recorded in alerts_log and audit_log and
alerts can be disabled entirely from config (human override), which is itself
logged. Ransomware/critical incidents carry the highest priority marker.
"""
from __future__ import annotations

import json
import logging
import os
import smtplib
import urllib.error
import urllib.request
from email.message import EmailMessage

from .audit import audit
from .config import Settings
from .db import Database
from .incidents import checklist_for
from .normalize import now_iso, utcnow as _utcnow  # noqa: F401  (re-exported for flush)

log = logging.getLogger("tracker.alerts")

# Retry policy for email/teams delivery: notify() only QUEUES those rows
# (status 'pending'); flush_pending_alerts() attempts them with exponential
# backoff. The ingest cycle therefore never blocks on an unreachable mail
# server, retries are bounded, and rows are updated in place - never
# duplicated - so a dead channel can never flood the alert log.
MAX_ALERT_ATTEMPTS = 10
_RETRY_BASE_SECONDS = 60          # 1m, 2m, 4m, ... capped at _RETRY_MAX
_RETRY_MAX_SECONDS = 6 * 3600


_KIND_LABELS = {
    "incident_opened": "Incident opened",
    "severity_raised": "Severity raised",
    "pc_added": "PC added to incident",
    "type_changed": "Incident type changed",
    "incident_merged": "Incidents merged",
    "recovered": "Incident recovered (re-check passed)",
    "reopened": "Incident REOPENED (new signal after cleanup)",
}


def render_message(settings: Settings, incident: dict, kind: str, message: str) -> str:
    label = _KIND_LABELS.get(kind, kind)
    priority = "P1 (highest)" if incident.get("severity") == "critical" else \
        str(incident.get("priority") or "-")
    pcs = incident.get("pcs") or []
    lines = [
        f"[{label}] {incident.get('incident_key')} - {incident.get('title') or incident.get('type')}",
        f"Type: {incident.get('type')}   Severity: {incident.get('severity')}   "
        f"Status: {incident.get('status')}   Priority: {priority}",
        f"Affected PCs ({len(pcs)}): {', '.join(pcs) if pcs else '-'}",
        f"Detail: {message}",
        "",
        "Response checklist:",
    ]
    for item in checklist_for(settings, str(incident.get("type", ""))):
        lines.append(f"  [ ] {item}")
    return "\n".join(lines)


def _send_email(settings: Settings, subject: str, body: str) -> tuple[str, str]:
    host = os.environ.get("SMTP_HOST", "")
    to_raw = os.environ.get("ALERT_TO", "")
    if not host or not to_raw:
        return "skipped_unconfigured", "SMTP_HOST/ALERT_TO not set"
    from_addr = os.environ.get("ALERT_FROM") or os.environ.get("SMTP_USER") or "tracker@localhost"
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = from_addr
    msg["To"] = to_raw
    msg.set_content(body)
    port = int(os.environ.get("SMTP_PORT", "587"))
    try:
        with smtplib.SMTP(host, port, timeout=15) as smtp:
            smtp.starttls()
            user = os.environ.get("SMTP_USER")
            password = os.environ.get("SMTP_PASSWORD")
            if user and password:
                smtp.login(user, password)
            smtp.send_message(msg)
        return "sent", f"smtp {host}:{port} -> {to_raw}"
    except (smtplib.SMTPException, OSError) as exc:
        log.error("email alert failed: %s", exc)
        return "failed", str(exc)[:500]


def _send_teams(settings: Settings, body: str) -> tuple[str, str]:
    url = os.environ.get("TEAMS_WEBHOOK_URL", "")
    if not url:
        return "skipped_unconfigured", "TEAMS_WEBHOOK_URL not set"
    payload = json.dumps({"text": body}).encode("utf-8")
    req = urllib.request.Request(url, data=payload,
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:  # noqa: S310 - admin-configured URL
            return "sent", f"webhook HTTP {resp.status}"
    except (urllib.error.URLError, OSError, ValueError) as exc:
        log.error("teams alert failed: %s", exc)
        return "failed", str(exc)[:500]


def notify(db: Database, settings: Settings, incident: dict, kind: str,
           message: str, actor: str = "system") -> str:
    """Record (and optionally send) one state-change alert. Returns status.

    Dedup key = incident + kind + state_version: the same state never alerts
    twice; any real state change bumps state_version and alerts once more.
    """
    incident_id = int(incident["id"])
    version = int(incident.get("state_version") or 0)
    base_key = f"{incident_id}:{kind}:v{version}"
    existing = db.one("SELECT status FROM alerts_log WHERE dedup_key=?",
                      (base_key + ":log",))
    if existing:
        return "duplicate"

    channels = settings.alert_channels
    body = render_message(settings, incident, kind, message)
    subject = f"[ThreatTracker] {incident.get('incident_key')} {kind}"

    if not channels:
        db.execute(
            "INSERT INTO alerts_log(ts, incident_id, kind, channel, dedup_key, status, detail) "
            "VALUES(?,?,?,?,?,?,?)",
            (now_iso(), incident_id, kind, "none", base_key + ":log", "disabled",
             "alerts disabled in config/app_config.yaml"))
        audit(db, actor, "alert_suppressed", str(incident.get("incident_key")),
              f"{kind}: alerts disabled in config")
        return "disabled"

    final_status = "logged"
    for channel in channels:
        if channel == "log":
            status, detail = "logged", "recorded in alerts log"
        elif channel in ("email", "teams"):
            # Queue the network send: delivery happens in flush_pending_alerts
            # on the scheduler, so an unreachable mail/webhook server cannot
            # block the ingest cycle (15 s timeout per attempt).
            status, detail = "pending", "queued for delivery with backoff retry"
        else:
            status, detail = "failed", f"unknown channel {channel!r}"
        db.execute(
            "INSERT INTO alerts_log(ts, incident_id, kind, channel, dedup_key, status, "
            "detail, attempts, next_retry_at, body, subject) "
            "VALUES(?,?,?,?,?,?,?,0,'',?,?)",
            (now_iso(), incident_id, kind, channel, f"{base_key}:{channel}", status,
             detail, body if channel in ("email", "teams") else "",
             subject if channel in ("email", "teams") else ""))
        if status == "pending":
            final_status = "pending"
        elif status in ("failed", "skipped_unconfigured") and final_status != "pending":
            final_status = status
        audit(db, actor, "alert_sent" if status in ("sent", "logged") else f"alert_{status}",
              str(incident.get("incident_key")), f"{kind} via {channel}: {status} ({detail})")
    return final_status


def flush_pending_alerts(db: Database, settings: Settings, limit: int = 10) -> int:
    """Attempt queued/failed email+Teams deliveries that are due.

    Called every minute from the scheduler. Updates rows in place (same
    dedup_key), applies exponential backoff, and stops after
    MAX_ALERT_ATTEMPTS tries with status 'gave_up'. Returns the number of
    attempts made. Never raises.
    """
    from datetime import datetime, timedelta, timezone

    due = db.query(
        "SELECT * FROM alerts_log WHERE channel IN ('email','teams') "
        "AND status IN ('pending','failed') AND attempts < ? "
        "AND (next_retry_at='' OR next_retry_at <= ?) "
        "ORDER BY id LIMIT ?",
        (MAX_ALERT_ATTEMPTS, now_iso(), limit),
    )
    made = 0
    for row in due:
        made += 1
        channel = row["channel"]
        attempts = int(row["attempts"]) + 1
        try:
            if not row["body"]:
                status, detail = "gave_up", "no stored message body for retry"
            elif channel == "email":
                status, detail = _send_email(settings, row["subject"], row["body"])
            else:
                status, detail = _send_teams(settings, row["body"])
        except Exception as exc:  # noqa: BLE001 - delivery must never crash the job
            log.exception("alert flush crashed for row %s", row["id"])
            status, detail = "failed", f"flush error: {type(exc).__name__}: {exc}"
        try:
            if status == "sent":
                db.execute(
                    "UPDATE alerts_log SET status='sent', detail=?, attempts=?, "
                    "next_retry_at='' WHERE id=?",
                    (detail, attempts, row["id"]))
            elif status == "skipped_unconfigured":
                db.execute(
                    "UPDATE alerts_log SET status='gave_up', detail=?, attempts=? "
                    "WHERE id=?", (detail, attempts, row["id"]))
            elif status == "gave_up":
                db.execute(
                    "UPDATE alerts_log SET status='gave_up', detail=?, attempts=? "
                    "WHERE id=?", (detail, attempts, row["id"]))
            else:
                if attempts >= MAX_ALERT_ATTEMPTS:
                    db.execute(
                        "UPDATE alerts_log SET status='gave_up', detail=?, attempts=? "
                        "WHERE id=?", (detail, attempts, row["id"]))
                else:
                    delay = min(_RETRY_BASE_SECONDS * (2 ** (attempts - 1)),
                                _RETRY_MAX_SECONDS)
                    next_at = (datetime.now(timezone.utc) + timedelta(seconds=delay)) \
                        .strftime("%Y-%m-%dT%H:%M:%SZ")
                    db.execute(
                        "UPDATE alerts_log SET status='failed', detail=?, attempts=?, "
                        "next_retry_at=? WHERE id=?",
                        (detail, attempts, next_at, row["id"]))
            audit(db, "system",
                  "alert_sent" if status == "sent" else "alert_failed",
                  str(row["id"]),
                  f"{row['kind']} via {channel} attempt {attempts}: {status} ({detail})")
        except Exception:  # noqa: BLE001
            log.exception("could not record alert flush result for row %s", row["id"])
    return made


def recent_alerts(db: Database, incident_id: int | None = None, limit: int = 100) -> list:
    if incident_id:
        return db.query(
            "SELECT * FROM alerts_log WHERE incident_id=? ORDER BY id DESC LIMIT ?",
            (incident_id, limit))
    return db.query("SELECT * FROM alerts_log ORDER BY id DESC LIMIT ?", (limit,))
