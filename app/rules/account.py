"""Account/access rules: failed-login bursts, burst-then-success, off-hours
logins and logins from unusual source PCs."""
from __future__ import annotations

from ..normalize import window_start
from .base import Ctx, ObsRule, SignalDraft, day_bucket, hour_bucket


def _burst_params(ctx: Ctx) -> tuple[int, str]:
    failures = int(ctx.settings.thresholds.get("login_burst_failures", 5))
    minutes = int(ctx.settings.thresholds.get("login_burst_minutes", 10))
    return failures, minutes


def _window_since(ts: str, minutes: int) -> str:
    from datetime import timedelta
    from ..normalize import parse_ts, iso
    dt = parse_ts(ts)
    if not dt:
        return ts
    return iso(dt - timedelta(minutes=minutes))


def _failures(ctx: Ctx, pc: str, since: str, until: str, user: str) -> int:
    """Count 4625 rows in [since, until], optionally for one target user."""
    rows = ctx.rows(pc, "event_4625", since, until)
    if not user:
        return len(rows)
    n = 0
    for row in rows:
        try:
            import json
            payload = json.loads(row["payload"])
        except (ValueError, TypeError):
            continue
        target = str(payload.get("target_user") or "").lower()
        if not target or target == user.lower():
            n += 1
    return n


class FailedLoginBurst(ObsRule):
    record_types = frozenset({"event_4625"})

    def eval(self, ctx: Ctx, rec: dict) -> list[SignalDraft]:
        need, minutes = _burst_params(ctx)
        since = _window_since(rec["ts"], minutes)
        count = _failures(ctx, rec["pc"], since, rec["ts"], "")
        if count < need:
            return []
        user = str(rec.get("target_user") or "any")
        return [SignalDraft(
            ts=rec["ts"], pc=rec["pc"], rule_id="acct_failed_burst", category="account",
            title=f"Failed-login burst ({count} failures in {minutes} min)",
            detail=f"target={user} source={rec.get('source_ip') or '?'} "
                   f"logon_type={rec.get('logon_type') or '?'}",
            correlation=[("account", user.lower()),
                         ("src_ip", str(rec.get("source_ip") or ""))],
            anchor=f"{user.lower()}:{hour_bucket(rec['ts'])}",
            observation_id=rec.get("_obs_id"))]


class SuccessAfterBurst(ObsRule):
    record_types = frozenset({"event_4624"})

    def eval(self, ctx: Ctx, rec: dict) -> list[SignalDraft]:
        need, minutes = _burst_params(ctx)
        since = _window_since(rec["ts"], minutes)
        user = str(rec.get("target_user") or "")
        count = _failures(ctx, rec["pc"], since, rec["ts"], user)
        if count < need:
            return []
        return [SignalDraft(
            ts=rec["ts"], pc=rec["pc"], rule_id="acct_success_after_burst",
            category="account",
            title=f"Successful login right after {count} failed attempts",
            detail=f"target={user or '?'} source={rec.get('source_ip') or '?'} "
                   f"logon_type={rec.get('logon_type') or '?'} (4625 burst then 4624)",
            correlation=[("account", user.lower()),
                         ("src_ip", str(rec.get("source_ip") or ""))],
            anchor=f"{user.lower()}:{rec['ts']}",
            observation_id=rec.get("_obs_id"))]


class OffhoursLogin(ObsRule):
    record_types = frozenset({"event_4624"})

    def eval(self, ctx: Ctx, rec: dict) -> list[SignalDraft]:
        if not ctx.offhours(rec["ts"]):
            return []
        user = str(rec.get("target_user") or "unknown")
        return [SignalDraft(
            ts=rec["ts"], pc=rec["pc"], rule_id="acct_offhours_login", category="account",
            title=f"Off-hours login: {user}",
            detail=f"logon_type={rec.get('logon_type') or '?'} source={rec.get('source_ip') or '?'}",
            correlation=[("account", user.lower()),
                         ("src_ip", str(rec.get("source_ip") or ""))],
            anchor=f"{user.lower()}:{rec['ts']}",
            observation_id=rec.get("_obs_id"))]


class UnusualSourcePC(ObsRule):
    record_types = frozenset({"event_4624"})

    def eval(self, ctx: Ctx, rec: dict) -> list[SignalDraft]:
        src = str(rec.get("source_ip") or "").strip()
        if not src or src == "-":
            return []
        lookback = int(ctx.settings.thresholds.get("unusual_source_lookback_days", 30))
        since = window_start(24 * lookback)
        history = ctx.count(rec["pc"], "event_4624", since, rec["ts"])
        if history < 3:  # need enough login history before "unusual" means anything
            return []
        known = ctx.field_values(rec["pc"], "event_4624", "source_ip", since)
        if src.lower() in known:
            return []
        user = str(rec.get("target_user") or "unknown")
        return [SignalDraft(
            ts=rec["ts"], pc=rec["pc"], rule_id="acct_unusual_source", category="account",
            title=f"Login from unusual source PC {src}",
            detail=f"user={user} logon_type={rec.get('logon_type') or '?'}; "
                   f"source not seen in the last {lookback} days",
            correlation=[("src_pc", src), ("account", user.lower())],
            anchor=f"{src}:{day_bucket(rec['ts'])}",
            observation_id=rec.get("_obs_id"))]


OBS_RULES: list[ObsRule] = [
    FailedLoginBurst(), SuccessAfterBurst(), OffhoursLogin(), UnusualSourcePC(),
]
