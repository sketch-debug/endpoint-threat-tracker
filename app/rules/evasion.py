"""Defense-evasion rules: Defender disabled/exclusions/service stopped and
security event log cleared (event 1102). Event-based rules fire on
5001/5007/1102; snapshot rules diff Defender status deliveries."""
from __future__ import annotations

from .base import Ctx, ObsRule, PCRule, SignalDraft, day_bucket, short_hash

_EVASION_WORDS = ("exclusion", "exclusions", "disable", "disabled", "allow", "ignore")


class DefenderRtpEvent(ObsRule):
    record_types = frozenset({"event_5001"})

    def eval(self, ctx: Ctx, rec: dict) -> list[SignalDraft]:
        return [SignalDraft(
            ts=rec["ts"], pc=rec["pc"], rule_id="evade_defender_rtp", category="evasion",
            title="Defender real-time protection disabled (event 5001)",
            detail=f"provider={rec.get('provider') or '?'} "
                   f"path={rec.get('path') or '-'} new={rec.get('new_value') or '-'}",
            anchor=f"5001:{rec['ts']}",
            observation_id=rec.get("_obs_id"))]


class DefenderExclusionEvent(ObsRule):
    record_types = frozenset({"event_5007"})

    def eval(self, ctx: Ctx, rec: dict) -> list[SignalDraft]:
        blob = " ".join(str(rec.get(k) or "") for k in ("path", "old_value", "new_value")).lower()
        if not any(word in blob for word in _EVASION_WORDS):
            return []  # 5007 fires for every Defender config change; keep signal/noise sane
        data = rec.get("data") or {}
        return [SignalDraft(
            ts=rec["ts"], pc=rec["pc"], rule_id="evade_defender_exclusion", category="evasion",
            title="Defender configuration changed (exclusions/disable)",
            detail=f"event 5007 path={rec.get('path') or '-'} "
                   f"new={rec.get('new_value') or '-'} old={rec.get('old_value') or '-'}",
            anchor=f"5007:{short_hash(str(data))}:{rec['ts'][:10]}",
            observation_id=rec.get("_obs_id"))]


class LogCleared(ObsRule):
    record_types = frozenset({"event_1102"})

    def eval(self, ctx: Ctx, rec: dict) -> list[SignalDraft]:
        return [SignalDraft(
            ts=rec["ts"], pc=rec["pc"], rule_id="evade_log_cleared", category="evasion",
            title="Security event log cleared (event 1102)",
            detail=f"provider={rec.get('provider') or 'Microsoft-Windows-Eventlog'}",
            anchor=f"1102:{rec['ts']}",
            observation_id=rec.get("_obs_id"))]


class DefenderStatusSnapshots(PCRule):
    """Diff newly delivered defender_status snapshots: RTP off / service
    stopped / newly added exclusions."""

    def eval_pc(self, ctx: Ctx, pc: str, new_recs: list[dict]) -> list[SignalDraft]:
        groups: dict[str, list[dict]] = {}
        for rec in new_recs:
            if rec.get("record_type") == "defender_status":
                groups.setdefault(rec["ts"], []).append(rec)
        if not groups:
            return []

        out: list[SignalDraft] = []
        for ts in sorted(groups):
            current = groups[ts][-1]
            prev_ts = ctx.snapshot_before(pc, "defender_status", ts)
            prev_excl: set[str] = set()
            has_prev = bool(prev_ts)
            if has_prev:
                for p in ctx.snapshot_payloads(pc, "defender_status", prev_ts):
                    for ex in p.get("exclusions") or []:
                        prev_excl.add(str(ex).lower())

            if str(current.get("real_time_protection") or "").lower() == "disabled":
                out.append(SignalDraft(
                    ts=ts, pc=pc, rule_id="evade_defender_rtp", category="evasion",
                    title="Defender real-time protection disabled (status export)",
                    detail="defender_status snapshot reports real_time_protection=disabled",
                    anchor=f"rtp:{pc}:{day_bucket(ts)}"))
            if str(current.get("service_status") or "").lower() == "stopped":
                out.append(SignalDraft(
                    ts=ts, pc=pc, rule_id="evade_defender_stopped", category="evasion",
                    title="Defender service not running (status export)",
                    detail="defender_status snapshot reports service_status=stopped",
                    anchor=f"svc:{pc}:{day_bucket(ts)}"))
            if has_prev:
                for ex in current.get("exclusions") or []:
                    if str(ex).lower() not in prev_excl:
                        out.append(SignalDraft(
                            ts=ts, pc=pc, rule_id="evade_defender_exclusion",
                            category="evasion",
                            title=f"New Defender exclusion added: {ex}",
                            detail=f"exclusion {ex} not present in previous snapshot {prev_ts}",
                            correlation=[("exclusion", str(ex).lower())],
                            anchor=f"excl:{pc}:{str(ex).lower()}:{day_bucket(ts)}"))
        return out


OBS_RULES: list[ObsRule] = [
    DefenderRtpEvent(), DefenderExclusionEvent(), LogCleared(),
]
PC_RULES: list[PCRule] = [DefenderStatusSnapshots()]
