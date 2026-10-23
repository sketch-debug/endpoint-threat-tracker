"""Persistence rules: new services/tasks/Run keys/startup/WMI items and new
local admin accounts. Event-based rules fire on 4698/7045/4720/4732; the
snapshot-diff rule fires on persistence inventory deliveries."""
from __future__ import annotations

from .base import Ctx, ObsRule, PCRule, SignalDraft, day_bucket

_CATEGORY_RULE = {
    "run_key": "pers_run_key",
    "service": "pers_service",
    "scheduled_task": "pers_task",
    "wmi_subscription": "pers_wmi",
    "startup": "pers_startup",
}
_CATEGORY_LABEL = {
    "run_key": "Run key entry",
    "service": "service",
    "scheduled_task": "scheduled task",
    "wmi_subscription": "WMI event subscription",
    "startup": "startup item",
}


class NewScheduledTask(ObsRule):
    record_types = frozenset({"event_4698"})

    def eval(self, ctx: Ctx, rec: dict) -> list[SignalDraft]:
        task = str(rec.get("task_name") or "").strip()
        if not task:
            return []
        corr = [("task", task)]
        cmd = str(rec.get("task_command") or rec.get("command_line") or "")
        if cmd:
            corr.append(("cmdline", cmd[:200]))
        return [SignalDraft(
            ts=rec["ts"], pc=rec["pc"], rule_id="pers_task", category="persistence",
            title=f"Scheduled task created: {task}",
            detail=f"event 4698; command={cmd or 'n/a'}; creator={rec.get('subject_user') or '?'}",
            correlation=corr, anchor=f"{task.lower()}:{rec['ts'][:10]}",
            observation_id=rec.get("_obs_id"))]


class NewService(ObsRule):
    record_types = frozenset({"event_7045"})

    def eval(self, ctx: Ctx, rec: dict) -> list[SignalDraft]:
        name = str(rec.get("service_name") or "").strip()
        if not name:
            return []
        image = str(rec.get("service_file") or "")
        corr = [("service", name)]
        if image:
            corr.append(("cmdline", image[:200]))
        return [SignalDraft(
            ts=rec["ts"], pc=rec["pc"], rule_id="pers_service", category="persistence",
            title=f"Service installed: {name}",
            detail=f"event 7045; image={image or 'n/a'}",
            correlation=corr, anchor=f"{name.lower()}:{rec['ts'][:10]}",
            observation_id=rec.get("_obs_id"))]


class NewLocalAdmin(ObsRule):
    record_types = frozenset({"event_4720", "event_4732"})

    def eval(self, ctx: Ctx, rec: dict) -> list[SignalDraft]:
        target = str(rec.get("target_user") or "").strip()
        member = str(rec.get("member_name") or "").strip()
        who = target or member
        if not who or who.startswith("S-1-5-"):
            return []
        is_group = rec["record_type"] == "event_4732"
        title = (f"Account added to Administrators: {who}" if is_group
                 else f"New local account created: {who}")
        return [SignalDraft(
            ts=rec["ts"], pc=rec["pc"], rule_id="pers_new_admin", category="persistence",
            title=title,
            detail=f"event {rec['event_id']}; subject={rec.get('subject_user') or '?'}",
            correlation=[("account", who.lower())],
            anchor=f"{rec['event_id']}:{who.lower()}:{rec['ts']}",
            observation_id=rec.get("_obs_id"))]


class PersistenceDiff(PCRule):
    """Diff each newly delivered persistence snapshot against the previous one.
    The very first snapshot for a PC is the baseline and produces no signals
    (config: thresholds.persistence_diff_requires_baseline)."""

    def eval_pc(self, ctx: Ctx, pc: str, new_recs: list[dict]) -> list[SignalDraft]:
        groups: dict[str, list[dict]] = {}
        for rec in new_recs:
            if rec.get("record_type") == "persistence_inventory":
                groups.setdefault(rec["ts"], []).append(rec)
        if not groups:
            return []

        require_baseline = bool(ctx.settings.thresholds.get(
            "persistence_diff_requires_baseline", True))
        out: list[SignalDraft] = []
        for ts in sorted(groups):
            prev_ts = ctx.snapshot_before(pc, "persistence_inventory", ts)
            if not prev_ts:
                if require_baseline:
                    continue  # first snapshot = baseline
                prev_items: set[tuple] = set()
            else:
                prev_items = {
                    (str(p.get("category", "")).lower(), str(p.get("item_name", "")).lower())
                    for p in ctx.snapshot_payloads(pc, "persistence_inventory", prev_ts)
                }
            seen: set[tuple] = set()
            for rec in groups[ts]:
                category = str(rec.get("category", "")).lower()
                item = str(rec.get("item_name", "")).strip()
                rule_id = _CATEGORY_RULE.get(category)
                if not rule_id or not item:
                    continue
                key = (category, item.lower())
                if key in prev_items or key in seen:
                    continue
                seen.add(key)
                corr = []
                if category == "scheduled_task":
                    corr.append(("task", item))
                elif category == "service":
                    corr.append(("service", item))
                command = str(rec.get("command") or "")
                if command:
                    corr.append(("cmdline", command[:200]))
                out.append(SignalDraft(
                    ts=ts, pc=pc, rule_id=rule_id, category="persistence",
                    title=f"New {_CATEGORY_LABEL[category]}: {item}",
                    detail=f"new vs snapshot {prev_ts}; details={str(rec.get('details') or '')[:200]} "
                           f"command={command[:200] or 'n/a'}",
                    correlation=corr,
                    anchor=f"{category}:{item.lower()}:{day_bucket(ts)}"))
        return out


OBS_RULES: list[ObsRule] = [NewScheduledTask(), NewService(), NewLocalAdmin()]
PC_RULES: list[PCRule] = [PersistenceDiff()]
