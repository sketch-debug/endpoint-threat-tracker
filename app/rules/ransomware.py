"""Ransomware rules: listed extensions/ransom notes in file activity, mass
file change bursts, and shadow-copy / backup tampering command lines."""
from __future__ import annotations

from .base import Ctx, ObsRule, PCRule, SignalDraft, basename, short_hash


class RansomExtension(ObsRule):
    record_types = frozenset({"file_activity"})

    def eval(self, ctx: Ctx, rec: dict) -> list[SignalDraft]:
        path = str(rec.get("file_path") or "")
        name = basename(path)
        ext = ctx.indicators.ransomware_extension(name)
        if not ext:
            return []
        corr = []
        if rec.get("process_name"):
            corr.append(("proc", basename(str(rec["process_name"]))))
        return [SignalDraft(
            ts=rec["ts"], pc=rec["pc"], rule_id="ransom_extension", category="ransomware",
            title=f"File given ransomware extension: {name}",
            detail=f"{path} action={rec.get('action') or '?'} "
                   f"(extension {ext} in ransomware_extensions.txt)",
            correlation=corr, anchor=f"{short_hash(path)}:{rec['ts'][:10]}",
            observation_id=rec.get("_obs_id"))]


class RansomNote(ObsRule):
    record_types = frozenset({"file_activity"})

    def eval(self, ctx: Ctx, rec: dict) -> list[SignalDraft]:
        path = str(rec.get("file_path") or "")
        name = basename(path)
        pattern = ctx.indicators.ransom_note(name)
        if not pattern:
            return []
        return [SignalDraft(
            ts=rec["ts"], pc=rec["pc"], rule_id="ransom_note", category="ransomware",
            title=f"Ransom note written: {name}",
            detail=f"{path} matches note pattern {pattern!r}",
            correlation=[("file", name)],
            anchor=f"{short_hash(path)}:{rec['ts'][:10]}",
            observation_id=rec.get("_obs_id"))]


class RansomShadowCopy(ObsRule):
    record_types = frozenset({"event_4688"})

    def eval(self, ctx: Ctx, rec: dict) -> list[SignalDraft]:
        cmd = str(rec.get("command_line") or "")
        match = ctx.indicators.shadow_match(cmd)
        if not match:
            return []
        return [SignalDraft(
            ts=rec["ts"], pc=rec["pc"], rule_id="ransom_shadow_copy", category="ransomware",
            title="Shadow copy deletion / backup tampering attempted",
            detail=f'cmd: {cmd[:500]} (pattern: {match.pattern[:80]})',
            correlation=[("cmdline", cmd[:200])],
            anchor=f"{short_hash(cmd)}:{rec['ts']}",
            observation_id=rec.get("_obs_id"))]


class MassFileChange(PCRule):
    """Many file renames/modifications in a short window (file-activity export)."""

    def eval_pc(self, ctx: Ctx, pc: str, new_recs: list[dict]) -> list[SignalDraft]:
        if not any(r.get("record_type") == "file_activity" for r in new_recs):
            return []
        from ..normalize import iso, parse_ts
        from datetime import timedelta

        need = int(ctx.settings.thresholds.get("mass_change_events", 20))
        minutes = int(ctx.settings.thresholds.get("mass_change_window_minutes", 5))

        candidates = [r for r in new_recs if r.get("record_type") == "file_activity"
                      and r.get("action", "").lower() in ("renamed", "rename", "modified",
                                                          "modify", "created", "create")]
        if not candidates:
            return []
        first_ts = min(r["ts"] for r in candidates)
        first_dt = parse_ts(first_ts)
        if not first_dt:
            return []
        since = iso(first_dt - timedelta(minutes=minutes))

        # Count across the whole window (includes the rows just ingested).
        events: list[tuple[str, str]] = []  # (ts, process)
        payloads = ctx.payloads_between(pc, "file_activity", since, "9999")
        for p in payloads:
            action = str(p.get("action") or "").lower()
            if action in ("renamed", "rename", "modified", "modify", "created", "create"):
                events.append((str(p.get("ts") or ""), str(p.get("process_name") or "")))
        events.sort()
        if len(events) < need:
            return []

        # sliding window: is there a `minutes` span containing >= need events?
        left, trigger_start = 0, None
        from datetime import datetime, timedelta as _td
        span = _td(minutes=minutes)
        for right in range(len(events)):
            rt = parse_ts(events[right][0])
            if not rt:
                continue
            while left <= right:
                lt = parse_ts(events[left][0])
                if lt and rt - lt > span:
                    left += 1
                else:
                    break
            if right - left + 1 >= need:
                trigger_start = events[left][0]
                break
        if trigger_start is None:
            return []

        procs = {}
        for _, proc in events:
            if proc:
                procs[proc] = procs.get(proc, 0) + 1
        top_proc = max(procs, key=procs.get) if procs else ""
        corr = [("proc", basename(top_proc))] if top_proc else []
        return [SignalDraft(
            ts=trigger_start, pc=pc, rule_id="ransom_mass_change", category="ransomware",
            title=f"Mass file changes: {len(events)} files in {minutes} min",
            detail=f"file-activity export shows {len(events)} renames/modifications/creations "
                   f"between {events[0][0]} and {events[-1][0]} (threshold {need}/{minutes}min)"
                   + (f"; most common process {top_proc}" if top_proc else ""),
            correlation=corr,
            anchor=f"mass:{pc}:{trigger_start[:13]}")]


OBS_RULES: list[ObsRule] = [RansomExtension(), RansomNote(), RansomShadowCopy()]
PC_RULES: list[PCRule] = [MassFileChange()]
