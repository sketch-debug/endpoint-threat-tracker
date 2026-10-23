"""Execution rules: suspicious command lines, suspicious paths, unsigned
processes, Office/browser spawning interpreters, Defender detections and
known-bad hashes."""
from __future__ import annotations

import re

from .base import Ctx, ObsRule, SignalDraft, basename, day_bucket, short_hash

_HASH_RE = re.compile(r"\b[0-9a-fA-F]{32}\b|\b[0-9a-fA-F]{64}\b")


class ProcPathAndSignature(ObsRule):
    """One process-inventory row -> exactly one of three weights:
    temp+unsigned combo (15), temp only (10) or unsigned only (5)."""
    record_types = frozenset({"process_inventory"})

    def eval(self, ctx: Ctx, rec: dict) -> list[SignalDraft]:
        path = str(rec.get("path") or "")
        name = str(rec.get("name") or "")
        sus = ctx.indicators.suspicious_path(path)
        sig = str(rec.get("signature_status") or "").strip().lower()
        unsigned = bool(sig) and sig not in ("valid", "trusted", "signed")
        common = dict(ts=rec["ts"], pc=rec["pc"],
                      correlation=[("proc", basename(name))],
                      observation_id=rec.get("_obs_id"))

        if sus and unsigned:
            return [SignalDraft(
                rule_id="exec_temp_unsigned", category="execution",
                title=f"Unsigned process from suspicious path: {name}",
                detail=f"{path} (matches suspicious path {sus!r}, signature={sig or 'unknown'})",
                anchor=f"{short_hash(path)}:{day_bucket(rec['ts'])}", **common)]
        if sus:
            return [SignalDraft(
                rule_id="proc_suspicious_path", category="execution",
                title=f"Process from suspicious path: {name}",
                detail=f"{path} (matches suspicious path {sus!r})",
                anchor=f"{short_hash(path)}:{day_bucket(rec['ts'])}", **common)]
        if unsigned:
            return [SignalDraft(
                rule_id="proc_unsigned", category="execution",
                title=f"Unsigned process running: {name}",
                detail=f"{path or name} signature={sig}",
                anchor=f"{short_hash(path or name)}:{day_bucket(rec['ts'])}", **common)]
        return []


class ProcBadHash(ObsRule):
    record_types = frozenset({"process_inventory", "file_activity"})

    def eval(self, ctx: Ctx, rec: dict) -> list[SignalDraft]:
        value = str(rec.get("sha256") or rec.get("hash") or "")
        hit = ctx.indicators.bad_hash(value)
        if not hit:
            return []
        name = rec.get("name") or rec.get("file_path") or "?"
        return [SignalDraft(
            ts=rec["ts"], pc=rec["pc"], rule_id="proc_bad_hash", category="execution",
            title=f"Known-bad hash on {name}",
            detail=f"hash {hit} matches bad_hashes.txt",
            correlation=[("hash", hit.lower())],
            anchor=f"{hit.lower()}:{day_bucket(rec['ts'])}",
            observation_id=rec.get("_obs_id"),
        )]


class DefenderDetectionRule(ObsRule):
    record_types = frozenset({"defender_detection"})

    def eval(self, ctx: Ctx, rec: dict) -> list[SignalDraft]:
        threat = str(rec.get("threat_name") or "unknown threat")
        common = dict(ts=rec["ts"], pc=rec["pc"], observation_id=rec.get("_obs_id"))
        out = [SignalDraft(
            rule_id="defender_detection", category="execution",
            title=f"Defender detected: {threat}",
            detail=f"process={rec.get('process_name') or '?'} action={rec.get('action') or '?'} "
                   f"resources={str(rec.get('resources') or '')[:300]}",
            correlation=[("threat", threat.lower())],
            anchor=f"{short_hash(threat + str(rec.get('process_name'))) }:{rec['ts']}",
            **common)]
        # A listed bad hash inside resources gets its own (correlating) signal.
        for token in _HASH_RE.findall(str(rec.get("resources") or "")):
            hit = ctx.indicators.bad_hash(token)
            if hit:
                out.append(SignalDraft(
                    rule_id="proc_bad_hash", category="execution",
                    title=f"Known-bad hash in Defender detection ({threat})",
                    detail=f"hash {hit} appears in resources",
                    correlation=[("hash", hit.lower()), ("threat", threat.lower())],
                    anchor=f"{hit.lower()}:{day_bucket(rec['ts'])}",
                    **common))
        return out


class SuspiciousCommand(ObsRule):
    record_types = frozenset({"event_4688"})

    def eval(self, ctx: Ctx, rec: dict) -> list[SignalDraft]:
        cmd = str(rec.get("command_line") or "")
        if not cmd:
            return []
        if ctx.indicators.shadow_match(cmd):
            return []  # shadow-copy tamper belongs to the ransomware rule
        match = ctx.indicators.command_match(cmd)
        if not match:
            return []
        return [SignalDraft(
            ts=rec["ts"], pc=rec["pc"], rule_id="exec_suspicious_command",
            category="execution",
            title=f"Suspicious command line: {basename(str(rec.get('process_name') or ''))}",
            detail=f'cmd: {cmd[:500]} (pattern: {match.pattern[:80]})',
            correlation=[("cmdline", cmd[:200])],
            anchor=f"{short_hash(cmd)}:{rec['ts']}",
            observation_id=rec.get("_obs_id"),
        )]


class OfficeSpawn(ObsRule):
    record_types = frozenset({"event_4688"})

    def eval(self, ctx: Ctx, rec: dict) -> list[SignalDraft]:
        parent = basename(str(rec.get("parent_process") or ""))
        child = basename(str(rec.get("process_name") or ""))
        if not parent or not child:
            return []
        parents = set(ctx.settings.office_apps) | set(ctx.settings.browsers)
        if parent not in parents or child not in set(ctx.settings.interpreters):
            return []
        return [SignalDraft(
            ts=rec["ts"], pc=rec["pc"], rule_id="exec_office_spawn", category="execution",
            title=f"{parent} spawned {child}",
            detail=f"parent {rec.get('parent_process')} spawned {rec.get('process_name')} "
                   f"cmd: {str(rec.get('command_line') or '')[:300]}",
            correlation=[("cmdline", str(rec.get("command_line") or "")[:200])],
            anchor=f"{parent}>{child}:{rec['ts']}",
            observation_id=rec.get("_obs_id"),
        )]


OBS_RULES: list[ObsRule] = [
    ProcPathAndSignature(), ProcBadHash(), DefenderDetectionRule(),
    SuspiciousCommand(), OfficeSpawn(),
]
