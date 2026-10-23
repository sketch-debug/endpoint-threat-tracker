"""Network-side rules: C2 domains and unapproved remote-access tools."""
from __future__ import annotations

from .base import Ctx, ObsRule, PCRule, SignalDraft, hour_bucket, basename


class DnsC2Domain(ObsRule):
    record_types = frozenset({"dns_query"})

    def eval(self, ctx: Ctx, rec: dict) -> list[SignalDraft]:
        domain = str(rec.get("domain", ""))
        hit = ctx.indicators.c2_domain(domain)
        if not hit:
            return []
        return [SignalDraft(
            ts=rec["ts"], pc=rec["pc"], rule_id="dns_c2_domain", category="network",
            title=f"DNS lookup to known C2/malware domain {domain}",
            detail=f"client {rec.get('client_ip', '?')} resolved {domain} "
                   f"(matches C2 indicator {hit})",
            correlation=[("domain", domain), ("src_ip", str(rec.get("client_ip", "")))],
            anchor=f"{domain}:{hour_bucket(rec['ts'])}:{rec.get('client_ip', '')}",
            observation_id=rec.get("_obs_id"),
        )]


class UnapprovedRemoteTool(ObsRule):
    record_types = frozenset({"process_inventory", "event_4688"})

    def eval(self, ctx: Ctx, rec: dict) -> list[SignalDraft]:
        name = rec.get("name") or basename(str(rec.get("process_name", "")))
        if not name:
            return []
        hit = ctx.indicators.unapproved_remote_tool(str(name))
        if not hit:
            return []
        path = rec.get("path") or rec.get("process_name") or ""
        return [SignalDraft(
            ts=rec["ts"], pc=rec["pc"], rule_id="net_unapproved_rat", category="network",
            title=f"Unapproved remote-access tool running: {hit}",
            detail=f"process {name} at {path}; not in approved_remote_tools.txt",
            correlation=[("tool", hit), ("proc", hit)],
            anchor=f"{hit}:{day_anchor(rec)}",
            observation_id=rec.get("_obs_id"),
        )]


def day_anchor(rec: dict) -> str:
    return f"{rec['ts'][:10]}:{rec.get('path') or rec.get('process_name', '')}"


OBS_RULES: list[ObsRule] = [DnsC2Domain(), UnapprovedRemoteTool()]
PC_RULES: list[PCRule] = []
