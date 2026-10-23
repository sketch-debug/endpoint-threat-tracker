"""Cryptomining detection rules (the original product core)."""
from __future__ import annotations

from ..normalize import window_start
from .base import Ctx, ObsRule, PCRule, SignalDraft, day_bucket, fnum, hour_bucket, basename


class DnsMiningPool(ObsRule):
    record_types = frozenset({"dns_query"})

    def eval(self, ctx: Ctx, rec: dict) -> list[SignalDraft]:
        domain = str(rec.get("domain", ""))
        hit = ctx.indicators.pool_domain(domain)
        if not hit:
            return []
        return [SignalDraft(
            ts=rec["ts"], pc=rec["pc"], rule_id="dns_mining_pool", category="miner",
            title=f"DNS lookup to mining pool {domain}",
            detail=f"client {rec.get('client_ip', '?')} resolved {domain} "
                   f"(matches indicator {hit})",
            correlation=[("domain", domain), ("src_ip", str(rec.get("client_ip", "")))],
            anchor=f"{domain}:{hour_bucket(rec['ts'])}:{rec.get('client_ip', '')}",
            observation_id=rec.get("_obs_id"),
        )]


class ConnMiningPort(ObsRule):
    record_types = frozenset({"connection"})

    def eval(self, ctx: Ctx, rec: dict) -> list[SignalDraft]:
        port = rec.get("port")
        if not ctx.indicators.port_listed(port):
            return []
        min_dur = float(ctx.settings.thresholds.get("mining_port_min_duration_seconds", 300))
        duration = fnum(rec.get("duration")) or 0.0
        if duration < min_dur:
            return []  # only long-lived flows to listed ports count
        return [SignalDraft(
            ts=rec["ts"], pc=rec["pc"], rule_id="conn_mining_port", category="miner",
            title=f"Long-lived connection on mining port {port}",
            detail=f"{rec.get('client_ip', '?')} -> {rec.get('dst_ip', '?')}:{port} "
                   f"for {duration:.0f}s (threshold {min_dur:.0f}s)",
            correlation=[("dst", str(rec.get("dst_ip", "")))],
            anchor=f"{rec.get('dst_ip','')}:{port}:{hour_bucket(rec['ts'])}:{rec.get('client_ip','')}",
            observation_id=rec.get("_obs_id"),
        )]


class ProcMinerName(ObsRule):
    record_types = frozenset({"process_inventory", "event_4688"})

    def eval(self, ctx: Ctx, rec: dict) -> list[SignalDraft]:
        name = rec.get("name") or basename(str(rec.get("process_name", "")))
        if not name:
            return []
        hit = ctx.indicators.miner_process(str(name))
        if not hit:
            return []
        path = rec.get("path") or rec.get("process_name") or ""
        return [SignalDraft(
            ts=rec["ts"], pc=rec["pc"], rule_id="proc_miner_name", category="miner",
            title=f"Miner process observed: {hit}",
            detail=f"process {name} at {path} (matches miner process indicator)",
            correlation=[("proc", hit)],
            anchor=f"{hit}:{rec['ts']}",
            observation_id=rec.get("_obs_id"),
        )]


class CpuHighOffhours(ObsRule):
    record_types = frozenset({"process_inventory"})

    def eval(self, ctx: Ctx, rec: dict) -> list[SignalDraft]:
        cpu = fnum(rec.get("cpu_percent"))
        threshold = float(ctx.settings.thresholds.get("high_cpu_percent", 85))
        if cpu is None or cpu < threshold:
            return []
        if not ctx.offhours(rec["ts"]):
            return []
        return [SignalDraft(
            ts=rec["ts"], pc=rec["pc"], rule_id="cpu_high_offhours", category="miner",
            title=f"High CPU off-hours: {rec.get('name', 'process')}",
            detail=f"{rec.get('name')} used {cpu:.0f}% CPU during off-hours "
                   f"(threshold {threshold:.0f}%)",
            anchor=f"{rec.get('name','')}:{hour_bucket(rec['ts'])}",
            observation_id=rec.get("_obs_id"),
        )]


OBS_RULES: list[ObsRule] = [DnsMiningPool(), ConnMiningPort(), ProcMinerName(), CpuHighOffhours()]
PC_RULES: list[PCRule] = []
