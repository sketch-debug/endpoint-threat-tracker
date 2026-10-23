"""Inventory CSV parsers: processes, scheduled tasks, persistence, Defender
status, file activity. All produced by the read-only PowerShell scripts.

Every inventory row carries hostname + timestamp so snapshots can be diffed
between deliveries (that is how "new task / new service / new exclusion" is
detected without touching the endpoint).
"""
from __future__ import annotations

from .base import HOSTNAME, TS, ParseError, base_record, pick

_SIG = ["signature_status", "signature", "authenticode_status", "status_signature"]
_CATEGORIES = {
    "run": "run_key", "run_key": "run_key", "runonce": "run_key", "runonce_key": "run_key",
    "service": "service", "services": "service",
    "task": "scheduled_task", "scheduled_task": "scheduled_task", "scheduledtask": "scheduled_task",
    "wmi": "wmi_subscription", "wmi_subscription": "wmi_subscription", "wmieventsubscription": "wmi_subscription",
    "startup": "startup", "startup_folder": "startup", "startupitem": "startup",
}


def _boolish(val) -> str | None:
    if val is None:
        return None
    v = str(val).strip().lower()
    if v in ("true", "1", "yes", "on", "enabled", "active", "running"):
        if v in ("running",):
            return "running"
        if v in ("true", "1", "yes", "on", "enabled", "active"):
            return "enabled"
    if v in ("false", "0", "no", "off", "disabled"):
        return "disabled"
    if v in ("stopped",):
        return "stopped"
    return str(val).strip()


def _exclusions(raw) -> list[str]:
    if raw is None:
        return []
    text = str(raw).strip()
    if text.startswith("["):
        import json
        try:
            val = json.loads(text)
            if isinstance(val, list):
                return [str(x) for x in val][:200]
        except ValueError:
            pass
    parts = [p.strip() for p in text.replace("|", ";").split(";")]
    return [p for p in parts if p][:200]


def parse_processes(rows: list[dict]) -> list[dict]:
    out = []
    for row in rows:
        rec = base_record(
            "process_inventory",
            pick(row, TS),
            hostname=pick(row, HOSTNAME),
            ip=pick(row, ["ip", "ip_address", "client_ip"]),
            pid=pick(row, ["pid", "process_id"]),
            ppid=pick(row, ["ppid", "parent_pid"]),
            name=pick(row, ["name", "image", "process_name", "processname"]),
            path=pick(row, ["path", "image_path", "executable", "exe"]),
            user=pick(row, ["user", "username", "account"]),
            cpu_percent=pick(row, ["cpu_percent", "cpu", "percent_processor_time"]),
            memory_mb=pick(row, ["memory_mb", "memory", "working_set_mb"]),
            signature_status=pick(row, _SIG),
            signer=pick(row, ["signer", "signer_name", "publisher"]),
            sha256=pick(row, ["sha256", "hash", "sha_256", "file_hash"]),
        )
        if rec and rec.get("name"):
            out.append(rec)
    if not out:
        raise ParseError("process inventory produced no valid records")
    return out


def parse_tasks(rows: list[dict]) -> list[dict]:
    out = []
    for row in rows:
        rec = base_record(
            "task_inventory",
            pick(row, TS),
            hostname=pick(row, HOSTNAME),
            task_name=pick(row, ["task_name", "name", "task"]),
            task_path=pick(row, ["task_path", "path"]),
            status=pick(row, ["status", "state"]),
            command=pick(row, ["command", "task_command", "action"]),
            arguments=pick(row, ["arguments", "args"]),
            user=pick(row, ["user", "run_as", "principal"]),
        )
        if rec and rec.get("task_name"):
            out.append(rec)
    if not out:
        raise ParseError("task inventory produced no valid records")
    return out


def parse_persistence(rows: list[dict]) -> list[dict]:
    out = []
    for row in rows:
        category = str(pick(row, ["category", "type", "kind"], "")).strip().lower()
        category = _CATEGORIES.get(category, category)
        rec = base_record(
            "persistence_inventory",
            pick(row, TS),
            hostname=pick(row, HOSTNAME),
            category=category,
            item_name=pick(row, ["item_name", "name", "item", "key"]),
            details=pick(row, ["details", "value", "data", "details_json"]),
            command=pick(row, ["command", "image", "path", "executable"]),
        )
        if rec and rec.get("item_name"):
            out.append(rec)
    if not out:
        raise ParseError("persistence inventory produced no valid records")
    return out


def parse_defender_status(rows: list[dict]) -> list[dict]:
    out = []
    for row in rows:
        rec = base_record(
            "defender_status",
            pick(row, TS),
            hostname=pick(row, HOSTNAME),
            real_time_protection=_boolish(pick(row, ["real_time_protection", "rtp", "realtime"])),
            service_status=_boolish(pick(row, ["service_status", "windefend", "service"])),
            exclusions=_exclusions(pick(row, ["exclusions", "exclusion", "exclusion_paths"])),
            behavior_monitor=_boolish(pick(row, ["behavior_monitor", "behaviormonitor", "behavior"])),
            ioav_protection=_boolish(pick(row, ["ioav_protection", "ioav"])),
            tamper_protection=_boolish(pick(row, ["tamper_protection", "tamper"])),
        )
        if rec and rec.get("hostname"):
            out.append(rec)
    if not out:
        raise ParseError("Defender status file produced no valid records")
    return out


def parse_file_activity(rows: list[dict]) -> list[dict]:
    out = []
    for row in rows:
        rec = base_record(
            "file_activity",
            pick(row, TS),
            hostname=pick(row, HOSTNAME),
            file_path=pick(row, ["file_path", "path", "file", "filename"]),
            action=pick(row, ["action", "event", "change", "operation"]),
            process_name=pick(row, ["process_name", "process", "image"]),
            sha256=pick(row, ["sha256", "hash", "sha_256", "file_hash"]),
        )
        if rec and rec.get("file_path"):
            out.append(rec)
    if not out:
        raise ParseError("file activity file produced no valid records")
    return out
