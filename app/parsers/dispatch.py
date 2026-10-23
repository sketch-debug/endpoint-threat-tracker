"""Format detection and the single parse_file() entry point.

Detection: filename hints first (all our export scripts and the generator use
documented prefixes), then header sniffing. Unknown formats raise ParseError
and the file is moved to the error folder untouched.
"""
from __future__ import annotations

from pathlib import Path

from ..config import Settings
from . import defender, dns, eventlog, firewall, inventory
from .base import ParseError, read_csv, read_json_records

# Filename prefixes we emit (scripts + generator). Keep in sync with README.
FILE_KINDS = (
    "dns_generic", "dns_technitium", "dns_adguard", "fw_connections",
    "defender_detections", "events_", "process_inv", "tasks_inv",
    "persistence_inv", "defender_status", "file_activity",
)


def _detect(name: str, header: set[str]) -> str:
    if "technitium" in name:
        return "dns_technitium"
    if "adguard" in name:
        raise ParseError("AdGuard logs must be exported as .json/.jsonl (querylog.json)")
    if "events" in name or ("event_id" in header and "data_json" in header) \
            or ({"id", "computer"} <= header and "timecreated" in header):
        return "events"
    if "defender_status" in name or "real_time_protection" in header:
        return "defender_status"
    if "defender_detection" in name or "threat_name" in header:
        return "defender_detections"
    if "process_inv" in name or ({"pid"} <= header and {"path", "image_path"} & header):
        return "process_inv"
    if "tasks_inv" in name or "task_name" in header:
        return "tasks_inv"
    if "persistence_inv" in name or ({"category", "item_name"} <= header):
        return "persistence_inv"
    if "file_activity" in name or ({"file_path", "action"} <= header):
        return "file_activity"
    if "dns" in name or ({"domain"} <= header and {"client_ip", "client", "ip"} & header):
        return "dns_generic"
    if name.startswith("fw") or "connection" in name or ({"port"} <= header and {"dst_ip", "destination_ip"} & header):
        return "fw_connections"
    raise ParseError("unrecognized file format (no known filename prefix or header)")


def parse_file(path: Path, settings: Settings) -> list[dict]:
    """Parse one inbox file into normalized records.

    Each record: {record_type, ts, [pc|hostname], fields...}. Raises ParseError
    when the file is not a supported format or yields no valid records.
    """
    name = path.name.lower()
    ext = path.suffix.lower()

    if ext in (".json", ".jsonl"):
        # Only AdGuard Home logs are JSON; sniff before committing to that.
        objs = read_json_records(path)
        if not any(("QH" in o) or ("domain" in o) for o in objs[:5]):
            raise ParseError("JSON file does not look like an AdGuard query log")
        return dns.parse(objs, settings, "adguard")

    if ext not in (".csv", ".txt", ".log"):
        raise ParseError(f"unsupported extension: {ext}")

    header, rows = read_csv(path)
    if not rows:
        raise ParseError("CSV has a header but no data rows")

    kind = _detect(name, header)
    if kind == "dns_technitium":
        return dns.parse(rows, settings, "technitium")
    if kind == "dns_generic":
        return dns.parse(rows, settings, "generic")
    if kind == "fw_connections":
        return firewall.parse(rows)
    if kind == "defender_detections":
        return defender.parse(rows)
    if kind == "events":
        return eventlog.parse(rows)
    if kind == "process_inv":
        return inventory.parse_processes(rows)
    if kind == "tasks_inv":
        return inventory.parse_tasks(rows)
    if kind == "persistence_inv":
        return inventory.parse_persistence(rows)
    if kind == "defender_status":
        return inventory.parse_defender_status(rows)
    if kind == "file_activity":
        return inventory.parse_file_activity(rows)
    raise ParseError(f"no parser for detected kind {kind!r}")
