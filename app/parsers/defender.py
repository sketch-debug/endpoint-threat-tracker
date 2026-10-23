"""Microsoft Defender detection history parser (Get-MpThreatDetection export).

The export script scripts/Export-DefenderDetections.ps1 writes these columns:
  timestamp, hostname, threat_name, severity, category, process_name,
  resources, action, threat_status
Aliases are tolerated for hand-made exports.
"""
from __future__ import annotations

from .base import HOSTNAME, TS, ParseError, base_record, pick


def parse(rows: list[dict]) -> list[dict]:
    out: list[dict] = []
    for row in rows:
        rec = base_record(
            "defender_detection",
            pick(row, TS) or pick(row, ["initialdetectiontime", "detection_time"]),
            hostname=pick(row, HOSTNAME) or pick(row, ["computer", "pscomputername"]),
            threat_name=pick(row, ["threat_name", "threatname", "threat", "malware_name"]),
            severity=pick(row, ["severity", "threat_severity"]),
            category=pick(row, ["category", "threat_category", "type"]),
            process_name=pick(row, ["process_name", "processname", "process"]),
            resources=pick(row, ["resources", "resource", "paths"]),
            action=pick(row, ["action", "action_success", "threat_status"]),
        )
        if rec and rec.get("threat_name"):
            out.append(rec)
    if not out:
        raise ParseError("Defender detection file produced no valid records")
    return out
