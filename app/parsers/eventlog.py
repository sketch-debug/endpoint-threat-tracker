"""Windows Event Log CSV parser (no XML, ever).

scripts/Export-EventLogs.ps1 writes:
  timestamp, event_id, computer, provider, level, data_json

data_json is a flat JSON object of the event's EventData fields (built by the
script from the event XML server-side), e.g. for 4688:
  {"NewProcessName":"C:\\\\Users\\\\...\\\\evil.exe","ParentProcessName":"...","CommandLine":"..."}

Each event becomes a record with record_type "event_<id>" plus convenience
top-level fields extracted for the rules (process_name, command_line, ...).
"""
from __future__ import annotations

import json
from pathlib import Path

from .base import HOSTNAME, MAX_FIELD_CHARS, TS, ParseError, base_record, pick, read_csv

# Convenience extractions: canonical field <- lowercased event data keys
_EXTRACT = {
    "process_name": ["newprocessname", "processname"],
    "parent_process": ["parentprocessname", "parentname"],
    "command_line": ["commandline", "cmdline"],
    "task_name": ["taskname", "task_path"],
    "task_command": ["taskcommand", "command"],
    "task_arguments": ["taskarguments", "arguments"],
    "service_name": ["servicename"],
    "service_file": ["servicefilename", "servicefilepath"],
    "target_user": ["targetusername", "accountname"],
    "subject_user": ["subjectusername", "accountnameto"],
    "source_ip": ["ipaddress", "workstationname", "clientaddress"],
    "logon_type": ["logontype"],
    "member_name": ["membername"],
    "path": ["path", "exclusionpath", "processpath"],
    "old_value": ["oldvalue"],
    "new_value": ["newvalue"],
}


def _event_data(raw: str) -> dict:
    raw = (raw or "").strip()
    if not raw:
        return {}
    try:
        obj = json.loads(raw)
    except ValueError:
        return {}
    if not isinstance(obj, dict):
        return {}
    out = {}
    for key, val in obj.items():
        if isinstance(key, str) and len(key) > 200:
            key = key[:200]
        if isinstance(val, str) and len(val) > MAX_FIELD_CHARS:
            val = val[:MAX_FIELD_CHARS]
        out[str(key)] = val
    return out


def parse(rows: list[dict]) -> list[dict]:
    out: list[dict] = []
    for row in rows:
        event_id = pick(row, ["event_id", "eventid", "id"])
        if event_id is None or not str(event_id).strip().isdigit():
            continue
        event_id = int(str(event_id).strip())
        data = _event_data(pick(row, ["data_json", "data_json_field", "properties", "data"], ""))
        data_lower = {str(k).lower(): v for k, v in data.items()}

        fields: dict = {
            "hostname": pick(row, HOSTNAME),
            "event_id": event_id,
            "provider": pick(row, ["provider", "providername", "source"]),
            "level": pick(row, ["level", "leveldisplayname", "severity"]),
            "data": data,
        }
        for canon, keys in _EXTRACT.items():
            for key in keys:
                val = data_lower.get(key)
                if val not in (None, ""):
                    fields[canon] = val
                    break

        rec = base_record(f"event_{event_id}", pick(row, TS), **fields)
        if rec:
            out.append(rec)
    if not out:
        raise ParseError("event file produced no valid records")
    return out


def parse_file(path: Path) -> list[dict]:
    _, rows = read_csv(path)
    return parse(rows)
