"""Shared parser helpers: safe CSV/JSON reading, header aliasing, dedup keys.

Safety rules for all parsers (defense in depth alongside ingest.py):
  * file size is capped by ingest before parsing ever starts
  * no XML anywhere (event exports are CSV with a JSON data column)
  * individual field values are truncated to MAX_FIELD_CHARS
  * row count is capped; unknown headers/rows are skipped, never crash the tool
"""
from __future__ import annotations

import csv
import hashlib
import json
from pathlib import Path

from ..normalize import ts_str

MAX_FIELD_CHARS = 8192
MAX_ROWS = 200_000


class ParseError(Exception):
    """Raised when a file cannot be understood as any supported format."""


def norm_header(h: str) -> str:
    return (h or "").strip().lower().replace(" ", "_").replace("-", "_")


def read_csv(path: Path) -> tuple[set[str], list[dict]]:
    """Read a CSV into (normalized header set, rows with normalized keys).

    Values are truncated; utf-8-sig handles PowerShell's BOM.
    """
    try:
        with open(path, "r", encoding="utf-8-sig", errors="replace", newline="") as fh:
            reader = csv.DictReader(fh)
            if not reader.fieldnames:
                raise ParseError("CSV has no header row")
            header = {norm_header(h) for h in reader.fieldnames if h}
            rows: list[dict] = []
            for i, row in enumerate(reader):
                if i >= MAX_ROWS:
                    raise ParseError(f"more than {MAX_ROWS} rows")
                clean: dict[str, str] = {}
                for key, val in row.items():
                    if key is None:
                        continue
                    if isinstance(val, str) and len(val) > MAX_FIELD_CHARS:
                        val = val[:MAX_FIELD_CHARS]
                    clean[norm_header(key)] = val
                rows.append(clean)
            return header, rows
    except (csv.Error, UnicodeError) as exc:
        raise ParseError(f"invalid CSV: {exc}") from exc


def read_json_records(path: Path) -> list[dict]:
    """Read JSON Lines or a JSON array of objects. Bad lines are skipped."""
    try:
        text = path.read_text(encoding="utf-8-sig", errors="replace")
    except OSError as exc:
        raise ParseError(f"cannot read file: {exc}") from exc
    text = text.strip()
    if not text:
        raise ParseError("empty file")
    if text.startswith("["):
        try:
            data = json.loads(text)
        except ValueError as exc:
            raise ParseError(f"invalid JSON array: {exc}") from exc
        if not isinstance(data, list):
            raise ParseError("JSON root is not an array")
        return [o for o in data[:MAX_ROWS] if isinstance(o, dict)]
    records: list[dict] = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        if len(records) >= MAX_ROWS:
            raise ParseError(f"more than {MAX_ROWS} records")
        try:
            obj = json.loads(line)
        except ValueError:
            continue
        if isinstance(obj, dict):
            records.append(obj)
    if not records:
        raise ParseError("no valid JSON objects found")
    return records


def pick(row: dict, aliases: list[str], default=None):
    """Return the first non-empty alias value from a normalized-key row."""
    for alias in aliases:
        val = row.get(norm_header(alias))
        if val is not None and str(val).strip() != "":
            return val
    return default


# Common alias groups (already lowercase/underscore form is applied by pick()).
TS = ["timestamp", "time", "datetime", "date", "timecreated", "ts", "event_time"]
CLIENT_IP = ["client_ip", "client", "clientip", "source_ip", "src_ip", "srcip",
             "source_address", "address", "ip", "ip_address"]
DOMAIN = ["domain", "name", "query", "question", "qname", "host", "hostname_query"]
HOSTNAME = ["hostname", "computer", "computername", "host", "system", "pc", "machine"]
PORT = ["port", "dst_port", "destination_port", "dport", "remote_port"]


def dedup_key(record: dict) -> str:
    """Natural key of a normalized record: full canonical payload hash."""
    payload = json.dumps(record, sort_keys=True, default=str, ensure_ascii=False)
    return hashlib.sha1(payload.encode("utf-8", "replace")).hexdigest()


def base_record(record_type: str, row_ts, **fields) -> dict | None:
    """Build a normalized record; returns None when the timestamp is unusable."""
    ts = ts_str(row_ts)
    if not ts:
        return None
    rec: dict = {"record_type": record_type, "ts": ts}
    for key, value in fields.items():
        if value is None:
            continue
        if isinstance(value, str):
            value = value.strip()
            if not value:
                continue
            if len(value) > MAX_FIELD_CHARS:
                value = value[:MAX_FIELD_CHARS]
        rec[key] = value
    return rec
