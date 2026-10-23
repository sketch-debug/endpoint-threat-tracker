"""Timestamp parsing/normalization shared by all parsers.

All timestamps are stored as ISO-8601 UTC strings ("YYYY-MM-DDTHH:MM:SSZ")
so sorting and window math are simple string/datetime comparisons.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

TS_FORMATS = (
    "%Y-%m-%dT%H:%M:%S.%f%z",
    "%Y-%m-%dT%H:%M:%S%z",
    "%Y-%m-%d %H:%M:%S.%f",
    "%Y-%m-%d %H:%M:%S",
    "%Y/%m/%d %H:%M:%S",
    "%m/%d/%Y %I:%M:%S %p",
    "%m/%d/%Y %H:%M:%S",
)


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def iso(dt: datetime) -> str:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    dt = dt.astimezone(timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def now_iso() -> str:
    return iso(utcnow())


def parse_ts(value) -> datetime | None:
    """Parse a timestamp from a string/number into an aware UTC datetime.

    Handles ISO-8601 (with Z or offset), common export formats and epoch
    seconds/milliseconds. Returns None when the value cannot be parsed.
    """
    if value is None:
        return None
    if isinstance(value, datetime):
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)
    if isinstance(value, (int, float)) or (isinstance(value, str) and value.strip().replace(".", "", 1).isdigit()):
        try:
            num = float(value)
        except (TypeError, ValueError):
            return None
        if num > 1e12:  # milliseconds
            num /= 1000.0
        if num <= 0:
            return None
        try:
            return datetime.fromtimestamp(num, tz=timezone.utc)
        except (OverflowError, OSError, ValueError):
            return None
    s = str(value).strip()
    if not s:
        return None
    # Normalize trailing "Z" and space separator for fromisoformat
    try:
        norm = s.replace("Z", "+00:00") if s.endswith("Z") else s
        dt = datetime.fromisoformat(norm)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except ValueError:
        pass
    for fmt in TS_FORMATS:
        try:
            dt = datetime.strptime(s, fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.astimezone(timezone.utc)
        except ValueError:
            continue
    return None


def ts_str(value) -> str | None:
    dt = parse_ts(value)
    return iso(dt) if dt else None


def window_start(hours: int, now: datetime | None = None) -> str:
    now = now or utcnow()
    return iso(now - timedelta(hours=hours))
