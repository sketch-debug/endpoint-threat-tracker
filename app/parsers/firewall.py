"""Firewall / router connection log CSV parser.

Expected columns (aliases tolerated): client ip, destination ip, port,
duration, timestamp. Produced as CSV by your firewall/router export.
"""
from __future__ import annotations

from .base import CLIENT_IP, TS, ParseError, base_record, pick

DST_IP = ["dst_ip", "destination_ip", "dest_ip", "remote_ip", "server_ip",
          "target_ip", "dst", "destination"]
DURATION = ["duration", "duration_seconds", "seconds", "connect_time",
            "bytes", "length"]


def parse(rows: list[dict]) -> list[dict]:
    out: list[dict] = []
    for row in rows:
        rec = base_record(
            "connection",
            pick(row, TS),
            client_ip=pick(row, CLIENT_IP),
            dst_ip=pick(row, DST_IP),
            port=pick(row, ["port", "dst_port", "destination_port", "dport"]),
            duration=pick(row, DURATION),
            proto=pick(row, ["proto", "protocol"]),
        )
        if rec and (rec.get("dst_ip") or rec.get("port")):
            out.append(rec)
    if not out:
        raise ParseError("firewall file produced no valid records")
    return out
