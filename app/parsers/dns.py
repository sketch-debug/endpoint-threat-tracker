"""DNS query log parsers.

Three input formats (see README "Adding a log format"):
  * generic CSV        : client ip, domain, timestamp (column aliases tolerated)
  * Technitium DNS     : CSV exported from the GUI/API; column mapping is
                         configurable in app_config.yaml (headers vary by version)
  * AdGuard Home       : querylog.json = JSON Lines with fields T, QH, IP, QT
"""
from __future__ import annotations

from ..config import Settings
from .base import CLIENT_IP, DOMAIN, TS, ParseError, base_record, pick


def parse_generic(rows: list[dict], source: str = "generic") -> list[dict]:
    out: list[dict] = []
    for row in rows:
        rec = base_record(
            "dns_query",
            pick(row, TS),
            client_ip=pick(row, CLIENT_IP),
            domain=pick(row, DOMAIN),
            qtype=pick(row, ["qtype", "query_type", "type"]),
            source=source,
        )
        if rec and rec.get("domain"):
            out.append(rec)
    return out


def parse_technitium(rows: list[dict], settings: Settings) -> list[dict]:
    """Technitium CSV export. Uses the configurable column mapping first,
    then falls back to the generic aliases."""
    mapping = settings.technitium_columns or {}
    ts_cols = list(mapping.get("timestamp", []))
    client_cols = list(mapping.get("client", []))
    domain_cols = list(mapping.get("domain", []))

    out: list[dict] = []
    for row in rows:
        ts = pick(row, ts_cols + TS)
        client = pick(row, client_cols + CLIENT_IP)
        domain = pick(row, domain_cols + DOMAIN)
        rec = base_record("dns_query", ts, client_ip=client, domain=domain,
                          qtype=pick(row, ["qtype", "query_type", "type"]),
                          source="technitium")
        if rec and rec.get("domain"):
            out.append(rec)
    return out


def parse_adguard(records: list[dict]) -> list[dict]:
    """AdGuard Home querylog.json (JSON Lines). Field names from the current
    source: T (timestamp), QH (queried host), IP (client), QT (query type).
    The on-disk schema is officially unstable, so extras are tolerated."""
    out: list[dict] = []
    for obj in records:
        rec = base_record(
            "dns_query",
            obj.get("T") or obj.get("time") or obj.get("timestamp"),
            client_ip=obj.get("IP") or obj.get("client") or obj.get("Client"),
            domain=obj.get("QH") or obj.get("host") or obj.get("domain") or obj.get("question"),
            qtype=obj.get("QT") or obj.get("type"),
            source="adguard",
        )
        if rec and rec.get("domain"):
            out.append(rec)
    return out


def parse(rows_or_objs, settings: Settings, source: str) -> list[dict]:
    if source == "adguard":
        records = parse_adguard(rows_or_objs)
    elif source == "technitium":
        records = parse_technitium(rows_or_objs, settings)
    else:
        records = parse_generic(rows_or_objs, source)
    if not records:
        raise ParseError("DNS file produced no valid records")
    return records
