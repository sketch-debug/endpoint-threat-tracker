"""Timestamp normalization and parser tests."""
from __future__ import annotations

from pathlib import Path

import pytest

from app.normalize import ts_str
from app.parsers import ParseError, dedup_key, parse_file
from app.parsers.base import norm_header, pick, read_csv, read_json_records


class TestParseTs:
    def test_iso_z(self):
        assert ts_str("2026-10-01T12:30:00Z") == "2026-10-01T12:30:00Z"

    def test_iso_offset_normalized_to_utc(self):
        # +02:00 two hours ahead -> UTC hour 10
        assert ts_str("2026-10-01T12:30:00+02:00") == "2026-10-01T10:30:00Z"

    def test_space_separator(self):
        assert ts_str("2026-10-01 12:30:00") == "2026-10-01T12:30:00Z"

    def test_powershell_export_format(self):
        assert ts_str("10/01/2026 1:05:09 PM") == "2026-10-01T13:05:09Z"

    def test_epoch_seconds(self):
        assert ts_str(1759338600) is not None

    def test_epoch_milliseconds(self):
        # ms epoch coerces to the same instant as the seconds form
        assert ts_str(1759338600000) == ts_str(1759338600)

    def test_garbage_returns_none(self):
        assert ts_str("not a timestamp") is None
        assert ts_str("") is None
        assert ts_str(None) is None


class TestBaseHelpers:
    def test_norm_header(self):
        assert norm_header(" Client IP-Addr ") == "client_ip_addr"

    def test_pick_first_nonempty_alias(self):
        row = {"timestamp": "", "time": "2026-10-01T00:00:00Z"}
        assert pick(row, ["timestamp", "time"]) == "2026-10-01T00:00:00Z"

    def test_dedup_key_is_order_independent(self):
        a = {"ts": "x", "pc": "A", "v": 1}
        b = {"v": 1, "pc": "A", "ts": "x"}
        assert dedup_key(a) == dedup_key(b)

    def test_dedup_key_differs_on_value(self):
        assert dedup_key({"a": 1}) != dedup_key({"a": 2})

    def test_read_csv_truncates_long_fields(self, tmp_path: Path):
        p = tmp_path / "big.csv"
        p.write_text("k,v\n" + "x" * 20000 + ",ok\n", encoding="utf-8")
        _, rows = read_csv(p)
        assert len(rows[0]["k"]) <= 8192 and rows[0]["v"] == "ok"

    def test_read_csv_handles_bom(self, tmp_path: Path):
        p = tmp_path / "bom.csv"
        p.write_bytes(b"\xef\xbb\xbfa,b\n1,2\n")
        header, rows = read_csv(p)
        assert "a" in header and rows[0]["a"] == "1"

    def test_read_json_records_jsonl(self, tmp_path: Path):
        p = tmp_path / "recs.jsonl"
        p.write_text('{"a": 1}\nnot-json\n{"b": 2}\n', encoding="utf-8")
        recs = read_json_records(p)
        assert recs == [{"a": 1}, {"b": 2}]

    def test_read_json_records_array(self, tmp_path: Path):
        p = tmp_path / "recs.json"
        p.write_text('[{"a": 1}, "skip", {"b": 2}]', encoding="utf-8")
        assert read_json_records(p) == [{"a": 1}, {"b": 2}]

    def test_read_json_records_empty_raises(self, tmp_path: Path):
        p = tmp_path / "empty.json"
        p.write_text("   ", encoding="utf-8")
        with pytest.raises(ParseError):
            read_json_records(p)


class TestDispatch:
    def test_dns_csv(self, tmp_path: Path):
        p = tmp_path / "dns.csv"
        p.write_text(
            "timestamp,client_ip,domain,query_type\n"
            "2026-10-01T09:00:00Z,192.168.10.21,pool.minexmr.com,A\n", encoding="utf-8")
        recs = parse_file(p, _fake_settings(tmp_path))
        assert recs[0]["record_type"] == "dns_query"
        assert recs[0]["domain"] == "pool.minexmr.com"
        assert recs[0]["client_ip"] == "192.168.10.21"

    def test_eventlog_csv(self, tmp_path: Path):
        p = tmp_path / "sec.csv"
        p.write_text(
            "timestamp,event_id,computer,provider,level,data_json\n"
            '2026-10-01T09:00:00Z,4688,PC-A,Provider,Information,'
            '{"NewProcessName":"C:\\\\evil.exe"}\n',
            encoding="utf-8")
        recs = parse_file(p, _fake_settings(tmp_path))
        assert recs[0]["record_type"] == "event_4688"
        assert recs[0]["hostname"] == "PC-A"
        assert recs[0]["process_name"].endswith("evil.exe")

    def test_unknown_file_raises(self, tmp_path: Path):
        p = tmp_path / "random.log"
        p.write_text("hello world,not,a,valid,file\nnope\n", encoding="utf-8")
        with pytest.raises(ParseError):
            parse_file(p, _fake_settings(tmp_path))


def _fake_settings(tmp_path: Path):
    """Minimal settings stand-in for parse_file (technitium_columns only)."""
    class _S:
        technitium_columns = {}
    return _S()
