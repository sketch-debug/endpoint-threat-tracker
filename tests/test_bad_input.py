"""Bad-input tests: every junk file class must be logged, quarantined to
inbox/errors, and must never stop the watcher or half-ingest silently.

Covers the brief's list: empty, huge, wrong encodings, truncated CSVs,
still-being-written files, wrong column names, malformed JSON/XML, and an
unexpected parser crash mid-batch.
"""
from __future__ import annotations

import os
import time

import app.ingest as ingest_mod
from app.ingest import Ingestor

DNS_CSV = (
    "timestamp,client_ip,domain,query_type\n"
    "2026-10-01T09:00:00Z,192.168.10.21,pool.minexmr.com,A\n"
    "2026-10-01T09:05:00Z,192.168.10.21,example.com,A\n"
)


def _ingestor(db, settings, indicators) -> Ingestor:
    return Ingestor(db, settings, indicators, detector=None)


def _age(path, seconds: int = 3600) -> None:
    """Make a file look old enough that it is not considered in-flight."""
    t = time.time() - seconds
    os.utime(path, (t, t))


def _assert_quarantined(settings, db, name: str) -> None:
    assert not (settings.inbox_dir / name).exists(), f"{name} left in inbox root"
    assert (settings.error_dir / name).exists(), f"{name} not moved to errors/"
    row = db.one("SELECT status, detail FROM files WHERE filename=? ORDER BY id DESC",
                 (name,))
    assert row is not None, f"{name} has no files-ledger row"
    assert row["status"] == "error", f"{name} ledger status={row['status']!r}"
    assert row["detail"], f"{name} ledger row has no reason recorded"


class TestBadInput:
    def test_empty_file_quarantined(self, db, settings, indicators):
        (settings.inbox_dir / "dns_generic_empty.csv").write_text("", encoding="utf-8")
        stats = _ingestor(db, settings, indicators).scan_once()
        assert stats["errors"] == 1
        _assert_quarantined(settings, db, "dns_generic_empty.csv")

    def test_huge_file_quarantined(self, db, settings, indicators):
        settings.app["ingest"]["max_file_bytes"] = 10
        (settings.inbox_dir / "dns_generic_big.csv").write_text(DNS_CSV, encoding="utf-8")
        stats = _ingestor(db, settings, indicators).scan_once()
        assert stats["errors"] == 1
        _assert_quarantined(settings, db, "dns_generic_big.csv")
        row = db.one("SELECT detail FROM files WHERE filename='dns_generic_big.csv'")
        assert "too large" in row["detail"]

    def test_wrong_encoding_quarantined(self, db, settings, indicators):
        # UTF-16LE with BOM: readable by PowerShell, garbage to a UTF-8 parser.
        content = "timestamp,client_ip,domain\n2026-10-01T09:00:00Z,10.0.0.1,x.com\n"
        (settings.inbox_dir / "dns_generic_utf16.csv").write_bytes(content.encode("utf-16"))
        stats = _ingestor(db, settings, indicators).scan_once()
        assert stats["errors"] == 1
        assert stats["ingested"] == 0
        _assert_quarantined(settings, db, "dns_generic_utf16.csv")

    def test_truncated_csv_quarantined(self, db, settings, indicators):
        # Cut off in the middle of a quoted field (writer died mid-row).
        truncated = (
            "timestamp,client_ip,domain,query_type\n"
            "2026-10-01T09:00:00Z,192.168.10.21,\"pool.minexm"
        )
        (settings.inbox_dir / "dns_generic_trunc.csv").write_text(
            truncated, encoding="utf-8")
        stats = _ingestor(db, settings, indicators).scan_once()
        assert stats["ingested"] == 0, "truncated CSV was half-ingested as valid"
        _assert_quarantined(settings, db, "dns_generic_trunc.csv")

    def test_inflight_file_deferred_then_ingested(self, db, settings, indicators):
        settings.app["ingest"]["stability_seconds"] = 30
        fresh = settings.inbox_dir / "dns_generic_inflight.csv"
        fresh.write_text(DNS_CSV, encoding="utf-8")  # mtime = now: still being written
        ing = _ingestor(db, settings, indicators)
        stats = ing.scan_once()
        assert fresh.exists(), "in-flight file was consumed"
        assert stats.get("deferred") == 1, f"no deferred stat: {stats}"
        assert stats["errors"] == 0
        assert db.one("SELECT COUNT(*) AS n FROM files")["n"] == 0
        # writer finished long ago -> next cycle picks it up
        _age(fresh)
        stats = ing.scan_once()
        assert stats["ingested"] == 1
        assert not fresh.exists()
        assert (settings.processed_dir / "dns_generic_inflight.csv").exists()

    def test_wrong_columns_quarantined(self, db, settings, indicators):
        # Recognized filename/header, but every timestamp is unusable -> no
        # records can be normalized. Must be a logged error, not a silent
        # "ingested 0 records" success.
        bad = (
            "timestamp,client_ip,domain\n"
            "TOTAL_GARBAGE_TIMESTAMP,192.168.10.21,pool.minexmr.com\n"
            "ALSO_NOT_A_TIME,192.168.10.21,example.com\n"
        )
        (settings.inbox_dir / "dns_generic_badvalues.csv").write_text(bad, encoding="utf-8")
        stats = _ingestor(db, settings, indicators).scan_once()
        assert stats["ingested"] == 0, "file with zero usable records counted as ingested"
        _assert_quarantined(settings, db, "dns_generic_badvalues.csv")

    def test_malformed_json_quarantined(self, db, settings, indicators):
        (settings.inbox_dir / "querylog.json").write_text("{not json at all", encoding="utf-8")
        stats = _ingestor(db, settings, indicators).scan_once()
        assert stats["errors"] == 1
        _assert_quarantined(settings, db, "querylog.json")

    def test_malformed_xml_quarantined(self, db, settings, indicators):
        (settings.inbox_dir / "junk.xml").write_text("<events><oops", encoding="utf-8")
        stats = _ingestor(db, settings, indicators).scan_once()
        assert stats["errors"] == 1
        _assert_quarantined(settings, db, "junk.xml")

    def test_unexpected_parser_crash_quarantines_and_batch_continues(
            self, db, settings, indicators, monkeypatch):
        # A parser bug (any non-ParseError exception) must park the offending
        # file and let the rest of the batch through.
        boom = settings.inbox_dir / "dns_generic_aaa_boom.csv"
        boom.write_text(DNS_CSV, encoding="utf-8")
        _age(boom)
        good = settings.inbox_dir / "dns_generic_zzz_good.csv"
        good.write_text(DNS_CSV + "2026-10-01T09:10:00Z,192.168.10.21,ok.example,A\n",
                        encoding="utf-8")
        _age(good)

        original = ingest_mod.parse_file

        def flaky(path, st):
            if path.name == "dns_generic_aaa_boom.csv":
                raise ValueError("synthetic parser bug")
            return original(path, st)

        monkeypatch.setattr(ingest_mod, "parse_file", flaky)
        stats = _ingestor(db, settings, indicators).scan_once()
        assert stats["errors"] == 1
        assert stats["ingested"] == 1, "batch stopped after one bad file"
        _assert_quarantined(settings, db, "dns_generic_aaa_boom.csv")
        assert (settings.processed_dir / "dns_generic_zzz_good.csv").exists()

    def test_mixed_junk_batch_leaves_inbox_empty_and_keeps_running(
            self, db, settings, indicators):
        inbox = settings.inbox_dir
        (inbox / "dns_generic_empty.csv").write_text("", encoding="utf-8")
        (inbox / "dns_generic_junk.csv").write_text("nope,nope\n1,2\n", encoding="utf-8")
        (inbox / "bad.json").write_text("[{broken", encoding="utf-8")
        (inbox / "junk.xml").write_text("<x>", encoding="utf-8")
        good = inbox / "dns_generic_ok.csv"
        good.write_text(DNS_CSV, encoding="utf-8")
        _age(good)
        for p in inbox.glob("dns_generic_junk.csv"):
            _age(p)

        stats = _ingestor(db, settings, indicators).scan_once()
        leftover = [p.name for p in inbox.iterdir()
                    if p.is_file() and not p.name.startswith(".")]
        assert leftover == [], f"inbox not drained: {leftover}"
        assert stats["errors"] >= 4
        assert (settings.processed_dir / "dns_generic_ok.csv").exists()
        statuses = {r["status"] for r in db.query("SELECT status FROM files")}
        assert "error" in statuses and "ingested" in statuses
