"""Ingest tests: validation, dedup ledger, error parking, PC resolution."""
from __future__ import annotations

from pathlib import Path

from app import detect
from app.config import Settings
from app.db import Database
from app.indicators import Indicators
from app.ingest import Ingestor, sha256_file

DNS_CSV = (
    "timestamp,client_ip,domain,query_type\n"
    "2026-10-01T09:00:00Z,192.168.10.21,pool.minexmr.com,A\n"
    "2026-10-01T09:05:00Z,192.168.10.21,example.com,A\n"
)


def _ingestor(db: Database, settings: Settings, indicators: Indicators) -> Ingestor:
    det = detect.Detector(db, settings, indicators)
    return Ingestor(db, settings, indicators, detector=det)


class TestIngest:
    def test_happy_path(self, db, settings, indicators):
        (settings.inbox_dir / "dns_generic_20261001.csv").write_text(DNS_CSV,
                                                                     encoding="utf-8")
        ing = _ingestor(db, settings, indicators)
        stats = ing.scan_once()
        assert stats["files"] == 1
        assert stats["ingested"] == 1
        assert stats["observations"] == 2
        assert stats["errors"] == 0
        # file moved to processed, ledger row present
        assert (settings.processed_dir / "dns_generic_20261001.csv").exists()
        row = db.one("SELECT * FROM files")
        assert row["status"] == "ingested" and row["record_count"] == 2

    def test_pc_resolved_from_ip_map(self, db, settings, indicators):
        (settings.inbox_dir / "dns_generic_20261001.csv").write_text(DNS_CSV,
                                                                     encoding="utf-8")
        ing = _ingestor(db, settings, indicators)
        ing.scan_once()
        pcs = {r["pc"] for r in db.query("SELECT DISTINCT pc FROM observations")}
        assert pcs == {"PC-LAB-01"}, "192.168.10.21 maps to PC-LAB-01 in ip_map.txt"

    def test_duplicate_content_skipped(self, db, settings, indicators):
        (settings.inbox_dir / "dns_generic_20261001.csv").write_text(DNS_CSV,
                                                                     encoding="utf-8")
        ing = _ingestor(db, settings, indicators)
        ing.scan_once()
        # same content, new filename -> ledger catches it by sha256
        (settings.inbox_dir / "dns_generic_copy.csv").write_text(DNS_CSV,
                                                                 encoding="utf-8")
        stats = ing.scan_once()
        assert stats["duplicates"] == 1
        assert stats["observations"] == 0

    def test_bad_extension_rejected(self, db, settings, indicators):
        (settings.inbox_dir / "payload.exe").write_text("MZ...", encoding="utf-8")
        ing = _ingestor(db, settings, indicators)
        stats = ing.scan_once()
        assert stats["errors"] == 1
        assert (settings.error_dir / "payload.exe").exists()
        assert db.one("SELECT status FROM files")["status"] == "error"

    def test_oversized_file_rejected(self, db, settings, indicators):
        settings.app["ingest"]["max_file_bytes"] = 10
        try:
            (settings.inbox_dir / "dns_generic_big.csv").write_text(DNS_CSV,
                                                                    encoding="utf-8")
            ing = _ingestor(db, settings, indicators)
            stats = ing.scan_once()
            assert stats["errors"] == 1
            row = db.one("SELECT detail FROM files")
            assert "too large" in row["detail"]
        finally:
            settings.app["ingest"]["max_file_bytes"] = 50 * 1024 * 1024

    def test_unparseable_csv_parked(self, db, settings, indicators):
        (settings.inbox_dir / "dns_generic_junk.csv").write_text(
            "not,a,valid,dns,file\n1,2,3,4\n", encoding="utf-8")
        ing = _ingestor(db, settings, indicators)
        stats = ing.scan_once()
        assert stats["errors"] == 1
        assert (settings.error_dir / "dns_generic_junk.csv").exists()

    def test_error_file_retryable_after_fix(self, db, settings, indicators):
        bad = settings.inbox_dir / "dns_generic_retry.csv"
        bad.write_text("garbage\n", encoding="utf-8")
        ing = _ingestor(db, settings, indicators)
        ing.scan_once()
        assert db.one("SELECT status FROM files")["status"] == "error"
        # fix the file and drop it again: new content -> new sha256 -> ingested
        fixed = settings.inbox_dir / "dns_generic_retry.csv"
        fixed.write_text(DNS_CSV, encoding="utf-8")
        stats = ing.scan_once()
        assert stats["ingested"] == 1
        statuses = {r["status"] for r in db.query("SELECT status FROM files")}
        assert statuses == {"error", "ingested"}

    def test_hidden_files_ignored(self, db, settings, indicators):
        (settings.inbox_dir / ".keep").write_text("x", encoding="utf-8")
        ing = _ingestor(db, settings, indicators)
        stats = ing.scan_once()
        assert stats["files"] == 0

    def test_sha256_file(self, tmp_path: Path):
        p = tmp_path / "x.txt"
        p.write_bytes(b"abc")
        assert sha256_file(p) == (
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
