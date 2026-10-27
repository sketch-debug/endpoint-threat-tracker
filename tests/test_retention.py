"""Retention/cleanup tests (brief section 5): configurable age-based deletes
in safe batches, with incidents and the dedup ledger never touched."""
from __future__ import annotations

import os
import time
from datetime import timedelta

from app.normalize import iso, utcnow
from app.retention import run_retention

OLD_OBS = {"file_id": None, "record_type": "dns_query", "pc": "PC-1"}


def _seed(db, settings) -> dict:
    now = utcnow()
    old = iso(now - timedelta(days=200))
    young = iso(now - timedelta(days=1))
    very_old = iso(now - timedelta(days=400))

    db.execute("INSERT INTO incidents(incident_key, type, created_at) "
               "VALUES(?,?,?)", ("IR-1", "miner", old))
    db.execute("INSERT INTO files(sha256, filename, status, ingested_at) "
               "VALUES(?,?,?,?)", ("abc123", "ledger.csv", "ingested", old))

    for i, ts in enumerate((old, young)):
        db.execute("INSERT INTO observations(file_id, record_type, pc, ts, "
                   "dedup_key, payload) VALUES(?,?,?,?,?,?)",
                   (None, "dns_query", "PC-1", ts, f"obs{i}", "{}"))
    for i, (ts, incident_id) in enumerate(
            ((old, None), (old, 1), (young, None))):
        db.execute("INSERT INTO signals(ts, pc, rule_id, category, weight, "
                   "title, detail, incident_id, dedup_key) "
                   "VALUES(?,?,?,?,?,?,?,?,?)",
                   (ts, "PC-1", "rule_x", "evasion", 10, "t", "", incident_id,
                    f"sig{i}"))
    for i, ts in enumerate((very_old, young)):
        db.execute("INSERT INTO audit_log(ts, actor, action, entity, detail) "
                   "VALUES(?,?,?,?,?)", (ts, "system", "note", "", ""))
    for i, ts in enumerate((very_old, young)):
        db.execute("INSERT INTO alerts_log(ts, incident_id, kind, channel, "
                   "dedup_key, status, detail) VALUES(?,?,?,?,?,?,?)",
                   (ts, 1, "incident_opened", "log", f"alr{i}", "logged", ""))
    return {"old": old, "young": young, "very_old": very_old}


class TestRetention:
    def test_age_based_deletes_and_protections(self, db, settings, indicators):
        dates = _seed(db, settings)
        deleted = run_retention(db, settings)

        assert deleted["observations"] == 1          # only the 200-day row
        assert deleted["signals"] == 1               # old + orphan only
        assert deleted["audit_log"] == 1             # 400 > 180
        assert deleted["alerts_log"] == 1            # 400 > 365

        obs_ts = [r["ts"] for r in db.query("SELECT ts FROM observations")]
        assert obs_ts == [dates["young"]], obs_ts

        sig = db.query("SELECT ts, incident_id FROM signals")
        # young orphan + OLD incident-linked kept; old orphan deleted
        assert len(sig) == 2
        assert any(r["incident_id"] == 1 for r in sig), \
            "incident-linked signal was deleted"

        assert db.one("SELECT COUNT(*) AS n FROM incidents")["n"] == 1
        assert db.one("SELECT COUNT(*) AS n FROM files")["n"] == 1, \
            "dedup ledger must never be purged"
        # the cleanup job writes its own fresh audit row, so check the
        # seeded rows specifically
        assert [r["ts"] for r in db.query(
            "SELECT ts FROM audit_log WHERE action='note'")] == [dates["young"]]
        assert [r["ts"] for r in db.query("SELECT ts FROM alerts_log")] == \
            [dates["young"]]
        row = db.one("SELECT action, detail FROM audit_log "
                     "WHERE action='retention_cleanup'")
        assert row and "observations=1" in row["detail"]

    def test_second_pass_is_idempotent(self, db, settings, indicators):
        _seed(db, settings)
        run_retention(db, settings)
        again = run_retention(db, settings)
        assert again == {"observations": 0, "signals": 0,
                         "audit_log": 0, "alerts_log": 0, "files": 0}

    def test_disabled_config_deletes_nothing(self, db, settings, indicators):
        _seed(db, settings)
        settings.app["retention"] = {"enabled": False}
        result = run_retention(db, settings)
        assert result == {"skipped": "disabled"}
        assert db.one("SELECT COUNT(*) AS n FROM observations")["n"] == 2

    def test_batched_deletion_reclaims_backlog(self, db, settings, indicators):
        """A backlog larger than one batch is fully reclaimed."""
        settings.app["retention"] = {"enabled": True, "observations_days": 90,
                                     "signals_days": 90, "audit_days": 180,
                                     "alerts_days": 365, "batch_size": 100}
        old = iso(utcnow() - timedelta(days=300))
        for i in range(350):
            db.execute("INSERT INTO observations(file_id, record_type, pc, ts, "
                       "dedup_key, payload) VALUES(?,?,?,?,?,?)",
                       (None, "dns_query", "PC-1", old, f"bulk{i}", "{}"))
        deleted = run_retention(db, settings)
        assert deleted["observations"] == 350
        assert db.one("SELECT COUNT(*) AS n FROM observations")["n"] == 0

    def test_files_retention_reclaims_outputs_but_never_inbox(
            self, db, settings, indicators):
        """Aged processed/error/report files go; fresh ones and inbox/ stay."""
        old = time.time() - 200 * 86400   # > the 90-day files_days default
        processed_old = settings.processed_dir / "old_export.csv"
        processed_new = settings.processed_dir / "new_export.csv"
        error_old = settings.error_dir / "old_error.csv"
        report_old = settings.reports_dir / "old_report.html"
        inbox_old = settings.inbox_dir / "old_drop.csv"
        for path in (processed_old, processed_new, error_old, report_old,
                     inbox_old):
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("x", encoding="utf-8")
        for path in (processed_old, error_old, report_old, inbox_old):
            os.utime(path, (old, old))

        deleted = run_retention(db, settings)

        assert deleted["files"] == 3
        assert not processed_old.exists()
        assert not error_old.exists()
        assert not report_old.exists()
        assert processed_new.exists()
        assert inbox_old.exists(), \
            "in-flight inbox drops must never be deleted"
