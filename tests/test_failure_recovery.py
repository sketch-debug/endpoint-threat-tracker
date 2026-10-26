"""Failure and recovery tests (brief section 4).

Covers: database locked by another writer, disk-full (quarantine move fails),
email unreachable (retry with backoff, no crash, no alert flood), kill
mid-import (no corrupt/half-imported data), overlapping scheduled jobs,
clock/TZ safety (future timestamps + scheduler timezone), and a startup feed
update that must not block the server.

Server-reboot recovery is proven outside pytest with a real Windows service
(nssm kill test + SERVICE_AUTO_START), recorded in RELIABILITY_REPORT.md.
"""
from __future__ import annotations

import os
import sqlite3
import subprocess
import sys
import threading
import time
from datetime import timedelta
from pathlib import Path

import pytest

import app.ingest as ingest_mod
import app.main as main_mod
from app import alerts, detect, scoring
from app.config import Settings
from app.db import Database
from app.indicators import Indicators
from app.ingest import Ingestor
from app.normalize import now_iso, parse_ts, utcnow

ROOT = Path(__file__).resolve().parent.parent

DNS_CSV = (
    "timestamp,client_ip,domain,query_type\n"
    "2026-10-01T09:00:00Z,192.168.10.21,pool.minexmr.com,A\n"
    "2026-10-01T09:05:00Z,192.168.10.21,example.com,A\n"
)


def _ingestor(db, settings, indicators) -> Ingestor:
    return Ingestor(db, settings, indicators, detector=None)


def _age(path, seconds: int = 3600) -> None:
    t = time.time() - seconds
    os.utime(path, (t, t))


INCIDENT = {
    "id": 1, "incident_key": "IR-2026-0001", "title": "miner on PC-1",
    "type": "miner", "severity": "high", "status": "open",
    "state_version": 1, "priority": "P2", "pcs": ["PC-1"],
}


class TestDatabaseLocked:
    def test_external_writer_blocks_then_recovers(self, db, settings):
        """A second process/connection holding the write lock makes our write
        wait (busy timeout) and then succeed - no error, no corruption."""
        conn = sqlite3.connect(str(settings.db_path), timeout=30)
        try:
            conn.execute("BEGIN IMMEDIATE")

            result = {}

            def writer():
                t0 = time.time()
                try:
                    db.execute(
                        "INSERT INTO audit_log(ts, actor, action, entity, detail) "
                        "VALUES(?,?,?,?,?)",
                        (now_iso(), "test", "db_lock_probe", "", ""))
                    result["ok"] = True
                    result["elapsed"] = time.time() - t0
                except Exception as exc:  # noqa: BLE001
                    result["error"] = repr(exc)

            th = threading.Thread(target=writer)
            th.start()
            time.sleep(1.5)          # keep the external lock held
            conn.execute(
                "INSERT INTO audit_log(ts, actor, action, entity, detail) "
                "VALUES(?,?,?,?,?)", (now_iso(), "external", "held_lock", "", ""))
            conn.commit()
            th.join(timeout=40)
            assert not th.is_alive(), "writer thread hung past busy timeout"
            assert "error" not in result, result.get("error")
            assert result.get("ok") is True
            assert result.get("elapsed", 0) >= 1.0, "write did not actually wait"
            rows = db.query("SELECT actor FROM audit_log WHERE action IN "
                            "('db_lock_probe','held_lock')")
            assert {r["actor"] for r in rows} == {"test", "external"}
        finally:
            conn.close()


class TestDiskFull:
    def test_move_failure_backs_off_no_flood_and_recovers(
            self, db, settings, indicators, monkeypatch):
        """When the quarantine move fails (disk full/permissions), the file
        must be backed off - not re-hashed/re-audited every 30 s scan - and
        processed normally once the move works again."""
        bad = settings.inbox_dir / "dns_generic_diskfull.csv"
        bad.write_text("not,a,dns,file\n1,2,3\n", encoding="utf-8")

        def failing_move(src, dst):
            raise OSError(28, "No space left on device")

        real_move = ingest_mod.shutil.move
        monkeypatch.setattr(ingest_mod.shutil, "move", failing_move)
        ing = _ingestor(db, settings, indicators)

        stats1 = ing.scan_once()
        assert stats1["errors"] == 1
        audits1 = db.one("SELECT COUNT(*) AS n FROM audit_log "
                         "WHERE action='ingest_rejected'")["n"]
        assert bad.exists(), "file should remain until the move succeeds"
        assert any(bad.name in k for k in ing._move_backoff), \
            "no backoff recorded after failed move"

        stats2 = ing.scan_once()   # immediately again, as the 30 s scan would
        audits2 = db.one("SELECT COUNT(*) AS n FROM audit_log "
                         "WHERE action='ingest_rejected'")["n"]
        assert stats2.get("deferred", 0) == 1, f"no backoff: {stats2}"
        assert stats2["errors"] == 0 and stats2["files"] == 0
        assert audits2 == audits1, "re-processed inside the backoff window (flood)"

        # disk cleared + backoff expired -> next scan quarantines it for real
        monkeypatch.setattr(ingest_mod.shutil, "move", real_move)
        ing._move_backoff.clear()
        stats3 = ing.scan_once()
        assert stats3["errors"] >= 1
        assert (settings.error_dir / "dns_generic_diskfull.csv").exists()


class TestEmailUnreachable:
    def test_notify_is_fast_and_flush_retries_with_backoff_no_flood(
            self, db, settings, monkeypatch):
        monkeypatch.setenv("SMTP_HOST", "127.0.0.1")
        monkeypatch.setenv("SMTP_PORT", "9")       # closed port -> refusal
        monkeypatch.setenv("ALERT_TO", "soc@example.local")
        settings.app["alerts"]["channels"] = ["log", "email"]

        t0 = time.time()
        ret = alerts.notify(db, settings, INCIDENT, "incident_opened",
                            "miner detected on PC-1")
        elapsed = time.time() - t0
        assert elapsed < 1.0, f"notify blocked the cycle for {elapsed:.1f}s"
        assert ret == "pending"
        rows = db.query("SELECT channel, status FROM alerts_log")
        by_ch = {r["channel"]: r["status"] for r in rows}
        assert by_ch["log"] == "logged"
        assert by_ch["email"] == "pending"
        n_rows = db.one("SELECT COUNT(*) AS n FROM alerts_log")["n"]

        # flush #1: attempt fails (connection refused), scheduled for retry
        alerts.flush_pending_alerts(db, settings)
        row = db.one("SELECT status, attempts, next_retry_at, body FROM alerts_log "
                     "WHERE channel='email'")
        assert row["status"] == "failed" and row["attempts"] == 1
        assert row["next_retry_at"] > now_iso(), "no backoff scheduled"
        assert row["body"], "rendered message not stored for retry"

        # flush #2 immediately: not due yet -> untouched, no new rows
        alerts.flush_pending_alerts(db, settings)
        row2 = db.one("SELECT status, attempts FROM alerts_log WHERE channel='email'")
        assert (row2["status"], row2["attempts"]) == ("failed", 1)
        assert db.one("SELECT COUNT(*) AS n FROM alerts_log")["n"] == n_rows, \
            "alert flood: new rows on retry"

        # make it due again -> second attempt, longer backoff, still one row
        db.execute("UPDATE alerts_log SET next_retry_at=? WHERE channel='email'",
                   (now_iso(),))
        alerts.flush_pending_alerts(db, settings)
        row3 = db.one("SELECT status, attempts, next_retry_at FROM alerts_log "
                      "WHERE channel='email'")
        assert row3["status"] == "failed" and row3["attempts"] == 2
        assert row3["next_retry_at"] > now_iso()
        assert db.one("SELECT COUNT(*) AS n FROM alerts_log")["n"] == n_rows

        # attempts cap -> terminal status, never retried again
        db.execute("UPDATE alerts_log SET attempts=?, next_retry_at=? "
                   "WHERE channel='email'", (alerts.MAX_ALERT_ATTEMPTS - 1, now_iso()))
        alerts.flush_pending_alerts(db, settings)
        row4 = db.one("SELECT status, attempts FROM alerts_log WHERE channel='email'")
        assert row4["status"] == "gave_up"
        db.execute("UPDATE alerts_log SET next_retry_at=? WHERE channel='email'",
                   (now_iso(),))
        alerts.flush_pending_alerts(db, settings)
        row5 = db.one("SELECT status, attempts FROM alerts_log WHERE channel='email'")
        assert (row5["status"], row5["attempts"]) == ("gave_up",
                                                      alerts.MAX_ALERT_ATTEMPTS)
        assert db.one("SELECT COUNT(*) AS n FROM alerts_log")["n"] == n_rows


CHILD_SCRIPT = '''
import sys, time
from pathlib import Path
sys.path.insert(0, sys.argv[3])
from app.config import Settings
from app.db import Database
from app.indicators import Indicators
from app.ingest import Ingestor

tmp = Path(sys.argv[1])
marker = Path(sys.argv[2])
settings = Settings(base_dir=Path(sys.argv[3]), path_overrides={
    "inbox_dir": str(tmp / "inbox"),
    "processed_dir": str(tmp / "processed"),
    "error_dir": str(tmp / "errors"),
    "db_path": str(tmp / "tracker.db"),
    "reports_dir": str(tmp / "reports"),
    "log_dir": str(tmp / "logs"),
})
settings.app.setdefault("ingest", {})["stability_seconds"] = 0
settings.ensure_dirs()
db = Database(settings.db_path)
ing = Ingestor(db, settings, Indicators(Path(sys.argv[3]) / "config"), detector=None)

class MidTxHang:
    def run(self, pcs):
        marker.write_text("in-tx", encoding="utf-8")
        time.sleep(600)          # parent kills us here, inside the transaction
        return {"signals": 0, "incidents_touched": 0}

ing.detector = MidTxHang()
print("starting", flush=True)
ing.scan_once()
print("finished", flush=True)
'''


class TestKillMidImport:
    def test_kill_inside_transaction_rolls_back_then_reingests_once(
            self, db, settings, indicators, tmp_path):
        """Hard-kill mid-import must leave no partial rows; the retry then
        ingests exactly once (ledger + UNIQUE dedup keys)."""
        (settings.inbox_dir / "dns_generic_kill.csv").write_text(
            DNS_CSV, encoding="utf-8")
        child_py = tmp_path / "kill_child.py"
        child_py.write_text(CHILD_SCRIPT, encoding="utf-8")
        marker = tmp_path / "in_tx.marker"

        proc = subprocess.Popen(
            [sys.executable, str(child_py), str(tmp_path), str(marker), str(ROOT)],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            deadline = time.time() + 30
            while time.time() < deadline and not marker.exists():
                if proc.poll() is not None:
                    out, err = proc.communicate()
                    pytest.fail(f"child died early:\n{out}\n{err}")
                time.sleep(0.1)
            assert marker.exists(), "child never reached the mid-import point"
            # mid-tx: rows are written but uncommitted -> invisible to us
            assert db.one("SELECT COUNT(*) AS n FROM files")["n"] == 0
            assert db.one("SELECT COUNT(*) AS n FROM observations")["n"] == 0
        finally:
            proc.kill()
            proc.wait(timeout=15)

        # after the hard kill: nothing partial persisted, db intact
        check = sqlite3.connect(str(settings.db_path))
        try:
            assert check.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
        finally:
            check.close()
        assert db.one("SELECT COUNT(*) AS n FROM files")["n"] == 0
        assert db.one("SELECT COUNT(*) AS n FROM observations")["n"] == 0

        # recovery: the untouched inbox file is ingested exactly once
        ing = _ingestor(db, settings, indicators)
        stats = ing.scan_once()
        assert stats["ingested"] == 1 and stats["observations"] == 2
        # the same content dropped again must dedupe, not double-import
        (settings.inbox_dir / "dns_generic_kill.csv").write_text(
            DNS_CSV, encoding="utf-8")
        stats2 = ing.scan_once()
        assert stats2["duplicates"] == 1
        assert db.one("SELECT COUNT(*) AS n FROM files")["n"] == 1
        assert db.one("SELECT COUNT(*) AS n FROM observations")["n"] == 2


class TestOverlappingJobs:
    def test_manual_and_scheduled_cycles_never_overlap(self, db, settings,
                                                       indicators):
        ing = _ingestor(db, settings, indicators)
        active = {"now": 0, "max": 0}
        lock = threading.Lock()

        def slow_scan():
            with lock:
                active["now"] += 1
                active["max"] = max(active["max"], active["now"])
            time.sleep(0.8)
            with lock:
                active["now"] -= 1
            return {"files": 0, "ingested": 0, "duplicates": 0, "errors": 0,
                    "deferred": 0, "observations": 0, "signals": 0,
                    "incidents_touched": 0}

        ing.scan_once = slow_scan
        from app.db import Database as _Db  # noqa: F401 - keep import explicit
        det = detect.Detector(db, settings, indicators)

        results = {}

        def scheduled():
            results["scheduled"] = detect.run_cycle(ing, det)

        t = threading.Thread(target=scheduled)
        t.start()
        time.sleep(0.2)                     # scheduled cycle is mid-run
        results["manual"] = detect.run_cycle(ing, det)   # manual /run/ingest
        t.join(timeout=10)

        assert results["manual"].get("skipped") is True, \
            f"manual run overlapped the scheduled cycle: {results['manual']}"
        assert active["max"] == 1, "two cycles ran concurrently"


class TestClockAndTimezone:
    def test_future_signal_does_not_hide_recent_window(self, db, settings):
        """One future/clock-skewed timestamp must not push the 24 h window
        past real recent signals (P19)."""
        recent = utcnow() - timedelta(hours=1)
        future = utcnow() + timedelta(hours=48)
        from app.normalize import iso
        for i, (dt, rule) in enumerate(((recent, "rule_recent"),
                                        (future, "rule_future"))):
            db.execute(
                "INSERT INTO signals(ts, pc, rule_id, category, weight, title, "
                "detail, dedup_key) VALUES(?,?,?,?,?,?,?,?)",
                (iso(dt), "PC-CLOCK", rule, "evasion", 10, rule, "", f"k{i}"))
        rows = scoring.pc_window(db, "PC-CLOCK", settings.window_hours)
        seen = {r["ts"] for r in rows}
        assert iso(recent) in seen, \
            "recent signal fell outside the window because of a future timestamp"
        assert iso(future) in seen   # anchor clamped to now still covers it

    def test_scheduler_is_utc_and_coalesces_missed_runs(self, settings):
        jobs_seen = {}

        def _job(name):
            def fn():
                jobs_seen[name] = jobs_seen.get(name, 0) + 1
            fn.__name__ = name
            return fn

        sched = main_mod.build_scheduler(
            settings,
            ingest_fn=_job("ingest"),
            recheck_fn=_job("recheck"),
            sessions_fn=_job("sessions"),
            alert_flush_fn=_job("alert_flush"),
            retention_fn=_job("retention"),
            heartbeat_fn=_job("heartbeat"),
        )
        assert str(sched.timezone).upper() in ("UTC", "DATEUTIL_UTC"), \
            f"scheduler timezone is {sched.timezone}, expected UTC"
        for job_id in ("ingest", "recheck", "sessions", "alert_flush",
                       "retention", "heartbeat"):
            job = sched.get_job(job_id)
            assert job is not None, f"missing scheduled job {job_id}"
            assert job.coalesce is True, f"job {job_id} does not coalesce"
            assert job.misfire_grace_time, f"job {job_id} has no misfire grace"


class TestStartupFeedUpdate:
    def test_feed_update_does_not_block_app_creation(self, monkeypatch):
        """On an isolated network each feed URL can stall; create_app must
        not run the update synchronously before the server can start."""
        release = threading.Event()
        called = threading.Event()

        def blocking_update(*args, **kwargs):
            called.set()
            release.wait(timeout=60)
            return {}

        monkeypatch.setattr(main_mod, "update_all", blocking_update)
        marker = ROOT / "data" / "last_feed_update.txt"
        old_marker = marker.read_text(encoding="utf-8") if marker.exists() else None
        if marker.exists():
            marker.unlink()          # force the "update due" path
        t0 = time.time()
        result = {}

        def build():
            try:
                result["app"] = main_mod.create_app()
            except Exception as exc:  # noqa: BLE001
                result["error"] = repr(exc)

        th = threading.Thread(target=build, daemon=True)
        th.start()
        th.join(timeout=3.0)
        assert not th.is_alive(), \
            "create_app still blocked on the feed update"
        assert "error" not in result, result.get("error")
        assert time.time() - t0 < 3.0
        release.set()
        if old_marker is not None:
            marker.write_text(old_marker, encoding="utf-8")
