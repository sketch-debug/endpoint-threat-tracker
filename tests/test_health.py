"""Self-monitoring tests (brief section 6): /health endpoint, heartbeat
alerts with hourly dedup, indicator-age warning, scheduler-run tracking and
rotating log files."""
from __future__ import annotations

import logging
import time
from datetime import timedelta
from pathlib import Path

from fastapi.testclient import TestClient

import app.detect as detect_mod
import app.main as main_mod
from app import health as health_mod
from app.config import Settings
from app.db import Database
from app.indicators import Indicators
from app.ingest import Ingestor
from app.normalize import iso, utcnow


def _client(settings) -> TestClient:
    # no context manager: lifespan (scheduler/feed thread) is not needed here
    return TestClient(main_mod.create_app(settings), raise_server_exceptions=False)


def _age_indicator_file(settings, days: float) -> Path:
    """Point settings at a tmp config dir with a suitably old indicator file."""
    cfg = settings.config_dir  # keep a reference; health reads it live
    tmp_ind = Path(settings.db_path).parent / "cfg" / "indicators"
    tmp_ind.mkdir(parents=True, exist_ok=True)
    ind = tmp_ind / "bad_hashes.txt"
    ind.write_text("a" * 64 + "\n", encoding="utf-8")
    old = time.time() - days * 86400
    import os
    os.utime(ind, (old, old))
    settings.config_dir = Path(settings.db_path).parent / "cfg"
    return cfg


class TestHealthEndpoint:
    def test_health_is_public_and_complete(self, settings):
        client = _client(settings)
        resp = client.get("/health")
        assert resp.status_code == 200, "middleware redirected /health to /login"
        data = resp.json()
        for key in ("status", "now", "last_ingest_at", "last_scheduler_run",
                    "database_mb", "free_disk_gb", "pending_alerts",
                    "indicator_age_days", "problems"):
            assert key in data, f"missing {key}"
        assert data["status"] == "ok", data["problems"]
        assert data["database_mb"] > 0
        assert data["free_disk_gb"] > 0
        assert data["pending_alerts"] == 0
        assert data["indicator_age_days"] is not None
        assert data["last_ingest_at"] is None   # fresh DB: honest nulls

    def test_health_reports_degraded_when_ingest_is_stale(self, settings, db):
        old = iso(utcnow() - timedelta(hours=48))
        db.execute("INSERT INTO files(sha256, filename, status, ingested_at) "
                   "VALUES(?,?,?,?)", ("x1", "old.csv", "ingested", old))
        settings.app["health"] = {"heartbeat_hours": 6,
                                  "indicator_max_age_days": 9999}
        payload = health_mod.health_payload(db, settings)
        assert payload["status"] == "degraded"
        assert any("no data ingested" in p for p in payload["problems"])
        assert payload["ingest_age_hours"] >= 48


class TestHeartbeat:
    def test_stale_ingest_alerts_once_per_hour(self, settings, db, monkeypatch):
        old = iso(utcnow() - timedelta(hours=48))
        db.execute("INSERT INTO files(sha256, filename, status, ingested_at) "
                   "VALUES(?,?,?,?)", ("x1", "old.csv", "ingested", old))
        settings.app["health"] = {"heartbeat_hours": 6,
                                  "indicator_max_age_days": 9999}

        first = health_mod.run_heartbeat(db, settings)
        assert first["alerted"] == 1
        assert any("no data ingested" in p for p in first["problems"])
        rows = db.query("SELECT * FROM alerts_log WHERE kind='heartbeat'")
        assert len(rows) == 1 and rows[0]["status"] == "logged"
        assert db.one("SELECT COUNT(*) AS n FROM audit_log "
                      "WHERE action='heartbeat_alert'")["n"] == 1

        # same hour again -> deduplicated, never a flood
        again = health_mod.run_heartbeat(db, settings)
        assert again["alerted"] == 0
        assert db.one("SELECT COUNT(*) AS n FROM alerts_log "
                      "WHERE kind='heartbeat'")["n"] == 1

    def test_healthy_system_alerts_nothing(self, settings, db):
        fresh = iso(utcnow() - timedelta(minutes=5))
        db.execute("INSERT INTO files(sha256, filename, status, ingested_at) "
                   "VALUES(?,?,?,?)", ("x1", "new.csv", "ingested", fresh))
        settings.app["health"] = {"heartbeat_hours": 6,
                                  "indicator_max_age_days": 9999}
        result = health_mod.run_heartbeat(db, settings)
        assert result == {"problems": [], "alerted": 0}
        assert db.one("SELECT COUNT(*) AS n FROM alerts_log")["n"] == 0

    def test_stale_indicator_lists_warn(self, settings, db, indicators):
        fresh = iso(utcnow() - timedelta(minutes=5))
        db.execute("INSERT INTO files(sha256, filename, status, ingested_at) "
                   "VALUES(?,?,?,?)", ("x1", "new.csv", "ingested", fresh))
        _age_indicator_file(settings, days=30)
        settings.app["health"] = {"heartbeat_hours": 9999,
                                  "indicator_max_age_days": 14}
        result = health_mod.run_heartbeat(db, settings)
        assert result["alerted"] == 1
        assert any("indicator lists" in p for p in result["problems"])
        payload = health_mod.health_payload(db, settings)
        assert payload["status"] == "degraded"
        assert payload["indicator_age_days"] >= 29


class TestSchedulerAndLogs:
    def test_run_cycle_records_last_scheduler_run(self, settings, db,
                                                  indicators):
        ing = Ingestor(db, settings, indicators, detector=None)
        det = detect_mod.Detector(db, settings, indicators)
        before = detect_mod.last_cycle_info()
        stats = detect_mod.run_cycle(ing, det)
        after = detect_mod.last_cycle_info()
        assert "skipped" not in stats or not stats.get("skipped")
        assert after["finished"], f"no finish timestamp recorded: {before}"
        assert after["started"]
        assert after["finished"] >= after["started"]

    def test_logs_rotate_by_size(self, settings, tmp_path):
        root = logging.getLogger()
        before = [h for h in root.handlers
                  if isinstance(h, logging.handlers.RotatingFileHandler)]
        try:
            for h in before:
                root.removeHandler(h)
            main_mod.setup_logging(settings)
            rot = [h for h in root.handlers
                   if isinstance(h, logging.handlers.RotatingFileHandler)]
            assert rot, "no rotating file handler installed"
            assert all(h.maxBytes == 5 * 1024 * 1024 for h in rot)
            assert all(h.backupCount == 5 for h in rot)
            assert any(Path(h.baseFilename) ==
                       Path(settings.log_dir / "tracker.log").resolve()
                       for h in rot)
            logging.getLogger("tracker").info("rotation probe")
            assert (settings.log_dir / "tracker.log").exists()
        finally:
            pass  # handlers are process-global; tests only add their own


import logging.handlers  # noqa: E402  (used by test_logs_rotate_by_size)
