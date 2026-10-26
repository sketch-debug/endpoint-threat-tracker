"""Backup and restore tests (brief section 7): encrypted+verified backup,
tamper detection, and a real restore into a clean folder whose dashboard
shows the same data. Windows-only (the script uses Windows PowerShell)."""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app import auth
from app.config import Settings
from app.normalize import iso, utcnow

pytestmark = pytest.mark.skipif(
    not sys.platform.startswith("win"),
    reason="Backup-Database.ps1 requires Windows PowerShell")

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "Backup-Database.ps1"
PASS = "correct-horse-battery-staple-1"


def _run_ps(*args: str) -> subprocess.CompletedProcess:
    cmd = ["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass",
           "-File", str(SCRIPT), *args]
    return subprocess.run(cmd, capture_output=True, text=True, timeout=300,
                           encoding="utf-8", errors="replace")


def _seed(db, settings) -> None:
    auth.create_user(db, "admin", "RestoreTest123", "admin", actor="test")
    db.execute("INSERT INTO incidents(incident_key, type, severity, status, "
               "title, created_at) VALUES(?,?,?,?,?,?)",
               ("IR-RESTORE-1", "miner", "high", "open", "restore drill",
                iso(utcnow())))
    db.execute("INSERT INTO signals(ts, pc, rule_id, category, weight, title, "
               "detail, dedup_key) VALUES(?,?,?,?,?,?,?,?)",
               (iso(utcnow()), "PC-1", "rule_r", "evasion", 40, "t", "", "rk1"))
    db.execute("INSERT INTO files(sha256, filename, status, ingested_at) "
               "VALUES(?,?,?,?)", ("fff1", "keepme.csv", "ingested",
                                   iso(utcnow())))


class TestBackupRestore:
    def test_backup_verify_and_restore_shows_same_data(
            self, db, settings, indicators, tmp_path):
        _seed(db, settings)
        db.close()                      # flush before the external snapshot
        backups = tmp_path / "backups"

        # 1. backup (also verifies what it wrote)
        res = _run_ps("-Passphrase", PASS,
                      "-Destination", str(backups),
                      "-DatabasePath", str(settings.db_path),
                      "-ProjectRoot", str(ROOT))
        out = (res.stdout or "") + (res.stderr or "")
        assert res.returncode == 0, out
        assert "BACKUP_OK" in out and "verified=integrity:ok" in out, out
        archives = list(backups.glob("tracker-backup-*.enc"))
        assert len(archives) == 1, archives
        assert not list(backups.glob("*.zip")), "plaintext zip left behind"

        # 2. standalone verify
        v = _run_ps("-Verify", "-Archive", str(archives[0]),
                    "-Passphrase", PASS, "-ProjectRoot", str(ROOT))
        vout = (v.stdout or "") + (v.stderr or "")
        assert v.returncode == 0 and "VERIFY_OK" in vout, vout

        # 3. tamper detection: flip one byte -> verification must fail
        data = bytearray(archives[0].read_bytes())
        data[-40] ^= 0xFF
        bad = tmp_path / "corrupt.enc"
        bad.write_bytes(bytes(data))
        b = _run_ps("-Verify", "-Archive", str(bad),
                    "-Passphrase", PASS, "-ProjectRoot", str(ROOT))
        assert b.returncode != 0, "corrupted archive verified successfully!"
        assert "BACKUP_FAILED" in ((b.stdout or "") + (b.stderr or ""))

        # 4. wrong passphrase also fails
        w = _run_ps("-Verify", "-Archive", str(archives[0]),
                    "-Passphrase", "wrong-passphrase", "-ProjectRoot", str(ROOT))
        assert w.returncode != 0

        # 5. restore into a clean folder
        restored = tmp_path / "restored"
        r = _run_ps("-Restore", "-Archive", str(archives[0]),
                    "-Passphrase", PASS, "-Target", str(restored),
                    "-ProjectRoot", str(ROOT))
        rout = (r.stdout or "") + (r.stderr or "")
        assert r.returncode == 0 and "RESTORE_OK" in rout, rout
        assert (restored / "data" / "tracker.db").exists()
        assert (restored / "config" / "app_config.yaml").exists()
        assert (restored / "manifest.json").exists()

        # 6. the restored instance's dashboard shows the same data
        rst_settings = Settings(base_dir=restored)
        client = TestClient(__import__("app.main", fromlist=["create_app"])
                            .create_app(rst_settings))
        login = client.post("/login", data={"username": "admin",
                                            "password": "RestoreTest123"})
        assert login.status_code in (200, 303), login.status_code
        page = client.get("/incidents")
        assert page.status_code == 200
        assert "IR-RESTORE-1" in page.text
        assert "restore drill" in page.text
        status = client.get("/api/status").json()
        assert status["signals_total"] == 1
        assert status["open_incidents"] == 1
        health = client.get("/health")
        assert health.status_code in (200, 503)
        assert health.json()["database_mb"] > 0
