"""Error visibility tests (brief section 8): exceptions log context but never
secrets, 500s are readable without leaking internals, and the dashboard
shows a degraded banner when /health says so (P12)."""
from __future__ import annotations

import logging
import sys

import pytest
from fastapi.testclient import TestClient

import app.main as main_mod
from app.errors import REDACTED, RedactSecretsFilter, install_error_handlers


class TestSecretRedaction:
    def test_env_secret_values_are_scrubbed(self, monkeypatch):
        monkeypatch.setenv("TRACKER_ADMIN_PASSWORD", "Sup3rS3cretPW!")
        monkeypatch.setenv("TEAMS_WEBHOOK_URL",
                           "https://outlook.office.com/webhook/abc123def456")
        record = logging.getLogger("t").makeRecord(
            "t", logging.INFO, __file__, 1,
            "login failed for admin with Sup3rS3cretPW! "
            "posting to https://outlook.office.com/webhook/abc123def456",
            (), None)
        assert RedactSecretsFilter().filter(record) is True
        msg = record.getMessage()
        assert "Sup3rS3cretPW!" not in msg
        assert "abc123def456" not in msg
        assert REDACTED in msg

    def test_key_value_pairs_are_scrubbed_even_without_env(self):
        record = logging.getLogger("t").makeRecord(
            "t", logging.ERROR, __file__, 1,
            "config load failed: password=hunter22 "
            "token=zzz-qqq session_secret=abcdef123456", (), None)
        RedactSecretsFilter().filter(record)
        msg = record.getMessage()
        assert "hunter22" not in msg and "zzz-qqq" not in msg
        assert "abcdef123456" not in msg
        assert "password=" + REDACTED in msg

    def test_setup_logging_attaches_the_filter(self, settings, tmp_path):
        root = logging.getLogger()
        before = len(root.handlers)
        try:
            main_mod.setup_logging(settings)
            assert any(
                any(isinstance(f, RedactSecretsFilter) for f in h.filters)
                for h in root.handlers), "no handler carries the redaction filter"
        finally:
            # remove only the handlers we just added
            for h in root.handlers[before:]:
                root.removeHandler(h)


class TestReadable500:
    def test_unhandled_error_returns_friendly_page_with_context(
            self, settings, monkeypatch, caplog):
        monkeypatch.setenv("TRACKER_ADMIN_PASSWORD", "TestAdmin123!")
        app = main_mod.create_app(settings)

        @app.get("/boom")
        async def boom():
            raise RuntimeError("internal detail with password=leaky123")

        client = TestClient(app, raise_server_exceptions=False)
        client.post("/login", data={"username": "admin",
                                    "password": "TestAdmin123!"})
        with caplog.at_level(logging.ERROR):
            resp = client.get("/boom",
                              headers={"Accept": "text/html"})
        assert resp.status_code == 500
        assert "Something went wrong" in resp.text
        assert "Correlation id" in resp.text
        assert "Traceback" not in resp.text, "raw traceback leaked to the page"
        assert "internal detail with password=leaky123" not in resp.text
        # the log captured the context (message + traceback)...
        joined = caplog.text
        assert "/boom" in joined and "RuntimeError" in joined
        # ...but never the secret-ish kv pair (it appears in the traceback's
        # source line, which the filter scrubs too)
        assert "leaky123" not in joined, joined
        assert REDACTED in joined

    def test_unauthenticated_page_still_redirects_to_login(self, settings):
        client = TestClient(main_mod.create_app(settings),
                            raise_server_exceptions=False)
        resp = client.get("/", follow_redirects=False)
        assert resp.status_code == 303


class TestDegradedBanner:
    @pytest.fixture()
    def admin_client(self, settings, monkeypatch):
        monkeypatch.setenv("TRACKER_ADMIN_PASSWORD", "TestAdmin123!")
        client = TestClient(main_mod.create_app(settings))
        client.post("/login", data={"username": "admin",
                                    "password": "TestAdmin123!"})
        return client

    def test_banner_shows_when_degraded(self, settings, db, admin_client):
        from app.normalize import iso, utcnow
        from datetime import timedelta
        settings.app["health"] = {"heartbeat_hours": 1,
                                  "indicator_max_age_days": 99999}
        db.execute("INSERT INTO files(sha256, filename, status, ingested_at) "
                   "VALUES(?,?,?,?)",
                   ("stale1", "stale.csv", "ingested",
                    iso(utcnow() - timedelta(hours=48))))
        resp = admin_client.get("/")
        assert resp.status_code == 200
        assert "System degraded" in resp.text
        assert "no data ingested" in resp.text
        assert 'href="/health"' in resp.text

    def test_no_banner_when_healthy(self, settings, db, admin_client):
        from app.normalize import iso, utcnow
        from datetime import timedelta
        settings.app["health"] = {"heartbeat_hours": 9999,
                                  "indicator_max_age_days": 99999}
        db.execute("INSERT INTO files(sha256, filename, status, ingested_at) "
                   "VALUES(?,?,?,?)",
                   ("fresh1", "fresh.csv", "ingested",
                    iso(utcnow() - timedelta(minutes=2))))
        resp = admin_client.get("/")
        assert resp.status_code == 200
        assert "System degraded" not in resp.text
