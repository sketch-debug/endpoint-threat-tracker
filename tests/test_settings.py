"""P8 regression: `ingest_validation.require_known_header` was dead config.

The key existed in app_config.yaml, was editable in the Settings form, and was
written back on save - but no ingest code ever read it, so admins believed in a
defense that did not exist. The fix removes it everywhere; these tests keep it
from creeping back into the UI, the route, or the saved file.
"""
from __future__ import annotations

import pytest
import yaml
from fastapi.testclient import TestClient

import app.main as main_mod


@pytest.fixture()
def admin_client(settings, monkeypatch):
    monkeypatch.setenv("TRACKER_ADMIN_PASSWORD", "TestAdmin123!")
    client = TestClient(main_mod.create_app(settings))
    client.post("/login", data={"username": "admin", "password": "TestAdmin123!"})
    return client


def _valid_form(settings) -> dict:
    return {
        "server_host": "127.0.0.1",
        "server_port": str(settings.app["server"]["port"]),
        "poll_seconds": str(settings.app["ingest"]["poll_seconds"]),
        "max_file_bytes": str(settings.app["ingest"]["max_file_bytes"]),
        "scoring_window_hours": str(settings.app["scoring_window_hours"]),
        "recheck_days": str(settings.app["recheck"]["days"]),
        "off_hours": "22:00-06:00",
    }


@pytest.fixture()
def hermetic_cfg(settings, tmp_path):
    """Point settings at a throwaway copy of app_config.yaml, so saving the
    Settings form never rewrites the tracked config/ file."""
    import shutil

    cfg_dir = tmp_path / "config"
    cfg_dir.mkdir()
    shutil.copy2(settings.config_dir / "app_config.yaml",
                 cfg_dir / "app_config.yaml")
    settings.config_dir = cfg_dir
    return settings


class TestLoginLockoutSettings:
    """The rate-limit thresholds are config: rendered, saved and validated."""

    def test_form_shows_current_lockout(self, settings, admin_client):
        resp = admin_client.get("/settings")
        assert resp.status_code == 200
        assert 'name="auth_max_failed_attempts"' in resp.text
        assert 'name="auth_lockout_window_minutes"' in resp.text

    def test_save_persists_lockout(self, hermetic_cfg, admin_client):
        data = _valid_form(hermetic_cfg)
        data["auth_max_failed_attempts"] = "3"
        data["auth_lockout_window_minutes"] = "10"
        resp = admin_client.post("/settings", data=data)
        assert resp.status_code == 200, resp.text

        saved = yaml.safe_load(
            (hermetic_cfg.config_dir / "app_config.yaml").read_text(encoding="utf-8"))
        assert saved["auth"] == {"max_failed_attempts": 3,
                                 "lockout_window_minutes": 10}

    def test_zero_is_rejected_not_saved(self, hermetic_cfg, admin_client):
        cfg = hermetic_cfg.config_dir / "app_config.yaml"
        before = yaml.safe_load(cfg.read_text(encoding="utf-8"))
        data = _valid_form(hermetic_cfg)
        data["auth_max_failed_attempts"] = "0"
        data["auth_lockout_window_minutes"] = "5"
        resp = admin_client.post("/settings", data=data)
        assert resp.status_code == 400
        assert "at least 1" in resp.text
        after = yaml.safe_load(cfg.read_text(encoding="utf-8"))
        assert after["auth"] == before["auth"], "a bad save must not touch config"


class TestDeadConfigRemoved:
    def test_settings_page_has_no_require_known_header_checkbox(self, admin_client):
        resp = admin_client.get("/settings")
        assert resp.status_code == 200
        assert "require_known_header" not in resp.text

    def test_shipped_config_has_no_ingest_validation_block(self, settings):
        data = yaml.safe_load(
            (settings.config_dir / "app_config.yaml").read_text(encoding="utf-8"))
        assert "ingest_validation" not in data

    def test_saving_settings_does_not_reintroduce_the_key(self, settings, admin_client):
        cfg = settings.config_dir / "app_config.yaml"
        before = cfg.read_text(encoding="utf-8")
        assert "ingest_validation" not in before

        resp = admin_client.post("/settings", data=_valid_form(settings))
        assert resp.status_code == 200, resp.text

        after = yaml.safe_load(cfg.read_text(encoding="utf-8"))
        assert "ingest_validation" not in after
        # the save still worked: the value we posted was written
        assert after["off_hours"] == ["22:00-06:00"]

    def test_saving_settings_without_the_old_field_still_works(self, settings,
                                                               admin_client):
        """Old bookmarked/HTML forms may still post the removed field."""
        data = _valid_form(settings)
        data["require_known_header"] = "on"
        resp = admin_client.post("/settings", data=data)
        assert resp.status_code == 200, resp.text
        saved = yaml.safe_load(
            (settings.config_dir / "app_config.yaml").read_text(encoding="utf-8"))
        assert "ingest_validation" not in saved
