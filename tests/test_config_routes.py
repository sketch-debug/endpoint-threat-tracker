"""HTTP coverage for the admin config/user/feeds routes (routes_config).

Every route in app/web/routes_config.py is exercised hermetically: config_dir
is repointed at a tmp copy of config/ so the indicator and scoring editors
can write files and .bak backups without ever touching the shipped lists,
and feed updates are monkeypatched so no test reaches the network.
"""
from __future__ import annotations

import shutil
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

import app.main as main_mod
from app import auth, feed_updater


@pytest.fixture()
def app(settings, monkeypatch):
    monkeypatch.setenv("TRACKER_ADMIN_PASSWORD", "TestAdmin123!")
    # hermetic config: the editors below write files + backups
    tmp_cfg = Path(settings.db_path).parent / "cfg"
    shutil.copytree(settings.config_dir, tmp_cfg)
    settings.config_dir = tmp_cfg
    return main_mod.create_app(settings)


@pytest.fixture()
def admin(app):
    client = TestClient(app)
    client.post("/login", data={"username": "admin", "password": "TestAdmin123!"})
    return client


@pytest.fixture()
def viewer(app, admin):
    admin.post("/users", data={"username": "vic",
                               "password": "ViewerPass123", "role": "viewer"})
    client = TestClient(app)
    client.post("/login", data={"username": "vic", "password": "ViewerPass123"})
    return client


class TestConfigPage:
    def test_admin_sees_lists_and_editor_links(self, admin):
        resp = admin.get("/config")
        assert resp.status_code == 200
        assert "c2_domains.txt" in resp.text     # shipped list is linked
        assert "/config/scoring" in resp.text

    def test_viewer_is_forbidden(self, viewer):
        assert viewer.get("/config").status_code == 403


class TestIndicatorEditor:
    def test_get_edit_page_shows_file_content(self, admin, settings):
        resp = admin.get("/config/indicators/c2_domains")
        assert resp.status_code == 200
        assert "c2_domains" in resp.text

    def test_get_rejects_invalid_name(self, admin):
        assert admin.get("/config/indicators/BadName").status_code == 400

    def test_get_missing_file_is_404(self, admin):
        assert admin.get("/config/indicators/no_such_list").status_code == 404

    def test_save_writes_backups_audits_and_reloads(self, admin, settings):
        path = settings.config_dir / "indicators" / "c2_domains.txt"
        old_content = path.read_text(encoding="utf-8")
        indicators_before = admin.app.state.indicators

        resp = admin.post("/config/indicators/c2_domains",
                          data={"content": "evil.example\n"})
        assert resp.status_code == 200, resp.text
        assert "Saved c2_domains.txt" in resp.text
        assert path.read_text(encoding="utf-8") == "evil.example\n"
        bak = path.with_suffix(".txt.bak")
        assert bak.read_text(encoding="utf-8") == old_content
        row = admin.app.state.db.one(
            "SELECT COUNT(*) AS n FROM audit_log "
            "WHERE action='config_indicator_edit'")
        assert row["n"] == 1
        assert admin.app.state.indicators is not indicators_before, \
            "saving a list must rebuild the live Indicators object"

    def test_save_rejects_oversized_content(self, admin):
        resp = admin.post("/config/indicators/c2_domains",
                          data={"content": "x" * (256 * 1024 + 1)})
        assert resp.status_code == 400
        assert "File too large" in resp.text

    def test_save_rejects_invalid_name(self, admin):
        assert admin.post("/config/indicators/BadName",
                          data={"content": "x"}).status_code == 400

    def test_save_missing_file_is_404(self, admin):
        assert admin.post("/config/indicators/no_such_list",
                          data={"content": "x"}).status_code == 404


class TestScoringEditor:
    def test_get_shows_current_config(self, admin):
        resp = admin.get("/config/scoring")
        assert resp.status_code == 200
        assert "rule_weights" in resp.text

    def test_save_valid_yaml_writes_backup(self, admin, settings):
        path = settings.config_dir / "scoring.yaml"
        content = path.read_text(encoding="utf-8")
        resp = admin.post("/config/scoring", data={"content": content})
        assert resp.status_code == 200, resp.text
        assert "scoring.yaml saved" in resp.text
        assert path.with_suffix(".yaml.bak").read_text(encoding="utf-8") == content
        row = admin.app.state.db.one(
            "SELECT COUNT(*) AS n FROM audit_log "
            "WHERE action='config_scoring_edit'")
        assert row["n"] == 1

    def test_save_invalid_yaml_is_400(self, admin):
        resp = admin.post("/config/scoring", data={"content": "rule_weights: ["})
        assert resp.status_code == 400
        # colon distinguishes the live error from the template's static copy
        # ("Invalid YAML is rejected before saving")
        assert "Invalid YAML:" in resp.text

    def test_save_non_mapping_is_400(self, admin):
        resp = admin.post("/config/scoring", data={"content": "- a\n- b\n"})
        assert resp.status_code == 400

    def test_save_missing_rule_weights_is_400(self, admin):
        resp = admin.post("/config/scoring", data={"content": "thresholds: {}\n"})
        assert resp.status_code == 400
        assert "rule_weights" in resp.text


class TestUserManagement:
    def test_users_page_lists_accounts(self, admin):
        resp = admin.get("/users")
        assert resp.status_code == 200
        assert "admin" in resp.text

    def test_create_user_then_duplicate_fails(self, admin):
        resp = admin.post("/users", data={"username": "ana1",
                                          "password": "AnalystPass123",
                                          "role": "analyst"},
                          follow_redirects=False)
        assert resp.status_code == 303
        assert "ana1" in admin.get("/users").text
        dup = admin.post("/users", data={"username": "ana1",
                                         "password": "AnalystPass123",
                                         "role": "analyst"})
        assert dup.status_code == 400

    def test_role_change_updates_the_account(self, admin):
        admin.post("/users", data={"username": "vic2",
                                   "password": "ViewerPass123",
                                   "role": "viewer"})
        resp = admin.post("/users/vic2/role", data={"role": "analyst"},
                          follow_redirects=False)
        assert resp.status_code == 303
        roles = {u["username"]: u["role"]
                 for u in auth.list_users(admin.app.state.db)}
        assert roles["vic2"] == "analyst"

    def test_password_change_succeeds_and_short_password_is_rejected(
            self, admin, app):
        admin.post("/users", data={"username": "pw1",
                                   "password": "OriginalPass123",
                                   "role": "viewer"})
        ok = admin.post("/users/pw1/password", data={"password": "NewPassword456"},
                        follow_redirects=False)
        assert ok.status_code == 303
        # the new password really logs in...
        fresh = TestClient(app)
        fresh.post("/login", data={"username": "pw1", "password": "NewPassword456"})
        assert fresh.get("/").status_code == 200

        bad = admin.post("/users/pw1/password", data={"password": "short"})
        assert bad.status_code == 400
        assert "at least 8" in bad.text

    def test_delete_other_user_then_refuse_self_delete(self, admin):
        admin.post("/users", data={"username": "gone1",
                                   "password": "DoomedPass123", "role": "viewer"})
        resp = admin.post("/users/gone1/delete", follow_redirects=False)
        assert resp.status_code == 303
        assert "gone1" not in admin.get("/users").text

        self_del = admin.post("/users/admin/delete", follow_redirects=False)
        assert self_del.status_code == 303
        assert "err=" in self_del.headers["location"]
        page = admin.get(self_del.headers["location"])
        assert "cannot delete your own account" in page.text

    def test_viewer_is_forbidden(self, viewer):
        assert viewer.get("/users").status_code == 403


class TestFeedsPage:
    def test_feeds_page_renders(self, admin):
        assert admin.get("/config/feeds").status_code == 200

    def test_run_feeds_reports_success(self, admin, monkeypatch):
        def fake_update(settings, db, actor=""):
            return {"updated": 1, "skipped": 2, "failed": 0}
        monkeypatch.setattr(feed_updater, "update_all", fake_update)
        resp = admin.post("/config/feeds", follow_redirects=False)
        assert resp.status_code == 303
        assert "msg=" in resp.headers["location"]
        page = admin.get(resp.headers["location"])
        assert "Feed update completed: 1 updated, 2 skipped, 0 failed" in page.text

    def test_run_feeds_reports_errors_without_500(self, admin, monkeypatch):
        def fake_update(settings, db, actor=""):
            raise RuntimeError("boom")
        monkeypatch.setattr(feed_updater, "update_all", fake_update)
        resp = admin.post("/config/feeds", follow_redirects=False)
        assert resp.status_code == 303
        assert "msg=" in resp.headers["location"]
        page = admin.get(resp.headers["location"])
        assert "Feed update error: boom" in page.text
