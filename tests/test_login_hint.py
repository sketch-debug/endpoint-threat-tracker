"""The login page must describe a password that can actually work.

install.ps1 prompts for or generates the admin password and writes it to .env,
while login.html used to advertise a hardcoded "admin / admin1234" on every
deployment. A new admin who trusted it failed the first login - and five
failures lock the real admin account out for five minutes. These tests pin
both branches: the default hint only while the bootstrap default is active,
and a pointer to .env once a real password is configured.
"""
from __future__ import annotations

from fastapi.testclient import TestClient

import app.main as main_mod


def _login_html(settings, monkeypatch, password: str | None) -> str:
    """GET /login with TRACKER_ADMIN_PASSWORD set to `password` (None = unset).

    The env is set AFTER create_app so a .env file on disk cannot re-populate
    the variable underneath the unset case (load_dotenv never overwrites, but
    it does fill gaps at Settings() construction).
    """
    client = TestClient(main_mod.create_app(settings))
    if password is None:
        monkeypatch.delenv("TRACKER_ADMIN_PASSWORD", raising=False)
    else:
        monkeypatch.setenv("TRACKER_ADMIN_PASSWORD", password)
    resp = client.get("/login")
    assert resp.status_code == 200
    return resp.text


class TestLoginHint:
    def test_default_password_is_still_advertised(self, settings, monkeypatch):
        html = _login_html(settings, monkeypatch, "admin1234")
        assert "admin / admin1234" in html

    def test_unset_password_falls_back_to_advertising_the_default(
            self, settings, monkeypatch):
        html = _login_html(settings, monkeypatch, None)
        assert "admin / admin1234" in html

    def test_install_time_password_points_at_env_not_the_default(
            self, settings, monkeypatch):
        html = _login_html(settings, monkeypatch, "a-random-install-pass")
        assert "admin1234" not in html, "a stale default hint is the bug"
        assert "TRACKER_ADMIN_PASSWORD" in html
        assert ".env" in html

    def test_wrong_password_response_carries_the_same_hint(self, settings,
                                                           monkeypatch):
        client = TestClient(main_mod.create_app(settings))
        monkeypatch.setenv("TRACKER_ADMIN_PASSWORD", "a-random-install-pass")
        resp = client.post("/login", data={"username": "admin",
                                           "password": "wrong"})
        assert resp.status_code == 401
        assert "admin1234" not in resp.text
        assert "TRACKER_ADMIN_PASSWORD" in resp.text
