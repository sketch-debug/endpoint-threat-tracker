"""Phase-2 audit hardening: PBKDF2 cost, login timing oracle, JSON 401s,
non-loopback warnings, security headers.

Each test pins one hardening item from the read-only audit:

6. PBKDF2 at 390k was below OWASP's current 600k recommendation for
   HMAC-SHA256. Iterations are stored per hash, so old hashes keep working.
7. authenticate() short-circuited before PBKDF2 for unknown usernames, so a
   missing account answered instantly while a real one took ~150ms - a
   username-enumeration oracle over response latency.
8. The auth middleware 303-redirected /api/* to the HTML login page, so
   fetch() callers got HTML where they expect 401 JSON.
9. Nothing warned when server.host was set off-loopback: login, /health and
   session cookies then travel over plain HTTP to that network.
10. No security headers (nosniff / framing / referrer / CSP) on any response.
"""
from __future__ import annotations

import logging

import pytest
from fastapi.testclient import TestClient

from app import auth
import app.main as main_mod


# ---- 6. PBKDF2 cost ------------------------------------------------------

def test_new_hashes_use_600k_iterations() -> None:
    stored = auth.hash_password("a-password-for-hashing")
    algo, iter_s, salt_hex, digest_hex = stored.split("$")
    assert algo == "pbkdf2_sha256"
    assert int(iter_s) == 600_000, "OWASP PBKDF2-HMAC-SHA256 recommendation"
    assert len(salt_hex) == 32 and len(digest_hex) == 64


def test_legacy_390k_hash_still_authenticates() -> None:
    """Iterations live in the stored string, so pre-upgrade hashes verify."""
    legacy = auth.hash_password("old-cost-password", iterations=390_000)
    assert legacy.split("$")[1] == "390000"
    assert auth.verify_password("old-cost-password", legacy)
    assert not auth.verify_password("wrong-password", legacy)


# ---- 7. username timing oracle ------------------------------------------

def test_authenticate_always_costs_exactly_one_pbkdf2(
        db, settings, monkeypatch: pytest.MonkeyPatch) -> None:
    """Known or unknown username: exactly one hash computation either way."""
    auth.create_user(db, "alice", "alices-password", "analyst", actor="system")
    auth._dummy_hash()  # warm the cache before counting

    calls = {"n": 0}
    real = auth.hash_password

    def counting(*args, **kwargs):
        calls["n"] += 1
        return real(*args, **kwargs)

    monkeypatch.setattr(auth, "hash_password", counting)

    calls["n"] = 0
    assert auth.authenticate(db, "nobody-here", "whatever1") is None
    unknown_cost = calls["n"]
    assert unknown_cost == 1, "an unknown user must still burn one PBKDF2"

    calls["n"] = 0
    assert auth.authenticate(db, "alice", "wrong-password") is None
    known_cost = calls["n"]
    assert known_cost == 1
    assert unknown_cost == known_cost, "the oracle is back: costs differ"

    calls["n"] = 0
    assert auth.authenticate(db, "alice", "alices-password") is not None
    assert calls["n"] == 1


# ---- 8. /api/* gets 401 JSON --------------------------------------------

def test_api_401_is_json_not_a_login_redirect(settings) -> None:
    client = TestClient(main_mod.create_app(settings))
    resp = client.get("/api/status")
    assert resp.status_code == 401
    assert resp.headers["content-type"].startswith("application/json")
    assert resp.json() == {"detail": "login required"}


def test_pages_still_redirect_to_login(settings) -> None:
    client = TestClient(main_mod.create_app(settings))
    resp = client.get("/", follow_redirects=False)
    assert resp.status_code == 303
    assert resp.headers["location"] == "/login"


# ---- 9. non-loopback bind warnings --------------------------------------

def test_startup_warns_when_bound_off_loopback(settings, caplog) -> None:
    settings.app.setdefault("server", {})["host"] = "0.0.0.0"
    with caplog.at_level(logging.WARNING):
        main_mod.create_app(settings)
    assert any("plain HTTP" in r.message and "0.0.0.0" in r.message
               for r in caplog.records), "silent LAN exposure"


def test_startup_silent_on_loopback(settings, caplog) -> None:
    settings.app.setdefault("server", {})["host"] = "127.0.0.1"
    with caplog.at_level(logging.WARNING):
        main_mod.create_app(settings)
    assert not any("plain HTTP" in r.message for r in caplog.records)


@pytest.fixture()
def admin_client(settings, monkeypatch):
    monkeypatch.setenv("TRACKER_ADMIN_PASSWORD", "TestAdmin123!")
    client = TestClient(main_mod.create_app(settings))
    client.post("/login", data={"username": "admin", "password": "TestAdmin123!"})
    return client


def _form(settings) -> dict:
    return {
        "server_host": "127.0.0.1",
        "server_port": str(settings.app["server"]["port"]),
        "poll_seconds": str(settings.app["ingest"]["poll_seconds"]),
        "max_file_bytes": str(settings.app["ingest"]["max_file_bytes"]),
        "scoring_window_hours": str(settings.app["scoring_window_hours"]),
        "recheck_days": str(settings.app["recheck"]["days"]),
        "off_hours": "",
    }


def _hermetic_cfg(settings, tmp_path) -> None:
    """Point save_settings at a copy: it writes config_dir/app_config.yaml,
    and the shared settings fixture does NOT override config_dir - without
    this, the test would rewrite the repo's real config file."""
    import shutil
    cfg_dir = tmp_path / "config"
    cfg_dir.mkdir()
    shutil.copy2(settings.config_dir / "app_config.yaml", cfg_dir / "app_config.yaml")
    settings.config_dir = cfg_dir


def test_settings_save_warns_on_non_loopback_host(admin_client, settings,
                                                   tmp_path) -> None:
    _hermetic_cfg(settings, tmp_path)
    form = _form(settings)
    form["server_host"] = "0.0.0.0"
    resp = admin_client.post("/settings", data=form)
    assert resp.status_code == 200
    assert "server.host=0.0.0.0" in resp.text
    assert "Set-FirewallRule.ps1" in resp.text


def test_settings_save_quiet_on_loopback(admin_client, settings, tmp_path) -> None:
    _hermetic_cfg(settings, tmp_path)
    resp = admin_client.post("/settings", data=_form(settings))
    assert resp.status_code == 200
    assert "Settings saved" in resp.text  # the flash itself must render
    assert "Set-FirewallRule.ps1" not in resp.text


# ---- 10. security headers ------------------------------------------------

@pytest.fixture()
def logged_in_client(settings, monkeypatch) -> TestClient:
    monkeypatch.setenv("TRACKER_ADMIN_PASSWORD", "TestAdmin123!")
    client = TestClient(main_mod.create_app(settings))
    client.post("/login", data={"username": "admin", "password": "TestAdmin123!"})
    return client


def test_security_headers_on_login_and_dashboard(settings) -> None:
    anon = TestClient(main_mod.create_app(settings))
    for resp in (anon.get("/login"), anon.get("/health")):
        assert resp.headers["X-Content-Type-Options"] == "nosniff"
        assert resp.headers["X-Frame-Options"] == "DENY"
        assert resp.headers["Referrer-Policy"] == "no-referrer"
        csp = resp.headers["Content-Security-Policy"]
        assert "script-src 'self'" in csp
        assert "frame-ancestors 'none'" in csp
        assert "base-uri 'self'" in csp
        assert "form-action 'self'" in csp


def test_security_headers_on_authenticated_pages(logged_in_client) -> None:
    resp = logged_in_client.get("/")
    assert resp.status_code == 200
    assert resp.headers["X-Content-Type-Options"] == "nosniff"
    assert "script-src 'self'" in resp.headers["Content-Security-Policy"]


def test_security_headers_on_401_303_and_500(settings, monkeypatch) -> None:
    """401/303 come from the middleware's early returns and the 500 from
    the error handler, which runs OUTSIDE that middleware - all three used
    to ship with no security headers at all."""
    monkeypatch.setenv("TRACKER_ADMIN_PASSWORD", "TestAdmin123!")
    app = main_mod.create_app(settings)

    @app.get("/boom")
    async def boom():
        raise RuntimeError("boom")

    client = TestClient(app, raise_server_exceptions=False)
    redirect = client.get("/", follow_redirects=False)   # anonymous 303
    unauthorized = client.get("/api/status")             # anonymous 401
    client.post("/login", data={"username": "admin",
                                "password": "TestAdmin123!"})
    failed = client.get("/boom", headers={"Accept": "text/html"})  # 500

    assert (redirect.status_code, unauthorized.status_code,
            failed.status_code) == (303, 401, 500)
    for what, resp in (("303", redirect), ("401", unauthorized),
                       ("500", failed)):
        assert resp.headers["X-Content-Type-Options"] == "nosniff", what
        assert resp.headers["X-Frame-Options"] == "DENY", what
        assert resp.headers["Referrer-Policy"] == "no-referrer", what
        csp = resp.headers["Content-Security-Policy"]
        assert "script-src 'self'" in csp, what
        assert "frame-ancestors 'none'" in csp, what


def test_no_template_ships_inline_script() -> None:
    """CSP script-src 'self' only holds if nothing needs inline JS."""
    from pathlib import Path
    tpl_dir = Path(main_mod.__file__).parent / "web" / "templates"
    offenders = []
    for path in tpl_dir.glob("*.html"):
        text = path.read_text(encoding="utf-8")
        for i, line in enumerate(text.splitlines(), 1):
            stripped = line.strip()
            if "<script" in stripped and "src=" not in stripped:
                offenders.append(f"{path.name}:{i} inline <script>")
            if " onsubmit=" in stripped or " onclick=" in stripped \
                    or " onload=" in stripped:
                offenders.append(f"{path.name}:{i} inline handler")
    assert not offenders, offenders


def test_users_page_delete_form_uses_data_confirm(admin_client) -> None:
    """The moved confirm still guards the destructive form (via dashboard.js)."""
    resp = admin_client.get("/users")
    assert resp.status_code == 200
    assert "data-confirm=" in resp.text
    assert "onsubmit=" not in resp.text
