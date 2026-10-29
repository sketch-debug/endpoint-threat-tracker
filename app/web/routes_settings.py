"""Settings page for editing app_config.yaml via dashboard."""
from __future__ import annotations

import shutil

import yaml
from fastapi import APIRouter, Form, HTTPException, Request
from fastapi.responses import HTMLResponse

from .. import audit as audit_mod
from .. import auth
from . import templates

router = APIRouter()


def _require_admin(request: Request):
    user = getattr(request.state, "user", None)
    if not user:
        raise HTTPException(status_code=401, detail="login required")
    if not auth.role_allows(user, "admin"):
        raise HTTPException(status_code=403, detail="admin required")
    return user


@router.get("/settings", response_class=HTMLResponse)
async def settings_page(request: Request):
    _require_admin(request)
    settings = request.app.state.settings
    cfg_path = settings.config_dir / "app_config.yaml"
    data = yaml.safe_load(cfg_path.read_text(encoding="utf-8")) or {}
    return templates.TemplateResponse("settings.html", {
        "request": request,
        "data": data,
    })


@router.post("/settings")
async def save_settings(request: Request,
                        server_host: str = Form(...),
                        server_port: int = Form(...),
                        poll_seconds: int = Form(...),
                        max_file_bytes: int = Form(...),
                        scoring_window_hours: int = Form(...),
                        recheck_days: int = Form(...),
                        off_hours: str = Form(""),
                        auth_max_failed_attempts: int | None = Form(None),
                        auth_lockout_window_minutes: int | None = Form(None)):
    user = _require_admin(request)
    settings = request.app.state.settings
    cfg_path = settings.config_dir / "app_config.yaml"
    try:
        data = yaml.safe_load(cfg_path.read_text(encoding="utf-8")) or {}
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"cannot read config: {exc}")

    # Login lockout. Optional so older/other forms (and bookmarks) that never
    # posted these still save; an explicit zero/negative is rejected instead of
    # silently switching the lockout off.
    if auth_max_failed_attempts is not None and auth_lockout_window_minutes is not None:
        if auth_max_failed_attempts < 1 or auth_lockout_window_minutes < 1:
            return templates.TemplateResponse("settings.html", {
                "request": request,
                "data": data,
                "error": "Login lockout attempts and window must be at least 1.",
            }, status_code=400)

    # server
    data.setdefault("server", {})
    data["server"]["host"] = server_host.strip() or "127.0.0.1"
    data["server"]["port"] = int(server_port)

    # ingest
    data.setdefault("ingest", {})
    data["ingest"]["poll_seconds"] = int(poll_seconds)
    data["ingest"]["max_file_bytes"] = int(max_file_bytes)

    # scoring window
    data["scoring_window_hours"] = int(scoring_window_hours)

    # recheck
    data.setdefault("recheck", {})
    data["recheck"]["days"] = int(recheck_days)

    # login lockout
    if auth_max_failed_attempts is not None and auth_lockout_window_minutes is not None:
        data.setdefault("auth", {})
        data["auth"]["max_failed_attempts"] = int(auth_max_failed_attempts)
        data["auth"]["lockout_window_minutes"] = int(auth_lockout_window_minutes)

    # off hours
    if off_hours.strip():
        # accept comma separated ranges
        ranges = [r.strip() for r in off_hours.split(",") if r.strip()]
        data["off_hours"] = ranges
    else:
        data["off_hours"] = []

    # backup
    backup = cfg_path.with_suffix(".yaml.bak")
    shutil.copy2(cfg_path, backup)

    cfg_path.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")

    # reload in-memory settings
    from ..config import Settings
    new_settings = Settings(settings.base_dir)
    request.app.state.settings = new_settings

    audit_mod.audit(request.app.state.db, user["username"], "settings_edit", "app_config.yaml", "saved via dashboard")
    msg = "Settings saved; previous version kept as app_config.yaml.bak."
    saved_host = str(data["server"]["host"])
    if saved_host not in ("127.0.0.1", "::1", "localhost"):
        msg += (f" NOTE: server.host={saved_host} serves login, /health and "
                "session cookies over plain HTTP to that network - restrict "
                "it with scripts/Set-FirewallRule.ps1 or use a TLS proxy.")
    return templates.TemplateResponse("settings.html", {
        "request": request,
        "data": data,
        "msg": msg,
    })
