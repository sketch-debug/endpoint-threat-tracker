"""Admin: indicator file editor, scoring config editor, user management."""
from __future__ import annotations

import re

import yaml
from fastapi import APIRouter, Form, HTTPException, Request
from fastapi.responses import HTMLResponse

from .. import audit as audit_mod
from .. import auth, rules
from . import templates

router = APIRouter()

_NAME_RE = re.compile(r"^[a-z0-9_]{1,64}$")
_MAX_INDICATOR_BYTES = 256 * 1024


def _require(request: Request, minimum: str) -> dict:
    user = getattr(request.state, "user", None)
    if not user:
        raise HTTPException(status_code=401, detail="login required")
    if not auth.role_allows(user, minimum):
        raise HTTPException(status_code=403, detail=f"role {minimum} or higher required")
    return user


def _indicator_files(settings) -> list[str]:
    directory = settings.config_dir / "indicators"
    if not directory.is_dir():
        return []
    return sorted(p.name for p in directory.glob("*.txt"))


@router.get("/config", response_class=HTMLResponse)
async def config_page(request: Request):
    _require(request, "admin")
    settings = request.app.state.settings
    files = _indicator_files(settings)
    return templates.TemplateResponse("config.html", {
        "request": request, "files": files, "types": list(settings.types),
        "rule_weights_yaml": yaml.safe_dump(settings.rule_weights,
                                            sort_keys=False).strip(),
        "alert_channels": settings.alert_channels,
        "recheck_days": settings.recheck_days,
    })


@router.get("/config/indicators/{name}", response_class=HTMLResponse)
async def edit_indicator(request: Request, name: str):
    _require(request, "admin")
    settings = request.app.state.settings
    if not _NAME_RE.match(name):
        raise HTTPException(status_code=400, detail="invalid file name")
    path = settings.config_dir / "indicators" / f"{name}.txt"
    if not path.is_file():
        raise HTTPException(status_code=404, detail="indicator file not found")
    content = path.read_text(encoding="utf-8", errors="replace")
    return templates.TemplateResponse("indicator_edit.html", {
        "request": request, "name": name, "content": content,
    })


@router.post("/config/indicators/{name}")
async def save_indicator(request: Request, name: str, content: str = Form(...)):
    user = _require(request, "admin")
    settings = request.app.state.settings
    if not _NAME_RE.match(name):
        raise HTTPException(status_code=400, detail="invalid file name")
    if len(content.encode("utf-8")) > _MAX_INDICATOR_BYTES:
        return templates.TemplateResponse("indicator_edit.html", {
            "request": request, "name": name, "content": content,
            "error": "File too large (max 256 KB).",
        }, status_code=400)
    path = settings.config_dir / "indicators" / f"{name}.txt"
    if not path.is_file():
        raise HTTPException(status_code=404, detail="indicator file not found")
    backup = path.with_suffix(path.suffix + ".bak")
    backup.write_text(path.read_text(encoding="utf-8"), encoding="utf-8")
    path.write_text(content, encoding="utf-8")
    audit_mod.audit(user_db(request), user["username"], "config_indicator_edit",
                    f"indicators/{name}.txt", f"saved ({len(content)} chars)")
    _reload_indicators(request)
    return templates.TemplateResponse("indicator_edit.html", {
        "request": request, "name": name, "content": content,
        "msg": f"Saved {name}.txt (previous version kept as .bak); "
               f"lists reloaded and active immediately.",
    })


def user_db(request: Request):
    return request.app.state.db


def _reload_indicators(request: Request) -> None:
    """Rebuild Indicators/Detector/Ingestor so saved lists take effect now."""
    from ..detect import Detector
    from ..indicators import Indicators
    from ..ingest import Ingestor
    app = request.app
    settings = app.state.settings
    ind = Indicators(settings.config_dir)
    det = Detector(app.state.db, settings, ind)
    ing = Ingestor(app.state.db, settings, ind, detector=det)
    app.state.indicators = ind
    app.state.detector = det
    app.state.ingestor = ing


@router.get("/config/scoring", response_class=HTMLResponse)
async def edit_scoring(request: Request):
    _require(request, "admin")
    settings = request.app.state.settings
    path = settings.config_dir / "scoring.yaml"
    return templates.TemplateResponse("scoring_edit.html", {
        "request": request,
        "content": path.read_text(encoding="utf-8") if path.is_file() else "",
    })


@router.post("/config/scoring")
async def save_scoring(request: Request, content: str = Form(...)):
    user = _require(request, "admin")
    settings = request.app.state.settings
    path = settings.config_dir / "scoring.yaml"
    try:
        parsed = yaml.safe_load(content) or {}
        if not isinstance(parsed, dict) or "rule_weights" not in parsed:
            raise ValueError("config must be a mapping with a 'rule_weights' key")
        warnings = rules.validate_rule_ids(dict(parsed.get("rule_weights", {})))
    except (yaml.YAMLError, ValueError) as exc:
        return templates.TemplateResponse("scoring_edit.html", {
            "request": request, "content": content,
            "error": f"Invalid YAML: {exc}",
        }, status_code=400)
    backup = path.with_suffix(".yaml.bak")
    backup.write_text(path.read_text(encoding="utf-8"), encoding="utf-8")
    path.write_text(content, encoding="utf-8")
    audit_mod.audit(user_db(request), user["username"], "config_scoring_edit",
                    "scoring.yaml", f"warnings={len(warnings)}")
    return templates.TemplateResponse("scoring_edit.html", {
        "request": request, "content": content,
        "msg": "scoring.yaml saved (previous version kept as scoring.yaml.bak).",
        "warnings": warnings,
    })


# ---------------------------------------------------------------- users ----

@router.get("/users", response_class=HTMLResponse)
async def users_page(request: Request):
    _require(request, "admin")
    db = request.app.state.db
    return templates.TemplateResponse("users.html", {
        "request": request, "users": auth.list_users(db),
    })


@router.post("/users")
async def create_user(request: Request, username: str = Form(...),
                      password: str = Form(...), role: str = Form(...)):
    user = _require(request, "admin")
    db = request.app.state.db
    try:
        auth.create_user(db, username.strip(), password, role, actor=user["username"])
        msg = f"User {username.strip().lower()} created."
    except Exception as exc:  # ValueError + sqlite IntegrityError (duplicate user)
        return templates.TemplateResponse("users.html", {
            "request": request, "users": auth.list_users(db), "error": str(exc),
        }, status_code=400)
    from urllib.parse import urlencode
    return _redir(f"/users?{urlencode({'msg': msg})}")


def _redir(location: str):
    from fastapi.responses import RedirectResponse
    return RedirectResponse(location, status_code=303)


@router.post("/users/{username}/role")
async def change_role(request: Request, username: str, role: str = Form(...)):
    admin = _require(request, "admin")
    db = request.app.state.db
    auth.set_role(db, username, role, actor=admin["username"])
    from urllib.parse import urlencode
    return _redir(f"/users?{urlencode({'msg': f'{username} is now {role}.'})}")


@router.post("/users/{username}/password")
async def change_password(request: Request, username: str,
                          password: str = Form(...)):
    admin = _require(request, "admin")
    db = request.app.state.db
    try:
        auth.set_password(db, username, password, actor=admin["username"])
        msg = f"Password changed for {username}."
    except ValueError as exc:
        msg = ""
        return templates.TemplateResponse("users.html", {
            "request": request, "users": auth.list_users(db), "error": str(exc),
        }, status_code=400)
    from urllib.parse import urlencode
    return _redir(f"/users?{urlencode({'msg': msg})}")


@router.post("/users/{username}/delete")
async def delete_user(request: Request, username: str):
    admin = _require(request, "admin")
    db = request.app.state.db
    if username.lower() == admin["username"].lower():
        return _redir("/users?err=You cannot delete your own account.")
    auth.delete_user(db, username, actor=admin["username"])
    from urllib.parse import urlencode
    return _redir(f"/users?{urlencode({'msg': f'User {username} deleted.'})}")
