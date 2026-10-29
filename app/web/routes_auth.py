"""Login / logout routes."""
from __future__ import annotations

import os

from fastapi import APIRouter, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from .. import auth
from . import templates

router = APIRouter()


def _login_context(request: Request, error: str | None = None) -> dict:
    """Template context for login.html, shared by every render of it.

    install.ps1 writes a chosen or generated password into .env, so on almost
    every real install "admin / admin1234" is WRONG: a new admin who trusts it
    fails login, and five failures lock the real admin out for five minutes.
    Advertise the default only while it is genuinely active (the bootstrap in
    app.main reads the same variable); otherwise point at where the password
    actually lives.
    """
    ctx = {
        "request": request,
        "bootstrap_default":
            os.environ.get("TRACKER_ADMIN_PASSWORD", "admin1234") == "admin1234",
    }
    if error is not None:
        ctx["error"] = error
    return ctx


@router.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    return templates.TemplateResponse("login.html", _login_context(request))


@router.post("/login")
# Deliberately sync: authenticate() runs PBKDF2 (~0.4s at 600k iterations)
# and hits SQLite. As an async def it would block the event loop for the
# whole computation - /health and the dashboard would stall behind every
# login attempt - so FastAPI runs it in its threadpool instead.
def login(request: Request, username: str = Form(...), password: str = Form(...)):
    db = request.app.state.db
    settings = request.app.state.settings
    client_ip = request.client.host if request.client else ""
    try:
        user = auth.authenticate(db, username, password, client_ip,
                                 settings=settings)
    except HTTPException as exc:
        # The rate limiter's 429 is the only expected HTTPException; render
        # the login page with its (safe, operator-written) detail. Anything
        # else - a DB failure, a config error - must propagate to the global
        # handler: str(exc) here echoed internal exception text (file paths,
        # SQL state) back to an anonymous client AND never logged it, so the
        # failure left no trace in tracker.log.
        return templates.TemplateResponse(
            "login.html",
            _login_context(request, str(exc.detail)),
            status_code=exc.status_code)
    if user is None:
        return templates.TemplateResponse(
            "login.html",
            _login_context(request, "Invalid username or password."),
            status_code=401)
    token = auth.create_session(db, settings, user["username"], user["role"])
    response = RedirectResponse("/", status_code=303)
    response.set_cookie(
        auth.SESSION_COOKIE, token,
        httponly=True, samesite="lax",
        secure=str(request.url.scheme) == "https",
        max_age=auth.SESSION_TTL_HOURS * 3600)
    return response


@router.post("/logout")
async def logout(request: Request):
    db = request.app.state.db
    auth.destroy_session(db, request.cookies.get(auth.SESSION_COOKIE))
    response = RedirectResponse("/login", status_code=303)
    response.delete_cookie(auth.SESSION_COOKIE)
    return response
