"""Login / logout routes."""
from __future__ import annotations

from fastapi import APIRouter, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from .. import auth
from . import templates

router = APIRouter()


@router.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})


@router.post("/login")
async def login(request: Request, username: str = Form(...), password: str = Form(...)):
    db = request.app.state.db
    settings = request.app.state.settings
    client_ip = request.client.host if request.client else ""
    try:
        user = auth.authenticate(db, username, password, client_ip)
    except Exception as exc:  # HTTPException(429) from rate limiter
        status = getattr(exc, "status_code", 500)
        return templates.TemplateResponse("login.html", {
            "request": request,
            "error": str(getattr(exc, "detail", exc)),
        }, status_code=status)
    if user is None:
        return templates.TemplateResponse("login.html", {
            "request": request,
            "error": "Invalid username or password.",
        }, status_code=401)
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
