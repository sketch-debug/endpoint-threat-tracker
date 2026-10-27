"""Web layer: server-rendered dashboard (Jinja2) + small JSON API."""
from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles
from starlette.templating import Jinja2Templates

from ..config import Settings
from ..db import Database

TEMPLATE_DIR = Path(__file__).parent / "templates"
STATIC_DIR = Path(__file__).parent / "static"


def _global_context(request: Request) -> dict:
    settings = getattr(request.app.state, "settings", None)
    health = None
    try:
        if settings is not None and hasattr(request.app.state, "db"):
            from ..health import health_payload
            health = health_payload(request.app.state.db, settings)
    except Exception:  # noqa: BLE001 - a broken banner must never break a page
        health = None
    return {
        "user": getattr(request.state, "user", None),
        "version": getattr(settings, "version", "") if settings else "",
        "msg": request.query_params.get("msg", ""),
        "err": request.query_params.get("err", ""),
        "health": health,
    }


templates = Jinja2Templates(directory=str(TEMPLATE_DIR),
                            context_processors=[_global_context])


def install_routes(app: FastAPI, settings: Settings, db: Database) -> None:
    app.state.settings = settings
    app.state.db = db
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")
    from . import (routes_auth, routes_config, routes_dashboard, routes_health,
                    routes_incidents, routes_settings)
    app.include_router(routes_auth.router)
    app.include_router(routes_health.router)
    app.include_router(routes_dashboard.router)
    app.include_router(routes_incidents.router)
    app.include_router(routes_config.router)
    app.include_router(routes_settings.router)
