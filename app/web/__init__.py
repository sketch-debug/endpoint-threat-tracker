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
        "health": health,
    }


class _Templates(Jinja2Templates):
    """TemplateResponse where query-param flashes are defaults, not overrides.

    Starlette runs context processors AFTER the handler context, so the old
    processor's ?msg=/?err= entries silently overwrote whatever the handler
    passed - every direct-render flash ("settings saved", "scoring.yaml
    saved") was invisible. Query params are merged here instead, before
    rendering, with handler-passed values winning.

    It also keeps the app's legacy TemplateResponse(name, ctx-with-request)
    call shape working: Starlette 1.x only accepts (request, name, ctx), so
    the translation lives here instead of at 22 call sites.
    """

    def TemplateResponse(self, name, context, *args, **kwargs):
        if isinstance(name, str) and isinstance(context, dict):
            request = context.get("request")
            if request is not None:
                context = {
                    "msg": request.query_params.get("msg", ""),
                    "err": request.query_params.get("err", ""),
                    **context,
                }
                return super().TemplateResponse(request, name, context,
                                                *args, **kwargs)
        return super().TemplateResponse(name, context, *args, **kwargs)


templates = _Templates(directory=str(TEMPLATE_DIR),
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
