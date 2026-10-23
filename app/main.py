"""FastAPI application: middleware, scheduler wiring, bootstrap, entry point.

Run with:  python -m app.main   (or start.bat on Windows)
"""
from __future__ import annotations

import logging
import os
from contextlib import asynccontextmanager
from logging.handlers import RotatingFileHandler

from apscheduler.schedulers.background import BackgroundScheduler
from fastapi import FastAPI, Request
from fastapi.responses import RedirectResponse

from . import auth, detect, recheck as recheck_mod
from .config import Settings
from .db import Database
from .indicators import Indicators
from .ingest import Ingestor
from .web import install_routes

log = logging.getLogger("tracker")


def setup_logging(settings: Settings) -> None:
    settings.ensure_dirs()
    fmt = logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s")
    root = logging.getLogger()
    root.setLevel(logging.INFO)
    stream = logging.StreamHandler()
    stream.setFormatter(fmt)
    root.addHandler(stream)
    file_handler = RotatingFileHandler(
        settings.log_dir / "tracker.log", maxBytes=5 * 1024 * 1024,
        backupCount=5, encoding="utf-8")
    file_handler.setFormatter(fmt)
    root.addHandler(file_handler)
    logging.getLogger("apscheduler").setLevel(logging.WARNING)


def bootstrap_admin(db: Database, settings: Settings) -> None:
    """Create the first admin account when the user table is empty."""
    row = db.one("SELECT COUNT(*) AS n FROM users")
    if row and int(row["n"]) > 0:
        return
    password = os.environ.get("TRACKER_ADMIN_PASSWORD", "admin1234")
    auth.create_user(db, "admin", password, "admin", actor="system")
    log.warning("bootstrap: created user 'admin' with the %s password. "
                "CHANGE IT on the Users page immediately.",
                "configured TRACKER_ADMIN_PASSWORD"
                if os.environ.get("TRACKER_ADMIN_PASSWORD") else "DEFAULT")


def create_app(settings: Settings | None = None,
               db_path: str | None = None) -> FastAPI:
    settings = settings or Settings()
    setup_logging(settings)
    db = Database(db_path or settings.db_path)
    indicators = Indicators(settings.config_dir)
    detector = detect.Detector(db, settings, indicators)
    ingestor = Ingestor(db, settings, indicators, detector=detector)
    bootstrap_admin(db, settings)

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        scheduler = BackgroundScheduler(timezone=None)
        scheduler.add_job(
            lambda: detect.run_cycle(app.state.ingestor, app.state.detector),
            "interval", seconds=max(5, settings.poll_seconds),
            id="ingest", max_instances=1, coalesce=True)
        scheduler.add_job(
            lambda: recheck_mod.run_recheck_sweep(app.state.db, app.state.settings),
            "interval", hours=1, id="recheck", max_instances=1)
        scheduler.add_job(
            lambda: auth.purge_expired(app.state.db),
            "interval", hours=6, id="sessions", max_instances=1)
        scheduler.start()
        log.info("scheduler started (ingest every %ss, recheck hourly)",
                 settings.poll_seconds)
        try:
            yield
        finally:
            scheduler.shutdown(wait=False)
            log.info("scheduler stopped")

    app = FastAPI(title="Endpoint Threat Detection & Incident Tracker",
                  version=settings.version, lifespan=lifespan, docs_url=None,
                  redoc_url=None)
    app.state.settings = settings
    app.state.db = db
    app.state.indicators = indicators
    app.state.detector = detector
    app.state.ingestor = ingestor

    @app.middleware("http")
    async def session_middleware(request: Request, call_next):
        cookie = request.cookies.get(auth.SESSION_COOKIE)
        request.state.user = auth.resolve_session(db, settings, cookie)
        path = request.url.path
        if path == "/favicon.ico":
            from fastapi.responses import Response
            return Response(status_code=204)
        if request.state.user is None and path not in ("/login",) \
                and not path.startswith("/static"):
            return RedirectResponse("/login", status_code=303)
        if request.state.user is not None and path == "/login":
            return RedirectResponse("/", status_code=303)
        return await call_next(request)

    install_routes(app, settings, db)
    return app


def main() -> None:
    settings = Settings()
    app = create_app(settings)
    import uvicorn
    uvicorn.run(app, host=settings.host, port=settings.port, log_level="info")


if __name__ == "__main__":
    main()
