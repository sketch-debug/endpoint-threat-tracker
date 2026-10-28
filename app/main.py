"""FastAPI application: middleware, scheduler wiring, bootstrap, entry point.

Run with:  python -m app.main   (or start.bat on Windows)
"""
from __future__ import annotations

import logging
import os
from contextlib import asynccontextmanager
from logging.handlers import RotatingFileHandler
from threading import Thread

from apscheduler.schedulers.background import BackgroundScheduler
from fastapi import FastAPI, Request
from fastapi.responses import RedirectResponse

from . import alerts as alerts_mod
from . import auth, detect, errors as errors_mod, recheck as recheck_mod
from . import health as health_mod
from . import retention as retention_mod
from .config import Settings
from .db import Database
from .feed_updater import update_all
from .indicators import Indicators
from .ingest import Ingestor
from .web import install_routes

log = logging.getLogger("tracker")


def setup_logging(settings: Settings) -> None:
    settings.ensure_dirs()
    errors_mod.install_record_redaction()
    fmt = logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s")
    redact = errors_mod.RedactSecretsFilter()
    root = logging.getLogger()
    root.setLevel(logging.INFO)
    stream = logging.StreamHandler()
    stream.setFormatter(fmt)
    stream.addFilter(redact)
    root.addHandler(stream)
    file_handler = RotatingFileHandler(
        settings.log_dir / "tracker.log", maxBytes=5 * 1024 * 1024,
        backupCount=5, encoding="utf-8")
    file_handler.setFormatter(fmt)
    file_handler.addFilter(redact)
    root.addHandler(file_handler)
    logging.getLogger("apscheduler").setLevel(logging.WARNING)


def background_feed_update(settings: Settings, db: Database) -> None:
    """Run the startup feed update off the request/startup path.

    On an isolated network every feed URL can stall for its request timeout;
    doing this synchronously in create_app delayed (or, before the server
    binds, blocked) startup by up to that much per configured feed.
    """
    try:
        import time
        marker = settings.base_dir / "data" / "last_feed_update.txt"
        should_update = True
        if marker.is_file():
            try:
                last = int(marker.read_text(encoding="utf-8").strip())
                days = settings.app.get("feeds_update", {}).get("interval_days", 7)
                if time.time() - last < days * 86400:
                    should_update = False
            except Exception:  # noqa: BLE001 - unreadable marker -> just update
                pass
        if not should_update:
            return
        log.info("running scheduled feed update…")
        res = update_all(settings, db, actor="system")
        log.info("feed update results: %s", res)
    except Exception as exc:  # noqa: BLE001 - feeds are best-effort at startup
        log.warning("feed update check failed: %s", exc)


def build_scheduler(settings: Settings, *, ingest_fn, recheck_fn, sessions_fn,
                    alert_flush_fn, retention_fn, heartbeat_fn) -> BackgroundScheduler:
    """All periodic jobs in one testable place.

    Fixed UTC timezone (a wall-clock/TZ change while running cannot break
    scheduling) and coalesce+misfire grace on every job so missed runs
    (sleep/reboot) collapse into one instead of replaying back-to-back.
    """
    scheduler = BackgroundScheduler(timezone="UTC")
    scheduler.add_job(
        ingest_fn, "interval", seconds=max(5, settings.poll_seconds),
        id="ingest", max_instances=1, coalesce=True, misfire_grace_time=30)
    scheduler.add_job(
        recheck_fn, "interval", hours=1, id="recheck", max_instances=1,
        coalesce=True, misfire_grace_time=300)
    scheduler.add_job(
        sessions_fn, "interval", hours=6, id="sessions", max_instances=1,
        coalesce=True, misfire_grace_time=300)
    scheduler.add_job(
        alert_flush_fn, "interval", seconds=60, id="alert_flush",
        max_instances=1, coalesce=True, misfire_grace_time=60)
    scheduler.add_job(
        retention_fn, "interval", hours=24, id="retention",
        max_instances=1, coalesce=True, misfire_grace_time=3600)
    scheduler.add_job(
        heartbeat_fn, "interval", minutes=15, id="heartbeat",
        max_instances=1, coalesce=True, misfire_grace_time=120)
    return scheduler


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
    if settings.host not in ("127.0.0.1", "::1", "localhost"):
        # off-loopback means login, /health and every session cookie travel
        # over plain HTTP to that network - say so out loud instead of
        # binding silently
        log.warning(
            "server.host=%s exposes the dashboard (login, /health, cookies) "
            "over plain HTTP to that network. Restrict it with "
            "scripts/Set-FirewallRule.ps1 or front it with a TLS proxy.",
            settings.host)
    db = Database(db_path or settings.db_path)
    indicators = Indicators(settings.config_dir)
    detector = detect.Detector(db, settings, indicators)
    ingestor = Ingestor(db, settings, indicators, detector=detector)
    bootstrap_admin(db, settings)
    # Startup feed update runs in background_feed_update() from the lifespan
    # below - never inline here, where unreachable feed URLs would delay
    # (or block) app creation on an isolated network.

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        # feeds first (background thread): on a no-internet server each URL
        # can stall its request timeout without delaying serving
        feed_thread = Thread(
            target=background_feed_update,
            args=(settings, app.state.db),
            daemon=True, name="feed-update")
        feed_thread.start()
        scheduler = build_scheduler(
            settings,
            ingest_fn=lambda: detect.run_cycle(app.state.ingestor, app.state.detector),
            recheck_fn=lambda: recheck_mod.run_recheck_sweep(app.state.db,
                                                             app.state.settings),
            sessions_fn=lambda: auth.purge_expired(app.state.db),
            alert_flush_fn=lambda: alerts_mod.flush_pending_alerts(
                app.state.db, app.state.settings),
            retention_fn=lambda: retention_mod.run_retention(
                app.state.db, app.state.settings),
            heartbeat_fn=lambda: health_mod.run_heartbeat(
                app.state.db, app.state.settings),
        )
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
        # Every branch below must fall through to apply_security_headers:
        # an early return meant 401/303/204 responses shipped with no
        # headers, and the 500 page (handled outside this middleware) with
        # none either - see install_error_handlers in errors.py.
        if path == "/favicon.ico":
            from fastapi.responses import Response
            response = Response(status_code=204)
        elif request.state.user is None and path not in ("/login", "/health") \
                and not path.startswith("/static"):
            if path.startswith("/api/"):
                # JSON callers get 401 JSON, not a 303 to the HTML login page
                from fastapi.responses import JSONResponse
                response = JSONResponse({"detail": "login required"},
                                        status_code=401)
            else:
                response = RedirectResponse("/login", status_code=303)
        elif request.state.user is not None and path == "/login":
            response = RedirectResponse("/", status_code=303)
        else:
            response = await call_next(request)
        errors_mod.apply_security_headers(response)
        return response

    install_routes(app, settings, db)
    errors_mod.install_error_handlers(app)
    return app


def main() -> None:
    settings = Settings()
    app = create_app(settings)
    import uvicorn
    uvicorn.run(app, host=settings.host, port=settings.port, log_level="info")


if __name__ == "__main__":
    main()
