"""/health - public self-monitoring endpoint (no login; bind is 127.0.0.1)."""
from __future__ import annotations

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from ..health import health_payload

router = APIRouter()


@router.get("/health")
async def health(request: Request):
    settings = request.app.state.settings
    db = request.app.state.db
    payload = health_payload(db, settings)
    status = 200 if payload["status"] == "ok" else 503
    return JSONResponse(payload, status_code=status)
