"""Incident list, detail, workflow, analyst edits, and report routes."""
from __future__ import annotations

from fastapi import APIRouter, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response

from .. import audit as audit_mod
from .. import auth, incidents, report, scoring
from . import templates

router = APIRouter()


def _require(request: Request, minimum: str) -> dict:
    user = getattr(request.state, "user", None)
    if not user:
        raise HTTPException(status_code=401, detail="login required")
    if not auth.role_allows(user, minimum):
        raise HTTPException(status_code=403, detail=f"role {minimum} or higher required")
    return user


def _redirect(path: str, msg: str = "", err: str = "") -> RedirectResponse:
    from urllib.parse import urlencode
    params = {k: v for k, v in (("msg", msg), ("err", err)) if v}
    target = f"{path}?{urlencode(params)}" if params else path
    return RedirectResponse(target, status_code=303)


@router.get("/incidents", response_class=HTMLResponse)
async def incidents_page(request: Request, status: str = "", severity: str = "",
                         itype: str = ""):
    _require(request, "viewer")
    db = request.app.state.db
    rows = incidents.list_incidents(db, status or None, severity or None, itype or None)
    inc_list = []
    for row in rows:
        item = dict(row)
        item["pcs"] = [r["pc"] for r in db.query(
            "SELECT pc FROM incident_pcs WHERE incident_id=? ORDER BY pc", (row["id"],))]
        inc_list.append(item)
    return templates.TemplateResponse("incidents.html", {
        "request": request, "incidents": inc_list, "status": status, "severity": severity,
        "itype": itype, "types": list(request.app.state.settings.types),
    })


@router.get("/incidents/{incident_id}", response_class=HTMLResponse)
async def incident_detail(request: Request, incident_id: int):
    _require(request, "viewer")
    db = request.app.state.db
    settings = request.app.state.settings
    try:
        inc = incidents.get(db, incident_id)
    except LookupError:
        raise HTTPException(status_code=404, detail="incident not found") from None
    return templates.TemplateResponse("incident.html", {
        "request": request, "inc": inc,
        "pcs": incidents.pcs_of(db, incident_id),
        "events": incidents.timeline(db, incident_id),
        "signals": incidents.incident_signals(db, incident_id),
        "checklist": incidents.checklist_state(db, incident_id),
        "types": list(settings.types),
        "states": incidents.PC_STATES,
        "recheck_days": settings.recheck_days,
        "summarize": lambda s: scoring.summarize_signal(settings, s),
    })


@router.post("/incidents/{incident_id}/entry-point")
async def set_entry_point(request: Request, incident_id: int,
                          entry_point: str = Form("")):
    user = _require(request, "analyst")
    incidents.set_entry_point(request.app.state.db, incident_id, entry_point,
                              actor=user["username"])
    return _redirect(f"/incidents/{incident_id}", msg="Entry point saved.")


@router.post("/incidents/{incident_id}/actions")
async def set_actions(request: Request, incident_id: int,
                      containment_actions: str = Form("")):
    user = _require(request, "analyst")
    incidents.set_actions(request.app.state.db, incident_id, containment_actions,
                          actor=user["username"])
    return _redirect(f"/incidents/{incident_id}", msg="Actions saved.")


@router.post("/incidents/{incident_id}/type")
async def set_type(request: Request, incident_id: int, itype: str = Form(...)):
    user = _require(request, "analyst")
    try:
        incidents.set_type(request.app.state.db, request.app.state.settings,
                           incident_id, itype, actor=user["username"])
    except ValueError as exc:
        return _redirect(f"/incidents/{incident_id}", err=str(exc))
    return _redirect(f"/incidents/{incident_id}",
                     msg=f"Type set to {itype} (analyst override).")


@router.post("/incidents/{incident_id}/reimaged")
async def set_reimaged(request: Request, incident_id: int, reimaged: str = Form(...)):
    user = _require(request, "analyst")
    incidents.set_reimaged(request.app.state.db, incident_id,
                           reimaged == "1", actor=user["username"])
    return _redirect(f"/incidents/{incident_id}", msg="Reimaged flag updated.")


@router.post("/incidents/{incident_id}/checklist")
async def toggle_checklist(request: Request, incident_id: int, item: str = Form(...),
                           done: str = Form("0")):
    user = _require(request, "analyst")
    incidents.toggle_checklist(request.app.state.db, incident_id, item,
                               done == "1", actor=user["username"])
    return _redirect(f"/incidents/{incident_id}")


@router.post("/incidents/{incident_id}/pc/{pc}/transition")
async def transition_pc(request: Request, incident_id: int, pc: str,
                        new_state: str = Form(...), note: str = Form(""),
                        owner: str = Form("")):
    user = _require(request, "analyst")
    try:
        incidents.transition_pc(request.app.state.db, request.app.state.settings,
                                incident_id, pc, new_state, actor=user["username"],
                                note=note, owner=owner)
    except (ValueError, LookupError) as exc:
        return _redirect(f"/incidents/{incident_id}", err=str(exc))
    return _redirect(f"/incidents/{incident_id}",
                     msg=f"{pc} -> {new_state}.")


@router.post("/incidents/{incident_id}/close")
async def close_incident(request: Request, incident_id: int, note: str = Form("")):
    user = _require(request, "analyst")
    from .. import alerts
    db = request.app.state.db
    settings = request.app.state.settings
    inc = incidents.close_incident(db, settings, incident_id, actor=user["username"],
                                   note=note or "closed by analyst")
    alerts.notify(db, settings, inc, "recovered",
                  f"Incident closed by {user['username']}: {note or 'no note'}",
                  actor=user["username"])
    return _redirect(f"/incidents/{incident_id}", msg="Incident closed.")


@router.post("/incidents/{incident_id}/reopen")
async def reopen_incident(request: Request, incident_id: int, reason: str = Form("")):
    user = _require(request, "analyst")
    from .. import alerts
    db = request.app.state.db
    settings = request.app.state.settings
    inc = incidents.reopen_incident(db, settings, incident_id, actor=user["username"],
                                    reason=reason or "reopened by analyst")
    alerts.notify(db, settings, inc, "reopened",
                  f"Incident reopened by {user['username']}: {reason or 'no reason'}",
                  actor=user["username"])
    return _redirect(f"/incidents/{incident_id}", msg="Incident reopened.")


@router.get("/incidents/{incident_id}/report")
async def incident_report(request: Request, incident_id: int):
    _require(request, "viewer")
    db = request.app.state.db
    settings = request.app.state.settings
    if not db.one("SELECT id FROM incidents WHERE id=?", (incident_id,)):
        raise HTTPException(status_code=404, detail="incident not found")
    try:
        incidents.get(db, incident_id)
    except LookupError:
        raise HTTPException(status_code=404, detail="incident not found") from None
    html_text = report.build_report(db, settings, incident_id)
    audit_mod.audit(db, (getattr(request.state, "user", None) or {}).get(
        "username", "unknown"), "report_view", str(incident_id), "html")
    return Response(content=html_text, media_type="text/html; charset=utf-8")


@router.get("/incidents/{incident_id}/report/download")
async def incident_report_download(request: Request, incident_id: int):
    user = _require(request, "viewer")
    db = request.app.state.db
    settings = request.app.state.settings
    try:
        incidents.get(db, incident_id)
    except LookupError:
        raise HTTPException(status_code=404, detail="incident not found") from None
    path = report.write_report(db, settings, incident_id)
    audit_mod.audit(db, user["username"], "report_download", str(incident_id), path.name)
    return Response(content=path.read_text(encoding="utf-8"),
                    media_type="text/html; charset=utf-8",
                    headers={"Content-Disposition":
                             f'attachment; filename="{path.name}"'})
