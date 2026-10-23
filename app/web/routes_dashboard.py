"""Dashboard, PC inventory/timeline, audit log, and manual run routes."""
from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse

from .. import audit as audit_mod
from .. import auth, detect, scoring
from ..normalize import now_iso
from . import templates

router = APIRouter()


def _require(request: Request, minimum: str) -> dict:
    user = getattr(request.state, "user", None)
    if not user:
        raise HTTPException(status_code=401, detail="login required")
    if not auth.role_allows(user, minimum):
        raise HTTPException(status_code=403, detail=f"role {minimum} or higher required")
    return user


@router.get("/", response_class=HTMLResponse)
async def dashboard(request: Request):
    _require(request, "viewer")
    db = request.app.state.db
    settings = request.app.state.settings
    open_incidents = db.query(
        "SELECT * FROM incidents WHERE status='open' ORDER BY "
        "CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 "
        "ELSE 3 END, id DESC")
    for idx, inc in enumerate(open_incidents):
        item = dict(inc)
        item["pcs"] = [r["pc"] for r in db.query(
            "SELECT pc FROM incident_pcs WHERE incident_id=? ORDER BY pc", (inc["id"],))]
        open_incidents[idx] = item
    def count(sql: str, params: tuple = ()) -> int:
        row = db.one(sql, params)
        return int(row["n"]) if row else 0

    counts = {
        "open": len(open_incidents),
        "critical": sum(1 for i in open_incidents if i["severity"] == "critical"),
        "high": sum(1 for i in open_incidents if i["severity"] == "high"),
        "pcs_active": len({pc for i in open_incidents for pc in i["pcs"]}),
        "signals_24h": count("SELECT COUNT(*) AS n FROM signals WHERE ts >= ?",
                             (now_iso()[:10],)),
        "closed_total": count("SELECT COUNT(*) AS n FROM incidents WHERE status='closed'"),
    }
    rechecking = db.query(
        "SELECT ip.pc, ip.recheck_until, ip.incident_id, i.incident_key, i.severity "
        "FROM incident_pcs ip JOIN incidents i ON i.id=ip.incident_id "
        "WHERE ip.state='verified' AND ip.recheck_until IS NOT NULL AND i.status='open' "
        "ORDER BY ip.recheck_until")
    last_file = db.one("SELECT filename, ingested_at AS received_at, record_count "
                       "FROM files ORDER BY id DESC LIMIT 1")
    recent_signals = db.query(
        "SELECT * FROM signals WHERE incident_id IS NOT NULL ORDER BY id DESC LIMIT 12")
    return templates.TemplateResponse("dashboard.html", {
        "request": request, "counts": counts, "incidents": open_incidents,
        "rechecking": rechecking, "last_file": last_file, "recent_signals": recent_signals,
        "chart": scoring.history_7d(db),
    })


@router.get("/api/status")
async def api_status(request: Request):
    _require(request, "viewer")
    db = request.app.state.db

    def count(sql: str) -> int:
        row = db.one(sql)
        return int(row["n"]) if row else 0

    last = db.one("SELECT ingested_at FROM files ORDER BY id DESC LIMIT 1")
    return JSONResponse({
        "now": now_iso(),
        "open_incidents": count("SELECT COUNT(*) AS n FROM incidents WHERE status='open'"),
        "signals_total": count("SELECT COUNT(*) AS n FROM signals"),
        "last_ingest": last["ingested_at"] if last else None,
    })


@router.get("/api/chart7")
async def api_chart7(request: Request):
    _require(request, "viewer")
    return JSONResponse(scoring.history_7d(request.app.state.db))


@router.get("/pcs", response_class=HTMLResponse)
async def pcs_page(request: Request):
    _require(request, "viewer")
    db = request.app.state.db
    rows = db.query("""
        SELECT s.pc AS pc, COUNT(*) AS signals,
               SUM(CASE WHEN s.incident_id IS NOT NULL THEN 1 ELSE 0 END) AS in_incidents,
               MAX(s.ts) AS last_seen
        FROM signals s GROUP BY s.pc ORDER BY signals DESC LIMIT 500""")
    pcs = []
    for row in rows:
        item = dict(row)
        score = scoring.score_pc(db, request.app.state.settings, item["pc"]) or {}
        item["score"] = score.get("score", 0)
        item["severity"] = score.get("severity") or "low"
        pcs.append(item)
    return templates.TemplateResponse("pcs.html", {"request": request, "pcs": pcs})


@router.get("/pcs/{pc}", response_class=HTMLResponse)
async def pc_detail(request: Request, pc: str):
    _require(request, "viewer")
    db = request.app.state.db
    settings = request.app.state.settings
    score = scoring.score_pc(db, settings, pc) or {"score": 0, "severity": "low",
                                                   "signals": [], "rules": [], "categories": []}
    pc_signals = db.query("SELECT * FROM signals WHERE pc=? ORDER BY ts DESC LIMIT 300", (pc,))
    pc_incidents = db.query(
        "SELECT i.*, ip.state, ip.first_seen, ip.state_ts, ip.owner, ip.note "
        "FROM incidents i JOIN incident_pcs ip ON ip.incident_id=i.id "
        "WHERE ip.pc=? ORDER BY i.id DESC", (pc,))
    return templates.TemplateResponse("pc.html", {
        "request": request, "pc": pc, "score": score, "signals": pc_signals,
        "incidents": pc_incidents,
    })


@router.get("/audit", response_class=HTMLResponse)
async def audit_page(request: Request, limit: int = 200):
    _require(request, "analyst")
    db = request.app.state.db
    entries = audit_mod.recent(db, min(int(limit), 1000))
    return templates.TemplateResponse("audit.html", {"request": request, "entries": entries})


@router.post("/run/ingest")
async def run_ingest(request: Request):
    user = _require(request, "analyst")
    stats = detect.run_cycle(request.app.state.ingestor, request.app.state.detector)
    audit_mod.audit(request.app.state.db, user["username"], "ingest_manual", "",
                    str(stats))
    return RedirectResponse(f"/?msg=Ingest complete: {stats}", status_code=303)


@router.post("/run/recheck")
async def run_recheck(request: Request):
    user = _require(request, "analyst")
    from .. import recheck as recheck_mod
    result = recheck_mod.run_recheck_sweep(request.app.state.db,
                                           request.app.state.settings)
    return RedirectResponse(f"/?msg=Re-check sweep: {result}", status_code=303)
