"""Self-contained HTML incident report (chosen output format).

One file per incident, no external assets or network requests, safe to email
or archive. Contains: incident summary, affected machines and their workflow,
timeline, likely entry point, actions taken, and the response checklist.
"""
from __future__ import annotations

import html
from datetime import datetime
from pathlib import Path

from . import incidents, scoring
from .config import Settings
from .db import Database

_CSS = """
body{font-family:'Segoe UI',Arial,sans-serif;margin:2rem auto;max-width:60rem;
     color:#1a1a2e;background:#fafafa;padding:0 1rem}
h1{border-bottom:3px solid #8b0000;padding-bottom:.4rem}
h2{margin-top:2rem;color:#8b0000}
table{border-collapse:collapse;width:100%;background:#fff;margin:.8rem 0}
th,td{border:1px solid #ccc;padding:.45rem .6rem;text-align:left;font-size:.92rem}
th{background:#f0f0f5}
.badge{display:inline-block;padding:.15rem .55rem;border-radius:.6rem;
       color:#fff;font-size:.78rem;font-weight:600}
.sev-critical{background:#8b0000}.sev-high{background:#c1440e}
.sev-medium{background:#b8860b}.sev-low{background:#4a6572}
.status-open{background:#8b0000}.status-closed{background:#2e7d32}
.meta{color:#555;font-size:.9rem}
footer{margin-top:3rem;border-top:1px solid #ccc;padding-top:.6rem;
       color:#777;font-size:.8rem}
code{background:#eee;padding:.1rem .3rem;border-radius:3px}
"""


def _e(value) -> str:
    return html.escape(str(value if value is not None else ""))


def _fmt_ts(value) -> str:
    text = str(value or "")
    return text.replace("T", " ")[:19] if text else "-"


def build_report(db: Database, settings: Settings, incident_id: int) -> str:
    inc = incidents.get(db, incident_id)
    pcs = incidents.pcs_of(db, incident_id)
    events = incidents.timeline(db, incident_id)
    signals = incidents.incident_signals(db, incident_id)
    checklist = incidents.checklist_state(db, incident_id)
    sev = _e(inc.get("severity"))
    pcs_rows = "".join(
        f"<tr><td>{_e(p['pc'])}</td><td>{_e(p['state'])}</td>"
        f"<td>{_fmt_ts(p['first_seen'])}</td><td>{_fmt_ts(p['state_ts'])}</td>"
        f"<td>{_fmt_ts(p['verified_at'])}</td>"
        f"<td>{_fmt_ts(p['recheck_until'])}</td>"
        f"<td>{'yes' if p['recheck_passed'] else 'no'}</td>"
        f"<td>{_e(p['owner'] or '-')}</td><td>{_e(p['note'] or '')}</td></tr>"
        for p in pcs) or "<tr><td colspan='9'>(none)</td></tr>"
    events_rows = "".join(
        f"<tr><td>{_fmt_ts(ev['ts'])}</td><td>{_e(ev['action'])}</td>"
        f"<td>{_e(ev['detail'])}</td><td>{_e(ev['actor'])}</td></tr>"
        for ev in events) or "<tr><td colspan='4'>(none)</td></tr>"
    signal_rows = "".join(
        f"<tr><td>{_fmt_ts(s['ts'])}</td><td>{_e(s['pc'])}</td><td>{_e(s['source_type'])}</td>"
        f"<td>{_e(s['rule_id'])}</td><td>{_e(s['category'])}</td>"
        f"<td>{_e(scoring.summarize_signal(settings, s))}</td></tr>"
        for s in signals[:300]) or "<tr><td colspan='6'>(none)</td></tr>"
    checklist_rows = "".join(
        f"<tr><td>{'&#9989;' if c['done'] else '&#9744;'}</td><td>{_e(c['item'])}</td>"
        f"<td>{_fmt_ts(c['ts'])}</td></tr>"
        for c in checklist) or "<tr><td colspan='3'>(no checklist)</td></tr>"
    generated = datetime.now().strftime("%Y-%m-%d %H:%M")
    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<title>Incident report {_e(inc['incident_key'])}</title>
<style>{_CSS}</style></head><body>
<h1>Incident report: {_e(inc['incident_key'])}</h1>
<p class="meta">Generated {generated} by Endpoint Threat Detection &amp; Incident Tracker
 (v{_e(settings.version)}) &mdash; defensive tool, read-only data.</p>

<h2>Summary</h2>
<table>
<tr><th>Incident key</th><td>{_e(inc['incident_key'])}</td></tr>
<tr><th>Title</th><td>{_e(inc['title'])}</td></tr>
<tr><th>Type</th><td>{_e(inc['type'])} (source: {_e(inc['type_source'])})</td></tr>
<tr><th>Status</th><td><span class="badge status-{_e(inc['status'])}">{_e(inc['status'])}</span></td></tr>
<tr><th>Severity</th><td><span class="badge sev-{sev}">{sev}</span></td></tr>
<tr><th>Opened</th><td>{_fmt_ts(inc['created_at'])}</td></tr>
<tr><th>Closed</th><td>{_fmt_ts(inc['closed_at'])}</td></tr>
<tr><th>Reimaged</th><td>{'yes' if inc.get('reimaged') else 'no / not recorded'}</td></tr>
<tr><th>Likely entry point</th><td>{_e(inc.get('entry_point') or 'not yet determined')}</td></tr>
<tr><th>Actions taken</th><td>{_e(inc.get('containment_actions') or '-')}</td></tr>
</table>

<h2>Affected machines ({len(pcs)})</h2>
<table><tr><th>PC</th><th>Workflow state</th><th>First seen</th><th>State changed</th>
<th>Verified</th><th>Re-check until</th><th>Re-check passed</th><th>Owner</th><th>Notes</th></tr>
{pcs_rows}</table>

<h2>Response checklist</h2>
<table><tr><th>Done</th><th>Step</th><th>Changed</th></tr>{checklist_rows}</table>

<h2>Likely entry point &amp; assessment</h2>
<p>{_e(inc.get('entry_point') or 'Not yet determined by an analyst.')}</p>

<h2>Timeline ({len(events)} events)</h2>
<table><tr><th>Time</th><th>Action</th><th>Detail</th><th>Actor</th></tr>{events_rows}</table>

<h2>Signals ({len(signals)})</h2>
<table><tr><th>Time</th><th>PC</th><th>Source</th><th>Rule</th><th>Category</th><th>Evidence</th></tr>
{signal_rows}</table>

<footer>Endpoint Threat Detection &amp; Incident Tracker &mdash; internal defensive
security tool. Contains metadata only (hostnames, process names, domains, timestamps).
No credentials or user content. {_e(inc['incident_key'])} @ {_e(generated)}</footer>
</body></html>"""


def write_report(db: Database, settings: Settings, incident_id: int) -> Path:
    reports_dir = settings.reports_dir
    reports_dir.mkdir(parents=True, exist_ok=True)
    key = db.one("SELECT incident_key FROM incidents WHERE id=?", (incident_id,))
    incident_key = key["incident_key"] if key else f"INC-{incident_id}"
    name = f"{incident_key}.html"
    path = reports_dir / name
    path.write_text(build_report(db, settings, incident_id), encoding="utf-8")
    return path
