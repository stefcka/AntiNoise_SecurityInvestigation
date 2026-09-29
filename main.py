"""Web dashboard. Run with:  uvicorn app.main:app --reload

Server-rendered HTML forms only: no JavaScript build, no frontend framework.
"""
import json
from datetime import datetime, timezone
from urllib.parse import quote

from fastapi import FastAPI, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from . import config, ledger, pipeline, store
from .adapters import SOURCE_LABELS
from .ai import investigator, llm
from .detection.rules import RULES_BY_ID
from .response import catalog, executor

app = FastAPI(title="Cloud Threat Detection & Investigation Platform")
app.mount("/static", StaticFiles(directory=config.BASE_DIR / "app" / "static"), name="static")
templates = Jinja2Templates(directory=config.BASE_DIR / "app" / "templates")
templates.env.filters["tojson_pretty"] = lambda v: json.dumps(v, indent=2, default=str)
templates.env.filters["short_time"] = lambda s: (s or "").replace("T", " ").replace("Z", " UTC")

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
CONTAINING = {"REVOKE_OAUTH_GRANT", "DISABLE_APPLICATION", "REVOKE_USER_SESSIONS", "DISABLE_USER", "ISOLATE_VM"}


def incident_status(incident_id: str) -> str:
    if store.list_kind("disposition", incident_id):
        return "False positive"
    acts = store.list_kind("action", incident_id)
    approved = [a for a in acts if a["decision"] == "APPROVED"]
    if any(a["action_type"] in CONTAINING and a["mode"] == "LIVE" and a["status"] in ("SUCCEEDED", "ACCEPTED_UNVERIFIED")
           for a in approved):
        return "Contained"
    if any(a["action_type"] in CONTAINING and a["status"] == "SIMULATED" for a in approved):
        return "Contained (simulated)"
    if any(a["action_type"] == "ESCALATE_INCIDENT" for a in approved):
        return "Escalated"
    if any(a["status"] == "FAILED" for a in approved):
        return "Action failed"
    if any(a["action_type"] == "NO_ACTION" for a in approved):
        return "Closed, no action"
    if acts:
        return "Open, recommendation rejected"
    return "Open"


def _segments(reasons: list[dict], cap: int = 100) -> list[dict]:
    """Turn score reasons into widths for the contribution bar."""
    out, used = [], 0
    for r in reasons:
        pts = r["points"]
        if pts <= 0:
            continue
        width = max(0, min(pts, cap - used))
        out.append({"factor": r["factor"], "points": pts, "width": width, "capped": width < pts})
        used += width
    return out


def _redirect(path: str, msg: str = "") -> RedirectResponse:
    return RedirectResponse(path + (f"?msg={quote(msg)}" if msg else ""), status_code=303)


# ---------------------------------------------------------------- pages
@app.get("/", response_class=HTMLResponse)
def index(request: Request, msg: str = ""):
    incidents = store.list_kind("incident")
    rows = []
    for inc in incidents:
        rows.append({**inc, "status": incident_status(inc["incident_id"]),
                     "ai_pending": pipeline.is_pending(inc["incident_id"])})
    rows.sort(key=lambda r: (r["status"] in ("False positive", "Contained", "Closed, no action"),
                             SEVERITY_ORDER[r["severity"]["level"]], -r["confidence"]["score"]))
    return templates.TemplateResponse(request, "index.html", {
        "incidents": rows, "msg": msg, "collector_ready": config.collector_configured(),
        "llm_status": llm.status(), "ai_queue": pipeline.queue_length(),
        "live_actions": sorted(config.LIVE_ACTIONS),
        "responder_ready": config.responder_configured()})


@app.get("/incidents/{incident_id}", response_class=HTMLResponse)
def incident_page(request: Request, incident_id: str, msg: str = ""):
    inc = store.get("incident", incident_id)
    if not inc:
        raise HTTPException(404, "Incident not found")
    _, events, signals = pipeline.incident_bundle(incident_id)
    assessments = list(reversed(store.list_kind("ai_assessment", incident_id)))
    return templates.TemplateResponse(request, "incident.html", {
        "inc": inc, "status": incident_status(incident_id), "msg": msg,
        "events": {e["event_id"]: e for e in events}, "signals": signals,
        "record_order": [e["event_id"] for e in sorted(events, key=lambda e: e["timestamp"])],
        "rules": RULES_BY_ID, "source_labels": SOURCE_LABELS,
        "sev_segments": _segments(inc["severity"]["reasons"]),
        "conf_segments": _segments(inc["confidence"]["reasons"]),
        "assessment": assessments[0] if assessments else None, "older_assessments": assessments[1:],
        "actions": list(reversed(store.list_kind("action", incident_id))),
        "dispositions": store.list_kind("disposition", incident_id),
        "chats": store.list_kind("chat", incident_id),
        "catalog": catalog.CATALOG, "live": {a: executor.is_live(a) for a in catalog.CATALOG},
        "llm_ready": config.llm_configured(), "analyst": config.ANALYST_NAME,
        "ai_pending": pipeline.is_pending(incident_id), "model_label": config.llm_model_label(),
        "ledger_count": len(ledger.read(incident_id))})


@app.get("/audit", response_class=HTMLResponse)
def audit_page(request: Request, incident: str = ""):
    records = ledger.read(incident or None)
    return templates.TemplateResponse(request, "audit.html", {
        "records": list(reversed(records)), "verify": ledger.verify(), "incident": incident})


# ---------------------------------------------------------------- pipeline
@app.post("/pipeline/fixtures")
def load_fixtures():
    results = pipeline.run_all_fixtures(run_ai=False)
    created = [i for r in results for i in r["incidents_created"]]
    events = sum(r["events"] for r in results)
    for incident_id in created:
        pipeline.enqueue_investigation(incident_id)
    note = " AI assessments are running in the background." if created and config.llm_configured() else ""
    return _redirect("/", f"Replayed {len(results)} sample datasets: {events} events, {len(created)} new incidents.{note}")


@app.post("/pipeline/live")
def collect_live(hours: int = Form(24)):
    if not config.collector_configured():
        return _redirect("/", "Live collection needs AZURE_TENANT_ID, COLLECTOR_CLIENT_ID and COLLECTOR_CLIENT_SECRET.")
    from .adapters import azure_live
    try:
        result = azure_live.collect(hours=hours)
    except Exception as exc:
        return _redirect("/", f"Live collection failed: {type(exc).__name__}: {str(exc)[:200]}")
    name = f"live-{datetime.now(timezone.utc):%Y%m%dT%H%M%SZ}"
    summary = pipeline.run_dataset(name, result["records"], result["directory_obj"],
                                   result["telemetry_available"], origin="live", run_ai=False)
    for incident_id in summary["incidents_created"]:
        pipeline.enqueue_investigation(incident_id)
    captures = config.DATA_DIR / "captures"
    captures.mkdir(parents=True, exist_ok=True)
    azure_live.save_capture(result, captures / f"{name}.json")
    note = f" Unavailable: {'; '.join(result['errors'])}." if result["errors"] else ""
    return _redirect("/", f"Collected {summary['events']} events, {len(summary['incidents_created'])} new incidents.{note}")


# ---------------------------------------------------------------- analyst actions
@app.post("/incidents/{incident_id}/actions")
def decide_action(incident_id: str, action_type: str = Form(...), decision: str = Form(...), note: str = Form("")):
    inc = store.get("incident", incident_id)
    if not inc:
        raise HTTPException(404)
    if decision not in ("APPROVED", "REJECTED"):
        raise HTTPException(400, "decision must be APPROVED or REJECTED")
    try:
        result = executor.decide(inc, action_type, decision, config.ANALYST_NAME, note)
    except ValueError as exc:
        return _redirect(f"/incidents/{incident_id}", str(exc))
    label = catalog.CATALOG[action_type]["label"]
    if decision == "REJECTED":
        return _redirect(f"/incidents/{incident_id}", f"Rejected: {label}.")
    if result["mode"] == "SIMULATED":
        return _redirect(f"/incidents/{incident_id}", f"{label}: simulated. No system was changed.")
    return _redirect(f"/incidents/{incident_id}", f"{label}: {result['status'].replace('_', ' ').lower()}.")


@app.post("/actions/{action_id}/restore")
def restore(action_id: str):
    original = store.get("action", action_id)
    if not original:
        raise HTTPException(404)
    try:
        res = executor.restore_vm_network(original, config.ANALYST_NAME)
    except ValueError as exc:
        return _redirect(f"/incidents/{original['incident_id']}", str(exc))
    return _redirect(f"/incidents/{original['incident_id']}", f"Restore network: {res['status'].lower()}.")


@app.post("/incidents/{incident_id}/false-positive")
def mark_false_positive(incident_id: str, reason: str = Form(...)):
    inc = store.get("incident", incident_id)
    if not inc:
        raise HTTPException(404)
    reason = reason.strip()
    if len(reason) < 10:
        return _redirect(f"/incidents/{incident_id}", "Give a reason of at least 10 characters.")
    assessments = store.list_kind("ai_assessment", incident_id)
    disp = {"disposition_id": f"disp_{incident_id}_{int(datetime.now().timestamp())}",
            "incident_id": incident_id, "disposition": "FALSE_POSITIVE", "reason": reason,
            "decided_by": config.ANALYST_NAME, "decided_at": store.now(),
            # What the system originally concluded, preserved alongside the analyst's decision.
            "original": {"title": inc["title"], "severity": inc["severity"], "confidence": inc["confidence"],
                         "matched_rules": inc["correlation"]["matched_rules"],
                         "evidence_event_ids": inc["evidence_event_ids"],
                         "ai_assessment_ids": [a["assessment_id"] for a in assessments],
                         "ai_summary": assessments[-1]["validated"]["summary"] if assessments else None,
                         "detection_version": inc["detection_version"]}}
    store.insert("disposition", disp["disposition_id"], disp, incident_id=incident_id)
    ledger.append("analyst.disposition", disp, incident_id=incident_id, actor=config.ANALYST_NAME)
    return _redirect(f"/incidents/{incident_id}", "Marked as false positive. The original detection is unchanged.")


@app.post("/incidents/{incident_id}/reinvestigate")
def reinvestigate(incident_id: str):
    if not store.get("incident", incident_id):
        raise HTTPException(404)
    pipeline.enqueue_investigation(incident_id)
    return _redirect(f"/incidents/{incident_id}", "New AI assessment queued. Earlier ones are kept.")


@app.post("/incidents/{incident_id}/ask")
def ask(incident_id: str, question: str = Form(...)):
    if not store.get("incident", incident_id):
        raise HTTPException(404)
    inc, events, signals = pipeline.incident_bundle(incident_id)
    question = question.strip()[:1000]
    if not question:
        return _redirect(f"/incidents/{incident_id}")
    history = store.list_kind("chat", incident_id)
    turn = investigator.answer_question(inc, events, signals, question, history)
    store.insert("chat", turn["chat_id"], turn, incident_id=incident_id)
    ledger.append("ai.qa", turn, incident_id=incident_id, actor=f"ai:{turn['model']}")
    return RedirectResponse(f"/incidents/{incident_id}#ask", status_code=303)


# ---------------------------------------------------------------- JSON API
@app.get("/api/incidents")
def api_incidents():
    return [{**i, "status": incident_status(i["incident_id"])} for i in store.list_kind("incident")]


@app.get("/api/incidents/{incident_id}")
def api_incident(incident_id: str):
    if not store.get("incident", incident_id):
        raise HTTPException(404)
    inc, events, signals = pipeline.incident_bundle(incident_id)
    return JSONResponse({"incident": inc, "status": incident_status(incident_id), "events": events,
                         "signals": signals, "ai_assessments": store.list_kind("ai_assessment", incident_id),
                         "actions": store.list_kind("action", incident_id),
                         "dispositions": store.list_kind("disposition", incident_id),
                         "audit": ledger.read(incident_id)})


@app.get("/api/audit/verify")
def api_verify():
    return ledger.verify()
