"""raw records -> normalize -> detect -> correlate -> score -> AI -> store + audit.

Fixture replay and live collection both come through run_dataset(), so the
demo exercises exactly the same code either way.

A local model can take tens of seconds per incident, so the web app creates
incidents immediately and runs AI assessments one at a time in a background
worker (enqueue_investigation). Detection never waits for the model.
"""
import threading
from collections import deque
from . import ledger, store
from .adapters import load_fixture, list_fixtures, normalize
from .ai import investigator
from .detection.correlation import correlate
from .detection.engine import detect
from .schemas import NormalizedEvent


def run_dataset(name: str, records: list[dict], directory, telemetry_available: list[str],
                origin: str = "fixture", run_ai: bool = True) -> dict:
    ledger.append("ingest", {"dataset": name, "origin": origin, "records": len(records),
                             "telemetry_available": sorted(telemetry_available)})

    events: list[NormalizedEvent] = []
    failures = []
    for r in records:
        try:
            events.append(normalize(r, directory))
        except Exception as exc:  # keep going; record what could not be parsed
            failures.append(f"{r.get('source')}: {type(exc).__name__}: {exc}")
    for e in events:
        store.insert("event", e.event_id, e.to_dict(), dataset=name)
    ledger.append("normalize", {"dataset": name, "events": len(events), "failures": failures,
                                "event_ids": [e.event_id for e in events]})

    signals = detect(events, getattr(directory, "tenant_domains", []))
    for s in signals:
        store.insert("signal", s.signal_id, s.to_dict(), dataset=name)
    ledger.append("detection", {"dataset": name, "signals": [
        {"signal_id": s.signal_id, "rule_id": s.rule_id, "event_id": s.event_id, "summary": s.summary}
        for s in signals]})

    events_by_id = {e.event_id: e for e in events}
    incidents = correlate(signals, events_by_id, directory, telemetry_available, store.now())
    created = []
    for inc in incidents:
        d = inc.to_dict()
        if not store.insert("incident", inc.incident_id, d, incident_id=inc.incident_id, dataset=name):
            continue  # already exists from an earlier run: the original is kept unchanged
        created.append(inc.incident_id)
        ledger.append("correlation", {"chain": inc.correlation, "signal_ids": inc.signal_ids,
                                      "evidence_event_ids": inc.evidence_event_ids,
                                      "context_event_ids": inc.context_event_ids}, incident_id=inc.incident_id)
        ledger.append("incident.created", {"title": inc.title, "scenario": inc.scenario,
                                           "detection_version": inc.detection_version,
                                           "allowed_actions": inc.allowed_actions,
                                           "recommended_actions": inc.recommended_actions,
                                           "action_targets": inc.action_targets}, incident_id=inc.incident_id)
        ledger.append("score.severity", inc.severity, incident_id=inc.incident_id)
        ledger.append("score.confidence", inc.confidence, incident_id=inc.incident_id)
        if run_ai:
            run_investigation(inc.incident_id)

    return {"dataset": name, "events": len(events), "signals": len(signals),
            "incidents_created": created, "normalize_failures": failures}


def incident_bundle(incident_id: str) -> tuple[dict, list[dict], list[dict]]:
    inc = store.get("incident", incident_id)
    events = store.get_many("event", inc["evidence_event_ids"] + inc.get("context_event_ids", []))
    signals = store.get_many("signal", inc["signal_ids"])
    return inc, events, signals


def run_investigation(incident_id: str) -> dict:
    inc, events, signals = incident_bundle(incident_id)
    assessment = investigator.investigate(inc, events, signals)
    store.insert("ai_assessment", assessment["assessment_id"], assessment, incident_id=incident_id)
    ledger.append("ai.assessment", {k: assessment[k] for k in (
        "assessment_id", "mode", "model", "prompt_version", "input_hash", "validated", "validation_errors",
        "raw_output")}, incident_id=incident_id, actor=f"ai:{assessment['model']}")
    return assessment


def run_all_fixtures(run_ai: bool = True) -> list[dict]:
    results = []
    for path in list_fixtures():
        fx = load_fixture(path)
        results.append(run_dataset(fx["dataset"], fx["records"], fx["directory_obj"],
                                   fx.get("telemetry_available", []), origin=fx.get("origin", "fixture"),
                                   run_ai=run_ai))
    return results


# ---------------------------------------------------------------- background AI worker
_jobs: deque = deque()
_pending: set = set()
_lock = threading.Lock()
_worker = None


def _work():
    global _worker
    while True:
        with _lock:
            if not _jobs:
                _worker = None
                return
            incident_id = _jobs.popleft()
        try:
            run_investigation(incident_id)
        except Exception as exc:  # never let one bad incident stop the queue
            ledger.append("ai.error", {"error": f"{type(exc).__name__}: {exc}"}, incident_id=incident_id)
        finally:
            with _lock:
                _pending.discard(incident_id)


def enqueue_investigation(incident_id: str) -> None:
    """Queue one incident for AI assessment. One model call at a time, in order."""
    global _worker
    with _lock:
        if incident_id in _pending:
            return
        _pending.add(incident_id)
        _jobs.append(incident_id)
        if _worker is None:
            _worker = threading.Thread(target=_work, name="ai-worker", daemon=True)
            _worker.start()


def is_pending(incident_id: str) -> bool:
    return incident_id in _pending


def queue_length() -> int:
    return len(_pending)
