"""Append-only JSON Lines audit ledger.

Each line is one AuditRecord. Every record stores the hash of the previous
record, so editing or deleting any line breaks the chain and `verify()` reports
exactly where. The code in this project only ever appends to the file.
"""
import hashlib
import json
import threading
from datetime import datetime, timezone

from . import config
from .schemas import AuditRecord

_lock = threading.Lock()
GENESIS = "0" * 64


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _hash(record: dict) -> str:
    body = {k: v for k, v in record.items() if k != "hash"}
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _last_record() -> dict | None:
    path = config.LEDGER_PATH
    if not path.exists():
        return None
    last = None
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                last = line
    return json.loads(last) if last else None


def append(record_type: str, data, incident_id: str | None = None, actor: str = "system") -> dict:
    """Append one record and return it."""
    config.DATA_DIR.mkdir(parents=True, exist_ok=True)
    with _lock:
        last = _last_record()
        rec = AuditRecord(
            seq=(last["seq"] + 1) if last else 1,
            timestamp=_now(),
            record_type=record_type,
            incident_id=incident_id,
            actor=actor,
            data=data,
            app_version=config.APP_VERSION,
            prev_hash=last["hash"] if last else GENESIS,
        ).to_dict()
        rec["hash"] = _hash(rec)
        with config.LEDGER_PATH.open("a", encoding="utf-8") as f:
            f.write(json.dumps(rec, default=str) + "\n")
        return rec


def read(incident_id: str | None = None) -> list[dict]:
    if not config.LEDGER_PATH.exists():
        return []
    out = []
    with config.LEDGER_PATH.open("r", encoding="utf-8") as f:
        for line in f:
            if not line.strip():
                continue
            rec = json.loads(line)
            if incident_id is None or rec.get("incident_id") == incident_id:
                out.append(rec)
    return out


def verify() -> dict:
    """Walk the whole chain. Returns {"ok": bool, "records": n, "problem": str|None}."""
    prev = GENESIS
    records = read()
    for i, rec in enumerate(records, start=1):
        if rec.get("seq") != i:
            return {"ok": False, "records": len(records), "problem": f"Sequence gap at line {i} (seq={rec.get('seq')})"}
        if rec.get("prev_hash") != prev:
            return {"ok": False, "records": len(records), "problem": f"Chain broken at seq {i}: prev_hash does not match"}
        if _hash(rec) != rec.get("hash"):
            return {"ok": False, "records": len(records), "problem": f"Record seq {i} was modified after it was written"}
        prev = rec["hash"]
    return {"ok": True, "records": len(records), "problem": None}
