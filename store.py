"""Tiny SQLite store. Every object is saved as a JSON document.

Rows are INSERT-only: nothing in the app updates or deletes a stored
detection, score, AI assessment, action, or disposition. Later decisions are
new rows, and the incident's current status is derived from them.
"""
import json
import sqlite3
from datetime import datetime, timezone

from . import config

KINDS = ("event", "signal", "incident", "ai_assessment", "action", "disposition", "chat")


def _conn() -> sqlite3.Connection:
    config.DATA_DIR.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(config.DB_PATH)
    conn.execute(
        """CREATE TABLE IF NOT EXISTS docs (
               kind TEXT NOT NULL,
               id TEXT NOT NULL,
               incident_id TEXT,
               dataset TEXT,
               created_at TEXT NOT NULL,
               body TEXT NOT NULL,
               PRIMARY KEY (kind, id))"""
    )
    return conn


def now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def insert(kind: str, doc_id: str, body: dict, incident_id: str | None = None, dataset: str | None = None) -> bool:
    """Insert once. Returns False if that id already exists (the original is kept)."""
    assert kind in KINDS, kind
    with _conn() as conn:
        cur = conn.execute(
            "INSERT OR IGNORE INTO docs (kind, id, incident_id, dataset, created_at, body) VALUES (?,?,?,?,?,?)",
            (kind, doc_id, incident_id, dataset, now(), json.dumps(body, default=str)),
        )
        return cur.rowcount == 1


def get(kind: str, doc_id: str) -> dict | None:
    with _conn() as conn:
        row = conn.execute("SELECT body FROM docs WHERE kind=? AND id=?", (kind, doc_id)).fetchone()
    return json.loads(row[0]) if row else None


def get_many(kind: str, ids: list[str]) -> list[dict]:
    return [d for d in (get(kind, i) for i in ids) if d is not None]


def list_kind(kind: str, incident_id: str | None = None) -> list[dict]:
    with _conn() as conn:
        if incident_id is None:
            rows = conn.execute("SELECT body FROM docs WHERE kind=? ORDER BY rowid", (kind,)).fetchall()
        else:
            rows = conn.execute(
                "SELECT body FROM docs WHERE kind=? AND incident_id=? ORDER BY rowid", (kind, incident_id)
            ).fetchall()
    return [json.loads(r[0]) for r in rows]
