"""
cyberagent/session.py — SQLite-backed conversation session persistence.

Schema:
    sessions  (id TEXT PK, name TEXT, created_at, last_active)
    messages  (id INTEGER PK, session_id, role, content, skills_loaded JSON, timestamp)
"""

import json
import sqlite3
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from .config import SESSIONS_DB


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


@contextmanager
def _conn():
    SESSIONS_DB.parent.mkdir(exist_ok=True)
    con = sqlite3.connect(str(SESSIONS_DB))
    con.row_factory = sqlite3.Row
    try:
        yield con
        con.commit()
    finally:
        con.close()


def _init_db():
    with _conn() as con:
        con.executescript("""
        CREATE TABLE IF NOT EXISTS sessions (
            id          TEXT PRIMARY KEY,
            name        TEXT NOT NULL,
            created_at  TEXT NOT NULL,
            last_active TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS messages (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id   TEXT NOT NULL,
            role         TEXT NOT NULL,
            content      TEXT NOT NULL,
            skills_loaded TEXT DEFAULT '[]',
            timestamp    TEXT NOT NULL,
            FOREIGN KEY (session_id) REFERENCES sessions(id)
        );
        """)


_init_db()


# ---------------------------------------------------------------------------
# Session CRUD
# ---------------------------------------------------------------------------

def new_session(name: Optional[str] = None) -> str:
    """Create and return a new session ID."""
    sid = str(uuid.uuid4())[:8]
    if not name:
        name = f"session-{_now()[:16]}"
    with _conn() as con:
        con.execute(
            "INSERT INTO sessions VALUES (?, ?, ?, ?)",
            (sid, name, _now(), _now()),
        )
    return sid


def list_sessions(limit: int = 10) -> list[dict]:
    """Return the most recent `limit` sessions."""
    with _conn() as con:
        rows = con.execute(
            "SELECT * FROM sessions ORDER BY last_active DESC LIMIT ?", (limit,)
        ).fetchall()
    return [dict(r) for r in rows]


def get_session(sid: str) -> Optional[dict]:
    """Return a session dict or None."""
    with _conn() as con:
        row = con.execute(
            "SELECT * FROM sessions WHERE id = ?", (sid,)
        ).fetchone()
    return dict(row) if row else None


def touch_session(sid: str):
    """Update last_active timestamp."""
    with _conn() as con:
        con.execute(
            "UPDATE sessions SET last_active = ? WHERE id = ?", (_now(), sid)
        )


def rename_session(sid: str, name: str):
    with _conn() as con:
        con.execute("UPDATE sessions SET name = ? WHERE id = ?", (name, sid))


# ---------------------------------------------------------------------------
# Message CRUD
# ---------------------------------------------------------------------------

def add_message(
    sid: str,
    role: str,
    content: str,
    skills_loaded: Optional[list[str]] = None,
):
    """Append a message to a session."""
    touch_session(sid)
    with _conn() as con:
        con.execute(
            "INSERT INTO messages (session_id, role, content, skills_loaded, timestamp) "
            "VALUES (?, ?, ?, ?, ?)",
            (sid, role, content, json.dumps(skills_loaded or []), _now()),
        )


def get_messages(sid: str) -> list[dict]:
    """Return all messages for a session as list of {role, content}."""
    with _conn() as con:
        rows = con.execute(
            "SELECT role, content FROM messages WHERE session_id = ? ORDER BY id",
            (sid,),
        ).fetchall()
    return [{"role": r["role"], "content": r["content"]} for r in rows]


def message_count(sid: str) -> int:
    with _conn() as con:
        row = con.execute(
            "SELECT COUNT(*) as n FROM messages WHERE session_id = ?", (sid,)
        ).fetchone()
    return row["n"] if row else 0
