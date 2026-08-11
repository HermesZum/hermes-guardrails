"""
SQLite audit log for Hermes guardrails.

Stores blocked attempts, warnings, and tool call audit records.
Thread-safe with RLock. Uses parameterized queries throughout.
"""

from __future__ import annotations

import json
import logging
import os
import sqlite3
import threading
import time
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp REAL NOT NULL,
    tool_name TEXT NOT NULL,
    action TEXT NOT NULL,
    severity TEXT NOT NULL,
    findings_json TEXT,
    message TEXT,
    session_id TEXT,
    task_id TEXT
);

CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log(timestamp);
CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_log(action);
CREATE INDEX IF NOT EXISTS idx_audit_tool ON audit_log(tool_name);

CREATE TABLE IF NOT EXISTS stats (
    key TEXT PRIMARY KEY,
    value INTEGER NOT NULL DEFAULT 0
);

INSERT OR IGNORE INTO stats (key, value) VALUES
    ('total_blocked', 0),
    ('total_warned', 0),
    ('total_scanned', 0),
    ('total_allowed', 0);
"""


class AuditStore:
    """Thread-safe SQLite audit log."""

    def __init__(self, db_path: str | Path):
        self._db_path = str(db_path)
        self._conn: Optional[sqlite3.Connection] = None
        self._lock = threading.RLock()
        self._connected = False

    def connect(self) -> None:
        """Open the database connection and create schema."""
        with self._lock:
            if self._connected:
                return
            path = Path(self._db_path)
            path.parent.mkdir(parents=True, exist_ok=True)
            conn = sqlite3.connect(self._db_path, check_same_thread=False)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA busy_timeout=5000")
            try:
                conn.executescript(_SCHEMA)
                conn.commit()
            except Exception:
                conn.close()
                raise
            self._conn = conn
            self._connected = True
            logger.info(f"guardrails-store: connected (db={self._db_path})")

    def close(self) -> None:
        """Close the database connection."""
        with self._lock:
            if self._conn:
                self._conn.close()
                self._conn = None
            self._connected = False

    def log(
        self,
        tool_name: str,
        action: str,
        severity: str = "info",
        findings: list | None = None,
        message: str = "",
        session_id: str = "",
        task_id: str = "",
    ) -> int:
        """Log an audit entry. Returns the row ID."""
        with self._lock:
            if not self._conn:
                return -1
            findings_json = json.dumps(
                [{"kind": f.kind, "value": f.masked(), "severity": f.severity.value}
                 for f in (findings or [])]
            ) if findings else ""
            cursor = self._conn.execute(
                """INSERT INTO audit_log
                   (timestamp, tool_name, action, severity, findings_json, message, session_id, task_id)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (time.time(), tool_name, action, severity, findings_json, message, session_id, task_id),
            )
            self._conn.commit()

            # Update stats
            stat_key = f"total_{action}" if action in ("blocked", "warned", "allowed") else "total_scanned"
            self._conn.execute(
                "UPDATE stats SET value = value + 1 WHERE key = ?",
                (stat_key,),
            )
            if action in ("blocked", "warned", "allowed", "scanned"):
                self._conn.execute(
                    "UPDATE stats SET value = value + 1 WHERE key = 'total_scanned'",
                )
            self._conn.commit()
            return cursor.lastrowid or -1

    def get_recent(self, limit: int = 50, action_filter: str = "") -> list[dict]:
        """Get recent audit entries."""
        with self._lock:
            if not self._conn:
                return []
            limit = max(1, min(int(limit), 500))
            if action_filter:
                rows = self._conn.execute(
                    """SELECT * FROM audit_log WHERE action = ?
                       ORDER BY timestamp DESC LIMIT ?""",
                    (action_filter, limit),
                ).fetchall()
            else:
                rows = self._conn.execute(
                    "SELECT * FROM audit_log ORDER BY timestamp DESC LIMIT ?",
                    (limit,),
                ).fetchall()
            return [dict(r) for r in rows]

    def get_stats(self) -> dict:
        """Get aggregate stats."""
        with self._lock:
            if not self._conn:
                return {}
            rows = self._conn.execute("SELECT key, value FROM stats").fetchall()
            return {r["key"]: r["value"] for r in rows}

    def get_blocked_count(self) -> int:
        """Get total blocked count."""
        with self._lock:
            if not self._conn:
                return 0
            row = self._conn.execute(
                "SELECT value FROM stats WHERE key = 'total_blocked'"
            ).fetchone()
            return row["value"] if row else 0

    def clear(self) -> int:
        """Clear all audit entries. Returns count deleted."""
        with self._lock:
            if not self._conn:
                return 0
            cursor = self._conn.execute("DELETE FROM audit_log")
            self._conn.execute(
                "UPDATE stats SET value = 0 WHERE key IN ('total_blocked', 'total_warned', 'total_scanned', 'total_allowed')"
            )
            self._conn.commit()
            return cursor.rowcount or 0