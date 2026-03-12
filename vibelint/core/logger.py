"""
core/logger.py
==============
SQLite-backed audit log for every VibeLint scan result.
Uses only the built-in sqlite3 module — no extra dependencies.
"""

import json
import os
import sqlite3
from datetime import datetime, timedelta, timezone

_DEFAULT_DB = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "vibelint.db")

_CREATE_TABLE = """
CREATE TABLE IF NOT EXISTS scan_log (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp        TEXT    NOT NULL,
    filename         TEXT    NOT NULL,
    language         TEXT    NOT NULL,
    total_violations INTEGER NOT NULL,
    critical_count   INTEGER NOT NULL,
    approved         INTEGER NOT NULL,
    result_json      TEXT    NOT NULL
)
"""


class ScanLogger:
    """Persist scan results to a local SQLite database."""

    def __init__(self, db_path: str | None = None):
        self.db_path: str = os.path.abspath(db_path or _DEFAULT_DB)
        self._ensure_table()

    # ── public API ──────────────────────────────────────────

    def log_scan(self, result: dict) -> int:
        """Insert a scan result and return the new row id."""
        conn = self._connect()
        try:
            cur = conn.execute(
                "INSERT INTO scan_log "
                "(timestamp, filename, language, total_violations, "
                "critical_count, approved, result_json) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    datetime.now(timezone.utc).isoformat(),
                    result["filename"],
                    result["language"],
                    result["stats"]["total"],
                    result["stats"]["critical"],
                    int(result["approved"]),
                    json.dumps(result),
                ),
            )
            conn.commit()
            return cur.lastrowid
        finally:
            conn.close()

    def get_recent_scans(self, days: int = 7) -> list[dict]:
        """Return scans from the last *days* days, newest first."""
        cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
        conn = self._connect()
        try:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                "SELECT id, timestamp, filename, language, "
                "total_violations, critical_count, approved, result_json "
                "FROM scan_log WHERE timestamp >= ? ORDER BY id DESC",
                (cutoff,),
            ).fetchall()
            return [self._row_to_dict(r) for r in rows]
        finally:
            conn.close()

    # ── internals ───────────────────────────────────────────

    def _connect(self) -> sqlite3.Connection:
        return sqlite3.connect(self.db_path)

    def _ensure_table(self) -> None:
        conn = self._connect()
        try:
            conn.execute(_CREATE_TABLE)
            conn.commit()
        finally:
            conn.close()

    @staticmethod
    def _row_to_dict(row: sqlite3.Row) -> dict:
        d = dict(row)
        d["approved"] = bool(d["approved"])
        return d
