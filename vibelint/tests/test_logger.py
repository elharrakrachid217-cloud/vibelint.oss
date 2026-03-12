"""
tests/test_logger.py
====================
Tests for ScanLogger — the SQLite-backed audit log for scan results.

Run with:
    pytest tests/test_logger.py -v
"""

import json
import os
import sqlite3
import tempfile
from datetime import datetime, timedelta, timezone

import pytest

from core.logger import ScanLogger


# ─────────────────────────────────────────
# FIXTURES
# ─────────────────────────────────────────

@pytest.fixture()
def db_path(tmp_path):
    """Return a throwaway database path inside pytest's temp directory."""
    return str(tmp_path / "test_vibelint.db")


@pytest.fixture()
def logger(db_path):
    return ScanLogger(db_path=db_path)


def _make_result(*, approved=True, filename="app.py", language="python",
                 violations=None, total=0, critical=0, high=0):
    """Build a minimal scan-result dict matching SecurityScanner output."""
    return {
        "approved": approved,
        "filename": filename,
        "language": language,
        "violations": violations or [],
        "remediated_code": "",
        "summary": "test summary",
        "stats": {"total": total, "critical": critical, "high": high},
    }


# ─────────────────────────────────────────
# TABLE CREATION
# ─────────────────────────────────────────

def test_creates_database_file(db_path, logger):
    assert os.path.exists(db_path)


def test_creates_scan_log_table(db_path, logger):
    conn = sqlite3.connect(db_path)
    cursor = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='scan_log'"
    )
    assert cursor.fetchone() is not None
    conn.close()


def test_table_has_expected_columns(db_path, logger):
    conn = sqlite3.connect(db_path)
    rows = conn.execute("PRAGMA table_info(scan_log)").fetchall()
    col_names = {r[1] for r in rows}
    expected = {
        "id", "timestamp", "filename", "language",
        "total_violations", "critical_count", "approved", "result_json",
    }
    assert expected.issubset(col_names)
    conn.close()


# ─────────────────────────────────────────
# LOGGING SCANS
# ─────────────────────────────────────────

def test_log_scan_inserts_row(logger, db_path):
    result = _make_result()
    logger.log_scan(result)

    conn = sqlite3.connect(db_path)
    count = conn.execute("SELECT COUNT(*) FROM scan_log").fetchone()[0]
    assert count == 1
    conn.close()


def test_log_scan_stores_correct_filename(logger, db_path):
    result = _make_result(filename="auth.py")
    logger.log_scan(result)

    conn = sqlite3.connect(db_path)
    row = conn.execute("SELECT filename FROM scan_log").fetchone()
    assert row[0] == "auth.py"
    conn.close()


def test_log_scan_stores_language(logger, db_path):
    result = _make_result(language="javascript")
    logger.log_scan(result)

    conn = sqlite3.connect(db_path)
    row = conn.execute("SELECT language FROM scan_log").fetchone()
    assert row[0] == "javascript"
    conn.close()


def test_log_scan_stores_violation_counts(logger, db_path):
    result = _make_result(approved=False, total=3, critical=2, high=1)
    logger.log_scan(result)

    conn = sqlite3.connect(db_path)
    row = conn.execute(
        "SELECT total_violations, critical_count FROM scan_log"
    ).fetchone()
    assert row == (3, 2)
    conn.close()


def test_log_scan_stores_approved_flag(logger, db_path):
    logger.log_scan(_make_result(approved=True))
    logger.log_scan(_make_result(approved=False))

    conn = sqlite3.connect(db_path)
    rows = conn.execute(
        "SELECT approved FROM scan_log ORDER BY id"
    ).fetchall()
    assert rows[0][0] == 1   # True stored as 1
    assert rows[1][0] == 0   # False stored as 0
    conn.close()


def test_log_scan_stores_full_json(logger, db_path):
    result = _make_result(filename="db.js", total=1, critical=1)
    logger.log_scan(result)

    conn = sqlite3.connect(db_path)
    raw = conn.execute("SELECT result_json FROM scan_log").fetchone()[0]
    parsed = json.loads(raw)
    assert parsed["filename"] == "db.js"
    assert parsed["stats"]["critical"] == 1
    conn.close()


def test_log_scan_stores_utc_timestamp(logger, db_path):
    logger.log_scan(_make_result())

    conn = sqlite3.connect(db_path)
    ts = conn.execute("SELECT timestamp FROM scan_log").fetchone()[0]
    dt = datetime.fromisoformat(ts)
    assert dt.date() == datetime.now(timezone.utc).date()
    conn.close()


def test_log_scan_returns_row_id(logger):
    row_id = logger.log_scan(_make_result())
    assert isinstance(row_id, int)
    assert row_id >= 1


def test_multiple_scans_get_sequential_ids(logger):
    id1 = logger.log_scan(_make_result(filename="a.py"))
    id2 = logger.log_scan(_make_result(filename="b.py"))
    assert id2 == id1 + 1


# ─────────────────────────────────────────
# get_recent_scans
# ─────────────────────────────────────────

def test_get_recent_scans_returns_list(logger):
    assert isinstance(logger.get_recent_scans(), list)


def test_get_recent_scans_empty_db(logger):
    assert logger.get_recent_scans() == []


def test_get_recent_scans_includes_today(logger):
    logger.log_scan(_make_result(filename="today.py"))
    scans = logger.get_recent_scans(days=7)
    assert len(scans) == 1
    assert scans[0]["filename"] == "today.py"


def test_get_recent_scans_excludes_old_entries(logger, db_path):
    logger.log_scan(_make_result(filename="recent.py"))

    conn = sqlite3.connect(db_path)
    old_ts = (datetime.now(timezone.utc) - timedelta(days=30)).isoformat()
    conn.execute(
        "INSERT INTO scan_log (timestamp, filename, language, "
        "total_violations, critical_count, approved, result_json) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        (old_ts, "old.py", "python", 0, 0, 1, "{}"),
    )
    conn.commit()
    conn.close()

    scans = logger.get_recent_scans(days=7)
    filenames = [s["filename"] for s in scans]
    assert "recent.py" in filenames
    assert "old.py" not in filenames


def test_get_recent_scans_respects_days_param(logger, db_path):
    logger.log_scan(_make_result(filename="fresh.py"))

    conn = sqlite3.connect(db_path)
    ts_5_days = (datetime.now(timezone.utc) - timedelta(days=5)).isoformat()
    conn.execute(
        "INSERT INTO scan_log (timestamp, filename, language, "
        "total_violations, critical_count, approved, result_json) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        (ts_5_days, "five_days.py", "python", 0, 0, 1, "{}"),
    )
    conn.commit()
    conn.close()

    assert len(logger.get_recent_scans(days=3)) == 1
    assert len(logger.get_recent_scans(days=7)) == 2


def test_get_recent_scans_returns_dicts_with_expected_keys(logger):
    logger.log_scan(_make_result())
    scan = logger.get_recent_scans()[0]
    expected_keys = {
        "id", "timestamp", "filename", "language",
        "total_violations", "critical_count", "approved", "result_json",
    }
    assert expected_keys == set(scan.keys())


def test_get_recent_scans_approved_is_bool(logger):
    logger.log_scan(_make_result(approved=True))
    scan = logger.get_recent_scans()[0]
    assert scan["approved"] is True


def test_get_recent_scans_ordered_newest_first(logger):
    logger.log_scan(_make_result(filename="first.py"))
    logger.log_scan(_make_result(filename="second.py"))
    scans = logger.get_recent_scans()
    assert scans[0]["filename"] == "second.py"
    assert scans[1]["filename"] == "first.py"


# ─────────────────────────────────────────
# EDGE CASES
# ─────────────────────────────────────────

def test_concurrent_loggers_same_db(db_path):
    """Two ScanLogger instances sharing one database should not corrupt it."""
    a = ScanLogger(db_path=db_path)
    b = ScanLogger(db_path=db_path)
    a.log_scan(_make_result(filename="a.py"))
    b.log_scan(_make_result(filename="b.py"))

    scans = a.get_recent_scans()
    assert len(scans) == 2


def test_default_db_path():
    """ScanLogger() with no args should default to vibelint.db."""
    logger = ScanLogger()
    assert logger.db_path.endswith("vibelint.db")
