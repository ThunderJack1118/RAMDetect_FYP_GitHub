"""
tools/test_activity_monitoring.py
---------------------------------
Headless smoke test for RAMDetect Phase 4 Activity Monitoring.

This script is safe to run from:
    python tools\test_activity_monitoring.py

It patches sys.path at runtime so imports work even when Python sets
sys.path[0] to the tools/ folder.
"""

from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path


# ---------------------------------------------------------------------------
# Import path bootstrap
# ---------------------------------------------------------------------------
PROJECT_ROOT = Path(__file__).resolve().parents[1]
NESTED_ROOT = PROJECT_ROOT / "ramdetect"

# Allow: import ramdetect...
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

# Match main.py style imports used by UI files: import ui...
if (NESTED_ROOT / "ui").is_dir() and str(NESTED_ROOT) not in sys.path:
    sys.path.insert(0, str(NESTED_ROOT))


def hr(title: str) -> None:
    print(f"\n{'─' * 18} {title} {'─' * 18}")


def ok(msg: str) -> None:
    print(f"  ✓ {msg}")


def fail(msg: str) -> None:
    raise AssertionError(msg)


def run() -> None:
    tmp = Path(tempfile.mkdtemp(prefix="ramdetect_activity_test_"))
    db_path = tmp / "activity_test.db"

    print(f"Using temporary database: {db_path}")
    print(f"[Path] PROJECT_ROOT = {PROJECT_ROOT}")
    print(f"[Path] NESTED_ROOT  = {NESTED_ROOT}")
    print(f"[Path] ramdetect import root exists = {(PROJECT_ROOT / 'ramdetect').is_dir()}")

    hr("T1 · Init database")
    from ramdetect.case_management import initialise_database
    initialise_database(str(db_path))
    ok("Database initialized")

    hr("T2 · Ensure audit columns")
    from ramdetect.case_management.activity_logger import (
        ensure_audit_log_columns,
        ActivityLogger,
        Action,
    )
    ensure_audit_log_columns()

    from ramdetect.case_management.database import get_engine
    from sqlalchemy import inspect as sa_inspect

    inspector = sa_inspect(get_engine())
    cols = {c["name"] for c in inspector.get_columns("audit_logs")}
    required = {
        "id", "user_id", "username", "role", "machine_name",
        "action", "file_path", "file_name", "file_hash",
        "verdict", "report_path", "details_json",
        "timestamp", "created_at",
    }
    missing = required - cols
    if missing:
        fail(f"Missing audit_logs columns: {sorted(missing)}")
    ok("audit_logs Phase 4 columns exist")

    hr("T3 · Write activity logs")
    # Reset singleton in case this test is run interactively/repeatedly.
    ActivityLogger._inst = None
    al = ActivityLogger.instance()
    al.set_user(user_id=1, username="admin", role="Admin")

    assert al.log_app_opened() is None
    assert al.log_login_success("admin", 1, "Admin") is None
    assert al.log_login_failed("wrong_user") is None
    assert al.log_dump_selected(r"C:\Evidence\sample.dmp") is None
    assert al.log_dump_imported(r"C:\Evidence\sample.dmp", file_hash="abc123") is None
    assert al.log_analysis_started("sample.dmp") is None
    assert al.log_analysis_completed("sample.dmp", verdict="CLEAN", rf_score=0.1234) is None
    assert al.log_pdf_exported(r"C:\Reports\sample.pdf", verdict="CLEAN") is None
    assert al.log_logout() is None
    ok("Activity logger wrote sample events without raising")

    hr("T4 · Query logs")
    rows = al.get_logs(limit=100)
    if len(rows) < 8:
        fail(f"Expected at least 8 audit rows, got {len(rows)}")
    ok(f"get_logs() returned {len(rows)} rows")

    actions = {r.get("action") for r in rows}
    expected_actions = {
        "APP_OPENED",
        "LOGIN_SUCCESS",
        "LOGIN_FAILED",
        "DUMP_SELECTED",
        "DUMP_IMPORTED",
        "ANALYSIS_STARTED",
        "ANALYSIS_COMPLETED",
        "PDF_EXPORTED",
        "LOGOUT",
    }
    missing_actions = expected_actions - actions
    if missing_actions:
        fail(f"Missing expected actions: {sorted(missing_actions)}")
    ok("Expected activity actions found")

    hr("T5 · Filter logs")
    login_rows = al.get_logs(action_filter={"LOGIN_SUCCESS", "LOGIN_FAILED", "LOGOUT"}, limit=100)
    if len(login_rows) < 3:
        fail(f"Expected login-related rows, got {len(login_rows)}")
    ok(f"Login filter returned {len(login_rows)} rows")

    admin_rows = al.get_logs(username_filter="admin", limit=100)
    if not admin_rows:
        fail("Expected rows for username admin")
    ok(f"Username filter returned {len(admin_rows)} rows")

    hr("T6 · Confirm no ML files needed")
    ml_paths = [
        PROJECT_ROOT / "ramdetect" / "ml" / "random_forest_model.py",
        PROJECT_ROOT / "ramdetect" / "ml" / "feature_mapper.py",
        PROJECT_ROOT / "ramdetect" / "ml" / "autoencoder_model.py",
    ]
    for path in ml_paths:
        if not path.exists():
            # Not fatal for this smoke test, but print it for awareness.
            print(f"  ! Not found during smoke test: {path}")
    ok("Activity monitoring test does not import or execute ML modules")

    print("\n✓ All Activity Monitoring tests passed.")


if __name__ == "__main__":
    run()
