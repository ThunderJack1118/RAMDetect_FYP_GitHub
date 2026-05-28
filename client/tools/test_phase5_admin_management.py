"""
tools/test_phase5_admin_management.py
-------------------------------------
Headless smoke test for RAMDetect Phase 5 Admin Management services.

Run from project root:
    python tools\test_phase5_admin_management.py
"""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
NESTED_ROOT = PROJECT_ROOT / "ramdetect"
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))
if str(NESTED_ROOT) not in sys.path and (NESTED_ROOT / "ui").is_dir():
    sys.path.insert(0, str(NESTED_ROOT))


def hr(title: str) -> None:
    print(f"\n{'─' * 18} {title} {'─' * 18}")


def ok(msg: str) -> None:
    print(f"  ✓ {msg}")


def run() -> None:
    tmp = Path(tempfile.mkdtemp(prefix="ramdetect_phase5_test_"))
    db_path = tmp / "phase5_admin.db"
    print(f"Using temporary database: {db_path}")

    hr("T1 · Init database")
    from ramdetect.case_management import initialise_database
    initialise_database(str(db_path))
    ok("Database initialized")

    hr("T2 · Create user")
    from ramdetect.case_management.user_service import create_user, list_users, reset_password, set_user_active
    user = create_user(
        username="analyst_test",
        password="Strong123",
        full_name="Test Analyst",
        role="Analyst",
        is_active=True,
    )
    assert user["username"] == "analyst_test"
    ok(f"Created user {user['username']}")

    users = list_users()
    assert any(u["username"] == "analyst_test" for u in users)
    ok(f"User list returned {len(users)} user(s)")

    hr("T3 · Reset and disable user")
    reset_password(user["id"], "NewStrong123")
    set_user_active(user["id"], False)
    users = list_users()
    disabled = [u for u in users if u["username"] == "analyst_test"][0]
    assert disabled["is_active"] is False
    ok("Password reset and disable worked")

    hr("T4 · Register workstation")
    from ramdetect.case_management.workstation_service import (
        list_workstations,
        register_or_update_workstation,
        set_workstation_blocked,
        set_workstation_trusted,
        update_workstation_notes,
    )
    ws = register_or_update_workstation(user_id=1, username="admin", role="Admin")
    assert ws["hostname"]
    ok(f"Registered workstation {ws['hostname']}")

    set_workstation_trusted(ws["id"], True)
    update_workstation_notes(ws["id"], "PTM trusted admin workstation")
    set_workstation_blocked(ws["id"], False)

    workstations = list_workstations()
    assert len(workstations) >= 1
    ok(f"Workstation list returned {len(workstations)} workstation(s)")

    hr("T5 · Audit logs")
    from ramdetect.case_management.activity_logger import ActivityLogger
    rows = ActivityLogger.instance().get_logs(limit=100)
    assert rows
    ok(f"Audit log returned {len(rows)} row(s)")

    print("\n✓ Phase 5 Admin Management smoke test passed.")


if __name__ == "__main__":
    run()
