"""
demo_case_management.py
-----------------------
Standalone smoke-test and demo script for RAMDetect Case Management
Phase 1 + Phase 2.

Run from the project root with:
    python tools/demo_case_management.py

The script exercises every major service function and prints a step-by-step
report. It writes to a temporary database so the main database is untouched.

No PyQt5 GUI is required to run this script.
"""

import json
import os
import sys
import tempfile
import textwrap
import traceback

# ── ensure the project root is on sys.path ────────────────────────────────
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)


def _hr(label: str = "") -> None:
    width = 60
    if label:
        pad = (width - len(label) - 2) // 2
        print("─" * pad + f" {label} " + "─" * pad)
    else:
        print("─" * width)


def _ok(msg: str) -> None:
    print(f"  ✓ {msg}")


def _fail(msg: str) -> None:
    print(f"  ✗ FAIL: {msg}")


# ── main demo ─────────────────────────────────────────────────────────────

def run_demo() -> None:
    # ── Step 0: use a temp database ──────────────────────────────────────
    tmp_dir = tempfile.mkdtemp(prefix="ramdetect_demo_")
    db_path = os.path.join(tmp_dir, "demo_cases.db")
    print(f"\nUsing temporary database: {db_path}\n")

    # Override DB path before any import creates the real engine
    from ramdetect.case_management import database as _db_module
    _db_module.init_engine(db_path)

    # ── Step 1: initialise database / create tables ──────────────────────
    _hr("STEP 1 · Init Database")
    from ramdetect.case_management.init_db import initialise_database

    initialise_database(db_path)
    _ok("Tables created and default admin checked")

    # ── Step 2: create default admin ────────────────────────────────────
    _hr("STEP 2 · Seed Default Admin")
    _ok("Default admin already handled by initialise_database()")

    # ── Step 3: authenticate ─────────────────────────────────────────────
    _hr("STEP 3 · Login")
    from ramdetect.case_management.auth_service import (
        authenticate_user, record_login_success, record_login_failure,
    )
    user = authenticate_user("admin", "admin123")
    assert user is not None, "Login failed — check auth_service"
    _ok(f"Authenticated: {user.username}  role={user.role}")

    bad = authenticate_user("admin", "wrongpassword")
    assert bad is None, "Bad password should return None"
    record_login_failure("admin", reason="wrong_password_demo")
    _ok("Bad password correctly rejected")

    record_login_success(user, machine_name="DEMO-PC")
    _ok("Login history recorded")

    # ── Step 4: create a case ────────────────────────────────────────────
    _hr("STEP 4 · Create Case")
    from ramdetect.case_management.case_service import (
        create_case, list_cases, update_case_status, add_case_note,
        list_case_notes, get_case_stats,
    )
    case = create_case(
        title               = "Suspicious Activity on WORKSTATION-07",
        description         = "User reported unusual high CPU usage and unknown processes.",
        severity            = "High",
        incident_type       = "Malware Infection",
        affected_host       = "WORKSTATION-07",
        department          = "Finance",
        created_by_user_id  = user.id,
        user                = user,
    )
    _ok(f"Case created: {case.case_id}  status={case.status}")

    # ── Step 5: list cases ───────────────────────────────────────────────
    _hr("STEP 5 · List Cases")
    cases = list_cases()
    assert len(cases) >= 1
    _ok(f"list_cases() returned {len(cases)} case(s)")

    cases_open = list_cases(status="Open")
    _ok(f"list_cases(status='Open') returned {len(cases_open)} case(s)")

    cases_search = list_cases(search="WORKSTATION")
    _ok(f"list_cases(search='WORKSTATION') returned {len(cases_search)} case(s)")

    # ── Step 6: update case status ───────────────────────────────────────
    _hr("STEP 6 · Update Case Status")
    ok = update_case_status(case.case_id, "In Progress", user=user)
    assert ok
    _ok("Status → In Progress")

    # ── Step 7: add a note ───────────────────────────────────────────────
    _hr("STEP 7 · Add Case Note")
    add_case_note(case.case_id, user.id, "Initial triage started. Memory dump requested.",
                  user=user)
    add_case_note(case.case_id, user.id, "DumpIt acquisition complete.", user=user)
    notes = list_case_notes(case.case_id)
    assert len(notes) == 2
    _ok(f"Added {len(notes)} note(s)")
    for n in notes:
        print(f"    [{n.created_at}] {n.note_text[:60]}")

    # ── Step 8: register evidence ────────────────────────────────────────
    _hr("STEP 8 · Register Evidence")
    # Create a fake 'dump' file for demo hashing
    fake_dump = os.path.join(tmp_dir, "WORKSTATION07_20240101.dmp")
    with open(fake_dump, "wb") as fh:
        fh.write(b"\x00MZ" + os.urandom(1024))  # tiny fake dump

    from ramdetect.case_management.evidence_service import (
        register_evidence, list_evidence_for_case, verify_evidence_hash,
    )
    ev = register_evidence(
        case_id              = case.case_id,
        file_path            = fake_dump,
        acquisition_method   = "DumpIt",
        collected_by_user_id = user.id,
        source_machine       = "WORKSTATION-07",
        notes                = "Acquired via DumpIt 2.0",
        user                 = user,
    )
    _ok(f"Evidence registered: {ev.evidence_id}")
    _ok(f"  MD5    = {ev.md5}")
    _ok(f"  SHA256 = {ev.sha256}")

    ev_list = list_evidence_for_case(case.case_id)
    assert len(ev_list) == 1
    _ok(f"list_evidence_for_case() returned {len(ev_list)} item(s)")

    # ── Step 9: verify hash ──────────────────────────────────────────────
    _hr("STEP 9 · Verify Evidence Hash")
    result = verify_evidence_hash(ev.evidence_id, user=user)
    assert result["file_accessible"] is True
    assert result["match_sha256"] is True
    _ok(f"Hash verified  sha256_match={result['match_sha256']}")

    # ── Step 10: create analysis session ────────────────────────────────
    _hr("STEP 10 · Create Analysis Session")
    from ramdetect.case_management.analysis_record_service import (
        create_analysis_session, complete_analysis_session,
        fail_analysis_session, list_analysis_sessions_for_case,
    )
    sess = create_analysis_session(
        dump_path        = fake_dump,
        case_id          = case.case_id,
        evidence_id      = ev.evidence_id,
        analyst_user_id  = user.id,
        selected_modules = ["eprocess", "dll", "injection", "vad"],
        user             = user,
    )
    _ok(f"Analysis session created: {sess.session_id}  status={sess.status}")

    # ── Step 11: complete analysis session ───────────────────────────────
    _hr("STEP 11 · Complete Analysis Session")
    fake_summary = {
        "processes":       87,
        "injected":         3,
        "dlls":           412,
        "handles":        921,
        "services":        42,
    }
    ok = complete_analysis_session(
        session_id                = sess.session_id,
        final_verdict             = "SUSPICIOUS",
        rf_suspicious_probability = 0.8742,
        ae_mse                    = 0.003214,
        artifact_summary          = fake_summary,
        key_findings_count        = 5,
        user                      = user,
    )
    assert ok
    _ok(f"Analysis session completed  verdict=SUSPICIOUS  rf_prob=0.8742")

    sessions = list_analysis_sessions_for_case(case.case_id)

    matching_session = None
    for item in sessions:
        if item.session_id == sess.session_id:
            matching_session = item
            break

    assert matching_session is not None
    assert matching_session.final_verdict == "SUSPICIOUS"
    assert matching_session.status.lower() in ("completed", "complete", "done")
    _ok(f"list_analysis_sessions_for_case() returned {len(sessions)} session(s)")

    # ── Step 12: fail another session ────────────────────────────────────
    _hr("STEP 12 · Fail Analysis Session (error path)")
    sess2 = create_analysis_session(
        dump_path = fake_dump,
        case_id   = case.case_id,
        user      = user,
    )
    fail_ok = fail_analysis_session(
        sess2.session_id,
        error_message = "Parser failed: unsupported memory profile",
        user          = user,
    )
    assert fail_ok
    _ok(f"Session {sess2.session_id} marked as failed")

    # ── Step 13: register reports ────────────────────────────────────────
    _hr("STEP 13 · Register Reports")
    from ramdetect.case_management.report_record_service import (
        register_report, list_reports_for_case,
    )
    fake_pdf = os.path.join(tmp_dir, "report_SUSPICIOUS.pdf")
    with open(fake_pdf, "w") as fh:
        fh.write("%PDF-1.4 (demo)")

    rpt = register_report(
        report_type          = "PDF",
        report_path          = fake_pdf,
        case_id              = case.case_id,
        analysis_session_id  = sess.session_id,
        generated_by_user_id = user.id,
        verdict_snapshot     = "SUSPICIOUS",
        user                 = user,
    )
    _ok(f"Report registered: {rpt.report_id}  type=PDF")

    rpt_list = list_reports_for_case(case.case_id)
    assert len(rpt_list) >= 1
    _ok(f"list_reports_for_case() returned {len(rpt_list)} report(s)")

    # ── Step 14: audit trail ─────────────────────────────────────────────
    _hr("STEP 14 · Audit Trail")
    from ramdetect.case_management.audit_service import list_audit_logs

    all_logs = list_audit_logs(limit=100)
    _ok(f"Total audit log entries: {len(all_logs)}")

    case_logs = list_audit_logs(case_id=case.id)
    _ok(f"Audit logs for case {case.case_id}: {len(case_logs)}")

    for log in case_logs[:8]:
        ts = log.created_at.strftime("%H:%M:%S") if log.created_at else "?"
        print(f"    [{ts}] {log.username:12s}  {log.action}")

    # ── Step 15: case stats ──────────────────────────────────────────────
    _hr("STEP 15 · Case Statistics")
    stats = get_case_stats()
    _ok("Dashboard stats:")
    for k, v in stats.items():
        print(f"    {k:20s}: {v}")

    # ── Done ─────────────────────────────────────────────────────────────
    _hr()
    print("\n  ✓ All Phase 1 + 2 demo steps passed.\n")
    print(f"  Temp database: {db_path}")
    print(f"  You can open it with any SQLite viewer (e.g. DB Browser for SQLite).\n")


if __name__ == "__main__":
    try:
        run_demo()
    except AssertionError as ae:
        _fail(f"Assertion failed: {ae}")
        traceback.print_exc()
        sys.exit(1)
    except Exception as exc:
        _fail(f"Unexpected error: {exc}")
        traceback.print_exc()
        sys.exit(1)
