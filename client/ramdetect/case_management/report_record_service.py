"""
report_record_service.py
------------------------
Report record service for RAMDetect Case Management.

Responsibilities
----------------
  - Register a generated report file (PDF / JSON / CSV) into the database.
  - Calculate SHA-256 of the report file for integrity tracking.
  - List reports for a case.
  - Write audit logs for every registration.

Report ID format: RPT-YYYYMMDD-NNNNNN
"""

import hashlib
import logging
import os
import uuid
from datetime import datetime

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _generate_report_id() -> str:
    date_part = datetime.utcnow().strftime("%Y%m%d")
    short_uid = uuid.uuid4().hex[:6].upper()
    return f"RPT-{date_part}-{short_uid}"


def _sha256_file(file_path: str) -> str:
    """Return the SHA-256 hex digest of a file, or empty string on error."""
    h = hashlib.sha256()
    try:
        with open(file_path, "rb") as fh:
            chunk_size = 4 * 1024 * 1024    # 4 MB
            while True:
                chunk = fh.read(chunk_size)
                if not chunk:
                    break
                h.update(chunk)
        return h.hexdigest()
    except OSError as exc:
        logger.warning("SHA-256 of report failed for %r: %s", file_path, exc)
        return ""


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def register_report(
    report_type: str,
    report_path: str,
    case_id: str | None             = None,
    analysis_session_id: str | None = None,
    generated_by_user_id: int | None = None,
    workstation_id: int | None = None,
    verdict_snapshot: str | None    = None,
    user=None,
) -> "Report":
    """Register a generated report file in the database.

    Parameters
    ----------
    report_type:
        PDF | JSON | CSV_ML | CSV_CIC
    report_path:
        Absolute path to the generated report file.
    case_id:
        Human-readable case identifier (optional).
    analysis_session_id:
        Human-readable session identifier (optional).
    generated_by_user_id:
        FK to users.id of the generating analyst.
    verdict_snapshot:
        CLEAN or SUSPICIOUS — snapshot of the ML verdict at generation time.
    user:
        User object for audit logging.

    Returns
    -------
    Report
        Detached ORM instance.
    """
    from ramdetect.case_management.database     import session_scope
    from ramdetect.case_management.models       import Case, AnalysisSession, Report
    from ramdetect.case_management.audit_service import write_audit_log

    # ── resolve optional FK integers ─────────────────────────────────────
    case_pk    = None
    session_pk = None

    with session_scope() as session:
        if case_id:
            case = session.query(Case).filter_by(case_id=case_id).first()
            if case:
                case_pk = case.id
        if analysis_session_id:
            rec = (session.query(AnalysisSession)
                   .filter_by(session_id=analysis_session_id).first())
            if rec:
                session_pk = rec.id

    # ── business ID generated before archive so PTM repository can store it as
    #    a logical source_report_id correlation field.
    report_id = _generate_report_id()

    # ── archive + compute report file hash ────────────────────────────────
    abs_path = os.path.abspath(report_path) if report_path else None
    original_path = abs_path
    archive_meta = {}
    if abs_path and os.path.exists(abs_path):
        try:
            from ramdetect.case_management.report_repository import archive_report_file
            archive_meta = archive_report_file(
                abs_path,
                username=getattr(user, "username", None),
                machine_name=None,
                workstation_id=workstation_id,
                action=f"REGISTER_REPORT_{report_type}",
                verdict=verdict_snapshot,
                source_report_id=report_id,
                source_session_id=analysis_session_id,
                source_workstation_id=str(workstation_id or ""),
            )
            if archive_meta.get("success"):
                abs_path = archive_meta.get("central_api_uri") or archive_meta.get("archive_path") or abs_path
        except Exception as exc:
            logger.warning("Report archive failed for %r: %s", abs_path, exc)

    file_sha256 = ""
    if abs_path and os.path.exists(abs_path):
        file_sha256 = _sha256_file(abs_path)

    # ── insert ────────────────────────────────────────────────────────────
    repository_report_id = archive_meta.get("central_api_report_id") or None
    repository_uri = archive_meta.get("central_api_uri") or None
    repository_upload_status = "uploaded" if archive_meta.get("central_api_uploaded") else ("failed" if archive_meta.get("central_api_error") else None)
    repository_uploaded_at = datetime.utcnow() if archive_meta.get("central_api_uploaded") else None

    with session_scope() as session:
        report = Report(
            report_id            = report_id,
            case_id              = case_pk,
            analysis_session_id  = session_pk,
            workstation_id       = workstation_id,
            report_type          = report_type,
            report_path          = abs_path,
            generated_by_user_id = generated_by_user_id,
            generated_at         = datetime.utcnow(),
            verdict_snapshot     = verdict_snapshot,
            sha256               = file_sha256 or archive_meta.get("sha256") or None,
            repository_report_id = repository_report_id,
            repository_uri       = repository_uri,
            repository_upload_status = repository_upload_status,
            repository_uploaded_at = repository_uploaded_at,
        )
        session.add(report)
        session.flush()
        session.refresh(report)
        session.expunge(report)

    write_audit_log(
        user,
        action      = "REGISTER_REPORT",
        entity_type = "Report",
        entity_id   = report_id,
        case_id     = case_pk,
        report_id = report.id,
        repository_report_id = repository_report_id,
        details     = {
            "report_id":       report_id,
            "source_report_id": report_id,
            "repository_report_id": repository_report_id,
            "repository_uri":  repository_uri,
            "repository_upload_status": repository_upload_status,
            "report_type":    report_type,
            "report_path":    str(abs_path),
            "original_path":  str(original_path),
            "archived_path":  str(archive_meta.get("archive_path", "")),
            "verdict":        verdict_snapshot,
            "sha256":         file_sha256,
        },
    )
    logger.info("Report registered: %s  type=%s  path=%r", report_id, report_type, abs_path)
    return get_report_by_id(report_id)


def get_report_by_id(report_id: str):
    """Return the Report with the given report_id, or None."""
    from ramdetect.case_management.database import session_scope
    from ramdetect.case_management.models   import Report

    with session_scope() as session:
        report = session.query(Report).filter_by(report_id=report_id).first()
        if report:
            session.expunge(report)
        return report


def list_reports_for_case(case_id: str) -> list:
    """Return all Report objects for a case, newest first."""
    from ramdetect.case_management.database import session_scope
    from ramdetect.case_management.models   import Case, Report

    with session_scope() as session:
        case = session.query(Case).filter_by(case_id=case_id).first()
        if case is None:
            return []
        reports = (session.query(Report)
                   .filter_by(case_id=case.id)
                   .order_by(Report.generated_at.desc())
                   .all())
        for r in reports:
            session.expunge(r)
        return reports


def list_reports_for_session(session_id: str) -> list:
    """Return all Report objects for an analysis session, newest first."""
    from ramdetect.case_management.database import session_scope
    from ramdetect.case_management.models   import AnalysisSession, Report

    with session_scope() as session:
        rec = (session.query(AnalysisSession)
               .filter_by(session_id=session_id).first())
        if rec is None:
            return []
        reports = (session.query(Report)
                   .filter_by(analysis_session_id=rec.id)
                   .order_by(Report.generated_at.desc())
                   .all())
        for r in reports:
            session.expunge(r)
        return reports
