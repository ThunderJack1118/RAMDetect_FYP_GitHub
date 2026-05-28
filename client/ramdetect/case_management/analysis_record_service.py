"""
analysis_record_service.py
--------------------------
Analysis session record service for RAMDetect Case Management.

Responsibilities
----------------
  - Create an AnalysisSession record before the ML pipeline starts.
  - Mark it completed (with verdict / probability / MSE) when finished.
  - Mark it failed if the pipeline raises an unhandled exception.
  - List analysis sessions for a given case.

Session ID format: SESS-YYYYMMDD-NNNNNN

CRITICAL: This module stores analysis results; it does NOT run the
ML pipeline, modify the RF threshold, or change any verdict logic.
The caller is responsible for providing the final_verdict from the
existing RF-AE pipeline.
"""

import json
import logging
import uuid
from datetime import datetime

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _generate_session_id() -> str:
    date_part = datetime.utcnow().strftime("%Y%m%d")
    short_uid = uuid.uuid4().hex[:6].upper()
    return f"SESS-{date_part}-{short_uid}"


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def create_analysis_session(
    dump_path: str,
    case_id: str | None         = None,
    evidence_id: str | None     = None,
    analyst_user_id: int | None = None,
    selected_modules: list | None = None,
    user=None,
) -> "AnalysisSession":
    """Create an AnalysisSession record at the start of an analysis run.

    Parameters
    ----------
    dump_path:
        Absolute path to the RAM dump file being analysed.
    case_id:
        Human-readable case identifier (optional; links to cases table).
    evidence_id:
        Human-readable evidence identifier (optional; links to evidence).
    analyst_user_id:
        FK to users.id of the running analyst.
    selected_modules:
        List of module names selected in the analysis configuration.
    user:
        User object for audit logging.

    Returns
    -------
    AnalysisSession
        Detached ORM instance with status='running'.
    """
    from ramdetect.case_management.database     import session_scope
    from ramdetect.case_management.models       import Case, EvidenceItem, AnalysisSession
    from ramdetect.case_management.audit_service import write_audit_log

    # ── resolve optional FK integers ─────────────────────────────────────
    case_pk     = None
    evidence_pk = None

    with session_scope() as session:
        if case_id:
            case = session.query(Case).filter_by(case_id=case_id).first()
            if case:
                case_pk = case.id
            else:
                logger.warning("create_analysis_session: case_id=%r not found", case_id)

        if evidence_id:
            ev = session.query(EvidenceItem).filter_by(evidence_id=evidence_id).first()
            if ev:
                evidence_pk = ev.id
            else:
                logger.warning("create_analysis_session: evidence_id=%r not found",
                               evidence_id)

    # ── insert ────────────────────────────────────────────────────────────
    session_id = _generate_session_id()
    modules_json = json.dumps(selected_modules or [], default=str)

    with session_scope() as session:
        record = AnalysisSession(
            session_id       = session_id,
            case_id          = case_pk,
            evidence_id      = evidence_pk,
            analyst_user_id  = analyst_user_id,
            workstation_id   = workstation_id,
            dump_path        = dump_path,
            selected_modules = modules_json,
            status           = "running",
            started_at       = datetime.utcnow(),
        )
        session.add(record)
        session.flush()
        session.refresh(record)
        session.expunge(record)

    write_audit_log(
        user,
        action      = "START_ANALYSIS",
        entity_type = "AnalysisSession",
        entity_id   = session_id,
        case_id     = case_pk,
        analysis_session_id = record.id,
        workstation_id = workstation_id,
        details     = {"dump_path": dump_path, "modules": selected_modules, "session_id": session_id},
    )
    logger.info("Analysis session created: %s  dump=%r", session_id, dump_path)
    return get_analysis_session_by_id(session_id)


def complete_analysis_session(
    session_id: str,
    final_verdict: str,
    rf_suspicious_probability: float | None = None,
    ae_mse: float | None                    = None,
    artifact_summary: dict | None           = None,
    key_findings_count: int                 = 0,
    user=None,
) -> bool:
    """Mark an AnalysisSession as completed and store ML results.

    Parameters
    ----------
    session_id:
        Human-readable session identifier.
    final_verdict:
        CLEAN | SUSPICIOUS | ERROR  (must come from the RF-AE ML pipeline).
    rf_suspicious_probability:
        Float output from Random Forest predict_proba, 0.0–1.0.
    ae_mse:
        Autoencoder reconstruction MSE used as feature 55.
    artifact_summary:
        Dict of key artifact counts (stored as JSON blob).
    key_findings_count:
        Total number of analyst-visible key findings.
    user:
        User object for audit logging.

    Returns
    -------
    bool
        True if the session was found and updated.
    """
    from ramdetect.case_management.database     import session_scope
    from ramdetect.case_management.models       import AnalysisSession
    from ramdetect.case_management.audit_service import write_audit_log

    artifact_json = json.dumps(artifact_summary or {}, default=str)

    with session_scope() as session:
        record = (session.query(AnalysisSession)
                  .filter_by(session_id=session_id).first())
        if record is None:
            logger.warning("complete_analysis_session: session_id=%r not found", session_id)
            return False

        record.final_verdict             = final_verdict
        record.rf_suspicious_probability = rf_suspicious_probability
        record.ae_mse                    = ae_mse
        record.artifact_summary_json     = artifact_json
        record.key_findings_count        = key_findings_count
        record.status                    = "completed"
        record.completed_at              = datetime.utcnow()
        record.error_message             = None

        case_pk = record.case_id
        session_pk = record.id
        workstation_id = getattr(record, "workstation_id", None)
        session.flush()

    write_audit_log(
        user,
        action      = "COMPLETE_ANALYSIS",
        entity_type = "AnalysisSession",
        entity_id   = session_id,
        case_id     = case_pk,
        analysis_session_id = session_pk,
        workstation_id = workstation_id,
        verdict = final_verdict,
        details     = {
            "session_id": session_id,
            "verdict":  final_verdict,
            "rf_prob":  rf_suspicious_probability,
            "ae_mse":   ae_mse,
            "findings": key_findings_count,
        },
    )
    logger.info("Analysis session completed: %s  verdict=%s", session_id, final_verdict)
    return True


def fail_analysis_session(
    session_id: str,
    error_message: str,
    user=None,
) -> bool:
    """Mark an AnalysisSession as failed.

    Parameters
    ----------
    session_id:
        Human-readable session identifier.
    error_message:
        Description of the failure.
    user:
        User object for audit logging.

    Returns
    -------
    bool
        True if the session was found and updated.
    """
    from ramdetect.case_management.database     import session_scope
    from ramdetect.case_management.models       import AnalysisSession
    from ramdetect.case_management.audit_service import write_audit_log

    with session_scope() as session:
        record = (session.query(AnalysisSession)
                  .filter_by(session_id=session_id).first())
        if record is None:
            logger.warning("fail_analysis_session: session_id=%r not found", session_id)
            return False

        record.status        = "failed"
        record.error_message = error_message
        record.completed_at  = datetime.utcnow()
        case_pk = record.case_id
        session_pk = record.id
        workstation_id = getattr(record, "workstation_id", None)
        session.flush()

    write_audit_log(
        user,
        action      = "FAIL_ANALYSIS",
        entity_type = "AnalysisSession",
        entity_id   = session_id,
        case_id     = case_pk,
        analysis_session_id = session_pk,
        workstation_id = workstation_id,
        details     = {"session_id": session_id, "error": error_message},
    )
    logger.warning("Analysis session failed: %s  error=%r", session_id, error_message)
    return True


def get_analysis_session_by_id(session_id: str):
    """Return the AnalysisSession with the given session_id, or None."""
    from ramdetect.case_management.database import session_scope
    from ramdetect.case_management.models   import AnalysisSession

    with session_scope() as session:
        record = (session.query(AnalysisSession)
                  .filter_by(session_id=session_id).first())
        if record:
            session.expunge(record)
        return record


def list_analysis_sessions_for_case(case_id: str) -> list:
    """Return all AnalysisSession objects for a case, newest first.
    
    Parameters
    ----------
    case_id:
        External case ID (e.g., "CASE-20260513-608FB8").
        Resolved to internal case.id before querying sessions.
    
    Returns
    -------
    list
        AnalysisSession objects ordered by started_at descending.
    """
    from ramdetect.case_management.database import session_scope
    from ramdetect.case_management.models   import Case, AnalysisSession

    with session_scope() as session:
        # Resolve external case_id to internal case.id (FK)
        case = session.query(Case).filter(Case.case_id == case_id).first()
        if case is None:
            return []
        
        # Query sessions using internal FK
        records = (session.query(AnalysisSession)
                   .filter(AnalysisSession.case_id == case.id)
                   .order_by(AnalysisSession.started_at.desc())
                   .all())
        for r in records:
            session.expunge(r)
        return records


def list_recent_analysis_sessions(limit: int = 10) -> list:
    """Return the most recent AnalysisSession records across all cases."""
    from ramdetect.case_management.database import session_scope
    from ramdetect.case_management.models   import AnalysisSession

    with session_scope() as session:
        records = (session.query(AnalysisSession)
                   .order_by(AnalysisSession.started_at.desc())
                   .limit(limit).all())
        for r in records:
            session.expunge(r)
        return records
