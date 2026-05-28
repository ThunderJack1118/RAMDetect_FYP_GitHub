"""
audit_service.py
----------------
Audit trail service for RAMDetect Case Management.

Design: audit_logs rows are append-only.  This module never updates or
deletes existing rows.  All service functions that mutate state call
write_audit_log() as the last step.
"""

import json
import logging
import socket
from datetime import datetime

logger = logging.getLogger(__name__)


def _get_machine_name() -> str:
    try:
        return socket.gethostname()
    except Exception:
        return "unknown"


def write_audit_log(
    user,
    action: str,
    entity_type: str | None = None,
    entity_id: str | None   = None,
    case_id: int | None     = None,
    workstation_id: int | None = None,
    analysis_session_id: int | None = None,
    report_id: int | None = None,
    repository_report_id: str | None = None,
    verdict: str | None = None,
    file_path: str | None = None,
    file_name: str | None = None,
    file_hash: str | None = None,
    report_path: str | None = None,
    details: dict | None    = None,
    machine_name: str | None = None,
) -> None:
    """Insert one row into audit_logs.

    Parameters
    ----------
    user:
        Any object with .id and .username attributes (User ORM instance or
        a lightweight stub).  Pass None to record a system/anonymous action.
    action:
        Short uppercase string describing the action, e.g. 'CREATE_CASE',
        'REGISTER_EVIDENCE', 'COMPLETE_ANALYSIS'.
    entity_type:
        Optional type label for the affected entity, e.g. 'Case', 'Evidence'.
    entity_id:
        Optional string identifier for the affected entity row
        (use the human-readable ID such as case_id or evidence_id).
    case_id:
        Optional FK reference to cases.id for easy case-scoped filtering.
    details:
        Optional dict with extra context.  Stored as JSON.
    machine_name:
        Calling machine hostname.  Auto-detected if None.
    """
    from ramdetect.case_management.database import session_scope
    from ramdetect.case_management.models   import AuditLog

    if machine_name is None:
        machine_name = _get_machine_name()

    user_id  = getattr(user, "id",       None) if user else None
    username = getattr(user, "username", None) if user else None

    details_json = json.dumps(details, default=str) if details else None

    try:
        with session_scope() as session:
            log = AuditLog(
                user_id      = user_id,
                username     = username,
                action       = action,
                entity_type  = entity_type,
                entity_id    = str(entity_id) if entity_id is not None else None,
                case_id      = case_id,
                workstation_id = workstation_id,
                analysis_session_id = analysis_session_id,
                report_id = report_id,
                repository_report_id = repository_report_id,
                verdict = verdict,
                file_path = file_path,
                file_name = file_name,
                file_hash = file_hash,
                report_path = report_path,
                details_json = details_json,
                machine_name = machine_name,
                created_at   = datetime.utcnow(),
            )
            session.add(log)
    except Exception as exc:
        # Audit failures must never crash the application
        logger.error("Failed to write audit log: action=%r error=%s", action, exc)


def list_audit_logs(
    case_id: int | None    = None,
    username: str | None   = None,
    limit: int             = 200,
    offset: int            = 0,
):
    """Return a list of detached AuditLog objects.

    Parameters
    ----------
    case_id:
        Filter to logs for a specific case (uses cases.id FK).
    username:
        Filter to logs for a specific username (substring match).
    limit / offset:
        Pagination.
    """
    from ramdetect.case_management.database import session_scope
    from ramdetect.case_management.models   import AuditLog
    from sqlalchemy import desc

    with session_scope() as session:
        q = session.query(AuditLog)
        if case_id is not None:
            q = q.filter(AuditLog.case_id == case_id)
        if username:
            q = q.filter(AuditLog.username.ilike(f"%{username}%"))
        q = q.order_by(desc(AuditLog.created_at)).offset(offset).limit(limit)
        rows = q.all()
        for r in rows:
            session.expunge(r)
        return rows
