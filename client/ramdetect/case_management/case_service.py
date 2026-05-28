"""
case_service.py
---------------
Case management service for RAMDetect.

Responsibilities
----------------
  - Create, read, list, and update forensic cases.
  - Add analyst notes to cases.
  - Write audit logs for every mutation.

Case ID format: CASE-YYYYMMDD-NNNN  (auto-generated, collision-safe)
"""

import logging
import uuid
from datetime import datetime

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _generate_case_id() -> str:
    """Return a unique human-readable case identifier."""
    date_part = datetime.utcnow().strftime("%Y%m%d")
    short_uid = uuid.uuid4().hex[:6].upper()
    return f"CASE-{date_part}-{short_uid}"


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def create_case(
    title: str,
    description: str          = "",
    severity: str             = "Medium",
    incident_type: str        = "",
    affected_host: str        = "",
    department: str           = "",
    created_by_user_id: int | None = None,
    assigned_to_user_id: int | None = None,
    user=None,
) -> "Case":
    """Create a new forensic case.

    Parameters
    ----------
    title:
        Short descriptive title.
    description:
        Free-text summary of the incident.
    severity:
        Critical | High | Medium | Low | Informational
    incident_type:
        E.g. 'Malware Infection', 'Ransomware', 'Process Injection'.
    affected_host:
        Hostname / IP of the affected machine.
    department:
        Owning department or team.
    created_by_user_id:
        FK to users.id of the creating analyst.
    assigned_to_user_id:
        FK to users.id of the responsible analyst.
    user:
        User object for audit logging (may be None).

    Returns
    -------
    Case
        The newly created, detached ORM instance.
    """
    from ramdetect.case_management.database     import session_scope
    from ramdetect.case_management.models       import Case
    from ramdetect.case_management.audit_service import write_audit_log

    case_id = _generate_case_id()

    with session_scope() as session:
        case = Case(
            case_id             = case_id,
            title               = title,
            description         = description,
            severity            = severity,
            status              = "Open",
            incident_type       = incident_type,
            affected_host       = affected_host,
            department          = department,
            created_by_user_id  = created_by_user_id,
            assigned_to_user_id = assigned_to_user_id,
        )
        session.add(case)
        session.flush()                     # get the auto-increment id
        session.refresh(case)
        session.expunge(case)

    write_audit_log(
        user,
        action      = "CREATE_CASE",
        entity_type = "Case",
        entity_id   = case_id,
        case_id     = case.id,
        details     = {"title": title, "severity": severity},
    )
    logger.info("Case created: %s – %s", case_id, title)
    return case


def get_case_by_case_id(case_id: str):
    """Return the Case with the given human-readable case_id, or None."""
    from ramdetect.case_management.database import session_scope
    from ramdetect.case_management.models   import Case

    with session_scope() as session:
        case = session.query(Case).filter_by(case_id=case_id).first()
        if case:
            session.expunge(case)
        return case


def get_case_by_id(pk: int):
    """Return the Case with the given primary-key id, or None."""
    from ramdetect.case_management.database import session_scope
    from ramdetect.case_management.models   import Case

    with session_scope() as session:
        case = session.query(Case).filter_by(id=pk).first()
        if case:
            session.expunge(case)
        return case


def list_cases(
    status: str | None  = None,
    search: str | None  = None,
    limit: int          = 200,
    offset: int         = 0,
):
    """Return a list of detached Case objects.

    Parameters
    ----------
    status:
        Filter by case status string (exact match), or None for all.
    search:
        Substring search across case_id, title, and affected_host.
    limit / offset:
        Pagination controls.
    """
    from ramdetect.case_management.database import session_scope
    from ramdetect.case_management.models   import Case
    from sqlalchemy import or_, desc

    with session_scope() as session:
        q = session.query(Case)
        if status:
            q = q.filter(Case.status == status)
        if search:
            pattern = f"%{search}%"
            q = q.filter(
                or_(
                    Case.case_id.ilike(pattern),
                    Case.title.ilike(pattern),
                    Case.affected_host.ilike(pattern),
                )
            )
        q = q.order_by(desc(Case.created_at)).offset(offset).limit(limit)
        cases = q.all()
        for c in cases:
            session.expunge(c)
        return cases


def update_case_status(
    case_id: str,
    new_status: str,
    user=None,
) -> bool:
    """Update the status of a case.

    Parameters
    ----------
    case_id:
        Human-readable case identifier (e.g. 'CASE-20240101-AB1234').
    new_status:
        Open | In Progress | Pending Review | Closed | Archived
    user:
        User object for audit logging.

    Returns
    -------
    bool
        True if the case was found and updated; False otherwise.
    """
    from ramdetect.case_management.database     import session_scope
    from ramdetect.case_management.models       import Case
    from ramdetect.case_management.audit_service import write_audit_log

    with session_scope() as session:
        case = session.query(Case).filter_by(case_id=case_id).first()
        if case is None:
            logger.warning("update_case_status: case_id=%r not found", case_id)
            return False

        old_status      = case.status
        case.status     = new_status
        case.updated_at = datetime.utcnow()

        if new_status == "Closed" and case.closed_at is None:
            case.closed_at = datetime.utcnow()

        pk = case.id
        session.expunge(case)

    write_audit_log(
        user,
        action      = "UPDATE_CASE_STATUS",
        entity_type = "Case",
        entity_id   = case_id,
        case_id     = pk,
        details     = {"old_status": old_status, "new_status": new_status},
    )
    logger.info("Case %s status: %s → %s", case_id, old_status, new_status)
    return True


def add_case_note(
    case_id: str,
    user_id: int,
    note_text: str,
    user=None,
) -> "CaseNote":
    """Append an analyst note to a case.

    Parameters
    ----------
    case_id:
        Human-readable case identifier.
    user_id:
        FK to users.id of the note author.
    note_text:
        The note content.
    user:
        User object for audit logging.

    Returns
    -------
    CaseNote
        The newly created, detached ORM instance.
    """
    from ramdetect.case_management.database     import session_scope
    from ramdetect.case_management.models       import Case, CaseNote
    from ramdetect.case_management.audit_service import write_audit_log

    with session_scope() as session:
        case = session.query(Case).filter_by(case_id=case_id).first()
        if case is None:
            raise ValueError(f"Case not found: {case_id!r}")

        note = CaseNote(
            case_id   = case.id,
            user_id   = user_id,
            note_text = note_text,
        )
        session.add(note)
        session.flush()
        session.refresh(note)
        case_pk = case.id
        session.expunge(note)

    write_audit_log(
        user,
        action      = "ADD_CASE_NOTE",
        entity_type = "CaseNote",
        entity_id   = case_id,
        case_id     = case_pk,
        details     = {"note_preview": note_text[:80]},
    )
    return note


def list_case_notes(case_id: str):
    """Return all CaseNote objects for a case, oldest first."""
    from ramdetect.case_management.database import session_scope
    from ramdetect.case_management.models   import Case, CaseNote

    with session_scope() as session:
        case = session.query(Case).filter_by(case_id=case_id).first()
        if case is None:
            return []
        notes = (session.query(CaseNote)
                 .filter_by(case_id=case.id)
                 .order_by(CaseNote.created_at.asc())
                 .all())
        for n in notes:
            session.expunge(n)
        return notes


def get_case_stats() -> dict:
    """Return aggregate counts for the dashboard summary.

    Returns
    -------
    dict with keys: total, open, in_progress, closed, archived, suspicious
    """
    from ramdetect.case_management.database import session_scope
    from ramdetect.case_management.models   import Case, AnalysisSession
    from sqlalchemy import func

    with session_scope() as session:
        total        = session.query(func.count(Case.id)).scalar() or 0
        open_count   = session.query(func.count(Case.id)).filter_by(status="Open").scalar() or 0
        in_progress  = session.query(func.count(Case.id)).filter_by(status="In Progress").scalar() or 0
        closed       = session.query(func.count(Case.id)).filter_by(status="Closed").scalar() or 0
        archived     = session.query(func.count(Case.id)).filter_by(status="Archived").scalar() or 0
        suspicious   = (session.query(func.count(AnalysisSession.id))
                        .filter_by(final_verdict="SUSPICIOUS").scalar() or 0)

    return {
        "total":       total,
        "open":        open_count,
        "in_progress": in_progress,
        "closed":      closed,
        "archived":    archived,
        "suspicious":  suspicious,
    }
