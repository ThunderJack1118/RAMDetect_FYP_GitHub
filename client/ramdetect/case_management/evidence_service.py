"""
evidence_service.py
-------------------
Evidence registration service for RAMDetect Case Management.

Responsibilities
----------------
  - Register RAM dump files as evidence items linked to a case.
  - Calculate MD5 and SHA-256 hashes for integrity verification.
  - Append a chain-of-custody 'collected' entry on registration.
  - Write audit logs for every mutation.

Evidence ID format: EVID-YYYYMMDD-NNNNNN  (auto-generated)

Important: The dump file is NEVER stored in the database.
Only the file path, size, and cryptographic hashes are stored.
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

def _generate_evidence_id() -> str:
    date_part = datetime.utcnow().strftime("%Y%m%d")
    short_uid = uuid.uuid4().hex[:6].upper()
    return f"EVID-{date_part}-{short_uid}"


# ---------------------------------------------------------------------------
# Hash calculation
# ---------------------------------------------------------------------------

def calculate_md5_sha256(file_path: str) -> tuple[str, str]:
    """Return (md5_hex, sha256_hex) for the file at *file_path*.

    Reads the file in 8 MB chunks so large RAM dumps do not exhaust memory.

    Parameters
    ----------
    file_path:
        Absolute or relative path to the file.

    Returns
    -------
    tuple[str, str]
        (md5_hex, sha256_hex).  Both are empty strings on IO error.
    """
    md5_obj    = hashlib.md5()
    sha256_obj = hashlib.sha256()

    try:
        with open(file_path, "rb") as fh:
            chunk_size = 8 * 1024 * 1024     # 8 MB
            while True:
                chunk = fh.read(chunk_size)
                if not chunk:
                    break
                md5_obj.update(chunk)
                sha256_obj.update(chunk)
        return md5_obj.hexdigest(), sha256_obj.hexdigest()
    except OSError as exc:
        logger.error("Hash calculation failed for %r: %s", file_path, exc)
        return "", ""


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def register_evidence(
    case_id: str,
    file_path: str,
    acquisition_method: str        = "Unknown",
    collected_by_user_id: int | None = None,
    source_machine: str | None     = None,
    notes: str | None              = None,
    user=None,
    skip_hash: bool                = False,
) -> "EvidenceItem":
    """Register a RAM dump file as an evidence item for a case.

    Parameters
    ----------
    case_id:
        Human-readable case identifier (e.g. 'CASE-20240101-AB1234').
    file_path:
        Path to the dump file on the local filesystem.
    acquisition_method:
        DumpIt | Manual Upload | Existing File | Unknown
    collected_by_user_id:
        FK to users.id of the collecting analyst.
    source_machine:
        Hostname of the machine the dump was taken from.
    notes:
        Free-text acquisition notes.
    user:
        User object for audit logging.
    skip_hash:
        Set True to skip hash calculation (useful for very large files
        during testing or when hashes were pre-calculated externally).

    Returns
    -------
    EvidenceItem
        Detached ORM instance with md5 / sha256 populated.
    """
    from ramdetect.case_management.database     import session_scope
    from ramdetect.case_management.models       import Case, EvidenceItem
    from ramdetect.case_management.audit_service import write_audit_log

    # ── resolve case ──────────────────────────────────────────────────────
    with session_scope() as session:
        case = session.query(Case).filter_by(case_id=case_id).first()
        if case is None:
            raise ValueError(f"Case not found: {case_id!r}")
        case_pk = case.id

    # ── file metadata ─────────────────────────────────────────────────────
    abs_path  = os.path.abspath(file_path)
    filename  = os.path.basename(abs_path)
    file_size = None
    md5       = ""
    sha256    = ""

    try:
        file_size = os.path.getsize(abs_path)
    except OSError as exc:
        logger.warning("Could not stat file %r: %s", abs_path, exc)

    if not skip_hash:
        logger.info("Calculating hashes for %r (size=%s bytes)…", filename, file_size)
        md5, sha256 = calculate_md5_sha256(abs_path)
        logger.info("MD5=%s  SHA256=%s", md5, sha256)

    # ── database insert ───────────────────────────────────────────────────
    evidence_id = _generate_evidence_id()

    with session_scope() as session:
        item = EvidenceItem(
            evidence_id          = evidence_id,
            case_id              = case_pk,
            original_filename    = filename,
            stored_path          = abs_path,
            file_size            = file_size,
            md5                  = md5  or None,
            sha256               = sha256 or None,
            acquisition_method   = acquisition_method,
            source_machine       = source_machine,
            collected_by_user_id = collected_by_user_id,
            notes                = notes,
        )
        session.add(item)
        session.flush()
        session.refresh(item)
        item_pk = item.id
        session.expunge(item)

    # ── chain of custody ──────────────────────────────────────────────────
    _record_custody_event(
        case_pk        = case_pk,
        evidence_pk    = item_pk,
        action         = "collected",
        performed_by   = collected_by_user_id,
        hash_verified  = bool(sha256),
        notes          = f"Initial registration via {acquisition_method}",
    )

    # ── audit ─────────────────────────────────────────────────────────────
    write_audit_log(
        user,
        action      = "REGISTER_EVIDENCE",
        entity_type = "Evidence",
        entity_id   = evidence_id,
        case_id     = case_pk,
        details     = {
            "filename":           filename,
            "acquisition_method": acquisition_method,
            "file_size":          file_size,
            "md5":                md5,
            "sha256":             sha256,
        },
    )
    logger.info("Evidence registered: %s → %s", evidence_id, filename)

    # Reload and return the detached item
    return get_evidence_by_evidence_id(evidence_id)


def get_evidence_by_evidence_id(evidence_id: str):
    """Return the EvidenceItem with the given human-readable evidence_id."""
    from ramdetect.case_management.database import session_scope
    from ramdetect.case_management.models   import EvidenceItem

    with session_scope() as session:
        item = session.query(EvidenceItem).filter_by(evidence_id=evidence_id).first()
        if item:
            session.expunge(item)
        return item


def list_evidence_for_case(case_id: str) -> list:
    """Return all EvidenceItem objects for a case, newest first."""
    from ramdetect.case_management.database import session_scope
    from ramdetect.case_management.models   import Case, EvidenceItem

    with session_scope() as session:
        case = session.query(Case).filter_by(case_id=case_id).first()
        if case is None:
            return []
        items = (session.query(EvidenceItem)
                 .filter_by(case_id=case.id)
                 .order_by(EvidenceItem.collected_at.desc())
                 .all())
        for i in items:
            session.expunge(i)
        return items


def verify_evidence_hash(evidence_id: str, user=None) -> dict:
    """Re-hash the evidence file and compare against stored hashes.

    Returns
    -------
    dict with keys: match_md5, match_sha256, current_md5, current_sha256,
                    stored_md5, stored_sha256, file_accessible
    """
    from ramdetect.case_management.audit_service import write_audit_log

    item = get_evidence_by_evidence_id(evidence_id)
    if item is None:
        raise ValueError(f"Evidence not found: {evidence_id!r}")

    result = {
        "file_accessible": False,
        "match_md5":       False,
        "match_sha256":    False,
        "current_md5":     "",
        "current_sha256":  "",
        "stored_md5":      item.md5   or "",
        "stored_sha256":   item.sha256 or "",
    }

    if not os.path.exists(item.stored_path):
        logger.warning("Evidence file not accessible: %r", item.stored_path)
        write_audit_log(user, action="VERIFY_HASH_FAIL",
                        entity_type="Evidence", entity_id=evidence_id,
                        details={"reason": "file_not_found"})
        return result

    result["file_accessible"] = True
    current_md5, current_sha256 = calculate_md5_sha256(item.stored_path)
    result["current_md5"]    = current_md5
    result["current_sha256"] = current_sha256
    result["match_md5"]      = (current_md5    == item.md5)    if item.md5    else False
    result["match_sha256"]   = (current_sha256 == item.sha256) if item.sha256 else False

    _record_custody_event(
        case_pk       = item.case_id,
        evidence_pk   = item.id,
        action        = "hash_verified",
        performed_by  = getattr(user, "id", None),
        hash_verified = result["match_sha256"],
        notes         = f"SHA256 match: {result['match_sha256']}",
    )
    write_audit_log(
        user,
        action      = "VERIFY_HASH",
        entity_type = "Evidence",
        entity_id   = evidence_id,
        details     = result,
    )
    return result


# ---------------------------------------------------------------------------
# Chain-of-custody helper (internal use only)
# ---------------------------------------------------------------------------

def _record_custody_event(
    case_pk: int,
    evidence_pk: int,
    action: str,
    performed_by: int | None = None,
    to_user: int | None      = None,
    from_user: int | None    = None,
    hash_verified: bool      = False,
    notes: str | None        = None,
) -> None:
    from ramdetect.case_management.database import session_scope
    from ramdetect.case_management.models   import ChainOfCustody

    with session_scope() as session:
        entry = ChainOfCustody(
            case_id             = case_pk,
            evidence_id         = evidence_pk,
            action              = action,
            from_user_id        = from_user,
            to_user_id          = to_user,
            performed_by_user_id = performed_by,
            hash_verified       = hash_verified,
            notes               = notes,
        )
        session.add(entry)


def list_chain_of_custody(evidence_id: str) -> list:
    """Return all ChainOfCustody rows for an evidence item, oldest first."""
    from ramdetect.case_management.database import session_scope
    from ramdetect.case_management.models   import EvidenceItem, ChainOfCustody

    with session_scope() as session:
        item = session.query(EvidenceItem).filter_by(evidence_id=evidence_id).first()
        if item is None:
            return []
        rows = (session.query(ChainOfCustody)
                .filter_by(evidence_id=item.id)
                .order_by(ChainOfCustody.timestamp.asc())
                .all())
        for r in rows:
            session.expunge(r)
        return rows
