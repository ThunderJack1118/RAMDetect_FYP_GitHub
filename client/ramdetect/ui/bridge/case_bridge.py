"""
case_bridge.py
--------------
Case management bridge for RAMDetect GUI.

Wraps the service layer so that GUI pages interact through a single,
testable interface.  All calls are synchronous (suitable for PyQt5 threads
or direct calls from Qt slots).

Usage::

    from ramdetect.ui.bridge.case_bridge    import CaseBridge
    from ramdetect.ui.bridge.auth_bridge    import AuthBridge

    auth  = AuthBridge.instance()
    cases = CaseBridge(auth)

    new_case = cases.create_case(title="Suspicious Host", severity="High")
    case_list = cases.list_cases()
"""

import logging

logger = logging.getLogger(__name__)


class CaseBridge:
    """Bridge for all case-management operations used by the GUI."""

    def __init__(self, auth_bridge=None):
        """
        Parameters
        ----------
        auth_bridge:
            AuthBridge instance.  If None, AuthBridge.instance() is used.
        """
        if auth_bridge is None:
            from ramdetect.ui.bridge.auth_bridge import AuthBridge
            auth_bridge = AuthBridge.instance()
        self._auth = auth_bridge

    # ── convenience ───────────────────────────────────────────────────────
    @property
    def _user(self):
        return self._auth.current_user

    @property
    def _user_id(self) -> int | None:
        return self._auth.current_user_id

    # ── Cases ─────────────────────────────────────────────────────────────

    def create_case(
        self,
        title: str,
        description: str   = "",
        severity: str      = "Medium",
        incident_type: str = "",
        affected_host: str = "",
        department: str    = "",
    ):
        from ramdetect.case_management.case_service import create_case
        return create_case(
            title               = title,
            description         = description,
            severity            = severity,
            incident_type       = incident_type,
            affected_host       = affected_host,
            department          = department,
            created_by_user_id  = self._user_id,
            user                = self._user,
        )

    def list_cases(self, status: str | None = None, search: str | None = None):
        from ramdetect.case_management.case_service import list_cases
        return list_cases(status=status, search=search)

    def get_case(self, case_id: str):
        from ramdetect.case_management.case_service import get_case_by_case_id
        return get_case_by_case_id(case_id)

    def update_status(self, case_id: str, new_status: str) -> bool:
        from ramdetect.case_management.case_service import update_case_status
        return update_case_status(case_id, new_status, user=self._user)

    def add_note(self, case_id: str, note_text: str):
        from ramdetect.case_management.case_service import add_case_note
        return add_case_note(case_id, self._user_id, note_text, user=self._user)

    def list_notes(self, case_id: str):
        from ramdetect.case_management.case_service import list_case_notes
        return list_case_notes(case_id)

    def get_stats(self) -> dict:
        from ramdetect.case_management.case_service import get_case_stats
        return get_case_stats()

    # ── Evidence ──────────────────────────────────────────────────────────

    def register_evidence(
        self,
        case_id: str,
        file_path: str,
        acquisition_method: str = "Unknown",
        source_machine: str     = "",
        notes: str              = "",
        skip_hash: bool         = False,
    ):
        from ramdetect.case_management.evidence_service import register_evidence
        return register_evidence(
            case_id              = case_id,
            file_path            = file_path,
            acquisition_method   = acquisition_method,
            collected_by_user_id = self._user_id,
            source_machine       = source_machine or None,
            notes                = notes or None,
            user                 = self._user,
            skip_hash            = skip_hash,
        )

    def list_evidence(self, case_id: str):
        from ramdetect.case_management.evidence_service import list_evidence_for_case
        return list_evidence_for_case(case_id)

    def verify_evidence_hash(self, evidence_id: str) -> dict:
        from ramdetect.case_management.evidence_service import verify_evidence_hash
        return verify_evidence_hash(evidence_id, user=self._user)

    def list_chain_of_custody(self, evidence_id: str):
        from ramdetect.case_management.evidence_service import list_chain_of_custody
        return list_chain_of_custody(evidence_id)

    # ── Analysis sessions ─────────────────────────────────────────────────

    def create_analysis_session(
        self,
        dump_path: str,
        case_id: str | None     = None,
        evidence_id: str | None = None,
        selected_modules: list | None = None,
    ):
        from ramdetect.case_management.analysis_record_service import (
            create_analysis_session,
        )
        return create_analysis_session(
            dump_path        = dump_path,
            case_id          = case_id,
            evidence_id      = evidence_id,
            analyst_user_id  = self._user_id,
            selected_modules = selected_modules,
            user             = self._user,
        )

    def complete_analysis_session(
        self,
        session_id: str,
        final_verdict: str,
        rf_prob: float | None = None,
        ae_mse: float | None  = None,
        artifact_summary: dict | None = None,
        key_findings_count: int = 0,
    ) -> bool:
        from ramdetect.case_management.analysis_record_service import (
            complete_analysis_session,
        )
        return complete_analysis_session(
            session_id                 = session_id,
            final_verdict              = final_verdict,
            rf_suspicious_probability  = rf_prob,
            ae_mse                     = ae_mse,
            artifact_summary           = artifact_summary,
            key_findings_count         = key_findings_count,
            user                       = self._user,
        )

    def fail_analysis_session(self, session_id: str, error_message: str) -> bool:
        from ramdetect.case_management.analysis_record_service import (
            fail_analysis_session,
        )
        return fail_analysis_session(session_id, error_message, user=self._user)

    def list_analysis_sessions(self, case_id: str):
        from ramdetect.case_management.analysis_record_service import (
            list_analysis_sessions_for_case,
        )
        return list_analysis_sessions_for_case(case_id)

    def list_recent_sessions(self, limit: int = 10):
        from ramdetect.case_management.analysis_record_service import (
            list_recent_analysis_sessions,
        )
        return list_recent_analysis_sessions(limit=limit)

    # ── Reports ───────────────────────────────────────────────────────────

    def register_report(
        self,
        report_type: str,
        report_path: str,
        case_id: str | None             = None,
        analysis_session_id: str | None = None,
        verdict_snapshot: str | None    = None,
    ):
        from ramdetect.case_management.report_record_service import register_report
        return register_report(
            report_type          = report_type,
            report_path          = report_path,
            case_id              = case_id,
            analysis_session_id  = analysis_session_id,
            generated_by_user_id = self._user_id,
            verdict_snapshot     = verdict_snapshot,
            user                 = self._user,
        )

    def list_reports(self, case_id: str):
        from ramdetect.case_management.report_record_service import list_reports_for_case
        return list_reports_for_case(case_id)

    # ── Audit logs ────────────────────────────────────────────────────────

    def list_audit_logs(
        self,
        case_id: int | None  = None,
        username: str | None = None,
        limit: int           = 200,
    ):
        from ramdetect.case_management.audit_service import list_audit_logs
        return list_audit_logs(case_id=case_id, username=username, limit=limit)
