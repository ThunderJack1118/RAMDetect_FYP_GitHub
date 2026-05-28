"""
activity_logger.py
------------------
Phase 4/5 — Staff Activity Monitoring and Audit Trail for RAMDetect.

Tracks:
- app open/close
- login/logout
- dump/file actions
- analysis start/completion/failure
- report/export actions
- admin user/workstation management actions

This module is monitoring-only. It never changes ML verdict logic.
"""

from __future__ import annotations

import json
import logging
import os
import socket
from pathlib import Path
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional

log = logging.getLogger(__name__)


class Action(str, Enum):
    APP_OPENED = "APP_OPENED"
    APP_CLOSED = "APP_CLOSED"
    LOGIN_SUCCESS = "LOGIN_SUCCESS"
    LOGIN_FAILED = "LOGIN_FAILED"
    LOGOUT = "LOGOUT"

    DUMP_SELECTED = "DUMP_SELECTED"
    DUMP_ACQUIRED = "DUMP_ACQUIRED"
    DUMP_IMPORTED = "DUMP_IMPORTED"

    ANALYSIS_STARTED = "ANALYSIS_STARTED"
    ANALYSIS_COMPLETED = "ANALYSIS_COMPLETED"
    ANALYSIS_FAILED = "ANALYSIS_FAILED"
    RESULT_VIEWED = "RESULT_VIEWED"

    REPORT_GENERATED = "REPORT_GENERATED"
    REPORT_OPENED = "REPORT_OPENED"
    REPORT_DOWNLOADED = "REPORT_DOWNLOADED"
    PDF_EXPORTED = "PDF_EXPORTED"
    JSON_EXPORTED = "JSON_EXPORTED"
    CSV_EXPORTED = "CSV_EXPORTED"
    XLSX_EXPORTED = "XLSX_EXPORTED"
    WORKBOOK_EXPORTED = "WORKBOOK_EXPORTED"

    SETTINGS_OPENED = "SETTINGS_OPENED"
    SETTINGS_CHANGED = "SETTINGS_CHANGED"

    USER_CREATED = "USER_CREATED"
    USER_UPDATED = "USER_UPDATED"
    USER_ENABLED = "USER_ENABLED"
    USER_DISABLED = "USER_DISABLED"
    PASSWORD_RESET = "PASSWORD_RESET"

    WORKSTATION_REGISTERED = "WORKSTATION_REGISTERED"
    WORKSTATION_SEEN = "WORKSTATION_SEEN"
    WORKSTATION_TRUSTED = "WORKSTATION_TRUSTED"
    WORKSTATION_UNTRUSTED = "WORKSTATION_UNTRUSTED"
    WORKSTATION_BLOCKED = "WORKSTATION_BLOCKED"
    WORKSTATION_UNBLOCKED = "WORKSTATION_UNBLOCKED"
    WORKSTATION_NOTES_UPDATED = "WORKSTATION_NOTES_UPDATED"


FILE_ACCESS_ACTIONS = {
    Action.DUMP_SELECTED,
    Action.DUMP_ACQUIRED,
    Action.DUMP_IMPORTED,
    Action.REPORT_GENERATED,
    Action.REPORT_OPENED,
    Action.REPORT_DOWNLOADED,
    Action.PDF_EXPORTED,
    Action.JSON_EXPORTED,
    Action.CSV_EXPORTED,
    Action.XLSX_EXPORTED,
    Action.WORKBOOK_EXPORTED,
}

REPORT_ACTIONS = {
    Action.REPORT_GENERATED,
    Action.REPORT_OPENED,
    Action.REPORT_DOWNLOADED,
    Action.PDF_EXPORTED,
    Action.JSON_EXPORTED,
    Action.CSV_EXPORTED,
    Action.XLSX_EXPORTED,
    Action.WORKBOOK_EXPORTED,
}

ANALYSIS_ACTIONS = {
    Action.ANALYSIS_STARTED,
    Action.ANALYSIS_COMPLETED,
    Action.ANALYSIS_FAILED,
    Action.RESULT_VIEWED,
}

LOGIN_ACTIONS = {
    Action.LOGIN_SUCCESS,
    Action.LOGIN_FAILED,
    Action.LOGOUT,
    Action.APP_OPENED,
    Action.APP_CLOSED,
}

ADMIN_ACTIONS = {
    Action.USER_CREATED,
    Action.USER_UPDATED,
    Action.USER_ENABLED,
    Action.USER_DISABLED,
    Action.PASSWORD_RESET,
    Action.WORKSTATION_REGISTERED,
    Action.WORKSTATION_TRUSTED,
    Action.WORKSTATION_UNTRUSTED,
    Action.WORKSTATION_BLOCKED,
    Action.WORKSTATION_UNBLOCKED,
    Action.WORKSTATION_NOTES_UPDATED,
}


ARCHIVABLE_REPORT_ACTIONS = {
    Action.REPORT_GENERATED.value,
    Action.PDF_EXPORTED.value,
    Action.JSON_EXPORTED.value,
    Action.CSV_EXPORTED.value,
    Action.XLSX_EXPORTED.value,
    Action.WORKBOOK_EXPORTED.value,
}


class ActivityLogger:
    _inst: Optional["ActivityLogger"] = None

    @classmethod
    def instance(cls) -> "ActivityLogger":
        if cls._inst is None:
            cls._inst = cls()
        return cls._inst

    def __init__(self) -> None:
        self._user_id: Optional[int] = None
        self._username: str = "unknown"
        self._role: str = "unknown"
        self._machine_name: str = _get_machine_name()
        self._workstation_id: Optional[int] = None
        self._offline_mode = _offline_local_mode_enabled()
        self._db_available = False
        self._check_db()

    def set_user(self, user_id: Optional[int], username: str, role: str) -> None:
        self._user_id = user_id
        self._username = username or "unknown"
        self._role = role or "unknown"
        self._register_workstation()

    def clear_user(self) -> None:
        self._user_id = None
        self._username = "unknown"
        self._role = "unknown"
        self._register_workstation()

    @property
    def current_username(self) -> str:
        return self._username

    @property
    def current_user_id(self) -> Optional[int]:
        return self._user_id

    @property
    def current_role(self) -> str:
        return self._role

    @property
    def machine_name(self) -> str:
        return self._machine_name

    @property
    def workstation_id(self) -> Optional[int]:
        return self._workstation_id

    def log(
        self,
        action: Action | str,
        *,
        file_path: Optional[str] = None,
        file_name: Optional[str] = None,
        file_hash: Optional[str] = None,
        verdict: Optional[str] = None,
        report_path: Optional[str] = None,
        details: Optional[dict[str, Any]] = None,
        username_override: Optional[str] = None,
        user_id_override: Optional[int] = None,
        role_override: Optional[str] = None,
        analysis_session_id: Optional[int] = None,
        report_id: Optional[int] = None,
        repository_report_id: Optional[str] = None,
    ) -> bool:
        action_str = action.value if isinstance(action, Action) else str(action)
        username = username_override if username_override is not None else self._username
        user_id = user_id_override if user_id_override is not None else self._user_id
        role = role_override if role_override is not None else self._role

        payload = details.copy() if isinstance(details, dict) else {}
        payload.setdefault("machine", self._machine_name)
        if self._workstation_id is not None:
            payload.setdefault("workstation_id", self._workstation_id)
        if self._offline_mode:
            payload.setdefault("offline_local_mode", True)

        # For generated/exported reports, keep/upload an admin-accessible copy.
        if action_str in ARCHIVABLE_REPORT_ACTIONS:
            source_report = report_path or file_path
            if source_report:
                try:
                    from ramdetect.case_management.report_repository import archive_report_file
                    archive = archive_report_file(
                        source_report,
                        username=username,
                        role=role,
                        machine_name=self._machine_name,
                        workstation_id=self._workstation_id,
                        action=action_str,
                        verdict=verdict,
                        source_report_id=payload.get("report_id") or payload.get("source_report_id"),
                        source_session_id=payload.get("session_id") or payload.get("source_session_id"),
                        source_workstation_id=str(self._workstation_id or payload.get("workstation_id") or ""),
                        source_machine_id=self._machine_name,
                    )
                    if archive.get("success"):
                        payload.setdefault("original_report_path", archive.get("source_path"))
                        payload.setdefault("archived_report_path", archive.get("archive_path"))
                        payload.setdefault("repository_root", archive.get("repository_root"))
                        payload.setdefault("archive_sha256", archive.get("sha256"))
                        payload.setdefault("archive_size_bytes", archive.get("size_bytes"))
                        payload.setdefault("already_archived", archive.get("already_archived", False))
                        if archive.get("central_api_uploaded") and archive.get("central_api_uri"):
                            payload.setdefault("central_api_uri", archive.get("central_api_uri"))
                            payload.setdefault("central_api_report_id", archive.get("central_api_report_id"))
                            repository_report_id = repository_report_id or archive.get("central_api_report_id")
                            payload.setdefault("repository_source", "PTM Central API")
                            report_path = str(archive.get("central_api_uri") or report_path or "")
                        else:
                            payload.setdefault("repository_source", "Local Managed Repository")
                            report_path = str(archive.get("archive_path") or report_path or "")
                        file_hash = file_hash or archive.get("sha256")
                        file_name = file_name or os.path.basename(str(archive.get("archive_path") or source_report or "report"))
                    else:
                        payload.setdefault("archive_error", archive.get("error"))
                except Exception as exc:
                    payload.setdefault("archive_error", str(exc))

        details_json = json.dumps(payload, default=str) if payload else None
        local_audit_log_id: Optional[int] = None
        local_success = False

        log.info("[AUDIT] user=%s role=%s action=%s file=%s verdict=%s",
                 username, role, action_str, file_name or file_path or "-", verdict or "-")

        if not self._db_available:
            self._check_db()

        if self._db_available:
            try:
                from ramdetect.case_management.database import session_scope
                from ramdetect.case_management.models import AuditLog, AnalysisSession, Report

                # Best-effort resolution for ERD-clean nullable FKs. Old callers may
                # only provide business identifiers inside details_json. If not found,
                # keep NULL and preserve details_json as the audit source of truth.
                with session_scope() as db:
                    if analysis_session_id is None:
                        sid = payload.get("session_id") or payload.get("source_session_id")
                        if sid:
                            rec = db.query(AnalysisSession).filter(AnalysisSession.session_id == str(sid)).first()
                            if rec:
                                analysis_session_id = rec.id
                    if report_id is None:
                        rid = payload.get("report_id") or payload.get("source_report_id")
                        if rid:
                            rec = db.query(Report).filter(Report.report_id == str(rid)).first()
                            if rec:
                                report_id = rec.id
                    repository_report_id = repository_report_id or payload.get("central_api_report_id") or payload.get("repository_report_id")

                    entry = AuditLog(
                        user_id=user_id,
                        username=username,
                        role=role,
                        machine_name=self._machine_name,
                        workstation_id=self._workstation_id,
                        analysis_session_id=analysis_session_id,
                        report_id=report_id,
                        repository_report_id=str(repository_report_id) if repository_report_id else None,
                        action=action_str,
                        file_path=file_path,
                        file_name=file_name,
                        file_hash=file_hash,
                        verdict=(str(verdict).upper() if verdict else None),
                        report_path=report_path,
                        details_json=details_json,
                        timestamp=datetime.now(timezone.utc).replace(tzinfo=None),
                    )
                    db.add(entry)
                    db.flush()
                    local_audit_log_id = entry.id
                local_success = True
            except Exception as exc:
                log.warning("ActivityLogger DB write failed for %s: %s", action_str, exc)
                self._db_available = False

        central_success = self._upload_central_activity_event(
            action=action_str,
            username=username,
            user_id=user_id,
            role=role,
            file_path=file_path,
            file_name=file_name,
            file_hash=file_hash,
            verdict=verdict,
            report_path=report_path,
            details_json=details_json,
            analysis_session_id=analysis_session_id,
            report_id=report_id,
            repository_report_id=repository_report_id,
            local_audit_log_id=local_audit_log_id,
        )

        if not (local_success or central_success):
            self._write_offline_activity_event(
                action=action_str,
                username=username,
                user_id=user_id,
                role=role,
                file_path=file_path,
                file_name=file_name,
                file_hash=file_hash,
                verdict=verdict,
                report_path=report_path,
                details_json=details_json,
                analysis_session_id=analysis_session_id,
                report_id=report_id,
                repository_report_id=repository_report_id,
            )
            return True

        return True


    def _write_offline_activity_event(
        self,
        *,
        action: str,
        username: str,
        user_id: Optional[int],
        role: str,
        file_path: Optional[str],
        file_name: Optional[str],
        file_hash: Optional[str],
        verdict: Optional[str],
        report_path: Optional[str],
        details_json: Optional[str],
        analysis_session_id: Optional[int],
        report_id: Optional[int],
        repository_report_id: Optional[str],
    ) -> None:
        """Persist best-effort local activity when PostgreSQL/PTM is unavailable."""
        try:
            logs_dir = _project_root() / "logs"
            logs_dir.mkdir(parents=True, exist_ok=True)
            event = {
                "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "offline_local_mode": True,
                "username": username or "Local Analyst",
                "user_id": user_id,
                "role": role or "Analyst",
                "machine_name": self._machine_name,
                "workstation_id": self._workstation_id,
                "action": action,
                "file_path": file_path or "",
                "file_name": file_name or "",
                "file_hash": file_hash or "",
                "verdict": (str(verdict).upper() if verdict else ""),
                "report_path": report_path or "",
                "repository_report_id": repository_report_id or "",
                "analysis_session_id": analysis_session_id or "",
                "report_id": report_id or "",
                "details_json": details_json or "{}",
            }
            with (logs_dir / "offline_activity_queue.jsonl").open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(event, default=str) + "\n")
        except Exception as exc:
            log.debug("Could not write offline activity event %s: %s", action, exc)

    def _upload_central_activity_event(
        self,
        *,
        action: str,
        username: str,
        user_id: Optional[int],
        role: str,
        file_path: Optional[str],
        file_name: Optional[str],
        file_hash: Optional[str],
        verdict: Optional[str],
        report_path: Optional[str],
        details_json: Optional[str],
        analysis_session_id: Optional[int],
        report_id: Optional[int],
        repository_report_id: Optional[str],
        local_audit_log_id: Optional[int],
    ) -> bool:
        """Best-effort central activity sync to PTM Repository Server.

        This lets Admin Activity Monitor view activity from other workstations.
        Failure must never break the local RAMDetect workflow.
        """
        if self._offline_mode or _offline_local_mode_enabled():
            return False

        try:
            from ramdetect.case_management.report_repository import upload_activity_event
            event = {
                "local_audit_log_id": local_audit_log_id,
                "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "username": username,
                "user_id": user_id,
                "role": role,
                "machine_name": self._machine_name,
                "workstation_id": self._workstation_id,
                "action": action,
                "file_path": file_path or "",
                "file_name": file_name or "",
                "file_hash": file_hash or "",
                "verdict": (str(verdict).upper() if verdict else ""),
                "report_path": report_path or "",
                "repository_report_id": repository_report_id or "",
                "analysis_session_id": analysis_session_id or "",
                "report_id": report_id or "",
                "details_json": details_json or "{}",
            }
            result = upload_activity_event(event)
            if not result.get("success"):
                log.debug("Central activity sync skipped/failed for %s: %s", action, result.get("error"))
                return False
            return True
        except Exception as exc:
            log.debug("Central activity sync unavailable for %s: %s", action, exc)
            return False

    # Convenience helpers
    def log_login_success(self, username: str, user_id: int, role: str) -> None:
        self.set_user(user_id, username, role)
        self.log(Action.LOGIN_SUCCESS, username_override=username, user_id_override=user_id, role_override=role)

    def log_login_failed(self, username: str) -> None:
        self.log(Action.LOGIN_FAILED, username_override=username, user_id_override=None, role_override="unknown")

    def log_logout(self) -> None:
        self.log(Action.LOGOUT)
        self.clear_user()

    def log_app_opened(self) -> None:
        self._register_workstation()
        self.log(Action.APP_OPENED)

    def log_app_closed(self) -> None:
        self.log(Action.APP_CLOSED)

    def log_dump_selected(self, path: str) -> None:
        self.log(Action.DUMP_SELECTED, file_path=path, file_name=os.path.basename(path))

    def log_dump_acquired(self, path: str, file_hash: Optional[str] = None) -> None:
        self.log(Action.DUMP_ACQUIRED, file_path=path, file_name=os.path.basename(path), file_hash=file_hash)

    def log_dump_imported(self, path: str, file_hash: Optional[str] = None) -> None:
        self.log(Action.DUMP_IMPORTED, file_path=path, file_name=os.path.basename(path), file_hash=file_hash)

    def log_analysis_started(
        self,
        dump_name: Optional[str] = None,
        *,
        dump_path: Optional[str] = None,
        session_id: Optional[str] = None,
        session_file: Optional[str] = None,
    ) -> None:
        self.log(
            Action.ANALYSIS_STARTED,
            file_path=dump_path,
            file_name=dump_name,
            details={"dump": dump_name, "dump_path": dump_path, "session_id": session_id, "session_file": session_file},
        )

    def log_analysis_completed(
        self,
        dump_name: Optional[str] = None,
        verdict: Optional[str] = None,
        rf_score: Optional[float] = None,
        *,
        dump_path: Optional[str] = None,
        session_id: Optional[str] = None,
        session_file: Optional[str] = None,
        hybrid_score: Optional[float] = None,
    ) -> None:
        self.log(
            Action.ANALYSIS_COMPLETED,
            file_path=dump_path,
            file_name=dump_name,
            verdict=verdict,
            details={
                "dump": dump_name,
                "dump_path": dump_path,
                "rf_score": rf_score,
                "hybrid_score": hybrid_score,
                "threshold": 0.5,
                "session_id": session_id,
                "session_file": session_file,
            },
        )

    def log_analysis_failed(
        self,
        dump_name: Optional[str] = None,
        reason: Optional[str] = None,
        *,
        dump_path: Optional[str] = None,
        session_id: Optional[str] = None,
        session_file: Optional[str] = None,
    ) -> None:
        self.log(
            Action.ANALYSIS_FAILED,
            file_path=dump_path,
            file_name=dump_name,
            details={"dump": dump_name, "dump_path": dump_path, "reason": reason, "session_id": session_id, "session_file": session_file},
        )

    def log_result_viewed(self, dump_name: Optional[str] = None, verdict: Optional[str] = None) -> None:
        self.log(Action.RESULT_VIEWED, file_name=dump_name, verdict=verdict)

    def log_report_generated(self, path: str, fmt: str, verdict: Optional[str] = None) -> None:
        self.log(Action.REPORT_GENERATED, file_path=path, file_name=os.path.basename(path), report_path=path, verdict=verdict, details={"format": fmt})

    def log_report_opened(self, path: str) -> None:
        self.log(Action.REPORT_OPENED, file_path=path, file_name=os.path.basename(path), report_path=path)

    def log_report_downloaded(
        self,
        source_path: str,
        destination_path: str,
        file_hash: Optional[str] = None,
        verdict: Optional[str] = None,
        report_name: Optional[str] = None,
    ) -> None:
        """Log an admin download from the local/central report repository."""
        name = report_name or os.path.basename(destination_path or "") or os.path.basename(source_path or "") or "report"
        source = str(source_path or "")
        self.log(
            Action.REPORT_DOWNLOADED,
            file_path=source_path,
            file_name=name,
            file_hash=file_hash,
            report_path=source_path,
            verdict=(str(verdict).upper() if verdict else None),
            details={
                "repository_source": "PTM Central API" if source.lower().startswith("ramdetect-api://") else "Local Managed Repository",
                "source_path": source_path,
                "repository_report_id": source.split("//report/", 1)[1].split("/", 1)[0] if source.lower().startswith("ramdetect-api://report/") else None,
                "downloaded_to": destination_path,
                "downloaded_file": os.path.basename(destination_path or name),
            },
        )

    def log_pdf_exported(self, path: str, verdict: Optional[str] = None) -> None:
        self.log(Action.PDF_EXPORTED, file_path=path, file_name=os.path.basename(path), report_path=path, verdict=verdict)

    def log_json_exported(self, path: str, verdict: Optional[str] = None) -> None:
        self.log(Action.JSON_EXPORTED, file_path=path, file_name=os.path.basename(path), report_path=path, verdict=verdict)

    def log_csv_exported(self, path: str, export_mode: Optional[str] = None, verdict: Optional[str] = None) -> None:
        self.log(Action.CSV_EXPORTED, file_path=path, file_name=os.path.basename(path), report_path=path, verdict=verdict, details={"export_mode": export_mode})

    def log_xlsx_exported(self, path: str, export_mode: Optional[str] = "activity_monitor", verdict: Optional[str] = None) -> None:
        self.log(Action.XLSX_EXPORTED, file_path=path, file_name=os.path.basename(path), report_path=path, verdict=verdict, details={"export_mode": export_mode})

    def log_workbook_exported(self, path: str, export_mode: Optional[str] = "workbook", verdict: Optional[str] = None) -> None:
        """Log a multi-sheet workbook export such as Artifact Viewer All XLSX."""
        self.log(Action.WORKBOOK_EXPORTED, file_path=path, file_name=os.path.basename(path), report_path=path, verdict=verdict, details={"export_mode": export_mode})

    def log_settings_opened(self) -> None:
        self.log(Action.SETTINGS_OPENED)

    def log_settings_changed(self, changed_keys: Optional[list] = None) -> None:
        self.log(Action.SETTINGS_CHANGED, details={"changed_keys": changed_keys or []})

    def get_logs(self, *, action_filter: Optional[set] = None, limit: int = 500, username_filter: Optional[str] = None) -> list[dict]:
        # In strict PTM mode, Admin workstations read central activity events
        # from all RAMDetect clients. Local DB remains the fallback if the
        # central API is unavailable or has no matching records.
        try:
            from ramdetect.case_management.report_repository import (
                list_central_activity_events,
                repository_admin_api_enabled,
            )
            if repository_admin_api_enabled():
                central_rows = list_central_activity_events(
                    action_filter=action_filter,
                    username_filter=username_filter,
                    limit=limit,
                )
                if central_rows:
                    return central_rows[:limit]
        except Exception as exc:
            log.debug("Central activity list unavailable: %s", exc)

        if not self._db_available:
            self._check_db()
        if not self._db_available:
            return []

        try:
            from ramdetect.case_management.database import session_scope
            from ramdetect.case_management.models import AuditLog

            with session_scope() as db:
                q = db.query(AuditLog).order_by(AuditLog.timestamp.desc(), AuditLog.id.desc())
                if username_filter:
                    q = q.filter(AuditLog.username == username_filter)
                if action_filter:
                    q = q.filter(AuditLog.action.in_([a.value if isinstance(a, Action) else str(a) for a in action_filter]))
                else:
                    q = q.filter(AuditLog.action != "WORKSTATION_SEEN")
                rows = q.limit(limit).all()
                return [_row_to_dict(r) for r in rows]
        except Exception as exc:
            log.warning("ActivityLogger.get_logs failed: %s", exc)
            return []

    def _check_db(self) -> None:
        self._offline_mode = self._offline_mode or _offline_local_mode_enabled()
        if self._offline_mode:
            self._db_available = False
            return
        try:
            from ramdetect.case_management.database import get_engine
            from ramdetect.case_management.models import AuditLog  # noqa: F401
            get_engine()
            self._db_available = True
        except Exception:
            self._db_available = False

    def _register_workstation(self) -> None:
        if self._offline_mode or _offline_local_mode_enabled():
            self._workstation_id = None
            return
        try:
            from ramdetect.case_management.workstation_service import register_or_update_workstation
            ws = register_or_update_workstation(user_id=self._user_id, username=self._username, role=self._role)
            self._workstation_id = ws.get("id")
        except Exception as exc:
            log.debug("Workstation registration unavailable: %s", exc)



def _offline_local_mode_enabled() -> bool:
    return os.environ.get("RAMDETECT_OFFLINE_LOCAL_MODE", "").strip().lower() in {"1", "true", "yes", "on"}


def _project_root() -> Path:
    # __file__ = <project>/ramdetect/case_management/activity_logger.py
    return Path(__file__).resolve().parents[2]

def ensure_audit_log_columns() -> None:
    """Idempotently add activity-monitoring columns to existing audit_logs."""
    try:
        from sqlalchemy import inspect as sa_inspect, text
        from ramdetect.case_management.database import get_engine

        engine = get_engine()
        inspector = sa_inspect(engine)
        if "audit_logs" not in inspector.get_table_names():
            return

        existing = {c["name"] for c in inspector.get_columns("audit_logs")}
        new_cols = {
            "role": "TEXT",
            "machine_name": "TEXT",
            "workstation_id": "INTEGER",
            "analysis_session_id": "INTEGER",
            "report_id": "INTEGER",
            "repository_report_id": "TEXT",
            "file_path": "TEXT",
            "file_name": "TEXT",
            "file_hash": "TEXT",
            "verdict": "TEXT",
            "report_path": "TEXT",
            "details_json": "TEXT",
            "timestamp": "DATETIME",
        }
        with engine.connect() as conn:
            for col, dtype in new_cols.items():
                if col not in existing:
                    conn.execute(text(f"ALTER TABLE audit_logs ADD COLUMN {col} {dtype}"))
                    conn.commit()
                    log.info("audit_logs: added column %s", col)
    except Exception as exc:
        log.warning("ensure_audit_log_columns failed: %s", exc)


def _get_machine_name() -> str:
    try:
        return socket.gethostname()
    except Exception:
        return "unknown"


def _fmt_ts(ts) -> str:
    if ts is None:
        return ""
    if isinstance(ts, str):
        text = ts.strip()
        if "T" in text:
            return text.replace("T", " ").replace("Z", "")
        return text
    try:
        return ts.strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return str(ts)


def _row_to_dict(row) -> dict:
    return {
        "id": getattr(row, "id", None),
        "timestamp": _fmt_ts(getattr(row, "timestamp", None) or getattr(row, "created_at", None)),
        "username": getattr(row, "username", "") or "",
        "user_id": getattr(row, "user_id", None),
        "role": getattr(row, "role", "") or "",
        "machine_name": getattr(row, "machine_name", "") or "",
        "workstation_id": getattr(row, "workstation_id", None),
        "analysis_session_id": getattr(row, "analysis_session_id", None),
        "report_id": getattr(row, "report_id", None),
        "repository_report_id": getattr(row, "repository_report_id", "") or "",
        "action": getattr(row, "action", "") or "",
        "file_path": getattr(row, "file_path", "") or "",
        "file_name": getattr(row, "file_name", "") or "",
        "file_hash": getattr(row, "file_hash", "") or "",
        "verdict": getattr(row, "verdict", "") or "",
        "report_path": getattr(row, "report_path", "") or "",
        "details_json": getattr(row, "details_json", "") or "",
    }
