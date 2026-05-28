"""
auth_bridge.py
--------------
Authentication bridge for RAMDetect GUI.

Phase 5:
- keeps current authenticated user
- updates ActivityLogger user context
- auto-registers the workstation on successful login
"""

from __future__ import annotations

import logging
import socket
from types import SimpleNamespace

logger = logging.getLogger(__name__)


class AuthBridge:
    _instance = None

    @classmethod
    def instance(cls) -> "AuthBridge":
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def __init__(self):
        self._current_user = None
        self._offline_mode = False

    @property
    def current_user(self):
        return self._current_user

    @property
    def offline_mode(self) -> bool:
        return self._offline_mode

    @property
    def is_authenticated(self) -> bool:
        return self._current_user is not None

    @property
    def current_user_id(self) -> int | None:
        return getattr(self._current_user, "id", None)

    @property
    def current_username(self) -> str:
        return getattr(self._current_user, "username", "guest")

    @property
    def current_role(self) -> str:
        return getattr(self._current_user, "role", "guest")

    @property
    def is_admin(self) -> bool:
        if not self.has_role("Admin", "admin"):
            return False
        try:
            from ramdetect.case_management.report_repository import repository_admin_api_enabled
            return repository_admin_api_enabled()
        except Exception:
            return False



    def activate_offline_local_user(self, username: str = "Local Analyst") -> None:
        """Bypass central authentication for Offline Local Mode.

        The offline user is intentionally Analyst-only. This prevents Admin
        Management, central Activity Monitor, workstation controls, and PTM
        repository downloads from being exposed when the server is unreachable.
        """
        self._offline_mode = True
        self._current_user = SimpleNamespace(
            id=None,
            username=username,
            full_name=username,
            role="Analyst",
            is_active=True,
            offline_mode=True,
        )
        try:
            from ramdetect.case_management.activity_logger import ActivityLogger
            ActivityLogger.instance().set_user(None, username, "Analyst")
        except Exception:
            pass
        logger.info("Offline Local Mode user activated: %s (Analyst)", username)

    def login(self, username: str, password: str) -> tuple[bool, str]:
        from ramdetect.case_management.auth_service import (
            LOGIN_REQUIREMENTS_TEXT,
            authenticate_user,
            normalise_username,
            record_login_failure,
            record_login_success,
            validate_login_inputs,
        )

        machine = self._machine_name()
        username = normalise_username(username)

        ok, validation_message = validate_login_inputs(username, password)
        if not ok:
            reason = "Invalid login input format"
            try:
                record_login_failure(username, reason=reason, machine_name=machine)
            except Exception:
                pass
            try:
                from ramdetect.case_management.activity_logger import ActivityLogger
                ActivityLogger.instance().log_login_failed(username)
            except Exception:
                pass
            logger.warning("Login rejected by input policy for %r", username)
            return False, validation_message or LOGIN_REQUIREMENTS_TEXT

        user = authenticate_user(username, password)

        if user is None:
            reason = "Invalid username or password"
            try:
                record_login_failure(username, reason=reason, machine_name=machine)
            except Exception:
                pass
            try:
                from ramdetect.case_management.activity_logger import ActivityLogger
                ActivityLogger.instance().log_login_failed(username)
            except Exception:
                pass
            logger.warning("Login failed for %r", username)
            return False, "Login failed. Please check the credentials and required format.\n" + LOGIN_REQUIREMENTS_TEXT


        # Admin accounts require the PTM Repository Admin API token.
        # This prevents an analyst/client workstation from using an Admin account
        # when RAMDETECT_REPOSITORY_ADMIN_API_TOKEN is intentionally empty.
        if str(getattr(user, "role", "") or "").lower() == "admin":
            try:
                from ramdetect.case_management.report_repository import repository_admin_api_enabled
                admin_token_ready = repository_admin_api_enabled()
            except Exception as exc:
                logger.warning("Admin token check failed: %s", exc)
                admin_token_ready = False

            if not admin_token_ready:
                reason = (
                    "Admin login is blocked on this workstation because the PTM "
                    "admin repository token is not configured. Use the Admin installer "
                    "or set RAMDETECT_REPOSITORY_ADMIN_API_TOKEN."
                )
                try:
                    record_login_failure(username, reason=reason, machine_name=machine)
                except Exception:
                    pass
                try:
                    from ramdetect.case_management.activity_logger import ActivityLogger
                    ActivityLogger.instance().log_login_failed(username)
                except Exception:
                    pass
                logger.warning("Admin login denied for %r because admin repository token is missing", username)
                return False, reason


        # Admin login requires a configured PTM Repository Admin API token.
        # Analyst/client workstations intentionally keep this token empty.
        if str(getattr(user, "role", "") or "").lower() == "admin":
            try:
                from ramdetect.case_management.report_repository import repository_admin_api_enabled
                admin_token_ready = repository_admin_api_enabled()
            except Exception as exc:
                logger.warning("Admin token readiness check failed: %s", exc)
                admin_token_ready = False

            if not admin_token_ready:
                reason = (
                    "Admin login is blocked on this workstation because the PTM "
                    "admin repository token is not configured. Use the Admin installer "
                    "or configure RAMDETECT_REPOSITORY_ADMIN_API_TOKEN."
                )
                try:
                    record_login_failure(username, reason=reason, machine_name=machine)
                except Exception:
                    pass
                try:
                    from ramdetect.case_management.activity_logger import ActivityLogger
                    ActivityLogger.instance().log_login_failed(username)
                except Exception:
                    pass
                logger.warning("Admin login denied for %r because admin repository token is missing", username)
                return False, reason

        # Register/update this PC before finalising the login. If an admin has
        # blocked the workstation, deny access from this PC while still recording
        # the failed login attempt.
        workstation_id = None
        try:
            from ramdetect.case_management.workstation_service import register_or_update_workstation
            ws = register_or_update_workstation(user_id=user.id, username=user.username, role=user.role)
            workstation_id = ws.get("id")
            if ws.get("is_blocked"):
                reason = "This workstation is blocked by an administrator."
                try:
                    record_login_failure(username, reason=reason, machine_name=machine, workstation_id=workstation_id)
                except Exception:
                    pass
                try:
                    from ramdetect.case_management.activity_logger import ActivityLogger
                    ActivityLogger.instance().log_login_failed(username)
                except Exception:
                    pass
                logger.warning("Blocked workstation login denied for %r on %s", username, ws.get("hostname"))
                return False, reason
        except Exception as exc:
            logger.debug("Workstation registration before login finalisation skipped: %s", exc)

        self._current_user = user
        self._offline_mode = False

        try:
            record_login_success(user, machine_name=machine, workstation_id=workstation_id)
        except Exception as exc:
            logger.warning("record_login_success failed: %s", exc)

        try:
            from ramdetect.case_management.activity_logger import ActivityLogger
            ActivityLogger.instance().set_user(user.id, user.username, user.role)
            ActivityLogger.instance().log_login_success(user.username, user.id, user.role)
        except Exception as exc:
            logger.warning("ActivityLogger login context failed: %s", exc)

        logger.info("User logged in: %r (id=%s role=%s)", user.username, user.id, user.role)
        return True, ""

    def logout(self) -> None:
        if self._current_user is None:
            return

        user = self._current_user
        if self._offline_mode:
            try:
                from ramdetect.case_management.activity_logger import ActivityLogger
                ActivityLogger.instance().log_logout()
            except Exception:
                pass
            logger.info("Offline Local Mode user logged out: %r", getattr(user, "username", "Local Analyst"))
            self._current_user = None
            self._offline_mode = False
            return

        try:
            from ramdetect.case_management.auth_service import record_logout
            record_logout(user.id)
        except Exception as exc:
            logger.warning("record_logout failed: %s", exc)

        try:
            from ramdetect.case_management.activity_logger import ActivityLogger
            ActivityLogger.instance().log_logout()
        except Exception:
            pass

        logger.info("User logged out: %r", user.username)
        self._current_user = None

    def has_role(self, *roles: str) -> bool:
        if self._current_user is None:
            return False
        user_role = str(getattr(self._current_user, "role", "")).lower()
        return user_role in {str(r).lower() for r in roles}

    @staticmethod
    def _machine_name() -> str:
        try:
            return socket.gethostname()
        except Exception:
            return "unknown"
