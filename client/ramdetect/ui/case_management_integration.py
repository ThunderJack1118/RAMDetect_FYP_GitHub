"""
case_management_integration.py
------------------------------
RAMDetect Phase 5 Activity/Admin integration.

Workflow:
    Login → Dashboard

Role behaviour:
    - Admin users see the Admin Console side panel on Dashboard, Activity
      Monitor, and Admin Management.
    - Analyst / Viewer users do not see the Admin Console side panel and use
      the normal RAMDetect workflow only.

Side panel is also hidden during operational scan workflow pages:
    Acquisition → Configuration → Realtime Analysis → Results

This preserves the original full-width RAMDetect scan workflow and prevents
non-admin users from accessing PTM monitoring screens.
"""

from __future__ import annotations

import logging
import socket
import traceback

from PyQt5.QtCore import QObject, pyqtSignal
from PyQt5.QtWidgets import QFrame, QHBoxLayout, QMainWindow, QMessageBox, QStackedWidget

logger = logging.getLogger(__name__)

PAGE_LOGIN = "cm_login"
PAGE_ACTIVITY = "activity_monitor"
PAGE_ADMIN = "admin_management"


class CaseManagementIntegration(QObject):
    user_logged_in = pyqtSignal(object)
    user_logged_out = pyqtSignal()

    def __init__(self, main_window: QMainWindow):
        super().__init__(main_window)
        self._mw = main_window
        self._auth = None
        self._pages: dict[str, object] = {}
        self._enabled = False
        self._shell: QFrame | None = None
        self._side_panel = None
        self._stack_ref: QStackedWidget | None = None
        self._offline_mode = bool(getattr(main_window, "offline_mode", False))

    def setup(self) -> None:
        try:
            if self._offline_mode:
                logger.info("Offline Local Mode active; Activity/Admin integration and login are skipped.")
                self._enabled = False
                return

            self._enabled = self._is_enabled()
            if not self._enabled:
                logger.info("Activity/Admin integration disabled.")
                return

            self._ensure_schema()
            self._create_bridge()
            self._create_pages()
            self._inject_into_stacked_widget()
            self._wrap_with_admin_shell()
            self._wire_signals()
            self._log_app_opened()
            logger.info("RAMDetect Activity/Admin integration setup complete.")
        except Exception:
            logger.error("Activity/Admin integration setup failed (non-fatal):\n%s", traceback.format_exc())
            try:
                QMessageBox.warning(
                    self._mw,
                    "Activity Monitoring Warning",
                    "Activity/Admin Monitoring could not initialise.\n"
                    "RAMDetect will still run normally.\n\nCheck the log for details.",
                )
            except Exception:
                pass
            self._enabled = False

    def startup_route(self) -> None:
        if self._offline_mode:
            self._navigate_to_dashboard()
            return
        if not self._enabled:
            return
        if self._require_login():
            self._set_admin_panel_visible(False)
            self.navigate_to(PAGE_LOGIN)
        else:
            self._navigate_to_dashboard()

    def shutdown(self) -> None:
        try:
            from ramdetect.case_management.activity_logger import ActivityLogger
            ActivityLogger.instance().log_app_closed()
        except Exception:
            pass

    def logout(self) -> None:
        if not self._enabled or self._auth is None:
            return

        self._auth.logout()
        self.user_logged_out.emit()

        page = self._pages.get(PAGE_LOGIN)
        if page is not None:
            for method_name in ("reset", "reset_form"):
                method = getattr(page, method_name, None)
                if callable(method):
                    method()
                    break

        self._set_admin_panel_visible(False)
        self.navigate_to(PAGE_LOGIN)

    @property
    def current_user(self):
        return None if self._auth is None else self._auth.current_user

    @property
    def is_authenticated(self) -> bool:
        return self._auth is not None and self._auth.is_authenticated

    @property
    def is_admin(self) -> bool:
        return self._is_admin_user()

    def _is_admin_user(self) -> bool:
        if self._auth is None or not getattr(self._auth, "is_authenticated", False):
            return False
        try:
            if self._auth.has_role("Admin", "admin"):
                return True
        except Exception:
            pass
        user = getattr(self._auth, "current_user", None)
        role = str(getattr(user, "role", "") or getattr(self._auth, "current_role", "") or "").strip().lower()
        return role == "admin"

    def navigate_to(self, page_key: str) -> None:
        if page_key in (PAGE_ACTIVITY, PAGE_ADMIN) and not self._is_admin_user():
            self._deny_admin_access()
            return

        page = self._pages.get(page_key)
        sw = self._stacked_widget()
        if page is None or sw is None:
            logger.warning("navigate_to: unavailable page %r", page_key)
            return
        idx = sw.indexOf(page)
        if idx >= 0:
            sw.setCurrentIndex(idx)

    # ── setup helpers ─────────────────────────────────────────────────────
    def _is_enabled(self) -> bool:
        try:
            from utils.config import get_config
            cfg = get_config()
            return bool(cfg.get("activity_monitoring.enabled", cfg.get("case_management.enabled", True)))
        except Exception:
            try:
                from ramdetect.utils.config import get_config
                cfg = get_config()
                return bool(cfg.get("activity_monitoring.enabled", cfg.get("case_management.enabled", True)))
            except Exception:
                return True

    def _require_login(self) -> bool:
        try:
            from utils.config import get_config
            cfg = get_config()
            return bool(cfg.get("activity_monitoring.require_login", cfg.get("case_management.require_login", True)))
        except Exception:
            try:
                from ramdetect.utils.config import get_config
                cfg = get_config()
                return bool(cfg.get("activity_monitoring.require_login", cfg.get("case_management.require_login", True)))
            except Exception:
                return True

    def _ensure_schema(self) -> None:
        try:
            from ramdetect.case_management.activity_logger import ensure_audit_log_columns
            ensure_audit_log_columns()
        except Exception:
            pass
        try:
            from ramdetect.case_management.workstation_service import ensure_workstation_schema
            ensure_workstation_schema()
        except Exception:
            pass

    def _create_bridge(self) -> None:
        try:
            from ui.bridge.auth_bridge import AuthBridge
        except ModuleNotFoundError:
            from ramdetect.ui.bridge.auth_bridge import AuthBridge
        self._auth = AuthBridge.instance()

    def _create_pages(self) -> None:
        try:
            from ui.pages.login import LoginPage
            from ui.pages.activity_monitor import ActivityMonitorPage
            from ui.pages.admin_management import AdminManagementPage
        except ModuleNotFoundError:
            from ramdetect.ui.pages.login import LoginPage
            from ramdetect.ui.pages.activity_monitor import ActivityMonitorPage
            from ramdetect.ui.pages.admin_management import AdminManagementPage

        login_page = LoginPage(parent=self._mw)
        login_page.set_auth_bridge(self._auth)

        activity_page = ActivityMonitorPage(parent=self._mw)
        activity_page.set_auth_bridge(self._auth)

        admin_page = AdminManagementPage(parent=self._mw)
        admin_page.set_auth_bridge(self._auth)

        self._pages = {
            PAGE_LOGIN: login_page,
            PAGE_ACTIVITY: activity_page,
            PAGE_ADMIN: admin_page,
        }

    def _inject_into_stacked_widget(self) -> None:
        sw = self._stacked_widget()
        if sw is None:
            raise RuntimeError("Cannot find MainWindow QStackedWidget")

        for page in self._pages.values():
            if sw.indexOf(page) < 0:
                sw.addWidget(page)

    def _wrap_with_admin_shell(self) -> None:
        if self._shell is not None:
            return

        sw = self._stacked_widget()
        if sw is None:
            raise RuntimeError("Cannot wrap UI because QStackedWidget was not found")
        self._stack_ref = sw

        try:
            from ui.widgets.admin_side_panel import AdminSidePanel
        except ModuleNotFoundError:
            from ramdetect.ui.widgets.admin_side_panel import AdminSidePanel

        current_central = self._mw.centralWidget()
        if current_central is sw and hasattr(self._mw, "takeCentralWidget"):
            self._mw.takeCentralWidget()
        else:
            sw.setParent(None)

        self._side_panel = AdminSidePanel(parent=self._mw)
        self._side_panel.dashboard_requested.connect(self._navigate_to_dashboard)
        self._side_panel.activity_requested.connect(self._navigate_to_activity_monitor)
        self._side_panel.admin_requested.connect(self._navigate_to_admin_management)
        self._side_panel.logout_requested.connect(self.logout)

        self._shell = QFrame()
        self._shell.setObjectName("AdminShell")
        self._shell.setStyleSheet("QFrame#AdminShell { background: #0f172a; border: none; }")

        row = QHBoxLayout(self._shell)
        row.setContentsMargins(0, 0, 0, 0)
        row.setSpacing(0)
        row.addWidget(self._side_panel)
        row.addWidget(sw, stretch=1)

        self._mw.setCentralWidget(self._shell)

        try:
            self._mw.stacked_widget = sw
            self._mw._stack = sw
        except Exception:
            pass

        try:
            sw.currentChanged.connect(self._on_stack_page_changed)
        except Exception:
            pass

        self._sync_panel_visibility()

    def _wire_signals(self) -> None:
        login_page = self._pages.get(PAGE_LOGIN)
        if login_page is not None:
            login_page.login_successful.connect(self._on_login_success)

    # ── navigation ────────────────────────────────────────────────────────
    def _on_login_success(self, user_obj) -> None:
        self.user_logged_in.emit(user_obj)

        username = getattr(user_obj, "username", "unknown")
        role = getattr(user_obj, "role", "unknown")
        if self._side_panel is not None:
            self._side_panel.set_user(username, role, self._machine_name())

        # Both Admin and Analyst/Viewer start from the normal Dashboard.
        # The side panel is only made visible later if the user is Admin.
        self._navigate_to_dashboard()
        self._sync_panel_visibility()

    def _navigate_to_dashboard(self) -> None:
        self._navigate_existing("dashboard", "dashboard")
        self._sync_panel_visibility()

    def _navigate_to_activity_monitor(self) -> None:
        if not self._is_admin_user():
            self._deny_admin_access()
            return
        page = self._pages.get(PAGE_ACTIVITY)
        if page is not None and hasattr(page, "refresh"):
            try:
                page.refresh()
            except Exception:
                pass
        self.navigate_to(PAGE_ACTIVITY)
        self._set_active_nav("activity")
        self._sync_panel_visibility()

    def _navigate_to_admin_management(self) -> None:
        if not self._is_admin_user():
            self._deny_admin_access()
            return
        page = self._pages.get(PAGE_ADMIN)
        if page is not None and hasattr(page, "refresh"):
            try:
                page.refresh()
            except Exception:
                pass
        self.navigate_to(PAGE_ADMIN)
        self._set_active_nav("admin")
        self._sync_panel_visibility()

    def _navigate_existing(self, page_name: str, nav_key: str | None = None) -> None:
        try:
            method = getattr(self._mw, "navigate_to", None)
            if callable(method):
                method(page_name)
            else:
                page_map = getattr(self._mw, "PAGE_MAP", {})
                idx = page_map.get(page_name)
                sw = self._stacked_widget()
                if sw is not None and idx is not None:
                    sw.setCurrentIndex(idx)

            if nav_key:
                self._set_active_nav(nav_key)
        except Exception as exc:
            logger.warning("Could not navigate to %s: %s", page_name, exc)

    def _on_stack_page_changed(self, index: int) -> None:
        self._sync_panel_visibility(index)

    def _sync_panel_visibility(self, index: int | None = None) -> None:
        sw = self._stacked_widget()
        if sw is None:
            return
        if index is None:
            index = sw.currentIndex()

        show_panel = False

        # Original Dashboard page.
        try:
            dashboard_idx = getattr(self._mw, "PAGE_MAP", {}).get("dashboard")
            if dashboard_idx is not None and index == int(dashboard_idx):
                show_panel = True
                self._set_active_nav("dashboard")
        except Exception:
            pass

        # Injected admin pages.
        try:
            activity_page = self._pages.get(PAGE_ACTIVITY)
            if activity_page is not None and index == sw.indexOf(activity_page):
                show_panel = True
                self._set_active_nav("activity")
        except Exception:
            pass

        try:
            admin_page = self._pages.get(PAGE_ADMIN)
            if admin_page is not None and index == sw.indexOf(admin_page):
                show_panel = True
                self._set_active_nav("admin")
        except Exception:
            pass

        # Admin Console side panel is intentionally admin-only. Analyst/Viewer
        # accounts can still use the original RAMDetect pages, but cannot see or
        # navigate to monitoring/admin pages.
        self._set_admin_panel_visible(show_panel and self.is_authenticated and self._is_admin_user())

    def _deny_admin_access(self) -> None:
        try:
            QMessageBox.warning(
                self._mw,
                "Administrator Access Required",
                "Only Admin accounts can access Activity Monitor and Admin Management.",
            )
        except Exception:
            pass
        self._set_admin_panel_visible(False)
        self._navigate_existing("dashboard", None)

    def _set_active_nav(self, key: str) -> None:
        if self._side_panel is not None and hasattr(self._side_panel, "set_active"):
            self._side_panel.set_active(key)

    def _set_admin_panel_visible(self, visible: bool) -> None:
        if self._side_panel is not None:
            self._side_panel.setVisible(bool(visible))

    def _log_app_opened(self) -> None:
        try:
            from ramdetect.case_management.activity_logger import ActivityLogger
            ActivityLogger.instance().log_app_opened()
        except Exception:
            pass

    def _stacked_widget(self) -> QStackedWidget | None:
        if self._stack_ref is not None:
            return self._stack_ref

        for attr in ("stacked_widget", "_stack", "stack", "pages", "pages_widget"):
            obj = getattr(self._mw, attr, None)
            if isinstance(obj, QStackedWidget):
                self._stack_ref = obj
                return obj

        try:
            found = self._mw.findChild(QStackedWidget)
            if isinstance(found, QStackedWidget):
                self._stack_ref = found
                return found
        except Exception:
            pass
        return None

    @staticmethod
    def _machine_name() -> str:
        try:
            return socket.gethostname()
        except Exception:
            return "unknown"
