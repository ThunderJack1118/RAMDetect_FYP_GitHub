"""ui/main_window.py — Main QMainWindow with QStackedWidget"""

import logging
import os

from PyQt5.QtCore import QSize, Qt, QTimer
from PyQt5.QtWidgets import QMainWindow, QStackedWidget, QApplication, QWidget

from ui.theme import apply_theme as apply_ui_theme, current_theme, save_theme

_QSS_PATH = os.path.join(os.path.dirname(__file__), "resources", "styles.qss")
log = logging.getLogger(__name__)


class MainWindow(QMainWindow):
    PAGE_MAP = {
        "dashboard": 0,
        "acquisition": 1,
        "analysis_config": 2,
        "realtime_analysis": 3,
        "results": 4,
        "process_explorer": 5,
        "artifacts_viewer": 6,
        "ml_insights": 7,
        "reports": 8,
        "settings": 9,
    }
    PAGE_ORDER = [
        "dashboard", "acquisition", "analysis_config", "realtime_analysis",
        "results", "process_explorer", "artifacts_viewer", "ml_insights",
        "reports", "settings",
    ]
    PAGE_SPECS = {
        "dashboard": ("ui.pages.dashboard", "DashboardPage"),
        "acquisition": ("ui.pages.acquisition", "AcquisitionPage"),
        "analysis_config": ("ui.pages.analysis_config", "AnalysisConfigPage"),
        "realtime_analysis": ("ui.pages.realtime_analysis", "RealtimeAnalysisPage"),
        "results": ("ui.pages.results_dashboard", "ResultsDashboardPage"),
        "process_explorer": ("ui.pages.process_explorer", "ProcessExplorerPage"),
        "artifacts_viewer": ("ui.pages.artifacts_viewer", "ArtifactsViewerPage"),
        "ml_insights": ("ui.pages.ml_insights", "MLInsightsPage"),
        "reports": ("ui.pages.reports", "ReportsPage"),
        "settings": ("ui.pages.settings", "SettingsPage"),
    }

    def __init__(self, runtime_info: dict | None = None):
        super().__init__()
        self.runtime_info = runtime_info or {"mode": "online", "offline_mode": False}
        self.offline_mode = bool(self.runtime_info.get("offline_mode"))
        self.setWindowTitle("RAMDetect — Memory Forensics Analysis")
        if self.offline_mode:
            self.setWindowTitle("RAMDetect — Offline Local Mode (Analyst)")
        self.setMinimumSize(QSize(1200, 750))
        self.resize(1400, 900)

        self._stack = QStackedWidget()
        self._stack.setObjectName("MainStack")
        self._stack.setAttribute(Qt.WA_StyledBackground, True)
        # Public alias used by Activity Monitoring integration.
        self.stacked_widget = self._stack
        self.setCentralWidget(self._stack)

        # Heavy pages are created lazily. Earlier builds constructed every page
        # immediately after login, which made the first window opening slow and
        # sometimes looked like a crash on lower-spec machines. The stack keeps
        # lightweight placeholders so page indices remain stable.
        self._pages = [None] * len(self.PAGE_ORDER)
        self._page_widgets = []
        for page_name in self.PAGE_ORDER:
            placeholder = QWidget()
            placeholder.setObjectName(f"LazyPagePlaceholder_{page_name}")
            placeholder.setProperty("ramdetectPlaceholder", True)
            placeholder.setAttribute(Qt.WA_StyledBackground, True)
            self._page_widgets.append(placeholder)
            self._stack.addWidget(placeholder)

        self._apply_stylesheet()

        if self.offline_mode:
            # Offline Local Mode intentionally bypasses central login and opens
            # the normal Analyst workflow immediately.
            self._ensure_page("dashboard")
            self.navigate_to("dashboard")
            self.cm = None
            self._activate_offline_local_mode()
        else:
            # Online mode must not show Dashboard before authentication.  Leave
            # the lightweight placeholder visible while the login integration is
            # injected, preventing the brief Dashboard flash seen on startup.
            self.cm = None
            QTimer.singleShot(0, self._setup_case_management_integration)


    def _setup_case_management_integration(self) -> None:
        """Start Activity/Admin integration after the first page is visible."""
        if self.offline_mode:
            return
        if getattr(self, "cm", None) is not None:
            return
        try:
            from ui.case_management_integration import CaseManagementIntegration
            self.cm = CaseManagementIntegration(self)
            self.cm.setup()
            self.cm.startup_route()
            # If activity/login integration is disabled by configuration, fall
            # back to the normal Dashboard instead of leaving the startup
            # placeholder on screen.
            if not getattr(self.cm, "_enabled", False):
                self._ensure_page("dashboard")
                self.navigate_to("dashboard")
        except Exception as exc:
            log.warning("Activity Monitoring setup failed: %s", exc)
            self.cm = None
            self._ensure_page("dashboard")
            self.navigate_to("dashboard")


    def _activate_offline_local_mode(self) -> None:
        """Open RAMDetect directly as an Analyst-only local tool.

        Offline Local Mode bypasses central login because the PostgreSQL server
        is unavailable. It does not enable Admin Management, central Activity
        Monitor, or PTM repository download features.
        """
        reason = str(self.runtime_info.get("reason") or "server unavailable")
        log.warning("Offline Local Mode active: %s", reason)

        # Give lower layers a safe analyst context for best-effort local logging.
        try:
            from ui.bridge.auth_bridge import AuthBridge
            AuthBridge.instance().activate_offline_local_user()
        except Exception as exc:
            log.debug("Could not activate offline AuthBridge user: %s", exc)

        try:
            from ramdetect.case_management.activity_logger import ActivityLogger
            logger = ActivityLogger.instance()
            logger.set_user(None, "Local Analyst", "Analyst")
            logger.log_app_opened()
        except Exception as exc:
            log.debug("Offline activity logger unavailable: %s", exc)

        self.navigate_to("dashboard")

    def navigate_to(self, page_name: str):
        idx = self.PAGE_MAP.get(page_name)
        if idx is None:
            print(f"[MainWindow] Unknown page: {page_name!r}")
            return

        self._ensure_page(page_name)
        if self._stack.currentIndex() != idx:
            self._stack.setCurrentIndex(idx)

        # Refresh only if this page has not yet been styled for the active theme.
        # Calling apply_theme() on every navigation caused expensive table/card
        # rebuilds and made opening pages feel laggy.
        try:
            self._refresh_visible_theme(self.property("ramdetectTheme") or current_theme(), force=False)
        except Exception:
            pass

    def _ensure_page(self, page_name: str):
        """Create a page only when it is first needed."""
        idx = self.PAGE_MAP.get(page_name)
        if idx is None:
            return None
        if idx < len(self._pages) and self._pages[idx] is not None:
            return self._pages[idx]

        module_name, class_name = self.PAGE_SPECS[page_name]
        try:
            import importlib
            page_cls = getattr(importlib.import_module(module_name), class_name)
            page = page_cls(self)
        except Exception as exc:
            log.exception("Could not create page %s: %s", page_name, exc)
            return None

        old_widget = self._page_widgets[idx] if idx < len(self._page_widgets) else None
        if old_widget is not None:
            try:
                self._stack.removeWidget(old_widget)
                old_widget.deleteLater()
            except Exception:
                pass
        self._stack.insertWidget(idx, page)
        self._pages[idx] = page
        self._page_widgets[idx] = page
        return page

    @property
    def dashboard_page(self):
        return self._ensure_page("dashboard")

    @property
    def acquisition_page(self):
        return self._ensure_page("acquisition")

    @property
    def analysis_config_page(self):
        return self._ensure_page("analysis_config")

    @property
    def realtime_analysis_page(self):
        return self._ensure_page("realtime_analysis")

    @property
    def results_page(self):
        return self._ensure_page("results")

    @property
    def process_explorer_page(self):
        return self._ensure_page("process_explorer")

    @property
    def artifacts_viewer_page(self):
        return self._ensure_page("artifacts_viewer")

    @property
    def ml_insights_page(self):
        return self._ensure_page("ml_insights")

    @property
    def reports_page(self):
        return self._ensure_page("reports")

    @property
    def settings_page(self):
        return self._ensure_page("settings")

    def _apply_stylesheet(self):
        """Load the saved RAMDetect UI theme stylesheet.

        Phase 1 only changes presentation.  It does not touch acquisition,
        parser, ML, database, report, repository, dump-path, or offline-mode
        logic.
        """
        try:
            active = apply_ui_theme(QApplication.instance(), current_theme())
            self._set_theme_properties(active)
            self._refresh_visible_theme(active, force=True)
        except Exception as exc:
            log.warning("Could not load RAMDetect theme stylesheet: %s", exc)
            try:
                with open(_QSS_PATH, "r", encoding="utf-8") as f:
                    self.setStyleSheet(f.read())
            except Exception as fallback_exc:
                log.warning("Could not load fallback stylesheet: %s", fallback_exc)

    def apply_theme(self, theme: str):
        """Apply a user-selected UI theme from Settings.

        Previous builds refreshed every page in the QStackedWidget after each
        theme switch. That is visually safe but expensive because several pages
        rebuild tables, badges, and inline-styled widgets inside apply_theme().
        This version applies the global QSS once, then refreshes only the
        visible page. Hidden pages refresh lazily when the user navigates to
        them.
        """
        try:
            active = save_theme(theme)
            old_active = str(self.property("ramdetectTheme") or "").strip().lower()

            # Avoid a second repaint/repolish pass when the user clicks the
            # already-active theme option.
            if old_active == active:
                self._refresh_visible_theme(active, force=False)
                return active

            self.setUpdatesEnabled(False)
            try:
                apply_ui_theme(QApplication.instance(), active)
                self._set_theme_properties(active)
                self._refresh_visible_theme(active, force=True)
            finally:
                self.setUpdatesEnabled(True)
                self.update()
            return active
        except Exception as exc:
            try:
                self.setUpdatesEnabled(True)
            except Exception:
                pass
            log.warning("Could not apply RAMDetect UI theme: %s", exc)
            return current_theme()

    def _set_theme_properties(self, theme: str) -> None:
        """Store the active theme on the main window and stack only."""
        self.setProperty("ramdetectTheme", theme)
        if hasattr(self, "_stack"):
            self._stack.setProperty("ramdetectTheme", theme)
            # Do not unpolish/polish the whole stack here. QApplication QSS
            # already repolishes widgets, and forcing the full stack again is a
            # major source of theme-switch freezing.
            self._stack.update()

    def _refresh_visible_theme(self, theme: str | None = None, force: bool = False) -> None:
        """Refresh only the currently visible page after a theme change."""
        active = theme or current_theme()
        page = None
        try:
            page = self._stack.currentWidget() if hasattr(self, "_stack") else None
        except Exception:
            page = None

        if page is not None and bool(page.property("ramdetectPlaceholder")):
            return
        if page is not None and not force and page.property("ramdetectThemeApplied") == active:
            return

        roots = [page] if page is not None else []

        try:
            from ui.widgets.header_bar import HeaderBar
            for root in roots:
                for header in root.findChildren(HeaderBar):
                    try:
                        header.apply_theme(active)
                    except Exception:
                        pass
        except Exception:
            pass

        try:
            from ui.widgets.admin_side_panel import AdminSidePanel
            for root in roots:
                for panel in root.findChildren(AdminSidePanel):
                    try:
                        panel.apply_theme(active)
                    except Exception:
                        pass
        except Exception:
            pass

        if page is not None and hasattr(page, "apply_theme"):
            try:
                page.apply_theme(active)
            except Exception:
                pass
        if page is not None:
            try:
                page.setProperty("ramdetectThemeApplied", active)
            except Exception:
                pass
    def closeEvent(self, event):
        try:
            if getattr(self, "cm", None):
                self.cm.shutdown()
        except Exception:
            pass
        super().closeEvent(event)

