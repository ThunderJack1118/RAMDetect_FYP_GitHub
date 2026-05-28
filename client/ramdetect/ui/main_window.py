"""ui/main_window.py — Main QMainWindow with QStackedWidget"""

import logging
import os

from PyQt5.QtCore import QSize
from PyQt5.QtWidgets import QMainWindow, QStackedWidget

from ui.pages import (
    DashboardPage, AcquisitionPage, AnalysisConfigPage,
    RealtimeAnalysisPage, ResultsDashboardPage, ProcessExplorerPage,
    ArtifactsViewerPage, MLInsightsPage, ReportsPage, SettingsPage,
)

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
        # Public alias used by Activity Monitoring integration.
        self.stacked_widget = self._stack
        self.setCentralWidget(self._stack)

        self._pages = [
            DashboardPage(self),
            AcquisitionPage(self),
            AnalysisConfigPage(self),
            RealtimeAnalysisPage(self),
            ResultsDashboardPage(self),
            ProcessExplorerPage(self),
            ArtifactsViewerPage(self),
            MLInsightsPage(self),
            ReportsPage(self),
            SettingsPage(self),
        ]

        # Optional named aliases for integration/helper code.
        self.dashboard_page = self._pages[0]
        self.acquisition_page = self._pages[1]
        self.analysis_config_page = self._pages[2]
        self.realtime_analysis_page = self._pages[3]
        self.results_page = self._pages[4]
        self.reports_page = self._pages[8]
        self.settings_page = self._pages[9]

        for page in self._pages:
            self._stack.addWidget(page)

        self._apply_stylesheet()
        self.navigate_to("dashboard")

        if self.offline_mode:
            self.cm = None
            self._activate_offline_local_mode()
        else:
            # Activity Monitoring integration.
            # Non-fatal: if this fails, original RAMDetect GUI still works.
            try:
                from ui.case_management_integration import CaseManagementIntegration
                self.cm = CaseManagementIntegration(self)
                self.cm.setup()
                self.cm.startup_route()
            except Exception as exc:
                log.warning("Activity Monitoring setup failed: %s", exc)
                self.cm = None


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
        self._stack.setCurrentIndex(idx)

    def _apply_stylesheet(self):
        if os.path.exists(_QSS_PATH):
            with open(_QSS_PATH, encoding="utf-8") as f:
                self.setStyleSheet(f.read())

    def closeEvent(self, event):
        try:
            if getattr(self, "cm", None):
                self.cm.shutdown()
        except Exception:
            pass
        super().closeEvent(event)
