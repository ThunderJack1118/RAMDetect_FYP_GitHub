"""
activity_monitor.py
-------------------
Phase 6 — Staff Activity Monitor page for RAMDetect with PTM central report repository support.

This version exports ONE beautiful .xlsx workbook containing every Activity
Monitor tab, and lets Admin users open/download reports from the PTM central repository.

Workbook sheets:
- Summary
- Login History
- Analysis History
- File Access
- Report History
- Full Audit Trail

No ML, parser, FeatureMapper, RF threshold, Autoencoder, or verdict logic is touched.
"""

from __future__ import annotations

import logging
import os
import json
from datetime import datetime, timezone
from pathlib import Path
from ui.style_helpers import set_role, set_tone

from PyQt5.QtCore import Qt, QRectF, QSortFilterProxyModel, QTimer, pyqtSignal, QUrl
from PyQt5.QtGui import QColor, QDesktopServices, QFont, QStandardItem, QStandardItemModel, QBitmap, QPainter
from PyQt5.QtWidgets import (
    QAbstractItemView,
    QComboBox,
    QDialog,
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QTableView,
    QTabWidget,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

log = logging.getLogger(__name__)

_ACTION_COLOURS = {
    "LOGIN_SUCCESS": "#22c55e",
    "LOGIN_FAILED": "#ef4444",
    "LOGOUT": "#94a3b8",
    "APP_OPENED": "#38bdf8",
    "APP_CLOSED": "#64748b",
    "DUMP_SELECTED": "#f59e0b",
    "DUMP_ACQUIRED": "#f97316",
    "DUMP_IMPORTED": "#f97316",
    "ANALYSIS_STARTED": "#a78bfa",
    "ANALYSIS_COMPLETED": "#22c55e",
    "ANALYSIS_FAILED": "#ef4444",
    "RESULT_VIEWED": "#06b6d4",
    "REPORT_GENERATED": "#60a5fa",
    "REPORT_OPENED": "#60a5fa",
    "REPORT_DOWNLOADED": "#22c55e",
    "PDF_EXPORTED": "#3b82f6",
    "JSON_EXPORTED": "#2563eb",
    "CSV_EXPORTED": "#14b8a6",
    "XLSX_EXPORTED": "#06b6d4",
    "WORKBOOK_EXPORTED": "#06b6d4",
    "ACTIVITY_WORKBOOK_SAVED": "#06b6d4",
    "SETTINGS_OPENED": "#fb923c",
    "SETTINGS_CHANGED": "#ef4444",
}

_VERDICT_COLOURS = {
    "SUSPICIOUS": "#ef4444",
    "CLEAN": "#22c55e",
    "ERROR": "#f59e0b",
}



_ACTION_LABELS = {
    "LOGIN_SUCCESS": "Login Success",
    "LOGIN_FAILED": "Login Failed",
    "LOGOUT": "Logout",
    "APP_OPENED": "App Opened",
    "APP_CLOSED": "App Closed",
    "DUMP_SELECTED": "Dump Selected",
    "DUMP_ACQUIRED": "Dump Acquired",
    "DUMP_IMPORTED": "Dump Imported",
    "ANALYSIS_STARTED": "Analysis Started",
    "ANALYSIS_COMPLETED": "Analysis Completed",
    "ANALYSIS_FAILED": "Analysis Failed",
    "RESULT_VIEWED": "Result Viewed",
    "REPORT_GENERATED": "Report Generated",
    "REPORT_OPENED": "Report Opened",
    "REPORT_DOWNLOADED": "Report Downloaded",
    "PDF_EXPORTED": "PDF Exported",
    "JSON_EXPORTED": "JSON Exported",
    "CSV_EXPORTED": "CSV Exported",
    "XLSX_EXPORTED": "XLSX Exported",
    "WORKBOOK_EXPORTED": "Workbook Exported",
    "ACTIVITY_WORKBOOK_SAVED": "Activity Workbook Saved",
    "SETTINGS_OPENED": "Settings Opened",
    "SETTINGS_CHANGED": "Settings Changed",
    "USER_CREATED": "User Created",
    "USER_UPDATED": "User Updated",
    "USER_ENABLED": "User Enabled",
    "USER_DISABLED": "User Disabled",
    "PASSWORD_RESET": "Password Reset",
    "WORKSTATION_REGISTERED": "Workstation Registered",
    "WORKSTATION_TRUSTED": "Workstation Trusted",
    "WORKSTATION_UNTRUSTED": "Workstation Untrusted",
    "WORKSTATION_BLOCKED": "Workstation Blocked",
    "WORKSTATION_UNBLOCKED": "Workstation Unblocked",
    "WORKSTATION_NOTES_UPDATED": "Workstation Notes Updated",
    "SCAN_HISTORY": "Scan History",
}


def _friendly_action(action: str) -> str:
    return _ACTION_LABELS.get(str(action or ""), str(action or "").replace("_", " ").title())


def _shorten_middle(value: str, max_len: int = 72) -> str:
    """Shorten long paths for table display while keeping the full value in tooltip."""
    value = str(value or "")
    if len(value) <= max_len:
        return value
    keep_left = max(12, (max_len - 3) // 2)
    keep_right = max(18, max_len - keep_left - 3)
    return value[:keep_left] + "..." + value[-keep_right:]


def _normalise_timestamp(value: str) -> str:
    """Display stored UTC timestamps as local workstation time.

    RAMDetect activity records from PostgreSQL/PTM API are stored in UTC.
    The Activity Monitor should display them in the local workstation timezone,
    for example Malaysia time UTC+8, without changing the stored audit record.
    """
    text = str(value or "").strip()
    if not text:
        return ""

    try:
        candidate = text.strip()
        candidate = candidate.replace(" UTC", "+00:00").replace("Z", "+00:00")

        # Support both ISO format and database-style UTC strings:
        # 2026-05-29T05:16:52Z
        # 2026-05-29 05:16:52
        if "T" not in candidate and len(candidate) >= 19 and candidate[4:5] == "-" and candidate[7:8] == "-":
            candidate = candidate[:10] + "T" + candidate[11:]

        dt = datetime.fromisoformat(candidate)

        # Naive database timestamps are treated as UTC because RAMDetect audit
        # logging stores central activity time in UTC.
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)

        return dt.astimezone().strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        # Preserve a readable fallback if an old/legacy row has unusual format.
        return text.replace("T", " ").replace("Z", "")


def _sort_timestamp(value: str) -> str:
    """Stable sortable timestamp key for mixed local/central rows."""
    text = str(value or "").strip()
    if not text:
        return ""
    if "T" in text:
        return text
    # Convert local display form to ISO-like text for reverse string sorting.
    return text.replace(" ", "T")


def _is_central_report_uri(value: str) -> bool:
    return str(value or "").strip().lower().startswith("ramdetect-api://")


def _safe_json(raw: str) -> dict:
    try:
        data = json.loads(raw or "")
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _format_details_for_cell(raw: str) -> str:
    """Convert audit details JSON into a readable one-line summary."""
    raw = raw or ""
    if not raw.strip():
        return ""
    data = _safe_json(raw)
    if not data:
        return raw

    labels = {
        "machine": "Machine",
        "workstation_id": "Workstation ID",
        "machine_id": "Machine ID",
        "session_id": "Session ID",
        "session_file": "Session JSON",
        "dump": "Dump",
        "dump_path": "Dump Path",
        "reason": "Reason",
        "export_mode": "Export Mode",
        "format": "Format",
        "threshold": "Threshold",
        "rf_score": "RF Score",
        "hybrid_score": "Hybrid Score",
        "source": "Source",
        "repository_id": "Repository ID",
        "central_api_uri": "Central URI",
        "original_report_path": "Original Path",
        "archived_report_path": "Archive Path",
        "server_local_storage_path": "Server Path",
        "downloaded_to": "Downloaded To",
        "destination_path": "Downloaded To",
        "downloaded_file": "Downloaded File",
        "archive_sha256": "SHA-256",
        "sha256": "SHA-256",
        "size_bytes": "Size",
        "archive_size_bytes": "Size",
    }
    preferred = [
        "machine", "workstation_id", "session_id", "dump", "reason",
        "export_mode", "format", "downloaded_file", "downloaded_to", "destination_path",
        "repository_id", "source", "central_api_uri", "sha256", "archive_sha256",
        "size_bytes", "archive_size_bytes", "session_file", "dump_path",
        "original_report_path", "archived_report_path", "server_local_storage_path", "machine_id",
    ]

    parts: list[str] = []
    used: set[str] = set()
    for key in preferred:
        if key in data and data[key] not in (None, "", False):
            val = str(data[key])
            if key in {"session_file", "dump_path", "original_report_path", "archived_report_path", "server_local_storage_path", "downloaded_to", "destination_path", "central_api_uri"} and len(val) > 64:
                val = "…" + val[-61:]
            parts.append(f"{labels.get(key, key)}: {val}")
            used.add(key)

    for key, value in data.items():
        if key in used or value in (None, "", False):
            continue
        val = str(value)
        if len(val) > 64:
            val = val[:61] + "…"
        parts.append(f"{labels.get(key, key)}: {val}")

    return " | ".join(parts)



def _bold() -> QFont:
    f = QFont("Segoe UI", 9)
    f.setBold(True)
    return f


class _SummaryCard(QFrame):
    def __init__(self, title: str, value: str = "0", subtitle: str = "", parent=None):
        super().__init__(parent)
        self.setObjectName("ActivitySummaryCard")
        self.setMinimumHeight(78)
        self.setStyleSheet(_summary_card_qss())
        layout = QVBoxLayout(self)
        layout.setContentsMargins(14, 10, 14, 10)
        layout.setSpacing(2)

        self._title = QLabel(title)
        self._title.setFont(QFont("Segoe UI", 9, QFont.DemiBold))
        set_tone(self._title, _summary_title_tone())

        self._value = QLabel(value)
        self._value.setFont(QFont("Segoe UI", 20, QFont.Bold))
        set_tone(self._value, _summary_value_tone())

        self._subtitle = QLabel(subtitle)
        self._subtitle.setFont(QFont("Segoe UI", 8))
        set_tone(self._subtitle, _summary_subtitle_tone())

        layout.addWidget(self._title)
        layout.addWidget(self._value)
        layout.addWidget(self._subtitle)

    def set_value(self, value: int | str) -> None:
        self._value.setText(str(value))


class _DownloadSuccessDialog(QDialog):
    """Compact RAMDetect-themed success dialog with expandable full path."""

    def __init__(self, saved_path: str, display_name: str, parent=None):
        super().__init__(parent)
        self._saved_path = str(saved_path or "")
        self._details_visible = False
        self.setWindowTitle("Download Report - RAMDetect")
        self.setModal(True)
        self.setMinimumWidth(610)
        self.setMaximumWidth(760)
        self.setStyleSheet(_download_success_dialog_qss())

        root = QVBoxLayout(self)
        root.setContentsMargins(16, 16, 16, 14)
        root.setSpacing(12)

        top = QHBoxLayout()
        top.setSpacing(12)

        icon = QLabel("i")
        icon.setObjectName("InfoIcon")
        icon.setAlignment(Qt.AlignCenter)
        icon.setFixedSize(42, 42)
        top.addWidget(icon, 0, Qt.AlignTop)

        text_box = QVBoxLayout()
        text_box.setSpacing(8)

        title = QLabel("Report/export downloaded successfully.")
        title.setObjectName("DialogTitle")
        title.setWordWrap(True)
        text_box.addWidget(title)

        saved_as = QLabel("Saved as:")
        saved_as.setObjectName("DialogLabel")
        text_box.addWidget(saved_as)

        file_label = QLabel(display_name or Path(self._saved_path).name or "downloaded_report")
        file_label.setObjectName("FileNameLabel")
        file_label.setTextInteractionFlags(Qt.TextSelectableByMouse)
        file_label.setWordWrap(True)
        file_label.setToolTip(self._saved_path)
        text_box.addWidget(file_label)

        top.addLayout(text_box, 1)
        root.addLayout(top)

        self._details = QTextEdit()
        self._details.setObjectName("PathDetails")
        self._details.setReadOnly(True)
        self._details.setPlainText(self._saved_path)
        self._details.setFixedHeight(86)
        self._details.hide()
        root.addWidget(self._details)

        buttons = QHBoxLayout()
        buttons.addStretch()

        self._ok_btn = QPushButton("OK")
        self._ok_btn.setObjectName("DialogPrimaryButton")
        self._ok_btn.clicked.connect(self.accept)

        self._details_btn = QPushButton("Show Details...")
        self._details_btn.setObjectName("DialogSecondaryButton")
        self._details_btn.clicked.connect(self._toggle_details)

        buttons.addWidget(self._ok_btn)
        buttons.addWidget(self._details_btn)
        root.addLayout(buttons)

    def _toggle_details(self) -> None:
        self._details_visible = not self._details_visible
        self._details.setVisible(self._details_visible)
        self._details_btn.setText("Hide Details..." if self._details_visible else "Show Details...")
        self.adjustSize()



def _activity_default_text() -> str:
    return "#1e3a6e" if _is_light() else "#dbeafe"


class _LogTableModel(QStandardItemModel):
    def __init__(self, columns: list[tuple[str, str, int]], parent=None):
        super().__init__(parent)
        self.COLUMNS = columns
        self.setHorizontalHeaderLabels([title for _, title, _ in self.COLUMNS])

    def load_rows(self, rows: list[dict]) -> None:
        self.setRowCount(0)
        for row in rows:
            items: list[QStandardItem] = []
            for key, _, _ in self.COLUMNS:
                raw_val = str(row.get(key) or "")
                if key == "timestamp":
                    val = _normalise_timestamp(raw_val)
                elif key == "details_json":
                    val = _format_details_for_cell(raw_val)
                elif key == "action":
                    val = _friendly_action(raw_val)
                elif key == "verdict":
                    # Audit rows may store verdicts as "clean"/"suspicious" depending
                    # on the caller. Display them consistently in uppercase without
                    # changing the stored audit record.
                    val = raw_val.upper()
                elif key in {"file_path", "report_path", "session_file", "session_folder", "dump_path"}:
                    val = _shorten_middle(raw_val, 74)
                else:
                    val = raw_val
                item = QStandardItem(val)
                item.setEditable(False)
                item.setData(raw_val, Qt.UserRole)
                item.setToolTip(raw_val if raw_val else val)
                item.setForeground(QColor(_activity_default_text()))
                if key == "action":
                    item.setForeground(QColor(_ACTION_COLOURS.get(raw_val, _activity_default_text())))
                    item.setFont(_bold())
                elif key == "verdict" and val.upper() in _VERDICT_COLOURS:
                    item.setForeground(QColor(_VERDICT_COLOURS[val.upper()]))
                    item.setFont(_bold())
                items.append(item)
            self.appendRow(items)


def _admin_table_border_colour() -> str:
    return "#7fa7ea" if _is_light() else "#536684"


def _apply_rounded_table_mask(widget: QWidget, radius: int = 12) -> None:
    """Clip QTableView children to the same radius as the visible table border."""
    try:
        if widget is None or widget.width() <= 2 or widget.height() <= 2:
            return
        mask = QBitmap(widget.size())
        mask.fill(Qt.color0)
        painter = QPainter(mask)
        painter.setRenderHint(QPainter.Antialiasing, True)
        painter.setPen(Qt.NoPen)
        painter.setBrush(Qt.color1)
        painter.drawRoundedRect(mask.rect(), radius, radius)
        painter.end()
        widget.setMask(mask)
    except Exception:
        try:
            widget.clearMask()
        except Exception:
            pass


class _AdminTableBorderOverlay(QWidget):
    """Paint the rounded admin table border above the header/table children.

    QHeaderView and the table viewport are separate child widgets.  If the
    border is drawn only by QSS, those children can cover the outer edge and
    make the four rounded corners look missing.  This transparent overlay keeps
    the table border visible without changing table data or sorting behaviour.
    """

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setAttribute(Qt.WA_TransparentForMouseEvents, True)
        self.setAttribute(Qt.WA_TranslucentBackground, True)

    def paintEvent(self, event):
        # Do not custom-paint on a transparent child widget.  The table view QSS
        # now owns the visible border.  Painting here caused repeated Qt
        # "paintEngine / painter not active" warnings when pages were opened.
        return super().paintEvent(event)


class _RoundedLogTableView(QTableView):
    """QTableView with rounded clipping and a visible admin table outline."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._border_overlay = None

    def _sync_border_overlay(self):
        # Clip header/viewport/row painting to the table radius. This removes
        # sharp row/header rectangles at the rounded outer table corners without
        # using a custom paintEvent overlay.
        _apply_rounded_table_mask(self, 12)

    def resizeEvent(self, event):
        super().resizeEvent(event)
        self._sync_border_overlay()

    def showEvent(self, event):
        super().showEvent(event)
        self._sync_border_overlay()


class _LogTable(QWidget):
    row_activated = pyqtSignal(dict)

    def __init__(self, columns: list[tuple[str, str, int]], parent=None, stretch_last: bool = True):
        super().__init__(parent)
        self._columns = columns
        self._model = _LogTableModel(columns, self)
        self._proxy = QSortFilterProxyModel(self)
        self._proxy.setSourceModel(self._model)
        self._proxy.setFilterCaseSensitivity(Qt.CaseInsensitive)
        self._proxy.setFilterKeyColumn(-1)

        self._view = _RoundedLogTableView(self)
        self._view.setModel(self._proxy)
        self._view.setSelectionBehavior(QAbstractItemView.SelectRows)
        self._view.setSelectionMode(QAbstractItemView.SingleSelection)
        self._view.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self._view.setSortingEnabled(True)
        self._view.verticalHeader().setVisible(False)
        header = self._view.horizontalHeader()
        header.setStretchLastSection(False)
        header.setSectionResizeMode(QHeaderView.Fixed)
        self._view.setAlternatingRowColors(False)
        self._view.setWordWrap(False)
        self._view.setTextElideMode(Qt.ElideMiddle)
        self._view.setShowGrid(False)
        self._view.setFocusPolicy(Qt.NoFocus)
        self._view.setFrameShape(QFrame.NoFrame)
        self._view.setHorizontalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        self._view.setVerticalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        self._view.setStyleSheet(_table_qss())
        self._view.doubleClicked.connect(self._on_double_clicked)

        for i, (_, _, width) in enumerate(columns):
            self._view.setColumnWidth(i, width)
        if stretch_last and columns:
            header.setSectionResizeMode(len(columns) - 1, QHeaderView.Stretch)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(self._view)

    def load(self, rows: list[dict]) -> None:
        self._model.load_rows(rows)

    def set_filter(self, text: str) -> None:
        self._proxy.setFilterFixedString(text)

    def row_count(self) -> int:
        return self._proxy.rowCount()

    def export_rows(self) -> list[dict]:
        """Return currently visible rows after search/sort filtering."""
        headers = [title for _, title, _ in self._columns]
        rows: list[dict] = []
        for r in range(self._proxy.rowCount()):
            row: dict[str, str] = {}
            for c, header in enumerate(headers):
                value = self._proxy.index(r, c).data()
                row[header] = "" if value is None else str(value)
            rows.append(row)
        return rows

    def _row_dict_at_proxy_row(self, proxy_row: int) -> dict:
        headers = [title for _, title, _ in self._columns]
        row: dict[str, str] = {}
        for c, header in enumerate(headers):
            idx = self._proxy.index(proxy_row, c)
            raw = idx.data(Qt.UserRole)
            value = raw if raw not in (None, "") else idx.data()
            row[header] = "" if value is None else str(value)
        return row

    def selected_row(self) -> dict:
        selected = self._view.selectionModel().selectedRows()
        if not selected:
            return {}
        return self._row_dict_at_proxy_row(selected[0].row())

    def _on_double_clicked(self, index) -> None:
        if index.isValid():
            self.row_activated.emit(self._row_dict_at_proxy_row(index.row()))


class ActivityMonitorPage(QWidget):
    """Staff usage and audit-trail monitor."""

    LOGIN_COLUMNS = [
        ("timestamp", "Timestamp", 145),
        ("username", "User", 90),
        ("role", "Role", 80),
        ("machine_name", "Machine", 120),
        ("action", "Action", 145),
        ("details_json", "Details", 460),
    ]

    ANALYSIS_COLUMNS = [
        ("timestamp", "Timestamp", 140),
        ("username", "User", 85),
        ("role", "Role", 70),
        ("machine_name", "Machine", 115),
        ("action", "Action", 145),
        ("session_id", "Session ID", 95),
        ("file_name", "Dump File", 285),
        ("verdict", "Verdict", 105),
        ("hybrid_score", "Hybrid Score", 110),
        ("size", "Size", 80),
        ("session_file", "Session JSON", 320),
        ("session_folder", "Session Folder", 240),
    ]

    FILE_COLUMNS = [
        ("timestamp", "Timestamp", 145),
        ("username", "User", 90),
        ("machine_name", "Machine", 120),
        ("action", "Action", 145),
        ("file_name", "File Name", 240),
        ("file_path", "Path", 420),
        ("file_hash", "Hash", 220),
    ]

    REPORT_COLUMNS = [
        ("timestamp", "Timestamp", 140),
        ("username", "User", 90),
        ("machine_name", "Machine", 120),
        ("action", "Action", 145),
        ("file_name", "Report/File", 210),
        ("verdict", "Verdict", 90),
        ("report_path", "Report Path", 380),
    ]

    ALL_COLUMNS = [
        ("timestamp", "Timestamp", 145),
        ("username", "User", 90),
        ("role", "Role", 80),
        ("machine_name", "Machine", 120),
        ("action", "Action", 190),
        ("file_name", "File / Report", 220),
        ("verdict", "Verdict", 95),
        ("details_json", "Details", 460),
    ]

    def __init__(self, parent=None):
        super().__init__(parent)
        self._auth_bridge = None
        self._auto_refresh = True
        self._build_ui()
        self._schedule_refresh()

    def set_auth_bridge(self, bridge) -> None:
        self._auth_bridge = bridge
        self.refresh()

    def refresh(self) -> None:
        try:
            from ramdetect.case_management.activity_logger import (
                ActivityLogger,
                ANALYSIS_ACTIONS,
                FILE_ACCESS_ACTIONS,
                LOGIN_ACTIONS,
                REPORT_ACTIONS,
            )
            al = ActivityLogger.instance()
            username_filter = self._user_filter()

            login_rows = al.get_logs(action_filter=LOGIN_ACTIONS, username_filter=username_filter)
            # Analysis History is based on RAMDetect scan_history.json/full session snapshots,
            # so it matches the Dashboard Recent Analysis History rather than depending only
            # on audit_logs. Audit analysis events still remain visible in Full Audit Trail.
            analysis_rows = self._load_analysis_audit_rows(username_filter=username_filter)
            file_rows = al.get_logs(action_filter=FILE_ACCESS_ACTIONS, username_filter=username_filter)
            file_rows = self._merge_analysis_dump_access_rows(file_rows, analysis_rows)
            report_rows = al.get_logs(action_filter=REPORT_ACTIONS, username_filter=username_filter)
            report_rows = self._merge_shared_repository_rows(report_rows, username_filter=username_filter)
            all_rows = al.get_logs(username_filter=username_filter)

            self._tab_login.load(login_rows)
            self._tab_analysis.load(analysis_rows)
            self._tab_files.load(file_rows)
            self._tab_reports.load(report_rows)
            self._tab_all.load(all_rows)

            self._card_logins.set_value(len(login_rows))
            self._card_files.set_value(len(file_rows))
            self._card_analysis.set_value(len(analysis_rows))
            self._card_reports.set_value(len(report_rows))

            self._update_status()
            self._update_report_buttons()
        except Exception as exc:
            log.warning("ActivityMonitorPage.refresh error: %s", exc)
            self._status_label.setText(f"⚠ Could not load activity logs: {exc}")

    def _build_ui(self) -> None:
        self.setStyleSheet(_page_qss())
        root = QVBoxLayout(self)
        root.setContentsMargins(18, 16, 18, 16)
        root.setSpacing(10)

        root.addWidget(self._make_header())
        root.addLayout(self._make_summary_cards())
        root.addWidget(self._make_toolbar())

        self._tabs = QTabWidget(self)
        self._tabs.setDocumentMode(True)
        self._tabs.setStyleSheet(_tabs_qss())

        self._tab_login = _LogTable(self.LOGIN_COLUMNS, self)
        self._tab_analysis = _LogTable(self.ANALYSIS_COLUMNS, self)
        self._tab_files = _LogTable(self.FILE_COLUMNS, self)
        self._tab_reports = _LogTable(self.REPORT_COLUMNS, self)
        self._tab_all = _LogTable(self.ALL_COLUMNS, self)
        self._tab_analysis.row_activated.connect(self._open_session_from_row)
        self._tab_reports.row_activated.connect(self._open_report_from_row)

        self._tabs.addTab(self._tab_login, "Login History")
        self._tabs.addTab(self._tab_analysis, "Analysis History")
        self._tabs.addTab(self._tab_files, "File Access")
        self._tabs.addTab(self._tab_reports, "Report History")
        self._tabs.addTab(self._tab_all, "Full Audit Trail")
        self._tabs.currentChanged.connect(lambda _: (self._update_status(), self._update_report_buttons()))
        self._tabs.currentChanged.connect(lambda _: self._update_report_buttons())
        root.addWidget(self._tabs, 1)

        self._status_label = QLabel("")
        self._status_label.setStyleSheet(_status_text_qss())
        root.addWidget(self._status_label)

    def _make_header(self) -> QWidget:
        # Header intentionally mirrors AdminManagementPage:
        # same card padding, title/subtitle hierarchy, and green access badge.
        card = QFrame()
        card.setObjectName("ActivityHeader")
        # Keep this header exactly aligned with AdminManagementPage.
        # Same fixed height, internal padding, title spacing, and badge size.
        card.setFixedHeight(107)

        h = QHBoxLayout(card)
        h.setContentsMargins(18, 14, 18, 14)
        h.setSpacing(10)

        title_box = QVBoxLayout()
        title_box.setSpacing(2)

        title = QLabel("Activity Monitor")
        title.setObjectName("AdminPageTitle")
        title.setStyleSheet(_header_title_qss())
        subtitle = QLabel("Staff usage, login activity, file access, analysis history, and audit trail")
        subtitle.setObjectName("AdminPageSubtitle")
        subtitle.setStyleSheet(_header_subtitle_qss())
        self._header_title_label = title
        self._header_subtitle_label = subtitle

        title_box.addWidget(title)
        title_box.addWidget(subtitle)
        h.addLayout(title_box, 1)

        self._role_badge = QLabel("●  Admin Access")
        self._role_badge.setAlignment(Qt.AlignCenter)
        self._role_badge.setMinimumHeight(42)
        self._role_badge.setMinimumWidth(150)
        self._role_badge.setStyleSheet(_access_badge_qss())
        h.addWidget(self._role_badge)

        return card

    def _make_summary_cards(self) -> QHBoxLayout:
        row = QHBoxLayout()
        row.setSpacing(12)
        self._card_logins = _SummaryCard("Login Events", "0", "successful, failed, logout")
        self._card_files = _SummaryCard("File Events", "0", "opened, imported, acquired")
        self._card_analysis = _SummaryCard("Analysis Events", "0", "started, completed, failed")
        self._card_reports = _SummaryCard("Report Events", "0", "generated, opened, exported")
        for card in (self._card_logins, self._card_files, self._card_analysis, self._card_reports):
            row.addWidget(card)
        return row

    def _make_toolbar(self) -> QWidget:
        bar = QFrame()
        bar.setObjectName("ActivityToolbar")
        h = QHBoxLayout(bar)
        h.setContentsMargins(12, 9, 12, 9)
        h.setSpacing(8)

        self._search = QLineEdit()
        self._search.setPlaceholderText("Search user, action, file, path, hash, verdict…")
        self._search.setMinimumHeight(32)
        self._search.setMaximumWidth(420)
        self._search.textChanged.connect(self._on_search)

        self._user_combo = QComboBox()
        self._user_combo.addItem("All Users")
        self._user_combo.setMinimumHeight(32)
        self._user_combo.setMinimumWidth(150)
        self._user_combo.currentTextChanged.connect(lambda _: self.refresh())

        btn_refresh = QPushButton("↻ Refresh")
        btn_refresh.setObjectName("NeutralButton")
        btn_refresh.setFixedWidth(105)
        btn_refresh.clicked.connect(self.refresh)

        self._btn_auto = QPushButton("⏸ Pause")
        self._btn_auto.setObjectName("NeutralButton")
        self._btn_auto.setFixedWidth(95)
        self._btn_auto.clicked.connect(self._toggle_auto_refresh)

        self._btn_export = QPushButton("⬇ Export XLSX")
        self._btn_export.setObjectName("ExportButton")
        self._btn_export.setFixedWidth(130)
        self._btn_export.clicked.connect(self._export_workbook)

        self._btn_open_report = QPushButton("↗ Open")
        self._btn_open_report.setObjectName("NeutralButton")
        self._btn_open_report.setFixedWidth(82)
        self._btn_open_report.setToolTip("Open the selected report/export file from the managed repository.")
        self._btn_open_report.clicked.connect(self._open_selected_report)

        self._btn_download_report = QPushButton("⬇ Download")
        self._btn_download_report.setObjectName("ExportButton")
        self._btn_download_report.setFixedWidth(108)
        self._btn_download_report.setToolTip("Admin-only: download the selected report/export file to another location.")
        self._btn_download_report.clicked.connect(self._download_selected_report)

        lbl_search = QLabel("Search:")
        lbl_user = QLabel("User:")

        h.addWidget(lbl_search)
        h.addWidget(self._search)
        h.addSpacing(6)
        h.addWidget(lbl_user)
        h.addWidget(self._user_combo)
        h.addStretch()
        h.addWidget(btn_refresh)
        h.addWidget(self._btn_auto)
        h.addWidget(self._btn_export)
        h.addWidget(self._btn_open_report)
        h.addWidget(self._btn_download_report)
        return bar


    def _merge_shared_repository_rows(self, report_rows: list[dict], username_filter: str | None = None) -> list[dict]:
        """Return Report History rows with central PTM repository preferred.

        In strict PTM mode, admin users should see one authoritative repository
        row per exported/generated report. Local audit rows are kept in Full
        Audit Trail, but hidden from Report History when central API rows are
        available to avoid duplicate local and ramdetect-api://... entries.
        """
        try:
            if not self._is_admin():
                return report_rows

            from ramdetect.case_management.report_repository import (
                list_repository_reports,
                repository_admin_api_enabled,
            )
            shared_rows = list_repository_reports(username_filter=username_filter, limit=2000)

            if repository_admin_api_enabled() and shared_rows:
                return sorted(shared_rows, key=lambda r: _sort_timestamp(r.get("timestamp", "")), reverse=True)

            def row_signature(row: dict) -> str:
                digest = str(row.get("file_hash") or "").strip().lower()
                if digest:
                    return f"sha256:{digest}"
                raw_path = str(row.get("report_path") or row.get("file_path") or "")
                if raw_path:
                    return "path:" + os.path.normcase(os.path.abspath(raw_path))
                return "name:" + str(row.get("file_name") or "").strip().lower()

            seen = {row_signature(r) for r in report_rows if row_signature(r)}
            merged = list(report_rows)
            for row in shared_rows:
                sig = row_signature(row)
                if sig and sig not in seen:
                    merged.append(row)
                    seen.add(sig)

            return sorted(merged, key=lambda r: _sort_timestamp(r.get("timestamp", "")), reverse=True)
        except Exception as exc:
            log.debug("PTM/shared repository scan unavailable: %s", exc)
            return report_rows



    def _load_analysis_audit_rows(self, username_filter: str | None = None) -> list[dict]:
        """
        Load Analysis History from audit activity events.

        This makes the Analysis History tab consistent with the Full Audit Trail.
        It is especially important for Admin workstations because completed
        analyses from analyst clients are synced as central audit events.
        """
        rows: list[dict] = []

        try:
            from ramdetect.case_management.activity_logger import ActivityLogger, ANALYSIS_ACTIONS

            logs = ActivityLogger.instance().get_logs(
                action_filter=ANALYSIS_ACTIONS,
                username_filter=username_filter,
                limit=1000,
            )

            for row in logs:
                details = {}
                raw = row.get("details_json") or ""
                if isinstance(raw, dict):
                    details = raw
                elif raw:
                    try:
                        details = json.loads(raw)
                    except Exception:
                        details = {}

                dump_path = (
                    row.get("file_path")
                    or details.get("dump_path")
                    or details.get("source_dump_path")
                    or ""
                )

                dump_name = (
                    row.get("file_name")
                    or details.get("dump")
                    or details.get("dump_name")
                    or (Path(dump_path).name if dump_path else "")
                )

                session_id = (
                    details.get("session_id")
                    or details.get("source_session_id")
                    or row.get("analysis_session_id")
                    or ""
                )

                score = (
                    details.get("hybrid_score")
                    or details.get("rf_score")
                    or details.get("score")
                    or ""
                )

                score_s = ""
                if score not in ("", None):
                    try:
                        score_f = float(score)
                        if score_f <= 1.0:
                            score_f *= 100.0
                        score_s = f"{score_f:.2f}%"
                    except Exception:
                        score_s = str(score)

                rows.append({
                    "timestamp": row.get("timestamp", ""),
                    "username": row.get("username", "") or "unknown",
                    "role": row.get("role", "") or "unknown",
                    "machine_name": row.get("machine_name", "") or "unknown",
                    "action": row.get("action", ""),
                    "session_id": str(session_id or ""),
                    "file_name": dump_name,
                    "verdict": str(row.get("verdict", "") or details.get("verdict", "") or "").upper(),
                    "hybrid_score": score_s,
                    "size": details.get("dump_size") or details.get("size") or "",
                    "session_file": details.get("session_file") or "",
                    "session_folder": details.get("session_folder") or "",
                    "dump_path": dump_path,
                })

        except Exception as exc:
            log.warning("Failed to load analysis audit rows: %s", exc)

        # If there are no audit rows, keep old local scan-history fallback.
        if not rows:
            return self._load_scan_history_rows(username_filter=username_filter)

        return rows


    def _merge_analysis_dump_access_rows(self, file_rows: list[dict], analysis_rows: list[dict]) -> list[dict]:
        """
        Ensure File Access shows dump files used during analysis.

        Some workflows record dump usage through ANALYSIS_STARTED /
        ANALYSIS_COMPLETED instead of a separate DUMP_SELECTED or DUMP_IMPORTED
        event. This method derives one dump-access row per analysed dump/session.
        """
        merged = list(file_rows)
        seen = set()

        for row in merged:
            key = (
                str(row.get("file_name", "")).lower(),
                str(row.get("file_path", "")).lower(),
            )
            seen.add(key)

        added_sessions = set()

        for row in analysis_rows:
            action = str(row.get("action", "") or "")
            if action not in {"ANALYSIS_STARTED", "ANALYSIS_COMPLETED", "ANALYSIS_FAILED"}:
                continue

            dump_path = str(row.get("dump_path", "") or "")
            dump_name = str(row.get("file_name", "") or (Path(dump_path).name if dump_path else ""))

            if not dump_name and not dump_path:
                continue

            session_id = str(row.get("session_id", "") or "")
            session_key = session_id or dump_name.lower() or dump_path.lower()

            if session_key in added_sessions:
                continue

            key = (dump_name.lower(), dump_path.lower())
            if key in seen:
                continue

            merged.append({
                "timestamp": row.get("timestamp", ""),
                "username": row.get("username", "") or "unknown",
                "machine_name": row.get("machine_name", "") or "unknown",
                "action": "DUMP_IMPORTED",
                "file_name": dump_name,
                "file_path": dump_path,
                "file_hash": "",
            })

            seen.add(key)
            added_sessions.add(session_key)

        return sorted(merged, key=lambda r: _sort_timestamp(r.get("timestamp", "")), reverse=True)


    def _load_scan_history_rows(self, username_filter: str | None = None) -> list[dict]:
        """
        Load completed scan sessions from AppState history for Analysis History.

        Dashboard history is the source of completed scan rows. Audit logs are
        used as an enrichment source for staff-monitoring fields:
        user, role, machine, action. Older scan rows created before Phase 4
        audit hooks are kept as legacy rows with user/machine marked unknown.
        """
        rows: list[dict] = []
        try:
            try:
                from ui.bridge.session import AppState
                from ui.bridge import session as session_mod
            except Exception:
                from ramdetect.ui.bridge.session import AppState
                from ramdetect.ui.bridge import session as session_mod

            sessions_dir = str(getattr(session_mod, "_SESSIONS_DIR", "") or "")
            audit_by_session, audit_by_file = self._analysis_audit_lookup(username_filter=None)

            for item in AppState.load_history():
                sid = str(item.get("id", "") or "")
                filename = item.get("filename", "") or ""

                audit = audit_by_session.get(sid) or audit_by_file.get(filename.lower()) or {}

                # If the Activity Monitor user filter is active, apply it after
                # audit enrichment. Legacy rows without a user should not appear
                # under a specific user because that would be misleading.
                username = audit.get("username") or "unknown"
                if username_filter and username != username_filter:
                    continue

                dt = item.get("datetime", "")
                if hasattr(dt, "strftime"):
                    ts = dt.strftime("%Y-%m-%d %H:%M:%S")
                else:
                    ts = str(dt or "")

                session_file = os.path.join(sessions_dir, f"{sid}.json") if sid and sessions_dir else ""
                if session_file and not os.path.exists(session_file):
                    session_file_display = f"{session_file} (missing)"
                else:
                    session_file_display = session_file

                try:
                    score = float(item.get("hybrid_score", item.get("confidence", 0.0)))
                    score_s = f"{score:.1f}%"
                except Exception:
                    score_s = str(item.get("hybrid_score", item.get("confidence", "")) or "")

                rows.append({
                    "timestamp": audit.get("timestamp") or ts,
                    "username": username,
                    "role": audit.get("role") or ("legacy" if username == "unknown" else ""),
                    "machine_name": audit.get("machine_name") or "unknown",
                    "action": audit.get("action") or "SCAN_HISTORY",
                    "session_id": sid,
                    "file_name": filename,
                    "verdict": str(item.get("status", "") or audit.get("verdict", "") or "").upper(),
                    "hybrid_score": score_s,
                    "size": item.get("size", "") or "",
                    "session_file": session_file_display,
                    "session_folder": sessions_dir,
                    "dump_path": item.get("dump_path", "") or "",
                })
        except Exception as exc:
            log.warning("Failed to load scan history rows: %s", exc)
        return rows

    def _analysis_audit_lookup(self, username_filter: str | None = None) -> tuple[dict, dict]:
        """
        Build lookup dictionaries from audit_logs.

        Returns:
            by_session_id, by_dump_filename

        Preference order is handled by database ordering; newest entries are
        returned first. ANALYSIS_COMPLETED is more useful than STARTED because
        it includes verdict/score after the realtime-analysis hook.
        """
        by_session: dict[str, dict] = {}
        by_file: dict[str, dict] = {}
        try:
            import json
            from ramdetect.case_management.activity_logger import ActivityLogger, ANALYSIS_ACTIONS
            logs = ActivityLogger.instance().get_logs(
                action_filter=ANALYSIS_ACTIONS,
                username_filter=username_filter,
                limit=1000,
            )

            def priority(action: str) -> int:
                order = {
                    "ANALYSIS_COMPLETED": 0,
                    "ANALYSIS_FAILED": 1,
                    "ANALYSIS_STARTED": 2,
                    "RESULT_VIEWED": 3,
                }
                return order.get(str(action), 9)

            logs = sorted(logs, key=lambda r: priority(r.get("action", "")))
            for row in logs:
                details = {}
                raw = row.get("details_json") or ""
                if raw:
                    try:
                        details = json.loads(raw)
                    except Exception:
                        details = {}

                sid = str(details.get("session_id") or row.get("session_id") or "").strip()
                fname = str(
                    row.get("file_name")
                    or details.get("dump")
                    or details.get("dump_name")
                    or ""
                ).strip()

                enriched = {
                    "timestamp": row.get("timestamp", ""),
                    "username": row.get("username", "") or "unknown",
                    "role": row.get("role", "") or "unknown",
                    "machine_name": row.get("machine_name", "") or "unknown",
                    "action": row.get("action", ""),
                    "verdict": row.get("verdict", ""),
                }

                if sid and sid not in by_session:
                    by_session[sid] = enriched
                if fname and fname.lower() not in by_file:
                    by_file[fname.lower()] = enriched
        except Exception as exc:
            log.debug("Analysis audit lookup unavailable: %s", exc)

        return by_session, by_file


    def _is_admin(self) -> bool:
        try:
            if self._auth_bridge is not None and self._auth_bridge.has_role("admin", "supervisor", "ptm_supervisor"):
                return True
        except Exception:
            pass
        try:
            from ramdetect.case_management.activity_logger import ActivityLogger
            role = (ActivityLogger.instance().current_role or "").lower()
            return role in {"admin", "supervisor", "ptm_supervisor"}
        except Exception:
            return False

    def _selected_report_row(self) -> dict:
        """Return selected row from a tab that may contain a report/export path."""
        current = self._tabs.currentWidget() if hasattr(self, "_tabs") else None
        if current in (self._tab_reports, self._tab_files, self._tab_all):
            try:
                return current.selected_row()
            except Exception:
                return {}
        return {}

    def _report_path_from_row(self, row: dict) -> str:
        """Find the best available report/export path from a table row."""
        candidates = [
            row.get("Report Path", ""),
            row.get("Path", ""),
            row.get("report_path", ""),
            row.get("file_path", ""),
        ]
        details = row.get("Details", "") or row.get("details_json", "")
        if details:
            try:
                data = json.loads(details)
                candidates.insert(0, str(data.get("archived_report_path") or ""))
                candidates.append(str(data.get("original_report_path") or ""))
            except Exception:
                pass
        for candidate in candidates:
            candidate = str(candidate or "").strip()
            if candidate and candidate != "—":
                return candidate
        return ""

    def _selected_report_file_name(self, row: dict, path: str) -> str:
        name = str(row.get("Report/File") or row.get("File Name") or row.get("File / Report") or "").strip()
        if not name and _is_central_report_uri(path):
            try:
                from urllib.parse import unquote
                name = unquote(str(path).split("/", 3)[-1])
            except Exception:
                name = ""
        if not name and path:
            name = Path(path).name
        return name or "ramdetect_report_export"

    def _update_report_buttons(self) -> None:
        """Enable admin report buttons only on tabs with report/file rows."""
        try:
            report_tab = self._tabs.currentWidget() in (self._tab_reports, self._tab_files, self._tab_all)
            is_admin = self._is_admin()
            self._btn_open_report.setEnabled(report_tab)
            self._btn_open_report.setVisible(report_tab)
            self._btn_download_report.setEnabled(report_tab and is_admin)
            self._btn_download_report.setVisible(report_tab)
        except Exception:
            pass

    def _open_report_from_row(self, row: dict) -> None:
        path = self._report_path_from_row(row)
        self._open_report_path(path)

    def _open_report_path(self, path: str) -> None:
        try:
            from ramdetect.case_management.report_repository import resolve_existing_report_path
            target = resolve_existing_report_path(path)
        except Exception:
            target = path if path and os.path.exists(path) else ""

        if not target:
            QMessageBox.information(
                self,
                "Open Report",
                "The selected report/export file is not available on this PC or in the managed report repository.",
            )
            return

        try:
            QDesktopServices.openUrl(QUrl.fromLocalFile(target))
        except Exception as exc:
            QMessageBox.warning(self, "Open Report", f"Could not open report/export file:\n{exc}")

    def _open_selected_report(self) -> None:
        row = self._selected_report_row()
        if not row:
            QMessageBox.information(self, "Open Report", "Select a row in Report History, File Access, or Full Audit Trail first.")
            return
        self._open_report_path(self._report_path_from_row(row))

    def _download_selected_report(self) -> None:
        if not self._is_admin():
            QMessageBox.warning(self, "Download Report", "Only Admin users can download report/export files from Activity Monitor.")
            return

        row = self._selected_report_row()
        if not row:
            QMessageBox.information(self, "Download Report", "Select a row in Report History, File Access, or Full Audit Trail first.")
            return

        source_path = self._report_path_from_row(row)
        if not source_path:
            QMessageBox.information(self, "Download Report", "The selected row does not contain a report/export path.")
            return

        default_name = self._selected_report_file_name(row, source_path)
        default_path = str(Path.home() / "Downloads" / default_name)
        dest, _ = QFileDialog.getSaveFileName(
            self,
            "Download RAMDetect Report/Export",
            default_path,
            "All Files (*.*)",
        )
        if not dest:
            return

        try:
            from ramdetect.case_management.report_repository import download_report_file
            result = download_report_file(source_path, dest)
            if not result.get("success"):
                QMessageBox.warning(self, "Download Report", result.get("error", "Download failed."))
                return

            try:
                from ramdetect.case_management.activity_logger import ActivityLogger
                ActivityLogger.instance().log_report_downloaded(
                    result.get("source_path") or source_path,
                    result.get("destination_path") or dest,
                    file_hash=result.get("sha256"),
                    verdict=str(row.get("Verdict") or row.get("verdict") or "").upper() or None,
                    report_name=self._selected_report_file_name(row, source_path),
                )
                self.refresh()
            except Exception:
                pass

            final_path = str(result.get("destination_path") or dest)
            final_name = Path(final_path).name
            _DownloadSuccessDialog(final_path, _shorten_middle(final_name, 86), self).exec_()
        except Exception as exc:
            QMessageBox.critical(self, "Download Report", f"Download failed:\n{exc}")


    def _open_session_from_row(self, row: dict) -> None:
        """Open session JSON if it exists; otherwise open the sessions folder."""
        target = row.get("Session JSON") or row.get("session_file") or ""
        if target.endswith(" (missing)"):
            target = ""
        if not target or not os.path.exists(target):
            target = row.get("Session Folder") or row.get("session_folder") or ""
        if not target or not os.path.exists(target):
            QMessageBox.information(
                self,
                "Open Session",
                "No session JSON/folder is available for the selected row.",
            )
            return
        try:
            QDesktopServices.openUrl(QUrl.fromLocalFile(target))
        except Exception as exc:
            QMessageBox.warning(self, "Open Session", f"Could not open session path:\n{exc}")

    def _collect_workbook_tabs(self) -> dict[str, list[dict]]:
        return {
            "Login History": self._tab_login.export_rows(),
            "Analysis History": self._tab_analysis.export_rows(),
            "File Access": self._tab_files.export_rows(),
            "Report History": self._tab_reports.export_rows(),
            "Full Audit Trail": self._tab_all.export_rows(),
        }

    def _export_metadata(self) -> dict:
        try:
            from ramdetect.case_management.activity_logger import ActivityLogger
            al = ActivityLogger.instance()
            username = al.current_username
            role = al.current_role
            machine = getattr(al, 'machine_name', getattr(al, '_machine_name', 'unknown'))
        except Exception:
            username = "unknown"
            role = "unknown"
            machine = "unknown"

        return {
            "title": "RAMDetect Activity Monitor Workbook",
            "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "generated_by": username,
            "role": role,
            "machine": machine,
            "search_filter": self._search.text().strip(),
            "user_filter": self._user_combo.currentText(),
        }

    def _export_workbook(self) -> None:
        """Export all Activity Monitor tabs into one styled XLSX workbook."""
        try:
            self.refresh()
            default_name = f"ramdetect_activity_monitor_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xlsx"
            default_path = str(Path.home() / "Desktop" / default_name)

            path, _ = QFileDialog.getSaveFileName(
                self,
                "Export Activity Monitor Workbook",
                default_path,
                "Excel Workbook (*.xlsx)",
            )
            if not path:
                return
            if not path.lower().endswith(".xlsx"):
                path += ".xlsx"

            from ramdetect.reporting.activity_workbook_reporter import ActivityWorkbookReporter
            result = ActivityWorkbookReporter.generate(
                tabs=self._collect_workbook_tabs(),
                metadata=self._export_metadata(),
                path=path,
                fname=Path(path).name,
            )

            if not result.get("success"):
                QMessageBox.critical(
                    self,
                    "Export Activity Monitor Workbook",
                    f"Workbook export failed:\n{result.get('error', 'Unknown error')}",
                )
                return

            # Activity Monitor XLSX is an admin audit snapshot, not a forensic report.
            # Do not log it as XLSX_EXPORTED with report_path/file_path, because that
            # causes ActivityLogger/report_repository to archive a second managed copy
            # under RAMDetect\\ramdetect_report_repository. Keep the workbook only at
            # the admin-selected save location and record a lightweight audit entry.
            try:
                from ramdetect.case_management.activity_logger import ActivityLogger
                saved_path = str(result.get("path") or path)
                ActivityLogger.instance().log(
                    "ACTIVITY_WORKBOOK_SAVED",
                    file_name=Path(saved_path).name,
                    details={
                        "export_type": "activity_monitor_workbook",
                        "saved_to": saved_path,
                        "sheets": result.get("sheets", []),
                        "records": result.get("records", 0),
                    },
                )
                self.refresh()
            except Exception:
                pass

            self._show_activity_workbook_export_success(
                saved_path=str(result.get("path") or path),
                sheets=result.get("sheets", []),
                records=result.get("records", 0),
            )
        except Exception as exc:
            log.exception("Activity Monitor workbook export failed")
            QMessageBox.critical(self, "Export Activity Monitor Workbook", f"Export failed:\n{exc}")


    def _show_activity_workbook_export_success(self, saved_path: str, sheets: list[str], records: int) -> None:
        """Show a RAMDetect-themed success popup for Activity Monitor workbook export."""
        try:
            dialog = QDialog(self)
            dialog.setWindowTitle("Export Activity Monitor Workbook - RAMDetect")
            dialog.setModal(True)
            dialog.resize(580, 260)

            dialog.setStyleSheet(_activity_workbook_dialog_qss())

            root = QVBoxLayout(dialog)
            root.setContentsMargins(22, 18, 22, 18)
            root.setSpacing(10)

            title = QLabel("Activity workbook exported successfully.")
            title.setObjectName("Title")
            root.addWidget(title)

            path_obj = Path(str(saved_path))
            body = QLabel(
                f"Saved as:\\n{path_obj.name}\\n\\n"
                f"Sheets: {', '.join([str(s) for s in sheets])}\\n"
                f"Records: {records}"
            )
            body.setObjectName("Body")
            body.setWordWrap(True)
            root.addWidget(body)

            details = QTextEdit()
            details.setReadOnly(True)
            details.setPlainText(str(saved_path))
            details.setMinimumHeight(72)
            details.hide()
            root.addWidget(details)

            btn_row = QHBoxLayout()
            btn_row.addStretch(1)

            details_btn = QPushButton("Show Details...")
            ok_btn = QPushButton("OK")
            ok_btn.setObjectName("PrimaryButton")

            def _toggle_details():
                if details.isVisible():
                    details.hide()
                    details_btn.setText("Show Details...")
                    dialog.resize(580, 260)
                else:
                    details.show()
                    details_btn.setText("Hide Details...")
                    dialog.resize(580, 360)

            details_btn.clicked.connect(_toggle_details)
            ok_btn.clicked.connect(dialog.accept)

            btn_row.addWidget(details_btn)
            btn_row.addWidget(ok_btn)
            root.addLayout(btn_row)

            dialog.exec_()
        except Exception:
            QMessageBox.information(
                self,
                "Export Activity Monitor Workbook",
                f"Workbook exported successfully:\\n{saved_path}",
            )


    def _user_filter(self) -> str | None:
        try:
            from ramdetect.case_management.activity_logger import ActivityLogger
            al = ActivityLogger.instance()
            role = (al.current_role or "").lower()
            is_admin = role in {"admin", "supervisor", "ptm_supervisor"}
            if self._auth_bridge is not None:
                is_admin = is_admin or self._auth_bridge.has_role("admin", "supervisor", "ptm_supervisor")

            if is_admin:
                self._user_combo.setEnabled(True)
                selected = self._user_combo.currentText()
                return None if selected in ("", "All Users") else selected

            self._user_combo.setEnabled(False)
            return al.current_username if al.current_username != "unknown" else None
        except Exception:
            return None

    def _update_status(self) -> None:
        try:
            from ramdetect.case_management.activity_logger import ActivityLogger
            al = ActivityLogger.instance()
            username = al.current_username
            role = al.current_role
            role_l = (role or "").lower()
            is_admin = role_l in {"admin", "supervisor", "ptm_supervisor"}
            scope = "all users" if is_admin else f"user: {username}"
            current_widget = self._tabs.currentWidget() if hasattr(self, "_tabs") else self._tab_all
            current_tab = self._tabs.tabText(self._tabs.currentIndex()) if hasattr(self, "_tabs") else "Full Audit Trail"
            current_count = current_widget.row_count() if hasattr(current_widget, "row_count") else self._tab_all.row_count()
            if current_tab == "Analysis History":
                hint = "double-click Analysis History row to open session JSON/folder"
            elif current_tab in {"Report History", "File Access", "Full Audit Trail"}:
                hint = "select a central PTM repository report row, then use Open or Download"
            else:
                hint = "auto-refresh every 30 seconds"
            self._status_label.setText(
                f"Showing {current_count} records in {current_tab} ({scope}) — {hint}"
            )
            if is_admin:
                self._role_badge.setText("●  Admin Access")
                self._role_badge.setMinimumHeight(42)
                self._role_badge.setMinimumWidth(150)
                self._role_badge.setStyleSheet(_access_badge_qss())
            else:
                self._role_badge.setText("Admin Access" if is_admin else f"{username}  [{role}]")
                self._role_badge.setMinimumHeight(42)
                self._role_badge.setMinimumWidth(150)
                self._role_badge.setStyleSheet(_role_badge_readonly_qss())
        except Exception:
            pass

    def _on_search(self, text: str) -> None:
        for tab in (self._tab_login, self._tab_analysis, self._tab_files, self._tab_reports, self._tab_all):
            tab.set_filter(text)
        self._update_status()

    def _toggle_auto_refresh(self) -> None:
        self._auto_refresh = not self._auto_refresh
        self._btn_auto.setText("⏸ Pause" if self._auto_refresh else "▶ Resume")

    def _schedule_refresh(self) -> None:
        self._timer = QTimer(self)
        self._timer.timeout.connect(self._auto_tick)
        self._timer.start(30_000)

    def _auto_tick(self) -> None:
        if self._auto_refresh:
            self.refresh()

    def _populate_user_combo(self) -> None:
        try:
            from ramdetect.case_management.database import session_scope
            from ramdetect.case_management.models import User
            current = self._user_combo.currentText()
            with session_scope() as db:
                users = [u for (u,) in db.query(User.username).order_by(User.username.asc()).all()]
            self._user_combo.blockSignals(True)
            self._user_combo.clear()
            self._user_combo.addItem("All Users")
            for u in users:
                self._user_combo.addItem(u)
            idx = self._user_combo.findText(current)
            if idx >= 0:
                self._user_combo.setCurrentIndex(idx)
            self._user_combo.blockSignals(False)
        except Exception:
            pass

    def showEvent(self, event):
        super().showEvent(event)
        self._apply_theme_styles()
        self._populate_user_combo()
        self.refresh()

    def _apply_theme_styles(self) -> None:
        """Re-apply page-local styles after live Light/Dark theme changes."""
        try:
            self.setStyleSheet(_page_qss())
            if hasattr(self, "_tabs"):
                self._tabs.setStyleSheet(_tabs_qss())
            for tab in (getattr(self, "_tab_login", None), getattr(self, "_tab_analysis", None),
                        getattr(self, "_tab_files", None), getattr(self, "_tab_reports", None),
                        getattr(self, "_tab_all", None)):
                view = getattr(tab, "_view", None)
                if view is not None:
                    view.setStyleSheet(_table_qss())
            for card in (getattr(self, "_card_logins", None), getattr(self, "_card_files", None),
                         getattr(self, "_card_analysis", None), getattr(self, "_card_reports", None)):
                if card is not None:
                    card.setStyleSheet(_summary_card_qss())
            if hasattr(self, "_header_title_label"):
                self._header_title_label.setStyleSheet(_header_title_qss())
            if hasattr(self, "_header_subtitle_label"):
                self._header_subtitle_label.setStyleSheet(_header_subtitle_qss())
            if hasattr(self, "_status_label"):
                self._status_label.setStyleSheet(_status_text_qss())
            if hasattr(self, "_role_badge"):
                self._role_badge.setStyleSheet(_access_badge_qss() if self._is_admin() else _role_badge_readonly_qss())
        except Exception:
            pass



def _active_theme() -> str:
    try:
        from ui.theme import current_theme
    except Exception:
        try:
            from ramdetect.ui.theme import current_theme
        except Exception:
            return "dark"
    try:
        return "light" if str(current_theme()).strip().lower() == "light" else "dark"
    except Exception:
        return "dark"


def _is_light() -> bool:
    return _active_theme() == "light"


def _summary_title_tone() -> str:
    return "#5b73ad" if _is_light() else "#94a3b8"


def _summary_value_tone() -> str:
    return "#1a56db" if _is_light() else "#f8fafc"


def _summary_subtitle_tone() -> str:
    return "#6f83b5" if _is_light() else "#64748b"


def _header_title_qss() -> str:
    if _is_light():
        return "font-size:22px;font-weight:800;color:#123b7a;background:transparent;border:none;"
    return "font-size:22px;font-weight:800;color:#ffffff;background:transparent;border:none;"


def _header_subtitle_qss() -> str:
    if _is_light():
        return "font-size:12px;color:#5570a9;background:transparent;border:none;"
    return "font-size:12px;color:#9fb0cc;background:transparent;border:none;"


def _status_text_qss() -> str:
    return "color:#7b8fb8;font-size:11px;background:transparent;border:none;" if _is_light() else "color:#94a3b8;font-size:11px;background:transparent;border:none;"


def _access_badge_qss() -> str:
    if _is_light():
        return (
            "background:#ecfdf5;color:#047857;border:1px solid #86efac;"
            "border-radius:12px;padding:8px 14px;font-size:12px;font-weight:800;"
        )
    return (
        "background:#063d24;color:#4ade80;border:1px solid #22c55e;"
        "border-radius:12px;padding:8px 14px;font-size:12px;font-weight:800;"
    )


def _role_badge_readonly_qss() -> str:
    if _is_light():
        return (
            "background:#f8fbff;color:#5570a9;border:1px solid #cfe0ff;"
            "border-radius:12px;padding:8px 14px;font-size:12px;font-weight:700;"
        )
    return (
        "background:#0f172a;color:#cbd5e1;border:1px solid #334155;"
        "border-radius:12px;padding:8px 14px;font-size:12px;font-weight:700;"
    )


def _summary_card_qss() -> str:
    if _is_light():
        return """
            QFrame#ActivitySummaryCard {
                background: #ffffff;
                border: 1px solid #cfe0ff;
                border-radius: 12px;
            }
            QLabel { background: transparent; border: none; }
        """
    return """
        QFrame#ActivitySummaryCard {
            background: rgba(30, 41, 59, 0.45);
            border: 1px solid rgba(51, 65, 85, 0.55);
            border-radius: 12px;
        }
        QLabel { background: transparent; border: none; }
    """


def _page_qss() -> str:
    if _is_light():
        return """
            QWidget { background: #f0f5ff; color: #1e3a6e; font-family: 'Segoe UI'; }
            QFrame#ActivityHeader, QFrame#ActivityToolbar {
                background: #ffffff;
                border: 1px solid #cfe0ff;
                border-radius: 12px;
            }
            QLineEdit, QComboBox {
                background: #ffffff;
                color: #1e3a6e;
                border: 1px solid #c7d9fb;
                border-radius: 8px;
                padding: 5px 10px;
                font-size: 12px;
            }
            QLineEdit:focus, QComboBox:focus { border: 1px solid #1a56db; }
            QComboBox QAbstractItemView {
                background: #ffffff;
                color: #1e3a6e;
                border: 1px solid #cfe0ff;
                selection-background-color: #eaf1ff;
                selection-color: #1a56db;
            }
            QPushButton#NeutralButton {
                background: #f8fbff;
                color: #1e3a6e;
                border: 1px solid #cfe0ff;
                border-radius: 8px;
                padding: 5px 10px;
                font-size: 11px;
                font-weight: 700;
            }
            QPushButton#NeutralButton:hover { background: #eaf1ff; border-color: #1a56db; color: #1a56db; }
            QPushButton#NeutralButton:disabled { background: #eef4ff; color: #9aa8c3; border-color: #d9e6ff; }
            QPushButton#ExportButton {
                background: #1a56db;
                color: #ffffff;
                border: 1px solid #1a56db;
                border-radius: 8px;
                padding: 5px 10px;
                font-size: 11px;
                font-weight: 800;
            }
            QPushButton#ExportButton:hover { background: #174bbf; border-color: #174bbf; }
            QLabel { background: transparent; border: none; color: #1e3a6e; }
        """
    return """
        QWidget { background: #0f172a; color: #e2e8f0; font-family: 'Segoe UI'; }
        QFrame#ActivityHeader, QFrame#ActivityToolbar {
            background: #111827;
            border: 1px solid #26334d;
            border-radius: 12px;
        }
        QLineEdit, QComboBox {
            background: #0f172a; color: #e2e8f0; border: 1px solid #334155;
            border-radius: 8px; padding: 5px 10px; font-size: 12px;
        }
        QLineEdit:focus, QComboBox:focus { border: 1px solid #06b6d4; }
        QPushButton#NeutralButton {
            background: #334155; color: #f8fafc; border: 1px solid #475569;
            border-radius: 8px; padding: 5px 10px; font-size: 11px; font-weight: 700;
        }
        QPushButton#NeutralButton:hover { background: #475569; }
        QPushButton#ExportButton {
            background: #0891b2; color: #ffffff; border: 1px solid #06b6d4;
            border-radius: 8px; padding: 5px 10px; font-size: 11px; font-weight: 800;
        }
        QPushButton#ExportButton:hover { background: #0e7490; }
        QLabel { background: transparent; border: none; }
    """


def _tabs_qss() -> str:
    if _is_light():
        return """
            QTabWidget::pane { border: none; background: transparent; margin-top: 8px; }
            QTabBar { qproperty-drawBase: 0; background: transparent; }
            QTabBar::tab {
                background: #ffffff;
                color: #5570a9;
                border: 1px solid #cfe0ff;
                padding: 7px 14px;
                margin-right: 4px;
                border-radius: 9px;
                font-size: 11px;
                font-weight: 700;
                min-width: 104px;
            }
            QTabBar::tab:selected { background: #1a56db; color: #ffffff; border-color: #1a56db; }
            QTabBar::tab:hover:!selected { background: #eaf1ff; color: #1a56db; border-color: #1a56db; }
        """
    return """
        QTabWidget::pane { border: 1px solid #26334d; border-radius: 10px; background: #111827; }
        QTabBar { qproperty-drawBase: 0; }
        QTabBar::tab {
            background: #172033; color: #9fb0cc; border: 1px solid #26334d;
            padding: 7px 14px; margin-right: 4px; border-top-left-radius: 9px;
            border-top-right-radius: 9px; font-size: 11px; font-weight: 700;
        }
        QTabBar::tab:selected { background: #0891b2; color: #ffffff; border-color: #06b6d4; }
        QTabBar::tab:hover:!selected { background: #1e293b; color: #dbeafe; }
    """


def _table_qss() -> str:
    if _is_light():
        return """
            QTableView {
                background: #ffffff;
                alternate-background-color: #ffffff;
                color: #1e3a6e;
                border: 2px solid #9fbef2;
                border-radius: 12px;
                gridline-color: transparent;
                font-size: 11px;
                selection-background-color: #c7dcff;
                selection-color: #0f3473;
            }
            QTableView::viewport { background: #ffffff; border: none; }
            QTableView::item { border: none; padding: 2px 6px; }
            QTableView::item:selected { background: #c7dcff; color: #0f3473; }
            QTableView::item:focus { outline: none; border: none; }
            QHeaderView::section {
                background: #eaf1ff;
                color: #5570a9;
                border: none;
                border-right: 1px solid #d4e3ff;
                border-bottom: 1px solid #b8cff8;
                padding: 7px 9px;
                font-size: 11px;
                font-weight: 800;
            }
            QHeaderView::section:hover { background: #dbeafe; color: #1a56db; }
            QTableCornerButton::section { background: #eaf1ff; border: none; border-bottom: 1px solid #b8cff8; }
            QScrollBar:vertical { background: #eef4ff; width: 8px; margin: 2px 2px 2px 0px; border-radius: 4px; }
            QScrollBar::handle:vertical { background: #8faee6; border-radius: 4px; min-height: 36px; }
            QScrollBar::handle:vertical:hover { background: #6f8fd3; }
            QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0px; background: transparent; }
            QScrollBar::add-page:vertical, QScrollBar::sub-page:vertical { background: #eef4ff; }
            QScrollBar:horizontal { background: #eef4ff; height: 8px; margin: 0px 2px 2px 2px; border-radius: 4px; }
            QScrollBar::handle:horizontal { background: #8faee6; border-radius: 4px; min-width: 36px; }
            QScrollBar::handle:horizontal:hover { background: #6f8fd3; }
            QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal { width: 0px; background: transparent; }
            QScrollBar::add-page:horizontal { background: #eef4ff; }
            QScrollBar::sub-page:horizontal { background: #eef4ff; }
        """
    return """
        QTableView {
            background: #0f172a;
            alternate-background-color: #0f172a;
            color: #dbeafe;
            border: 2px solid #40506f;
            border-radius: 12px;
            gridline-color: transparent;
            font-size: 11px;
            selection-background-color: #164e63;
            selection-color: white;
        }
        QTableView::viewport { background: #0f172a; border: none; }
        QTableView::item { border: none; padding: 2px 6px; }
        QTableView::item:selected { background: #164e63; color: #ffffff; }
        QTableView::item:focus { outline: none; border: none; }
        QHeaderView::section {
            background: #0b1220;
            color: #dbeafe;
            border: none;
            border-right: 1px solid #26334d;
            border-bottom: 1px solid #34435f;
            padding: 7px 9px;
            font-size: 11px;
            font-weight: 800;
        }
        QTableCornerButton::section { background: #0b1220; border: none; border-bottom: 1px solid #34435f; }
        QScrollBar:vertical { background: #0b1220; width: 8px; margin: 2px 2px 2px 0px; border-radius: 4px; }
        QScrollBar::handle:vertical { background: rgba(100,116,139,0.50); border-radius: 4px; min-height: 36px; }
        QScrollBar::handle:vertical:hover { background: rgba(148,163,184,0.62); }
        QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0px; background: transparent; }
        QScrollBar::add-page:vertical, QScrollBar::sub-page:vertical { background: #0b1220; }
        QScrollBar:horizontal { background: #0b1220; height: 8px; margin: 0px 2px 2px 2px; border-radius: 4px; }
        QScrollBar::handle:horizontal { background: rgba(100,116,139,0.45); border-radius: 4px; min-width: 36px; }
        QScrollBar::handle:horizontal:hover { background: rgba(148,163,184,0.60); }
        QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal { width: 0px; background: transparent; }
        QScrollBar::add-page:horizontal, QScrollBar::sub-page:horizontal { background: #0b1220; }
    """


def _download_success_dialog_qss() -> str:
    if _is_light():
        return """
            QDialog { background: #ffffff; color: #1e3a6e; font-family: 'Segoe UI'; }
            QLabel { background: transparent; border: none; color: #1e3a6e; }
            QLabel#InfoIcon { background: #dbeafe; color: #1a56db; border: 1px solid #9fb7e5; border-radius: 20px; font-size: 20px; font-weight: 900; }
            QLabel#DialogTitle { color: #123b7a; font-size: 13px; font-weight: 700; }
            QLabel#DialogLabel { color: #5570a9; font-size: 11px; font-weight: 700; }
            QLabel#FileNameLabel { color: #1e3a6e; font-size: 12px; font-weight: 600; background: #f8fbff; border: 1px solid #cfe0ff; border-radius: 8px; padding: 8px 10px; }
            QTextEdit#PathDetails { background: #f8fbff; color: #1e3a6e; border: 1px solid #cfe0ff; border-radius: 8px; padding: 8px; font-size: 11px; selection-background-color: #dbeafe; }
            QPushButton#DialogPrimaryButton { background: #1a56db; color: #ffffff; border: 1px solid #1a56db; border-radius: 8px; padding: 8px 22px; font-size: 12px; font-weight: 800; min-width: 82px; }
            QPushButton#DialogPrimaryButton:hover { background: #174bbf; border-color: #174bbf; }
            QPushButton#DialogSecondaryButton { background: #f8fbff; color: #1e3a6e; border: 1px solid #cfe0ff; border-radius: 8px; padding: 8px 16px; font-size: 12px; font-weight: 800; min-width: 132px; }
            QPushButton#DialogSecondaryButton:hover { background: #eaf1ff; border-color: #1a56db; color: #1a56db; }
        """
    return """
        QDialog { background: #0f172a; color: #e2e8f0; font-family: 'Segoe UI'; }
        QLabel { background: transparent; border: none; color: #e2e8f0; }
        QLabel#InfoIcon { background: #075985; color: #e0f2fe; border: 1px solid #06b6d4; border-radius: 20px; font-size: 20px; font-weight: 900; }
        QLabel#DialogTitle { color: #f8fafc; font-size: 13px; font-weight: 700; }
        QLabel#DialogLabel { color: #9fb0cc; font-size: 11px; font-weight: 700; }
        QLabel#FileNameLabel { color: #dbeafe; font-size: 12px; font-weight: 600; background: #111827; border: 1px solid #26334d; border-radius: 8px; padding: 8px 10px; }
        QTextEdit#PathDetails { background: #0b1220; color: #dbeafe; border: 1px solid #334155; border-radius: 8px; padding: 8px; font-size: 11px; selection-background-color: #0e7490; }
        QPushButton#DialogPrimaryButton { background: #334155; color: #f8fafc; border: 1px solid #64748b; border-radius: 8px; padding: 8px 22px; font-size: 12px; font-weight: 800; min-width: 82px; }
        QPushButton#DialogPrimaryButton:hover { background: #0891b2; border: 1px solid #22d3ee; color: #ffffff; }
        QPushButton#DialogPrimaryButton:pressed { background: #0e7490; border: 1px solid #67e8f9; }
        QPushButton#DialogSecondaryButton { background: #172033; color: #dbeafe; border: 1px solid #334155; border-radius: 8px; padding: 8px 16px; font-size: 12px; font-weight: 800; min-width: 132px; }
        QPushButton#DialogSecondaryButton:hover { background: #1e3a5f; border: 1px solid #38bdf8; color: #ffffff; }
        QPushButton#DialogSecondaryButton:pressed { background: #075985; border: 1px solid #67e8f9; }
    """


def _activity_workbook_dialog_qss() -> str:
    if _is_light():
        return """
            QDialog { background-color: #ffffff; color: #1e3a6e; }
            QLabel#Title { color: #123b7a; font-size: 18px; font-weight: 800; }
            QLabel#Body { color: #1e3a6e; font-size: 13px; }
            QTextEdit { background-color: #f8fbff; color: #1e3a6e; border: 1px solid #cfe0ff; border-radius: 10px; padding: 8px; selection-background-color: #dbeafe; }
            QPushButton { background-color: #f8fbff; color: #1e3a6e; border: 1px solid #cfe0ff; border-radius: 10px; padding: 8px 18px; font-weight: 700; }
            QPushButton:hover { background-color: #eaf1ff; border: 1px solid #1a56db; color: #1a56db; }
            QPushButton#PrimaryButton { background-color: #1a56db; color: #ffffff; border: 1px solid #1a56db; }
            QPushButton#PrimaryButton:hover { background-color: #174bbf; border: 1px solid #174bbf; color: #ffffff; }
        """
    return """
        QDialog { background-color: #0f172a; color: #e5eefc; }
        QLabel#Title { color: #f8fafc; font-size: 18px; font-weight: 800; }
        QLabel#Body { color: #dbeafe; font-size: 13px; }
        QTextEdit { background-color: #111c2e; color: #dbeafe; border: 1px solid #334155; border-radius: 10px; padding: 8px; selection-background-color: #0891b2; }
        QPushButton { background-color: #1e293b; color: #f8fafc; border: 1px solid #334155; border-radius: 10px; padding: 8px 18px; font-weight: 700; }
        QPushButton:hover { background-color: #26364d; border: 1px solid #22d3ee; color: #ffffff; }
        QPushButton#PrimaryButton { background-color: #0891b2; border: 1px solid #22d3ee; }
        QPushButton#PrimaryButton:hover { background-color: #06b6d4; border: 1px solid #67e8f9; }
    """
