"""
audit_trail.py
--------------
Global Audit Trail page for RAMDetect.

Shows all audit log entries with optional filters for case ID or username.
This page is read-only; audit logs are append-only in the database.
"""

from PyQt5.QtCore    import Qt
from PyQt5.QtGui     import QFont
from PyQt5.QtWidgets import (
    QHBoxLayout, QHeaderView, QLabel, QLineEdit,
    QPushButton, QSizePolicy, QSpacerItem,
    QTableWidget, QTableWidgetItem, QVBoxLayout, QWidget,
)

import logging
from ui.style_helpers import set_role, set_tone
logger = logging.getLogger(__name__)


class AuditTrailPage(QWidget):
    """Read-only audit log viewer."""

    def __init__(self, case_bridge=None, parent=None):
        super().__init__(parent)
        self._bridge = case_bridge
        self._build_ui()

    # ------------------------------------------------------------------
    def set_case_bridge(self, bridge) -> None:
        self._bridge = bridge

    def refresh(self) -> None:
        self._load_logs()

    # ------------------------------------------------------------------
    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(12)

        # Header
        hdr = QHBoxLayout()
        title = QLabel("Audit Trail")
        title.setFont(QFont("Segoe UI", 16, QFont.Bold))
        set_tone(title, "#e0e6f0")
        hdr.addWidget(title)
        hdr.addSpacerItem(QSpacerItem(40, 0, QSizePolicy.Expanding))

        btn_refresh = QPushButton("⟳ Refresh")
        btn_refresh.setFixedWidth(100)
        btn_refresh.setCursor(Qt.PointingHandCursor)
        btn_refresh.clicked.connect(self._load_logs)
        hdr.addWidget(btn_refresh)
        layout.addLayout(hdr)

        # Filter row
        filter_row = QHBoxLayout()

        lbl_case = QLabel("Case ID:")
        set_tone(lbl_case, "#a0adc4")
        self._filter_case = QLineEdit()
        self._filter_case.setPlaceholderText("e.g. CASE-20240101-AB1234")
        self._filter_case.setFixedWidth(220)
        self._filter_case.setMinimumHeight(32)
        self._filter_case.returnPressed.connect(self._load_logs)

        lbl_user = QLabel("Username:")
        set_tone(lbl_user, "#a0adc4")
        self._filter_user = QLineEdit()
        self._filter_user.setPlaceholderText("Partial match")
        self._filter_user.setFixedWidth(160)
        self._filter_user.setMinimumHeight(32)
        self._filter_user.returnPressed.connect(self._load_logs)

        btn_search = QPushButton("Search")
        btn_search.setFixedWidth(90)
        btn_search.setCursor(Qt.PointingHandCursor)
        btn_search.clicked.connect(self._load_logs)

        btn_clear = QPushButton("Clear")
        btn_clear.setFixedWidth(70)
        btn_clear.setCursor(Qt.PointingHandCursor)
        btn_clear.clicked.connect(self._clear_filters)

        filter_row.addWidget(lbl_case)
        filter_row.addWidget(self._filter_case)
        filter_row.addSpacing(16)
        filter_row.addWidget(lbl_user)
        filter_row.addWidget(self._filter_user)
        filter_row.addSpacing(8)
        filter_row.addWidget(btn_search)
        filter_row.addWidget(btn_clear)
        filter_row.addSpacerItem(QSpacerItem(40, 0, QSizePolicy.Expanding))
        layout.addLayout(filter_row)

        # Audit log table
        cols = ["Timestamp (UTC)", "Username", "Action",
                "Entity Type", "Entity ID", "Case ID",
                "Machine", "Details"]
        self._table = QTableWidget()
        self._table.setColumnCount(len(cols))
        self._table.setHorizontalHeaderLabels(cols)
        self._table.horizontalHeader().setSectionResizeMode(7, QHeaderView.Stretch)
        self._table.setSelectionBehavior(QTableWidget.SelectRows)
        self._table.setEditTriggers(QTableWidget.NoEditTriggers)
        self._table.setAlternatingRowColors(True)
        self._table.verticalHeader().setVisible(False)
        self._table.setSortingEnabled(True)
        self._table.setStyleSheet("font-size: 11px;")
        layout.addWidget(self._table)

        # Footer count
        self._lbl_count = QLabel("0 records")
        self._lbl_count.setStyleSheet("color: #7a8cb0; font-size: 11px;")
        layout.addWidget(self._lbl_count)

    # ------------------------------------------------------------------
    def _clear_filters(self) -> None:
        self._filter_case.clear()
        self._filter_user.clear()
        self._load_logs()

    def _load_logs(self) -> None:
        if self._bridge is None:
            return

        case_id_text = self._filter_case.text().strip() or None
        username_text = self._filter_user.text().strip() or None

        # If a full case_id string was entered, resolve the integer PK
        case_pk = None
        if case_id_text:
            try:
                case = self._bridge.get_case(case_id_text)
                if case:
                    case_pk = case.id
            except Exception:
                pass

        try:
            logs = self._bridge.list_audit_logs(
                case_id  = case_pk,
                username = username_text,
                limit    = 500,
            )
        except Exception as exc:
            logger.error("Failed to load audit logs: %s", exc)
            logs = []

        self._table.setSortingEnabled(False)
        self._table.setRowCount(0)

        for log in logs:
            row = self._table.rowCount()
            self._table.insertRow(row)

            def _set(col, text):
                self._table.setItem(row, col,
                                    QTableWidgetItem(str(text) if text is not None else ""))

            _set(0, log.created_at.strftime("%Y-%m-%d %H:%M:%S") if log.created_at else "")
            _set(1, log.username)
            _set(2, log.action)
            _set(3, log.entity_type)
            _set(4, log.entity_id)
            _set(5, log.case_id)
            _set(6, log.machine_name)
            _set(7, log.details_json)

        self._table.setSortingEnabled(True)
        self._lbl_count.setText(f"{len(logs)} record(s)")
