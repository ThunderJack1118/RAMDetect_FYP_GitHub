"""
Dashboard — Page 1
──────────────────
• Stats pulled live from AppState.get_stats()  (real persisted history)
• History table from AppState.load_history()
• Refreshes every time the page becomes visible (showEvent)
• "New Scan" starts a clean AppState.new_session() before navigating
• "View Details →" loads the session from history back into AppState.current
• Sortable columns: click any header to sort asc/desc
• Empty-state card when no scans have been run yet
"""


from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QFrame, QTableWidget, QTableWidgetItem,
    QPushButton, QHeaderView, QSizePolicy,
)
from PyQt5.QtCore import Qt, pyqtSignal, QPoint
from PyQt5.QtGui  import QFont, QColor, QPainter, QPen

from ui.widgets.status_badge import StatusBadge
from ui.widgets.confidence_meter import ConfidenceMeter
from ui.widgets.header_bar import HeaderBar
from ui.bridge.session import AppState, ScanSession


# ─────────────────────────────────────────────────────────────────────────────
# Activity (pulse/waveform) icon  — mirrors lucide-react <Activity />
# ─────────────────────────────────────────────────────────────────────────────

class _ActivityIcon(QWidget):
    """
    Paints a small cyan ECG-style pulse waveform (20×20 px),
    matching the lucide-react <Activity> icon used in the React prototype.
    """
    def __init__(self, size: int = 20, parent=None):
        super().__init__(parent)
        self._sz = size
        self.setFixedSize(size, size)
        self.setAttribute(Qt.WA_TranslucentBackground)
        self.setStyleSheet("background: transparent;")

    def paintEvent(self, _event):
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        pen = QPen(QColor("#06b6d4"), 1.8, Qt.SolidLine, Qt.RoundCap, Qt.RoundJoin)
        p.setPen(pen)
        s = self._sz
        # Scaled waveform: flat → up-spike → down-spike → flat
        pts = [
            QPoint(0,          int(s * 0.50)),
            QPoint(int(s*0.25), int(s * 0.50)),
            QPoint(int(s*0.38), int(s * 0.15)),
            QPoint(int(s*0.50), int(s * 0.85)),
            QPoint(int(s*0.62), int(s * 0.35)),
            QPoint(int(s*0.75), int(s * 0.50)),
            QPoint(s,           int(s * 0.50)),
        ]
        for i in range(len(pts) - 1):
            p.drawLine(pts[i], pts[i + 1])
        p.end()


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _card(radius: int = 12) -> QFrame:
    f = QFrame()
    f.setObjectName("appCard")
    f.setFrameShape(QFrame.NoFrame)
    f.setFrameShadow(QFrame.Plain)
    f.setStyleSheet(
        f"QFrame#appCard {{"
        f"  background: rgba(30,41,59,0.45);"
        f"  border: 1px solid rgba(51,65,85,0.5);"
        f"  border-radius: {radius}px;"
        f"}}"
    )
    return f


def _lbl(text, size=13, bold=False, color="#ffffff") -> QLabel:
    l = QLabel(text)
    l.setFont(QFont("Segoe UI", size, QFont.Bold if bold else QFont.Normal))
    l.setStyleSheet(f"color: {color}; background: transparent;")
    return l


def _score_to_percent(raw_value) -> float:
    """
    Normalize a stored model score to 0–100.

    RAMDetect history may store model output either as a 0–1 fraction
    (0.55) or as an already-scaled percentage (55.0). The dashboard should
    display percentages consistently without losing decimal precision.
    """
    try:
        val = float(raw_value)
    except (TypeError, ValueError):
        return 0.0

    if 0.0 <= val <= 1.0:
        val *= 100.0

    return max(0.0, min(100.0, val))


def _hybrid_score_pct(item: dict) -> float:
    """
    Return RAMDetect's final Hybrid Score as a 0–100 percentage.

    Under the current RF-AE architecture, the Dashboard must show the
    final suspicious-class hybrid score directly for both CLEAN and
    SUSPICIOUS rows. A CLEAN row with Hybrid Score 14.3% simply means
    the score is below the fixed 50% suspicious threshold; it must not be
    inverted into 85.7% verdict confidence.
    """
    return round(_score_to_percent(item.get("hybrid_score", item.get("confidence", 0.0))), 1)


def _hybrid_score_tooltip(item: dict, shown_pct: float) -> str:
    status = str(item.get("status", "")).strip().upper() or "UNKNOWN"
    return (
        f"Verdict: {status}\n"
        f"Hybrid Score: {shown_pct:.1f}%\n"
        "Decision threshold: Suspicious if Hybrid Score ≥ 50.0%"
    )


# ─────────────────────────────────────────────────────────────────────────────
# Stat card
# ─────────────────────────────────────────────────────────────────────────────

class _StatCard(QFrame):
    _THEMES = {
        "total":      ("🔍", "#3b82f6", "rgba(59,130,246,0.12)",  "#ffffff"),
        "clean":      ("🛡",  "#34d399", "rgba(52,211,153,0.12)",  "#34d399"),
        "suspicious": ("⚠",  "#f87171", "rgba(248,113,113,0.12)", "#f87171"),
        "last":       ("🕐", "#06b6d4", "rgba(6,182,212,0.12)",   "#ffffff"),
    }

    def __init__(self, kind: str, label: str, value: str, parent=None):
        super().__init__(parent)
        self.setObjectName("statCard")
        self.setFrameShape(QFrame.NoFrame)
        self.setFrameShadow(QFrame.Plain)
        icon, icon_col, icon_bg, num_col = self._THEMES.get(
            kind, ("?", "#fff", "transparent", "#fff")
        )
        # Scope to #statCard only — prevents cascade to child QLabels
        self.setStyleSheet(
            "QFrame#statCard {"
            "  background: rgba(30,41,59,0.45);"
            "  border: 1px solid rgba(51,65,85,0.5);"
            "  border-radius: 12px;"
            "}"
        )
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        self.setMinimumHeight(104)

        row = QHBoxLayout(self)
        row.setContentsMargins(22, 18, 22, 18)
        row.setSpacing(16)

        left = QVBoxLayout()
        left.setSpacing(5)

        lbl_w = QLabel(label)
        lbl_w.setFont(QFont("Segoe UI", 12))
        # Explicit border:none + border-radius:0 prevents PyQt5 cascade
        lbl_w.setStyleSheet(
            "color: #94a3b8; background: transparent;"
            " border: none; border-radius: 0px;"
        )

        self._num = QLabel(value)
        self._num.setFont(QFont("Segoe UI", 26, QFont.Bold))
        if kind == "last":
            self._num.setFont(QFont("Segoe UI", 18, QFont.DemiBold))
        self._num.setStyleSheet(
            f"color: {num_col}; background: transparent;"
            " border: none; border-radius: 0px;"
        )

        left.addWidget(lbl_w)
        left.addWidget(self._num)
        row.addLayout(left, stretch=1)

        icon_w = QLabel(icon)
        icon_w.setAlignment(Qt.AlignHCenter | Qt.AlignVCenter)
        icon_w.setFixedSize(48, 48)
        icon_w.setFont(QFont("Segoe UI", 20))
        bottom_pad = "6px" if kind == "suspicious" else "0px"
        icon_w.setStyleSheet(
            f"background: {icon_bg}; border-radius: 24px;"
            f" color: {icon_col}; border: none;"
            f" qproperty-alignment: AlignCenter;"
            f" padding-bottom: {bottom_pad}; margin: 0px;"
        )
        row.addWidget(icon_w, alignment=Qt.AlignVCenter | Qt.AlignRight)

    def set_value(self, val: str):
        self._num.setText(val)


# ─────────────────────────────────────────────────────────────────────────────
# Empty state  (shown when no scans exist yet)
# ─────────────────────────────────────────────────────────────────────────────

class _EmptyState(QWidget):
    new_scan_clicked = pyqtSignal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setStyleSheet(
            "QWidget { background: transparent; border: none; border-radius: 0; }"
            "QLabel  { border: none; border-radius: 0; background: transparent; }"
        )
        vb = QVBoxLayout(self)
        # The empty-state owns the whole history-card body when there is no
        # scan history. Keep it centered with enough breathing room, without
        # leaving a fake/empty table area above it.
        vb.setContentsMargins(24, 34, 24, 38)
        vb.setAlignment(Qt.AlignCenter)
        vb.setSpacing(12)

        icon = QLabel("🔬")
        icon.setFont(QFont("Segoe UI", 42))
        icon.setAlignment(Qt.AlignCenter)
        icon.setStyleSheet(
            "background: transparent; color: #64748b;"
            " border: none; border-radius: 0px;"
        )

        title = QLabel("No scans yet")
        title.setFont(QFont("Segoe UI", 17, QFont.Bold))
        title.setAlignment(Qt.AlignCenter)
        title.setStyleSheet(
            "color: #94a3b8; background: transparent;"
            " border: none; border-radius: 0px;"
        )

        sub = QLabel("Acquire a RAM dump or load an existing file to get started.")
        sub.setFont(QFont("Segoe UI", 12))
        sub.setAlignment(Qt.AlignCenter)
        sub.setStyleSheet(
            "color: #7f91ad; background: transparent;"
            " border: none; border-radius: 0px;"
        )

        btn = QPushButton("+ Start Your First Scan")
        btn.setObjectName("primaryBtn")
        btn.setFont(QFont("Segoe UI", 13, QFont.DemiBold))
        btn.setFixedSize(240, 44)
        btn.clicked.connect(self.new_scan_clicked)

        vb.addWidget(icon)
        vb.addWidget(title)
        vb.addWidget(sub)
        vb.addSpacing(8)
        vb.addWidget(btn, alignment=Qt.AlignCenter)


# ─────────────────────────────────────────────────────────────────────────────
# Dashboard page
# ─────────────────────────────────────────────────────────────────────────────

class DashboardPage(QWidget):
    def __init__(self, main_window, parent=None):
        super().__init__(parent)
        self.mw = main_window
        self.setStyleSheet("background: transparent;")
        self._sort_col  = 1    # default sort: Date column
        self._sort_asc  = False

        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        # ── Header ────────────────────────────────────────────────────────────
        hdr = HeaderBar(
            "New Scan",
            show_action=True,
            show_dashboard=False,
            offline_mode=getattr(self.mw, "offline_mode", False),
        )
        # Side-panel layout: align header logo and New Scan button with the
        # stat cards/history cards below.
        if hdr.layout() is not None:
            hdr.layout().setContentsMargins(20, 0, 20, 0)
        hdr.settings_clicked.connect(lambda: self.mw.navigate_to("settings"))
        hdr.action_clicked.connect(self._new_scan)
        root.addWidget(hdr)

        # ── Body ──────────────────────────────────────────────────────────────
        body = QVBoxLayout()
        body.setContentsMargins(20, 14, 20, 22)
        body.setSpacing(13)

        # Stat cards row
        stats_row = QHBoxLayout()
        stats_row.setSpacing(12)
        self.card_total = _StatCard("total",      "Total Scans", "0")
        self.card_clean = _StatCard("clean",      "Clean",       "0")
        self.card_susp  = _StatCard("suspicious", "Suspicious",  "0")
        self.card_last  = _StatCard("last",       "Last Scan",   "—")
        for c in (self.card_total, self.card_clean, self.card_susp, self.card_last):
            stats_row.addWidget(c)
        body.addLayout(stats_row)

        # History card (table + empty state stacked)
        # Keep the card responsive but do not let it consume the entire page height.
        # A bottom stretch preserves breathing room below the table at larger window sizes.
        self._history_card = self._build_history_card()
        body.addWidget(self._history_card, stretch=0)
        body.addStretch(1)

        root.addLayout(body, stretch=1)

        # Initial data load
        self._refresh_data()

    # ── Build history card ────────────────────────────────────────────────────

    def _build_history_card(self) -> QFrame:
        card = _card(12)
        card.setObjectName("historyCard")
        card.setFrameShape(QFrame.NoFrame)
        card.setFrameShadow(QFrame.Plain)
        card.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        card.setMinimumHeight(422)
        card.setMaximumHeight(552)
        card.setFixedHeight(512)
        # Only style the card frame itself — no cascade to children
        card.setStyleSheet(
            "QFrame#historyCard {"
            "  background: rgba(30,41,59,0.45);"
            "  border: 1px solid rgba(51,65,85,0.5);"
            "  border-radius: 12px;"
            "}"
        )

        vb = QVBoxLayout(card)
        vb.setContentsMargins(0, 0, 0, 0)
        vb.setSpacing(0)

        # ── Card header bar ───────────────────────────────────────────────────
        hdr_bar = QFrame()
        hdr_bar.setObjectName("histHdr")
        hdr_bar.setFrameStyle(QFrame.NoFrame)
        hdr_bar.setFixedHeight(52)
        hdr_bar.setStyleSheet(
            "QFrame#histHdr {"
            "  background: transparent;"
            "  border: none;"
            "  border-bottom: 1px solid rgba(51,65,85,0.4);"
            "  border-radius: 0px;"
            "}"
        )
        hdr_row = QHBoxLayout(hdr_bar)
        hdr_row.setContentsMargins(20, 0, 20, 0)
        hdr_row.setSpacing(10)

        icon_l = _ActivityIcon(20)
        title_l = QLabel("Recent Analysis History")
        title_l.setFont(QFont("Segoe UI", 13, QFont.Bold))
        title_l.setStyleSheet(
            "color: #ffffff; background: transparent;"
            " border: none; border-radius: 0px;"
        )

        hdr_row.addWidget(icon_l, alignment=Qt.AlignVCenter)
        hdr_row.addWidget(title_l)
        hdr_row.addStretch()


        vb.addWidget(hdr_bar)

        # ── Table ─────────────────────────────────────────────────────────────
        self.table = QTableWidget()
        self.table.setObjectName("historyTable")
        self.table.setFrameShape(QFrame.NoFrame)
        self.table.setFrameShadow(QFrame.Plain)
        self.table.setColumnCount(6)
        self.table.setHorizontalHeaderLabels(
            ["Filename", "Date & Time", "Size", "Status", "Hybrid Score", "Actions"]
        )
        self.table.verticalHeader().setVisible(False)
        self.table.setShowGrid(False)
        self.table.setSelectionBehavior(QTableWidget.SelectRows)
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.table.setFocusPolicy(Qt.NoFocus)
        self.table.setSortingEnabled(False)
        self.table.setTextElideMode(Qt.ElideMiddle)
        self.table.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.table.setAlternatingRowColors(True)
        # Row bg colours -- cell widgets must match exactly to prevent ghost
        self._row_bg = ("#111827", "#0d1523")
        self.table.setStyleSheet(
            "QTableWidget#historyTable { "
            "  background: #111827; "
            "  border: none; "
            "  border-radius: 0px; "
            "}"
            "QTableWidget::item    { padding: 0px 4px 0px 12px; border: none; color: #ffffff; }"
            "QTableWidget::item:alternate { background: #0d1523; }"
            "QTableWidget::item:hover     { background: rgba(51,65,85,0.45); }"
            "QTableWidget::item:selected  { background: rgba(6,182,212,0.15); color: white; }"
            "QScrollBar:vertical {"
            "  background: #0b1220;"
            "  width: 8px;"
            "  margin: 2px 1px 2px 0px;"
            "  border-radius: 4px;"
            "}"
            "QScrollBar::handle:vertical {"
            "  background: rgba(100,116,139,0.50);"
            "  border-radius: 4px;"
            "  min-height: 36px;"
            "}"
            "QScrollBar::handle:vertical:hover {"
            "  background: rgba(148,163,184,0.62);"
            "}"
            "QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {"
            "  height: 0px;"
            "  background: transparent;"
            "}"
            "QScrollBar::add-page:vertical, QScrollBar::sub-page:vertical {"
            "  background: transparent;"
            "}"
        )

        hh = self.table.horizontalHeader()
        hh.setSectionResizeMode(0, QHeaderView.Fixed);  hh.resizeSection(0, 300)  # Filename
        hh.setSectionResizeMode(1, QHeaderView.Fixed);  hh.resizeSection(1, 155)  # Date & Time
        hh.setSectionResizeMode(2, QHeaderView.Fixed);  hh.resizeSection(2, 82)   # Size
        hh.setSectionResizeMode(3, QHeaderView.Fixed);  hh.resizeSection(3, 170)  # Status
        hh.setSectionResizeMode(4, QHeaderView.Stretch)                           # Hybrid Score
        hh.setSectionResizeMode(5, QHeaderView.Fixed);  hh.resizeSection(5, 185)  # Actions
        hh.sectionClicked.connect(self._header_clicked)
        hh.setDefaultAlignment(Qt.AlignLeft | Qt.AlignVCenter)
        hh.setFixedHeight(42)
        hh.setStyleSheet(
            "QHeaderView           { background: #0d1523; border: none; }"
            "QHeaderView::section  {"
            "  background: #0d1523; color: #cbd5e1;"
            "  font-size: 12px; font-weight: 600;"
            # padding-left: 2px matches item padding-left for column alignment
            "  padding-left: 12px;"
            "  border: none;"
            "  border-bottom: 1px solid rgba(51,65,85,0.5);"
            "}"
            "QHeaderView::section:hover { background: rgba(6,182,212,0.07); }"
        )

        self._table_wrap = QFrame()
        table_wrap = self._table_wrap
        table_wrap.setObjectName("historyTableWrap")
        table_wrap.setFrameShape(QFrame.NoFrame)
        table_wrap.setStyleSheet(
            "QFrame#historyTableWrap {"
            "  background: #111827;"
            "  border: none;"
            "  border-bottom-left-radius: 12px;"
            "  border-bottom-right-radius: 12px;"
            "}"
        )
        tw = QVBoxLayout(table_wrap)
        # This bottom inset is the key visual fix: the table viewport no longer
        # reaches the outer edge, so the rounded lower corners remain visible.
        tw.setContentsMargins(0, 0, 0, 8)
        tw.setSpacing(0)
        tw.addWidget(self.table, stretch=1)
        vb.addWidget(table_wrap, stretch=1)

        # ── Empty state (shown when history is empty) ─────────────────────────
        self._empty = _EmptyState()
        self._empty.new_scan_clicked.connect(self._new_scan)
        vb.addWidget(self._empty, stretch=1)
        self._empty.hide()

        return card

    # ── Data loading ──────────────────────────────────────────────────────────

    def _refresh_data(self):
        """Pull fresh data from AppState and update all widgets."""
        stats = AppState.get_stats()
        self.card_total.set_value(str(stats["total"]))
        self.card_clean.set_value(str(stats["clean"]))
        self.card_susp.set_value(str(stats["suspicious"]))
        self.card_last.set_value(stats["last_scan"])

        self._history = AppState.load_history()
        n = len(self._history)

        if n == 0:
            # Hide the whole table container, not only QTableWidget.
            # Previously the wrapper stayed visible and created the large
            # dark rectangle above the "No scans yet" message.
            self.table.setRowCount(0)
            self.table.hide()
            if hasattr(self, "_table_wrap"):
                self._table_wrap.hide()
            self._empty.show()
        else:
            self._empty.hide()
            if hasattr(self, "_table_wrap"):
                self._table_wrap.show()
            self.table.show()
            self._populate_table(self._history)

    def _populate_table(self, history: list):
        # Apply current sort
        col = self._sort_col
        asc = self._sort_asc
        SORT_KEYS = {
            0: lambda h: h["filename"].lower(),
            1: lambda h: h["datetime"],
            2: lambda h: h.get("size_bytes", 0),       # sort size numerically
            3: lambda h: h["status"],
            4: _hybrid_score_pct,
        }
        if col in SORT_KEYS:
            history = sorted(history, key=SORT_KEYS[col], reverse=not asc)

        self.table.setRowCount(len(history))
        for row, item in enumerate(history):
            self.table.setRowHeight(row, 54)
            rbg = self._row_bg[row % 2]

            # -- Col 0: Filename -------------------------------------------------
            # Use QTableWidgetItem instead of a QLabel cell widget so Qt can
            # properly elide long names in the middle while preserving the file
            # extension. Full path/name remains available in the tooltip.
            fn_item = QTableWidgetItem(item["filename"])
            fn_item.setFont(QFont("Segoe UI", 11))
            fn_item.setForeground(QColor("#ffffff"))
            fn_item.setTextAlignment(Qt.AlignLeft | Qt.AlignVCenter)
            fn_item.setToolTip(item.get("dump_path", item["filename"]))
            self.table.setItem(row, 0, fn_item)

            # -- Col 1: Date & Time  (2px left via QSS padding reduction) ------
            dt_str = item["datetime"].strftime("%Y-%m-%d  %H:%M")
            dt = QTableWidgetItem(dt_str)
            dt.setFont(QFont("Segoe UI", 11))
            dt.setForeground(QColor("#94a3b8"))
            dt.setTextAlignment(Qt.AlignLeft | Qt.AlignVCenter)  # ← add this
            self.table.setItem(row, 1, dt)

            # -- Col 2: Size  (2px left via QSS padding reduction) -------------
            sz = QTableWidgetItem(item["size"])
            sz.setFont(QFont("Segoe UI", 11))
            sz.setForeground(QColor("#94a3b8"))
            sz.setTextAlignment(Qt.AlignLeft | Qt.AlignVCenter)
            sz.setData(Qt.UserRole, item.get("size_bytes", 0))
            self.table.setItem(row, 2, sz)

            # -- Col 3: Status badge  (3px left: margin 12->9) -----------------
            badge_cell = QWidget()
            badge_cell.setObjectName(f"bCell{row}")
            badge_cell.setAutoFillBackground(True)
            badge_cell.setStyleSheet(
                f"QWidget#bCell{row} {{ background: {rbg}; border: none; }}"
            )
            bl = QHBoxLayout(badge_cell)
            bl.setContentsMargins(0, 0, 4, 0)
            bl.setAlignment(Qt.AlignLeft | Qt.AlignVCenter)
            badge = StatusBadge(item["status"])
            badge.setAttribute(Qt.WA_StyledBackground, True)
            badge.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Fixed)
            bl.addWidget(badge)
            bl.addStretch()
            self.table.setCellWidget(row, 3, badge_cell)

            # -- Col 4: Hybrid Score bar ---------------------------------------
            # The Hybrid Score is RAMDetect's final suspicious-class ML score.
            # Do not invert it for CLEAN rows.
            hybrid_pct = _hybrid_score_pct(item)
            meter_cell = QWidget()
            meter_cell.setObjectName(f"mCell{row}")
            meter_cell.setAutoFillBackground(True)
            meter_cell.setStyleSheet(
                f"QWidget#mCell{row} {{ background: {rbg}; border: none; }}"
            )
            meter_cell.setToolTip(_hybrid_score_tooltip(item, hybrid_pct))
            ml = QHBoxLayout(meter_cell)
            ml.setContentsMargins(0, 0, 8, 0)
            ml.setAlignment(Qt.AlignVCenter)
            meter = ConfidenceMeter(hybrid_pct, item["status"], height=8)
            meter.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Preferred)
            ml.addWidget(meter)
            self.table.setCellWidget(row, 4, meter_cell)

            # -- Col 5: Actions  (3px left: margin 8->5) ----------------------
            action_cell = QWidget()
            action_cell.setObjectName(f"aCell{row}")
            action_cell.setAutoFillBackground(True)
            action_cell.setStyleSheet(
                f"QWidget#aCell{row} {{ background: {rbg}; border: none; }}"
            )
            al = QHBoxLayout(action_cell)
            al.setContentsMargins(0, 0, 16, 0)
            al.setSpacing(4)
            al.setAlignment(Qt.AlignLeft | Qt.AlignVCenter)

            view_btn = QPushButton("View Details →")
            view_btn.setObjectName("linkBtn")
            view_btn.setFont(QFont("Segoe UI", 11))
            view_btn.setFixedWidth(116)
            view_btn.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Fixed)
            view_btn.setStyleSheet(
                "QPushButton#linkBtn { padding: 4px 0px 4px 0px; text-align: left; }"
            )
            view_btn.clicked.connect(lambda _, h=item: self._view_details(h))
            al.addWidget(view_btn)

            dump_path = item.get("dump_path", "")
            if dump_path:
                import os
                rerun_btn = QPushButton("↺")
                rerun_btn.setObjectName("iconBtn")
                rerun_btn.setToolTip("Re-run analysis on this dump")
                rerun_btn.setFont(QFont("Segoe UI", 13))
                rerun_btn.setFixedSize(26, 26)
                rerun_btn.setStyleSheet(
                    "QPushButton#iconBtn {"
                    "  padding: 0px; margin: 0px;"
                    "  qproperty-iconSize: 0px;"
                    "  text-align: center;"
                    "  line-height: 26px;"
                    "}"
                )
                rerun_btn.clicked.connect(
                    lambda _, dp=dump_path, fn=item["filename"]: self._rerun(dp, fn)
                )
                al.addWidget(rerun_btn)

            al.addStretch()
            self.table.setCellWidget(row, 5, action_cell)

        # Update sort indicator in header
        self._update_sort_indicators()

    # ── Sort ──────────────────────────────────────────────────────────────────

    def _header_clicked(self, col: int):
        """Toggle asc/desc on the clicked column; ignore Actions column."""
        if col == 5:
            return
        if self._sort_col == col:
            self._sort_asc = not self._sort_asc
        else:
            self._sort_col = col
            self._sort_asc = True
        self._populate_table(self._history)

    def _update_sort_indicators(self):
        hh = self.table.horizontalHeader()
        labels = ["Filename", "Date & Time", "Size", "Status", "Hybrid Score", "Actions"]
        for i, base in enumerate(labels):
            if i == self._sort_col and i != 5:
                arrow = " ▲" if self._sort_asc else " ▼"
                hh.model().setHeaderData(
                    i, Qt.Horizontal, base + arrow
                )
            else:
                hh.model().setHeaderData(i, Qt.Horizontal, base)

    # ── Navigation ────────────────────────────────────────────────────────────

    def _new_scan(self):
        """Start a fresh session then navigate to Acquisition."""
        AppState.new_session()
        self.mw.navigate_to("acquisition")

    def _view_details(self, history_item: dict):
        """
        Restore a previous scan's data into AppState.current so the
        Results page can display it, then navigate there.

        Priority:
          1. Full session JSON (saved by AppState.save_full() after analysis)
             — all artifact data, ML result and findings are available.
          2. Fallback to synthesised ml_result from history summary when no
             session file exists (hybrid score scaled from 0-1 → 0-100).
        """
        session_id  = history_item.get("id", "")
        hybrid_pct  = _hybrid_score_pct(history_item)
        status      = history_item["status"]    # 'clean' | 'suspicious'
        is_susp     = status == "suspicious"

        # ── 1. Try to load full session from disk ─────────────────────────────
        if session_id and AppState.full_session_exists(session_id):
            full_sess = AppState.load_full(session_id)
            if full_sess is not None:
                AppState._current = full_sess
                self.mw.navigate_to("results")
                return

        # ── 2. Fallback: build a lightweight session from history summary ──────
        rf_est = max(0.0, min(100.0, hybrid_pct + (1.5 if is_susp else -1.5)))
        ae_est = max(0.0, min(100.0, hybrid_pct - (4.0 if is_susp else -4.0)))

        ml_result = {
            "verdict":              status,
            "confidence":           hybrid_pct,
            "hybrid_score":         hybrid_pct,
            "suspicion_score":      hybrid_pct,
            "display_score":        hybrid_pct,
            "display_score_label":  "hybrid_score",
            "rf_score":             round(rf_est, 1),
            "ae_score":             round(ae_est, 1),
            "reconstruction_error": 0.0,
            "ae_threshold":         0.004,
            "label":                1 if is_susp else 0,
            "feature_importance":   [],
            "anomaly_distribution": {
                "clean":      round(100.0 - hybrid_pct, 1),
                "suspicious": round(hybrid_pct, 1),
            },
        }
        findings = ([{
            "severity":    "medium",
            "category":    "History View",
            "description": (
                "Full artifact detail is only available immediately after a live scan "
                "or when the session was saved. "
                f"Recorded hybrid score: {hybrid_pct:.1f}%."
            ),
        }] if is_susp else [])

        sess = ScanSession.from_history_dict({
            "id":         session_id,
            "filename":   history_item["filename"],
            "datetime":   history_item["datetime"].isoformat(),
            "size":       history_item["size"],
            "size_bytes": history_item.get("size_bytes", 0),
            "mode":       history_item.get("mode", "file"),
            "dump_path":  history_item.get("dump_path", ""),
            "status":     status,
            "confidence": hybrid_pct,
            "hybrid_score": hybrid_pct,
        })
        sess.ml_result = ml_result
        sess.findings  = findings

        AppState._current = sess
        self.mw.navigate_to("results")

    def _rerun(self, dump_path: str, filename: str):
        """Pre-fill acquisition page with this dump file and navigate."""
        sess = AppState.new_session()
        sess.dump_path     = dump_path
        sess.dump_filename = filename
        sess.mode          = "file"
        self.mw.navigate_to("acquisition")

    # ── Responsive sizing ─────────────────────────────────────────────────────

    def resizeEvent(self, event):
        """Keep the history card balanced so the table does not touch the window edge."""
        super().resizeEvent(event)
        card = getattr(self, "_history_card", None)
        if card is not None:
            # Tuned for RAMDetect's 72px header + stat-card row.
            # Larger windows get a taller table, but the card keeps a visible bottom margin.
            target_h = max(422, min(552, self.height() - 318))
            card.setFixedHeight(target_h)

    # ── Auto-refresh on show ──────────────────────────────────────────────────

    def showEvent(self, event):
        """Refresh stats and table every time this page becomes visible."""
        super().showEvent(event)
        self._refresh_data()