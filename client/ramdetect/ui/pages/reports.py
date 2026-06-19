"""
ui/pages/reports.py — Reports page (Page 9)
Single outer card per panel. Sections are plain divider-separated blocks
inside the parent card — NO nested card borders, no white lines.
"""
from __future__ import annotations
import os
import subprocess
import platform
from datetime import datetime

from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QFrame, QPushButton,
    QTableWidget, QTableWidgetItem, QHeaderView, QSizePolicy,
    QScrollArea, QMessageBox, QDialog, QRadioButton, QButtonGroup, QDialogButtonBox,
)
from PyQt5.QtCore import Qt, QThread, QTimer, pyqtSignal
from PyQt5.QtGui import QColor

from ui.pages.base_page import BasePage
from ui.bridge.session import AppState
from ui.bridge.report_bridge import ReportBridge, _HAS_REPORTLAB
from ui.widgets.status_badge import StatusBadge
from ui.style_helpers import set_role, set_tone
from ui.theme import current_theme

# ── Palette ───────────────────────────────────────────────────────────────────
_BG_CARD   = '#1e293b'           # slate-800 solid — no transparency artifacts
_BG_INNER  = '#162032'           # slightly darker for info boxes
_BORDER    = '#334155'           # slate-700
_BORDER_LT = '#475569'           # slate-600
_CYAN      = '#06b6d4'
_CYAN_DIM  = 'rgba(6,182,212,26)'
_CYAN_BRD  = 'rgba(6,182,212,102)'
_GREEN     = '#34d399'
_GREEN_DIM = 'rgba(52,211,153,38)'
_GREEN_BRD = 'rgba(52,211,153,89)'
_RED       = '#f87171'
_RED_DIM   = 'rgba(248,113,113,38)'
_RED_BRD   = 'rgba(248,113,113,89)'
_TEXT      = '#f1f5f9'
_TEXT_SEC  = '#cbd5e1'
_MUTED     = '#94a3b8'
_MUTED2    = '#64748b'


def _refresh_palette(theme: str | None = None) -> None:
    """Refresh report-page presentation constants for the active UI theme."""
    global _BG_CARD, _BG_INNER, _BORDER, _BORDER_LT, _CYAN, _CYAN_DIM, _CYAN_BRD
    global _GREEN, _GREEN_DIM, _GREEN_BRD, _RED, _RED_DIM, _RED_BRD
    global _TEXT, _TEXT_SEC, _MUTED, _MUTED2
    light = (theme or current_theme() or 'dark').lower() == 'light'
    if light:
        _BG_CARD   = '#ffffff'
        _BG_INNER  = '#f8fbff'
        _BORDER    = '#d9e6ff'
        _BORDER_LT = '#c8d8f5'
        _CYAN      = '#1a56db'
        _CYAN_DIM  = '#eef4ff'
        _CYAN_BRD  = '#9fb7e5'
        _GREEN     = '#10b981'
        _GREEN_DIM = '#ecfdf5'
        _GREEN_BRD = '#86efac'
        _RED       = '#dc2626'
        _RED_DIM   = '#fff1f2'
        _RED_BRD   = '#fecaca'
        _TEXT      = '#1e3a6e'
        _TEXT_SEC  = '#385f9f'
        _MUTED     = '#6b82b4'
        _MUTED2    = '#7b8fb8'
    else:
        _BG_CARD   = '#1e293b'
        _BG_INNER  = '#162032'
        _BORDER    = '#334155'
        _BORDER_LT = '#475569'
        _CYAN      = '#06b6d4'
        _CYAN_DIM  = 'rgba(6,182,212,26)'
        _CYAN_BRD  = 'rgba(6,182,212,102)'
        _GREEN     = '#34d399'
        _GREEN_DIM = 'rgba(52,211,153,38)'
        _GREEN_BRD = 'rgba(52,211,153,89)'
        _RED       = '#f87171'
        _RED_DIM   = 'rgba(248,113,113,38)'
        _RED_BRD   = 'rgba(248,113,113,89)'
        _TEXT      = '#f1f5f9'
        _TEXT_SEC  = '#cbd5e1'
        _MUTED     = '#94a3b8'
        _MUTED2    = '#64748b'


def _rgba(light_hex: str, dark_rgba: str) -> str:
    return light_hex if (current_theme() or 'dark').lower() == 'light' else dark_rgba


def _is_light() -> bool:
    return (current_theme() or 'dark').lower() == 'light'


# ── Helpers ───────────────────────────────────────────────────────────────────

def _lbl(text: str, size: int = 13, color: str = _TEXT,
         bold: bool = False, mono: bool = False) -> QLabel:
    w = QLabel(text)
    w.setStyleSheet(
        f"color:{color};font-size:{size}px;background:transparent;border:none;border-radius:0px;"
        + ("font-weight:bold;" if bold else "")
        + ("font-family:Consolas,monospace;" if mono else "")
    )
    return w


def _divider() -> QWidget:
    """1 px slate-700 horizontal rule — plain QWidget, no QFrame.HLine to avoid ghost double-line."""
    w = QWidget()
    w.setFixedHeight(1)
    w.setAttribute(Qt.WA_StyledBackground, True)
    w.setStyleSheet(f"background:{_BORDER}; border:none; margin:0; padding:0;")
    return w


def _panel_card() -> QFrame:
    """Outer full-height card — single border, solid bg, rounded corners."""
    f = QFrame()
    f.setObjectName("ReportPanelCard")
    f.setFrameShape(QFrame.NoFrame)   # NoFrame avoids ghost double-line from StyledPanel
    f.setAttribute(Qt.WA_StyledBackground, True)
    # Scope to the outer card only. QLabel inherits QFrame, so a generic
    # "QFrame { ... }" selector creates unwanted rectangular borders around
    # labels such as Current Report and Source File.
    f.setStyleSheet(f"""
        QFrame#ReportPanelCard {{
            background: {_BG_CARD};
            border: 1px solid {_BORDER};
            border-radius: 12px;
        }}
    """)
    return f


def _audit_report_generated(path: str, fmt: str | None = None, verdict: str | None = None) -> None:
    """Best-effort Activity Monitor audit hook for report generation.

    This helper must never break report generation. It only writes a monitoring
    record when the Phase 4 activity logger is available.
    """
    try:
        from ramdetect.case_management.activity_logger import ActivityLogger
        ActivityLogger.instance().log_report_generated(
            path=path or "",
            fmt=(fmt or "unknown"),
            verdict=verdict,
        )
    except Exception:
        pass


def _audit_report_opened(path: str) -> None:
    """Best-effort Activity Monitor audit hook for opening a saved report."""
    try:
        from ramdetect.case_management.activity_logger import ActivityLogger
        ActivityLogger.instance().log_report_opened(path or "")
    except Exception:
        pass


# ── Clickable frame ───────────────────────────────────────────────────────────

class _ClickFrame(QFrame):
    clicked = pyqtSignal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setFrameShape(QFrame.NoFrame)
        self.setAttribute(Qt.WA_StyledBackground, True)
        from PyQt5.QtGui import QCursor
        self.setCursor(QCursor(Qt.PointingHandCursor))

    def mouseReleaseEvent(self, event):
        if event.button() == Qt.LeftButton and self.rect().contains(event.pos()):
            self.clicked.emit()
        super().mouseReleaseEvent(event)


# ── Toast notification ────────────────────────────────────────────────────────

class _Toast(QWidget):
    """
    Frameless floating pop-up notification — appears centred over the
    parent window and auto-dismisses after 3.5 s.

    Uses Qt.Tool | FramelessWindowHint | WindowStaysOnTopHint so it
    truly floats above every other widget (same pattern as the
    _ToastDialog in ArtifactsViewer).
    """

    def __init__(self, parent: QWidget, message: str, success: bool = True):
        super().__init__(
            parent,
            Qt.Tool | Qt.FramelessWindowHint | Qt.WindowStaysOnTopHint,
        )
        self.setAttribute(Qt.WA_TranslucentBackground)
        self.setAttribute(Qt.WA_DeleteOnClose)

        border = _GREEN if success else _RED
        bg     = 'rgba(17,51,34,247)' if success else 'rgba(60,17,17,247)'
        icon   = '✓' if success else '✗'

        # ── Outer transparent wrapper ──────────────────────────────────────
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)

        box = QFrame()
        box.setObjectName("ReportToastBox")
        box.setStyleSheet(f"""
            QFrame#ReportToastBox {{
                background: {bg};
                border: 2px solid {border};
                border-radius: 12px;
            }}
        """)
        bv = QHBoxLayout(box)
        bv.setContentsMargins(20, 16, 20, 16)
        bv.setSpacing(12)

        ico_lbl = QLabel(icon)
        ico_lbl.setStyleSheet(
            f"color:{border}; font-size:20px; font-weight:bold;"
            "background:transparent; border:none;"
        )
        bv.addWidget(ico_lbl)

        txt_lbl = QLabel(message)
        txt_lbl.setStyleSheet(
            f"color:{border}; font-size:12px;"
            "background:transparent; border:none;"
        )
        txt_lbl.setWordWrap(True)
        txt_lbl.setMaximumWidth(420)
        bv.addWidget(txt_lbl, 1)

        outer.addWidget(box)
        self.adjustSize()

    def show_on(self, parent: QWidget):
        """Centre over the top-level window and auto-dismiss after 3.5 s."""
        win = parent.window() if parent else None
        if win:
            geo = win.geometry()
            x   = geo.x() + (geo.width()  - self.sizeHint().width())  // 2
            y   = geo.y() + (geo.height() - self.sizeHint().height()) // 2
            self.move(x, y)
        self.show()
        self.raise_()
        QTimer.singleShot(3500, self.close)


# ── Worker ────────────────────────────────────────────────────────────────────

class _GenerateWorker(QThread):
    done = pyqtSignal(dict)

    def __init__(self, session, fmt: str, options: dict | None = None):
        super().__init__()
        self._session = session
        self._fmt = fmt
        self._options = options or {}

    def run(self):
        try:
            self.done.emit(ReportBridge.generate(self._session, self._fmt, self._options))
        except TypeError:
            # ReportBridge.generate doesn't accept options yet — fall back to 2-arg call
            self.done.emit(ReportBridge.generate(self._session, self._fmt))


# ══════════════════════════════════════════════════════════════════════════════
# PAGE
# ══════════════════════════════════════════════════════════════════════════════

class ReportsPage(BasePage):
    PAGE_TITLE = "Reports"

    _FORMATS = [
        ('pdf',  '📄', 'PDF Report',   'Executive summary with visualizations', '~2.4 MB'),
        ('json', '{}', 'JSON Export',  'Structured data for automation',         '~1.1 MB'),
        ('csv',  '📊', 'CSV Export',   'Tabular data for analysis',              '~850 KB'),
    ]
    _PDF_OPTS = [
        ('executive_summary', 'Executive Summary'),
        ('detailed_findings',  'Detailed Findings'),
        ('process_tree',       'Process Tree Diagram'),
        ('ml_analysis',        'ML Analysis & Charts'),
        ('artifact_tables',    'Artifact Tables'),
        ('report_only_artifacts', 'Report-Only Artifact Alerts'),
        ('visualizations',     'Data Visualizations'),
    ]

    def __init__(self, main_window):
        _refresh_palette(current_theme())
        # Reports is reached from Results Dashboard, so keep a quick return
        # button in the shared header, same as Artifacts Viewer.
        super().__init__(main_window, show_dashboard=True, show_results=True)
        self._selected_fmt: str = 'pdf'
        self._fmt_btns:  dict[str, _ClickFrame] = {}
        self._opt_btns:  dict[str, _ClickFrame] = {}
        self._opt_state: dict[str, bool] = {k: True for k, _ in self._PDF_OPTS}
        self._worker: _GenerateWorker | None = None
        self._table_paths: list[str] = []
        self._build_body()

    # ── Root ──────────────────────────────────────────────────────────────────

    def _build_body(self):
        root = self.body.layout()
        if root is None:
            root = QHBoxLayout(self.body)
        else:
            while root.count():
                item = root.takeAt(0)
                if item.widget():
                    item.widget().deleteLater()
                elif item.layout():
                    while item.layout().count():
                        child = item.layout().takeAt(0)
                        if child.widget():
                            child.widget().deleteLater()
        root.setContentsMargins(40, 20, 40, 20)
        root.setSpacing(18)
        root.addWidget(self._build_left(),  1)
        root.addWidget(self._build_right(), 1)

    # ══════════════════════════════════════════════════════════════════════════
    # LEFT PANEL
    # ══════════════════════════════════════════════════════════════════════════

    def _build_left(self) -> QFrame:
        """
        One outer card. Inside: a scrollable region (sections split by _divider())
        and a generate button pinned at the bottom. Zero nested card borders.
        """
        card = _panel_card()
        card.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        v = QVBoxLayout(card)
        v.setContentsMargins(0, 0, 0, 0)
        v.setSpacing(0)

        # ── Scrollable content ────────────────────────────────────────────────
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        scroll.setVerticalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        scroll.setFrameShape(QFrame.NoFrame)
        scroll.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        scroll.setStyleSheet(f"""
            QScrollArea {{ background: transparent; border: none; }}
            QScrollBar:vertical {{
                background: {_BG_CARD}; width: 6px; border-radius: 3px;
            }}
            QScrollBar::handle:vertical {{
                background: {_BORDER_LT}; border-radius: 3px; min-height: 20px;
            }}
            QScrollBar::add-line:vertical,
            QScrollBar::sub-line:vertical {{ height: 0; }}
        """)

        inner = QWidget()
        inner.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Preferred)
        set_role(inner, "transparent")
        iv = QVBoxLayout(inner)
        iv.setContentsMargins(0, 0, 0, 0)
        iv.setSpacing(0)

        iv.addWidget(self._section_current_report())
        iv.addWidget(_divider())
        iv.addWidget(self._section_format())
        iv.addWidget(_divider())
        self._pdf_section = self._section_pdf_options()
        iv.addWidget(self._pdf_section)
        iv.addStretch(1)

        scroll.setWidget(inner)
        scroll.viewport().setStyleSheet("background: transparent;")
        v.addWidget(scroll, 1)

        # ── Divider + generate button ─────────────────────────────────────────
        v.addWidget(_divider())

        btn_wrap = QWidget()
        set_role(btn_wrap, "transparent")
        bv = QVBoxLayout(btn_wrap)
        bv.setContentsMargins(20, 14, 20, 16)
        bv.setSpacing(0)

        self._gen_btn = QPushButton("⬇   Generate Download Report")
        self._gen_btn.setMinimumHeight(50)
        self._gen_btn.setCursor(Qt.PointingHandCursor)
        self._gen_btn.setStyleSheet(f"""
            QPushButton {{
                background: qlineargradient(
                    x1:0, y1:0, x2:1, y2:0,
                    stop:0 {_CYAN}, stop:1 #2563eb);
                color: #ffffff;
                border: none;
                border-radius: 10px;
                font-size: 14px;
                font-weight: bold;
            }}
            QPushButton:hover {{
                background: qlineargradient(
                    x1:0, y1:0, x2:1, y2:0,
                    stop:0 #0891b2, stop:1 #1d4ed8);
            }}
            QPushButton:pressed {{
                background: qlineargradient(
                    x1:0, y1:0, x2:1, y2:0,
                    stop:0 #0e7490, stop:1 #1e40af);
            }}
            QPushButton:disabled {{
                background: #1e293b;
                color: {_MUTED2};
            }}
        """)
        self._gen_btn.clicked.connect(self._generate)
        bv.addWidget(self._gen_btn)

        v.addWidget(btn_wrap)
        # Store card ref for toast positioning
        self._left_card = card
        return card

    # ── Section helpers (plain QWidget, NO border/card) ───────────────────────

    def _section_current_report(self) -> QWidget:
        w = QWidget()
        set_role(w, "transparent")
        v = QVBoxLayout(w)
        v.setContentsMargins(20, 18, 20, 18)
        v.setSpacing(12)

        hdr = QHBoxLayout()
        hdr.setSpacing(8)
        hdr.addWidget(_lbl("📋", 14))
        hdr.addWidget(_lbl("Current Report", 14, _TEXT, bold=True))
        hdr.addStretch()
        v.addLayout(hdr)

        # Source file box — QWidget (not QFrame) has no native frame painting
        src = QWidget()
        src.setObjectName("srcBox")
        src.setAttribute(Qt.WA_StyledBackground, True)
        src.setStyleSheet(f"""
            QWidget#srcBox {{
                background: {_BG_INNER};
                border: 1px solid {_BORDER};
                border-radius: 8px;
            }}
        """)
        sv = QVBoxLayout(src)
        sv.setContentsMargins(14, 12, 14, 12)
        sv.setSpacing(4)

        row = QHBoxLayout()
        self._src_lbl = _lbl("Source File", 11, _MUTED)
        row.addWidget(self._src_lbl)
        row.addStretch()
        self._info_badge = StatusBadge('pending')
        row.addWidget(self._info_badge)
        sv.addLayout(row)

        self._info_filename = _lbl("—", 13, _TEXT_SEC, bold=True)
        self._info_filename.setWordWrap(True)
        sv.addWidget(self._info_filename)

        self._info_date = _lbl("—", 11, _MUTED)
        sv.addWidget(self._info_date)
        v.addWidget(src)

        # Output filename box — QWidget (not QFrame) has no native frame painting
        out = QWidget()
        out.setObjectName("outBox")
        out.setAttribute(Qt.WA_StyledBackground, True)
        out.setStyleSheet(f"""
            QWidget#outBox {{
                background: {_CYAN_DIM};
                border: 1px solid {_CYAN_BRD};
                border-radius: 8px;
            }}
        """)
        ov = QVBoxLayout(out)
        ov.setContentsMargins(14, 10, 14, 10)
        ov.setSpacing(3)
        ov.addWidget(_lbl("Output Filename", 11, _MUTED))
        self._info_output = _lbl("—", 12, _CYAN, bold=True, mono=True)
        self._info_output.setWordWrap(True)
        ov.addWidget(self._info_output)
        v.addWidget(out)

        return w

    def _section_format(self) -> QWidget:
        w = QWidget()
        set_role(w, "transparent")
        v = QVBoxLayout(w)
        v.setContentsMargins(20, 18, 20, 18)
        v.setSpacing(10)

        hdr = QHBoxLayout()
        hdr.setSpacing(8)
        hdr.addWidget(_lbl("📄", 14))
        hdr.addWidget(_lbl("Select Export Format", 14, _TEXT, bold=True))
        hdr.addStretch()
        v.addLayout(hdr)

        for fmt_id, icon, label, desc, size in self._FORMATS:
            btn = self._make_format_row(fmt_id, icon, label, desc, size)
            self._fmt_btns[fmt_id] = btn
            v.addWidget(btn)

        self._refresh_fmt_styles()
        return w

    def _make_format_row(self, fmt_id, icon, label, desc, size_str) -> _ClickFrame:
        frame = _ClickFrame()
        frame.setObjectName(f"fmtRow_{fmt_id}")
        frame.setFixedHeight(62)
        frame.setFrameShape(QFrame.NoFrame)
        frame.setAttribute(Qt.WA_StyledBackground, True)
        frame.clicked.connect(lambda f=fmt_id: self._select_fmt(f))

        h = QHBoxLayout(frame)
        h.setContentsMargins(14, 0, 14, 0)
        h.setSpacing(12)

        icon_box = QFrame()
        icon_box.setFixedSize(38, 38)
        icon_box.setObjectName(f"ib_{fmt_id}")
        icon_box.setStyleSheet(
            f"QFrame#ib_{fmt_id} {{ background:rgba(71,85,105,128); border-radius:8px; border:none; }}"
        )
        il = QVBoxLayout(icon_box)
        il.setContentsMargins(0, 0, 0, 0)
        ico = QLabel(icon)
        ico.setAlignment(Qt.AlignCenter)
        ico.setStyleSheet("font-size:15px; background:transparent; border:none;")
        il.addWidget(ico)
        h.addWidget(icon_box)

        tw = QWidget()
        set_role(tw, "transparent")
        tv = QVBoxLayout(tw)
        tv.setContentsMargins(0, 0, 0, 0)
        tv.setSpacing(2)
        nl = QLabel(label)
        nl.setStyleSheet(f"color:{_TEXT}; font-size:13px; font-weight:bold; background:transparent; border:none;")
        dl = QLabel(desc)
        dl.setStyleSheet(f"color:{_MUTED}; font-size:11px; background:transparent; border:none;")
        tv.addWidget(nl)
        tv.addWidget(dl)
        h.addWidget(tw, 1)

        rw = QWidget()
        set_role(rw, "transparent")
        rv = QVBoxLayout(rw)
        rv.setContentsMargins(0, 0, 0, 0)
        rv.setSpacing(2)
        rv.setAlignment(Qt.AlignRight | Qt.AlignVCenter)
        ck = QLabel("✓")
        ck.setObjectName(f"ck_{fmt_id}")
        ck.setAlignment(Qt.AlignRight)
        ck.setStyleSheet(f"color:{_CYAN}; font-size:15px; font-weight:bold; background:transparent; border:none;")
        ck.setVisible(False)
        sz = QLabel(size_str)
        sz.setAlignment(Qt.AlignRight)
        sz.setStyleSheet(f"color:{_MUTED}; font-size:11px; background:transparent; border:none;")
        rv.addWidget(ck)
        rv.addWidget(sz)
        h.addWidget(rw)

        frame.setProperty('icon_box', icon_box)
        frame.setProperty('check_lbl', ck)
        frame.setProperty('fmt_id', fmt_id)
        return frame

    def _refresh_fmt_styles(self):
        for fmt_id, frame in self._fmt_btns.items():
            sel = (fmt_id == self._selected_fmt)
            ib: QFrame = frame.property('icon_box')
            ck: QLabel = frame.property('check_lbl')
            if sel:
                frame.setStyleSheet(f"""
                    QFrame#fmtRow_{fmt_id} {{
                        background: {_CYAN_DIM};
                        border: 2px solid {_CYAN};
                        border-radius: 10px;
                    }}
                """)
                ib.setStyleSheet(
                    f"QFrame#ib_{fmt_id} {{ background:rgba(6,182,212,64); border-radius:8px; border:none; }}"
                )
                ck.setVisible(True)
            else:
                frame.setStyleSheet(f"""
                    QFrame#fmtRow_{fmt_id} {{
                        background: {_BG_INNER};
                        border: 1px solid {_BORDER};
                        border-radius: 10px;
                    }}
                """)
                ib.setStyleSheet(
                    f"QFrame#ib_{fmt_id} {{ background:rgba(71,85,105,128); border-radius:8px; border:none; }}"
                )
                ck.setVisible(False)

        if hasattr(self, '_pdf_section'):
            self._pdf_section.setVisible(self._selected_fmt == 'pdf')

    def _select_fmt(self, fmt: str):
        self._selected_fmt = fmt
        self._refresh_fmt_styles()
        self._refresh_output_name()

    def _section_pdf_options(self) -> QWidget:
        w = QWidget()
        set_role(w, "transparent")
        v = QVBoxLayout(w)
        v.setContentsMargins(20, 18, 20, 18)
        v.setSpacing(8)
        v.addWidget(_lbl("Report Contents", 14, _TEXT, bold=True))

        for key, label in self._PDF_OPTS:
            btn = self._make_opt_toggle(key, label)
            self._opt_btns[key] = btn
            v.addWidget(btn)

        return w

    def _make_opt_toggle(self, key: str, label: str) -> _ClickFrame:
        frame = _ClickFrame()
        frame.setObjectName(f"optRow_{key}")
        frame.setFixedHeight(42)
        frame.setFrameShape(QFrame.NoFrame)
        frame.setAttribute(Qt.WA_StyledBackground, True)
        frame.clicked.connect(lambda k=key: self._toggle_opt(k))

        h = QHBoxLayout(frame)
        h.setContentsMargins(16, 0, 16, 0)
        h.setSpacing(0)

        tl = QLabel(label)
        tl.setStyleSheet(f"color:{_TEXT_SEC}; font-size:13px; background:transparent; border:none;")
        h.addWidget(tl)
        h.addStretch()

        ck = QLabel("✓")
        ck.setStyleSheet(f"color:{_CYAN}; font-size:14px; font-weight:bold; background:transparent; border:none;")
        h.addWidget(ck)

        frame.setProperty('check_lbl', ck)
        self._apply_opt_style(frame, True)
        return frame

    def _toggle_opt(self, key: str):
        self._opt_state[key] = not self._opt_state[key]
        self._apply_opt_style(self._opt_btns[key], self._opt_state[key])

    def _apply_opt_style(self, frame: _ClickFrame, checked: bool):
        ck: QLabel = frame.property('check_lbl')
        if checked:
            row_name = frame.objectName() or "optRow"
            frame.setStyleSheet(f"""
                QFrame#{row_name} {{
                    background: {_CYAN_DIM};
                    border: 1px solid {_CYAN_BRD};
                    border-radius: 8px;
                }}
            """)
            ck.setVisible(True)
        else:
            row_name = frame.objectName() or "optRow"
            frame.setStyleSheet(f"""
                QFrame#{row_name} {{
                    background: rgba(15,23,42,89);
                    border: 1px solid {_BORDER};
                    border-radius: 8px;
                }}
            """)
            ck.setVisible(False)

    # ══════════════════════════════════════════════════════════════════════════
    # RIGHT PANEL
    # ══════════════════════════════════════════════════════════════════════════

    def _build_right(self) -> QFrame:
        card = _panel_card()
        card.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        v = QVBoxLayout(card)
        v.setContentsMargins(0, 0, 0, 0)
        v.setSpacing(0)

        # Header — flat rectangle, no border-radius, fills flush under card's top border
        hdr = QWidget()
        hdr.setObjectName("libHdr")
        hdr.setAttribute(Qt.WA_StyledBackground, True)
        hdr.setStyleSheet(f"""
            QWidget#libHdr {{
                background: {_rgba("#f8fbff", "rgba(51,65,85,64)")};
                border: none;
                border-top-left-radius: 11px;
                border-top-right-radius: 11px;
            }}
            QWidget#libHdr * {{
                background: transparent;
                border: none;
            }}
        """)
        hl = QHBoxLayout(hdr)
        hl.setContentsMargins(20, 16, 20, 16)
        hl.setSpacing(8)
        hl.addWidget(_lbl("📋", 14))
        hl.addWidget(_lbl("Saved Reports Library", 14, _TEXT, bold=True))
        hl.addStretch()
        v.addWidget(hdr)
        v.addWidget(_divider())

        # Table
        self._table = QTableWidget(0, 5)
        self._table.setHorizontalHeaderLabels(
            ['Name', 'Format', 'Size', 'Status', 'Actions']
        )
        hh = self._table.horizontalHeader()
        hh.setSectionResizeMode(0, QHeaderView.Stretch)
        hh.setSectionResizeMode(1, QHeaderView.Fixed)
        hh.setSectionResizeMode(2, QHeaderView.Fixed)
        hh.setSectionResizeMode(3, QHeaderView.Fixed)
        hh.setSectionResizeMode(4, QHeaderView.Fixed)

        # Date is removed from the visible table and moved into the Name tooltip.
        # Keep fixed columns compact but wide enough for badges/actions.
        self._table.setColumnWidth(1, 76)    # Format
        self._table.setColumnWidth(2, 86)    # Size
        self._table.setColumnWidth(3, 124)   # Status badge
        self._table.setColumnWidth(4, 166)   # Open / Folder actions
        self._table.verticalHeader().setVisible(False)
        self._table.setSelectionBehavior(QTableWidget.SelectRows)
        self._table.setEditTriggers(QTableWidget.NoEditTriggers)
        self._table.setShowGrid(False)
        self._table.setAlternatingRowColors(False)
        self._table.setWordWrap(False)
        self._table.setTextElideMode(Qt.ElideMiddle)
        self._table.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        # Reserve a small right gutter so Actions buttons do not get clipped by
        # the vertical scrollbar area on Windows/high-DPI scaling.
        self._table.setViewportMargins(0, 0, 6, 0)
        # Force header view to be completely flat — no border-radius from any global QSS
        hh.setStyleSheet(f"""
            QHeaderView {{ border: none; border-radius: 0px; background: transparent; }}
            QHeaderView::section {{
                background: {_rgba('#eaf1ff', 'rgba(51,65,85,76)')};
                color: {_MUTED};
                padding: 10px 6px;
                border: none;
                border-radius: 0px;
                border-bottom: 1px solid {_BORDER};
                font-size: 11px;
                font-weight: bold;
            }}
        """)
        self._table.setStyleSheet(f"""
            QTableWidget {{
                background: transparent;
                border: none;
                color: {_TEXT_SEC};
                font-size: 12px;
            }}
            QTableWidget::item {{
                padding: 6px 8px;
                border-bottom: 1px solid {_BORDER};
                background: transparent;
            }}
            QTableWidget::item:hover   {{ background: rgba(71,85,105,51); }}
            QTableWidget::item:selected {{
                background: {_rgba("#dbeafe", "rgba(6,182,212,31)")};
                color: {_TEXT};
            }}
            QHeaderView {{
                border: none;
                border-radius: 0px;
                background: transparent;
            }}
            QHeaderView::section {{
                background: {_rgba("#eaf1ff", "rgba(51,65,85,76)")};
                color: {_MUTED};
                padding: 10px 8px;
                border: none;
                border-radius: 0px;
                border-bottom: 1px solid {_BORDER};
                font-size: 11px;
                font-weight: bold;
            }}
            QTableCornerButton::section {{
                background: {_rgba("#eaf1ff", "rgba(51,65,85,76)")};
                border: none;
                border-radius: 0px;
            }}
            QScrollBar:vertical {{
                background: {_BG_CARD};
                width: 8px;
                border-radius: 4px;
            }}
            QScrollBar::handle:vertical {{
                background: {_BORDER_LT};
                border-radius: 4px;
                min-height: 24px;
            }}
            QScrollBar::add-line:vertical,
            QScrollBar::sub-line:vertical {{ height: 0; }}
        """)
        v.addWidget(self._table, 1)

        # Footer
        v.addWidget(_divider())
        footer = QWidget()
        set_role(footer, "transparent")
        fl = QHBoxLayout(footer)
        fl.setContentsMargins(20, 12, 20, 12)

        self._lib_footer = QLabel("Total Reports: 0")
        self._lib_footer.setStyleSheet(
            f"color:{_MUTED}; font-size:13px; background:transparent; border:none;"
        )
        fl.addWidget(self._lib_footer)
        fl.addStretch()

        clear_btn = QPushButton("Clear All Reports")
        clear_btn.setCursor(Qt.PointingHandCursor)
        clear_btn.setStyleSheet(f"""
            QPushButton {{
                background: transparent;
                color: {_CYAN};
                border: none;
                font-size: 13px;
                font-weight: bold;
                padding: 0px;
            }}
            QPushButton:hover {{ color: #38bdf8; text-decoration: underline; }}
        """)
        clear_btn.clicked.connect(self._clear_all_reports)
        fl.addWidget(clear_btn)
        v.addWidget(footer)

        return card

    # ── Table row helpers ──────────────────────────────────────────────────────

    def _make_format_badge(self, fmt: str) -> QLabel:
        fmt_u = (fmt or "?").upper()
        lbl = QLabel(fmt_u)
        lbl.setAlignment(Qt.AlignCenter)
        lbl.setFixedHeight(22)
        lbl.setMinimumWidth(44)
        fg = {'PDF': _CYAN if _is_light() else _TEXT_SEC, 'JSON': _CYAN, 'CSV': _GREEN, 'XLSX': _CYAN if _is_light() else '#67e8f9', 'XML': '#7c3aed' if _is_light() else '#a78bfa'}.get(fmt_u, _TEXT_SEC)
        bg = '#f8fbff' if _is_light() else '#334155'
        brd = '#9fb7e5' if _is_light() else '#475569'
        lbl.setToolTip(f"Report format: {fmt_u}")
        lbl.setStyleSheet(f"""
            QLabel {{
                background: {bg};
                color: {fg};
                border: 1px solid {brd};
                border-radius: 5px;
                padding-left: 8px;
                padding-right: 8px;
                padding-top: 0px;
                padding-bottom: 0px;
                font-size: 10px;
                font-weight: bold;
                font-family: Consolas, monospace;
            }}
        """)
        return lbl

    def _make_status_cell(self, status: str) -> QWidget:
        """Render saved-report status clearly.

        Older artifact CSV/XLSX exports may not carry the analysis verdict, so
        showing a dash is confusing. In that case the library status means the
        file is saved/available, not clean or suspicious.
        """
        w = QWidget()
        set_role(w, "transparent")
        h = QHBoxLayout(w)
        h.setContentsMargins(2, 2, 2, 2)
        h.setAlignment(Qt.AlignCenter)

        s = (status or "").strip().lower()
        if s in ('clean', 'benign'):
            text, bg, fg, brd, tip = (
                "✓  CLEAN", _GREEN_DIM, _GREEN, _GREEN_BRD,
                "This report belongs to a session with a CLEAN ML verdict."
            )
        elif s in ('suspicious', 'malicious', 'ransomware'):
            text, bg, fg, brd, tip = (
                "⚠  SUSPICIOUS", _RED_DIM, _RED, _RED_BRD,
                "This report belongs to a session with a SUSPICIOUS ML verdict."
            )
        elif s in ('running', 'pending', 'processing'):
            text, bg, fg, brd, tip = (
                "⟳  PENDING", 'rgba(6,182,212,26)', _CYAN, _CYAN_BRD,
                "Report generation or analysis status is not complete yet."
            )
        else:
            text, bg, fg, brd, tip = (
                "✓  SAVED",
                ('#eef4ff' if _is_light() else 'rgba(148,163,184,31)'),
                (_CYAN if _is_light() else _MUTED),
                ('#c8d8f5' if _is_light() else 'rgba(148,163,184,71)'),
                "Saved report file. No verdict metadata was stored with this file."
            )

        lbl = QLabel(text)
        lbl.setAlignment(Qt.AlignCenter)
        lbl.setMinimumWidth(86)
        lbl.setToolTip(tip)
        lbl.setStyleSheet(f"""
            QLabel {{
                background:{bg}; color:{fg};
                border:1px solid {brd}; border-radius:10px;
                padding-top:2px; padding-bottom:2px; padding-left:7px; padding-right:7px; font-size:10px; font-weight:bold;
            }}
        """)
        h.addWidget(lbl)
        return w

    def _make_action_cell(self, path: str) -> QWidget:
        w = QWidget()
        set_role(w, "transparent")
        h = QHBoxLayout(w)
        h.setContentsMargins(2, 4, 2, 4)
        h.setSpacing(6)
        h.setAlignment(Qt.AlignCenter)

        action_bg = '#eef4ff' if _is_light() else 'rgba(51,65,85,128)'
        action_fg = _CYAN if _is_light() else _TEXT_SEC
        action_brd = '#c8d8f5' if _is_light() else _BORDER
        action_hover_bg = '#dbeafe' if _is_light() else 'rgba(6,182,212,38)'
        base_style = f"""
            QPushButton {{
                background: {action_bg};
                color: {action_fg};
                border: 1px solid {action_brd};
                border-radius: 6px;
                font-size: 10px;
                font-weight: 700;
                padding-top: 0px;
                padding-bottom: 0px;
                padding-left: 4px;
                padding-right: 4px;
            }}
            QPushButton:hover {{
                background: {action_hover_bg};
                color: {_CYAN};
                border-color: {_CYAN_BRD};
            }}
            QPushButton:pressed {{
                background: {_CYAN};
                color: #ffffff;
            }}
        """

        actions = [
            ("Open",   "Open this report file",       lambda _, p=path: self._open_file(p),   48),
            ("Folder", "Show this report in folder",  lambda _, p=path: self._open_folder(p), 68),
        ]
        for label, tip, cb, width in actions:
            btn = QPushButton(label)
            btn.setFixedSize(width, 28)
            btn.setToolTip(f"{tip}\n{path}")
            btn.setCursor(Qt.PointingHandCursor)
            btn.setStyleSheet(base_style)
            btn.clicked.connect(cb)
            h.addWidget(btn)

        return w

    def _item(self, text: str, color: str = _TEXT_SEC) -> QTableWidgetItem:
        it = QTableWidgetItem(str(text))
        it.setForeground(QColor(color))
        it.setTextAlignment(Qt.AlignVCenter | Qt.AlignLeft)
        return it

    # ── Logic ─────────────────────────────────────────────────────────────────

    def _refresh_session_info(self):
        sess = AppState.current
        if sess is None:
            self._info_filename.setText("No active session")
            self._info_date.setText("Run an analysis first")
            self._info_badge.set_status('pending')
            self._info_output.setText("—")
            self._gen_btn.setEnabled(False)
            return
        self._info_filename.setText(sess.dump_filename or "Unknown")
        ts = sess.created_at.strftime('%Y-%m-%d  %H:%M:%S') if sess.created_at else "—"
        extra = f"   ·   {sess.dump_size_str}" if getattr(sess, 'dump_size_str', '') else ''
        self._info_date.setText(ts + extra)
        verdict = sess.verdict if sess.status not in ('pending', 'running') else 'pending'
        self._info_badge.set_status(verdict)
        self._gen_btn.setEnabled(sess.status not in ('pending', 'running'))
        self._refresh_output_name()

    def _refresh_output_name(self):
        sess = AppState.current
        base = (
            os.path.splitext(sess.dump_filename)[0]
            if (sess and sess.dump_filename) else 'unknown'
        )
        self._info_output.setText(f"{base}_report.{self._selected_fmt}")

    def _refresh_library(self):
        reports = ReportBridge.list_reports()
        self._table.setRowCount(0)
        self._table_paths = []
        for r in reports:
            row = self._table.rowCount()
            self._table.insertRow(row)
            self._table_paths.append(r['path'])

            dt_str = (
                r['date'].strftime('%Y-%m-%d %H:%M')
                if isinstance(r['date'], datetime) else str(r['date'])
            )

            name_item = self._item(r['name'], _TEXT_SEC)
            name_item.setToolTip(
                f"Report: {r['name']}\n"
                f"Generated/modified: {dt_str}\n"
                f"Path: {r['path']}"
            )
            self._table.setItem(row, 0, name_item)

            fw = QWidget()
            set_role(fw, "transparent")
            fl = QHBoxLayout(fw)
            fl.setContentsMargins(6, 2, 6, 2)
            fl.setAlignment(Qt.AlignCenter)
            fl.addWidget(self._make_format_badge(r.get('format', '?')))
            self._table.setCellWidget(row, 1, fw)

            size_item = self._item(r.get('size', '—'), _MUTED)
            size_item.setToolTip(f"File size: {r.get('size', '—')}")
            self._table.setItem(row, 2, size_item)

            verdict = r.get('verdict', r.get('status', 'saved'))
            self._table.setCellWidget(row, 3, self._make_status_cell(verdict))
            self._table.setCellWidget(row, 4, self._make_action_cell(r['path']))
            self._table.setRowHeight(row, 50)

        # Avoid retained horizontal scroll offset that can visually clip the
        # Report Name column after refresh/navigation.
        self._table.horizontalScrollBar().setValue(0)

        n = self._table.rowCount()
        no_rl = "  ·  ReportLab not installed" if not _HAS_REPORTLAB else ''
        self._lib_footer.setText(f"Total Reports: {n}{no_rl}")

    def _select_csv_export_mode(self) -> str | None:
        """Ask the user which CSV mode to export. Returns mode id or None if cancelled."""
        dlg = QDialog(self)
        dlg.setWindowTitle("Select CSV Export Mode")
        dlg.setModal(True)
        dlg.setStyleSheet(f"""
            QDialog {{ background: {_BG_CARD}; color: {_TEXT}; }}
            QLabel {{ background: transparent; color: {_TEXT_SEC}; }}
            QRadioButton {{ background: transparent; color: {_TEXT}; font-size: 13px; padding: 4px; }}
            QRadioButton::indicator {{ width: 14px; height: 14px; }}
            QDialogButtonBox QPushButton {{
                background: {_CYAN}; color: white; border: none; border-radius: 6px;
                padding: 7px 14px; font-weight: bold;
            }}
            QDialogButtonBox QPushButton:hover {{ background: #0891b2; }}
        """)

        layout = QVBoxLayout(dlg)
        layout.setContentsMargins(18, 16, 18, 14)
        layout.setSpacing(12)

        title = _lbl("Choose CSV Export Mode", 15, _TEXT, bold=True)
        layout.addWidget(title)

        desc = QLabel(
            "RAMDetect separates features used by the ML decision path from "
            "CIC-MalMem2022 semantic compatibility/export features to avoid confusion."
        )
        desc.setWordWrap(True)
        desc.setStyleSheet(f"color:{_TEXT_SEC}; font-size:12px; background:transparent;")
        layout.addWidget(desc)

        group = QButtonGroup(dlg)

        rb_ml = QRadioButton("ML Decision Feature Export (recommended)")
        rb_ml.setChecked(True)
        group.addButton(rb_ml, 1)
        layout.addWidget(rb_ml)
        ml_hint = QLabel(
            "Exports the feature vector and verdict metadata used by the current RF-AE decision path. "
            "Use this for normal analysis and classifier traceability."
        )
        ml_hint.setWordWrap(True)
        ml_hint.setStyleSheet(f"color:{_MUTED}; font-size:11px; margin-left:22px; background:transparent;")
        layout.addWidget(ml_hint)

        rb_cic = QRadioButton("CIC-MalMem2022 Semantic Compatibility Export")
        group.addButton(rb_cic, 2)
        layout.addWidget(rb_cic)
        cic_hint = QLabel(
            "Exports a CIC-MalMem2022-shaped row plus compatibility matrix. "
            "This is for FYP/research compatibility checking and includes semantic/export-supported features such as svcscan.*. "
            "It does not change the ML verdict."
        )
        cic_hint.setWordWrap(True)
        cic_hint.setStyleSheet(f"color:{_MUTED}; font-size:11px; margin-left:22px; background:transparent;")
        layout.addWidget(cic_hint)

        note = QLabel(
            "Tip: ML Support and CIC Semantic Coverage are different metrics. "
            "The semantic export should not be interpreted as the RF-AE input vector."
        )
        note.setWordWrap(True)
        note.setStyleSheet(f"color:{_CYAN}; font-size:11px; background:transparent;")
        layout.addWidget(note)

        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(dlg.accept)
        buttons.rejected.connect(dlg.reject)
        layout.addWidget(buttons)

        if dlg.exec_() != QDialog.Accepted:
            return None
        return "cic_semantic_compatibility" if group.checkedId() == 2 else "ml_decision_features"

    def _generate(self):
        sess = AppState.current
        if sess is None:
            self._set_status("No active session — run an analysis first.", error=True)
            return
        if sess.status in ('pending', 'running'):
            self._set_status("Analysis not complete yet.", error=True)
            return

        csv_mode = None
        if self._selected_fmt == 'csv':
            csv_mode = self._select_csv_export_mode()
            if csv_mode is None:
                return

        # Build the base name for the report file (without extension)
        base = (
            os.path.splitext(sess.dump_filename)[0]
            if (sess and sess.dump_filename) else 'unknown'
        )
        options = {
            'name':        f"{base}_report",          # key that ReportBridge looks up
            'base_name':   base,
            'fmt':         self._selected_fmt,
            'pdf_sections': dict(self._opt_state),    # which PDF sections to include
        }
        if csv_mode:
            options['csv_export_mode'] = csv_mode

        self._gen_btn.setEnabled(False)
        self._set_status("⟳  Generating report…")
        self._worker = _GenerateWorker(sess, self._selected_fmt, options)
        self._worker.done.connect(self._on_generate_done)
        self._worker.start()

    def _on_generate_done(self, result: dict):
        self._gen_btn.setEnabled(True)
        if result['success']:
            mode = result.get('export_mode_label')
            suffix = f" — {mode}" if mode else ""
            try:
                sess = AppState.current
                verdict = getattr(sess, "verdict", None) or getattr(sess, "status", None)
            except Exception:
                verdict = None
            _audit_report_generated(result.get("path", ""), result.get("format") or self._selected_fmt, verdict=verdict)
            self._show_toast(f"Saved: {result['filename']}  ({result['size_str']}){suffix}", success=True)
            self._refresh_library()
        else:
            self._show_toast(f"Error: {result['error']}", success=False)

    def _show_toast(self, msg: str, success: bool = True):
        """Show a floating dismissing toast notification centered on the full page."""
        toast = _Toast(self, msg, success)
        toast.show_on(self)

    def _set_status(self, msg: str, error: bool = False):
        """Legacy status setter — routes to toast."""
        self._show_toast(msg, success=not error)

    def _open_file(self, path: str):
        if not os.path.exists(path):
            self._set_status(f"File not found: {path}", error=True)
            return
        try:
            if platform.system() == 'Windows':   os.startfile(path)
            elif platform.system() == 'Darwin':  subprocess.Popen(['open', path])
            else:                                subprocess.Popen(['xdg-open', path])
            _audit_report_opened(path)
        except Exception as e:
            self._set_status(f"Cannot open file: {e}", error=True)

    def _open_folder(self, path: str):
        folder = os.path.dirname(path)
        try:
            if platform.system() == 'Windows':
                subprocess.Popen(['explorer', '/select,', path])
            elif platform.system() == 'Darwin':  subprocess.Popen(['open', folder])
            else:                                subprocess.Popen(['xdg-open', folder])
        except Exception as e:
            self._set_status(f"Cannot open folder: {e}", error=True)

    def _clear_all_reports(self):
        reports = ReportBridge.list_reports()
        if not reports:
            return
        reply = QMessageBox.question(
            self, "Clear All Reports",
            f"Delete all {len(reports)} report(s)? This cannot be undone.",
            QMessageBox.Yes | QMessageBox.No,
        )
        if reply == QMessageBox.Yes:
            for r in reports:
                ReportBridge.delete_report(r['path'])
            self._refresh_library()
            self._set_status(f"Deleted {len(reports)} report(s).")

    # ── showEvent ─────────────────────────────────────────────────────────────

    def apply_theme(self, theme: str | None = None):
        # Rebuild the UI-only report page so inline report/table styles match
        # the current Light/Dark stylesheet. This does not touch generated files.
        selected_fmt = getattr(self, '_selected_fmt', 'pdf')
        opt_state = dict(getattr(self, '_opt_state', {}))
        _refresh_palette(theme or current_theme())
        self._selected_fmt = selected_fmt
        self._opt_state = opt_state or {k: True for k, _ in self._PDF_OPTS}
        self._fmt_btns = {}
        self._opt_btns = {}
        self._table_paths = []
        self._build_body()
        self._refresh_session_info()
        self._refresh_library()

    def _on_show(self):
        _refresh_palette(current_theme())
        self._refresh_session_info()
        self._refresh_library()
