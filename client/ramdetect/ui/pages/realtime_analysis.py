"""
Real-time Analysis — Page 5
────────────────────────────
Drives the AnalysisWorker QThread from ui.bridge.analysis_bridge.

Signal → UI mapping
───────────────────
  worker.progress(pct)              → overall % label + bar
  worker.phase_changed(idx, name)   → phase card → ACTIVE state
  worker.module_done(idx, name)     → module dot → ✓ green
  worker.log(level, msg)            → colour-coded console line
  worker.finished(session)          → save session, show "View Results"
  worker.errored(msg)               → red error banner, "Retry" button

Cancel
──────
  "Cancel" button → worker.cancel() → worker stops gracefully
  UI resets to idle so user can go back to Acquisition/Config

showEvent
─────────
  Every visit: cancel any running worker, reset all cards, start fresh
  AnalysisWorker with AppState.current session.
"""

import html as _html
import re as _re
from datetime import datetime

from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QFrame, QPushButton, QProgressBar,
    QTextEdit, QScrollArea, QGraphicsOpacityEffect,
)
from PyQt5.QtCore import Qt, QTimer, QPropertyAnimation, QEasingCurve
from PyQt5.QtGui  import QFont

from ui.widgets.header_bar import HeaderBar
from ui.widgets.progress_stepper import ProgressStepper
from ui.bridge               import AnalysisWorker, PHASE_MAP, AppState
from ui.style_helpers import set_role, set_tone, refresh_style
from ui.theme import current_theme


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _card() -> QFrame:
    f = QFrame()
    f.setObjectName("RealtimePanelCard")
    f.setAttribute(Qt.WA_StyledBackground, True)
    # Scope the style to this card only.  QLabel also inherits QFrame in Qt,
    # so a generic "QFrame { ... }" selector creates unwanted borders around
    # labels/progress text inside the card.
    f.setStyleSheet(_realtime_panel_qss())
    return f


def _theme_name() -> str:
    return "light" if str(current_theme()).strip().lower() == "light" else "dark"


def _is_light() -> bool:
    return _theme_name() == "light"


def _map_color(color: str) -> str:
    """Map old dark-page colours to readable light-theme equivalents."""
    if not _is_light():
        return color
    c = (color or "").strip().lower().replace(" ", "")
    mapping = {
        "#ffffff": "#1e3a6e",
        "white": "#1e3a6e",
        "#e2e8f0": "#1e3a6e",
        "#cbd5e1": "#2f4f85",
        "#94a3b8": "#5f75a6",
        "#64748b": "#7a8cb0",
        "#475569": "#9aa9c5",
        "#334155": "#b7c8ee",
        "#1e293b": "#dbe7ff",
        "#111827": "#ffffff",
        "#0f172a": "#f0f5ff",
    }
    return mapping.get(c, color)


def _plain_style(color: str, size: int | None = None, bold: bool = False) -> str:
    extra = ""
    if size is not None:
        extra += f"font-size:{size}px;"
    if bold:
        extra += "font-weight:700;"
    return f"color:{_map_color(color)}; background: transparent; border: none; border-radius: 0px; {extra}"


def _realtime_panel_qss() -> str:
    if _is_light():
        return (
            "QFrame#RealtimePanelCard { background: #ffffff;"
            "  border: 1px solid #9ec5ff; border-radius: 14px; }"
        )
    return (
        "QFrame#RealtimePanelCard { background: rgba(30,41,59,0.45);"
        "  border: 1px solid rgba(51,65,85,0.5); border-radius: 12px; }"
    )


def _phase_card_qss(state: str) -> str:
    state = (state or "pending").lower()
    if _is_light():
        styles = {
            "pending":  ("#ffffff", "#b9d2ff"),
            "active":   ("#f0fbff", "#1a56db"),
            "complete": ("#f0fdf7", "#22c55e"),
            "error":    ("#fff7f7", "#ef4444"),
        }
        bg, border = styles.get(state, styles["pending"])
        return f"QFrame#PhaseCard {{ background: {bg}; border: 1px solid {border}; border-radius: 10px; }}"
    styles = {
        "pending":  ("rgba(30,41,59,0.3)", "rgba(51,65,85,0.4)"),
        "active":   ("rgba(6,182,212,0.05)", "#06b6d4"),
        "complete": ("rgba(52,211,153,0.05)", "rgba(52,211,153,0.4)"),
        "error":    ("rgba(248,113,113,0.05)", "rgba(248,113,113,0.4)"),
    }
    bg, border = styles.get(state, styles["pending"])
    return f"QFrame#PhaseCard {{ background: {bg}; border: 1px solid {border}; border-radius: 10px; }}"


def _badge_qss(kind: str) -> str:
    kind = (kind or "pending").lower()
    if _is_light():
        styles = {
            "pending": ("#eef4ff", "#7a8cb0", "#d6e4ff"),
            "active": ("#e0f2fe", "#1a56db", "#bfdbfe"),
            "complete": ("#dcfce7", "#16a34a", "#bbf7d0"),
            "error": ("#fee2e2", "#dc2626", "#fecaca"),
        }
        bg, fg, br = styles.get(kind, styles["pending"])
        return f"background:{bg}; color:{fg}; border:1px solid {br}; border-radius:8px; padding:2px 8px;"
    styles = {
        "pending": ("rgba(51,65,85,0.4)", "#64748b", "transparent"),
        "active": ("rgba(6,182,212,0.15)", "#06b6d4", "transparent"),
        "complete": ("rgba(52,211,153,0.15)", "#34d399", "transparent"),
        "error": ("rgba(248,113,113,0.15)", "#f87171", "transparent"),
    }
    bg, fg, br = styles.get(kind, styles["pending"])
    return f"background:{bg}; color:{fg}; border:none; border-radius:8px; padding:2px 8px;"


def _theme_is_light(theme: str | None = None) -> bool:
    return str(theme or current_theme() or "dark").strip().lower() == "light"


def _console_header_qss(theme: str | None = None) -> str:
    if _theme_is_light(theme):
        border = "#b9d2ff"
    else:
        border = "rgba(71,85,105,0.34)"
    return (
        "QFrame#ConsoleHeaderBar { background: transparent; border: none; "
        f"border-bottom: 1px solid {border}; }}"
    )


def _log_badge_qss(theme: str | None = None) -> str:
    if _theme_is_light(theme):
        return (
            "QLabel#RealtimeLineCountBadge { background: #eef4ff; color: #06b6d4; "
            "border: 1px solid #cfe0ff; border-radius: 8px; padding: 0px 10px; }"
        )
    return (
        "QLabel#RealtimeLineCountBadge { background: rgba(6,182,212,0.10); color: #22d3ee; "
        "border: 1px solid rgba(6,182,212,0.30); border-radius: 8px; padding: 0px 10px; }"
    )


def _clear_button_qss(theme: str | None = None) -> str:
    if _theme_is_light(theme):
        return (
            "QPushButton#RealtimeClearButton { background: #ffffff; color: #1a56db; "
            "border: 1px solid #b9d2ff; border-radius: 8px; padding: 0px; font-weight: 800; }"
            "QPushButton#RealtimeClearButton:hover { background: #eef4ff; border-color: #1a56db; }"
        )
    # Match the dark Realtime console reference: dark button shell, not a light badge.
    return (
        "QPushButton#RealtimeClearButton { background: #1e293b; color: #f8fafc; "
        "border: 1px solid rgba(71,85,105,0.78); border-radius: 8px; padding: 0px; font-weight: 800; }"
        "QPushButton#RealtimeClearButton:hover { background: #263449; color: #ffffff; "
        "border-color: rgba(6,182,212,0.55); }"
    )


def _progress_bar_qss(kind: str = "overall") -> str:
    if kind == "activity":
        chunk = "rgba(26,86,219,0.55)" if _is_light() else "rgba(6,182,212,0.45)"
        return f"QProgressBar {{ background: transparent; border: none; border-radius: 2px; }} QProgressBar::chunk {{ background: {chunk}; border-radius: 2px; }}"
    track = "#dbe7ff" if _is_light() else "#1e293b"
    return (
        f"QProgressBar {{ background: {track}; border-radius: 4px; border: none; }}"
        "QProgressBar::chunk { background: qlineargradient("
        "  x1:0, y1:0, x2:1, y2:0, stop:0 #06b6d4, stop:1 #2563eb);"
        "  border-radius: 4px; }"
    )


def _local_scrollbar_qss() -> str:
    if _is_light():
        return (
            "QScrollBar:vertical { background: #eef4ff; width: 8px; border-radius: 4px; margin: 0px; }"
            "QScrollBar::handle:vertical { background: #9fb7e5; border-radius: 4px; min-height: 28px; }"
            "QScrollBar::handle:vertical:hover { background: #1a56db; }"
            "QScrollBar::add-page:vertical, QScrollBar::sub-page:vertical { background: transparent; }"
            "QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0px; border: none; background: transparent; }"
            "QScrollBar:horizontal { background: #eef4ff; height: 8px; border-radius: 4px; margin: 0px; }"
            "QScrollBar::handle:horizontal { background: #9fb7e5; border-radius: 4px; min-width: 28px; }"
            "QScrollBar::add-page:horizontal, QScrollBar::sub-page:horizontal { background: transparent; }"
            "QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal { width: 0px; border: none; background: transparent; }"
        )
    return (
        "QScrollBar:vertical { background: rgba(15,23,42,0.55); width: 8px; border-radius: 4px; margin: 0px; }"
        "QScrollBar::handle:vertical { background: rgba(71,85,105,0.85); border-radius: 4px; min-height: 28px; }"
        "QScrollBar::handle:vertical:hover { background: #06b6d4; }"
        "QScrollBar::add-page:vertical, QScrollBar::sub-page:vertical { background: transparent; }"
        "QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0px; border: none; background: transparent; }"
        "QScrollBar:horizontal { background: rgba(15,23,42,0.55); height: 8px; border-radius: 4px; margin: 0px; }"
        "QScrollBar::handle:horizontal { background: rgba(71,85,105,0.85); border-radius: 4px; min-width: 28px; }"
        "QScrollBar::add-page:horizontal, QScrollBar::sub-page:horizontal { background: transparent; }"
        "QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal { width: 0px; border: none; background: transparent; }"
    )


def _phase_scroll_qss() -> str:
    return "QScrollArea { background: transparent; border: none; }" + _local_scrollbar_qss()


def _console_qss() -> str:
    if _is_light():
        return (
            "QTextEdit { background: #f8fbff; border: none; border-radius: 0px;"
            " color: #2f4f85; padding: 12px 6px; }"
            + _local_scrollbar_qss()
        )
    return (
        "QTextEdit { background: rgba(15,23,42,0.60); border: none; border-radius: 0px;"
        " color: #93a4c2; padding: 12px 6px; }"
        + _local_scrollbar_qss()
    )


def _soften_console_markup(text: str) -> str:
    """Dim ASCII/Unicode progress bars and separator rules in console HTML."""
    block_col = "#9fb7e5" if _is_light() else "#52617a"
    rule_col = "#9fb7e5" if _is_light() else "#46546a"
    text = _re.sub(
        r"([─━═-]{4,})",
        rf'<span style="color:{rule_col}">\1</span>',
        text,
    )
    text = _re.sub(
        r"([█▓▒░▉▊▋▌▍▎▏▐▔▁▂▃▄▅▆▇■□]{3,})",
        rf'<span style="color:{block_col}">\1</span>',
        text,
    )
    return text


LOG_COLORS = {
    "INFO":    "#06b6d4",
    "WARNING": "#facc15",
    "ERROR":   "#f87171",
}


def _session_file_for(session) -> str:
    """Return expected full-session JSON path for Activity Monitor linking."""
    try:
        from ui.bridge import session as session_mod
        sessions_dir = getattr(session_mod, "_SESSIONS_DIR", "")
        if sessions_dir and getattr(session, "session_id", ""):
            import os
            return os.path.join(sessions_dir, f"{session.session_id}.json")
    except Exception:
        pass
    return ""


def _audit_analysis_started(session) -> None:
    try:
        from ramdetect.case_management.activity_logger import ActivityLogger
        ActivityLogger.instance().log_analysis_started(
            getattr(session, "dump_filename", "") or None,
            dump_path=getattr(session, "dump_path", "") or None,
            session_id=getattr(session, "session_id", "") or None,
            session_file=_session_file_for(session) or None,
        )
    except Exception:
        pass


def _audit_analysis_completed(session, verdict: str | None = None, hybrid_score: float | None = None) -> None:
    try:
        from ramdetect.case_management.activity_logger import ActivityLogger
        ActivityLogger.instance().log_analysis_completed(
            getattr(session, "dump_filename", "") or None,
            verdict=(verdict or getattr(session, "verdict", "") or None),
            dump_path=getattr(session, "dump_path", "") or None,
            session_id=getattr(session, "session_id", "") or None,
            session_file=_session_file_for(session) or None,
            hybrid_score=hybrid_score,
        )
    except Exception:
        pass


def _audit_analysis_failed(session, reason: str) -> None:
    try:
        from ramdetect.case_management.activity_logger import ActivityLogger
        ActivityLogger.instance().log_analysis_failed(
            getattr(session, "dump_filename", "") or None,
            reason=reason,
            dump_path=getattr(session, "dump_path", "") or None,
            session_id=getattr(session, "session_id", "") or None,
            session_file=_session_file_for(session) or None,
        )
    except Exception:
        pass


# ─────────────────────────────────────────────────────────────────────────────
# Phase card widget
# ─────────────────────────────────────────────────────────────────────────────

class _PhaseCard(QFrame):
    """
    One card per pipeline phase.  States: PENDING → ACTIVE → COMPLETE / ERROR.
    Module rows tick to ✓ as module_done signals arrive.
    """

    _STYLE_PENDING  = ("QFrame#PhaseCard { background: rgba(30,41,59,0.3);"
                       "  border: 1px solid rgba(51,65,85,0.4); border-radius: 10px; }")
    _STYLE_ACTIVE   = ("QFrame#PhaseCard { background: rgba(6,182,212,0.05);"
                       "  border: 1px solid #06b6d4; border-radius: 10px; }")
    _STYLE_COMPLETE = ("QFrame#PhaseCard { background: rgba(52,211,153,0.05);"
                       "  border: 1px solid rgba(52,211,153,0.4); border-radius: 10px; }")
    _STYLE_ERROR    = ("QFrame#PhaseCard { background: rgba(248,113,113,0.05);"
                       "  border: 1px solid rgba(248,113,113,0.4); border-radius: 10px; }")

    def __init__(self, phase_idx: int, phase_meta: dict, parent=None):
        super().__init__(parent)
        self._idx     = phase_idx
        self.setObjectName("PhaseCard")
        self.setAttribute(Qt.WA_StyledBackground, True)
        self._modules = phase_meta["modules"]
        self._mod_labels: dict[str, QLabel] = {}   # module_name → dot label
        self._active  = False

        vb = QVBoxLayout(self)
        vb.setContentsMargins(14, 12, 14, 12)
        vb.setSpacing(8)

        # ── Header row ────────────────────────────────────────────────────────
        hdr = QHBoxLayout()

        self._icon = QLabel("○")
        self._icon.setFont(QFont("Segoe UI", 16))
        self._icon.setStyleSheet(_plain_style("#64748b"))
        self._icon.setFixedWidth(24)
        hdr.addWidget(self._icon)

        self._name_lbl = QLabel(f"Phase {phase_idx + 1}: {phase_meta['name']}")
        self._name_lbl.setFont(QFont("Segoe UI", 13, QFont.DemiBold))
        self._name_lbl.setStyleSheet(_plain_style("#ffffff"))
        hdr.addWidget(self._name_lbl, stretch=1)

        self._badge = QLabel("PENDING")
        self._badge.setFont(QFont("Segoe UI", 10, QFont.Bold))
        self._badge.setStyleSheet(_badge_qss("pending"))
        hdr.addWidget(self._badge)
        vb.addLayout(hdr)

        # ── Module rows ───────────────────────────────────────────────────────
        for mod_name in self._modules:
            row = QHBoxLayout()
            row.setSpacing(8)
            row.setContentsMargins(4, 0, 4, 0)

            dot = QLabel("●")
            dot.setFont(QFont("Segoe UI", 8))
            dot.setStyleSheet(_plain_style("#475569"))
            dot.setFixedWidth(16)

            mod_lbl = QLabel(mod_name)
            mod_lbl.setFont(QFont("Segoe UI", 11))
            mod_lbl.setStyleSheet(_plain_style("#64748b"))

            row.addWidget(dot)
            row.addWidget(mod_lbl, stretch=1)
            vb.addLayout(row)

            # Store both labels keyed by module name
            self._mod_labels[mod_name] = (dot, mod_lbl)

        self.set_pending()

    # ── State setters ─────────────────────────────────────────────────────────

    def set_pending(self):
        self._active = False
        self.setStyleSheet(_phase_card_qss("pending"))
        self._icon.setText("○")
        self._icon.setStyleSheet(_plain_style("#64748b"))
        self._name_lbl.setStyleSheet(_plain_style("#ffffff"))
        self._badge.setText("PENDING")
        self._badge.setStyleSheet(_badge_qss("pending"))
        for dot, lbl in self._mod_labels.values():
            dot.setText("●")
            dot.setFont(QFont("Segoe UI", 8))
            dot.setStyleSheet(_plain_style("#475569"))
            lbl.setStyleSheet(_plain_style("#64748b"))

    def set_active(self):
        self._active = True
        self.setStyleSheet(_phase_card_qss("active"))
        self._icon.setText("⟳")
        self._icon.setStyleSheet(_plain_style("#06b6d4"))
        self._name_lbl.setStyleSheet(_plain_style("#ffffff"))
        self._badge.setText("ACTIVE")
        self._badge.setStyleSheet(_badge_qss("active"))

    def set_complete(self):
        self._active = False
        self.setStyleSheet(_phase_card_qss("complete"))
        self._icon.setText("✓")
        self._icon.setStyleSheet(_plain_style("#34d399"))
        self._name_lbl.setStyleSheet(_plain_style("#34d399"))
        self._badge.setText("COMPLETE")
        self._badge.setStyleSheet(_badge_qss("complete"))
        # Tick all remaining module dots
        for dot, lbl in self._mod_labels.values():
            if dot.text() != "✓":
                dot.setText("✓")
                dot.setFont(QFont("Segoe UI", 10, QFont.Bold))
                dot.setStyleSheet(_plain_style("#34d399"))
                lbl.setStyleSheet(_plain_style("#34d399"))

    def set_error(self):
        self._active = False
        self.setStyleSheet(_phase_card_qss("error"))
        self._icon.setText("✗")
        self._icon.setStyleSheet(_plain_style("#f87171"))
        self._name_lbl.setStyleSheet(_plain_style("#f87171"))
        self._badge.setText("ERROR")
        self._badge.setStyleSheet(_badge_qss("error"))

    def animate_tick(self, tick: int):
        """Animate the active refresh icon without changing phase logic."""
        if not self._active:
            return
        frames = ("⟳", "↻", "⟳", "↺")
        self._icon.setText(frames[tick % len(frames)])

    def mark_module_done(self, module_name: str):
        """Tick the dot for a specific module to green ✓."""
        if module_name in self._mod_labels:
            dot, lbl = self._mod_labels[module_name]
            dot.setText("✓")
            dot.setFont(QFont("Segoe UI", 10, QFont.Bold))
            dot.setStyleSheet(
                "color: #34d399; background: transparent; border: none; border-radius: 0px;"
            )
            lbl.setStyleSheet(
                "color: #34d399; background: transparent; border: none; border-radius: 0px;"
            )


# ─────────────────────────────────────────────────────────────────────────────
# RealtimeAnalysisPage
# ─────────────────────────────────────────────────────────────────────────────

class RealtimeAnalysisPage(QWidget):
    def __init__(self, main_window, parent=None):
        super().__init__(parent)
        self.setObjectName("RealtimeAnalysisPage")
        self.setAttribute(Qt.WA_StyledBackground, True)
        self.mw              = main_window
        self._worker         = None
        self._last_session_id = None   # guards against re-run on window restore
        self._anim_tick       = 0
        self._progress_target = 0
        self._current_phase_idx = 0
        self._phase_count = max(1, len(PHASE_MAP))
        self._activity_timer  = QTimer(self)
        self._activity_timer.setInterval(120)
        self._activity_timer.timeout.connect(self._animate_activity)
        self._progress_anim   = None
        set_role(self, "transparent")

        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        self._header = HeaderBar(show_action=False, show_dashboard=True)

        # Realtime analysis is a critical running workflow.  Lock header
        # navigation here so users cannot leave through Settings/Dashboard while
        # the worker is preparing/running.  This also prevents accidental page
        # switching that can briefly expose the previous completed session UI.
        self._header.dashboard_clicked.connect(self._blocked_navigation_notice)
        self._header.settings_clicked.connect(self._blocked_navigation_notice)
        root.addWidget(self._header)
        self._lock_header_navigation(True)

        root.addWidget(ProgressStepper(current_step=3))

        body = QHBoxLayout()
        body.setContentsMargins(40, 28, 40, 28)
        body.setSpacing(24)
        body.addWidget(self._build_left(),  stretch=1)
        body.addWidget(self._build_right(), stretch=1)
        root.addLayout(body, stretch=1)

    def _blocked_navigation_notice(self):
        """Ignore Settings/Dashboard clicks while the analysis page is active."""
        # Buttons are disabled visually, so this is only a defensive fallback for
        # programmatic signal emission or platform-specific click forwarding.
        self._on_log("WARNING", "Navigation is locked while analysis is running. Use Cancel to return to configuration.")

    def _lock_header_navigation(self, locked: bool = True):
        """Disable Settings and Dashboard header buttons on this page."""
        try:
            for btn in self._header.findChildren(QPushButton):
                text = (btn.text() or "").strip().lower()
                tip = (btn.toolTip() or "").strip().lower()
                if "dashboard" in text or "settings" in tip or text == "⚙":
                    btn.setEnabled(not locked)
                    btn.setToolTip(
                        "Locked during real-time analysis"
                        if locked else ("Settings" if text == "⚙" else "")
                    )
                    if locked:
                        btn.setGraphicsEffect(None)
                        if _is_light():
                            btn.setStyleSheet(
                                "QPushButton, QPushButton:disabled { background: #eef4ff;"
                                "  border: 1px solid #cfe0ff; border-radius: 8px;"
                                "  color: #8ea1c6; padding: 0 14px; font-weight: 800; }"
                            )
                        else:
                            btn.setStyleSheet(
                                "QPushButton, QPushButton:disabled { background: rgba(51,65,85,0.30);"
                                "  border: 1px solid rgba(100,116,139,0.45); border-radius: 8px;"
                                "  color: rgba(203,213,225,0.62); padding: 0 14px; font-weight: 800; }"
                            )
                    else:
                        btn.setGraphicsEffect(None)
                        btn.setStyleSheet("")
        except Exception:
            pass

    # ── Left panel: progress + phase cards ───────────────────────────────────

    def _build_left(self) -> QFrame:
        card = _card()
        vb = QVBoxLayout(card)
        vb.setContentsMargins(20, 18, 20, 18)
        vb.setSpacing(16)

        # Overall progress block
        ov = QFrame()
        set_role(ov, "transparent")
        ov_vb = QVBoxLayout(ov)
        ov_vb.setContentsMargins(0, 0, 0, 0)
        ov_vb.setSpacing(8)

        self.overall_pct = QLabel("0%")
        self.overall_pct.setFont(QFont("Segoe UI", 36, QFont.Bold))
        self.overall_pct.setAlignment(Qt.AlignCenter)
        set_tone(self.overall_pct, "#06b6d4")

        ov_sub = QLabel("Overall Progress")
        ov_sub.setFont(QFont("Segoe UI", 12))
        ov_sub.setAlignment(Qt.AlignCenter)
        set_tone(ov_sub, "#94a3b8")

        self.overall_bar = QProgressBar()
        self.overall_bar.setRange(0, 100)
        self.overall_bar.setValue(0)
        self.overall_bar.setFixedHeight(8)
        self.overall_bar.setTextVisible(False)
        self.overall_bar.setStyleSheet(_progress_bar_qss("overall"))

        self.activity_bar = QProgressBar()
        self.activity_bar.setRange(0, 100)
        self.activity_bar.setValue(0)
        self.activity_bar.setFixedHeight(4)
        self.activity_bar.setTextVisible(False)
        self.activity_bar.setStyleSheet(_progress_bar_qss("activity"))
        self.activity_bar.hide()

        ov_vb.addWidget(self.overall_pct)
        ov_vb.addWidget(ov_sub)
        ov_vb.addWidget(self.overall_bar)
        ov_vb.addWidget(self.activity_bar)
        vb.addWidget(ov)

        # Phase cards scroll area
        scroll = QScrollArea()
        scroll.setObjectName("RealtimePhaseScroll")
        scroll.setWidgetResizable(True)
        scroll.setStyleSheet(_phase_scroll_qss())
        sw = QWidget()
        set_role(sw, "transparent")
        sw_vb = QVBoxLayout(sw)
        sw_vb.setContentsMargins(0, 0, 4, 0)
        sw_vb.setSpacing(10)

        self._phase_cards: list[_PhaseCard] = []
        for i, phase_meta in enumerate(PHASE_MAP):
            pc = _PhaseCard(i, phase_meta)
            self._phase_cards.append(pc)
            sw_vb.addWidget(pc)

        sw_vb.addStretch()
        scroll.setWidget(sw)
        vb.addWidget(scroll, stretch=1)

        return card

    # ── Right panel: console + buttons ───────────────────────────────────────

    def _build_right(self) -> QFrame:
        card = _card()
        vb = QVBoxLayout(card)
        vb.setContentsMargins(0, 0, 0, 0)
        vb.setSpacing(0)

        # Console header bar
        hdr_bar = QFrame()
        hdr_bar.setObjectName("ConsoleHeaderBar")
        hdr_bar.setFixedHeight(52)
        hdr_bar.setStyleSheet(_console_header_qss())
        hdr_row = QHBoxLayout(hdr_bar)
        hdr_row.setContentsMargins(16, 0, 16, 0)

        self._console_title = QLabel("⌨  Analysis Console")
        self._console_title.setFont(QFont("Segoe UI", 13, QFont.Bold))
        set_tone(self._console_title, "#ffffff")
        hdr_row.addWidget(self._console_title)
        hdr_row.addStretch()

        # Live log counter badge
        self._log_badge = QLabel("0 lines")
        self._log_badge.setObjectName("RealtimeLineCountBadge")
        self._log_badge.setFont(QFont("Segoe UI", 10))
        self._log_badge.setFixedHeight(30)
        self._log_badge.setStyleSheet(_log_badge_qss())
        hdr_row.addWidget(self._log_badge)
        hdr_row.addSpacing(8)

        clr_btn = QPushButton("Clear")
        self.clear_btn = clr_btn
        clr_btn.setObjectName("RealtimeClearButton")
        clr_btn.setFont(QFont("Segoe UI", 11, QFont.DemiBold))
        clr_btn.setFixedSize(74, 30)
        clr_btn.setStyleSheet(_clear_button_qss())
        clr_btn.clicked.connect(self._clear_console)
        hdr_row.addWidget(clr_btn)

        vb.addWidget(hdr_bar)

        # Console output
        self.console = QTextEdit()
        self.console.setObjectName("RealtimeConsole")
        self.console.setReadOnly(True)
        self.console.setFont(QFont("Courier New", 11))
        self.console.setStyleSheet(_console_qss())
        # Remove paragraph margins Qt adds between every append() call
        self.console.document().setDefaultStyleSheet(
            "p, div, span { margin: 0; padding: 0; line-height: 1.55; }"
        )
        vb.addWidget(self.console, stretch=1)

        # Button row (cancel / view results / retry)
        btn_frame = QFrame()
        btn_frame.setObjectName("ConsoleButtonFrame")
        btn_frame.setStyleSheet("QFrame#ConsoleButtonFrame { background: transparent; border: none; }")
        btn_row = QHBoxLayout(btn_frame)
        btn_row.setContentsMargins(16, 10, 16, 14)
        btn_row.setSpacing(10)

        # Error banner (hidden by default)
        self._err_banner = QLabel("")
        self._err_banner.setFont(QFont("Segoe UI", 11))
        self._err_banner.setStyleSheet("color: #dc2626; background: " + ("#fff7f7" if _is_light() else "rgba(248,113,113,0.08)") + "; border: 1px solid " + ("#fecaca" if _is_light() else "rgba(248,113,113,0.3)") + "; border-radius: 8px; padding: 6px 12px;")
        self._err_banner.setWordWrap(True)
        self._err_banner.hide()
        vb.addWidget(self._err_banner)

        self.cancel_btn = QPushButton("✕  Cancel")
        self.cancel_btn.setObjectName("dangerBtn")
        self.cancel_btn.setFont(QFont("Segoe UI", 12, QFont.DemiBold))
        self.cancel_btn.setFixedHeight(44)
        self.cancel_btn.clicked.connect(self._cancel)
        btn_row.addWidget(self.cancel_btn)

        self.cont_btn = QPushButton("View Results  →")
        self.cont_btn.setObjectName("primaryBtn")
        self.cont_btn.setFont(QFont("Segoe UI", 13, QFont.DemiBold))
        self.cont_btn.setFixedHeight(44)
        self.cont_btn.setStyleSheet(
            "QPushButton { background: qlineargradient(x1:0,y1:0,x2:1,y2:0,"
            "  stop:0 #06b6d4, stop:1 #2563eb);"
            "  color: white; border: none; border-radius: 8px;"
            "  font-weight: 600; font-size: 13px; }"
            "QPushButton:hover { background: qlineargradient(x1:0,y1:0,x2:1,y2:0,"
            "  stop:0 #0891b2, stop:1 #1d4ed8); }"
            "QPushButton:pressed { background: qlineargradient(x1:0,y1:0,x2:1,y2:0,"
            "  stop:0 #0e7490, stop:1 #1e40af); }"
        )
        self.cont_btn.hide()
        self.cont_btn.clicked.connect(lambda: self.mw.navigate_to("results"))
        btn_row.addWidget(self.cont_btn)

        self.retry_btn = QPushButton("↺  Retry")
        self.retry_btn.setObjectName("iconBtn")
        self.retry_btn.setFont(QFont("Segoe UI", 12))
        self.retry_btn.setFixedHeight(44)
        self.retry_btn.hide()
        self.retry_btn.clicked.connect(self._retry)
        btn_row.addWidget(self.retry_btn)

        vb.addWidget(btn_frame)

        self._log_line_count = 0
        return card

    # ── Worker lifecycle ──────────────────────────────────────────────────────

    def _start_worker(self):
        """Create, connect, and start a fresh AnalysisWorker."""
        self._reset_ui()

        sess = AppState.current
        self._last_session_id = sess.session_id   # mark this session as in-progress
        _audit_analysis_started(sess)
        self._worker = AnalysisWorker(session=sess, parent=self)

        # Connect all signals → slots (all run on main thread because QThread signals
        # are queued across thread boundaries automatically)
        self._worker.progress.connect(self._on_progress)
        self._worker.phase_changed.connect(self._on_phase_changed)
        self._worker.module_done.connect(self._on_module_done)
        self._worker.log.connect(self._on_log)
        self._worker.finished.connect(self._on_finished)
        self._worker.errored.connect(self._on_error)

        # Log the session context as first console lines
        self._on_log("INFO", f"Session ID : {sess.session_id}")
        self._on_log("INFO", f"Dump file  : {sess.dump_filename or '(no file set)'}")
        self._on_log("INFO", f"Dump size  : {sess.dump_size_str}")
        self._on_log("INFO", f"Modules    : {', '.join(sess.selected_modules)}")
        self._on_log("INFO", "─" * 52)

        self._worker.start()
        self.activity_bar.show()
        if not self._activity_timer.isActive():
            self._activity_timer.start()

    def _cancel(self):
        """Cancel the backend cooperatively and return to config immediately.

        The previous implementation waited for only 2 seconds and then dropped
        the worker reference, so parser/executor tasks could continue running in
        the background.  Keep the worker alive and let AnalysisWorker.cancel()
        shut down active pools/readers.
        """
        if self._worker and self._worker.isRunning():
            self._on_log("WARNING", "Cancelling analysis — stopping backend tasks…")
            try:
                self._worker.cancel()
                self._worker.requestInterruption()
            except Exception:
                pass
        self.cancel_btn.show()
        self.cont_btn.hide()
        self.retry_btn.hide()
        self._err_banner.hide()
        self._last_session_id = None
        # Navigate back to config so user can restart. The worker reference is
        # intentionally kept until it exits to avoid orphaning backend work.
        self.mw.navigate_to("analysis_config")

    def _retry(self):
        """Retry the full analysis with the same session."""
        self.retry_btn.hide()
        self._err_banner.hide()
        self._start_worker()

    # ── Signal slots (all called on main thread) ──────────────────────────────

    def _on_progress(self, pct: int):
        """Update overall progress with smooth animation.

        Some parser backends also print textual progress into the console before
        emitting worker.progress(), so _on_log() can call this as a safe fallback.
        The displayed value is monotonic during a run to avoid the bar jumping
        backward when a module reports its own local percentage.
        """
        try:
            pct = int(round(float(pct)))
        except (TypeError, ValueError):
            return
        pct = max(0, min(100, pct))

        current = int(self.overall_bar.value())
        if pct < current and current < 100:
            return

        self._progress_target = pct
        self.overall_pct.setText(f"{pct}%")

        if self._progress_anim is not None:
            self._progress_anim.stop()

        self._progress_anim = QPropertyAnimation(self.overall_bar, b"value", self)
        self._progress_anim.setDuration(320)
        self._progress_anim.setStartValue(current)
        self._progress_anim.setEndValue(pct)
        self._progress_anim.setEasingCurve(QEasingCurve.OutCubic)
        self._progress_anim.start()

    def _on_phase_local_progress(self, local_pct: float):
        """Scale parser/module-local percentage into the overall workflow.

        Example: if there are 4 phases and Phase 1 reports 80%, the overall
        progress should be around 20%, not 80%. This prevents the left panel from
        racing to 90% while still inside EPROCESS scanning.
        """
        try:
            local_pct = float(local_pct)
        except (TypeError, ValueError):
            return

        phase_idx = max(0, min(int(getattr(self, "_current_phase_idx", 0)), self._phase_count - 1))
        phase_span = 100.0 / float(self._phase_count)
        phase_base = phase_idx * phase_span

        # Leave a tiny margin until the worker explicitly moves to the next phase.
        phase_cap = phase_base + (phase_span * 0.96)
        overall = phase_base + (max(0.0, min(100.0, local_pct)) / 100.0) * phase_span
        self._on_progress(min(overall, phase_cap))

    def _on_phase_changed(self, phase_idx: int, phase_name: str):
        self._current_phase_idx = max(0, min(int(phase_idx), self._phase_count - 1))

        # Move the overall bar to the start of the active phase if needed.
        phase_base = (self._current_phase_idx * 100.0) / float(self._phase_count)
        self._on_progress(phase_base)

        # Mark previous phase complete
        if phase_idx > 0:
            self._phase_cards[phase_idx - 1].set_complete()
        # Activate current phase
        if phase_idx < len(self._phase_cards):
            self._phase_cards[phase_idx].set_active()

    def _on_module_done(self, phase_idx: int, module_name: str):
        if phase_idx < len(self._phase_cards):
            self._phase_cards[phase_idx].mark_module_done(module_name)

    def _on_log(self, level: str, msg: str):
        """
        FIX #5: HTML-escape the raw message before injecting it into the
        console's rich-text buffer.

        Previously, any < > & in log output (e.g. the → arrow from certain
        backend loggers, or path strings containing < or >) would corrupt the
        HTML layout or render as invisible characters.  _html.escape() converts
        those characters to their safe entity equivalents before insertion.
        """
        ts      = datetime.now().strftime("%H:%M:%S.%f")[:12]
        col     = LOG_COLORS.get(level, "#94a3b8")
        raw_msg = str(msg)

        # Fallback progress extraction:
        # Native parser logs sometimes contain module-local progress like "87.5%".
        # Do NOT treat that as overall workflow progress. Scale it into the
        # currently active phase so Phase 1 can reach only about 25% of the full
        # workflow, Phase 2 about 50%, etc.
        m = _re.search(r"(\d{1,3}(?:\.\d+)?)\s*%", raw_msg)
        if m:
            try:
                parsed_pct = float(m.group(1))
                if 0.0 <= parsed_pct <= 100.0:
                    self._on_phase_local_progress(parsed_pct)
            except Exception:
                pass

        safe_msg = _soften_console_markup(_html.escape(raw_msg))   # FIX #5: sanitise before inserting
        ts_col = "#5f75a6" if _is_light() else "#64748b"
        msg_col = "#2f4f85" if _is_light() else "#93a4c2"

        html = (
            f'<span style="color:{ts_col}">{ts}</span>&nbsp;'
            f'<span style="color:{col};font-weight:bold">[{level}]</span>&nbsp;'
            f'<span style="color:{msg_col}">{safe_msg}</span>'
        )
        from PyQt5.QtGui import QTextCursor
        cur = self.console.textCursor()
        cur.movePosition(QTextCursor.End)
        if self._log_line_count > 0:
            cur.insertHtml('<br>')
        cur.insertHtml(html)
        self.console.setTextCursor(cur)
        # Auto-scroll to bottom
        sb = self.console.verticalScrollBar()
        sb.setValue(sb.maximum())

        self._log_line_count += 1
        self._log_badge.setText(f"{self._log_line_count} lines")

    def _on_finished(self, session):
        """Analysis complete — save session and show View Results button."""
        if self._phase_cards:
            self._phase_cards[-1].set_complete()

        self._on_progress(100)
        self.activity_bar.hide()
        if self._activity_timer.isActive():
            self._activity_timer.stop()

        # Persist to scan history
        session.status = "complete"
        AppState.save_current()

        self._on_log("INFO", "─" * 52)
        verdict = session.ml_result.get("verdict", "unknown").upper()
        score = (
            session.ml_result.get("suspicion_score")
            or session.ml_result.get("hybrid_score")
            or session.ml_result.get("confidence", 0)
        )

        try:
            disp_score = float(score)
        except (TypeError, ValueError):
            disp_score = 0.0
        disp_score = disp_score * 100.0 if 0.0 <= disp_score <= 1.0 else disp_score

        _audit_analysis_completed(session, verdict=verdict, hybrid_score=disp_score)

        col     = "#f87171" if verdict == "SUSPICIOUS" else "#34d399"
        from PyQt5.QtGui import QTextCursor
        cur = self.console.textCursor()
        cur.movePosition(QTextCursor.End)
        cur.insertHtml('<br>')
        cur.insertHtml(
            f'<span style="color:{col};font-weight:bold;font-size:13px">'
            f'&#x25BA; VERDICT: {verdict}  (hybrid score {disp_score:.1f}%)'
            f'</span>'
        )
        self.console.setTextCursor(cur)
        sb = self.console.verticalScrollBar()
        sb.setValue(sb.maximum())

        self.cancel_btn.hide()
        self.cont_btn.show()
        self._worker = None

    def _on_error(self, msg: str):
        """Worker raised an exception — show error state."""
        if self._phase_cards:
            # Mark the currently-active phase as error
            for pc in self._phase_cards:
                if pc._badge.text() == "ACTIVE":
                    pc.set_error()
                    break

        self.activity_bar.hide()
        if self._activity_timer.isActive():
            self._activity_timer.stop()

        self._on_log("ERROR", f"Analysis failed: {msg}")
        try:
            _audit_analysis_failed(AppState.current, str(msg))
        except Exception:
            pass
        # FIX #5: error banner text is set as plain text (not HTML), so
        # special characters in the message are safe here without escaping.
        self._err_banner.setText(f"⚠  {msg}")
        self._err_banner.show()

        self.cancel_btn.hide()
        self.retry_btn.show()
        self._worker = None

    # ── UI helpers ────────────────────────────────────────────────────────────

    def _animate_activity(self):
        """Small visual heartbeat while the analysis worker is active."""
        self._anim_tick = (self._anim_tick + 1) % 1000

        # Rotate / refresh the active phase icon.
        for pc in self._phase_cards:
            pc.animate_tick(self._anim_tick)

        # Thin activity line below the main progress bar.
        if hasattr(self, "activity_bar") and self.activity_bar.isVisible():
            self.activity_bar.setValue((self._anim_tick * 5) % 101)

    def _reset_ui(self):
        """Reset all widgets to their initial state before a new run."""
        self.overall_pct.setText("0%")
        self.overall_bar.setValue(0)
        self._progress_target = 0
        self._current_phase_idx = 0
        self._phase_count = max(1, len(PHASE_MAP))
        if hasattr(self, "activity_bar"):
            self.activity_bar.setValue(0)
            self.activity_bar.hide()
        for pc in self._phase_cards:
            pc.set_pending()
        self.console.clear()
        self._log_line_count = 0
        self._log_badge.setText("0 lines")
        self._err_banner.hide()
        self.cancel_btn.show()
        self.cont_btn.hide()
        self.retry_btn.hide()

    def _clear_console(self):
        self.console.clear()
        self._log_line_count = 0
        self._log_badge.setText("0 lines")

    # ── Auto-start on page show ───────────────────────────────────────────────

    def apply_theme(self, theme: str | None = None):
        """Refresh theme-aware Realtime Analysis widgets after live switching."""
        active = "light" if str(theme or current_theme()).strip().lower() == "light" else "dark"
        self.setProperty("ramdetectTheme", active)
        try:
            self._header.apply_theme(active)
        except Exception:
            pass
        for card in self.findChildren(QFrame, "RealtimePanelCard"):
            card.setStyleSheet(_realtime_panel_qss())
        for pc in getattr(self, "_phase_cards", []):
            try:
                state = (pc._badge.text() or "pending").strip().lower()
                pc.setStyleSheet(_phase_card_qss(state))
                if state == "pending":
                    pc.set_pending()
                elif state == "active":
                    pc.set_active()
                elif state == "complete":
                    pc.set_complete()
                elif state == "error":
                    pc.set_error()
            except Exception:
                pass
        if hasattr(self, "overall_bar"):
            self.overall_bar.setStyleSheet(_progress_bar_qss("overall"))
        if hasattr(self, "activity_bar"):
            self.activity_bar.setStyleSheet(_progress_bar_qss("activity"))
        for scroll_area in self.findChildren(QScrollArea, "RealtimePhaseScroll"):
            try:
                scroll_area.setStyleSheet(_phase_scroll_qss())
            except Exception:
                pass
        for hdr in self.findChildren(QFrame, "ConsoleHeaderBar"):
            try:
                hdr.setStyleSheet(_console_header_qss(active))
            except Exception:
                pass
        if hasattr(self, "_log_badge"):
            self._log_badge.setStyleSheet(_log_badge_qss(active))
        if hasattr(self, "clear_btn"):
            self.clear_btn.setStyleSheet(_clear_button_qss(active))
        if hasattr(self, "console"):
            self.console.setStyleSheet(_console_qss())
        self._lock_header_navigation(True)
        refresh_style(self)

    def showEvent(self, event):
        """
        Start a fresh worker only when the session has changed (i.e. the user
        has loaded a new dump and is visiting this page for the first time for
        that session).  Window minimize/restore re-fires showEvent but the
        session ID is the same, so we skip the restart and let the existing
        worker or completed state stand untouched.
        """
        super().showEvent(event)
        current_id = AppState.current.session_id if AppState.current else None
        if current_id == self._last_session_id:
            # Same session — window was just restored or re-shown; do nothing.
            return
        # New session: clear the previous completed UI immediately.  Previously
        # _reset_ui() only ran inside _start_worker() after a 120 ms delay, so the
        # right console could briefly show the previous "VERDICT / View Results"
        # completed state when a new analysis was opened.
        self._reset_ui()
        self._lock_header_navigation(True)
        self._on_log("INFO", "Preparing new analysis session…")

        # Cancel any stale worker and kick off a fresh run.
        if self._worker and self._worker.isRunning():
            self._worker.cancel()
            self._worker.wait(1000)
            self._worker = None

        # Small delay so the reset page finishes painting before the worker starts.
        QTimer.singleShot(120, self._start_worker)
