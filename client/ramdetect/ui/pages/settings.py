"""
ui/pages/settings.py — FYP-limited Settings page
──────────────────────────────────────────────
This page intentionally exposes only configuration options that are relevant
for the RAMDetect FYP workflow:

  • DumpIt acquisition path/output directory
  • Project output paths for reports/logs
  • Analysis convenience options
  • Report export preferences
  • Read-only architecture/ML decision summary

It does NOT expose ML threshold/model/weight controls because the current
RAMDetect architecture is ML-only with a fixed RF threshold of 0.5 and
54 canonical base features + Autoencoder MSE = 55 fused RF input.
"""
from __future__ import annotations

from typing import Any
from pathlib import Path
import os

from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QGridLayout,
    QLabel, QFrame, QPushButton, QLineEdit,
    QCheckBox, QComboBox, QScrollArea,
    QFileDialog, QMessageBox, QDialog, QApplication,
)
from PyQt5.QtCore import Qt, QTimer
from PyQt5.QtGui import QFont

from ui.pages.base_page import BasePage
from ui.bridge.config_bridge import Config
from ui.style_helpers import set_role, set_tone, set_variant, set_state
from ui.theme import current_theme, save_theme, apply_theme as apply_ui_theme
from ui.widgets.theme_switch import ThemeSwitch

# ── Palette ──────────────────────────────────────────────────────────────────
_BG      = '#0f172a'
_CARD    = '#1e293b'
_CARD_2  = '#111827'
_BORDER  = '#334155'
_CYAN    = '#06b6d4'
_GREEN   = '#34d399'
_RED     = '#f87171'
_YELLOW  = '#facc15'
_BLUE    = '#60a5fa'
_TEXT    = '#e2e8f0'
_MUTED   = '#94a3b8'
_WHITE   = '#ffffff'

# Only reset/save the settings that are actually visible on this FYP page.
# This prevents the Settings page from changing hidden ML threshold/model logic.
_FYP_DEFAULTS: dict[str, Any] = {
    'acquisition.dumpit_path': 'tools/DumpIt.exe',
    'acquisition.output_dir': 'dumps/',
    'paths.reports_dir': 'reports/',
    'paths.logs_dir': 'logs/',
    'analysis.enable_logging': True,
    'analysis.auto_save': True,
    'report.default_format': 'pdf',
    'reports.header_text': 'RAMDetect Forensic Analysis Report',
    'reports.organisation': 'UTHM PTM ICT Security Team',
}


_PROJECT_PATH_KEYS = {
    'acquisition.output_dir': 'dumps',
    'paths.reports_dir': 'reports',
    'paths.logs_dir': 'logs',
}


def _settings_project_root() -> Path:
    """Resolve the current RAMDetect project root, regardless of install folder."""
    here = Path(__file__).resolve()
    for parent in here.parents:
        if (parent / "main.py").is_file() and (parent / "ramdetect").is_dir():
            return parent
    # settings.py -> pages -> ui -> ramdetect -> project root
    return here.parents[3]


def _portable_project_path_value(key: str, value: Any) -> str:
    """Normalize visible project-owned paths so copied clients do not keep stale absolute paths.

    For acquisition.output_dir/reports/logs we store portable relative paths in config.yaml.
    ConfigBridge can still resolve them to the current RAMDetect project root at runtime.
    DumpIt executable paths are not forced because a user may intentionally browse an
    external DumpIt.exe location.
    """
    if key not in _PROJECT_PATH_KEYS:
        return "" if value is None else str(value)

    raw = "" if value is None else str(value).strip()
    default_rel = _PROJECT_PATH_KEYS[key]
    if not raw:
        return default_rel

    normalized = raw.replace("\\", "/").rstrip("/")
    # If copied config contains another RAMDetect absolute path, replace it with
    # the portable project-relative folder name.
    if "/RAMDetect/" in normalized and normalized.lower().endswith("/" + default_rel.lower()):
        return default_rel

    # Keep already-relative project folder values portable.
    if not os.path.isabs(raw):
        tail = normalized.split("/")[-1].lower()
        if tail == default_rel.lower():
            return default_rel
        return raw

    # For the dump output folder, enforce RAMDetect's managed ./dumps directory.
    # This matches the acquisition page rule and avoids sidecar files elsewhere.
    if key == 'acquisition.output_dir':
        return default_rel

    return raw


# ─────────────────────────────────────────────────────────────────────────────
# Styling helpers
# ─────────────────────────────────────────────────────────────────────────────

def _card(parent=None) -> QFrame:
    f = QFrame(parent)
    f.setObjectName('settingsCard')
    f.setFrameShape(QFrame.NoFrame)
    f.setAttribute(Qt.WA_StyledBackground, True)
    set_role(f, "settings-card")
    return f


def _soft_card(parent=None) -> QFrame:
    f = QFrame(parent)
    f.setObjectName('softCard')
    f.setFrameShape(QFrame.NoFrame)
    f.setAttribute(Qt.WA_StyledBackground, True)
    set_role(f, "settings-soft-card")
    return f


def _section_header(title: str, subtitle: str = '') -> QWidget:
    w = QWidget()
    w.setObjectName('SettingsSectionHeader')
    w.setAttribute(Qt.WA_StyledBackground, True)
    set_role(w, "transparent")
    # Keep Settings section headers as text-only headers. This prevents the
    # older global QSS from creating a separate dark/light rectangle behind
    # section titles after live theme switching.
    w.setStyleSheet(
        "QWidget#SettingsSectionHeader { background: transparent; border: none; }"
        "QWidget#SettingsSectionHeader QLabel { background: transparent; border: none; padding: 0px; margin: 0px; }"
    )
    v = QVBoxLayout(w)
    v.setContentsMargins(0, 0, 0, 6)
    v.setSpacing(2)

    t = QLabel(title)
    t.setObjectName('SettingsSectionTitle')
    t.setFont(QFont('Segoe UI', 13, QFont.Bold))
    t.setWordWrap(False)
    set_tone(t, _WHITE)
    v.addWidget(t)

    if subtitle:
        s = QLabel(subtitle)
        s.setObjectName('SettingsSectionSubtitle')
        s.setWordWrap(True)
        s.setFont(QFont('Segoe UI', 10))
        set_tone(s, _MUTED)
        v.addWidget(s)
    return w


def _label(text: str, size: int = 12, color: str = _TEXT, bold: bool = False) -> QLabel:
    lbl = QLabel(text)
    lbl.setObjectName('SettingsLabel')
    lbl.setWordWrap(True)
    lbl.setFont(QFont('Segoe UI', size, QFont.Bold if bold else QFont.Normal))
    # Prevent the pale/dark rectangular label blocks that appeared after live theme switching.
    lbl.setStyleSheet('background: transparent; border: none; padding: 0px; margin: 0px;')
    set_tone(lbl, color)
    return lbl


def _line_edit(placeholder: str = '') -> QLineEdit:
    e = QLineEdit()
    e.setObjectName('SettingsLineEdit')
    e.setPlaceholderText(placeholder)
    e.setMinimumHeight(32)
    e.setMaximumHeight(34)
    return e


def _combo(options: list[str]) -> QComboBox:
    c = QComboBox()
    c.setObjectName('SettingsComboBox')
    c.addItems(options)
    c.setMinimumHeight(32)
    c.setMaximumHeight(34)
    return c


def _checkbox(label: str) -> QCheckBox:
    cb = QCheckBox(label)
    cb.setObjectName('SettingsCheckBox')
    cb.setMinimumHeight(28)
    return cb


def _browse_btn() -> QPushButton:
    b = QPushButton('Browse')
    b.setObjectName('SettingsBrowseButton')
    b.setFixedSize(92, 34)
    b.setFont(QFont('Segoe UI', 9, QFont.Bold))
    set_variant(b, "browse")
    return b


def _pill(text: str, color: str = _CYAN) -> QLabel:
    p = QLabel(text)
    p.setAlignment(Qt.AlignCenter)
    p.setAttribute(Qt.WA_StyledBackground, True)
    p.setMinimumHeight(26)
    p.setProperty("role", "pill")
    set_tone(p, color)
    return p


def _keyword_chip(text: str) -> QFrame:
    """Small boxed keyword chip for the FYP System Settings summary card."""
    chip = QFrame()
    chip.setObjectName('SettingsKeywordChip')
    chip.setFrameShape(QFrame.NoFrame)
    chip.setAttribute(Qt.WA_StyledBackground, True)
    chip.setMinimumHeight(32)
    chip.setMinimumWidth(94)

    row = QHBoxLayout(chip)
    row.setContentsMargins(10, 0, 10, 0)
    row.setSpacing(0)

    lbl = QLabel(text)
    lbl.setObjectName('SettingsKeywordText')
    lbl.setAlignment(Qt.AlignCenter)
    lbl.setWordWrap(False)
    lbl.setFont(QFont('Segoe UI', 9, QFont.Bold))
    lbl.setStyleSheet('background: transparent; border: none; padding: 0px; margin: 0px;')
    set_tone(lbl, _CYAN)
    row.addWidget(lbl)
    return chip


def _themed_confirm(parent, title: str, message: str, yes_text: str = 'Yes', no_text: str = 'No') -> bool:
    """Compact RAMDetect-themed confirmation dialog.

    Designed to keep the familiar QMessageBox layout:
      title bar → message body → bottom action area
    but with RAMDetect's blue/black theme instead of Windows' light gray body.
    """
    dlg = QDialog(parent)
    dlg.setWindowFlags(Qt.Dialog | Qt.FramelessWindowHint)
    dlg.setModal(True)
    dlg.setObjectName('ramdetectConfirmDialog')
    dlg.setFixedWidth(660)

    dlg.setStyleSheet(f"""
        QDialog#ramdetectConfirmDialog {{
            background: {_CARD_2};
            border: 1px solid rgba(96,165,250,0.55);
            border-radius: 10px;
        }}
        QLabel {{
            background: transparent;
            border: none;
        }}
        QPushButton {{
            min-width: 86px;
            min-height: 34px;
            border-radius: 8px;
            padding: 7px 18px;
            font-size: 13px;
            font-weight: 800;
        }}
        QPushButton#yesButton {{
            background: rgba(51,65,85,0.96);
            color: {_WHITE};
            border: 1px solid rgba(96,165,250,0.48);
        }}
        QPushButton#yesButton:hover {{
            background: qlineargradient(x1:0,y1:0,x2:1,y2:0,stop:0 {_CYAN},stop:1 #2563eb);
            border-color: {_CYAN};
        }}
        QPushButton#noButton {{
            background: rgba(51,65,85,0.82);
            color: {_WHITE};
            border: 1px solid rgba(71,85,105,0.95);
        }}
        QPushButton#noButton:hover {{
            background: rgba(71,85,105,0.96);
            border-color: rgba(148,163,184,0.85);
        }}
    """)

    root = QVBoxLayout(dlg)
    root.setContentsMargins(0, 0, 0, 0)
    root.setSpacing(0)

    # Compact title bar, similar to a QMessageBox header but dark themed.
    title_bar = QFrame()
    title_bar.setObjectName('confirmTitleBar')
    title_bar.setFixedHeight(42)
    title_bar.setStyleSheet(f"""
        QFrame#confirmTitleBar {{
            background: #0b1220;
            border: none;
            border-bottom: 1px solid rgba(51,65,85,0.75);
            border-top-left-radius: 10px;
            border-top-right-radius: 10px;
        }}
    """)
    title_l = QHBoxLayout(title_bar)
    title_l.setContentsMargins(12, 0, 10, 0)
    title_l.setSpacing(8)

    app_icon = QLabel('▣')
    app_icon.setFixedSize(18, 18)
    app_icon.setAlignment(Qt.AlignCenter)
    app_icon.setStyleSheet(f"""
        QLabel {{
            color: {_CYAN};
            font-size: 10px;
            border: 1px solid rgba(96,165,250,0.45);
            border-radius: 3px;
            background: rgba(96,165,250,0.10);
        }}
    """)
    title_l.addWidget(app_icon)

    title_lbl = QLabel(title)
    title_lbl.setStyleSheet(f"color:{_TEXT}; font-size:13px; font-weight:600;")
    title_l.addWidget(title_lbl, 1)

    close_btn = QPushButton('×')
    close_btn.setObjectName('closeButton')
    close_btn.setFixedSize(30, 30)
    close_btn.setCursor(Qt.PointingHandCursor)
    close_btn.setStyleSheet(f"""
        QPushButton#closeButton {{
            background: transparent;
            color: {_TEXT};
            border: none;
            border-radius: 6px;
            font-size: 20px;
            font-weight: 400;
            min-width: 30px;
            min-height: 30px;
            padding: 0;
        }}
        QPushButton#closeButton:hover {{
            background: rgba(248,113,113,0.18);
            color: #fecaca;
        }}
    """)
    close_btn.clicked.connect(dlg.reject)
    title_l.addWidget(close_btn)

    root.addWidget(title_bar)

    # Message body: same simple message-box structure, but dark and readable.
    body = QFrame()
    body.setObjectName('confirmBody')
    body.setStyleSheet(f"""
        QFrame#confirmBody {{
            background: #111827;
            border: none;
        }}
    """)
    body_l = QHBoxLayout(body)
    body_l.setContentsMargins(22, 20, 22, 20)
    body_l.setSpacing(22)

    icon = QLabel('?')
    icon.setAlignment(Qt.AlignCenter)
    icon.setFixedSize(54, 54)
    icon.setStyleSheet(f"""
        QLabel {{
            color: {_WHITE};
            background: rgba(6,182,212,0.22);
            border: 1px solid rgba(6,182,212,0.72);
            border-radius: 27px;
            font-size: 30px;
            font-weight: 800;
        }}
    """)
    body_l.addWidget(icon, 0, Qt.AlignTop)

    msg_lbl = QLabel(message)
    msg_lbl.setWordWrap(True)
    msg_lbl.setMinimumHeight(54)
    msg_lbl.setAlignment(Qt.AlignVCenter | Qt.AlignLeft)
    msg_lbl.setStyleSheet(f"""
        QLabel {{
            color: {_TEXT};
            font-size: 14px;
            font-weight: 500;
        }}
    """)
    body_l.addWidget(msg_lbl, 1)

    root.addWidget(body)

    footer = QFrame()
    footer.setObjectName('confirmFooter')
    footer.setFixedHeight(82)
    footer.setStyleSheet(f"""
        QFrame#confirmFooter {{
            background: {_CARD};
            border: none;
            border-top: 1px solid rgba(51,65,85,0.65);
            border-bottom-left-radius: 10px;
            border-bottom-right-radius: 10px;
        }}
    """)
    footer_l = QHBoxLayout(footer)
    footer_l.setContentsMargins(18, 16, 18, 16)
    footer_l.addStretch(1)

    yes_btn = QPushButton(yes_text)
    yes_btn.setObjectName('yesButton')
    yes_btn.setCursor(Qt.PointingHandCursor)
    no_btn = QPushButton(no_text)
    no_btn.setObjectName('noButton')
    no_btn.setCursor(Qt.PointingHandCursor)

    yes_btn.clicked.connect(dlg.accept)
    no_btn.clicked.connect(dlg.reject)

    footer_l.addWidget(yes_btn)
    footer_l.addSpacing(10)
    footer_l.addWidget(no_btn)
    root.addWidget(footer)

    return dlg.exec_() == QDialog.Accepted


# ─────────────────────────────────────────────────────────────────────────────
# Settings page
# ─────────────────────────────────────────────────────────────────────────────

class SettingsPage(BasePage):
    PAGE_TITLE = 'Settings'

    def __init__(self, main_window):
        super().__init__(main_window, show_dashboard=True)
        self._main_window = main_window
        self._fields: dict[str, QWidget] = {}
        self._logout_panel: QFrame | None = None
        self._logout_user_label: QLabel | None = None
        self._theme_buttons: dict[str, QPushButton] = {}
        self._theme_status: QLabel | None = None
        self._theme_switch: ThemeSwitch | None = None
        self._theme_preview: QFrame | None = None
        self._settings_scroll: QScrollArea | None = None
        self._settings_container: QWidget | None = None
        self._theme_apply_busy = False
        self._build_body()

    # ── Layout ────────────────────────────────────────────────────────────────

    def _build_body(self):
        scroll = QScrollArea()
        self._settings_scroll = scroll
        scroll.setObjectName('SettingsScroll')
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)

        container = QWidget()
        self._settings_container = container
        container.setObjectName('SettingsContainer')
        root = QVBoxLayout(container)
        # Page-level margins are applied on self.body below so the Settings
        # scroll viewport follows the same HeaderBar/body margin standard as
        # the workflow pages. The container itself stays flush inside the
        # viewport, preventing double margins and inconsistent card edges.
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(10)

        root.addWidget(self._page_intro())

        # Place account/logout immediately after the top Settings summary so
        # users can switch accounts before editing workflow preferences.
        self._logout_panel = self._non_admin_logout_panel()
        root.addWidget(self._logout_panel)

        root.addWidget(self._section_appearance())
        root.addWidget(self._section_architecture_summary())

        paths_row = QHBoxLayout()
        paths_row.setSpacing(10)
        paths_row.addWidget(self._section_dumpit(), 1)
        paths_row.addWidget(self._section_project_outputs(), 1)
        root.addLayout(paths_row)

        root.addWidget(self._section_analysis_report())
        root.addWidget(self._action_row())
        root.addStretch(1)

        scroll.setWidget(container)

        bl = QVBoxLayout(self.body)
        # Match the global workflow margin used by Acquisition and Results.
        # Keep the scroll area inside the margin instead of letting the viewport
        # touch the window edge.
        bl.setContentsMargins(40, 28, 40, 16)
        bl.setSpacing(0)
        bl.addWidget(scroll)

    def _page_intro(self) -> QFrame:
        card = _card()
        card.setObjectName('SettingsIntroCard')
        card.setMaximumHeight(112)
        h = QHBoxLayout(card)
        h.setContentsMargins(16, 12, 16, 12)
        h.setSpacing(16)

        left = QVBoxLayout()
        left.setSpacing(3)
        title = _label('FYP System Settings', 17, _WHITE, True)
        subtitle = _label(
            'Only project-relevant settings are editable here. ML architecture, threshold, and verdict logic are locked to match the official RAMDetect design.',
            10,
            _MUTED,
        )
        subtitle.setMaximumHeight(42)
        left.addWidget(title)
        left.addWidget(subtitle)
        h.addLayout(left, 1)

        pills = QHBoxLayout()
        pills.setSpacing(7)
        for txt in ('Post-incident', 'DumpIt', 'ML-only', 'RF threshold 0.5'):
            pills.addWidget(_keyword_chip(txt))
        h.addLayout(pills, 0)
        return card

    def _section_appearance(self) -> QFrame:
        """Local UI theme switch with a compact animated RAMDetect appearance control."""
        card = _card()
        card.setObjectName('settingsAppearanceCard')
        card.setMaximumHeight(235)
        v = QVBoxLayout(card)
        v.setContentsMargins(18, 14, 18, 14)
        v.setSpacing(10)

        header = QHBoxLayout()
        header.setSpacing(10)
        icon = QLabel('🎨')
        icon.setObjectName('AppearanceIcon')
        icon.setFixedSize(36, 36)
        icon.setAlignment(Qt.AlignCenter)
        header.addWidget(icon, alignment=Qt.AlignTop)

        title_stack = QVBoxLayout()
        title_stack.setSpacing(2)
        title_stack.addWidget(_label('Appearance', 15, _WHITE, True))
        subtitle = _label(
            'Choose how RAMDetect is displayed on this workstation. This is a local UI preference only.',
            10,
            _MUTED,
        )
        title_stack.addWidget(subtitle)
        header.addLayout(title_stack, 1)

        self._theme_status = QLabel('')
        self._theme_status.setObjectName('ThemeStatusLabel')
        self._theme_status.setAlignment(Qt.AlignCenter)
        self._theme_status.setMinimumWidth(132)
        self._theme_status.setMaximumWidth(155)
        header.addWidget(self._theme_status)
        v.addLayout(header)

        divider = QFrame()
        divider.setFixedHeight(1)
        set_role(divider, "separator")
        v.addWidget(divider)

        content = QHBoxLayout()
        content.setSpacing(10)

        switch_card = _soft_card()
        switch_card.setObjectName('ThemeSwitchCard')
        sw_v = QVBoxLayout(switch_card)
        sw_v.setContentsMargins(14, 10, 14, 10)
        sw_v.setSpacing(7)
        sw_v.addWidget(_label('Interface Theme', 11, _WHITE, True))
        msg = _label('Animated switch between RAMDetect dark cyber-forensics mode and clean light mode.', 9, _MUTED)
        msg.setMaximumHeight(36)
        sw_v.addWidget(msg)

        self._theme_switch = ThemeSwitch(current_theme())
        self._theme_switch.theme_changed.connect(self._apply_theme_choice)
        sw_v.addWidget(self._theme_switch, alignment=Qt.AlignLeft)
        content.addWidget(switch_card, 1)

        preview = _soft_card()
        preview.setObjectName('ThemePreviewCard')
        self._theme_preview = preview
        pv = QVBoxLayout(preview)
        pv.setContentsMargins(14, 10, 14, 10)
        pv.setSpacing(7)
        pv.addWidget(_label('Preview', 11, _WHITE, True))
        mini_header = QFrame()
        mini_header.setObjectName('ThemeMiniHeader')
        mini_header.setFixedHeight(28)
        mini_row = QHBoxLayout(mini_header)
        mini_row.setContentsMargins(10, 0, 10, 0)
        mini_row.addWidget(_label('RAMDetect', 9, _WHITE, True))
        mini_row.addStretch()
        p = _pill('v1.0')
        p.setObjectName('SettingsPreviewPill')
        mini_row.addWidget(p)
        pv.addWidget(mini_header)
        mini_grid = QHBoxLayout()
        mini_grid.setSpacing(7)
        for label, value in [('Clean', '—'), ('Suspicious', '—'), ('Last Scan', 'No scan')]:
            box = QFrame()
            box.setObjectName('ThemeMiniCard')
            bv = QVBoxLayout(box)
            bv.setContentsMargins(9, 6, 9, 6)
            bv.setSpacing(1)
            bv.addWidget(_label(label, 8, _MUTED))
            bv.addWidget(_label(value, 11, _WHITE, True))
            mini_grid.addWidget(box)
        pv.addLayout(mini_grid)
        content.addWidget(preview, 1)

        v.addLayout(content)
        self._refresh_theme_buttons()
        return card

    def _refresh_theme_buttons(self):
        active = current_theme()
        if self._theme_switch is not None:
            self._theme_switch.set_theme(active, animated=False, emit=False)
        for theme_name, btn in self._theme_buttons.items():
            set_state(btn, 'active' if theme_name == active else 'inactive')
        if self._theme_status is not None:
            label = 'Dark Mode' if active == 'dark' else 'Light Mode'
            self._theme_status.setText(f'Current theme\n{label}')
        if self._theme_preview is not None:
            self._theme_preview.setProperty('activeTheme', active)
            try:
                self._theme_preview.style().unpolish(self._theme_preview)
                self._theme_preview.style().polish(self._theme_preview)
                self._theme_preview.update()
            except Exception:
                pass
        self._apply_local_theme_surfaces(active)

    def _apply_theme_choice(self, theme_name: str):
        """Apply theme from the animated switch using a guarded delayed update.

        QApplication.setStyleSheet() can momentarily block while repolishing the
        already-created RAMDetect pages.  The short delay lets the switch paint
        its first animation frame and prevents repeated rapid clicks from making
        the application appear frozen.
        """
        requested = 'light' if str(theme_name).lower() == 'light' else 'dark'
        if requested == current_theme():
            if self._theme_switch is not None:
                self._theme_switch.set_theme(requested, animated=False, emit=False)
            self._refresh_theme_buttons()
            return
        if self._theme_apply_busy:
            if self._theme_switch is not None:
                self._theme_switch.set_theme(current_theme(), animated=True, emit=False)
            return

        self._theme_apply_busy = True
        if self._theme_switch is not None:
            self._theme_switch.setEnabled(False)
        try:
            QApplication.setOverrideCursor(Qt.WaitCursor)
        except Exception:
            pass

        # Keep the UI responsive, but avoid an unnecessary long delay before
        # the actual theme application starts. The QApplication theme helper now
        # freezes top-level repainting during the repolish step.
        QTimer.singleShot(40, lambda theme=requested: self._finish_theme_choice(theme))

    def _finish_theme_choice(self, theme_name: str):
        active = current_theme()
        try:
            # Prefer MainWindow's helper so all HeaderBar logos refresh together.
            # MainWindow.apply_theme() already persists the theme, so do not save
            # it here first. This avoids duplicate QSettings writes and repeated
            # theme refresh paths during live switching.
            if hasattr(self._main_window, 'apply_theme'):
                active = self._main_window.apply_theme(theme_name)
            else:
                active = apply_ui_theme(theme=theme_name, persist=True)
            self._refresh_theme_buttons()
            if self._save_status is not None:
                self._save_status.setText(f'✓  UI theme changed to {active.title()} Mode')
                QTimer.singleShot(3000, lambda: self._save_status.setText(''))
        finally:
            self._theme_apply_busy = False
            if self._theme_switch is not None:
                self._theme_switch.setEnabled(True)
                self._theme_switch.set_theme(active, animated=False, emit=False)
            try:
                QApplication.restoreOverrideCursor()
            except Exception:
                pass

    def _settings_local_qss(self, theme_name: str) -> str:
        """Return compact Settings-only styling for the current theme."""
        if theme_name == 'light':
            return """
                QWidget#SettingsContainer { background: #f0f5ff; }
                QWidget#SettingsContainer QLabel {
                    background: transparent;
                    border: none;
                    padding: 0px;
                    margin: 0px;
                }
                QFrame#SettingsIntroCard,
                QFrame#settingsCard,
                QFrame#settingsAppearanceCard,
                QFrame#nonAdminLogoutPanel {
                    background: #ffffff;
                    border: 1px solid #cfe0ff;
                    border-radius: 14px;
                }
                QFrame#ThemeSwitchCard,
                QFrame#ThemePreviewCard,
                QFrame#SettingsFormCard,
                QFrame#SettingsMetricTile,
                QFrame#SettingsPathPanel,
                QFrame#SettingsReportPanel {
                    background: #ffffff;
                    border: 1px solid #d6e4ff;
                    border-radius: 12px;
                }
                QFrame#ThemeMiniHeader {
                    background: #1a56db;
                    border: none;
                    border-radius: 8px;
                }
                QFrame#ThemeMiniCard {
                    background: #f8fbff;
                    border: 1px solid #dbe7ff;
                    border-radius: 8px;
                }
                QLabel#AppearanceIcon {
                    background: #eef4ff;
                    color: #1a56db;
                    border: 1px solid #cfe0ff;
                    border-radius: 11px;
                    font-size: 17px;
                }
                QLabel#ThemeStatusLabel {
                    color: #1e3a6e;
                    background: #f8fbff;
                    border: 1px solid #d6e4ff;
                    border-radius: 10px;
                    padding: 6px 10px;
                    font-size: 11px;
                    font-weight: 800;
                }
                QLabel#SettingsTopPill,
                QLabel[role="pill"] {
                    color: #1a56db;
                    background: #eef4ff;
                    border: 1px solid #d6e4ff;
                    border-radius: 9px;
                    padding: 5px 10px;
                    font-size: 10px;
                    font-weight: 800;
                }
                QLineEdit#SettingsLineEdit,
                QComboBox#SettingsComboBox {
                    background: #f4f8ff;
                    border: 1px solid #d6e4ff;
                    border-radius: 9px;
                    padding: 5px 10px;
                    color: #1e3a6e;
                    font-size: 11px;
                }
                QLineEdit#SettingsLineEdit:focus,
                QComboBox#SettingsComboBox:focus {
                    border: 1px solid #1a56db;
                    background: #ffffff;
                }
                QPushButton#SettingsBrowseButton,
                QPushButton[variant="secondary"] {
                    background: #f8fbff;
                    color: #1e3a6e;
                    border: 1px solid #cfe0ff;
                    border-radius: 9px;
                    padding: 4px 8px;
                    font-size: 10px;
                    font-weight: 800;
                }
                QPushButton#SettingsBrowseButton:hover,
                QPushButton[variant="secondary"]:hover {
                    background: #eaf1ff;
                    color: #1a56db;
                    border-color: #1a56db;
                }
                QPushButton[variant="primary"] {
                    background: #1a56db;
                    color: #ffffff;
                    border: 1px solid #1a56db;
                    border-radius: 9px;
                    padding: 7px 14px;
                    font-size: 11px;
                    font-weight: 800;
                }
                QPushButton[variant="dangerSoft"] {
                    background: #fff7f7;
                    color: #b91c1c;
                    border: 1px solid #fecaca;
                    border-radius: 9px;
                    padding: 7px 14px;
                    font-size: 11px;
                    font-weight: 800;
                }
                QCheckBox#SettingsCheckBox {
                    color: #1e3a6e;
                    background: #f8fbff;
                    border: 1px solid #d6e4ff;
                    border-radius: 8px;
                    padding: 3px 8px;
                    font-size: 10px;
                }
                QWidget#SettingsSectionHeader {
                    background: transparent;
                    border: none;
                }
                QWidget#SettingsSectionHeader QLabel,
                QLabel#SettingsSectionTitle,
                QLabel#SettingsSectionSubtitle {
                    background: transparent;
                    border: none;
                    padding: 0px;
                    margin: 0px;
                }
                QFrame#SettingsKeywordChip {
                    background: #f8fbff;
                    border: 1px solid #cfe0ff;
                    border-radius: 10px;
                }
                QLabel#SettingsKeywordText {
                    color: #1a56db;
                    background: transparent;
                    border: none;
                    font-size: 9px;
                    font-weight: 800;
                }
                QFrame#SettingsArchitectureCard {
                    background: #ffffff;
                    border: 1px solid #cfe0ff;
                    border-radius: 16px;
                }
                QFrame#SettingsArchitectureCard QFrame#SettingsMetricTile {
                    background: #ffffff;
                    border: 1px solid #d6e4ff;
                    border-radius: 10px;
                }
                QFrame#SettingsArchitectureCard QFrame#SettingsMetricTile QLabel {
                    background: transparent;
                    border: none;
                }
            """
        return """
            QWidget#SettingsContainer { background: #0f172a; }
            QWidget#SettingsContainer QLabel {
                background: transparent;
                border: none;
                padding: 0px;
                margin: 0px;
            }
            QFrame#SettingsIntroCard,
            QFrame#settingsCard,
            QFrame#settingsAppearanceCard,
            QFrame#nonAdminLogoutPanel {
                background: rgba(30,41,59,0.78);
                border: 1px solid rgba(51,65,85,0.75);
                border-radius: 14px;
            }
            QFrame#ThemeSwitchCard,
            QFrame#ThemePreviewCard,
            QFrame#SettingsFormCard,
            QFrame#SettingsMetricTile,
            QFrame#SettingsPathPanel,
            QFrame#SettingsReportPanel {
                background: rgba(15,23,42,0.22);
                border: 1px solid rgba(51,65,85,0.70);
                border-radius: 12px;
            }
            QFrame#ThemeMiniHeader {
                background: rgba(6,182,212,0.18);
                border: 1px solid rgba(6,182,212,0.25);
                border-radius: 8px;
            }
            QFrame#ThemeMiniCard {
                background: rgba(15,23,42,0.28);
                border: 1px solid rgba(51,65,85,0.55);
                border-radius: 8px;
            }
            QLabel#AppearanceIcon {
                background: rgba(6,182,212,0.10);
                color: #22d3ee;
                border: 1px solid rgba(51,65,85,0.72);
                border-radius: 11px;
                font-size: 17px;
            }
            QLabel#ThemeStatusLabel {
                color: #dbeafe;
                background: rgba(15,23,42,0.52);
                border: 1px solid rgba(51,65,85,0.72);
                border-radius: 10px;
                padding: 6px 10px;
                font-size: 11px;
                font-weight: 800;
            }
            QLabel#SettingsTopPill,
            QLabel[role="pill"] {
                color: #22d3ee;
                background: rgba(6,182,212,0.09);
                border: 1px solid rgba(6,182,212,0.20);
                border-radius: 9px;
                padding: 5px 10px;
                font-size: 10px;
                font-weight: 800;
            }
            QLineEdit#SettingsLineEdit,
            QComboBox#SettingsComboBox {
                background: rgba(15,23,42,0.58);
                border: 1px solid rgba(51,65,85,0.70);
                border-radius: 9px;
                padding: 5px 10px;
                color: #e2e8f0;
                font-size: 11px;
            }
            QPushButton#SettingsBrowseButton,
            QPushButton[variant="secondary"] {
                background: rgba(15,23,42,0.52);
                color: #e2e8f0;
                border: 1px solid rgba(51,65,85,0.72);
                border-radius: 9px;
                padding: 4px 8px;
                font-size: 10px;
                font-weight: 800;
            }
            QPushButton#SettingsBrowseButton:hover,
            QPushButton[variant="secondary"]:hover {
                background: rgba(6,182,212,0.12);
                color: #22d3ee;
                border-color: rgba(6,182,212,0.45);
            }
            QPushButton[variant="primary"] {
                background: qlineargradient(x1:0,y1:0,x2:1,y2:0,stop:0 #06b6d4,stop:1 #2563eb);
                color: #ffffff;
                border: 1px solid rgba(6,182,212,0.65);
                border-radius: 9px;
                padding: 7px 14px;
                font-size: 11px;
                font-weight: 800;
            }
            QPushButton[variant="dangerSoft"] {
                background: rgba(127,29,29,0.18);
                color: #fecaca;
                border: 1px solid rgba(248,113,113,0.35);
                border-radius: 9px;
                padding: 7px 14px;
                font-size: 11px;
                font-weight: 800;
            }
            QCheckBox#SettingsCheckBox {
                color: #e2e8f0;
                background: rgba(15,23,42,0.28);
                border: 1px solid rgba(51,65,85,0.55);
                border-radius: 8px;
                padding: 3px 8px;
                font-size: 10px;
            }
            QWidget#SettingsSectionHeader {
                background: transparent;
                border: none;
            }
            QWidget#SettingsSectionHeader QLabel,
            QLabel#SettingsSectionTitle,
            QLabel#SettingsSectionSubtitle {
                background: transparent;
                border: none;
                padding: 0px;
                margin: 0px;
            }
            QFrame#SettingsKeywordChip {
                background: rgba(6,182,212,0.08);
                border: 1px solid rgba(6,182,212,0.25);
                border-radius: 10px;
            }
            QLabel#SettingsKeywordText {
                color: #22d3ee;
                background: transparent;
                border: none;
                font-size: 9px;
                font-weight: 800;
            }
            QFrame#SettingsArchitectureCard {
                background: rgba(30,41,59,0.76);
                border: 1px solid rgba(51,65,85,0.72);
                border-radius: 16px;
            }
            QFrame#SettingsArchitectureCard QFrame#SettingsMetricTile {
                background: rgba(15,23,42,0.22);
                border: 1px solid rgba(51,65,85,0.58);
                border-radius: 10px;
            }
            QFrame#SettingsArchitectureCard QFrame#SettingsMetricTile QLabel {
                background: transparent;
                border: none;
            }
        """
    def _apply_local_theme_surfaces(self, theme_name: str | None = None):
        """Adjust Settings scroll/container backgrounds after live theme change.

        Some Settings controls still have inline dark styles from the previous
        FYP-limited page design. This Phase 1 method keeps the outer Settings
        canvas aligned with the selected theme while later phases move the
        remaining inner controls into QSS.
        """
        theme_name = (theme_name or current_theme()).strip().lower()
        theme_name = 'light' if theme_name == 'light' else 'dark'
        bg = '#f0f5ff' if theme_name == 'light' else _BG
        if self._settings_scroll is not None:
            self._settings_scroll.setStyleSheet(
                f"QScrollArea#SettingsScroll {{ background:{bg}; border:none; }}"
                "QScrollArea#SettingsScroll > QWidget { background: transparent; border:none; }"
            )
            try:
                self._settings_scroll.viewport().setStyleSheet(f"background:{bg}; border:none;")
            except Exception:
                pass
        if self._settings_container is not None:
            self._settings_container.setStyleSheet(self._settings_local_qss(theme_name))

    def _non_admin_logout_panel(self) -> QFrame:
        """
        Analyst/Viewer users do not see the Admin Console side panel.
        This panel gives them a clear way to log out and return to the
        RAMDetect login screen from Settings. Admin users already have the
        side-panel Logout button, so this panel is hidden for Admin accounts.
        """
        card = _card()
        card.setObjectName('nonAdminLogoutPanel')
        card.setMaximumHeight(76)
        h = QHBoxLayout(card)
        h.setContentsMargins(16, 10, 16, 10)
        h.setSpacing(10)

        left = QVBoxLayout()
        left.setSpacing(2)
        title = _label('Signed in as regular RAMDetect user', 12, _WHITE, True)
        self._logout_user_label = _label(
            'Use Log Out to return to the login screen or switch account.',
            10,
            _MUTED,
        )
        left.addWidget(title)
        left.addWidget(self._logout_user_label)
        h.addLayout(left, 1)

        logout_btn = QPushButton('⏻  Log Out')
        logout_btn.setCursor(Qt.PointingHandCursor)
        logout_btn.setMinimumHeight(34)
        logout_btn.setMaximumHeight(36)
        set_variant(logout_btn, 'dangerSoft')
        logout_btn.clicked.connect(self._logout_to_login)
        h.addWidget(logout_btn)

        card.setVisible(False)
        return card

    def _update_logout_panel_visibility(self):
        if self._logout_panel is None:
            return

        user = self._current_auth_user()
        if user is None:
            self._logout_panel.setVisible(False)
            return

        role = str(getattr(user, 'role', '') or '').strip().lower()
        is_admin = role == 'admin'
        self._logout_panel.setVisible(not is_admin)

        if self._logout_user_label is not None and not is_admin:
            username = str(getattr(user, 'username', 'user') or 'user')
            display_role = str(getattr(user, 'role', 'Analyst') or 'Analyst')
            self._logout_user_label.setText(
                f'Current user: {username} ({display_role}). Use Log Out to return to the login screen or switch account.'
            )

    def _current_auth_user(self):
        try:
            from ui.bridge.auth_bridge import AuthBridge
        except Exception:
            try:
                from ramdetect.ui.bridge.auth_bridge import AuthBridge
            except Exception:
                AuthBridge = None

        if AuthBridge is not None:
            try:
                bridge = AuthBridge.instance()
                if getattr(bridge, 'is_authenticated', False):
                    return getattr(bridge, 'current_user', None)
            except Exception:
                pass

        cm = getattr(self._main_window, 'cm', None)
        if cm is not None:
            try:
                if getattr(cm, 'is_authenticated', False):
                    return getattr(cm, 'current_user', None)
            except Exception:
                pass
        return None

    def _logout_to_login(self):
        if not _themed_confirm(
            self,
            'Log Out - RAMDetect',
            'Log out from RAMDetect and return to the login screen?',
            yes_text='Log Out',
            no_text='Cancel',
        ):
            return

        cm = getattr(self._main_window, 'cm', None)
        if cm is not None and hasattr(cm, 'logout'):
            cm.logout()
            return

        # Fallback path for development runs where CaseManagementIntegration
        # has not been attached to MainWindow.
        try:
            from ui.bridge.auth_bridge import AuthBridge
        except Exception:
            from ramdetect.ui.bridge.auth_bridge import AuthBridge
        try:
            AuthBridge.instance().logout()
        except Exception:
            pass
    # ── Read-only summary ────────────────────────────────────────────────────

    def _section_architecture_summary(self) -> QFrame:
        card = _card()
        card.setObjectName('SettingsArchitectureCard')
        v = QVBoxLayout(card)
        v.setContentsMargins(16, 12, 16, 12)
        v.setSpacing(8)
        v.addWidget(_section_header(
            '🛡️  RAMDetect Architecture Lock',
            'Displayed for transparency only; these values cannot be changed from Settings.'
        ))

        grid = QGridLayout()
        grid.setHorizontalSpacing(8)
        grid.setVerticalSpacing(8)

        items = [
            ('System Scope', 'Post-incident RAM forensics', _BLUE),
            ('Acquisition', 'DumpIt + existing dump upload', _CYAN),
            ('Parser Pipeline', 'Custom RAMDetect extraction', _CYAN),
            ('Final Decision', 'ML-only verdict', _GREEN),
            ('RF Threshold', 'Fixed at 0.5', _YELLOW),
            ('Feature Fusion', '54 features + AE MSE = 55', _GREEN),
            ('ML Support', '28/55 decision features', _CYAN),
            ('CIC Export', '36/55 semantic · CSV 100%', _CYAN),
        ]

        for i, (title, desc, accent) in enumerate(items):
            grid.addWidget(self._readonly_metric(title, desc, accent), i // 4, i % 4)

        v.addLayout(grid)
        note = _label(
            'Hybrid Score remains the final RF-AE suspicion score. CLEAN/SUSPICIOUS still follows the fixed Random Forest threshold of 0.5.',
            9,
            _MUTED,
        )
        note.setMaximumHeight(34)
        v.addWidget(note)
        return card

    def _readonly_metric(self, title: str, desc: str, accent: str) -> QFrame:
        box = _soft_card()
        box.setObjectName('SettingsMetricTile')
        box.setMinimumHeight(62)
        box.setMaximumHeight(76)
        v = QVBoxLayout(box)
        v.setContentsMargins(10, 7, 10, 7)
        v.setSpacing(2)
        t = _label(title, 10, accent, True)
        d = _label(desc, 9, _TEXT)
        d.setMaximumHeight(32)
        v.addWidget(t)
        v.addWidget(d)
        return box

    def _section_dumpit(self) -> QFrame:
        card = _card()
        card.setObjectName('SettingsPathPanel')
        v = QVBoxLayout(card)
        v.setContentsMargins(14, 10, 14, 10)
        v.setSpacing(7)
        v.addWidget(_section_header(
            '🔧  DumpIt Acquisition',
            'Configure DumpIt and the RAM dump output folder.'
        ))

        self._path_row(
            parent_layout=v,
            key='acquisition.dumpit_path',
            label='DumpIt executable path',
            placeholder='tools/DumpIt.exe',
            browse_file=True,
            file_filter='DumpIt Executable (*.exe);;Executable Files (*.exe);;All Files (*)',
        )
        self._path_row(
            parent_layout=v,
            key='acquisition.output_dir',
            label='Default dump output directory',
            placeholder='dumps/',
            browse_file=False,
        )
        return card

    def _section_project_outputs(self) -> QFrame:
        card = _card()
        card.setObjectName('SettingsPathPanel')
        v = QVBoxLayout(card)
        v.setContentsMargins(14, 10, 14, 10)
        v.setSpacing(7)
        v.addWidget(_section_header(
            '📁  Project Output Paths',
            'Folders for reports and runtime logs.'
        ))

        self._path_row(v, 'paths.reports_dir', 'Reports directory', 'reports/', browse_file=False)
        self._path_row(v, 'paths.logs_dir', 'Logs directory', 'logs/', browse_file=False)
        return card

    def _section_analysis_report(self) -> QFrame:
        card = _card()
        card.setObjectName('SettingsReportPanel')
        v = QVBoxLayout(card)
        v.setContentsMargins(14, 10, 14, 10)
        v.setSpacing(8)
        v.addWidget(_section_header(
            '📄  Analysis and Report Preferences',
            'GUI convenience options only. These do not alter ML classification logic.'
        ))

        checks = QHBoxLayout()
        checks.setSpacing(8)
        for cfg_key, text in [
            ('analysis.enable_logging', 'Enable detailed analysis logging'),
            ('analysis.auto_save', 'Auto-save completed scans to Dashboard history'),
        ]:
            cb = _checkbox(text)
            checks.addWidget(cb, 1)
            self._fields[cfg_key] = cb
        v.addLayout(checks)

        form = QGridLayout()
        form.setHorizontalSpacing(10)
        form.setVerticalSpacing(5)

        combo_lbl = _label('Default export format', 10, _MUTED, True)
        combo = _combo(['pdf', 'json', 'csv'])
        combo.setMaximumWidth(170)
        self._fields['report.default_format'] = combo
        form.addWidget(combo_lbl, 0, 0)
        form.addWidget(combo, 1, 0)

        header_lbl = _label('Report header text', 10, _MUTED, True)
        header = _line_edit('RAMDetect Forensic Analysis Report')
        self._fields['reports.header_text'] = header
        form.addWidget(header_lbl, 0, 1)
        form.addWidget(header, 1, 1)

        org_lbl = _label('Organisation / case owner', 10, _MUTED, True)
        org = _line_edit('UTHM PTM ICT Security Team')
        self._fields['reports.organisation'] = org
        form.addWidget(org_lbl, 0, 2)
        form.addWidget(org, 1, 2)
        form.setColumnStretch(0, 0)
        form.setColumnStretch(1, 1)
        form.setColumnStretch(2, 1)
        v.addLayout(form)
        return card

    def _path_row(
        self,
        parent_layout: QVBoxLayout,
        key: str,
        label: str,
        placeholder: str,
        browse_file: bool = False,
        file_filter: str = 'All Files (*)',
    ):
        lbl = _label(label, 10, _MUTED, True)
        parent_layout.addWidget(lbl)
        row = QHBoxLayout()
        row.setSpacing(7)
        line = _line_edit(placeholder)
        row.addWidget(line, 1)
        btn = _browse_btn()
        if browse_file:
            btn.clicked.connect(lambda: self._browse_file(line, file_filter))
        else:
            btn.clicked.connect(lambda: self._browse_dir(line))
        row.addWidget(btn)
        parent_layout.addLayout(row)
        self._fields[key] = line

    def _action_row(self) -> QWidget:
        w = QWidget()
        w.setObjectName('SettingsActionRow')
        w.setAttribute(Qt.WA_StyledBackground, True)
        set_role(w, "transparent")
        h = QHBoxLayout(w)
        h.setContentsMargins(0, 0, 0, 0)
        h.setSpacing(8)

        self._save_status = _label('', 10, _GREEN)
        h.addWidget(self._save_status, 1)

        reset_btn = QPushButton('↺  Reset FYP Settings')
        reset_btn.setMinimumHeight(34)
        reset_btn.setMaximumHeight(36)
        set_variant(reset_btn, 'secondary')
        reset_btn.clicked.connect(self._reset_defaults)
        h.addWidget(reset_btn)

        save_btn = QPushButton('💾  Save FYP Settings')
        save_btn.setMinimumHeight(34)
        save_btn.setMaximumHeight(36)
        set_variant(save_btn, 'primary')
        save_btn.clicked.connect(self._save)
        h.addWidget(save_btn)
        return w

    def _load_from_config(self):
        """Populate visible FYP widgets from Config without touching hidden ML settings."""
        for key, widget in self._fields.items():
            val = Config.get(key)
            if val is None:
                val = _FYP_DEFAULTS.get(key)
            if val is None:
                continue

            if isinstance(widget, QLineEdit):
                widget.setText(_portable_project_path_value(key, val))
            elif isinstance(widget, QCheckBox):
                widget.setChecked(bool(val))
            elif isinstance(widget, QComboBox):
                text_val = str(val)
                idx = widget.findText(text_val)
                if idx < 0:
                    for i in range(widget.count()):
                        if widget.itemText(i).lower() == text_val.lower():
                            idx = i
                            break
                if idx >= 0:
                    widget.setCurrentIndex(idx)

    def _save(self):
        """Save visible FYP settings only. Does not modify ML threshold or model logic."""
        for key, widget in self._fields.items():
            if isinstance(widget, QLineEdit):
                Config.set(key, _portable_project_path_value(key, widget.text().strip()))
            elif isinstance(widget, QCheckBox):
                Config.set(key, widget.isChecked())
            elif isinstance(widget, QComboBox):
                Config.set(key, widget.currentText())
        self._save_status.setText('✓  FYP settings saved')
        QTimer.singleShot(3000, lambda: self._save_status.setText(''))

    def _reset_defaults(self):
        if not _themed_confirm(
            self,
            'Reset FYP Settings',
            'Reset only the visible FYP workflow settings? This will not change ML threshold, model files, verdict logic, or feature mapping.',
            yes_text='Reset',
            no_text='Cancel',
        ):
            return

        for key, value in _FYP_DEFAULTS.items():
            if key in self._fields:
                Config.set(key, value)
        self._load_from_config()
        self._save_status.setText('↺  FYP settings reset')
        QTimer.singleShot(3000, lambda: self._save_status.setText(''))

    # ── Dialog helpers ───────────────────────────────────────────────────────

    def _browse_file(self, line_edit: QLineEdit, filter_str: str):
        path, _ = QFileDialog.getOpenFileName(self, 'Select File', '', filter_str)
        if path:
            line_edit.setText(path)

    def _browse_dir(self, line_edit: QLineEdit):
        path = QFileDialog.getExistingDirectory(self, 'Select Directory', str(_settings_project_root()))
        if path:
            line_edit.setText(path)

    # ── showEvent ─────────────────────────────────────────────────────────────

    def _on_show(self):
        self._load_from_config()
        self._save_status.setText('')
        self._refresh_theme_buttons()
        self._update_logout_panel_visibility()
