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
    QFileDialog, QMessageBox, QDialog,
)
from PyQt5.QtCore import Qt, QTimer

from ui.pages.base_page import BasePage
from ui.bridge.config_bridge import Config

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
    f.setStyleSheet(f"""
        QFrame#settingsCard {{
            background: rgba(30,41,59,0.72);
            border: 1px solid rgba(51,65,85,0.70);
            border-radius: 14px;
        }}
    """)
    return f


def _soft_card(parent=None) -> QFrame:
    f = QFrame(parent)
    f.setObjectName('softCard')
    f.setFrameShape(QFrame.NoFrame)
    f.setStyleSheet(f"""
        QFrame#softCard {{
            background: rgba(15,23,42,0.42);
            border: 1px solid rgba(51,65,85,0.45);
            border-radius: 10px;
        }}
    """)
    return f


def _section_header(title: str, subtitle: str = '') -> QWidget:
    w = QWidget()
    w.setStyleSheet('background: transparent; border: none;')
    v = QVBoxLayout(w)
    v.setContentsMargins(0, 0, 0, 8)
    v.setSpacing(3)

    t = QLabel(title)
    t.setFontStyleSheet = None
    t.setStyleSheet(f"""
        color:{_WHITE};
        font-size:16px;
        font-weight:700;
        background:transparent;
        border:none;
    """)
    v.addWidget(t)

    if subtitle:
        s = QLabel(subtitle)
        s.setWordWrap(True)
        s.setStyleSheet(f"""
            color:{_MUTED};
            font-size:12px;
            background:transparent;
            border:none;
        """)
        v.addWidget(s)

    line = QFrame()
    line.setFixedHeight(1)
    line.setStyleSheet(f"background: rgba(51,65,85,0.65); border: none;")
    v.addWidget(line)
    return w


def _label(text: str, size: int = 12, color: str = _TEXT, bold: bool = False) -> QLabel:
    lbl = QLabel(text)
    lbl.setWordWrap(True)
    lbl.setStyleSheet(
        f"color:{color}; font-size:{size}px; "
        f"font-weight:{'700' if bold else '400'}; "
        "background:transparent; border:none;"
    )
    return lbl


def _line_edit(placeholder: str = '') -> QLineEdit:
    e = QLineEdit()
    e.setPlaceholderText(placeholder)
    e.setMinimumHeight(36)
    e.setStyleSheet(f"""
        QLineEdit {{
            background: rgba(15,23,42,0.72);
            border: 1px solid rgba(51,65,85,0.90);
            border-radius: 8px;
            padding: 8px 11px;
            color: {_TEXT};
            font-size: 12px;
        }}
        QLineEdit:focus {{ border-color: {_CYAN}; }}
    """)
    return e


def _combo(options: list[str]) -> QComboBox:
    c = QComboBox()
    c.addItems(options)
    c.setMinimumHeight(36)
    c.setStyleSheet(f"""
        QComboBox {{
            background: rgba(15,23,42,0.72);
            border: 1px solid rgba(51,65,85,0.90);
            border-radius: 8px;
            padding: 7px 11px;
            color: {_TEXT};
            font-size: 12px;
        }}
        QComboBox::drop-down {{ border:none; width:22px; }}
        QComboBox QAbstractItemView {{
            background:{_CARD};
            border:1px solid {_BORDER};
            color:{_TEXT};
            selection-background-color:{_CYAN};
        }}
    """)
    return c


def _checkbox(label: str) -> QCheckBox:
    cb = QCheckBox(label)
    cb.setStyleSheet(f"""
        QCheckBox {{ color:{_TEXT}; font-size:12px; spacing:9px; background:transparent; }}
        QCheckBox::indicator {{
            width:17px; height:17px;
            border:2px solid {_BORDER};
            border-radius:4px;
            background:#0f172a;
        }}
        QCheckBox::indicator:checked {{ background:{_CYAN}; border-color:{_CYAN}; }}
        QCheckBox::indicator:hover {{ border-color:{_CYAN}; }}
    """)
    return cb


def _browse_btn() -> QPushButton:
    b = QPushButton('Browse')
    b.setFixedSize(76, 36)
    b.setStyleSheet(f"""
        QPushButton {{
            background: rgba(51,65,85,0.72);
            color:{_TEXT};
            border:1px solid rgba(71,85,105,0.85);
            border-radius:8px;
            font-size:10px;
            font-weight:600;
        }}
        QPushButton:hover {{ background:rgba(6,182,212,0.18); border-color:{_CYAN}; color:{_WHITE}; }}
    """)
    return b


def _pill(text: str, color: str = _CYAN) -> QLabel:
    p = QLabel(text)
    p.setAlignment(Qt.AlignCenter)
    p.setStyleSheet(f"""
        color:{color};
        background: rgba(6,182,212,0.09);
        border:1px solid rgba(6,182,212,0.24);
        border-radius:10px;
        padding:4px 10px;
        font-size:11px;
        font-weight:700;
    """)
    return p


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
        self._build_body()

    # ── Layout ────────────────────────────────────────────────────────────────

    def _build_body(self):
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        scroll.setStyleSheet(f"QScrollArea {{ background:{_BG}; border:none; }}")

        container = QWidget()
        container.setStyleSheet(f"background:{_BG};")
        root = QVBoxLayout(container)
        root.setContentsMargins(36, 22, 36, 28)
        root.setSpacing(16)

        root.addWidget(self._page_intro())
        self._logout_panel = self._non_admin_logout_panel()
        root.addWidget(self._logout_panel)
        root.addWidget(self._section_architecture_summary())
        root.addWidget(self._section_dumpit())
        root.addWidget(self._section_project_outputs())
        root.addWidget(self._section_analysis_report())
        root.addWidget(self._action_row())
        root.addStretch(1)

        scroll.setWidget(container)

        bl = QVBoxLayout(self.body)
        bl.setContentsMargins(0, 0, 0, 0)
        bl.addWidget(scroll)

    def _page_intro(self) -> QFrame:
        card = _card()
        h = QHBoxLayout(card)
        h.setContentsMargins(18, 14, 18, 14)
        h.setSpacing(14)

        left = QVBoxLayout()
        left.setSpacing(4)
        title = _label('FYP System Settings', 18, _WHITE, True)
        subtitle = _label(
            'Only project-relevant settings are editable here. ML architecture, threshold, and verdict logic are locked to match the official RAMDetect design.',
            12,
            _MUTED,
        )
        left.addWidget(title)
        left.addWidget(subtitle)
        h.addLayout(left, 1)

        pills = QHBoxLayout()
        pills.setSpacing(8)
        pills.addWidget(_pill('Post-incident'))
        pills.addWidget(_pill('DumpIt'))
        pills.addWidget(_pill('ML-only'))
        pills.addWidget(_pill('RF threshold 0.5'))
        h.addLayout(pills)
        return card

    def _non_admin_logout_panel(self) -> QFrame:
        """
        Analyst/Viewer users do not see the Admin Console side panel.
        This panel gives them a clear way to log out and return to the
        RAMDetect login screen from Settings. Admin users already have the
        side-panel Logout button, so this panel is hidden for Admin accounts.
        """
        card = _card()
        card.setObjectName('nonAdminLogoutPanel')
        card.setStyleSheet(f"""
            QFrame#nonAdminLogoutPanel {{
                background: rgba(127,29,29,0.13);
                border: 1px solid rgba(248,113,113,0.36);
                border-radius: 14px;
            }}
            QFrame#nonAdminLogoutPanel QLabel {{
                background: transparent;
                border: none;
            }}
        """)
        h = QHBoxLayout(card)
        h.setContentsMargins(18, 13, 18, 13)
        h.setSpacing(12)

        left = QVBoxLayout()
        left.setSpacing(3)
        title = _label('Signed in as regular RAMDetect user', 14, _WHITE, True)
        self._logout_user_label = _label(
            'Use Log Out to return to the login screen or switch account.',
            12,
            _MUTED,
        )
        left.addWidget(title)
        left.addWidget(self._logout_user_label)
        h.addLayout(left, 1)

        logout_btn = QPushButton('⏻  Log Out')
        logout_btn.setCursor(Qt.PointingHandCursor)
        logout_btn.setMinimumHeight(40)
        logout_btn.setStyleSheet(f"""
            QPushButton {{
                background: rgba(127,29,29,0.35);
                color:#fecaca;
                border:1px solid rgba(248,113,113,0.70);
                border-radius:10px;
                padding:8px 18px;
                font-size:13px;
                font-weight:700;
            }}
            QPushButton:hover {{
                background: rgba(185,28,28,0.50);
                border-color:{_RED};
                color:{_WHITE};
            }}
        """)
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
        v = QVBoxLayout(card)
        v.setContentsMargins(18, 16, 18, 16)
        v.setSpacing(13)
        v.addWidget(_section_header(
            '🛡️  RAMDetect Architecture Lock',
            'These values are displayed for transparency only and cannot be changed from Settings.'
        ))

        grid = QGridLayout()
        grid.setHorizontalSpacing(12)
        grid.setVerticalSpacing(12)

        items = [
            ('System Scope', 'Post-incident RAM forensics, not live endpoint detection.', _BLUE),
            ('Acquisition', 'DumpIt-based RAM acquisition and existing dump upload.', _CYAN),
            ('Parser Pipeline', 'Custom RAMDetect parser pipeline for forensic artifact extraction.', _CYAN),
            ('Final Decision', 'ML-only verdict. No veto rules, no clean dampeners, no deterministic overrides.', _GREEN),
            ('RF Threshold', 'Fixed at 0.5 for Clean/Suspicious classification.', _YELLOW),
            ('Feature Fusion', '54 canonical features + Autoencoder MSE = 55 fused RF input.', _GREEN),
            ('ML Decision Support', '28/55 features currently supported in the ML decision path.', _CYAN),
            ('CIC Export Coverage', '36/55 = 65.45% semantic/export coverage; CSV schema compatibility = 100.00%.', _CYAN),
            ('Dataset', 'CIC-MalMem2022 is the main ML dataset.', _BLUE),
        ]

        for i, (title, desc, accent) in enumerate(items):
            grid.addWidget(self._readonly_metric(title, desc, accent), i // 3, i % 3)

        v.addLayout(grid)
        note = _label(
            'Note: Hybrid Score means the final RF-AE suspicion score. A clean result below 50% remains CLEAN because the fixed Random Forest threshold is 0.5.',
            12,
            _MUTED,
        )
        v.addWidget(note)
        return card

    def _readonly_metric(self, title: str, desc: str, accent: str) -> QFrame:
        box = _soft_card()
        box.setMinimumHeight(82)
        v = QVBoxLayout(box)
        v.setContentsMargins(12, 10, 12, 10)
        v.setSpacing(4)
        t = _label(title, 12, accent, True)
        d = _label(desc, 11, _TEXT)
        v.addWidget(t)
        v.addWidget(d)
        v.addStretch(1)
        return box

    # ── Editable FYP sections ────────────────────────────────────────────────

    def _section_dumpit(self) -> QFrame:
        card = _card()
        v = QVBoxLayout(card)
        v.setContentsMargins(18, 16, 18, 16)
        v.setSpacing(10)
        v.addWidget(_section_header(
            '🔧  DumpIt Acquisition',
            'Configure the acquisition tool path and the default location for acquired RAM dumps.'
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
        v = QVBoxLayout(card)
        v.setContentsMargins(18, 16, 18, 16)
        v.setSpacing(10)
        v.addWidget(_section_header(
            '📁  Project Output Paths',
            'These paths control where RAMDetect stores generated reports and runtime logs.'
        ))

        self._path_row(v, 'paths.reports_dir', 'Reports directory', 'reports/', browse_file=False)
        self._path_row(v, 'paths.logs_dir', 'Logs directory', 'logs/', browse_file=False)
        return card

    def _section_analysis_report(self) -> QFrame:
        card = _card()
        v = QVBoxLayout(card)
        v.setContentsMargins(18, 16, 18, 16)
        v.setSpacing(13)
        v.addWidget(_section_header(
            '📄  Analysis and Report Preferences',
            'Convenience options for the GUI workflow. These do not alter ML classification logic.'
        ))

        checks = QVBoxLayout()
        checks.setSpacing(8)
        for cfg_key, text in [
            ('analysis.enable_logging', 'Enable detailed analysis logging'),
            ('analysis.auto_save', 'Auto-save completed scans to Dashboard history'),
        ]:
            cb = _checkbox(text)
            checks.addWidget(cb)
            self._fields[cfg_key] = cb
        v.addLayout(checks)

        v.addWidget(_label('Default export format', 11, _MUTED, True))
        combo = _combo(['pdf', 'json', 'csv'])
        v.addWidget(combo)
        self._fields['report.default_format'] = combo

        v.addWidget(_label('Report header text', 11, _MUTED, True))
        header = _line_edit('RAMDetect Forensic Analysis Report')
        v.addWidget(header)
        self._fields['reports.header_text'] = header

        v.addWidget(_label('Organisation / case owner', 11, _MUTED, True))
        org = _line_edit('UTHM PTM ICT Security Team')
        v.addWidget(org)
        self._fields['reports.organisation'] = org

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
        parent_layout.addWidget(_label(label, 11, _MUTED, True))
        row = QHBoxLayout()
        row.setSpacing(8)
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

    # ── Actions ──────────────────────────────────────────────────────────────

    def _action_row(self) -> QWidget:
        w = QWidget()
        w.setStyleSheet('background: transparent; border: none;')
        h = QHBoxLayout(w)
        h.setContentsMargins(0, 2, 0, 0)
        h.setSpacing(10)
        h.addStretch(1)

        reset_btn = QPushButton('↺  Reset FYP Settings')
        reset_btn.setStyleSheet(f"""
            QPushButton {{
                background: rgba(30,41,59,0.70);
                color:{_MUTED};
                border:1px solid {_BORDER};
                border-radius:8px;
                padding:10px 18px;
                font-size:13px;
                font-weight:600;
            }}
            QPushButton:hover {{ background:{_BORDER}; color:{_TEXT}; }}
        """)
        reset_btn.clicked.connect(self._reset_defaults)
        h.addWidget(reset_btn)

        save_btn = QPushButton('💾  Save FYP Settings')
        save_btn.setStyleSheet(f"""
            QPushButton {{
                background:qlineargradient(x1:0,y1:0,x2:1,y2:0,stop:0 {_CYAN},stop:1 #2563eb);
                color:#fff;
                border:none;
                border-radius:8px;
                padding:10px 22px;
                font-weight:700;
                font-size:13px;
            }}
            QPushButton:hover {{ background:#0891b2; }}
        """)
        save_btn.clicked.connect(self._save)
        h.addWidget(save_btn)

        self._save_status = _label('', 11, _GREEN)
        h.addWidget(self._save_status)
        return w

    # ── Config sync ───────────────────────────────────────────────────────────

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
        self._update_logout_panel_visibility()
