"""
HeaderBar
─────────
Branded top bar used on every page.

  LogoIcon     — loads official ramdetect.png logo from ui/resources/photo
  ShieldIcon   — legacy fallback custom-painted shield
  HeaderBar    — height-72 bar with branding, optional version badge,
                 settings gear, and either a "Dashboard" back-button or a
                 primary action button

Signals
  settings_clicked  — gear icon pressed
  action_clicked    — primary action button pressed
  dashboard_clicked — dashboard back-button pressed
"""

import os
import sys
from ui.style_helpers import set_role, set_tone, set_variant, set_state
from ui.theme import current_theme

from PyQt5.QtWidgets import (QWidget, QHBoxLayout, QVBoxLayout,
                              QLabel, QPushButton, QFrame, QApplication)
from PyQt5.QtCore    import Qt, pyqtSignal, QPoint, QSize
from PyQt5.QtGui     import (QFont, QLinearGradient, QColor,
                              QPainter, QPen, QBrush, QPolygon,
                              QPixmap, QImage, QIcon)


# ─────────────────────────────────────────────────────────────────────────────
# Resource helpers
# ─────────────────────────────────────────────────────────────────────────────

def _ui_resource_path(*parts: str) -> str:
    """Return an absolute path inside ramdetect/ui/resources, PyInstaller-safe."""
    base = getattr(sys, "_MEIPASS", None)
    if base:
        # PyInstaller layouts vary; try both bundled root/resources and package path.
        candidates = [
            os.path.join(base, "resources", *parts),
            os.path.join(base, "ui", "resources", *parts),
            os.path.join(base, "ramdetect", "ui", "resources", *parts),
        ]
        for candidate in candidates:
            if os.path.exists(candidate):
                return candidate

    ui_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(ui_dir, "resources", *parts)


class LogoIcon(QLabel):
    """
    Displays the RAMDetect logo in the header.

    Dark theme uses the existing RAMDetect logo and keeps styling in
    ramdetect/ui/resources/styles.qss.
    """
    def __init__(self, size: int = 54, parent=None):
        super().__init__(parent)
        self._size = size
        self.setObjectName("ramdetectLogoIcon")
        self.setFixedSize(size, size)
        self.setAlignment(Qt.AlignCenter)
        self.setAttribute(Qt.WA_TranslucentBackground)
        set_role(self, "transparent")

        self.apply_theme(current_theme())

    def apply_theme(self, theme: str = "dark") -> None:
        # Phase 1: choose the best available logo asset for the selected theme.
        # Light mode uses the blue/black logo when available; dark mode keeps
        # the existing white/clean RAMDetect logo identity.
        theme = (theme or current_theme() or "dark").strip().lower()
        if theme == "light":
            # Match AdminSidePanel ordering so the Dashboard header and admin
            # panel use the same blue RAMDetect asset in light mode.
            candidates = [
                _ui_resource_path("photo", "RAMDETECT-LOGO_blue.png"),
                _ui_resource_path("photo", "ramdetect_blue.jpg"),
                _ui_resource_path("photo", "ramdetect_black.png"),
                _ui_resource_path("photo", "RAMDETECT-LOGO-CLEAN.png"),
                _ui_resource_path("photo", "ramdetect.png"),
            ]
        else:
            candidates = [
                _ui_resource_path("photo", "RAMDETECT-LOGO-CLEAN.png"),
                _ui_resource_path("photo", "ramdetect.png"),
                _ui_resource_path("photo", "ramdetect_black.png"),
            ]

        logo_path = next((path for path in candidates if os.path.exists(path)), candidates[0])
        pix = QPixmap(logo_path)
        if not pix.isNull():
            pix = self._crop_padding_for_theme(pix, theme)
            scaled = pix.scaled(
                self._size, self._size,
                Qt.KeepAspectRatio,
                Qt.SmoothTransformation,
            )
            self.setPixmap(scaled)
            self.setText("")
            self.setToolTip(logo_path)
        else:
            self.setPixmap(QPixmap())
            self.setText("🛡")
            self.setFont(QFont("Segoe UI", max(18, self._size // 2)))
            set_tone(self, "#06b6d4")
            self.setToolTip(f"Logo not found: {logo_path}")

    @staticmethod
    def _crop_padding_for_theme(pix: QPixmap, theme: str) -> QPixmap:
        """Crop flat logo padding without modifying source image files."""
        img = pix.toImage().convertToFormat(QImage.Format_ARGB32)
        w, h = img.width(), img.height()
        if w <= 1 or h <= 1:
            return pix

        corners = [
            img.pixelColor(0, 0), img.pixelColor(w - 1, 0),
            img.pixelColor(0, h - 1), img.pixelColor(w - 1, h - 1),
        ]
        bg = sum((c.red() + c.green() + c.blue()) / 3 for c in corners) / len(corners)
        dark_bg = bg < 128
        remove_light_canvas = (str(theme or "").lower() == "light" and not dark_bg)

        min_x, min_y, max_x, max_y = w, h, -1, -1
        for y in range(h):
            for x in range(w):
                c = img.pixelColor(x, y)
                if c.alpha() <= 10:
                    continue
                bright = (c.red() + c.green() + c.blue()) / 3

                if remove_light_canvas and c.red() >= 238 and c.green() >= 238 and c.blue() >= 238:
                    c.setAlpha(0)
                    img.setPixelColor(x, y, c)
                    continue

                is_content = bright > 35 if dark_bg else bright < 235
                if is_content:
                    min_x = min(min_x, x)
                    min_y = min(min_y, y)
                    max_x = max(max_x, x)
                    max_y = max(max_y, y)

        if max_x < min_x or max_y < min_y:
            return QPixmap.fromImage(img)

        content_w = max_x - min_x + 1
        content_h = max_y - min_y + 1
        pad = max(4, int(max(content_w, content_h) * 0.06))
        min_x = max(0, min_x - pad)
        min_y = max(0, min_y - pad)
        max_x = min(w - 1, max_x + pad)
        max_y = min(h - 1, max_y + pad)
        return QPixmap.fromImage(img.copy(min_x, min_y, max_x - min_x + 1, max_y - min_y + 1))


# ─────────────────────────────────────────────────────────────────────────────
# Shield icon widget
# ─────────────────────────────────────────────────────────────────────────────

class ShieldIcon(QWidget):
    """
    Draws a rounded shield with a cyan→blue gradient body and a
    subtle inner-top highlight arc.  Fixed 40×40 px.
    """
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setFixedSize(40, 40)
        self.setAttribute(Qt.WA_TranslucentBackground)
        set_role(self, "transparent")

    def paintEvent(self, _event):
        # Legacy fallback widget kept for compatibility. The main header uses
        # image assets, so avoid custom QPainter drawing here to prevent
        # paintEngine warnings on some PyQt/Windows builds.
        return


# ─────────────────────────────────────────────────────────────────────────────
# Header bar
# ─────────────────────────────────────────────────────────────────────────────

_VERSION = "v1.0"


class HeaderBar(QWidget):
    """
    Fixed-height (72 px) top bar.

    Parameters
    ──────────
    action_label   text on the primary action button (default "New Scan")
    show_action    show the primary action button (default True)
    show_dashboard show a "⌂ Dashboard" back-button instead (default False)
                   overrides show_action
    show_version   show a small version pill (default True)
    offline_mode   show Offline Local Mode subtitle and badge (default False)
    """

    settings_clicked  = pyqtSignal()
    action_clicked    = pyqtSignal()
    dashboard_clicked = pyqtSignal()
    results_clicked   = pyqtSignal()

    def __init__(self,
                 action_label:   str  = "New Scan",
                 show_action:    bool = True,
                 show_dashboard: bool = False,
                 show_results:   bool = False,
                 show_version:   bool = True,
                 offline_mode:   bool = False,
                 parent=None):
        super().__init__(parent)
        self._offline_mode = bool(offline_mode)
        self.setObjectName("ramdetectHeaderBar")
        self.setAttribute(Qt.WA_StyledBackground, True)
        self.logo_icon = None
        self.title_label = None
        self.subtitle_label = None
        self.version_badge = None
        self.offline_badge = None
        self.results_button = None
        self.settings_button = None
        self.dashboard_button = None
        self.action_button = None
        self.setFixedHeight(72)

        row = QHBoxLayout(self)
        row.setContentsMargins(40, 0, 40, 0)
        row.setSpacing(14)
        row.setAlignment(Qt.AlignVCenter)

        # ── Branding ──────────────────────────────────────────────────────────
        self.logo_icon = LogoIcon(54)
        row.addWidget(self.logo_icon, alignment=Qt.AlignVCenter)

        brand = QVBoxLayout()
        brand.setSpacing(1)
        brand.setAlignment(Qt.AlignVCenter)

        title = QLabel("RAMDetect")
        self.title_label = title
        title.setFont(QFont("Segoe UI", 16, QFont.Bold))
        title.setObjectName("HeaderTitle")

        subtitle_text = "Offline Local Mode" if self._offline_mode else "Memory Forensics Analysis Platform"
        subtitle_weight = QFont.DemiBold if self._offline_mode else QFont.Normal

        sub = QLabel(subtitle_text)
        self.subtitle_label = sub
        sub.setObjectName("HeaderSubtitle")
        sub.setFont(QFont("Segoe UI", 10, subtitle_weight))
        set_state(sub, "offline" if self._offline_mode else "online")
        if self._offline_mode:
            sub.setToolTip(
                "RAMDetect is running without the PostgreSQL/PTM server. "
                "Only local analyst tools are available."
            )

        brand.addWidget(title)
        brand.addWidget(sub)
        row.addLayout(brand)

        # ── Version pill ──────────────────────────────────────────────────────
        if show_version:
            ver = QLabel(_VERSION)
            self.version_badge = ver
            ver.setFont(QFont("Segoe UI", 9, QFont.Bold))
            ver.setObjectName("VersionBadge")
            ver.setAlignment(Qt.AlignVCenter)
            row.addWidget(ver, alignment=Qt.AlignVCenter)

        if self._offline_mode:
            offline_badge = QLabel("OFFLINE MODE")
            self.offline_badge = offline_badge
            offline_badge.setFont(QFont("Segoe UI", 9, QFont.Bold))
            offline_badge.setObjectName("OfflineBadge")
            offline_badge.setAlignment(Qt.AlignVCenter)
            offline_badge.setToolTip(
                "Login was bypassed because the server is unavailable. "
                "Admin Management, central Activity Monitor, and PTM Repository are disabled."
            )
            row.addWidget(offline_badge, alignment=Qt.AlignVCenter)

        row.addStretch()

        # ── Right buttons ─────────────────────────────────────────────────────
        # ← Results back-button (shown on branch pages that lead from Results)
        if show_results:
            res_btn = QPushButton("← Results")
            self.results_button = res_btn
            res_btn.setObjectName("iconBtn")
            res_btn.setFont(QFont("Segoe UI", 12, QFont.DemiBold))
            res_btn.setFixedHeight(38)
            set_variant(res_btn, "navActive")
            res_btn.clicked.connect(self.results_clicked)
            row.addWidget(res_btn, alignment=Qt.AlignVCenter)

        # Settings button
        gear = QPushButton()
        self.settings_button = gear
        gear.setObjectName("iconBtn")
        gear.setFixedSize(38, 38)
        gear.setToolTip("Settings")
        settings_svg = _ui_resource_path("photo", "settings_24dp_FFFFFF_FILL1_wght700_GRAD200_opsz48.svg")
        if os.path.exists(settings_svg):
            gear.setIcon(QIcon(settings_svg))
            gear.setIconSize(QSize(18, 18))
        else:
            gear.setText("⚙")
            gear.setFont(QFont("Segoe UI", 15))
        set_variant(gear, "iconHeader")
        gear.clicked.connect(self.settings_clicked)
        row.addWidget(gear, alignment=Qt.AlignVCenter)

        # Primary / dashboard button
        if show_dashboard:
            back = QPushButton(" Dashboard")
            self.dashboard_button = back
            back.setObjectName("iconBtn")
            back.setFont(QFont("Segoe UI", 12, QFont.DemiBold))
            back.setFixedHeight(38)
            set_variant(back, "nav")
            home_svg = _ui_resource_path("photo", "home_24dp_E3E3E3_FILL1_wght700_GRAD200_opsz48.svg")
            if os.path.exists(home_svg):
                back.setIcon(QIcon(home_svg))
                back.setIconSize(QSize(18, 18))
            back.clicked.connect(self.dashboard_clicked)
            row.addWidget(back, alignment=Qt.AlignVCenter)
        elif show_action:
            act = QPushButton(action_label)
            self.action_button = act
            act.setObjectName("primaryBtn")
            act.setFont(QFont("Segoe UI", 12, QFont.DemiBold))
            act.setFixedSize(108, 38)
            set_variant(act, "primary")
            act.clicked.connect(self.action_clicked)
            row.addWidget(act, alignment=Qt.AlignVCenter)

    # ── Theme compatibility hook ─────────────────────────────────────────────

    def apply_theme(self, theme: str = "dark") -> None:
        """Re-apply header object names/properties after a theme change."""
        theme = (theme or current_theme() or "dark").strip().lower()
        self.setProperty("ramdetectTheme", theme)
        if theme == "light":
            self.setStyleSheet("""
                QWidget#ramdetectHeaderBar {
                    background: #f0f5ff;
                    border: none;
                }
                QLabel#HeaderTitle { color: #1e3a6e; background: transparent; border: none; }
                QLabel#HeaderSubtitle { color: #5d76a9; background: transparent; border: none; }
                QLabel#HeaderSubtitle[state="offline"] { color: #b7791f; }
                QLabel#VersionBadge {
                    color: #1a56db; background: #eef4ff; border: 1px solid #c8d8f5;
                    border-radius: 8px; padding: 1px 8px;
                }
                QLabel#OfflineBadge {
                    color: #b7791f; background: #fff7df; border: 1px solid #f8d37a;
                    border-radius: 8px; padding: 2px 10px;
                }
                QLabel#ramdetectLogoIcon { background: transparent; border: none; }
                QPushButton#iconBtn, QPushButton#primaryBtn {
                    background: #1a56db; color: #ffffff; border: 1px solid #1a56db;
                    border-radius: 9px; font-weight: 800;
                }
                QPushButton#iconBtn:hover, QPushButton#primaryBtn:hover {
                    background: #174bbf; border-color: #174bbf; color: #ffffff;
                }
                QPushButton#iconBtn:disabled, QPushButton#primaryBtn:disabled,
                QPushButton#iconBtn[variant="nav"]:disabled, QPushButton#iconBtn[variant="iconHeader"]:disabled {
                    background: #f8fbff;
                    color: #9aa8c3;
                    border: 1px solid #d9e6ff;
                }
            """)
        else:
            self.setStyleSheet("")
        if self.logo_icon is not None and hasattr(self.logo_icon, "apply_theme"):
            self.logo_icon.apply_theme(theme)
        if self.title_label is not None:
            self.title_label.setObjectName("HeaderTitle")
        if self.subtitle_label is not None:
            self.subtitle_label.setObjectName("HeaderSubtitle")
            set_state(self.subtitle_label, "offline" if self._offline_mode else "online")
        if self.version_badge is not None:
            self.version_badge.setObjectName("VersionBadge")
        if self.offline_badge is not None:
            self.offline_badge.setObjectName("OfflineBadge")
        set_variant(self.settings_button, "iconHeader")
        set_variant(self.dashboard_button, "nav")
        set_variant(self.results_button, "navActive")
        set_variant(self.action_button, "primary")
        try:
            self.style().unpolish(self)
            self.style().polish(self)
            self.update()
        except Exception:
            pass
