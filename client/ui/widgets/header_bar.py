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

from PyQt5.QtWidgets import (QWidget, QHBoxLayout, QVBoxLayout,
                              QLabel, QPushButton, QFrame)
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
    Displays the official RAMDetect image logo from:
        ramdetect/ui/resources/photo/ramdetect.png

    The source logo has a large black canvas around the white mark.  The widget
    auto-crops the dark padding before scaling, so the mark appears large and
    balanced in the header instead of looking like a tiny icon.
    """
    def __init__(self, size: int = 54, parent=None):
        super().__init__(parent)
        self._size = size
        self.setFixedSize(size, size)
        self.setAlignment(Qt.AlignCenter)
        self.setAttribute(Qt.WA_TranslucentBackground)
        self.setStyleSheet("background: transparent; border: none;")

        logo_path = _ui_resource_path("photo", "RAMDETECT-LOGO-CLEAN.png")
        pix = QPixmap(logo_path)
        if not pix.isNull():
            pix = self._crop_dark_padding(pix)
            scaled = pix.scaled(
                size, size,
                Qt.KeepAspectRatio,
                Qt.SmoothTransformation,
            )
            self.setPixmap(scaled)
            self.setToolTip(logo_path)
        else:
            self.setText("🛡")
            self.setFont(QFont("Segoe UI", max(18, size // 2)))
            self.setStyleSheet("color: #06b6d4; background: transparent; border: none;")
            self.setToolTip(f"Logo not found: {logo_path}")

    @staticmethod
    def _crop_dark_padding(pix: QPixmap) -> QPixmap:
        """Crop near-black padding from ramdetect.png while keeping a small margin."""
        img = pix.toImage().convertToFormat(QImage.Format_ARGB32)
        w, h = img.width(), img.height()
        min_x, min_y, max_x, max_y = w, h, -1, -1

        # Treat visible non-black pixels as logo content.  This works for the
        # uploaded white-on-black mark and also for future coloured versions.
        for y in range(h):
            for x in range(w):
                c = img.pixelColor(x, y)
                if c.alpha() > 10 and max(c.red(), c.green(), c.blue()) > 28:
                    if x < min_x: min_x = x
                    if y < min_y: min_y = y
                    if x > max_x: max_x = x
                    if y > max_y: max_y = y

        if max_x < min_x or max_y < min_y:
            return pix

        content_w = max_x - min_x + 1
        content_h = max_y - min_y + 1
        pad = max(6, int(max(content_w, content_h) * 0.08))
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
        self.setStyleSheet("background: transparent;")

    def paintEvent(self, _event):
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)

        # ── Outer shield body ─────────────────────────────────────────────────
        body_grad = QLinearGradient(0, 0, 40, 40)
        body_grad.setColorAt(0.0, QColor("#06b6d4"))   # cyan
        body_grad.setColorAt(0.6, QColor("#2563eb"))   # blue
        body_grad.setColorAt(1.0, QColor("#1e3a8a"))   # deep blue

        p.setBrush(QBrush(body_grad))
        p.setPen(Qt.NoPen)

        # Rounded-top shield: top-arch + tapered sides + bottom-point
        # Points: top-left-shoulder, top-right-shoulder, right-side,
        #         bottom-point, left-side
        shield = QPolygon([
            QPoint( 4,  8),   # top-left
            QPoint(36,  8),   # top-right
            QPoint(36, 22),   # right-mid
            QPoint(20, 38),   # bottom tip
            QPoint( 4, 22),   # left-mid
        ])
        p.drawPolygon(shield)

        # ── Top rounded cap ───────────────────────────────────────────────────
        cap_grad = QLinearGradient(4, 3, 36, 12)
        cap_grad.setColorAt(0.0, QColor("#22d3ee"))
        cap_grad.setColorAt(1.0, QColor("#0e7490"))
        p.setBrush(QBrush(cap_grad))
        p.drawEllipse(4, 3, 32, 14)

        # ── Inner highlight (semi-transparent white arc at top) ────────────────
        p.setBrush(Qt.NoBrush)
        glow = QPen(QColor(255, 255, 255, 60), 1.5)
        p.setPen(glow)
        p.drawArc(9, 6, 22, 10, 0, 180 * 16)

        # ── Tiny shield check-mark ────────────────────────────────────────────
        tick = QPen(QColor(255, 255, 255, 200), 2.0, Qt.SolidLine, Qt.RoundCap, Qt.RoundJoin)
        p.setPen(tick)
        p.drawLine(QPoint(14, 20), QPoint(18, 25))
        p.drawLine(QPoint(18, 25), QPoint(26, 15))

        p.end()


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
        self.setFixedHeight(72)
        self.setStyleSheet(
            "HeaderBar {"
            "  background: rgba(10,17,34,0.92);"
            "  border-bottom: 1px solid rgba(6,182,212,0.18);"
            "}"
        )

        row = QHBoxLayout(self)
        row.setContentsMargins(40, 0, 40, 0)
        row.setSpacing(14)
        row.setAlignment(Qt.AlignVCenter)

        # ── Branding ──────────────────────────────────────────────────────────
        row.addWidget(LogoIcon(54), alignment=Qt.AlignVCenter)

        brand = QVBoxLayout()
        brand.setSpacing(1)
        brand.setAlignment(Qt.AlignVCenter)

        title = QLabel("RAMDetect")
        title.setFont(QFont("Segoe UI", 16, QFont.Bold))
        title.setStyleSheet("color: #ffffff; background: transparent; letter-spacing: 0.5px;")

        subtitle_text = "Offline Local Mode" if self._offline_mode else "Memory Forensics Analysis Platform"
        subtitle_color = "#f59e0b" if self._offline_mode else "#64748b"
        subtitle_weight = QFont.DemiBold if self._offline_mode else QFont.Normal

        sub = QLabel(subtitle_text)
        sub.setFont(QFont("Segoe UI", 10, subtitle_weight))
        sub.setStyleSheet(f"color: {subtitle_color}; background: transparent;")
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
            ver.setFont(QFont("Segoe UI", 9, QFont.Bold))
            ver.setStyleSheet(
                "color: #06b6d4;"
                "background: rgba(6,182,212,0.10);"
                "border: 1px solid rgba(6,182,212,0.25);"
                "border-radius: 8px;"
                "padding: 1px 7px;"
            )
            ver.setAlignment(Qt.AlignVCenter)
            row.addWidget(ver, alignment=Qt.AlignVCenter)

        if self._offline_mode:
            offline_badge = QLabel("OFFLINE MODE")
            offline_badge.setFont(QFont("Segoe UI", 9, QFont.Bold))
            offline_badge.setStyleSheet(
                "color: #f8fafc;"
                "background: rgba(245,158,11,0.18);"
                "border: 1px solid rgba(245,158,11,0.45);"
                "border-radius: 8px;"
                "padding: 2px 10px;"
            )
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
            res_btn.setObjectName("iconBtn")
            res_btn.setFont(QFont("Segoe UI", 12, QFont.DemiBold))
            res_btn.setFixedHeight(38)
            res_btn.setStyleSheet(
                "QPushButton { background: rgba(6,182,212,0.12);"
                "  border: 1px solid rgba(6,182,212,0.35); border-radius: 8px;"
                "  color: #06b6d4; padding: 0 14px; }"
                "QPushButton:hover { background: rgba(6,182,212,0.22);"
                "  border-color: rgba(6,182,212,0.6); color: #22d3ee; }"
            )
            res_btn.clicked.connect(self.results_clicked)
            row.addWidget(res_btn, alignment=Qt.AlignVCenter)

        # Settings button
        gear = QPushButton()
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
        gear.setStyleSheet(
            "QPushButton { background: rgba(51,65,85,0.35);"
            "  border: 1px solid rgba(51,65,85,0.5); border-radius: 8px;"
            "  color: #ffffff; padding: 0px; }"
            "QPushButton:hover { background: rgba(6,182,212,0.12);"
            "  border-color: rgba(6,182,212,0.35); }"
        )
        gear.clicked.connect(self.settings_clicked)
        row.addWidget(gear, alignment=Qt.AlignVCenter)

        # Primary / dashboard button
        if show_dashboard:
            back = QPushButton(" Dashboard")
            back.setObjectName("iconBtn")
            back.setFont(QFont("Segoe UI", 12, QFont.DemiBold))
            back.setFixedHeight(38)
            back.setStyleSheet(
                "QPushButton { background: rgba(51,65,85,0.35);"
                "  border: 1px solid rgba(51,65,85,0.5); border-radius: 8px;"
                "  color: #94a3b8; padding: 0 14px; }"
                "QPushButton:hover { background: rgba(6,182,212,0.12); color: #06b6d4;"
                "  border-color: rgba(6,182,212,0.35); }"
            )
            home_svg = _ui_resource_path("photo", "home_24dp_E3E3E3_FILL1_wght700_GRAD200_opsz48.svg")
            if os.path.exists(home_svg):
                back.setIcon(QIcon(home_svg))
                back.setIconSize(QSize(18, 18))
            back.clicked.connect(self.dashboard_clicked)
            row.addWidget(back, alignment=Qt.AlignVCenter)
        elif show_action:
            act = QPushButton(action_label)
            act.setObjectName("primaryBtn")
            act.setFont(QFont("Segoe UI", 12, QFont.DemiBold))
            act.setFixedSize(108, 38)
            act.setStyleSheet(
                "QPushButton {"
                "  background: qlineargradient(x1:0,y1:0,x2:1,y2:0,"
                "    stop:0 #06b6d4, stop:1 #2563eb);"
                "  color: white;"
                "  border: none;"
                "  border-radius: 8px;"
                "  font-size: 13px;"
                "  font-weight: 600;"
                "}"
                "QPushButton:hover {"
                "  background: qlineargradient(x1:0,y1:0,x2:1,y2:0,"
                "    stop:0 #0891b2, stop:1 #1d4ed8);"
                "}"
            )
            act.clicked.connect(self.action_clicked)
            row.addWidget(act, alignment=Qt.AlignVCenter)