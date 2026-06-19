"""
admin_side_panel.py
-------------------
Professional RAMDetect admin side panel.

Phase 5:
- Dashboard
- Activity Monitor
- Admin Management
- Logout

Settings and New Scan remain in the original RAMDetect HeaderBar.
"""

from __future__ import annotations

import socket
from pathlib import Path

from PyQt5.QtCore import QSize, Qt, pyqtSignal
from PyQt5.QtGui import QFont, QIcon, QPixmap
from PyQt5.QtWidgets import QFrame, QHBoxLayout, QLabel, QPushButton, QSizePolicy, QVBoxLayout
from ui.style_helpers import set_role, set_tone, set_variant
from ui.theme import current_theme


def _resource_path(*parts: str) -> str:
    return str(Path(__file__).resolve().parents[1] / "resources" / Path(*parts))


def _is_light() -> bool:
    try:
        return str(current_theme()).strip().lower() == "light"
    except Exception:
        return False


class _NavButton(QPushButton):
    def __init__(self, text: str, key: str, icon_path: str | None = None, parent=None):
        super().__init__(text, parent)
        self.key = key
        self.setToolTip(text)
        self._active = False
        self.setCursor(Qt.PointingHandCursor)
        self.setMinimumHeight(32)
        self.setMaximumHeight(32)
        self.setFont(QFont("Segoe UI", 8, QFont.DemiBold))
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        if icon_path:
            self.setIcon(QIcon(icon_path))
            self.setIconSize(QSize(15, 15))
        self._apply_style()

    def set_active(self, active: bool) -> None:
        self._active = active
        self._apply_style()

    def _apply_style(self) -> None:
        set_variant(self, "sideNavActive" if self._active else "sideNav")


class AdminSidePanel(QFrame):
    dashboard_requested = pyqtSignal()
    activity_requested = pyqtSignal()
    admin_requested = pyqtSignal()
    logout_requested = pyqtSignal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("AdminSidePanel")
        self.setFixedWidth(198)
        self.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Expanding)

        self._buttons: dict[str, _NavButton] = {}
        self._logo_label: QLabel | None = None
        self._user_label: QLabel | None = None
        self._role_label: QLabel | None = None
        self._machine_label: QLabel | None = None
        self._build_ui()

    def _build_ui(self) -> None:
        root = QVBoxLayout(self)
        root.setContentsMargins(10, 16, 10, 14)
        root.setSpacing(10)

        brand = QFrame()
        set_role(brand, "transparent")
        row = QHBoxLayout(brand)
        row.setContentsMargins(0, 0, 0, 0)
        row.setSpacing(8)

        logo = QLabel()
        logo.setObjectName("AdminSideLogo")
        logo.setFixedSize(58, 58)
        logo.setAlignment(Qt.AlignCenter)
        self._logo_label = logo
        self._update_logo()

        text_box = QVBoxLayout()
        text_box.setContentsMargins(0, 0, 0, 0)
        text_box.setSpacing(0)
        title = QLabel("Admin Console")
        title.setObjectName("AdminConsoleTitle")
        title.setFont(QFont("Segoe UI", 10, QFont.Bold))
        set_tone(title, "#f8fafc")
        subtitle = QLabel("Activity Monitoring")
        subtitle.setObjectName("AdminConsoleSubtitle")
        subtitle.setFont(QFont("Segoe UI", 7))
        set_tone(subtitle, "#64748b")
        text_box.addWidget(title)
        text_box.addWidget(subtitle)

        row.addWidget(logo)
        row.addLayout(text_box, 1)
        root.addWidget(brand)

        user_card = QFrame()
        user_card.setObjectName("SignedInCard")
        u = QVBoxLayout(user_card)
        u.setContentsMargins(9, 8, 9, 8)
        u.setSpacing(1)
        small = QLabel("SIGNED IN")
        small.setFont(QFont("Segoe UI", 7, QFont.Bold))
        small.setProperty("role", "overline")
        self._user_label = QLabel("admin")
        self._user_label.setFont(QFont("Segoe UI", 9, QFont.Bold))
        set_tone(self._user_label, "#e2e8f0")
        self._role_label = QLabel("Admin")
        self._role_label.setFont(QFont("Segoe UI", 8))
        set_tone(self._role_label, "#06b6d4")
        self._machine_label = QLabel(self._machine_name())
        self._machine_label.setFont(QFont("Segoe UI", 8))
        set_tone(self._machine_label, "#64748b")
        u.addWidget(small)
        u.addWidget(self._user_label)
        u.addWidget(self._role_label)
        u.addWidget(self._machine_label)
        root.addWidget(user_card)

        root.addSpacing(4)
        section = QLabel("WORKSPACE")
        section.setFont(QFont("Segoe UI", 7, QFont.Bold))
        section.setProperty("role", "overline")
        root.addWidget(section)

        self._add_nav(root, "dashboard", "Dashboard", self.dashboard_requested,
                      _resource_path("photo", "home_24dp_E3E3E3_FILL1_wght700_GRAD200_opsz48.svg"))
        self._add_nav(root, "activity", "Activity Monitor", self.activity_requested,
                      _resource_path("photo", "pie_chart_24dp_E3E3E3_FILL1_wght700_GRAD200_opsz24.svg"))
        self._add_nav(root, "admin", "Admin Management", self.admin_requested,
                      _resource_path("photo", "person_edit_24dp_E3E3E3_FILL1_wght700_GRAD200_opsz24.svg"))

        root.addStretch(1)

        footer = QLabel("Monitoring enabled")
        footer.setObjectName("AdminSideFooter")
        footer.setAlignment(Qt.AlignCenter)
        footer.setFont(QFont("Segoe UI", 8))
        set_tone(footer, "#52627a")
        root.addWidget(footer)

        logout = QPushButton("⏻  Logout")
        logout.setObjectName("AdminSideLogout")
        logout.setCursor(Qt.PointingHandCursor)
        logout.setMinimumHeight(40)
        logout.setMaximumHeight(40)
        logout.setFont(QFont("Segoe UI", 9, QFont.DemiBold))
        set_variant(logout, "logout")
        logout.clicked.connect(self.logout_requested)
        root.addWidget(logout)
        self.set_active("dashboard")


    def _update_logo(self) -> None:
        """Load the correct admin-side logo for the active theme."""
        logo = getattr(self, "_logo_label", None)
        if logo is None:
            return
        photo_dir = Path(__file__).resolve().parents[1] / "resources" / "photo"
        if _is_light():
            candidates = (
                photo_dir / "RAMDETECT-LOGO_blue.png",
                photo_dir / "ramdetect_blue.jpg",
                photo_dir / "ramdetect.png",
            )
        else:
            # Match the main RAMDetect dark header asset.
            candidates = (
                photo_dir / "ramdetect.png",
                photo_dir / "RAMDETECT-LOGO.png",
                photo_dir / "RAMDETECT-LOGO_blue.png",
            )
        logo_path = next((p for p in candidates if p.exists()), None)
        if logo_path is None:
            logo.setPixmap(QPixmap())
            logo.setText("RD")
            set_tone(logo, "#06b6d4")
            return
        logo.setText("")
        pix = QPixmap(str(logo_path))
        pix = self._crop_logo_pixmap(pix)
        logo.setPixmap(pix.scaled(56, 56, Qt.KeepAspectRatio, Qt.SmoothTransformation))

    def showEvent(self, event) -> None:
        super().showEvent(event)
        self._update_logo()

    def apply_theme(self, theme: str | None = None) -> None:
        self._update_logo()

    def _add_nav(self, root: QVBoxLayout, key: str, text: str, signal, icon_path: str | None = None) -> None:
        btn = _NavButton(text, key, icon_path, self)
        btn.clicked.connect(signal)
        self._buttons[key] = btn
        root.addWidget(btn)

    def set_active(self, key: str) -> None:
        for name, btn in self._buttons.items():
            btn.set_active(name == key)

    def set_user(self, username: str, role: str, machine: str | None = None) -> None:
        if self._user_label:
            self._user_label.setText(username or "unknown")
        if self._role_label:
            self._role_label.setText(role or "unknown")
        if self._machine_label:
            machine = machine or self._machine_name()
            self._machine_label.setText(machine)
            self._machine_label.setToolTip(machine)

    @staticmethod
    def _machine_name() -> str:
        try:
            return socket.gethostname()
        except Exception:
            return "unknown"

    @staticmethod
    def _crop_logo_pixmap(pixmap: QPixmap) -> QPixmap:
        if pixmap.isNull():
            return pixmap
        img = pixmap.toImage()
        w, h = img.width(), img.height()
        min_x, min_y, max_x, max_y = w, h, -1, -1
        for y in range(h):
            for x in range(w):
                c = img.pixelColor(x, y)
                if c.alpha() > 10 and max(c.red(), c.green(), c.blue()) > 35:
                    min_x = min(min_x, x); min_y = min(min_y, y)
                    max_x = max(max_x, x); max_y = max(max_y, y)
        if max_x <= min_x or max_y <= min_y:
            return pixmap
        pad = 10
        return pixmap.copy(max(0, min_x-pad), max(0, min_y-pad),
                           min(w-1, max_x+pad) - max(0, min_x-pad) + 1,
                           min(h-1, max_y+pad) - max(0, min_y-pad) + 1)
