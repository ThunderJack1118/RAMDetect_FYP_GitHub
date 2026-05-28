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


def _resource_path(*parts: str) -> str:
    return str(Path(__file__).resolve().parents[1] / "resources" / Path(*parts))


class _NavButton(QPushButton):
    def __init__(self, text: str, key: str, icon_path: str | None = None, parent=None):
        super().__init__(text, parent)
        self.key = key
        self._active = False
        self.setCursor(Qt.PointingHandCursor)
        self.setMinimumHeight(34)
        self.setMaximumHeight(34)
        self.setFont(QFont("Segoe UI", 9, QFont.DemiBold))
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        if icon_path:
            self.setIcon(QIcon(icon_path))
            self.setIconSize(QSize(18, 18))
        self._apply_style()

    def set_active(self, active: bool) -> None:
        self._active = active
        self._apply_style()

    def _apply_style(self) -> None:
        if self._active:
            self.setStyleSheet("""
                QPushButton {
                    background: rgba(6, 182, 212, 0.12);
                    color: #e0faff;
                    border: 1px solid rgba(6, 182, 212, 0.40);
                    border-radius: 8px;
                    padding: 0 8px;
                    text-align: left;
                    font-size: 10px;
                    font-weight: 700;
                }
                QPushButton:hover { background: rgba(6, 182, 212, 0.18); }
            """)
        else:
            self.setStyleSheet("""
                QPushButton {
                    background: transparent;
                    color: #b6c2d5;
                    border: 1px solid transparent;
                    border-radius: 8px;
                    padding: 0 8px;
                    text-align: left;
                    font-size: 10px;
                    font-weight: 600;
                }
                QPushButton:hover {
                    background: rgba(30, 41, 59, 0.72);
                    border: 1px solid rgba(51, 65, 85, 0.75);
                    color: #f8fafc;
                }
            """)


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
        self._user_label: QLabel | None = None
        self._role_label: QLabel | None = None
        self._machine_label: QLabel | None = None
        self._build_ui()

    def _build_ui(self) -> None:
        self.setStyleSheet("""
            QFrame#AdminSidePanel {
                background: #0b1220;
                border-right: 1px solid rgba(51, 65, 85, 0.58);
            }
            QLabel { background: transparent; border: none; }
        """)
        root = QVBoxLayout(self)
        root.setContentsMargins(12, 16, 12, 14)
        root.setSpacing(10)

        brand = QFrame()
        brand.setStyleSheet("background: transparent; border: none;")
        row = QHBoxLayout(brand)
        row.setContentsMargins(0, 0, 0, 0)
        row.setSpacing(8)

        logo = QLabel()
        logo.setFixedSize(44, 44)
        logo.setAlignment(Qt.AlignCenter)
        logo_path = Path(__file__).resolve().parents[1] / "resources" / "photo" / "ramdetect.png"
        if logo_path.exists():
            pix = QPixmap(str(logo_path))
            pix = self._crop_logo_pixmap(pix)
            logo.setPixmap(pix.scaled(42, 42, Qt.KeepAspectRatio, Qt.SmoothTransformation))
        else:
            logo.setText("RD")
            logo.setStyleSheet("color: #06b6d4; font-weight: 800;")

        text_box = QVBoxLayout()
        text_box.setContentsMargins(0, 0, 0, 0)
        text_box.setSpacing(0)
        title = QLabel("Admin Console")
        title.setFont(QFont("Segoe UI", 10, QFont.Bold))
        title.setStyleSheet("color: #f8fafc;")
        subtitle = QLabel("Activity Monitoring")
        subtitle.setFont(QFont("Segoe UI", 7))
        subtitle.setStyleSheet("color: #64748b;")
        text_box.addWidget(title)
        text_box.addWidget(subtitle)

        row.addWidget(logo)
        row.addLayout(text_box, 1)
        root.addWidget(brand)

        user_card = QFrame()
        user_card.setObjectName("SignedInCard")
        user_card.setStyleSheet("""
            QFrame#SignedInCard {
                background: rgba(15, 23, 42, 0.72);
                border: 1px solid rgba(51, 65, 85, 0.68);
                border-radius: 10px;
            }
            QFrame#SignedInCard QLabel {
                background: transparent;
                border: none;
            }
        """)
        u = QVBoxLayout(user_card)
        u.setContentsMargins(9, 8, 9, 8)
        u.setSpacing(1)
        small = QLabel("SIGNED IN")
        small.setFont(QFont("Segoe UI", 7, QFont.Bold))
        small.setStyleSheet("color: #64748b; letter-spacing: 1.0px;")
        self._user_label = QLabel("admin")
        self._user_label.setFont(QFont("Segoe UI", 9, QFont.Bold))
        self._user_label.setStyleSheet("color: #e2e8f0;")
        self._role_label = QLabel("Admin")
        self._role_label.setFont(QFont("Segoe UI", 8))
        self._role_label.setStyleSheet("color: #06b6d4;")
        self._machine_label = QLabel(self._machine_name())
        self._machine_label.setFont(QFont("Segoe UI", 8))
        self._machine_label.setStyleSheet("color: #64748b;")
        u.addWidget(small)
        u.addWidget(self._user_label)
        u.addWidget(self._role_label)
        u.addWidget(self._machine_label)
        root.addWidget(user_card)

        root.addSpacing(4)
        section = QLabel("WORKSPACE")
        section.setFont(QFont("Segoe UI", 7, QFont.Bold))
        section.setStyleSheet("color: #64748b; letter-spacing: 1.1px;")
        root.addWidget(section)

        self._add_nav(root, "dashboard", "Dashboard", self.dashboard_requested,
                      _resource_path("photo", "home_24dp_E3E3E3_FILL1_wght700_GRAD200_opsz48.svg"))
        self._add_nav(root, "activity", "Activity Monitor", self.activity_requested,
                      _resource_path("photo", "pie_chart_24dp_E3E3E3_FILL1_wght700_GRAD200_opsz24.svg"))
        self._add_nav(root, "admin", "Admin Management", self.admin_requested,
                      _resource_path("photo", "person_edit_24dp_E3E3E3_FILL1_wght700_GRAD200_opsz24.svg"))

        root.addStretch(1)

        footer = QLabel("Monitoring enabled")
        footer.setAlignment(Qt.AlignCenter)
        footer.setFont(QFont("Segoe UI", 8))
        footer.setStyleSheet("color: #52627a;")
        root.addWidget(footer)

        logout = QPushButton("⏻  Logout")
        logout.setCursor(Qt.PointingHandCursor)
        logout.setMinimumHeight(34)
        logout.setMaximumHeight(34)
        logout.setFont(QFont("Segoe UI", 9, QFont.DemiBold))
        logout.setStyleSheet("""
            QPushButton {
                background: transparent;
                color: #fca5a5;
                border: 1px solid rgba(127, 29, 29, 0.72);
                border-radius: 8px;
                font-size: 10px;
                font-weight: 700;
            }
            QPushButton:hover {
                background: rgba(127, 29, 29, 0.22);
                border-color: #ef4444;
                color: #fecaca;
            }
        """)
        logout.clicked.connect(self.logout_requested)
        root.addWidget(logout)
        self.set_active("dashboard")

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
