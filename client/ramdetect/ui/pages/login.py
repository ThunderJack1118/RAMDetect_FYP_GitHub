"""
login.py
--------
RAMDetect Staff Access Login page.

This version restores the compact single-card panel style from login_old.py,
while keeping the newer login UX features:
- input format validation
- username/password tooltips
- compact single pop-out error message with timeout
- field-level error highlight without duplicate inline alerts
- reset/reset_form compatibility
- login_successful(current_user) signal contract

No database, ML, parser, FeatureMapper, Random Forest, Autoencoder, or verdict
logic is changed here.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path

from PyQt5.QtCore import QEasingCurve, QPropertyAnimation, Qt, QTimer, pyqtSignal
from PyQt5.QtGui import QColor, QFont, QPixmap
from PyQt5.QtWidgets import (
    QFrame,
    QGraphicsOpacityEffect,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QSizePolicy,
    QVBoxLayout,
    QWidget,
)

logger = logging.getLogger(__name__)

LOGIN_REQUIREMENTS_FALLBACK = (
    "Username: 3–32 characters; letters, numbers, underscore (_), dot (.), or hyphen (-) only.\n"
    "Password: 6–128 characters."
)


def _ui_base_dir() -> Path:
    """Return ramdetect/ui directory."""
    return Path(__file__).resolve().parent.parent


def _logo_path() -> Path:
    return _ui_base_dir() / "resources" / "photo" / "ramdetect.png"


def _crop_logo_pixmap(pixmap: QPixmap) -> QPixmap:
    """Crop dark canvas around RAMDetect logo before scaling."""
    if pixmap.isNull():
        return pixmap

    img = pixmap.toImage()
    w, h = img.width(), img.height()
    min_x, min_y, max_x, max_y = w, h, -1, -1

    for y in range(h):
        for x in range(w):
            c: QColor = img.pixelColor(x, y)
            if c.alpha() > 10 and max(c.red(), c.green(), c.blue()) > 42:
                min_x = min(min_x, x)
                min_y = min(min_y, y)
                max_x = max(max_x, x)
                max_y = max(max_y, y)

    if max_x <= min_x or max_y <= min_y:
        return pixmap

    pad = 18
    min_x = max(0, min_x - pad)
    min_y = max(0, min_y - pad)
    max_x = min(w - 1, max_x + pad)
    max_y = min(h - 1, max_y + pad)
    return pixmap.copy(min_x, min_y, max_x - min_x + 1, max_y - min_y + 1)


def _validate_login_input(username: str, password: str) -> tuple[bool, str]:
    """UI-side validation before AuthBridge/AuthService is called."""
    try:
        from ramdetect.case_management.auth_service import validate_login_inputs
        ok, msg = validate_login_inputs(username, password)
        if ok:
            return True, ""
        return False, msg or LOGIN_REQUIREMENTS_FALLBACK
    except Exception:
        if not username:
            return False, "Username is required."
        if "\x00" in username or not re.fullmatch(r"[A-Za-z0-9_.-]{3,32}", username):
            return False, LOGIN_REQUIREMENTS_FALLBACK
        if not password or "\x00" in password or len(password) < 6 or len(password) > 128:
            return False, LOGIN_REQUIREMENTS_FALLBACK
        return True, ""


def _toast_parts(message: str) -> tuple[str, str]:
    """Return a compact toast title/body without repeating the full rules."""
    msg = (message or "Login failed. Please try again.").strip()
    lower = msg.lower()

    if "username is required" in lower:
        return "Check username", "Username is required."
    if "password" in lower and ("6" in msg or "128" in msg or "required" in lower):
        return "Check password", "Password must be 6–128 characters."
    if "username:" in msg or "3–32" in msg:
        return "Check username", "Use 3–32 characters: letters, numbers, _, . or -."
    if "invalid" in lower or "failed" in lower:
        return "Login failed", "Invalid username or password. Please try again."

    first = msg.splitlines()[0].strip() if msg else "Login failed. Please try again."
    return "Login failed", first[:130]


def _error_target(message: str) -> str:
    """Best-effort target field for visual highlighting."""
    msg = (message or "").lower()
    if "password" in msg and "username" not in msg:
        return "password"
    if "username" in msg and "password" not in msg:
        return "username"
    return "both"


class _LoginToast(QFrame):
    """Small theme-matched pop-out error that fades automatically."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("LoginToast")
        self.setAttribute(Qt.WA_StyledBackground, True)
        self.setWindowFlags(Qt.Widget | Qt.FramelessWindowHint)
        self.setStyleSheet("""
            QFrame#LoginToast {
                background: rgba(17, 24, 39, 0.98);
                border: 1px solid rgba(239, 68, 68, 0.68);
                border-radius: 10px;
            }
            QLabel#ToastIcon {
                color: #fecaca;
                font-size: 15px;
                font-weight: 900;
                background: transparent;
                border: none;
            }
            QLabel#ToastTitle {
                color: #fecaca;
                font-size: 11px;
                font-weight: 800;
                background: transparent;
                border: none;
            }
            QLabel#ToastBody {
                color: #cbd5e1;
                font-size: 9px;
                background: transparent;
                border: none;
            }
        """)

        row = QHBoxLayout(self)
        row.setContentsMargins(12, 9, 12, 9)
        row.setSpacing(9)

        icon = QLabel("!")
        icon.setObjectName("ToastIcon")
        icon.setFixedSize(24, 24)
        icon.setAlignment(Qt.AlignCenter)
        icon.setStyleSheet(
            "background: rgba(127, 29, 29, 0.35);"
            "border: 1px solid rgba(239, 68, 68, 0.55);"
            "border-radius: 12px; color: #fecaca; font-weight: 900;"
        )

        text_box = QVBoxLayout()
        text_box.setContentsMargins(0, 0, 0, 0)
        text_box.setSpacing(1)

        self._title = QLabel("Login failed")
        self._title.setObjectName("ToastTitle")
        self._body = QLabel("")
        self._body.setObjectName("ToastBody")
        self._body.setWordWrap(True)

        text_box.addWidget(self._title)
        text_box.addWidget(self._body)

        row.addWidget(icon, alignment=Qt.AlignTop)
        row.addLayout(text_box, 1)

        self._opacity = QGraphicsOpacityEffect(self)
        self.setGraphicsEffect(self._opacity)

        self._fade = QPropertyAnimation(self._opacity, b"opacity", self)
        self._fade.setDuration(500)
        self._fade.setEasingCurve(QEasingCurve.InOutQuad)
        self._fade.finished.connect(self.hide)

        self._hide_timer = QTimer(self)
        self._hide_timer.setSingleShot(True)
        self._hide_timer.timeout.connect(self._start_fade)
        self.hide()

    def show_message(self, title: str, message: str, duration_ms: int = 3200) -> None:
        # A single toast is reused. Repeated login errors update this toast
        # instead of creating another large notification on screen.
        self._fade.stop()
        self._hide_timer.stop()
        self._opacity.setOpacity(1.0)
        self._title.setText(title or "Login failed")
        self._body.setText(message or "Please try again.")

        parent = self.parentWidget()
        card = getattr(parent, "_login_card", None) if parent is not None else None

        # Align the toast width with the login card. This prevents the toast
        # from being centered against the whole page while the form card is
        # centered separately, which caused the visible horizontal offset.
        if card is not None and card.width() > 0:
            width = card.width()
        else:
            width = 390
            if parent is not None:
                width = min(430, max(340, parent.width() - 120))
        self.setFixedWidth(width)
        self.adjustSize()
        self._reposition()
        self.show()
        self.raise_()
        self._hide_timer.start(duration_ms)

    def _reposition(self) -> None:
        parent = self.parentWidget()
        if parent is None:
            return

        card = getattr(parent, "_login_card", None)
        if card is not None:
            # Use the card's exact left edge because show_message() sets the
            # toast width to the card width. This fixes the previous +12 px
            # offset that made the toast look shifted to the right.
            x = card.x()
            y = card.y() - self.height() - 12
            if y < 18:
                y = 18
        else:
            x = max(16, (parent.width() - self.width()) // 2)
            y = 24
        self.move(x, y)

    def _start_fade(self) -> None:
        if not self.isVisible():
            return
        self._fade.stop()
        self._fade.setStartValue(1.0)
        self._fade.setEndValue(0.0)
        self._fade.start()

    def hide_now(self) -> None:
        self._hide_timer.stop()
        self._fade.stop()
        self.hide()


class LoginPage(QWidget):
    """Compact RAMDetect staff login page."""

    login_successful = pyqtSignal(object)

    def __init__(self, parent=None):
        super().__init__(parent)
        self._auth = None
        self._toast: _LoginToast | None = None
        self._build_ui()

    # ------------------------------------------------------------------
    def set_auth_bridge(self, auth_bridge) -> None:
        self._auth = auth_bridge

    # ------------------------------------------------------------------
    def _build_ui(self) -> None:
        self.setObjectName("LoginPage")
        self.setStyleSheet("""
            QWidget#LoginPage {
                background: #0f172a;
                font-family: 'Segoe UI';
            }
            QLabel {
                background: transparent;
                border: none;
            }
            QLineEdit#LoginField {
                background: #111827;
                color: #e5e7eb;
                border: 1px solid #334155;
                border-radius: 8px;
                padding: 0 12px;
                font-size: 12px;
                selection-background-color: #2563eb;
            }
            QLineEdit#LoginField:hover {
                border: 1px solid #475569;
            }
            QLineEdit#LoginField:focus {
                border: 1px solid #22d3ee;
                background: #172133;
            }
            QLineEdit#LoginField[error="true"] {
                border: 1px solid #ef4444;
                background: rgba(127, 29, 29, 0.16);
            }
            QLineEdit#LoginField[error="true"]:focus {
                border: 1px solid #f87171;
                background: rgba(127, 29, 29, 0.18);
            }
        """)

        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setAlignment(Qt.AlignCenter)

        # Restored compact old-login panel style.
        card = QFrame()
        self._login_card = card
        card.setObjectName("LoginCard")
        card.setFixedWidth(430)
        card.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Minimum)
        card.setStyleSheet("""
            QFrame#LoginCard {
                background: #1b2232;
                border: 1px solid #33415f;
                border-radius: 16px;
            }
        """)

        card_layout = QVBoxLayout(card)
        card_layout.setContentsMargins(30, 26, 30, 24)
        card_layout.setSpacing(7)

        # ── Logo ──────────────────────────────────────────────────────
        logo = QLabel()
        logo.setAlignment(Qt.AlignCenter)
        logo.setStyleSheet("background: transparent; border: none;")
        if _logo_path().exists():
            pixmap = _crop_logo_pixmap(QPixmap(str(_logo_path())))
            logo.setPixmap(pixmap.scaled(58, 58, Qt.KeepAspectRatio, Qt.SmoothTransformation))
        else:
            logo.setText("RD")
            logo.setStyleSheet("color: #e2e8f0; font-size: 18px; font-weight: 700; background: transparent; border: none;")
        card_layout.addWidget(logo)
        card_layout.addSpacing(3)

        # ── Branding ─────────────────────────────────────────────────
        title = QLabel("RAMDetect")
        title.setAlignment(Qt.AlignCenter)
        title.setFont(QFont("Segoe UI", 29, QFont.Bold))
        title.setStyleSheet("""
            color: #f8fafc;
            letter-spacing: 0.3px;
            background: transparent;
            border: none;
        """)
        card_layout.addWidget(title)

        subtitle = QLabel("Staff Access Login")
        subtitle.setAlignment(Qt.AlignCenter)
        subtitle.setFont(QFont("Segoe UI", 12, QFont.DemiBold))
        subtitle.setStyleSheet("""
            color: #93b4f7;
            background: transparent;
            border: none;
        """)
        card_layout.addWidget(subtitle)

        # Old-style subtle divider.
        divider = QFrame()
        divider.setFixedHeight(1)
        divider.setStyleSheet("background: #2b3652; border: none;")
        card_layout.addSpacing(10)
        card_layout.addWidget(divider)
        card_layout.addSpacing(12)

        # ── Username ─────────────────────────────────────────────────
        lbl_user = QLabel("Username")
        lbl_user.setStyleSheet("""
            color: #dbeafe;
            font-size: 11px;
            font-weight: 600;
            background: transparent;
            border: none;
        """)
        card_layout.addWidget(lbl_user)

        self._username = QLineEdit()
        self._username.setObjectName("LoginField")
        self._username.setPlaceholderText("Enter username")
        self._username.setMaxLength(32)
        self._username.setMinimumHeight(34)
        self._username.setMaximumHeight(34)
        self._username.setToolTip(
            "Username: 3–32 characters; letters, numbers, underscore (_), dot (.), or hyphen (-) only."
        )
        self._username.returnPressed.connect(self._on_login)
        self._username.textChanged.connect(self._clear_error_visuals)
        card_layout.addWidget(self._username)

        # Smaller username-password gap; larger gap before Login remains below.
        card_layout.addSpacing(6)

        # ── Password ─────────────────────────────────────────────────
        lbl_pass = QLabel("Password")
        lbl_pass.setStyleSheet("""
            color: #dbeafe;
            font-size: 11px;
            font-weight: 600;
            background: transparent;
            border: none;
        """)
        card_layout.addWidget(lbl_pass)

        self._password = QLineEdit()
        self._password.setObjectName("LoginField")
        self._password.setEchoMode(QLineEdit.Password)
        self._password.setPlaceholderText("Enter password")
        self._password.setMaxLength(128)
        self._password.setMinimumHeight(34)
        self._password.setMaximumHeight(34)
        self._password.setToolTip("Password: 6–128 characters.")
        self._password.returnPressed.connect(self._on_login)
        self._password.textChanged.connect(self._clear_error_visuals)
        card_layout.addWidget(self._password)

        card_layout.addSpacing(16)

        # Kept for compatibility with earlier integration code, but not shown.
        # Errors now use one compact toast + field highlight to avoid duplicate alerts.
        self._error_label = QLabel("")
        self._error_label.hide()

        # Login button.
        self._btn_login = QPushButton("Log In")
        self._btn_login.setObjectName("LoginPrimaryButton")
        self._btn_login.setCursor(Qt.PointingHandCursor)
        self._btn_login.setMinimumHeight(36)
        self._btn_login.setMaximumHeight(36)
        self._btn_login.setFont(QFont("Segoe UI", 12, QFont.DemiBold))
        self._btn_login.clicked.connect(self._on_login)
        self._btn_login.setStyleSheet("""
            QPushButton#LoginPrimaryButton {
                background: #3b82f6;
                color: #ffffff;
                border: none;
                border-radius: 8px;
                font-size: 12px;
                font-weight: 600;
            }
            QPushButton#LoginPrimaryButton:hover {
                background: #2563eb;
            }
            QPushButton#LoginPrimaryButton:pressed {
                background: #1d4ed8;
            }
            QPushButton#LoginPrimaryButton:disabled {
                background: #1e3a8a;
                color: #94a3b8;
            }
        """)
        card_layout.addWidget(self._btn_login)

        hint = QLabel("Default: admin / admin123")
        hint.setAlignment(Qt.AlignCenter)
        hint.setStyleSheet("""
            color: #64748b;
            font-size: 9px;
            background: transparent;
            border: none;
        """)
        card_layout.addSpacing(7)
        card_layout.addWidget(hint)

        root.addWidget(card)

        self._toast = _LoginToast(self)
        self._username.setFocus()

    # ------------------------------------------------------------------
    def resizeEvent(self, event) -> None:
        super().resizeEvent(event)
        toast = getattr(self, "_toast", None)
        if toast is not None and toast.isVisible():
            toast._reposition()

    # ------------------------------------------------------------------
    def _on_login(self) -> None:
        username = self._username.text().strip()
        password = self._password.text()

        self._error_label.hide()
        self._clear_field_errors()

        ok, validation_message = _validate_login_input(username, password)
        if not ok:
            self._show_error(validation_message)
            return

        if self._auth is None:
            self._show_error("Auth bridge not configured. Please check setup.")
            return

        self._btn_login.setEnabled(False)
        self._btn_login.setText("Logging in…")

        try:
            success, message = self._auth.login(username, password)
        except Exception as exc:
            logger.exception("Login failed due to unexpected error")
            self._show_error(f"Login error: {exc}")
            return

        if success:
            logger.info("Login page: success for %r", username)
            self._password.clear()
            self._btn_login.setEnabled(True)
            self._btn_login.setText("Log In")
            self.login_successful.emit(self._auth.current_user)
            return

        self._show_error(message or "Login failed. Please try again.")

    # ------------------------------------------------------------------
    def _show_error(self, text: str) -> None:
        title, body = _toast_parts(text)
        target = _error_target(text)

        self._btn_login.setEnabled(True)
        self._btn_login.setText("Log In")

        # Clear the password before applying the red field highlight because
        # textChanged() clears old highlights while the user starts typing again.
        self._password.clear()
        self._mark_field_error(target)
        self._password.setFocus()

        toast = getattr(self, "_toast", None)
        if toast is not None:
            toast.show_message(title, body)

    # ------------------------------------------------------------------
    def _refresh_field_style(self, widget: QLineEdit) -> None:
        widget.style().unpolish(widget)
        widget.style().polish(widget)
        widget.update()

    # ------------------------------------------------------------------
    def _set_field_error(self, widget: QLineEdit, enabled: bool) -> None:
        widget.setProperty("error", enabled)
        self._refresh_field_style(widget)

    # ------------------------------------------------------------------
    def _mark_field_error(self, target: str) -> None:
        self._set_field_error(self._username, target in {"username", "both"})
        self._set_field_error(self._password, target in {"password", "both"})

    # ------------------------------------------------------------------
    def _clear_field_errors(self) -> None:
        self._set_field_error(self._username, False)
        self._set_field_error(self._password, False)

    # ------------------------------------------------------------------
    def _clear_error_visuals(self) -> None:
        self._error_label.hide()
        self._clear_field_errors()

    # ------------------------------------------------------------------
    def reset(self) -> None:
        """Clear the form when returning to login."""
        self._username.clear()
        self._password.clear()
        self._error_label.hide()
        self._clear_field_errors()
        toast = getattr(self, "_toast", None)
        if toast is not None:
            toast.hide_now()
        self._btn_login.setEnabled(True)
        self._btn_login.setText("Log In")
        self._username.setFocus()

    # ------------------------------------------------------------------
    def reset_form(self) -> None:
        """Compatibility alias used by integration code."""
        self.reset()
