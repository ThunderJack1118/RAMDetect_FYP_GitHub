"""
admin_management.py
-------------------
RAMDetect Phase 5 Admin Management page.

Tabs:
- User List: create users, enable/disable accounts, reset passwords.
- PC / Workstation List: view auto-registered PCs, trust/block PCs, add notes.

This is an admin UI only. It does not touch ML, parsers, FeatureMapper,
Random Forest, Autoencoder, threshold, or verdict logic.
"""

from __future__ import annotations

import re

from PyQt5.QtCore import Qt
from PyQt5.QtGui import QColor, QFont, QPen
from PyQt5.QtWidgets import (
    QCheckBox,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QStyledItemDelegate,
    QStyleOptionViewItem,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)


USERNAME_RULE_TEXT = "Username: 3–32 characters; letters, numbers, underscore (_), dot (.), or hyphen (-) only."
PASSWORD_RULE_TEXT = "Password: 6–128 characters."
CREATE_USER_RULE_TEXT = USERNAME_RULE_TEXT + "\n" + PASSWORD_RULE_TEXT
_USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{3,32}$")


def _style_dialog_buttons(buttons: QDialogButtonBox, ok_text: str = "OK") -> None:
    ok = buttons.button(QDialogButtonBox.Ok)
    if ok is not None:
        ok.setText(ok_text)
        ok.setCursor(Qt.PointingHandCursor)
    cancel = buttons.button(QDialogButtonBox.Cancel)
    if cancel is not None:
        cancel.setText("Cancel")
        cancel.setCursor(Qt.PointingHandCursor)



class _CleanLastColumnDelegate(QStyledItemDelegate):
    """Draw subtle table lines but hide the final column's right border.

    Qt's native grid draws a visible right-side line on the final cell/column.
    This delegate keeps the table separators clean while avoiding the extra
    line that appears beside the last column such as Created At / Last Seen.
    """
    def paint(self, painter, option, index):
        opt = QStyleOptionViewItem(option)
        self.initStyleOption(opt, index)

        # Default paint first: text, selection, background.
        super().paint(painter, opt, index)

        painter.save()

        row_line = QColor("#1e293b")
        col_line = QColor("#26334d")
        rect = option.rect

        # Horizontal row separator.
        painter.setPen(QPen(row_line, 1))
        painter.drawLine(rect.left(), rect.bottom(), rect.right(), rect.bottom())

        # Vertical separator only for non-final columns.
        model = index.model()
        last_col = model.columnCount() - 1 if model is not None else index.column()
        if index.column() < last_col:
            painter.setPen(QPen(col_line, 1))
            painter.drawLine(rect.right(), rect.top(), rect.right(), rect.bottom())

        painter.restore()

def _item(text: str, color: str | None = None, bold: bool = False) -> QTableWidgetItem:
    it = QTableWidgetItem("" if text is None else str(text))
    it.setFlags(it.flags() & ~Qt.ItemIsEditable)
    it.setToolTip(it.text())
    if color:
        it.setForeground(QColor(color))
    if bold:
        f = QFont("Segoe UI", 9)
        f.setBold(True)
        it.setFont(f)
    return it

def _table_card(table: QTableWidget) -> QFrame:
    """Rounded table container.

    The card owns the border/radius while the QTableWidget stays borderless.
    This prevents table/header borders from spilling outside the card.
    """
    card = QFrame()
    card.setObjectName("TableCard")
    card.setStyleSheet("""
        QFrame#TableCard {
            background: #0f172a;
            border: 1px solid #26334d;
            border-radius: 12px;
        }
    """)
    lay = QVBoxLayout(card)
    lay.setContentsMargins(2, 2, 2, 7)
    lay.setSpacing(0)
    lay.addWidget(table, 1)
    return card


def _info_strip(text: str) -> QFrame:
    strip = QFrame()
    strip.setObjectName("InfoStrip")
    lay = QHBoxLayout(strip)
    lay.setContentsMargins(12, 7, 12, 7)
    lay.setSpacing(8)

    icon = QLabel("ℹ")
    icon.setStyleSheet("color:#22d3ee;font-weight:900;")
    msg = QLabel(text)
    msg.setObjectName("InfoText")

    lay.addWidget(icon)
    lay.addWidget(msg, 1)
    return strip



class CreateUserDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Create RAMDetect User")
        self.setMinimumWidth(440)
        self.setStyleSheet(_dialog_qss())

        root = QVBoxLayout(self)
        root.setContentsMargins(18, 16, 18, 16)
        root.setSpacing(10)

        title = QLabel("Create New Staff Account")
        title.setStyleSheet("font-size: 18px; font-weight: 800; color: #f8fafc;")
        root.addWidget(title)

        self.username = QLineEdit()
        self.username.setPlaceholderText("Username, e.g. analyst01")
        self.username.setMaxLength(32)
        self.username.setToolTip(USERNAME_RULE_TEXT)
        self.full_name = QLineEdit()
        self.full_name.setPlaceholderText("Full name")
        self.full_name.setMaxLength(80)
        self.full_name.setToolTip("Optional staff display name used in Admin Management and audit records.")
        self.password = QLineEdit()
        self.password.setEchoMode(QLineEdit.Password)
        self.password.setPlaceholderText("Password, 6–128 characters")
        self.password.setMaxLength(128)
        self.password.setToolTip(PASSWORD_RULE_TEXT)
        self.confirm = QLineEdit()
        self.confirm.setEchoMode(QLineEdit.Password)
        self.confirm.setPlaceholderText("Confirm password")
        self.confirm.setMaxLength(128)
        self.confirm.setToolTip("Must match the password exactly.")

        self.role = QComboBox()
        self.role.addItems(["Analyst", "Viewer", "Admin"])
        self.role.setToolTip("Choose the user role. Only Admin users can access Admin Management.")

        self.active = QCheckBox("Account active")
        self.active.setChecked(True)
        self.active.setToolTip("Disable this if the account should be created but not allowed to log in yet.")
        self.active.setStyleSheet("color: #cbd5e1;")

        for label, widget in [
            ("Username", self.username),
            ("Full Name", self.full_name),
            ("Password", self.password),
            ("Confirm Password", self.confirm),
            ("Role", self.role),
        ]:
            root.addWidget(QLabel(label))
            root.addWidget(widget)

        root.addWidget(self.active)

        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        _style_dialog_buttons(buttons, "Create User")
        buttons.accepted.connect(self._validate)
        buttons.rejected.connect(self.reject)
        root.addWidget(buttons)

    def _validate(self):
        username = self.username.text().strip()
        password = self.password.text()
        if not _USERNAME_RE.fullmatch(username):
            QMessageBox.warning(self, "Create User", CREATE_USER_RULE_TEXT)
            return
        if "\x00" in password or len(password) < 6 or len(password) > 128:
            QMessageBox.warning(self, "Create User", PASSWORD_RULE_TEXT)
            return
        if password != self.confirm.text():
            QMessageBox.warning(self, "Create User", "Passwords do not match.")
            return
        self.accept()

    def values(self) -> dict:
        return {
            "username": self.username.text().strip(),
            "full_name": self.full_name.text().strip(),
            "password": self.password.text(),
            "role": self.role.currentText(),
            "is_active": self.active.isChecked(),
        }


class ResetPasswordDialog(QDialog):
    def __init__(self, username: str, parent=None):
        super().__init__(parent)
        self.setWindowTitle(f"Reset Password - {username}")
        self.setMinimumWidth(420)
        self.setStyleSheet(_dialog_qss())

        root = QVBoxLayout(self)
        root.setContentsMargins(18, 16, 18, 16)
        root.setSpacing(10)

        title = QLabel(f"Reset Password for {username}")
        title.setStyleSheet("font-size: 17px; font-weight: 800; color: #f8fafc;")
        root.addWidget(title)

        self.password = QLineEdit()
        self.password.setEchoMode(QLineEdit.Password)
        self.password.setPlaceholderText("New password, 6–128 characters")
        self.password.setMaxLength(128)
        self.password.setToolTip(PASSWORD_RULE_TEXT)
        self.confirm = QLineEdit()
        self.confirm.setEchoMode(QLineEdit.Password)
        self.confirm.setPlaceholderText("Confirm new password")
        self.confirm.setMaxLength(128)
        self.confirm.setToolTip("Must match the new password exactly.")

        root.addWidget(QLabel("New Password"))
        root.addWidget(self.password)
        root.addWidget(QLabel("Confirm Password"))
        root.addWidget(self.confirm)

        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        _style_dialog_buttons(buttons, "Save Password")
        buttons.accepted.connect(self._validate)
        buttons.rejected.connect(self.reject)
        root.addWidget(buttons)

    def _validate(self):
        password = self.password.text()
        if "\x00" in password or len(password) < 6 or len(password) > 128:
            QMessageBox.warning(self, "Reset Password", PASSWORD_RULE_TEXT)
            return
        if password != self.confirm.text():
            QMessageBox.warning(self, "Reset Password", "Passwords do not match.")
            return
        self.accept()

    def value(self) -> str:
        return self.password.text()


class WorkstationNotesDialog(QDialog):
    def __init__(self, hostname: str, notes: str, parent=None):
        super().__init__(parent)
        self.setWindowTitle(f"Workstation Notes - {hostname}")
        self.setMinimumSize(520, 320)
        self.setStyleSheet(_dialog_qss())

        root = QVBoxLayout(self)
        root.setContentsMargins(18, 16, 18, 16)
        root.setSpacing(10)

        title = QLabel(f"Notes for {hostname}")
        title.setStyleSheet("font-size: 17px; font-weight: 800; color: #f8fafc;")
        root.addWidget(title)

        self.notes = QPlainTextEdit()
        self.notes.setPlainText(notes or "")
        self.notes.setPlaceholderText("Add PTM/admin notes about this PC...")
        root.addWidget(self.notes, 1)

        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        _style_dialog_buttons(buttons, "Save Notes")
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        root.addWidget(buttons)

    def value(self) -> str:
        return self.notes.toPlainText().strip()


class AdminManagementPage(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._auth_bridge = None
        self._users: list[dict] = []
        self._workstations: list[dict] = []
        self._build_ui()

    def set_auth_bridge(self, bridge) -> None:
        self._auth_bridge = bridge
        self.refresh()

    def refresh(self) -> None:
        self._refresh_users()
        self._refresh_workstations()
        self._update_permissions()

    def _is_admin(self) -> bool:
        """Return True only for admin/supervisor roles.

        The fallback checks are intentional because different integration paths may
        expose the current user as an object or a dict. This keeps the Admin
        Management header/controls consistent after login without changing any
        authentication or ML logic.
        """
        if self._auth_bridge is None:
            return False

        try:
            if self._auth_bridge.has_role("Admin", "admin", "Supervisor", "PTM Supervisor", "ptm_supervisor"):
                return True
        except Exception:
            pass

        try:
            user = getattr(self._auth_bridge, "current_user", None)
            if isinstance(user, dict):
                role = user.get("role") or user.get("role_name") or ""
            else:
                role = getattr(user, "role", "") or getattr(user, "role_name", "")
            return str(role).strip().lower() in {"admin", "supervisor", "ptm supervisor", "ptm_supervisor"}
        except Exception:
            return False

    def _build_ui(self) -> None:
        self.setStyleSheet(_page_qss())
        root = QVBoxLayout(self)
        root.setContentsMargins(18, 16, 18, 16)
        root.setSpacing(10)

        header = QFrame()
        header.setObjectName("AdminHeader")
        # Keep this header exactly aligned with ActivityMonitorPage.
        # Same fixed height, internal padding, title spacing, and badge size.
        header.setFixedHeight(107)

        h = QHBoxLayout(header)
        h.setContentsMargins(18, 14, 18, 14)
        h.setSpacing(10)

        title_box = QVBoxLayout()
        title_box.setSpacing(2)

        title = QLabel("Admin Management")
        title.setStyleSheet("font-size: 22px; font-weight: 800; color: #f8fafc;")
        subtitle = QLabel("Manage RAMDetect staff accounts and registered PTM workstations")
        subtitle.setStyleSheet("font-size: 12px; color: #9fb0cc;")
        title_box.addWidget(title)
        title_box.addWidget(subtitle)
        h.addLayout(title_box, 1)

        self._role_badge = QLabel("●  Admin Access")
        self._role_badge.setAlignment(Qt.AlignCenter)
        self._role_badge.setMinimumHeight(42)
        self._role_badge.setMinimumWidth(150)
        self._role_badge.setStyleSheet(
            "background:#052e1a;"
            "color:#22c55e;"
            "border:1px solid #166534;"
            "border-radius:12px;"
            "padding:8px 14px;"
            "font-size:12px;"
            "font-weight:800;"
        )
        h.addWidget(self._role_badge)
        root.addWidget(header)

        self.tabs = QTabWidget()
        self.tabs.setStyleSheet(_tabs_qss())
        self.tabs.addTab(self._build_users_tab(), "User List")
        self.tabs.addTab(self._build_workstations_tab(), "PC / Workstation List")
        root.addWidget(self.tabs, 1)

    def _build_users_tab(self) -> QWidget:
        w = QWidget()
        w.setObjectName("AdminTabPage")
        w.setStyleSheet("QWidget#AdminTabPage { background: transparent; }")
        layout = QVBoxLayout(w)
        layout.setContentsMargins(0, 12, 0, 0)
        layout.setSpacing(10)

        bar = QFrame()
        bar.setObjectName("Toolbar")
        b = QHBoxLayout(bar)
        b.setContentsMargins(12, 9, 12, 9)

        self.btn_create = QPushButton("+ New User")
        self.btn_reset = QPushButton("Reset Password")
        self.btn_toggle = QPushButton("Disable / Enable")
        self.btn_refresh_users = QPushButton("↻ Refresh")

        for btn in (self.btn_create, self.btn_reset, self.btn_toggle, self.btn_refresh_users):
            btn.setObjectName("NeutralButton")
            b.addWidget(btn)
        b.addStretch()
        layout.addWidget(bar)

        self.btn_create.clicked.connect(self._create_user)
        self.btn_reset.clicked.connect(self._reset_password)
        self.btn_toggle.clicked.connect(self._toggle_user_active)
        self.btn_refresh_users.clicked.connect(self._refresh_users)

        self.users_table = QTableWidget(0, 7)
        self.users_table.setHorizontalHeaderLabels([
            "ID", "Username", "Full Name", "Role", "Status", "Last Login", "Created At"
        ])
        self.users_table.verticalHeader().setVisible(False)
        self.users_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.users_table.setSelectionMode(QTableWidget.SingleSelection)
        self.users_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.users_table.setAlternatingRowColors(True)
        self.users_table.setHorizontalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        self.users_table.setVerticalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        self.users_table.setFrameShape(QFrame.NoFrame)
        self.users_table.setShowGrid(False)
        self.users_table.setFocusPolicy(Qt.NoFocus)
        self.users_table.setItemDelegate(_CleanLastColumnDelegate(self.users_table))
        self.users_table.setStyleSheet(_table_qss())

        hh = self.users_table.horizontalHeader()
        hh.setSectionResizeMode(0, QHeaderView.Fixed); hh.resizeSection(0, 55)
        hh.setSectionResizeMode(1, QHeaderView.Fixed); hh.resizeSection(1, 145)
        hh.setSectionResizeMode(2, QHeaderView.Stretch)
        hh.setSectionResizeMode(3, QHeaderView.Fixed); hh.resizeSection(3, 100)
        hh.setSectionResizeMode(4, QHeaderView.Fixed); hh.resizeSection(4, 95)
        hh.setSectionResizeMode(5, QHeaderView.Fixed); hh.resizeSection(5, 165)
        hh.setSectionResizeMode(6, QHeaderView.Fixed); hh.resizeSection(6, 170)
        # Prevent a stray inner line / empty strip after the Created At column.
        hh.setStretchLastSection(True)

        layout.addWidget(_table_card(self.users_table), 1)

        self.user_summary = QLabel("0 users")
        self.user_summary.setObjectName("SummaryText")
        layout.addWidget(self.user_summary)

        return w

    def _build_workstations_tab(self) -> QWidget:
        w = QWidget()
        w.setObjectName("AdminTabPage")
        w.setStyleSheet("QWidget#AdminTabPage { background: transparent; }")
        layout = QVBoxLayout(w)
        layout.setContentsMargins(0, 12, 0, 0)
        layout.setSpacing(10)

        bar = QFrame()
        bar.setObjectName("Toolbar")
        b = QHBoxLayout(bar)
        b.setContentsMargins(12, 9, 12, 9)

        self.btn_register_pc = QPushButton("Register This PC")
        self.btn_trust = QPushButton("Trust / Untrust")
        self.btn_block = QPushButton("Block / Unblock")
        self.btn_notes = QPushButton("Notes")
        self.btn_refresh_pc = QPushButton("↻ Refresh")

        for btn in (self.btn_register_pc, self.btn_trust, self.btn_block, self.btn_notes, self.btn_refresh_pc):
            btn.setObjectName("NeutralButton")
            b.addWidget(btn)
        b.addStretch()
        layout.addWidget(bar)

        self.btn_register_pc.clicked.connect(self._register_this_pc)
        self.btn_trust.clicked.connect(self._toggle_trusted)
        self.btn_block.clicked.connect(self._toggle_blocked)
        self.btn_notes.clicked.connect(self._edit_notes)
        self.btn_refresh_pc.clicked.connect(self._refresh_workstations)

        self.ws_table = QTableWidget(0, 10)
        self.ws_table.setHorizontalHeaderLabels([
            "ID", "Status", "Hostname", "Notes", "IP Address", "Windows User",
            "Last User", "Last Role", "First Seen", "Last Seen"
        ])
        self.ws_table.verticalHeader().setVisible(False)
        self.ws_table.verticalHeader().setDefaultSectionSize(42)
        self.ws_table.setWordWrap(True)
        self.ws_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.ws_table.setSelectionMode(QTableWidget.SingleSelection)
        self.ws_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.ws_table.setAlternatingRowColors(True)
        self.ws_table.setHorizontalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        self.ws_table.setVerticalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        self.ws_table.setFrameShape(QFrame.NoFrame)
        self.ws_table.setShowGrid(False)
        self.ws_table.setFocusPolicy(Qt.NoFocus)
        self.ws_table.setItemDelegate(_CleanLastColumnDelegate(self.ws_table))
        self.ws_table.setStyleSheet(_table_qss())

        hh = self.ws_table.horizontalHeader()
        hh.setSectionResizeMode(0, QHeaderView.Fixed); hh.resizeSection(0, 55)
        hh.setSectionResizeMode(1, QHeaderView.Fixed); hh.resizeSection(1, 95)
        hh.setSectionResizeMode(2, QHeaderView.Fixed); hh.resizeSection(2, 160)
        # Wider notes preview; full note remains available through tooltip.
        hh.setSectionResizeMode(3, QHeaderView.Fixed); hh.resizeSection(3, 330)
        hh.setSectionResizeMode(4, QHeaderView.Fixed); hh.resizeSection(4, 145)
        hh.setSectionResizeMode(5, QHeaderView.Fixed); hh.resizeSection(5, 145)
        hh.setSectionResizeMode(6, QHeaderView.Fixed); hh.resizeSection(6, 105)
        hh.setSectionResizeMode(7, QHeaderView.Fixed); hh.resizeSection(7, 95)
        hh.setSectionResizeMode(8, QHeaderView.Fixed); hh.resizeSection(8, 170)
        # Fixed width prevents the Last Seen timestamp from appearing as only "05-14..."
        # after horizontal scrolling.
        hh.setSectionResizeMode(9, QHeaderView.Fixed); hh.resizeSection(9, 170)

        layout.addWidget(_info_strip(
            "PCs are auto-registered when RAMDetect opens or staff log in. "
            "Use Trust/Block for PTM admin control."
        ))
        layout.addWidget(_table_card(self.ws_table), 1)

        self.ws_summary = QLabel("0 workstations")
        self.ws_summary.setObjectName("SummaryText")
        layout.addWidget(self.ws_summary)

        return w

    def _update_permissions(self) -> None:
        is_admin = self._is_admin()
        for btn in (
            self.btn_create, self.btn_reset, self.btn_toggle,
            self.btn_register_pc, self.btn_trust, self.btn_block, self.btn_notes,
        ):
            btn.setEnabled(is_admin)

        self._role_badge.setMinimumHeight(42)
        self._role_badge.setMinimumWidth(150)

        if is_admin:
            self._role_badge.setText("●  Admin Access")
            self._role_badge.setStyleSheet(
                "background:#052e1a;"
                "color:#22c55e;"
                "border:1px solid #166534;"
                "border-radius:12px;"
                "padding:8px 14px;"
                "font-size:12px;"
                "font-weight:800;"
            )
        else:
            self._role_badge.setText("View only")
            self._role_badge.setStyleSheet(
                "background:#2b1518;"
                "color:#fecaca;"
                "border:1px solid #7f1d1d;"
                "border-radius:12px;"
                "padding:8px 14px;"
                "font-size:12px;"
                "font-weight:800;"
            )

    def _refresh_users(self) -> None:
        try:
            from ramdetect.case_management.user_service import list_users
            self._users = list_users(include_disabled=True)
            self.users_table.setRowCount(0)

            for row, u in enumerate(self._users):
                self.users_table.insertRow(row)
                status_col = "#22c55e" if u["is_active"] else "#ef4444"
                self.users_table.setItem(row, 0, _item(u["id"]))
                self.users_table.setItem(row, 1, _item(u["username"], bold=True))
                self.users_table.setItem(row, 2, _item(u["full_name"]))
                self.users_table.setItem(row, 3, _item(u["role"], "#06b6d4", True))
                self.users_table.setItem(row, 4, _item(u["status"], status_col, True))
                self.users_table.setItem(row, 5, _item(u["last_login_at"]))
                self.users_table.setItem(row, 6, _item(u["created_at"]))

            active = sum(1 for u in self._users if u.get("is_active"))
            disabled = len(self._users) - active
            if hasattr(self, "user_summary"):
                self.user_summary.setText(
                    f"{len(self._users)} user(s) · {active} active · {disabled} disabled"
                )
        except Exception as exc:
            QMessageBox.warning(self, "User List", f"Could not load users:\n{exc}")

    def _refresh_workstations(self) -> None:
        try:
            from ramdetect.case_management.workstation_service import list_workstations
            self._workstations = list_workstations()
            self.ws_table.setRowCount(0)

            for row, ws in enumerate(self._workstations):
                self.ws_table.insertRow(row)
                status = ws["status"]
                color = "#ef4444" if status == "Blocked" else ("#22c55e" if status == "Trusted" else "#f59e0b")
                self.ws_table.setItem(row, 0, _item(ws["id"]))
                self.ws_table.setItem(row, 1, _item(status, color, True))
                self.ws_table.setItem(row, 2, _item(ws["hostname"], bold=True))
                self.ws_table.setItem(row, 3, _item(ws["notes"]))
                self.ws_table.setItem(row, 4, _item(ws["ip_address"]))
                self.ws_table.setItem(row, 5, _item(ws["windows_username"]))
                self.ws_table.setItem(row, 6, _item(ws["last_username"]))
                self.ws_table.setItem(row, 7, _item(ws["last_role"]))
                self.ws_table.setItem(row, 8, _item(ws["first_seen_at"]))
                self.ws_table.setItem(row, 9, _item(ws["last_seen_at"]))

            self.ws_table.resizeRowsToContents()
            trusted = sum(1 for ws in self._workstations if ws.get("is_trusted"))
            blocked = sum(1 for ws in self._workstations if ws.get("is_blocked"))
            if hasattr(self, "ws_summary"):
                self.ws_summary.setText(
                    f"{len(self._workstations)} workstation(s) · {trusted} trusted · {blocked} blocked"
                )
        except Exception as exc:
            QMessageBox.warning(self, "Workstation List", f"Could not load workstations:\n{exc}")

    def _selected_user(self) -> dict | None:
        row = self.users_table.currentRow()
        if row < 0 or row >= len(self._users):
            QMessageBox.information(self, "User List", "Select a user first.")
            return None
        return self._users[row]

    def _selected_ws(self) -> dict | None:
        row = self.ws_table.currentRow()
        if row < 0 or row >= len(self._workstations):
            QMessageBox.information(self, "Workstation List", "Select a workstation first.")
            return None
        return self._workstations[row]

    def _create_user(self) -> None:
        if not self._is_admin():
            return
        dlg = CreateUserDialog(self)
        if dlg.exec_() != QDialog.Accepted:
            return
        try:
            from ramdetect.case_management.user_service import create_user
            create_user(**dlg.values())
            self._refresh_users()
            QMessageBox.information(self, "Create User", "User created successfully.")
        except Exception as exc:
            QMessageBox.warning(self, "Create User", str(exc))

    def _reset_password(self) -> None:
        if not self._is_admin():
            return
        user = self._selected_user()
        if not user:
            return
        dlg = ResetPasswordDialog(user["username"], self)
        if dlg.exec_() != QDialog.Accepted:
            return
        try:
            from ramdetect.case_management.user_service import reset_password
            reset_password(user["id"], dlg.value())
            QMessageBox.information(self, "Reset Password", "Password reset successfully.")
        except Exception as exc:
            QMessageBox.warning(self, "Reset Password", str(exc))

    def _toggle_user_active(self) -> None:
        if not self._is_admin():
            return
        user = self._selected_user()
        if not user:
            return
        active = not user["is_active"]
        action = "enable" if active else "disable"
        if QMessageBox.question(self, "Change Account Status", f"{action.title()} user {user['username']}?") != QMessageBox.Yes:
            return
        try:
            from ramdetect.case_management.user_service import set_user_active
            set_user_active(user["id"], active)
            self._refresh_users()
        except Exception as exc:
            QMessageBox.warning(self, "Change Account Status", str(exc))

    def _register_this_pc(self) -> None:
        if not self._is_admin():
            return
        try:
            from ramdetect.case_management.workstation_service import register_or_update_workstation
            user = self._auth_bridge.current_user if self._auth_bridge else None
            register_or_update_workstation(
                user_id=getattr(user, "id", None),
                username=getattr(user, "username", None),
                role=getattr(user, "role", None),
            )
            self._refresh_workstations()
            QMessageBox.information(self, "Register PC", "This workstation was registered/updated.")
        except Exception as exc:
            QMessageBox.warning(self, "Register PC", str(exc))

    def _toggle_trusted(self) -> None:
        if not self._is_admin():
            return
        ws = self._selected_ws()
        if not ws:
            return
        try:
            from ramdetect.case_management.workstation_service import set_workstation_trusted
            set_workstation_trusted(ws["id"], not ws["is_trusted"])
            self._refresh_workstations()
        except Exception as exc:
            QMessageBox.warning(self, "Trust Workstation", str(exc))

    def _toggle_blocked(self) -> None:
        if not self._is_admin():
            return
        ws = self._selected_ws()
        if not ws:
            return
        try:
            from ramdetect.case_management.workstation_service import set_workstation_blocked
            set_workstation_blocked(ws["id"], not ws["is_blocked"])
            self._refresh_workstations()
        except Exception as exc:
            QMessageBox.warning(self, "Block Workstation", str(exc))

    def _edit_notes(self) -> None:
        if not self._is_admin():
            return
        ws = self._selected_ws()
        if not ws:
            return
        dlg = WorkstationNotesDialog(ws["hostname"], ws["notes"], self)
        if dlg.exec_() != QDialog.Accepted:
            return
        try:
            from ramdetect.case_management.workstation_service import update_workstation_notes
            update_workstation_notes(ws["id"], dlg.value())
            self._refresh_workstations()
        except Exception as exc:
            QMessageBox.warning(self, "Workstation Notes", str(exc))


def _page_qss() -> str:
    return """
        QWidget {
            background: #0f172a;
            color: #e2e8f0;
            font-family: 'Segoe UI';
        }
        QFrame#AdminHeader, QFrame#Toolbar {
            background: #111827;
            border: 1px solid #26334d;
            border-radius: 12px;
        }
        QFrame#InfoStrip {
            background: rgba(15, 23, 42, 0.58);
            border: 1px solid rgba(38, 51, 77, 0.90);
            border-left: 3px solid #06b6d4;
            border-radius: 9px;
        }
        QLabel {
            background: transparent;
            border: none;
            color: #dbeafe;
        }
        QLabel#InfoText {
            color: #94a3b8;
            font-size: 11px;
        }
        QLabel#SummaryText {
            color: #7f91ad;
            font-size: 11px;
            padding-left: 2px;
        }
        QLineEdit, QComboBox, QPlainTextEdit {
            background: #0f172a;
            color: #e2e8f0;
            border: 1px solid #334155;
            border-radius: 8px;
            padding: 6px 10px;
            font-size: 12px;
        }
        QLineEdit:focus, QComboBox:focus, QPlainTextEdit:focus {
            border: 1px solid #06b6d4;
        }
        QPushButton#NeutralButton {
            background: #334155;
            color: #f8fafc;
            border: 1px solid #475569;
            border-radius: 8px;
            padding: 6px 12px;
            font-size: 11px;
            font-weight: 700;
            min-height: 30px;
        }
        QPushButton#NeutralButton:hover {
            background: #475569;
            border-color: #06b6d4;
        }
        QPushButton#NeutralButton:disabled {
            background: #1e293b;
            color: #64748b;
            border-color: #334155;
        }
        QMessageBox {
            background: #111827;
            color: #e2e8f0;
        }
        QMessageBox QLabel {
            color: #e2e8f0;
        }
        QMessageBox QPushButton {
            background: #334155;
            color: #ffffff;
            border: 1px solid #475569;
            border-radius: 7px;
            padding: 6px 18px;
            min-width: 72px;
            font-weight: 700;
        }
        QMessageBox QPushButton:hover {
            border: 1px solid #06b6d4;
            background: #475569;
        }
        QScrollBar:horizontal {
            background: #0b1220;
            height: 7px;
            margin: 0px;
            border-radius: 4px;
        }
        QScrollBar::handle:horizontal {
            background: #475569;
            min-width: 28px;
            border-radius: 4px;
        }
        QScrollBar::handle:horizontal:hover {
            background: #64748b;
        }
        QScrollBar::add-line:horizontal,
        QScrollBar::sub-line:horizontal {
            width: 0px;
            background: transparent;
        }
        QScrollBar::add-page:horizontal,
        QScrollBar::sub-page:horizontal {
            background: #0b1220;
            border-radius: 4px;
        }
        QScrollBar:vertical {
            background: #0b1220;
            width: 7px;
            margin: 0px;
            border-radius: 4px;
        }
        QScrollBar::handle:vertical {
            background: #475569;
            min-height: 28px;
            border-radius: 4px;
        }
        QScrollBar::handle:vertical:hover {
            background: #64748b;
        }
        QScrollBar::add-line:vertical,
        QScrollBar::sub-line:vertical {
            height: 0px;
            background: transparent;
        }
        QScrollBar::add-page:vertical,
        QScrollBar::sub-page:vertical {
            background: #0b1220;
            border-radius: 4px;
        }
    """

def _tabs_qss() -> str:
    return """
        QTabWidget {
            background: transparent;
            border: none;
        }
        QTabWidget::pane {
            border: none;
            background: transparent;
            margin-top: 8px;
        }
        QTabWidget > QWidget {
            background: transparent;
        }
        QTabBar {
            background: transparent;
        }
        QTabBar::tab {
            background: #172033;
            color: #9fb0cc;
            border: 1px solid #26334d;
            padding: 7px 12px;
            margin-right: 6px;
            border-radius: 8px;
            font-size: 11px;
            font-weight: 700;
            min-width: 104px;
        }
        QTabBar::tab:selected {
            background: #075985;
            color: #ffffff;
            border-color: #06b6d4;
            border-bottom: 2px solid #22d3ee;
        }
        QTabBar::tab:hover:!selected {
            background: #1e293b;
            color: #dbeafe;
            border-color: #334155;
        }
    """

def _table_qss() -> str:
    return """
        QTableWidget {
            background: transparent;
            alternate-background-color: #111c2e;
            color: #dbeafe;
            border: none;
            border-radius: 0px;
            gridline-color: transparent;
            font-size: 11px;
            selection-background-color: #0e7490;
            selection-color: white;
        }
        QTableWidget::viewport {
            background: #0f172a;
            border: none;
        }
        QTableWidget::item {
            padding: 3px 8px;
            border: none;
        }
        QTableWidget::item:selected {
            background: #0e7490;
            color: #ffffff;
            border: none;
        }
        QTableWidget::item:focus {
            outline: none;
            border: none;
        }
        QHeaderView {
            background: transparent;
            border: none;
        }
        QHeaderView::section {
            background: #0b1220;
            color: #cbd5e1;
            border: none;
            border-right: none;
            border-bottom: 1px solid #26334d;
            padding: 8px 10px;
            font-size: 11px;
            font-weight: 800;
        }
        QTableCornerButton::section {
            background: #0b1220;
            border: none;
            border-bottom: 1px solid #26334d;
            border-right: none;
        }
        QScrollBar:horizontal {
            background: #0b1220;
            height: 7px;
            margin: 0px;
            border-radius: 4px;
        }
        QScrollBar::handle:horizontal {
            background: #475569;
            min-width: 28px;
            border-radius: 4px;
        }
        QScrollBar::handle:horizontal:hover {
            background: #64748b;
        }
        QScrollBar::add-line:horizontal,
        QScrollBar::sub-line:horizontal {
            width: 0px;
            background: transparent;
        }
        QScrollBar::add-page:horizontal,
        QScrollBar::sub-page:horizontal {
            background: #0b1220;
            border-radius: 4px;
        }
        QScrollBar:vertical {
            background: #0b1220;
            width: 7px;
            margin: 0px;
            border-radius: 4px;
        }
        QScrollBar::handle:vertical {
            background: #475569;
            min-height: 28px;
            border-radius: 4px;
        }
        QScrollBar::handle:vertical:hover {
            background: #64748b;
        }
        QScrollBar::add-line:vertical,
        QScrollBar::sub-line:vertical {
            height: 0px;
            background: transparent;
        }
        QScrollBar::add-page:vertical,
        QScrollBar::sub-page:vertical {
            background: #0b1220;
            border-radius: 4px;
        }
    """

def _dialog_qss() -> str:
    return _page_qss() + """
        QDialog {
            background: #0f172a;
        }
        QDialog QPushButton {
            background: #1e293b;
            color: #f8fafc;
            border: 1px solid #475569;
            border-radius: 8px;
            padding: 7px 18px;
            min-width: 80px;
            min-height: 30px;
            font-size: 12px;
            font-weight: 800;
        }
        QDialog QPushButton:hover {
            background: #334155;
            border: 1px solid #06b6d4;
            color: #ffffff;
        }
        QDialog QPushButton:pressed {
            background: #075985;
            border: 1px solid #22d3ee;
        }
        QDialogButtonBox QPushButton {
            background: #1e293b;
            color: #f8fafc;
            border: 1px solid #475569;
            border-radius: 8px;
            padding: 7px 18px;
            min-width: 80px;
            min-height: 30px;
            font-size: 12px;
            font-weight: 800;
        }
        QDialogButtonBox QPushButton:hover {
            background: #334155;
            border: 1px solid #06b6d4;
        }
        QCheckBox {
            color: #cbd5e1;
            spacing: 8px;
        }
        QCheckBox::indicator {
            width: 18px;
            height: 18px;
            border-radius: 4px;
            border: 1px solid #475569;
            background: #0f172a;
        }
        QCheckBox::indicator:checked {
            background: #06b6d4;
            border: 1px solid #22d3ee;
        }
        QToolTip {
            background: #111827;
            color: #dbeafe;
            border: 1px solid #06b6d4;
            border-radius: 6px;
            padding: 6px;
            font-size: 11px;
        }
    """

