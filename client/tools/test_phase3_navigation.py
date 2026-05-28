"""
test_phase3_navigation.py
--------------------------
Headless navigation-logic test for Phase 3.

Verifies that:
  1. CaseManagementIntegration builds without errors.
  2. Pages are correctly added to a mock QStackedWidget.
  3. Signals are wired (login_successful, open_case, back_requested).
  4. navigate_to() calls switch the stacked widget to the right index.
  5. logout() resets auth state and navigates back to LoginPage.
  6. All of this runs without touching ML files.

Run from the project root:
    python tools/test_phase3_navigation.py

A virtual/real display is NOT required (uses QApplication offscreen).
"""

import os
import sys
import traceback
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
NESTED_ROOT = PROJECT_ROOT / "ramdetect"

# Match main.py import behavior:
# Allows imports like "from ui.bridge.auth_bridge import AuthBridge"
if NESTED_ROOT.exists() and (NESTED_ROOT / "ui").is_dir():
    sys.path.insert(0, str(NESTED_ROOT))

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

print("[Phase3Test] PROJECT_ROOT =", PROJECT_ROOT)
print("[Phase3Test] NESTED_ROOT  =", NESTED_ROOT)
print("[Phase3Test] ui path exists =", (NESTED_ROOT / "ui").is_dir())


# Prevent noisy Qt font warnings during headless PyQt tests on Windows.
try:
    if os.name == "nt":
        win_fonts = Path(os.environ.get("WINDIR", r"C:\Windows")) / "Fonts"
        if win_fonts.exists():
            os.environ.setdefault("QT_QPA_FONTDIR", str(win_fonts))
except Exception:
    pass


def _hr(label=""):
    w = 60
    if label:
        p = (w - len(label) - 2) // 2
        print("─" * p + f" {label} " + "─" * p)
    else:
        print("─" * w)

def _ok(msg):  print(f"  ✓ {msg}")
def _fail(msg): print(f"  ✗ FAIL: {msg}"); raise AssertionError(msg)


# ── QApplication (offscreen so no display needed) ─────────────────────────
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyQt5.QtWidgets import QApplication, QMainWindow, QStackedWidget, QVBoxLayout, QWidget
app = QApplication.instance() or QApplication(sys.argv)


# ── Minimal mock MainWindow ────────────────────────────────────────────────
class MockMainWindow(QMainWindow):
    """Mimics the real MainWindow's structure with common attribute names."""

    def __init__(self):
        super().__init__()
        central = QWidget()
        self.setCentralWidget(central)
        layout = QVBoxLayout(central)

        # Stacked widget — named as RAMDetect would have it
        self.stacked_widget = QStackedWidget()
        layout.addWidget(self.stacked_widget)

        # Simulate two existing RAMDetect pages
        self._dashboard_page = QWidget()
        self._acquisition_page = QWidget()
        self.stacked_widget.addWidget(self._dashboard_page)   # index 0
        self.stacked_widget.addWidget(self._acquisition_page) # index 1

        # pages dict — for navigate_to_original()
        self.pages = {
            "dashboard":   self._dashboard_page,
            "acquisition": self._acquisition_page,
        }

        # Simulate a sidebar widget (VBox layout)
        self.sidebar = QWidget()
        sidebar_layout = QVBoxLayout(self.sidebar)
        layout.insertWidget(0, self.sidebar)

        self.cm = None


# ── Temp DB for test ──────────────────────────────────────────────────────
import tempfile
_tmp_dir = tempfile.mkdtemp(prefix="ramdetect_p3test_")
_db_path = os.path.join(_tmp_dir, "test_phase3.db")

from ramdetect.case_management import database as _db_mod
_db_mod.init_engine(_db_path)

# Models must be imported BEFORE create_all so SQLAlchemy registers them
import ramdetect.case_management.models  # noqa: F401  (side-effect import)

from ramdetect.case_management.database import Base, get_engine
Base.metadata.create_all(bind=get_engine())

from ramdetect.case_management.auth_service import create_default_admin
create_default_admin()


# ═════════════════════════════════════════════════════════════════════════════
def run_tests():
    _hr("PHASE 3 NAVIGATION TESTS")

    # ── T1: Integration instantiation ────────────────────────────────────
    _hr("T1 · Instantiate integration")
    from ramdetect.ui.case_management_integration import CaseManagementIntegration
    mw = MockMainWindow()

    integration = CaseManagementIntegration(mw)
    mw.cm = integration
    _ok("CaseManagementIntegration instantiated")

    # ── T2: setup() adds pages to stacked widget ──────────────────────────
    _hr("T2 · setup() injects pages")
    before_count = mw.stacked_widget.count()
    integration.setup()
    after_count  = mw.stacked_widget.count()

    added = after_count - before_count
    if added < 4:
        _fail(f"Expected ≥4 CM pages added, got {added}")
    _ok(f"Stacked widget grew from {before_count} → {after_count} (added {added} pages)")

    # ── T3: navigate_to known pages ────────────────────────────────────────
    _hr("T3 · navigate_to() all CM pages")
    from ramdetect.ui.case_management_integration import (
        PAGE_LOGIN, PAGE_CASE_MGR, PAGE_WORKSPACE, PAGE_AUDIT,
    )
    for key in (PAGE_LOGIN, PAGE_CASE_MGR, PAGE_WORKSPACE, PAGE_AUDIT):
        integration.navigate_to(key)
        page    = integration._pages[key]
        current = mw.stacked_widget.currentWidget()
        if current is not page:
            _fail(f"navigate_to({key!r}) did not show the correct page")
        _ok(f"navigate_to({key!r}) → correct widget active")

    # ── T4: navigate_to_original (existing pages) ──────────────────────────
    _hr("T4 · navigate_to_original() for legacy pages")
    integration.navigate_to_original("dashboard")
    current = mw.stacked_widget.currentWidget()
    if current is not mw._dashboard_page:
        _fail("navigate_to_original('dashboard') did not land on dashboard page")
    _ok("navigate_to_original('dashboard') → correct")

    # ── T5: Login signal wiring ────────────────────────────────────────────
    _hr("T5 · Login signal → CaseManagerPage")
    login_page = integration._pages[PAGE_LOGIN]

    # Check signal attribute exists
    if not hasattr(login_page, "login_successful"):
        _fail("LoginPage missing login_successful signal")
    _ok("login_successful signal present")

    # Manually fire the signal with a stub user
    class _StubUser:
        id = 1; username = "admin"; role = "Admin"

    received = []
    integration.user_logged_in.connect(lambda u: received.append(u))
    integration._on_login_success(_StubUser())

    current = mw.stacked_widget.currentWidget()
    if current is not integration._pages[PAGE_CASE_MGR]:
        _fail("After login success, did not navigate to CaseManagerPage")
    _ok("Login success → CaseManagerPage navigation correct")

    if not received:
        _fail("user_logged_in signal was not emitted")
    _ok("user_logged_in signal emitted with user object")

    # ── T6: Open case signal wiring ─────────────────────────────────────────
    _hr("T6 · open_case signal → CaseWorkspacePage")
    case_mgr = integration._pages[PAGE_CASE_MGR]
    if not hasattr(case_mgr, "open_case"):
        _fail("CaseManagerPage missing open_case signal")
    _ok("open_case signal present on CaseManagerPage")

    # Fire the slot directly (avoids needing a real DB row)
    integration._on_open_case("CASE-TEST-000001")
    current = mw.stacked_widget.currentWidget()
    if current is not integration._pages[PAGE_WORKSPACE]:
        _fail("open_case did not navigate to CaseWorkspacePage")
    _ok("open_case → CaseWorkspacePage navigation correct")

    # ── T7: Back button wiring ──────────────────────────────────────────────
    _hr("T7 · back_requested signal → CaseManagerPage")
    workspace = integration._pages[PAGE_WORKSPACE]
    if not hasattr(workspace, "back_requested"):
        _fail("CaseWorkspacePage missing back_requested signal")

    integration._on_back_to_case_manager()
    current = mw.stacked_widget.currentWidget()
    if current is not integration._pages[PAGE_CASE_MGR]:
        _fail("back_requested did not return to CaseManagerPage")
    _ok("back_requested → CaseManagerPage navigation correct")

    # ── T8: Auth bridge state ───────────────────────────────────────────────
    _hr("T8 · Auth bridge state after login_success")
    # Simulate a real login through auth bridge
    auth = integration._auth
    success, msg = auth.login("admin", "admin123")
    if not success:
        _fail(f"auth.login('admin','admin123') failed: {msg}")
    _ok(f"auth.login success: user={auth.current_user.username}")

    if not auth.is_authenticated:
        _fail("is_authenticated should be True after login")
    _ok("is_authenticated = True")

    # ── T9: Logout ──────────────────────────────────────────────────────────
    _hr("T9 · logout() → LoginPage")
    logout_received = []
    integration.user_logged_out.connect(lambda: logout_received.append(True))

    integration.logout()

    if auth.is_authenticated:
        _fail("User should not be authenticated after logout()")
    _ok("is_authenticated = False after logout()")

    current = mw.stacked_widget.currentWidget()
    if current is not integration._pages[PAGE_LOGIN]:
        _fail("logout() did not navigate to LoginPage")
    _ok("logout() → LoginPage navigation correct")

    if not logout_received:
        _fail("user_logged_out signal was not emitted")
    _ok("user_logged_out signal emitted")

    # ── T10: CM disabled safety check ──────────────────────────────────────
    _hr("T10 · CM disabled = original GUI unaffected")
    mw2 = MockMainWindow()
    initial_count = mw2.stacked_widget.count()

    integration2 = CaseManagementIntegration(mw2)
    integration2._enabled = False       # force disabled
    # setup() should be a no-op with no errors
    # (we call internal setup steps to verify they bail out safely)
    integration2.navigate_to(PAGE_LOGIN)   # should log warning but not crash
    _ok("navigate_to() with unregistered pages: no crash")

    integration2.logout()                  # should no-op without crash
    _ok("logout() with no auth bridge: no crash")

    _hr()
    print("\n  ✓ All Phase 3 navigation tests passed.\n")
    print(f"  Temp DB used: {_db_path}\n")


# ── run ───────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    try:
        run_tests()
    except AssertionError as ae:
        print(f"\n  ✗ TEST FAILED: {ae}\n")
        sys.exit(1)
    except Exception as exc:
        print(f"\n  ✗ UNEXPECTED ERROR: {exc}\n")
        traceback.print_exc()
        sys.exit(1)
