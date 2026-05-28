from pathlib import Path
import re
import shutil
from datetime import datetime

ROOTS = [
    Path(r"C:\Users\annsi\Downloads\GITHUB\RAMDetect"),
    Path(r"C:\Users\annsi\Downloads\GITHUB\RAMDetect_Client_Package"),
]

STAMP = datetime.now().strftime("%Y%m%d-%H%M%S")

AUTH_GUARD = '''
        # Admin login requires a configured PTM Repository Admin API token.
        # Analyst/client workstations intentionally keep this token empty.
        if str(getattr(user, "role", "") or "").lower() == "admin":
            try:
                from ramdetect.case_management.report_repository import repository_admin_api_enabled
                admin_token_ready = repository_admin_api_enabled()
            except Exception as exc:
                logger.warning("Admin token readiness check failed: %s", exc)
                admin_token_ready = False

            if not admin_token_ready:
                reason = (
                    "Admin login is blocked on this workstation because the PTM "
                    "admin repository token is not configured. Use the Admin installer "
                    "or configure RAMDETECT_REPOSITORY_ADMIN_API_TOKEN."
                )
                try:
                    record_login_failure(username, reason=reason, machine_name=machine)
                except Exception:
                    pass
                try:
                    from ramdetect.case_management.activity_logger import ActivityLogger
                    ActivityLogger.instance().log_login_failed(username)
                except Exception:
                    pass
                logger.warning("Admin login denied for %r because admin repository token is missing", username)
                return False, reason

'''

def backup(path: Path):
    if path.exists():
        shutil.copy2(path, path.with_suffix(path.suffix + f".bak-admin-lock-{STAMP}"))

def patch_report_repository(root: Path):
    path = root / "ramdetect" / "case_management" / "report_repository.py"
    if not path.exists():
        print(f"[SKIP] Missing: {path}")
        return

    backup(path)
    text = path.read_text(encoding="utf-8")

    pattern = r'''def repository_api_token\(\*, admin: bool = False\) -> str:\s*
    if admin:
        return \(
            os\.environ\.get\("RAMDETECT_REPOSITORY_ADMIN_API_TOKEN", ""\)\.strip\(\)
            or os\.environ\.get\("RAMDETECT_REPOSITORY_API_TOKEN", ""\)\.strip\(\)
        \)
    return os\.environ\.get\("RAMDETECT_REPOSITORY_API_TOKEN", ""\)\.strip\(\)
'''

    replacement = '''def repository_api_token(*, admin: bool = False) -> str:
    if admin:
        return os.environ.get("RAMDETECT_REPOSITORY_ADMIN_API_TOKEN", "").strip()
    return os.environ.get("RAMDETECT_REPOSITORY_API_TOKEN", "").strip()
'''

    text2, count = re.subn(pattern, replacement, text, flags=re.S)

    if count == 0:
        # More general fallback replacement.
        text2 = re.sub(
            r'def repository_api_token\(\*, admin: bool = False\) -> str:.*?def _offline_local_mode_enabled',
            replacement + "\n\ndef _offline_local_mode_enabled",
            text,
            count=1,
            flags=re.S
        )

    path.write_text(text2, encoding="utf-8")
    print(f"[OK] Patched strict admin token in: {path}")

def patch_auth_bridge_file(path: Path):
    if not path.exists():
        return

    backup(path)
    text = path.read_text(encoding="utf-8")

    # Strengthen is_admin so UI/Admin pages are hidden if no admin token exists.
    text = re.sub(
        r'''    @property\s*
    def is_admin\(self\) -> bool:
        return self\.has_role\("Admin", "admin"\)
''',
        '''    @property
    def is_admin(self) -> bool:
        if not self.has_role("Admin", "admin"):
            return False
        try:
            from ramdetect.case_management.report_repository import repository_admin_api_enabled
            return repository_admin_api_enabled()
        except Exception:
            return False

''',
        text,
        count=1,
        flags=re.S
    )

    # Add login block before workstation registration.
    if "Admin login requires a configured PTM Repository Admin API token" not in text:
        marker = "        # Register/update this PC before finalising the login."
        if marker in text:
            text = text.replace(marker, AUTH_GUARD + marker, 1)
        else:
            print(f"[WARN] Login insertion marker not found in: {path}")

    path.write_text(text, encoding="utf-8")
    print(f"[OK] Patched admin login lock in: {path}")

def patch_auth_bridge(root: Path):
    candidates = [
        root / "ramdetect" / "ui" / "bridge" / "auth_bridge.py",
        root / "ui" / "bridge" / "auth_bridge.py",
        root / "ui" / "bridge_auth_bridge.py",
        root / "ramdetect" / "ui" / "bridge_auth_bridge.py",
    ]

    for path in candidates:
        patch_auth_bridge_file(path)

for root in ROOTS:
    print("=" * 70)
    print(f"[RAMDetect] Patching admin-token lock in: {root}")
    patch_report_repository(root)
    patch_auth_bridge(root)

print("=" * 70)
print("[RAMDetect] Admin-token login lock patch complete.")
