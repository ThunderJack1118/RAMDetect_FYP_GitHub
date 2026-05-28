from pathlib import Path
import re
import shutil
from datetime import datetime

ROOTS = [
    Path(r"C:\Users\annsi\Downloads\GITHUB\RAMDetect"),
    Path(r"C:\Users\annsi\Downloads\GITHUB\RAMDetect_Client_Package"),
]

STAMP = datetime.now().strftime("%Y%m%d-%H%M%S")

ADMIN_GUARD = '''
        # Admin accounts require the PTM Repository Admin API token.
        # This prevents an analyst/client workstation from using an Admin account
        # when RAMDETECT_REPOSITORY_ADMIN_API_TOKEN is intentionally empty.
        if str(getattr(user, "role", "") or "").lower() == "admin":
            try:
                from ramdetect.case_management.report_repository import repository_admin_api_enabled
                admin_token_ready = repository_admin_api_enabled()
            except Exception as exc:
                logger.warning("Admin token check failed: %s", exc)
                admin_token_ready = False

            if not admin_token_ready:
                reason = (
                    "Admin login is blocked on this workstation because the PTM "
                    "admin repository token is not configured. Use the Admin installer "
                    "or set RAMDETECT_REPOSITORY_ADMIN_API_TOKEN."
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
        shutil.copy2(path, path.with_suffix(path.suffix + f".bak-admin-token-{STAMP}"))

def patch_report_repository(root: Path):
    path = root / "ramdetect" / "case_management" / "report_repository.py"
    if not path.exists():
        print(f"[SKIP] Missing: {path}")
        return

    backup(path)
    text = path.read_text(encoding="utf-8")

    # Admin token must NOT fall back to client upload token.
    old = '''def repository_api_token(*, admin: bool = False) -> str:
    if admin:
        return (
            os.environ.get("RAMDETECT_REPOSITORY_ADMIN_API_TOKEN", "").strip()
            or os.environ.get("RAMDETECT_REPOSITORY_API_TOKEN", "").strip()
        )
    return os.environ.get("RAMDETECT_REPOSITORY_API_TOKEN", "").strip()
'''

    new = '''def repository_api_token(*, admin: bool = False) -> str:
    if admin:
        return os.environ.get("RAMDETECT_REPOSITORY_ADMIN_API_TOKEN", "").strip()
    return os.environ.get("RAMDETECT_REPOSITORY_API_TOKEN", "").strip()
'''

    if old in text:
        text = text.replace(old, new)
        print(f"[OK] Removed admin-token fallback to client token: {path}")
    else:
        # Fallback regex for slightly different formatting.
        text = re.sub(
            r'def repository_api_token\(\*, admin: bool = False\) -> str:\s*\n\s*if admin:\s*\n\s*return \(\s*\n\s*os\.environ\.get\("RAMDETECT_REPOSITORY_ADMIN_API_TOKEN", ""\)\.strip\(\)\s*\n\s*or os\.environ\.get\("RAMDETECT_REPOSITORY_API_TOKEN", ""\)\.strip\(\)\s*\n\s*\)\s*\n\s*return os\.environ\.get\("RAMDETECT_REPOSITORY_API_TOKEN", ""\)\.strip\(\)\s*\n',
            new,
            text,
            flags=re.S
        )

    path.write_text(text, encoding="utf-8")

def patch_auth_bridge_file(path: Path):
    if not path.exists():
        return

    backup(path)
    text = path.read_text(encoding="utf-8")

    if "Admin accounts require the PTM Repository Admin API token" in text:
        print(f"[OK] Admin guard already exists: {path}")
        return

    marker = "        # Register/update this PC before finalising the login."
    if marker not in text:
        print(f"[WARN] Could not find login insertion marker: {path}")
        return

    text = text.replace(marker, ADMIN_GUARD + marker, 1)
    path.write_text(text, encoding="utf-8")
    print(f"[OK] Added admin-token login guard: {path}")

def patch_auth_bridge(root: Path):
    candidates = [
        root / "ramdetect" / "ui" / "bridge" / "auth_bridge.py",
        root / "ui" / "bridge" / "auth_bridge.py",
    ]
    for path in candidates:
        patch_auth_bridge_file(path)

def write_server_scripts(root: Path):
    analyst = root / "Configure_RAMDetect_Analyst_Server.ps1"
    admin = root / "Configure_RAMDetect_Admin_Server.ps1"

    analyst.write_text(r'''param(
    [Parameter(Mandatory=$true)][string]$ServerIP,
    [Parameter(Mandatory=$true)][string]$ClientToken,
    [string]$DbUser = "ramdetect_app",
    [string]$DbPassword = "changeme",
    [string]$DbName = "ramdetect_db",
    [int]$DbPort = 5432,
    [int]$ApiPort = 8765
)

setx RAMDETECT_RUNTIME_MODE "auto"
setx RAMDETECT_DB_URL "postgresql+psycopg2://$DbUser`:$DbPassword@$ServerIP`:$DbPort/$DbName"
setx RAMDETECT_REPOSITORY_API_URL "http://$ServerIP`:$ApiPort"
setx RAMDETECT_REPOSITORY_API_TOKEN "$ClientToken"
setx RAMDETECT_REPOSITORY_ADMIN_API_TOKEN ""

Write-Host ""
Write-Host "[RAMDetect] Analyst server configuration saved." -ForegroundColor Green
Write-Host "Close and reopen RAMDetect for changes to take effect."
Write-Host "Admin token is intentionally empty on Analyst workstation."
''', encoding="utf-8")

    admin.write_text(r'''param(
    [Parameter(Mandatory=$true)][string]$ServerIP,
    [Parameter(Mandatory=$true)][string]$ClientToken,
    [Parameter(Mandatory=$true)][string]$AdminToken,
    [string]$DbUser = "ramdetect_app",
    [string]$DbPassword = "changeme",
    [string]$DbName = "ramdetect_db",
    [int]$DbPort = 5432,
    [int]$ApiPort = 8765
)

setx RAMDETECT_RUNTIME_MODE "auto"
setx RAMDETECT_DB_URL "postgresql+psycopg2://$DbUser`:$DbPassword@$ServerIP`:$DbPort/$DbName"
setx RAMDETECT_REPOSITORY_API_URL "http://$ServerIP`:$ApiPort"
setx RAMDETECT_REPOSITORY_API_TOKEN "$ClientToken"
setx RAMDETECT_REPOSITORY_ADMIN_API_TOKEN "$AdminToken"

Write-Host ""
Write-Host "[RAMDetect] Admin server configuration saved." -ForegroundColor Green
Write-Host "Close and reopen RAMDetect for changes to take effect."
Write-Host "Admin token is configured for Admin Management / central repository access."
''', encoding="utf-8")

    print(f"[OK] Wrote server config scripts in: {root}")

def patch_installer_files(root: Path):
    installer_dir = root / "installer"
    if not installer_dir.exists():
        return

    analyst_iss = installer_dir / "RAMDetect_Analyst.iss"
    admin_iss = installer_dir / "RAMDetect_Admin.iss"

    if analyst_iss.exists():
        backup(analyst_iss)
        text = analyst_iss.read_text(encoding="utf-8")
        line = 'Source: "..\\Configure_RAMDetect_Analyst_Server.ps1"; DestDir: "{app}"; Flags: ignoreversion'
        if "Configure_RAMDetect_Analyst_Server.ps1" not in text:
            text = text.replace(
                'Source: "..\\dist\\RAMDetect\\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs',
                'Source: "..\\dist\\RAMDetect\\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs\n' + line
            )
        analyst_iss.write_text(text, encoding="utf-8")
        print(f"[OK] Analyst installer includes config script: {analyst_iss}")

    if admin_iss.exists():
        backup(admin_iss)
        text = admin_iss.read_text(encoding="utf-8")
        line = 'Source: "..\\Configure_RAMDetect_Admin_Server.ps1"; DestDir: "{app}"; Flags: ignoreversion'
        if "Configure_RAMDetect_Admin_Server.ps1" not in text:
            text = text.replace(
                'Source: "..\\dist\\RAMDetect\\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs',
                'Source: "..\\dist\\RAMDetect\\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs\n' + line
            )
        admin_iss.write_text(text, encoding="utf-8")
        print(f"[OK] Admin installer includes config script: {admin_iss}")

for root in ROOTS:
    print("=" * 70)
    print(f"[RAMDetect] Patching: {root}")
    patch_report_repository(root)
    patch_auth_bridge(root)
    write_server_scripts(root)
    patch_installer_files(root)

print("=" * 70)
print("[RAMDetect] Admin-token access control and server config scripts complete.")
