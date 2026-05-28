from pathlib import Path
import re
import shutil
from datetime import datetime

ROOTS = [
    Path(r"C:\Users\annsi\Downloads\GITHUB\RAMDetect"),
    Path(r"C:\Users\annsi\Downloads\GITHUB\RAMDetect_Client_Package"),
]

STAMP = datetime.now().strftime("%Y%m%d-%H%M%S")

LOCAL_ENV_HELPER = r'''
def _local_env_value(name: str, default: str = "") -> str:
    """Read RAMDetect_RUNTIME.env beside the installed/source app as a fallback to Windows env."""
    raw = os.environ.get(name)
    if raw not in (None, ""):
        return str(raw).strip()

    candidates = []
    try:
        import sys as _sys
        exe_dir = Path(_sys.executable).resolve().parent
        candidates.append(exe_dir / "RAMDetect_RUNTIME.env")
        candidates.append(exe_dir / "_internal" / "RAMDetect_RUNTIME.env")
    except Exception:
        pass

    try:
        candidates.append(Path.cwd() / "RAMDetect_RUNTIME.env")
    except Exception:
        pass

    try:
        here = Path(__file__).resolve()
        for parent in [here.parent, *here.parents]:
            candidates.append(parent / "RAMDetect_RUNTIME.env")
    except Exception:
        pass

    for env_path in candidates:
        try:
            if not env_path.exists():
                continue
            for line in env_path.read_text(encoding="utf-8", errors="ignore").splitlines():
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, v = line.split("=", 1)
                if k.strip() == name:
                    return v.strip().strip('"').strip("'")
        except Exception:
            continue

    return default
'''

def backup(path: Path):
    if path.exists():
        shutil.copy2(path, path.with_suffix(path.suffix + f".bak-local-env-{STAMP}"))

def patch_report_repository(root: Path):
    path = root / "ramdetect" / "case_management" / "report_repository.py"
    if not path.exists():
        print(f"[SKIP] Missing: {path}")
        return

    backup(path)
    text = path.read_text(encoding="utf-8")

    if "def _local_env_value(" not in text:
        marker = "API_URI_PREFIX = \"ramdetect-api://\""
        text = text.replace(marker, marker + "\n\n" + LOCAL_ENV_HELPER, 1)

    text = re.sub(
        r'def repository_api_url\(\) -> str:\s*\n\s*return os\.environ\.get\("RAMDETECT_REPOSITORY_API_URL", ""\)\.strip\(\)\.rstrip\("/"\)\s*\n',
        'def repository_api_url() -> str:\n    return _local_env_value("RAMDETECT_REPOSITORY_API_URL", "").strip().rstrip("/")\n',
        text,
        count=1
    )

    text = re.sub(
        r'def repository_api_token\(\*, admin: bool = False\) -> str:.*?return os\.environ\.get\("RAMDETECT_REPOSITORY_API_TOKEN", ""\)\.strip\(\)\s*\n',
        'def repository_api_token(*, admin: bool = False) -> str:\n    if admin:\n        return _local_env_value("RAMDETECT_REPOSITORY_ADMIN_API_TOKEN", "").strip()\n    return _local_env_value("RAMDETECT_REPOSITORY_API_TOKEN", "").strip()\n',
        text,
        count=1,
        flags=re.S
    )

    text = re.sub(
        r'def _offline_local_mode_enabled\(\) -> bool:\s*\n\s*return os\.environ\.get\("RAMDETECT_OFFLINE_LOCAL_MODE", ""\)\.strip\(\)\.lower\(\) in \{"1", "true", "yes", "on"\}\s*\n',
        'def _offline_local_mode_enabled() -> bool:\n    return _local_env_value("RAMDETECT_OFFLINE_LOCAL_MODE", "").strip().lower() in {"1", "true", "yes", "on"}\n',
        text,
        count=1
    )

    path.write_text(text, encoding="utf-8")
    print(f"[OK] Patched local env fallback: {path}")

def patch_config_script(path: Path, is_admin: bool):
    if not path.exists():
        return

    backup(path)
    text = path.read_text(encoding="utf-8")

    if "RAMDetect_RUNTIME.env" in text:
        print(f"[OK] Script already writes RAMDetect_RUNTIME.env: {path}")
        return

    if is_admin:
        block = r'''
$RuntimeEnvFile = Join-Path $PSScriptRoot "RAMDetect_RUNTIME.env"
@"
RAMDETECT_RUNTIME_MODE=auto
RAMDETECT_DB_URL=postgresql+psycopg2://$DbUser`:$DbPassword@$ServerIP`:$DbPort/$DbName
RAMDETECT_REPOSITORY_API_URL=http://$ServerIP`:$ApiPort
RAMDETECT_REPOSITORY_API_TOKEN=$ClientToken
RAMDETECT_REPOSITORY_ADMIN_API_TOKEN=$AdminToken
"@ | Set-Content $RuntimeEnvFile -Encoding UTF8

Write-Host "[RAMDetect] Local runtime env written to: $RuntimeEnvFile" -ForegroundColor Green
'''
    else:
        block = r'''
$RuntimeEnvFile = Join-Path $PSScriptRoot "RAMDetect_RUNTIME.env"
@"
RAMDETECT_RUNTIME_MODE=auto
RAMDETECT_DB_URL=postgresql+psycopg2://$DbUser`:$DbPassword@$ServerIP`:$DbPort/$DbName
RAMDETECT_REPOSITORY_API_URL=http://$ServerIP`:$ApiPort
RAMDETECT_REPOSITORY_API_TOKEN=$ClientToken
RAMDETECT_REPOSITORY_ADMIN_API_TOKEN=
"@ | Set-Content $RuntimeEnvFile -Encoding UTF8

Write-Host "[RAMDetect] Local runtime env written to: $RuntimeEnvFile" -ForegroundColor Green
'''

    text = text.replace('Write-Host "Close and reopen RAMDetect for changes to take effect."', block + '\nWrite-Host "Close and reopen RAMDetect for changes to take effect."', 1)
    path.write_text(text, encoding="utf-8")
    print(f"[OK] Patched config script: {path}")

for root in ROOTS:
    print("=" * 70)
    print(f"[RAMDetect] Patching: {root}")
    patch_report_repository(root)
    patch_config_script(root / "Configure_RAMDetect_Analyst_Server.ps1", False)
    patch_config_script(root / "Configure_RAMDetect_Admin_Server.ps1", True)

print("=" * 70)
print("[RAMDetect] Local runtime env fallback patch complete.")
