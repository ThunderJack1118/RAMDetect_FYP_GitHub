"""
connectivity.py
---------------
Runtime connectivity detection for RAMDetect Offline Local Mode.

If the PostgreSQL activity/admin database cannot be reached during startup,
RAMDetect should still open for local post-incident RAM analysis. In that case,
the GUI bypasses central login and exposes only the Analyst-level local workflow.

This module is runtime-routing only. It does not touch parser output,
FeatureMapper, Autoencoder MSE fusion, Random Forest threshold, or ML verdict
logic.
"""

from __future__ import annotations

import json
import logging
import os
import subprocess
import time
import urllib.request
from dataclasses import asdict, dataclass
from typing import Any

log = logging.getLogger(__name__)


@dataclass
class ConnectivityCheck:
    name: str
    available: bool
    configured: bool
    detail: str = ""


@dataclass
class RuntimeMode:
    mode: str
    offline_mode: bool
    database: ConnectivityCheck
    repository: ConnectivityCheck
    reason: str = ""
    service: ConnectivityCheck | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _truthy(value: str | None) -> bool:
    return str(value or "").strip().lower() in {"1", "true", "yes", "on"}




def _runtime_mode_preference() -> str:
    """Return startup connectivity preference: auto, offline, or online.

    Supported values:
    - auto: normal RAMDetect behaviour. Use Online Mode when PostgreSQL is reachable,
      otherwise fall back to Offline Local Mode.
    - offline / offline_local / local: skip DB/API probes and start local Analyst mode.
    - online: require the online login path when PostgreSQL is reachable; if it is not
      reachable, the safe fallback remains Offline Local Mode.

    The legacy RAMDETECT_FORCE_OFFLINE_LOCAL_MODE=1 flag is still supported.
    """
    if _truthy(os.environ.get("RAMDETECT_FORCE_OFFLINE_LOCAL_MODE")):
        return "offline"

    raw = (
        os.environ.get("RAMDETECT_RUNTIME_MODE")
        or os.environ.get("RAMDETECT_CONNECTIVITY_MODE")
        or str(_read_config_value("runtime.mode", "") or "")
        or str(_read_config_value("connectivity.mode", "") or "")
        or "auto"
    )
    value = str(raw or "auto").strip().lower().replace("-", "_")
    if value in {"offline", "offline_local", "local", "force_offline"}:
        return "offline"
    if value in {"online", "central", "server"}:
        return "online"
    return "auto"


def _read_config_value(path: str, default: Any = None) -> Any:
    try:
        from ramdetect.utils.config import get_config
        cfg = get_config()
        if hasattr(cfg, "get"):
            return cfg.get(path, default)
    except Exception:
        pass
    return default


def _database_url() -> str:
    env_url = os.environ.get("RAMDETECT_DB_URL", "").strip()
    if env_url:
        return env_url
    configured = _read_config_value("case_management.database_url", "")
    return str(configured or "").strip()


def _repository_url() -> str:
    env_url = os.environ.get("RAMDETECT_REPOSITORY_API_URL", "").strip().rstrip("/")
    if env_url:
        return env_url
    configured = _read_config_value("repository.api_url", "") or _read_config_value("ptm_repository.api_url", "")
    return str(configured or "").strip().rstrip("/")


def _postgres_service_name() -> str:
    """Return the Windows PostgreSQL service name used by RAMDetect startup."""
    return os.environ.get("RAMDETECT_POSTGRES_SERVICE_NAME", "postgresql-x64-18").strip() or "postgresql-x64-18"


def _service_start_timeout() -> int:
    """Return the service start wait timeout in seconds."""
    raw = os.environ.get("RAMDETECT_POSTGRES_SERVICE_START_TIMEOUT", "20")
    try:
        return max(3, min(120, int(raw)))
    except Exception:
        return 20


def _powershell_quote(value: str) -> str:
    """Safely quote a string for a single-quoted PowerShell literal."""
    return "'" + str(value).replace("'", "''") + "'"


def try_start_postgresql_service(timeout_seconds: int | None = None) -> ConnectivityCheck:
    """Best-effort startup for the local PostgreSQL Windows service.

    This is intended for the PTM/admin workstation where PostgreSQL Server is
    installed locally. Analyst clients that do not have the service installed
    will simply skip this step and fall back to the normal database connectivity
    check.

    The function is safe by design:
    - It runs only on Windows.
    - It can be disabled using RAMDETECT_DISABLE_POSTGRES_SERVICE_AUTOSTART=1.
    - It does not raise if the service cannot be started.
    - If Administrator permission is missing, RAMDetect continues to Offline
      Local Mode after the database check fails.
    """
    service_name = _postgres_service_name()

    if os.name != "nt":
        return ConnectivityCheck(
            name="PostgreSQL Windows service",
            available=False,
            configured=False,
            detail="not a Windows runtime; service autostart skipped",
        )

    if _truthy(os.environ.get("RAMDETECT_DISABLE_POSTGRES_SERVICE_AUTOSTART")):
        return ConnectivityCheck(
            name="PostgreSQL Windows service",
            available=False,
            configured=False,
            detail="disabled by RAMDETECT_DISABLE_POSTGRES_SERVICE_AUTOSTART",
        )

    wait_seconds = int(timeout_seconds or _service_start_timeout())
    svc = _powershell_quote(service_name)

    ps_script = f"""
$svc = Get-Service -Name {svc} -ErrorAction SilentlyContinue
if ($null -eq $svc) {{
    Write-Output "NOT_FOUND"
    exit 3
}}
if ($svc.Status -eq "Running") {{
    Write-Output "ALREADY_RUNNING"
    exit 0
}}
try {{
    Start-Service -Name {svc} -ErrorAction Stop
}} catch {{
    Write-Output ("START_FAILED: " + $_.Exception.Message)
    exit 4
}}
$deadline = (Get-Date).AddSeconds({wait_seconds})
do {{
    Start-Sleep -Milliseconds 500
    $svc = Get-Service -Name {svc} -ErrorAction SilentlyContinue
    if ($null -ne $svc -and $svc.Status -eq "Running") {{
        Write-Output "STARTED_RUNNING"
        exit 0
    }}
}} while ((Get-Date) -lt $deadline)
$status = if ($null -eq $svc) {{ "missing" }} else {{ $svc.Status.ToString() }}
Write-Output ("START_TIMEOUT: " + $status)
exit 5
""".strip()

    try:
        completed = subprocess.run(
            [
                "powershell.exe",
                "-NoProfile",
                "-ExecutionPolicy",
                "Bypass",
                "-Command",
                ps_script,
            ],
            capture_output=True,
            text=True,
            timeout=wait_seconds + 8,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        output = " ".join(
            part.strip()
            for part in [completed.stdout, completed.stderr]
            if part and part.strip()
        )
        output = output or f"PowerShell exit code {completed.returncode}"

        ok = completed.returncode == 0
        configured = "NOT_FOUND" not in output
        if ok:
            log.info("PostgreSQL service check: %s", output)
        else:
            log.warning("PostgreSQL service autostart did not succeed: %s", output)
        return ConnectivityCheck(
            name="PostgreSQL Windows service",
            available=ok,
            configured=configured,
            detail=output,
        )
    except Exception as exc:
        log.warning("PostgreSQL service autostart failed: %s", exc)
        return ConnectivityCheck(
            name="PostgreSQL Windows service",
            available=False,
            configured=True,
            detail=str(exc),
        )


def check_database_available(timeout_seconds: int = 2) -> ConnectivityCheck:
    """Return whether the PostgreSQL server is reachable with SELECT 1."""
    url = _database_url()
    if not url:
        return ConnectivityCheck(
            name="PostgreSQL",
            available=False,
            configured=False,
            detail="RAMDETECT_DB_URL/case_management.database_url is not configured",
        )

    try:
        from sqlalchemy import create_engine, text

        connect_args: dict[str, Any] = {}
        if url.lower().startswith("postgresql"):
            # psycopg2 honours connect_timeout in seconds. This prevents RAMDetect
            # from hanging at startup when a copied client is away from the PTM LAN.
            connect_args["connect_timeout"] = int(timeout_seconds)

        engine = create_engine(
            url,
            connect_args=connect_args,
            pool_pre_ping=True,
            future=True,
        )
        try:
            with engine.connect() as conn:
                conn.execute(text("SELECT 1")).scalar()
        finally:
            engine.dispose()
        return ConnectivityCheck("PostgreSQL", True, True, "SELECT 1 succeeded")
    except Exception as exc:
        return ConnectivityCheck("PostgreSQL", False, True, str(exc))


def wait_for_database_available(
    *,
    total_wait_seconds: int = 30,
    probe_timeout_seconds: int = 2,
) -> ConnectivityCheck:
    """Retry SELECT 1 until PostgreSQL is ready for real connections.

    Windows may report the PostgreSQL service as Running before PostgreSQL is
    fully ready to accept SQL connections. This helper prevents RAMDetect from
    entering Offline Local Mode too early immediately after Start-Service.
    """
    try:
        total_wait_seconds = max(3, min(120, int(total_wait_seconds)))
    except Exception:
        total_wait_seconds = 30

    try:
        probe_timeout_seconds = max(1, min(10, int(probe_timeout_seconds)))
    except Exception:
        probe_timeout_seconds = 2

    deadline = time.time() + total_wait_seconds
    last = check_database_available(timeout_seconds=probe_timeout_seconds)

    while time.time() < deadline:
        if last.available:
            return last
        time.sleep(1)
        last = check_database_available(timeout_seconds=probe_timeout_seconds)

    return last


def check_repository_available(timeout_seconds: int = 2) -> ConnectivityCheck:
    """Return whether the PTM Repository API /health endpoint is reachable."""
    url = _repository_url()
    if not url:
        return ConnectivityCheck(
            name="PTM Repository API",
            available=False,
            configured=False,
            detail="RAMDETECT_REPOSITORY_API_URL is not configured",
        )

    try:
        req = urllib.request.Request(url + "/health", method="GET")
        with urllib.request.urlopen(req, timeout=int(timeout_seconds)) as resp:
            payload = resp.read().decode("utf-8", errors="replace")
        try:
            data = json.loads(payload) if payload else {}
        except Exception:
            data = {}
        status = str(data.get("status", "ok") or "").lower()
        if status and status not in {"ok", "healthy", "success"}:
            return ConnectivityCheck("PTM Repository API", False, True, f"/health returned status={status}")
        return ConnectivityCheck("PTM Repository API", True, True, "/health reachable")
    except Exception as exc:
        return ConnectivityCheck("PTM Repository API", False, True, str(exc))


def detect_runtime_mode(timeout_seconds: int = 2) -> dict[str, Any]:
    """Detect whether RAMDetect should start in online or offline-local mode.

    Startup rule:
    - auto: try PostgreSQL SELECT 1. If reachable, use Online Mode; otherwise
      fall back to Offline Local Mode.
    - offline: skip PostgreSQL/PTM probes and immediately open Analyst-only
      Offline Local Mode. This is useful for analyst/client installer testing
      and disconnected post-incident triage.
    - online: prefer the normal central login path when PostgreSQL is reachable.
      If PostgreSQL is not reachable, the safe fallback remains Offline Local Mode.

    The PTM Repository API status is reported separately. If PostgreSQL is up
    but the PTM API is down, login can still continue; repository upload/download
    remains best-effort through existing repository logic.
    """
    preference = _runtime_mode_preference()

    service = ConnectivityCheck(
        name="PostgreSQL Windows service",
        available=False,
        configured=False,
        detail="not attempted",
    )

    # Manual Offline Local Mode must be immediate. Do not probe PostgreSQL or the
    # repository here, because the analyst package should open quickly even when
    # copied away from the PTM LAN.
    if preference == "offline":
        db = ConnectivityCheck(
            name="PostgreSQL",
            available=False,
            configured=bool(_database_url()),
            detail="connectivity probes skipped by RAMDETECT_RUNTIME_MODE=offline",
        )
        repo = ConnectivityCheck(
            name="PTM Repository API",
            available=False,
            configured=bool(_repository_url()),
            detail="connectivity probes skipped by RAMDETECT_RUNTIME_MODE=offline",
        )
        mode = RuntimeMode(
            mode="offline_local",
            offline_mode=True,
            database=db,
            repository=repo,
            reason="Forced Offline Local Mode by RAMDETECT_RUNTIME_MODE=offline",
            service=service,
        )
        return mode.to_dict()

    db = check_database_available(timeout_seconds=timeout_seconds)

    # If the database URL is missing, starting the Windows service cannot fix it.
    # In that case, go directly to Offline Local Mode with a clear reason.
    if db.configured and not db.available:
        try:
            service = try_start_postgresql_service(timeout_seconds=_service_start_timeout())
        except NameError:
            # Compatibility guard for partially patched files. Keep startup safe
            # and continue to Offline Local Mode instead of falling back to the
            # broken online path.
            service = ConnectivityCheck(
                name="PostgreSQL Windows service",
                available=False,
                configured=True,
                detail="service autostart function missing in connectivity.py",
            )

        # Re-test patiently after service autostart. Windows can report
        # postgresql-x64-18 as Running before the PostgreSQL socket/database is
        # ready for SELECT 1.
        if service.available:
            ready_timeout_raw = os.environ.get("RAMDETECT_DB_READY_TIMEOUT", "30")
            try:
                ready_timeout = max(3, min(120, int(ready_timeout_raw)))
            except Exception:
                ready_timeout = 30

            log.info(
                "PostgreSQL service is running; waiting up to %ss for database readiness.",
                ready_timeout,
            )
            db = wait_for_database_available(
                total_wait_seconds=ready_timeout,
                probe_timeout_seconds=timeout_seconds,
            )
        else:
            # Still re-test once because the service may have been started
            # externally while RAMDetect was launching.
            db = check_database_available(timeout_seconds=timeout_seconds)

    repo = check_repository_available(timeout_seconds=timeout_seconds)

    offline = not db.available

    if not db.configured:
        reason = db.detail
    elif not db.available:
        if service.detail and service.detail != "not attempted":
            reason = (
                "PostgreSQL activity/admin database is unreachable after service check "
                f"({service.detail}). Last DB error: {db.detail}"
            )
        else:
            reason = f"PostgreSQL activity/admin database is unreachable. Last DB error: {db.detail}"
    else:
        if service.available and "STARTED_RUNNING" in str(service.detail):
            reason = "Online mode available after starting PostgreSQL service"
        elif service.available and "ALREADY_RUNNING" in str(service.detail):
            reason = "Online mode available; PostgreSQL service already running"
        else:
            reason = "Online mode available"

    mode = RuntimeMode(
        mode="offline_local" if offline else "online",
        offline_mode=offline,
        database=db,
        repository=repo,
        reason=reason,
        service=service,
    )
    return mode.to_dict()


def apply_runtime_environment(runtime_info: dict[str, Any]) -> None:
    """Expose runtime mode to lower-level modules through an environment flag."""
    if bool((runtime_info or {}).get("offline_mode")):
        os.environ["RAMDETECT_OFFLINE_LOCAL_MODE"] = "1"
    else:
        os.environ.pop("RAMDETECT_OFFLINE_LOCAL_MODE", None)
