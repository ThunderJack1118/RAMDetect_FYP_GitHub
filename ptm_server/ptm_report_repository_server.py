"""
ptm_report_repository_server.py
--------------------------------
Strict PTM deployment backend for RAMDetect report/export repository.

Design
------
RAMDetect staff clients never receive Google Drive credentials and never write
straight to a shared Drive folder. They upload generated report/export files to
this central API. The central API stores metadata in SQLite and stores files in:

1. local server repository storage, and optionally
2. a controlled Google Drive / Shared Drive folder through a service account.

Admins use an admin API token to list/download every report. Client machines use
an upload-only token.

This module is monitoring/report-storage only. It does not touch RAM parsing,
FeatureMapper, Autoencoder MSE fusion, Random Forest threshold, or verdict logic.

Run example
-----------
python -m venv .venv
.venv\\Scripts\\activate
pip install -r requirements_repository_server.txt
uvicorn ptm_report_repository_server:app --host 0.0.0.0 --port 8765
"""

from __future__ import annotations

import hashlib
import json
import mimetypes
import os
import re
import secrets
import sqlite3
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from fastapi import Body, Depends, FastAPI, File, Form, Header, HTTPException, Query, UploadFile
from fastapi.responses import FileResponse, StreamingResponse
from pydantic import BaseModel

APP_NAME = "RAMDetect PTM Report Repository"
API_VERSION = "v1"


# ─────────────────────────────────────────────────────────────────────────────
# Configuration
# ─────────────────────────────────────────────────────────────────────────────


def _env(name: str, default: str = "") -> str:
    return os.environ.get(name, default).strip()


def repository_root() -> Path:
    root = _env("RAMDETECT_PTM_REPOSITORY_ROOT")
    if root:
        return Path(root).expanduser().resolve()
    return (Path.cwd() / "ptm_report_repository_storage").resolve()


def db_path() -> Path:
    configured = _env("RAMDETECT_PTM_REPOSITORY_DB")
    if configured:
        return Path(configured).expanduser().resolve()
    return repository_root() / "repository.db"


def google_drive_enabled() -> bool:
    return bool(_env("RAMDETECT_GOOGLE_SERVICE_ACCOUNT_JSON") and _env("RAMDETECT_GOOGLE_DRIVE_FOLDER_ID"))


def _safe_part(value: Any, default: str = "unknown", max_len: int = 80) -> str:
    text = str(value or "").strip() or default
    text = re.sub(r"[^A-Za-z0-9_.-]+", "_", text).strip("._-") or default
    return text[:max_len]


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_tokens() -> dict[str, dict[str, Any]]:
    """Load API tokens from environment.

    Preferred format:
        RAMDETECT_REPOSITORY_TOKENS_JSON='[
          {"name":"ptm-admin","token":"...","role":"admin"},
          {"name":"ramdetect-client","token":"...","role":"client"}
        ]'

    Fallback demo variables:
        RAMDETECT_REPOSITORY_ADMIN_TOKEN
        RAMDETECT_REPOSITORY_CLIENT_TOKEN
    """
    tokens: dict[str, dict[str, Any]] = {}
    raw = _env("RAMDETECT_REPOSITORY_TOKENS_JSON")
    if raw:
        try:
            data = json.loads(raw)
            if isinstance(data, list):
                for item in data:
                    if not isinstance(item, dict):
                        continue
                    token = str(item.get("token") or "").strip()
                    role = str(item.get("role") or "").strip().lower()
                    name = str(item.get("name") or role or "token").strip()
                    if token and role in {"admin", "client"}:
                        tokens[token] = {"name": name, "role": role}
        except Exception as exc:
            raise RuntimeError(f"Invalid RAMDETECT_REPOSITORY_TOKENS_JSON: {exc}") from exc

    admin_token = _env("RAMDETECT_REPOSITORY_ADMIN_TOKEN")
    if admin_token:
        tokens[admin_token] = {"name": "ptm-admin", "role": "admin"}

    client_token = _env("RAMDETECT_REPOSITORY_CLIENT_TOKEN")
    if client_token:
        tokens[client_token] = {"name": "ramdetect-client", "role": "client"}

    if not tokens:
        # Safe-by-default: no auto-generated usable token. Health endpoint still works.
        return {}
    return tokens


def auth_context(authorization: Optional[str] = Header(default=None)) -> dict[str, Any]:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Missing Bearer token")
    token = authorization.split(" ", 1)[1].strip()
    for known, meta in parse_tokens().items():
        if secrets.compare_digest(token, known):
            return dict(meta)
    raise HTTPException(status_code=403, detail="Invalid API token")


def require_admin(ctx: dict[str, Any] = Depends(auth_context)) -> dict[str, Any]:
    if ctx.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin token required")
    return ctx


def require_uploader(ctx: dict[str, Any] = Depends(auth_context)) -> dict[str, Any]:
    if ctx.get("role") not in {"admin", "client"}:
        raise HTTPException(status_code=403, detail="Upload permission required")
    return ctx


# ─────────────────────────────────────────────────────────────────────────────
# Database
# ─────────────────────────────────────────────────────────────────────────────


def connect() -> sqlite3.Connection:
    repository_root().mkdir(parents=True, exist_ok=True)
    db_path().parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(str(db_path()))
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA journal_mode=WAL")
    con.execute("PRAGMA foreign_keys=ON")
    return con


def init_db() -> None:
    with connect() as con:
        con.execute(
            """
            CREATE TABLE IF NOT EXISTS reports (
                id TEXT PRIMARY KEY,
                created_at TEXT NOT NULL,
                uploaded_by_token TEXT,
                username TEXT,
                role TEXT,
                machine_name TEXT,
                workstation_id TEXT,
                action TEXT,
                verdict TEXT,
                original_file_name TEXT,
                stored_file_name TEXT,
                original_path TEXT,
                local_storage_path TEXT,
                google_drive_file_id TEXT,
                google_drive_folder_id TEXT,
                file_hash TEXT,
                size_bytes INTEGER,
                mime_type TEXT,
                details_json TEXT,
                source_report_id TEXT,
                source_session_id TEXT,
                source_workstation_id TEXT,
                source_machine_id TEXT,
                source_audit_log_id TEXT
            )
            """
        )
        con.execute(
            """
            CREATE TABLE IF NOT EXISTS downloads (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                report_id TEXT NOT NULL,
                downloaded_at TEXT NOT NULL,
                downloaded_by_token TEXT,
                admin_name TEXT,
                client_host TEXT,
                FOREIGN KEY(report_id) REFERENCES reports(id) ON DELETE CASCADE
            )
            """
        )
        con.execute(
            """
            CREATE TABLE IF NOT EXISTS activity_events (
                id TEXT PRIMARY KEY,
                received_at TEXT NOT NULL,
                uploaded_by_token TEXT,
                local_audit_log_id TEXT,
                event_timestamp TEXT,
                username TEXT,
                user_id TEXT,
                role TEXT,
                machine_name TEXT,
                workstation_id TEXT,
                action TEXT NOT NULL,
                file_path TEXT,
                file_name TEXT,
                file_hash TEXT,
                verdict TEXT,
                report_path TEXT,
                repository_report_id TEXT,
                analysis_session_id TEXT,
                report_id TEXT,
                details_json TEXT
            )
            """
        )
        con.execute("CREATE INDEX IF NOT EXISTS idx_activity_received ON activity_events(received_at DESC)")
        con.execute("CREATE INDEX IF NOT EXISTS idx_activity_timestamp ON activity_events(event_timestamp DESC)")
        con.execute("CREATE INDEX IF NOT EXISTS idx_activity_user ON activity_events(username)")
        con.execute("CREATE INDEX IF NOT EXISTS idx_activity_machine ON activity_events(machine_name)")
        con.execute("CREATE INDEX IF NOT EXISTS idx_activity_action ON activity_events(action)")
        con.execute("CREATE INDEX IF NOT EXISTS idx_reports_created ON reports(created_at DESC)")
        con.execute("CREATE INDEX IF NOT EXISTS idx_reports_user ON reports(username)")
        con.execute("CREATE INDEX IF NOT EXISTS idx_reports_machine ON reports(machine_name)")
        con.execute("CREATE INDEX IF NOT EXISTS idx_reports_verdict ON reports(verdict)")
        _ensure_repository_schema_columns(con)


def _ensure_repository_schema_columns(con: sqlite3.Connection) -> None:
    """Add Phase 6 cross-system correlation columns to existing repository.db."""
    existing = {row[1] for row in con.execute("PRAGMA table_info(reports)").fetchall()}
    additions = {
        "source_report_id": "TEXT",
        "source_session_id": "TEXT",
        "source_workstation_id": "TEXT",
        "source_machine_id": "TEXT",
        "source_audit_log_id": "TEXT",
    }
    for column, ddl in additions.items():
        if column not in existing:
            con.execute(f"ALTER TABLE reports ADD COLUMN {column} {ddl}")
    con.execute("CREATE INDEX IF NOT EXISTS idx_reports_source_report ON reports(source_report_id)")
    con.execute("CREATE INDEX IF NOT EXISTS idx_reports_source_session ON reports(source_session_id)")

    # Phase 7: central activity sync table migration for existing repository.db.
    con.execute(
        """
        CREATE TABLE IF NOT EXISTS activity_events (
            id TEXT PRIMARY KEY,
            received_at TEXT NOT NULL,
            uploaded_by_token TEXT,
            local_audit_log_id TEXT,
            event_timestamp TEXT,
            username TEXT,
            user_id TEXT,
            role TEXT,
            machine_name TEXT,
            workstation_id TEXT,
            action TEXT NOT NULL,
            file_path TEXT,
            file_name TEXT,
            file_hash TEXT,
            verdict TEXT,
            report_path TEXT,
            repository_report_id TEXT,
            analysis_session_id TEXT,
            report_id TEXT,
            details_json TEXT
        )
        """
    )
    con.execute("CREATE INDEX IF NOT EXISTS idx_activity_received ON activity_events(received_at DESC)")
    con.execute("CREATE INDEX IF NOT EXISTS idx_activity_timestamp ON activity_events(event_timestamp DESC)")
    con.execute("CREATE INDEX IF NOT EXISTS idx_activity_user ON activity_events(username)")
    con.execute("CREATE INDEX IF NOT EXISTS idx_activity_machine ON activity_events(machine_name)")
    con.execute("CREATE INDEX IF NOT EXISTS idx_activity_action ON activity_events(action)")


def row_to_dict(row: sqlite3.Row) -> dict[str, Any]:
    return {k: row[k] for k in row.keys()}


# ─────────────────────────────────────────────────────────────────────────────
# Hashing/storage helpers
# ─────────────────────────────────────────────────────────────────────────────


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def safe_storage_path(report_id: str, created_at: str, machine_name: str, username: str, filename: str) -> Path:
    dt = created_at[:10] if created_at else datetime.utcnow().strftime("%Y-%m-%d")
    machine = _safe_part(machine_name)
    user = _safe_part(username)
    stem = _safe_part(Path(filename).stem, "report", 120)
    suffix = Path(filename).suffix or ".dat"
    out_dir = repository_root() / "reports" / dt / machine / user
    out_dir.mkdir(parents=True, exist_ok=True)
    return out_dir / f"{report_id}_{stem}{suffix}"


# ─────────────────────────────────────────────────────────────────────────────
# Optional Google Drive backend. Imported lazily so local/dev mode still works.
# ─────────────────────────────────────────────────────────────────────────────


class DriveUploadResult(BaseModel):
    file_id: str = ""
    folder_id: str = ""


def _drive_service():
    from google.oauth2 import service_account
    from googleapiclient.discovery import build

    service_account_path = _env("RAMDETECT_GOOGLE_SERVICE_ACCOUNT_JSON")
    scopes = ["https://www.googleapis.com/auth/drive.file"]
    credentials = service_account.Credentials.from_service_account_file(
        service_account_path,
        scopes=scopes,
    )
    delegated_user = _env("RAMDETECT_GOOGLE_DELEGATED_USER")
    if delegated_user:
        credentials = credentials.with_subject(delegated_user)
    return build("drive", "v3", credentials=credentials, cache_discovery=False)


def upload_to_google_drive(local_path: Path, *, display_name: str, mime_type: str) -> DriveUploadResult:
    if not google_drive_enabled():
        return DriveUploadResult()

    from googleapiclient.http import MediaFileUpload

    folder_id = _env("RAMDETECT_GOOGLE_DRIVE_FOLDER_ID")
    service = _drive_service()
    media = MediaFileUpload(str(local_path), mimetype=mime_type or "application/octet-stream", resumable=True)
    body = {
        "name": display_name,
        "parents": [folder_id],
    }
    result = service.files().create(
        body=body,
        media_body=media,
        fields="id,name,parents,size,md5Checksum,webViewLink",
        supportsAllDrives=True,
    ).execute()
    return DriveUploadResult(file_id=str(result.get("id") or ""), folder_id=folder_id)


def download_from_google_drive(file_id: str, destination: Path) -> bool:
    if not file_id or not google_drive_enabled():
        return False

    from googleapiclient.http import MediaIoBaseDownload

    service = _drive_service()
    request = service.files().get_media(fileId=file_id, supportsAllDrives=True)
    destination.parent.mkdir(parents=True, exist_ok=True)
    with destination.open("wb") as fh:
        downloader = MediaIoBaseDownload(fh, request)
        done = False
        while not done:
            _, done = downloader.next_chunk()
    return True


# ─────────────────────────────────────────────────────────────────────────────
# API
# ─────────────────────────────────────────────────────────────────────────────


app = FastAPI(title=APP_NAME, version=API_VERSION)


@app.on_event("startup")
def _startup() -> None:
    init_db()


@app.get("/health")
def health() -> dict[str, Any]:
    return {
        "status": "ok",
        "service": APP_NAME,
        "version": API_VERSION,
        "repository_root": str(repository_root()),
        "database": str(db_path()),
        "google_drive_enabled": google_drive_enabled(),
        "tokens_configured": bool(parse_tokens()),
    }


@app.post("/api/v1/reports/upload")
async def upload_report(
    file: UploadFile = File(...),
    username: str = Form("unknown"),
    role: str = Form("unknown"),
    machine_name: str = Form("unknown"),
    workstation_id: str = Form(""),
    action: str = Form("REPORT_ARCHIVED"),
    verdict: str = Form(""),
    original_path: str = Form(""),
    file_hash: str = Form(""),
    details_json: str = Form("{}"),
    source_report_id: str = Form(""),
    source_session_id: str = Form(""),
    source_workstation_id: str = Form(""),
    source_machine_id: str = Form(""),
    source_audit_log_id: str = Form(""),
    ctx: dict[str, Any] = Depends(require_uploader),
) -> dict[str, Any]:
    report_id = uuid.uuid4().hex[:16]
    created_at = utc_now()
    original_name = Path(file.filename or "ramdetect_report_export.bin").name
    mime_type = file.content_type or mimetypes.guess_type(original_name)[0] or "application/octet-stream"
    local_path = safe_storage_path(report_id, created_at, machine_name, username, original_name)

    # Stream to a temporary path first, then atomically move.
    tmp_fd, tmp_name = tempfile.mkstemp(prefix="ramdetect_upload_", suffix=".tmp", dir=str(repository_root()))
    os.close(tmp_fd)
    tmp_path = Path(tmp_name)
    try:
        size = 0
        with tmp_path.open("wb") as out:
            while True:
                chunk = await file.read(1024 * 1024)
                if not chunk:
                    break
                size += len(chunk)
                out.write(chunk)
        digest = sha256_file(tmp_path)
        if file_hash and file_hash.lower() != digest.lower():
            raise HTTPException(status_code=400, detail="SHA-256 mismatch during upload")
        local_path.parent.mkdir(parents=True, exist_ok=True)
        tmp_path.replace(local_path)
    finally:
        try:
            if tmp_path.exists():
                tmp_path.unlink()
        except Exception:
            pass

    drive_result = DriveUploadResult()
    if google_drive_enabled():
        drive_name = f"{created_at.replace(':', '').replace('-', '')}_{_safe_part(machine_name)}_{_safe_part(username)}_{original_name}"
        drive_result = upload_to_google_drive(local_path, display_name=drive_name, mime_type=mime_type)

    # Validate JSON but keep original-style text if invalid.
    details_safe = details_json or "{}"
    try:
        json.loads(details_safe)
    except Exception:
        details_safe = json.dumps({"raw_details": details_json}, default=str)

    with connect() as con:
        con.execute(
            """
            INSERT INTO reports (
                id, created_at, uploaded_by_token, username, role, machine_name,
                workstation_id, action, verdict, original_file_name, stored_file_name,
                original_path, local_storage_path, google_drive_file_id,
                google_drive_folder_id, file_hash, size_bytes, mime_type, details_json,
                source_report_id, source_session_id, source_workstation_id,
                source_machine_id, source_audit_log_id
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                report_id,
                created_at,
                ctx.get("name"),
                username or "unknown",
                role or "unknown",
                machine_name or "unknown",
                workstation_id or "",
                action or "REPORT_ARCHIVED",
                (verdict or "").upper(),
                original_name,
                local_path.name,
                original_path or "",
                str(local_path),
                drive_result.file_id,
                drive_result.folder_id,
                digest,
                local_path.stat().st_size,
                mime_type,
                details_safe,
                source_report_id or "",
                source_session_id or "",
                source_workstation_id or "",
                source_machine_id or "",
                source_audit_log_id or "",
            ),
        )

    return {
        "success": True,
        "id": report_id,
        "created_at": created_at,
        "file_name": original_name,
        "file_hash": digest,
        "size_bytes": local_path.stat().st_size,
        "google_drive_file_id": drive_result.file_id,
        "local_storage_path": str(local_path),
        "source_report_id": source_report_id or "",
        "source_session_id": source_session_id or "",
        "source_workstation_id": source_workstation_id or "",
        "source_machine_id": source_machine_id or "",
        "source_audit_log_id": source_audit_log_id or "",
    }


@app.get("/api/v1/reports")
def list_reports(
    username: str = Query(""),
    machine_name: str = Query(""),
    verdict: str = Query(""),
    limit: int = Query(500, ge=1, le=5000),
    ctx: dict[str, Any] = Depends(require_admin),
) -> dict[str, Any]:
    where = []
    args: list[Any] = []
    if username:
        where.append("LOWER(username) = LOWER(?)")
        args.append(username)
    if machine_name:
        where.append("LOWER(machine_name) = LOWER(?)")
        args.append(machine_name)
    if verdict:
        where.append("UPPER(verdict) = UPPER(?)")
        args.append(verdict)
    sql = "SELECT * FROM reports"
    if where:
        sql += " WHERE " + " AND ".join(where)
    sql += " ORDER BY created_at DESC LIMIT ?"
    args.append(limit)
    with connect() as con:
        rows = [row_to_dict(r) for r in con.execute(sql, args).fetchall()]
    return {"success": True, "count": len(rows), "reports": rows}


@app.get("/api/v1/reports/{report_id}")
def get_report(report_id: str, ctx: dict[str, Any] = Depends(require_admin)) -> dict[str, Any]:
    with connect() as con:
        row = con.execute("SELECT * FROM reports WHERE id = ?", (report_id,)).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Report not found")
    return {"success": True, "report": row_to_dict(row)}


@app.get("/api/v1/reports/{report_id}/download")
def download_report(
    report_id: str,
    x_client_host: Optional[str] = Header(default=""),
    ctx: dict[str, Any] = Depends(require_admin),
):
    with connect() as con:
        row = con.execute("SELECT * FROM reports WHERE id = ?", (report_id,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Report not found")
        data = row_to_dict(row)

        local_path = Path(data.get("local_storage_path") or "")
        if not local_path.exists() and data.get("google_drive_file_id"):
            cache = repository_root() / "download_cache" / f"{report_id}_{data.get('stored_file_name') or data.get('original_file_name')}"
            ok = download_from_google_drive(str(data.get("google_drive_file_id")), cache)
            if ok:
                local_path = cache

        if not local_path.exists() or not local_path.is_file():
            raise HTTPException(status_code=404, detail="Report file is not available in repository storage")

        con.execute(
            "INSERT INTO downloads(report_id, downloaded_at, downloaded_by_token, admin_name, client_host) VALUES (?, ?, ?, ?, ?)",
            (report_id, utc_now(), ctx.get("name"), ctx.get("name"), x_client_host or ""),
        )

    filename = data.get("original_file_name") or local_path.name
    media_type = data.get("mime_type") or mimetypes.guess_type(filename)[0] or "application/octet-stream"
    return FileResponse(
        str(local_path),
        filename=filename,
        media_type=media_type,
        headers={"X-RAMDetect-Report-ID": report_id, "X-RAMDetect-SHA256": data.get("file_hash") or ""},
    )



@app.post("/api/v1/activity/upload")
def upload_activity_event(
    payload: dict[str, Any] = Body(...),
    ctx: dict[str, Any] = Depends(require_uploader),
) -> dict[str, Any]:
    """Receive one RAMDetect activity/audit event from a client workstation.

    Client tokens may upload activity only. Admin tokens may upload too for
    local lab/demo mode. This endpoint stores monitoring data only and never
    affects RAM analysis or ML verdict logic.
    """
    if not isinstance(payload, dict):
        raise HTTPException(status_code=400, detail="Invalid activity payload")

    action = str(payload.get("action") or "").strip()
    if not action:
        raise HTTPException(status_code=400, detail="Activity action is required")

    details_raw = payload.get("details_json")
    if isinstance(details_raw, dict):
        details_json = json.dumps(details_raw, default=str)
    else:
        details_json = str(details_raw or "")
    if details_json:
        try:
            json.loads(details_json)
        except Exception:
            details_json = json.dumps({"raw_details": details_json}, default=str)

    event_id = uuid.uuid4().hex[:16]
    received_at = utc_now()

    def s(name: str, default: str = "") -> str:
        val = payload.get(name, default)
        return str(val if val is not None else default)

    with connect() as con:
        con.execute(
            """
            INSERT INTO activity_events (
                id, received_at, uploaded_by_token, local_audit_log_id,
                event_timestamp, username, user_id, role, machine_name,
                workstation_id, action, file_path, file_name, file_hash,
                verdict, report_path, repository_report_id,
                analysis_session_id, report_id, details_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                event_id,
                received_at,
                ctx.get("name"),
                s("local_audit_log_id"),
                s("timestamp") or received_at,
                s("username", "unknown") or "unknown",
                s("user_id"),
                s("role", "unknown") or "unknown",
                s("machine_name", "unknown") or "unknown",
                s("workstation_id"),
                action,
                s("file_path"),
                s("file_name"),
                s("file_hash"),
                s("verdict").upper(),
                s("report_path"),
                s("repository_report_id"),
                s("analysis_session_id"),
                s("report_id"),
                details_json,
            ),
        )

    return {"success": True, "id": event_id, "received_at": received_at}


@app.get("/api/v1/activity")
def list_activity_events(
    username: str = Query(""),
    machine_name: str = Query(""),
    action: str = Query(""),
    limit: int = Query(1000, ge=1, le=10000),
    ctx: dict[str, Any] = Depends(require_admin),
) -> dict[str, Any]:
    """List central activity events from all RAMDetect workstations.

    Admin token required. This allows an administrator workstation to monitor
    events generated by staff workstations without directly connecting to those
    workstations.
    """
    where: list[str] = []
    args: list[Any] = []
    if username:
        where.append("LOWER(username) = LOWER(?)")
        args.append(username)
    if machine_name:
        where.append("LOWER(machine_name) = LOWER(?)")
        args.append(machine_name)
    if action:
        actions = [a.strip().upper() for a in action.split(",") if a.strip()]
        if actions:
            where.append("UPPER(action) IN (%s)" % ",".join("?" for _ in actions))
            args.extend(actions)

    sql = "SELECT * FROM activity_events"
    if where:
        sql += " WHERE " + " AND ".join(where)
    sql += " ORDER BY COALESCE(event_timestamp, received_at) DESC, received_at DESC LIMIT ?"
    args.append(limit)

    with connect() as con:
        rows = [row_to_dict(r) for r in con.execute(sql, args).fetchall()]
    return {"success": True, "count": len(rows), "activity_events": rows}

@app.get("/api/v1/downloads")
def list_downloads(limit: int = Query(500, ge=1, le=5000), ctx: dict[str, Any] = Depends(require_admin)) -> dict[str, Any]:
    with connect() as con:
        rows = [row_to_dict(r) for r in con.execute("SELECT * FROM downloads ORDER BY downloaded_at DESC LIMIT ?", (limit,)).fetchall()]
    return {"success": True, "count": len(rows), "downloads": rows}
