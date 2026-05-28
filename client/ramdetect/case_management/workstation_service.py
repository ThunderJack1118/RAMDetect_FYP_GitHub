"""
workstation_service.py
----------------------
PC / workstation inventory service for RAMDetect Activity Monitoring.

Workstations auto-register when RAMDetect opens or a user logs in. Admin users
can trust/block/add notes through Admin Management.
"""

from __future__ import annotations

import getpass
import hashlib
import os
import platform
import socket
from datetime import datetime
from typing import Any


def _hostname() -> str:
    try:
        return socket.gethostname()
    except Exception:
        return "unknown"


def _windows_username() -> str:
    try:
        return getpass.getuser()
    except Exception:
        return os.environ.get("USERNAME") or os.environ.get("USER") or "unknown"


def _ip_address() -> str:
    try:
        hostname = _hostname()
        return socket.gethostbyname(hostname)
    except Exception:
        return ""


def _os_info() -> str:
    try:
        return f"{platform.system()} {platform.release()} {platform.version()}".strip()
    except Exception:
        return ""


def get_local_machine_info() -> dict[str, str]:
    hostname = _hostname()
    win_user = _windows_username()
    osinfo = _os_info()
    raw = f"{hostname}|{win_user}|{platform.node()}".lower()
    machine_id = hashlib.sha256(raw.encode("utf-8", errors="ignore")).hexdigest()[:24]
    return {
        "machine_id": machine_id,
        "hostname": hostname,
        "ip_address": _ip_address(),
        "windows_username": win_user,
        "os_info": osinfo,
    }


def _dt(value) -> str:
    if value is None:
        return ""
    try:
        return value.strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return str(value)


def _ws_to_dict(ws) -> dict[str, Any]:
    return {
        "id": ws.id,
        "machine_id": ws.machine_id,
        "hostname": ws.hostname,
        "ip_address": ws.ip_address or "",
        "windows_username": ws.windows_username or "",
        "os_info": ws.os_info or "",
        "first_seen_at": _dt(ws.first_seen_at),
        "last_seen_at": _dt(ws.last_seen_at),
        "last_user_id": ws.last_user_id,
        "last_username": ws.last_username or "",
        "last_role": ws.last_role or "",
        "is_trusted": bool(ws.is_trusted),
        "is_blocked": bool(ws.is_blocked),
        "status": "Blocked" if ws.is_blocked else ("Trusted" if ws.is_trusted else "Pending"),
        "notes": ws.notes or "",
    }


def register_or_update_workstation(
    *,
    user_id: int | None = None,
    username: str | None = None,
    role: str | None = None,
) -> dict:
    """Create/update the current workstation row and return it as dict."""
    info = get_local_machine_info()

    from ramdetect.case_management.database import session_scope
    from ramdetect.case_management.models import Workstation

    now = datetime.utcnow()
    created = False

    with session_scope() as db:
        ws = db.query(Workstation).filter(Workstation.machine_id == info["machine_id"]).first()
        if ws is None:
            ws = Workstation(
                machine_id=info["machine_id"],
                hostname=info["hostname"],
                ip_address=info["ip_address"],
                windows_username=info["windows_username"],
                os_info=info["os_info"],
                first_seen_at=now,
                last_seen_at=now,
                last_user_id=user_id,
                last_username=username,
                last_role=role,
            )
            db.add(ws)
            created = True
        else:
            ws.hostname = info["hostname"]
            ws.ip_address = info["ip_address"]
            ws.windows_username = info["windows_username"]
            ws.os_info = info["os_info"]
            ws.last_seen_at = now
            if user_id is not None:
                ws.last_user_id = user_id
            if username:
                ws.last_username = username
            if role:
                ws.last_role = role

        db.flush()
        data = _ws_to_dict(ws)

    if created:
        _audit("WORKSTATION_REGISTERED", details=data)
    # Do not audit every normal workstation heartbeat. last_seen_at is already
    # updated in the workstations table, and logging every WORKSTATION_SEEN
    # makes Full Audit Trail noisy for PTM reviewers.

    return data


def list_workstations() -> list[dict]:
    from ramdetect.case_management.database import session_scope
    from ramdetect.case_management.models import Workstation

    with session_scope() as db:
        rows = db.query(Workstation).order_by(Workstation.last_seen_at.desc()).all()
        return [_ws_to_dict(r) for r in rows]


def set_workstation_trusted(workstation_id: int, trusted: bool) -> dict:
    from ramdetect.case_management.database import session_scope
    from ramdetect.case_management.models import Workstation

    with session_scope() as db:
        ws = db.query(Workstation).filter(Workstation.id == int(workstation_id)).first()
        if not ws:
            raise ValueError("Workstation not found.")
        ws.is_trusted = bool(trusted)
        if trusted:
            ws.is_blocked = False
        db.flush()
        data = _ws_to_dict(ws)

    _audit("WORKSTATION_TRUSTED" if trusted else "WORKSTATION_UNTRUSTED", details=data)
    return data


def set_workstation_blocked(workstation_id: int, blocked: bool) -> dict:
    from ramdetect.case_management.database import session_scope
    from ramdetect.case_management.models import Workstation

    with session_scope() as db:
        ws = db.query(Workstation).filter(Workstation.id == int(workstation_id)).first()
        if not ws:
            raise ValueError("Workstation not found.")
        ws.is_blocked = bool(blocked)
        if blocked:
            ws.is_trusted = False
        db.flush()
        data = _ws_to_dict(ws)

    _audit("WORKSTATION_BLOCKED" if blocked else "WORKSTATION_UNBLOCKED", details=data)
    return data


def update_workstation_notes(workstation_id: int, notes: str) -> dict:
    from ramdetect.case_management.database import session_scope
    from ramdetect.case_management.models import Workstation

    with session_scope() as db:
        ws = db.query(Workstation).filter(Workstation.id == int(workstation_id)).first()
        if not ws:
            raise ValueError("Workstation not found.")
        ws.notes = notes or None
        db.flush()
        data = _ws_to_dict(ws)

    _audit("WORKSTATION_NOTES_UPDATED", details={"workstation_id": workstation_id})
    return data


def ensure_workstation_schema() -> None:
    """Lightweight migration for existing SQLite databases."""
    try:
        from sqlalchemy import inspect as sa_inspect, text
        from ramdetect.case_management.database import get_engine
        engine = get_engine()
        inspector = sa_inspect(engine)

        # create_all already creates new tables. This is only for added columns
        # if a workstation table was created by a previous draft.
        if "workstations" not in inspector.get_table_names():
            return

        existing = {c["name"] for c in inspector.get_columns("workstations")}
        new_cols = {
            "last_role": "TEXT",
            "notes": "TEXT",
            "is_trusted": "BOOLEAN DEFAULT 0",
            "is_blocked": "BOOLEAN DEFAULT 0",
        }
        with engine.connect() as conn:
            for col, dtype in new_cols.items():
                if col not in existing:
                    conn.execute(text(f"ALTER TABLE workstations ADD COLUMN {col} {dtype}"))
                    conn.commit()
    except Exception:
        pass


def _audit(action: str, details: dict | None = None) -> None:
    try:
        from ramdetect.case_management.activity_logger import ActivityLogger
        ActivityLogger.instance().log(action, details=details or {})
    except Exception:
        pass
