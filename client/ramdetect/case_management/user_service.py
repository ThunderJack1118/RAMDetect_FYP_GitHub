"""
user_service.py
---------------
Admin-facing user-management service for RAMDetect.

Used by Admin Management GUI:
- list users
- create user
- enable/disable user
- reset password
- change role/full name

No ML/parser/verdict logic is touched.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

VALID_ROLES = {"Admin", "Analyst", "Viewer"}


def _dt(value) -> str:
    if value is None:
        return ""
    try:
        return value.strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return str(value)


def _user_to_dict(user) -> dict[str, Any]:
    return {
        "id": user.id,
        "username": user.username,
        "full_name": user.full_name or "",
        "role": user.role or "",
        "is_active": bool(user.is_active),
        "status": "Active" if user.is_active else "Disabled",
        "created_at": _dt(user.created_at),
        "last_login_at": _dt(user.last_login_at),
    }


def list_users(include_disabled: bool = True) -> list[dict]:
    from ramdetect.case_management.database import session_scope
    from ramdetect.case_management.models import User

    with session_scope() as db:
        q = db.query(User).order_by(User.username.asc())
        if not include_disabled:
            q = q.filter(User.is_active.is_(True))
        return [_user_to_dict(u) for u in q.all()]


def get_user(user_id: int) -> dict | None:
    from ramdetect.case_management.database import session_scope
    from ramdetect.case_management.models import User

    with session_scope() as db:
        u = db.query(User).filter(User.id == user_id).first()
        return _user_to_dict(u) if u else None


def create_user(username: str, password: str, full_name: str = "", role: str = "Analyst", is_active: bool = True) -> dict:
    from ramdetect.case_management.auth_service import (
        _hash_password,
        normalise_username,
        validate_account_inputs,
    )

    username = normalise_username(username)
    full_name = (full_name or "").strip()
    role = (role or "Analyst").strip()

    ok, validation_message = validate_account_inputs(username, password)
    if not ok:
        raise ValueError(validation_message)
    if role not in VALID_ROLES:
        raise ValueError(f"Invalid role: {role}. Allowed roles: {', '.join(sorted(VALID_ROLES))}")

    from ramdetect.case_management.database import session_scope
    from ramdetect.case_management.models import User

    with session_scope() as db:
        existing = db.query(User).filter(User.username == username).first()
        if existing:
            raise ValueError(f"Username already exists: {username}")

        user = User(
            username=username,
            password_hash=_hash_password(password),
            full_name=full_name or None,
            role=role,
            is_active=bool(is_active),
            created_at=datetime.utcnow(),
        )
        db.add(user)
        db.flush()
        data = _user_to_dict(user)

    _audit("USER_CREATED", details={"username": username, "role": role, "is_active": bool(is_active)})
    return data


def update_user(user_id: int, *, full_name: str | None = None, role: str | None = None, is_active: bool | None = None) -> dict:
    from ramdetect.case_management.database import session_scope
    from ramdetect.case_management.models import User

    if role is not None:
        role = role.strip()
        if role not in VALID_ROLES:
            raise ValueError(f"Invalid role: {role}")

    with session_scope() as db:
        user = db.query(User).filter(User.id == int(user_id)).first()
        if not user:
            raise ValueError("User not found.")

        before = {"full_name": user.full_name, "role": user.role, "is_active": user.is_active}

        if full_name is not None:
            user.full_name = full_name.strip() or None
        if role is not None:
            user.role = role
        if is_active is not None:
            user.is_active = bool(is_active)

        db.flush()
        data = _user_to_dict(user)

    _audit("USER_UPDATED", details={"user_id": user_id, "before": before, "after": data})
    return data


def set_user_active(user_id: int, active: bool) -> dict:
    data = update_user(user_id, is_active=active)
    _audit("USER_ENABLED" if active else "USER_DISABLED", details={"user_id": user_id, "username": data.get("username")})
    return data


def reset_password(user_id: int, new_password: str) -> None:
    from ramdetect.case_management.auth_service import _hash_password, validate_password

    ok, validation_message = validate_password(new_password, for_login=False)
    if not ok:
        raise ValueError(validation_message)

    from ramdetect.case_management.database import session_scope
    from ramdetect.case_management.models import User

    with session_scope() as db:
        user = db.query(User).filter(User.id == int(user_id)).first()
        if not user:
            raise ValueError("User not found.")
        user.password_hash = _hash_password(new_password)
        username = user.username

    _audit("PASSWORD_RESET", details={"user_id": user_id, "username": username})


def _audit(action: str, details: dict | None = None) -> None:
    try:
        from ramdetect.case_management.activity_logger import ActivityLogger
        ActivityLogger.instance().log(action, details=details or {})
    except Exception:
        pass
