"""
auth_service.py
---------------
Authentication and login-history service for RAMDetect Case Management.

Password hashing
----------------
Uses Python's standard hashlib.pbkdf2_hmac (SHA-256, 390 000 iterations,
32-byte salt).  This requires no third-party packages and is strong enough
for a local FYP deployment.

Migration note: swap _hash_password / _verify_password with bcrypt or
Argon2 if deploying to a shared / internet-facing environment.
"""

import hashlib
import hmac
import logging
import os
import re
import socket
from datetime import datetime

logger = logging.getLogger(__name__)

# ── pbkdf2 parameters ──────────────────────────────────────────────────────
_HASH_ALGO      = "sha256"
_ITERATIONS     = 390_000   # OWASP 2023 recommendation for PBKDF2-SHA256
_SALT_BYTES     = 32
_HASH_BYTES     = 32
_SEPARATOR      = "$"       # stored format: algo$iterations$hex_salt$hex_hash


# ── Login / account input policy ───────────────────────────────────────────
# These checks are defence-in-depth. The database access below still uses
# SQLAlchemy ORM filters, which are parameterized and do not concatenate user
# input into raw SQL.
USERNAME_MIN_LENGTH = 3
USERNAME_MAX_LENGTH = 32
PASSWORD_MIN_LENGTH = 6
PASSWORD_MAX_LENGTH = 128
USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{3,32}$")

USERNAME_REQUIREMENTS = (
    "Username must be 3–32 characters and may only contain letters, numbers, "
    "underscore (_), dot (.), or hyphen (-)."
)
PASSWORD_REQUIREMENTS = "Password must be 6–128 characters."
LOGIN_REQUIREMENTS_TEXT = f"{USERNAME_REQUIREMENTS}\n{PASSWORD_REQUIREMENTS}"


def normalise_username(username: str | None) -> str:
    """Trim UI whitespace while preserving the account's intended case."""
    return (username or "").strip()


def is_valid_username(username: str | None) -> bool:
    username = normalise_username(username)
    if "\x00" in username:
        return False
    return bool(USERNAME_RE.fullmatch(username))


def validate_username(username: str | None) -> tuple[bool, str]:
    username = normalise_username(username)
    if not username:
        return False, "Username is required. " + USERNAME_REQUIREMENTS
    if "\x00" in username:
        return False, "Username contains an invalid character. " + USERNAME_REQUIREMENTS
    if not USERNAME_RE.fullmatch(username):
        return False, USERNAME_REQUIREMENTS
    return True, ""


def validate_password(password: str | None, *, for_login: bool = True) -> tuple[bool, str]:
    password = "" if password is None else str(password)
    if not password:
        return False, "Password is required. " + PASSWORD_REQUIREMENTS
    if "\x00" in password:
        return False, "Password contains an invalid character. " + PASSWORD_REQUIREMENTS
    if len(password) > PASSWORD_MAX_LENGTH:
        return False, PASSWORD_REQUIREMENTS
    if not for_login and len(password) < PASSWORD_MIN_LENGTH:
        return False, PASSWORD_REQUIREMENTS
    # For login, keep the minimum-length rule too so obviously invalid input does
    # not reach the authentication query.
    if for_login and len(password) < PASSWORD_MIN_LENGTH:
        return False, PASSWORD_REQUIREMENTS
    return True, ""


def validate_login_inputs(username: str | None, password: str | None) -> tuple[bool, str]:
    ok, msg = validate_username(username)
    if not ok:
        return False, msg
    ok, msg = validate_password(password, for_login=True)
    if not ok:
        return False, msg
    return True, ""


def validate_account_inputs(username: str | None, password: str | None) -> tuple[bool, str]:
    ok, msg = validate_username(username)
    if not ok:
        return False, msg
    ok, msg = validate_password(password, for_login=False)
    if not ok:
        return False, msg
    return True, ""


def _safe_audit_username(username: str | None) -> str:
    """Keep failed-login/audit rows readable and bounded."""
    clean = normalise_username(username).replace("\x00", "")
    return clean[:USERNAME_MAX_LENGTH]


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _hash_password(plaintext: str) -> str:
    """Return a salted PBKDF2 hash string safe to store in the database."""
    salt = os.urandom(_SALT_BYTES)
    dk = hashlib.pbkdf2_hmac(_HASH_ALGO, plaintext.encode(), salt, _ITERATIONS,
                              dklen=_HASH_BYTES)
    return _SEPARATOR.join([
        _HASH_ALGO,
        str(_ITERATIONS),
        salt.hex(),
        dk.hex(),
    ])


def _verify_password(plaintext: str, stored_hash: str) -> bool:
    """Return True if *plaintext* matches *stored_hash*."""
    try:
        algo, iterations, salt_hex, hash_hex = stored_hash.split(_SEPARATOR)
        salt  = bytes.fromhex(salt_hex)
        dk    = hashlib.pbkdf2_hmac(algo, plaintext.encode(), salt, int(iterations),
                                    dklen=_HASH_BYTES)
        return hmac.compare_digest(dk.hex(), hash_hex)
    except Exception:
        return False


def _get_machine_name() -> str:
    try:
        return socket.gethostname()
    except Exception:
        return "unknown"


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def create_default_admin() -> None:
    """Insert the default admin account into the database.

    username : admin
    password : admin123
    role     : Admin

    No-op if a user named 'admin' already exists.
    """
    from ramdetect.case_management.database import session_scope
    from ramdetect.case_management.models   import User

    with session_scope() as session:
        existing = session.query(User).filter_by(username="admin").first()
        if existing:
            logger.debug("Default admin already exists; skipping.")
            return

        admin = User(
            username      = "admin",
            password_hash = _hash_password("admin123"),
            full_name     = "System Administrator",
            role          = "Admin",
            is_active     = True,
        )
        session.add(admin)
        logger.info("Default admin account created.")


def create_default_analyst() -> None:
    """Insert a default Analyst account for role-based GUI testing.

    username : analyst
    password : analyst123
    role     : Analyst

    No-op if a user named 'analyst' already exists.
    """
    from ramdetect.case_management.database import session_scope
    from ramdetect.case_management.models   import User

    with session_scope() as session:
        existing = session.query(User).filter_by(username="analyst").first()
        if existing:
            logger.debug("Default analyst already exists; skipping.")
            return

        analyst = User(
            username      = "analyst",
            password_hash = _hash_password("analyst123"),
            full_name     = "RAMDetect Analyst",
            role          = "Analyst",
            is_active     = True,
        )
        session.add(analyst)
        logger.info("Default analyst account created.")


def authenticate_user(username: str, password: str):
    """Verify credentials and return the User ORM object on success.

    SQL injection note
    ------------------
    The query uses SQLAlchemy ORM comparison filters, not string-built SQL.
    Username/password values are therefore bound as parameters by the database
    driver. Input validation above is an additional defensive layer.

    Returns
    -------
    User | None
        The matching User instance, or None if authentication fails.
    """
    from ramdetect.case_management.database import session_scope
    from ramdetect.case_management.models   import User

    username = normalise_username(username)
    ok, _ = validate_login_inputs(username, password)
    if not ok:
        return None

    with session_scope() as session:
        # Parameterized ORM query. Do not replace this with raw string SQL.
        user = (session.query(User)
                .filter(User.username == username)
                .filter(User.is_active.is_(True))
                .first())

        if user is None:
            return None

        if _verify_password(password, user.password_hash):
            # Detach from session so the caller can use the object freely
            session.expunge(user)
            return user

    return None


def update_last_login(user_id: int) -> None:
    """Stamp the users.last_login_at column with the current UTC time."""
    from ramdetect.case_management.database import session_scope
    from ramdetect.case_management.models   import User

    with session_scope() as session:
        user = session.query(User).filter_by(id=user_id).first()
        if user:
            user.last_login_at = datetime.utcnow()


def record_login_success(user, machine_name: str | None = None,
                          ip_address: str | None = None,
                          workstation_id: int | None = None) -> None:
    """Write a successful login row to login_history.

    Parameters
    ----------
    user:
        A User ORM instance (already authenticated).
    machine_name:
        Calling machine hostname.  Auto-detected if None.
    ip_address:
        Calling machine IP address.  Nullable / optional.
    """
    from ramdetect.case_management.database import session_scope
    from ramdetect.case_management.models   import LoginHistory
    if machine_name is None:
        machine_name = _get_machine_name()

    with session_scope() as session:
        entry = LoginHistory(
            user_id      = user.id,
            workstation_id = workstation_id,
            username     = user.username,
            machine_name = machine_name,
            ip_address   = ip_address,
            status       = "success",
        )
        session.add(entry)

    update_last_login(user.id)


def record_login_failure(username: str, reason: str,
                          machine_name: str | None = None,
                          ip_address: str | None = None,
                          workstation_id: int | None = None) -> None:
    """Write a failed login row to login_history.

    Parameters
    ----------
    username:
        The username that was attempted.
    reason:
        Short human-readable failure reason (e.g. 'invalid_password').
    machine_name:
        Calling machine hostname.  Auto-detected if None.
    ip_address:
        Calling machine IP address.
    """
    from ramdetect.case_management.database import session_scope
    from ramdetect.case_management.models   import LoginHistory

    if machine_name is None:
        machine_name = _get_machine_name()

    username = _safe_audit_username(username)

    with session_scope() as session:
        entry = LoginHistory(
            user_id        = None,
            workstation_id = workstation_id,
            username       = username,
            machine_name   = machine_name,
            ip_address     = ip_address,
            status         = "failed",
            failure_reason = reason,
        )
        session.add(entry)

    logger.warning("Login failure for username=%r reason=%r machine=%r",
                   username, reason, machine_name)


def record_logout(user_id: int) -> None:
    """Stamp the most-recent successful login_history row with logout_time.

    ActivityLogger writes the audit LOGOUT row from AuthBridge. This service
    only updates login_history.logout_time.
    """
    from ramdetect.case_management.database import session_scope
    from ramdetect.case_management.models   import LoginHistory, User

    with session_scope() as session:
        # Find the most-recent login row that has no logout_time yet
        row = (session.query(LoginHistory)
               .filter_by(user_id=user_id, status="success")
               .filter(LoginHistory.logout_time.is_(None))
               .order_by(LoginHistory.login_time.desc())
               .first())
        if row:
            row.logout_time = datetime.utcnow()
            row.status      = "logged_out"

        user = session.query(User).filter_by(id=user_id).first()
        if user:
            session.expunge(user)



def get_user_by_id(user_id: int):
    """Return the User ORM object for *user_id*, or None."""
    from ramdetect.case_management.database import session_scope
    from ramdetect.case_management.models   import User

    with session_scope() as session:
        user = session.query(User).filter_by(id=user_id).first()
        if user:
            session.expunge(user)
        return user


def list_users():
    """Return all active users as a list of detached User objects."""
    from ramdetect.case_management.database import session_scope
    from ramdetect.case_management.models   import User

    with session_scope() as session:
        users = session.query(User).filter_by(is_active=True).all()
        for u in users:
            session.expunge(u)
        return users
