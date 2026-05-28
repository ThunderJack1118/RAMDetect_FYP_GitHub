"""
database.py
-----------
SQLAlchemy engine, session factory, and base declarative class for
RAMDetect Case Management / Activity Monitoring.

Supports:
- PostgreSQL deployment (multi-PC mode, production):
    postgresql+psycopg2://ramdetect_app:PASSWORD@SERVER_IP:5432/ramdetect_db

Configuration priority:
1. Environment variable RAMDETECT_DB_URL (required)
2. config.yaml → case_management.database_url (required)
"""

from __future__ import annotations

import logging
import os

from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker

logger = logging.getLogger(__name__)

Base = declarative_base()

_engine = None
_SessionFactory = None
_engine_url = None


def _read_config_value(path: str, default=None):
    """Read a dotted config value safely using RAMDetect ConfigManager."""
    try:
        from ramdetect.utils.config import get_config
        cfg = get_config()
        if hasattr(cfg, "get"):
            return cfg.get(path, default)
    except Exception:
        pass
    return default


def get_database_url(db_url: str | None = None) -> str:
    """
    Return the PostgreSQL database URL.

    Precedence:
    1. Explicit db_url argument
    2. RAMDETECT_DB_URL environment variable
    3. config.yaml case_management.database_url

    Raises ValueError if no PostgreSQL URL is configured.
    """
    if db_url:
        return str(db_url)

    env_url = os.environ.get("RAMDETECT_DB_URL")
    if env_url:
        url = str(env_url).strip()
        if url:
            return url

    configured_url = _read_config_value("case_management.database_url", None)
    if configured_url:
        url = str(configured_url).strip()
        if url:
            return url

    raise ValueError(
        "PostgreSQL database URL not configured. Set RAMDETECT_DB_URL environment variable "
        "or configure case_management.database_url in config.yaml"
    )


def init_engine(db_url: str | None = None, force: bool = False) -> None:
    """
    Create the PostgreSQL SQLAlchemy engine and session factory.

    Safe to call multiple times. Use force=True only for tests or when switching
    database target during the same Python process.
    """
    global _engine, _SessionFactory, _engine_url

    url = get_database_url(db_url=db_url)

    if _engine is not None and not force:
        return

    if _engine is not None and force:
        try:
            _engine.dispose()
        except Exception:
            pass
        _engine = None
        _SessionFactory = None

    logger.info("RAMDetect PostgreSQL database: %s", url)

    _engine = create_engine(
        url,
        connect_args={},
        echo=False,
        pool_pre_ping=True,
        pool_size=20,
        max_overflow=10,
        future=True,
    )

    _SessionFactory = sessionmaker(
        bind=_engine,
        autoflush=False,
        autocommit=False,
        expire_on_commit=False,
        future=True,
    )
    _engine_url = url


def get_engine():
    if _engine is None:
        init_engine()
    return _engine


def get_session():
    if _SessionFactory is None:
        init_engine()
    return _SessionFactory()


class session_scope:
    """Context manager for database sessions."""

    def __init__(self):
        self._session = None

    def __enter__(self):
        self._session = get_session()
        return self._session

    def __exit__(self, exc_type, exc_val, exc_tb):
        if exc_type:
            self._session.rollback()
            logger.debug("Session rolled back due to %s", getattr(exc_type, "__name__", exc_type))
        else:
            try:
                self._session.commit()
            except Exception:
                self._session.rollback()
                raise
        self._session.close()
        return False


def reset_engine_for_tests() -> None:
    """Dispose current engine. Intended for tests only."""
    global _engine, _SessionFactory, _engine_url
    if _engine is not None:
        try:
            _engine.dispose()
        except Exception:
            pass
    _engine = None
    _SessionFactory = None
    _engine_url = None
