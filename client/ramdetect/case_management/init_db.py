"""
init_db.py
----------
Database initialisation for RAMDetect Case Management / Activity Monitoring.

Safe to call on every startup. Handles:
- PostgreSQL connection verification
- table creation
- default admin seeding
- local workstation auto-registration
"""

from __future__ import annotations

import logging

logger = logging.getLogger(__name__)


def initialise_database(db_url: str | None = None) -> None:
    from ramdetect.case_management.database import Base, get_engine, init_engine

    # Import ORM models before create_all(), otherwise metadata is incomplete.
    import ramdetect.case_management.models  # noqa: F401

    init_engine(db_url=db_url)

    logger.info("Creating RAMDetect activity/case-management tables if missing…")
    Base.metadata.create_all(bind=get_engine())
    logger.info("Tables ready.")

    try:
        from ramdetect.case_management.activity_logger import ensure_audit_log_columns
        ensure_audit_log_columns()
    except Exception as exc:
        logger.warning("Audit column migration skipped: %s", exc)

    try:
        from ramdetect.case_management.workstation_service import ensure_workstation_schema
        ensure_workstation_schema()
    except Exception as exc:
        logger.warning("Workstation schema migration skipped: %s", exc)

    _ensure_activity_relationship_columns()

    _seed_default_accounts()

    try:
        from ramdetect.case_management.workstation_service import register_or_update_workstation
        register_or_update_workstation()
    except Exception as exc:
        logger.debug("Startup workstation auto-registration skipped: %s", exc)



def _add_column_if_missing(table_name: str, column_name: str, ddl: str) -> None:
    """PostgreSQL nullable-column migration for existing databases.

    New databases get full ORM FK definitions from models.py.
    """
    try:
        from sqlalchemy import inspect as sa_inspect, text
        from ramdetect.case_management.database import get_engine

        engine = get_engine()
        inspector = sa_inspect(engine)
        if table_name not in inspector.get_table_names():
            return
        existing = {c["name"] for c in inspector.get_columns(table_name)}
        if column_name in existing:
            return
        with engine.connect() as conn:
            conn.execute(text(f"ALTER TABLE {table_name} ADD COLUMN {column_name} {ddl}"))
            conn.commit()
        logger.info("%s: added column %s", table_name, column_name)
    except Exception as exc:
        logger.warning("Column migration skipped for %s.%s: %s", table_name, column_name, exc)


def _ensure_activity_relationship_columns() -> None:
    """Add Phase 6 ERD-correction relationship/correlation fields if missing."""
    migrations = [
        ("login_history", "workstation_id", "INTEGER"),
        ("analysis_sessions", "workstation_id", "INTEGER"),
        ("audit_logs", "analysis_session_id", "INTEGER"),
        ("audit_logs", "report_id", "INTEGER"),
        ("audit_logs", "repository_report_id", "TEXT"),
        ("reports", "workstation_id", "INTEGER"),
        ("reports", "repository_report_id", "TEXT"),
        ("reports", "repository_uri", "TEXT"),
        ("reports", "repository_upload_status", "VARCHAR(32)"),
        ("reports", "repository_uploaded_at", "DATETIME"),
    ]
    for table, column, ddl in migrations:
        _add_column_if_missing(table, column, ddl)

def _seed_default_accounts() -> None:
    """Ensure built-in demo accounts exist for FYP role testing.

    Admin account:
        admin / admin123

    Analyst account:
        analyst / analyst123

    Both calls are idempotent and do not overwrite existing accounts.
    """
    from ramdetect.case_management.auth_service import (
        create_default_admin,
        create_default_analyst,
    )

    create_default_admin()
    create_default_analyst()
    logger.info("Default accounts checked: admin/Admin and analyst/Analyst")


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(levelname)s:%(name)s:%(message)s")
    initialise_database()
    print("RAMDetect activity-monitoring database is ready.")
