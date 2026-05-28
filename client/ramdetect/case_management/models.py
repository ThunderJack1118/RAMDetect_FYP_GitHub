"""
models.py
---------
SQLAlchemy ORM definitions for RAMDetect Case Management / Activity Monitoring.

The Activity Monitoring portion supports:
- staff accounts
- login history
- workstation / PC inventory
- audit logs
- scan/report/case metadata

No ML, parser, FeatureMapper, Random Forest, Autoencoder, or verdict logic is
implemented here.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
)
from sqlalchemy.orm import relationship

from ramdetect.case_management.database import Base


class User(Base):
    __tablename__ = "users"

    id            = Column(Integer, primary_key=True, autoincrement=True)
    username      = Column(String(64), unique=True, nullable=False, index=True)
    password_hash = Column(String(256), nullable=False)
    full_name     = Column(String(128), nullable=True)
    role          = Column(String(32), nullable=False, default="Analyst")
    # Roles: Admin | Analyst | Viewer
    is_active     = Column(Boolean, default=True, nullable=False)
    created_at    = Column(DateTime, default=datetime.utcnow, nullable=False)
    last_login_at = Column(DateTime, nullable=True)

    login_history = relationship(
        "LoginHistory",
        back_populates="user",
        foreign_keys="LoginHistory.user_id",
        cascade="all, delete-orphan",
    )
    audit_logs = relationship(
        "AuditLog",
        back_populates="user",
        foreign_keys="AuditLog.user_id",
    )
    last_seen_workstations = relationship(
        "Workstation",
        back_populates="last_user",
        foreign_keys="Workstation.last_user_id",
    )

    # Legacy case-management relationships retained for compatibility.
    created_cases = relationship("Case", back_populates="created_by", foreign_keys="Case.created_by_user_id")
    assigned_cases = relationship("Case", back_populates="assigned_to", foreign_keys="Case.assigned_to_user_id")
    evidence_items = relationship("EvidenceItem", back_populates="collected_by", foreign_keys="EvidenceItem.collected_by_user_id")
    analysis_sessions = relationship("AnalysisSession", back_populates="analyst", foreign_keys="AnalysisSession.analyst_user_id")
    reports = relationship("Report", back_populates="generated_by", foreign_keys="Report.generated_by_user_id")
    case_notes = relationship("CaseNote", back_populates="user", foreign_keys="CaseNote.user_id")

    def __repr__(self):
        return f"<User id={self.id} username={self.username!r} role={self.role!r} active={self.is_active}>"


class LoginHistory(Base):
    __tablename__ = "login_history"

    id             = Column(Integer, primary_key=True, autoincrement=True)
    user_id        = Column(Integer, ForeignKey("users.id"), nullable=True)
    workstation_id = Column(Integer, ForeignKey("workstations.id"), nullable=True)
    username       = Column(String(64), nullable=False)
    login_time     = Column(DateTime, default=datetime.utcnow, nullable=False)
    logout_time    = Column(DateTime, nullable=True)
    machine_name   = Column(String(128), nullable=True)
    ip_address     = Column(String(64), nullable=True)
    status         = Column(String(16), nullable=False, default="success")
    failure_reason = Column(String(256), nullable=True)

    user = relationship("User", back_populates="login_history", foreign_keys=[user_id])
    workstation = relationship("Workstation", back_populates="login_history", foreign_keys=[workstation_id])

    def __repr__(self):
        return f"<LoginHistory id={self.id} username={self.username!r} status={self.status!r}>"


class Workstation(Base):
    """
    Registered RAMDetect workstation / PC.

    Workstations are auto-registered when RAMDetect opens or when staff log in.
    Admin users can trust/block/annotate them from Admin Management.
    """

    __tablename__ = "workstations"

    id               = Column(Integer, primary_key=True, autoincrement=True)
    machine_id       = Column(String(128), unique=True, nullable=False, index=True)
    hostname         = Column(String(128), nullable=False, index=True)
    ip_address       = Column(String(64), nullable=True)
    windows_username = Column(String(128), nullable=True)
    os_info          = Column(String(256), nullable=True)

    first_seen_at    = Column(DateTime, default=datetime.utcnow, nullable=False)
    last_seen_at     = Column(DateTime, default=datetime.utcnow, nullable=False)

    last_user_id     = Column(Integer, ForeignKey("users.id"), nullable=True)
    last_username    = Column(String(64), nullable=True)
    last_role        = Column(String(32), nullable=True)

    is_trusted       = Column(Boolean, default=False, nullable=False)
    is_blocked       = Column(Boolean, default=False, nullable=False)
    notes            = Column(Text, nullable=True)

    last_user = relationship("User", back_populates="last_seen_workstations", foreign_keys=[last_user_id])
    login_history = relationship("LoginHistory", back_populates="workstation", foreign_keys="LoginHistory.workstation_id")
    analysis_sessions = relationship("AnalysisSession", back_populates="workstation", foreign_keys="AnalysisSession.workstation_id")
    reports = relationship("Report", back_populates="workstation", foreign_keys="Report.workstation_id")
    audit_logs = relationship("AuditLog", back_populates="workstation", foreign_keys="AuditLog.workstation_id")

    def __repr__(self):
        return f"<Workstation id={self.id} hostname={self.hostname!r} trusted={self.is_trusted} blocked={self.is_blocked}>"


# Legacy forensic case tables are kept so older Phase 1/2 code still imports.
class Case(Base):
    __tablename__ = "cases"

    id                  = Column(Integer, primary_key=True, autoincrement=True)
    case_id             = Column(String(32), unique=True, nullable=False, index=True)
    title               = Column(String(256), nullable=False)
    description         = Column(Text, nullable=True)
    severity            = Column(String(16), nullable=False, default="Medium")
    status              = Column(String(32), nullable=False, default="Open")
    incident_type       = Column(String(64), nullable=True)
    affected_host       = Column(String(128), nullable=True)
    department          = Column(String(128), nullable=True)
    created_by_user_id  = Column(Integer, ForeignKey("users.id"), nullable=True)
    assigned_to_user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    created_at          = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at          = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)
    closed_at           = Column(DateTime, nullable=True)

    created_by = relationship("User", back_populates="created_cases", foreign_keys=[created_by_user_id])
    assigned_to = relationship("User", back_populates="assigned_cases", foreign_keys=[assigned_to_user_id])
    evidence_items = relationship("EvidenceItem", back_populates="case", cascade="all, delete-orphan")
    analysis_sessions = relationship("AnalysisSession", back_populates="case", cascade="all, delete-orphan")
    reports = relationship("Report", back_populates="case", cascade="all, delete-orphan")
    audit_logs = relationship("AuditLog", back_populates="case", foreign_keys="AuditLog.case_id")
    case_notes = relationship("CaseNote", back_populates="case", cascade="all, delete-orphan")
    chain_of_custody = relationship("ChainOfCustody", back_populates="case", cascade="all, delete-orphan")


class EvidenceItem(Base):
    __tablename__ = "evidence_items"

    id                   = Column(Integer, primary_key=True, autoincrement=True)
    evidence_id          = Column(String(32), unique=True, nullable=False, index=True)
    case_id              = Column(Integer, ForeignKey("cases.id"), nullable=False)
    original_filename    = Column(String(256), nullable=False)
    stored_path          = Column(Text, nullable=False)
    file_size            = Column(Integer, nullable=True)
    md5                  = Column(String(32), nullable=True)
    sha256               = Column(String(64), nullable=True)
    acquisition_method   = Column(String(64), nullable=True)
    source_machine       = Column(String(128), nullable=True)
    collected_by_user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    collected_at         = Column(DateTime, default=datetime.utcnow, nullable=False)
    notes                = Column(Text, nullable=True)

    case = relationship("Case", back_populates="evidence_items", foreign_keys=[case_id])
    collected_by = relationship("User", back_populates="evidence_items", foreign_keys=[collected_by_user_id])
    analysis_sessions = relationship("AnalysisSession", back_populates="evidence", foreign_keys="AnalysisSession.evidence_id")
    chain_of_custody = relationship("ChainOfCustody", back_populates="evidence", foreign_keys="ChainOfCustody.evidence_id")


class AnalysisSession(Base):
    __tablename__ = "analysis_sessions"

    id                      = Column(Integer, primary_key=True, autoincrement=True)
    session_id              = Column(String(32), unique=True, nullable=False, index=True)
    case_id                 = Column(Integer, ForeignKey("cases.id"), nullable=True)
    evidence_id             = Column(Integer, ForeignKey("evidence_items.id"), nullable=True)
    analyst_user_id         = Column(Integer, ForeignKey("users.id"), nullable=True)
    workstation_id          = Column(Integer, ForeignKey("workstations.id"), nullable=True)
    dump_path               = Column(Text, nullable=True)
    selected_modules        = Column(Text, nullable=True)
    final_verdict           = Column(String(16), nullable=True)
    rf_suspicious_probability = Column(Float, nullable=True)
    ae_mse                  = Column(Float, nullable=True)
    artifact_summary_json   = Column(Text, nullable=True)
    key_findings_count      = Column(Integer, nullable=True, default=0)
    started_at              = Column(DateTime, default=datetime.utcnow, nullable=False)
    completed_at            = Column(DateTime, nullable=True)
    status                  = Column(String(16), nullable=False, default="pending")
    error_message           = Column(Text, nullable=True)

    case = relationship("Case", back_populates="analysis_sessions", foreign_keys=[case_id])
    evidence = relationship("EvidenceItem", back_populates="analysis_sessions", foreign_keys=[evidence_id])
    analyst = relationship("User", back_populates="analysis_sessions", foreign_keys=[analyst_user_id])
    workstation = relationship("Workstation", back_populates="analysis_sessions", foreign_keys=[workstation_id])
    reports = relationship("Report", back_populates="analysis_session", foreign_keys="Report.analysis_session_id")
    audit_logs = relationship("AuditLog", back_populates="analysis_session", foreign_keys="AuditLog.analysis_session_id")


class Report(Base):
    __tablename__ = "reports"

    id                  = Column(Integer, primary_key=True, autoincrement=True)
    report_id           = Column(String(32), unique=True, nullable=False, index=True)
    case_id             = Column(Integer, ForeignKey("cases.id"), nullable=True)
    analysis_session_id = Column(Integer, ForeignKey("analysis_sessions.id"), nullable=True)
    workstation_id      = Column(Integer, ForeignKey("workstations.id"), nullable=True)
    report_type         = Column(String(32), nullable=False)
    report_path         = Column(Text, nullable=True)
    generated_by_user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    generated_at        = Column(DateTime, default=datetime.utcnow, nullable=False)
    verdict_snapshot    = Column(String(16), nullable=True)
    sha256              = Column(String(64), nullable=True)
    repository_report_id = Column(String(64), nullable=True, index=True)
    repository_uri      = Column(Text, nullable=True)
    repository_upload_status = Column(String(32), nullable=True)
    repository_uploaded_at = Column(DateTime, nullable=True)

    case = relationship("Case", back_populates="reports", foreign_keys=[case_id])
    analysis_session = relationship("AnalysisSession", back_populates="reports", foreign_keys=[analysis_session_id])
    generated_by = relationship("User", back_populates="reports", foreign_keys=[generated_by_user_id])
    workstation = relationship("Workstation", back_populates="reports", foreign_keys=[workstation_id])
    audit_logs = relationship("AuditLog", back_populates="report", foreign_keys="AuditLog.report_id")


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id             = Column(Integer, primary_key=True, autoincrement=True)
    user_id        = Column(Integer, ForeignKey("users.id"), nullable=True)
    username       = Column(String(64), nullable=True)
    role           = Column(String(32), nullable=True)

    action         = Column(String(128), nullable=False)
    entity_type    = Column(String(64), nullable=True)
    entity_id      = Column(String(64), nullable=True)
    case_id        = Column(Integer, ForeignKey("cases.id"), nullable=True)
    analysis_session_id = Column(Integer, ForeignKey("analysis_sessions.id"), nullable=True)
    report_id      = Column(Integer, ForeignKey("reports.id"), nullable=True)
    repository_report_id = Column(String(64), nullable=True, index=True)

    machine_name   = Column(String(128), nullable=True)
    workstation_id = Column(Integer, ForeignKey("workstations.id"), nullable=True)

    file_path      = Column(Text, nullable=True)
    file_name      = Column(String(512), nullable=True)
    file_hash      = Column(String(128), nullable=True)
    verdict        = Column(String(32), nullable=True)
    report_path    = Column(Text, nullable=True)
    details_json   = Column(Text, nullable=True)

    timestamp      = Column(DateTime, default=datetime.utcnow, nullable=False)
    created_at     = Column(DateTime, default=datetime.utcnow, nullable=False)

    user = relationship("User", back_populates="audit_logs", foreign_keys=[user_id])
    case = relationship("Case", back_populates="audit_logs", foreign_keys=[case_id])
    workstation = relationship("Workstation", back_populates="audit_logs", foreign_keys=[workstation_id])
    analysis_session = relationship("AnalysisSession", back_populates="audit_logs", foreign_keys=[analysis_session_id])
    report = relationship("Report", back_populates="audit_logs", foreign_keys=[report_id])

    def __repr__(self):
        return f"<AuditLog id={self.id} action={self.action!r} username={self.username!r}>"


class CaseNote(Base):
    __tablename__ = "case_notes"

    id         = Column(Integer, primary_key=True, autoincrement=True)
    case_id    = Column(Integer, ForeignKey("cases.id"), nullable=False)
    user_id    = Column(Integer, ForeignKey("users.id"), nullable=True)
    note_text  = Column(Text, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    case = relationship("Case", back_populates="case_notes", foreign_keys=[case_id])
    user = relationship("User", back_populates="case_notes", foreign_keys=[user_id])


class ChainOfCustody(Base):
    __tablename__ = "chain_of_custody"

    id                   = Column(Integer, primary_key=True, autoincrement=True)
    case_id              = Column(Integer, ForeignKey("cases.id"), nullable=False)
    evidence_id          = Column(Integer, ForeignKey("evidence_items.id"), nullable=False)
    action               = Column(String(64), nullable=False)
    from_user_id         = Column(Integer, ForeignKey("users.id"), nullable=True)
    to_user_id           = Column(Integer, ForeignKey("users.id"), nullable=True)
    performed_by_user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    timestamp            = Column(DateTime, default=datetime.utcnow, nullable=False)
    hash_verified        = Column(Boolean, default=False, nullable=False)
    notes                = Column(Text, nullable=True)

    case = relationship("Case", back_populates="chain_of_custody", foreign_keys=[case_id])
    evidence = relationship("EvidenceItem", back_populates="chain_of_custody", foreign_keys=[evidence_id])
