from __future__ import annotations

from datetime import datetime
from uuid import UUID, uuid4

from sqlalchemy import Boolean, DateTime, Enum, ForeignKey, String, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from packages.domain.enums import (
    FindingCategory,
    Plan,
    ScanStatus,
    ScanType,
    Severity,
    SupportedLanguage,
)
from packages.infra.database.connection import Base


class ClientModel(Base):
    __tablename__ = "clients"
    id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), primary_key=True, default=uuid4)
    email: Mapped[str] = mapped_column(String(255), unique=True, nullable=False, index=True)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    api_key_hash: Mapped[str | None] = mapped_column(
        String(64), unique=True, nullable=True, index=True
    )
    api_key_id: Mapped[str | None] = mapped_column(String(32), unique=True, nullable=True)
    api_key_revoked: Mapped[bool] = mapped_column(Boolean, default=False)
    plan: Mapped[str] = mapped_column(Enum(Plan, name="plan_enum"), default=Plan.FREE)
    lgpd_consent_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    lgpd_consent_version: Mapped[str | None] = mapped_column(String(10), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow)
    projects: Mapped[list["ProjectModel"]] = relationship(
        back_populates="client", cascade="all, delete-orphan"
    )


class ProjectModel(Base):
    __tablename__ = "projects"
    id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), primary_key=True, default=uuid4)
    client_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("clients.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    name: Mapped[str] = mapped_column(String(100), nullable=False)
    domain: Mapped[str | None] = mapped_column(String(255), nullable=True)
    ownership_verified: Mapped[bool] = mapped_column(Boolean, default=False)
    ownership_proof_id: Mapped[UUID | None] = mapped_column(PG_UUID(as_uuid=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow)
    client: Mapped["ClientModel"] = relationship(back_populates="projects")
    scans: Mapped[list["ScanModel"]] = relationship(
        back_populates="project", cascade="all, delete-orphan"
    )


class OwnershipProofModel(Base):
    __tablename__ = "ownership_proofs"
    id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), primary_key=True, default=uuid4)
    project_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("projects.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    client_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), nullable=False, index=True)
    domain: Mapped[str] = mapped_column(String(255), nullable=False)
    token: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    token_expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    methods_verified: Mapped[list] = mapped_column(JSONB, default=list)
    is_valid: Mapped[bool] = mapped_column(Boolean, default=False)
    verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow)


class ScanModel(Base):
    __tablename__ = "scans"
    id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), primary_key=True, default=uuid4)
    project_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("projects.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    client_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), nullable=False, index=True)
    type: Mapped[str] = mapped_column(Enum(ScanType, name="scan_type_enum"), nullable=False)
    status: Mapped[str] = mapped_column(
        Enum(ScanStatus, name="scan_status_enum"), default=ScanStatus.PENDING, nullable=False
    )
    language: Mapped[str | None] = mapped_column(
        Enum(SupportedLanguage, name="language_enum"), nullable=True
    )
    input_ref: Mapped[str] = mapped_column(String(512), nullable=False)
    result_ref: Mapped[str | None] = mapped_column(String(512), nullable=True)
    ownership_proof_id: Mapped[UUID | None] = mapped_column(PG_UUID(as_uuid=True), nullable=True)
    initiated_by: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), nullable=False)
    failure_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    project: Mapped["ProjectModel"] = relationship(back_populates="scans")
    findings: Mapped[list["FindingModel"]] = relationship(
        back_populates="scan", cascade="all, delete-orphan"
    )


class FindingModel(Base):
    __tablename__ = "findings"
    id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), primary_key=True, default=uuid4)
    scan_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("scans.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    severity: Mapped[str] = mapped_column(
        Enum(Severity, name="severity_enum"), nullable=False, index=True
    )
    category: Mapped[str] = mapped_column(
        Enum(FindingCategory, name="finding_category_enum"), nullable=False
    )
    lgpd_article: Mapped[str | None] = mapped_column(String(20), nullable=True)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    remediation: Mapped[str] = mapped_column(Text, nullable=False)
    raw_evidence_ref: Mapped[str] = mapped_column(String(512), nullable=False)
    location: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow)
    scan: Mapped["ScanModel"] = relationship(back_populates="findings")


class AuditLogModel(Base):
    __tablename__ = "audit_log"
    id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), primary_key=True, default=uuid4)
    event: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    context: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    integrity_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
