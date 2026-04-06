from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional
from uuid import UUID

from .enums import (
    FindingCategory,
    Plan,
    ScanStatus,
    ScanType,
    Severity,
    SupportedLanguage,
    VerificationMethod,
)


@dataclass
class Client:
    id: UUID
    email: str
    api_key_hash: str
    plan: Plan
    created_at: datetime
    lgpd_consent_at: Optional[datetime]
    lgpd_consent_version: Optional[str]

    def has_valid_consent(self, current_version: str) -> bool:
        return self.lgpd_consent_at is not None and self.lgpd_consent_version == current_version


@dataclass
class Project:
    id: UUID
    client_id: UUID
    name: str
    created_at: datetime
    domain: Optional[str] = None
    ownership_verified: bool = False
    ownership_proof_id: Optional[UUID] = None


@dataclass
class OwnershipProof:
    id: UUID
    project_id: UUID
    client_id: UUID
    domain: str
    token: str
    token_expires_at: datetime
    methods_verified: list[VerificationMethod] = field(default_factory=list)
    verified_at: Optional[datetime] = None
    is_valid: bool = False

    def is_expired(self) -> bool:
        return datetime.utcnow() > self.token_expires_at

    def has_sufficient_verification(self) -> bool:
        return len(self.methods_verified) >= 2


@dataclass
class Scan:
    id: UUID
    project_id: UUID
    client_id: UUID
    type: ScanType
    status: ScanStatus
    initiated_by: UUID
    created_at: datetime
    input_ref: str
    language: Optional[SupportedLanguage] = None
    result_ref: Optional[str] = None
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None
    failure_reason: Optional[str] = None
    ownership_proof_id: Optional[UUID] = None


@dataclass
class FindingLocation:
    file: str
    line_start: int
    line_end: int


@dataclass
class Finding:
    id: UUID
    scan_id: UUID
    severity: Severity
    category: FindingCategory
    description: str
    remediation: str
    raw_evidence_ref: str
    lgpd_article: Optional[str] = None
    location: Optional[FindingLocation] = None


@dataclass
class AuditEntry:
    id: UUID
    event: str
    timestamp: datetime
    context: dict
    integrity_hash: str
