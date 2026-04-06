from __future__ import annotations

from typing import Optional
from uuid import UUID

from pydantic import BaseModel, Field, field_validator

from packages.domain.enums import ScanStatus, ScanType, SupportedLanguage


class SubmitSASTRequest(BaseModel):
    project_id: UUID
    code: str = Field(min_length=1)
    language: SupportedLanguage = SupportedLanguage.PYTHON

    @field_validator("code")
    @classmethod
    def validate_code_size(cls, v: str) -> str:
        if len(v.encode("utf-8")) > 500_000:
            raise ValueError("Código excede o limite de 500KB.")
        return v


class SubmitDASTRequest(BaseModel):
    project_id: UUID
    target_url: str
    ownership_proof_id: UUID

    @field_validator("target_url")
    @classmethod
    def validate_url(cls, v: str) -> str:
        if not v.startswith(("http://", "https://")):
            raise ValueError("URL deve começar com http:// ou https://")
        return v


class ScanStatusResponse(BaseModel):
    scan_id: UUID
    type: ScanType
    status: ScanStatus
    created_at: str
    started_at: Optional[str]
    finished_at: Optional[str]
    failure_reason: Optional[str] = None
