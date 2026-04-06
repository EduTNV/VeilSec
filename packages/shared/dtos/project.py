from __future__ import annotations

from datetime import datetime
from typing import Optional
from uuid import UUID

from pydantic import BaseModel, Field, field_validator


class CreateProjectRequest(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    domain: Optional[str] = Field(default=None)

    @field_validator("domain")
    @classmethod
    def validate_domain(cls, v: str | None) -> str | None:
        if v is None:
            return v
        v = v.replace("https://", "").replace("http://", "").rstrip("/")
        return v or None


class ProjectResponse(BaseModel):
    id: UUID
    name: str
    domain: Optional[str]
    ownership_verified: bool
    created_at: datetime


class OwnershipChallengeResponse(BaseModel):
    proof_id: UUID
    token: str
    expires_at: datetime
    instructions: dict

    @classmethod
    def build(
        cls, proof_id: UUID, token: str, expires_at: datetime, domain: str
    ) -> "OwnershipChallengeResponse":
        return cls(
            proof_id=proof_id,
            token=token,
            expires_at=expires_at,
            instructions={
                "dns_txt": {
                    "method": "DNS_TXT",
                    "record": f"_aegis-verify.{domain}",
                    "value": f"aegis-ownership={token}",
                },
                "well_known": {
                    "method": "WELL_KNOWN",
                    "url": f"https://{domain}/.well-known/aegis-security.txt",
                    "content": token,
                },
                "http_header": {
                    "method": "HTTP_HEADER",
                    "header": "X-Aegis-Ownership",
                    "value": token,
                },
            },
        )


class OwnershipStatusResponse(BaseModel):
    is_valid: bool
    methods_verified: list[str]
    verified_at: Optional[datetime]
    message: str
