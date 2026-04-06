from __future__ import annotations

import json
from typing import Literal

import structlog
from pydantic import BaseModel, Field, ValidationError

from packages.domain.exceptions import LLMOutputValidationError

log = structlog.get_logger(__name__)


class SASTFinding(BaseModel):
    rule_id: str = Field(pattern=r"^LGPD-\d{3}$")
    severity: Literal["low", "medium", "high", "critical"]
    lgpd_article: str = Field(max_length=20)
    category: str
    description: str = Field(max_length=500)
    remediation: str = Field(max_length=300)
    line_start: int | None = None
    line_end: int | None = None


class SASTOutput(BaseModel):
    findings: list[SASTFinding] = Field(max_length=50)
    lgpd_articles: list[str]
    severity: Literal["low", "medium", "high", "critical"]


class OutputValidator:
    def parse(self, raw_output: str) -> SASTOutput:
        try:
            data = json.loads(raw_output)
            return SASTOutput(**data)
        except (json.JSONDecodeError, ValidationError, Exception) as e:
            log.error("layer4.schema_violation", error=str(e))
            raise LLMOutputValidationError(str(e)) from e
