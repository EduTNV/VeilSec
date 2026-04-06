from __future__ import annotations

from typing import Optional
from uuid import UUID

from pydantic import BaseModel

from packages.domain.enums import FindingCategory, Severity


class FindingLocationDTO(BaseModel):
    file: str
    line_start: int
    line_end: int


class FindingDTO(BaseModel):
    id: UUID
    severity: Severity
    category: FindingCategory
    lgpd_article: Optional[str]
    description: str
    remediation: str
    location: Optional[FindingLocationDTO]


class ReportSummary(BaseModel):
    total_findings: int
    critical: int
    high: int
    medium: int
    low: int
    overall_risk: Severity

    @classmethod
    def from_findings(cls, findings: list[FindingDTO]) -> "ReportSummary":
        counts = {s: 0 for s in Severity}
        for f in findings:
            counts[f.severity] += 1
        if counts[Severity.CRITICAL] > 0:
            overall = Severity.CRITICAL
        elif counts[Severity.HIGH] > 0:
            overall = Severity.HIGH
        elif counts[Severity.MEDIUM] > 0:
            overall = Severity.MEDIUM
        else:
            overall = Severity.LOW
        return cls(
            total_findings=len(findings),
            critical=counts[Severity.CRITICAL],
            high=counts[Severity.HIGH],
            medium=counts[Severity.MEDIUM],
            low=counts[Severity.LOW],
            overall_risk=overall,
        )


class ReportResponse(BaseModel):
    scan_id: UUID
    summary: ReportSummary
    findings: list[FindingDTO]
    lgpd_articles_violated: list[str]
    generated_at: str

    @classmethod
    def build(
        cls, scan_id: UUID, findings: list[FindingDTO], generated_at: str
    ) -> "ReportResponse":
        return cls(
            scan_id=scan_id,
            summary=ReportSummary.from_findings(findings),
            findings=sorted(findings, key=lambda f: list(Severity).index(f.severity)),
            lgpd_articles_violated=sorted({f.lgpd_article for f in findings if f.lgpd_article}),
            generated_at=generated_at,
        )
