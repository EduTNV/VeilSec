from __future__ import annotations

from datetime import datetime, timedelta
from uuid import UUID

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from packages.domain.entities import Finding, FindingLocation, Scan
from packages.domain.enums import FindingCategory, ScanStatus, ScanType, Severity, SupportedLanguage
from packages.domain.exceptions import ScanAccessDeniedError, ScanNotFoundError
from packages.infra.database.models import FindingModel, ScanModel
from packages.shared.settings import get_settings

settings = get_settings()

# Sentinel usado após aplicação da política de retenção (Art. 15 LGPD)
_DELETED_INPUT_REF = "DELETED"


class ScanRepository:
    """
    Repositório de acesso a dados para a entidade Scan.

    Toda query que busca scans por ID DEVE validar o client_id
    como escopo obrigatório para prevenir acesso cruzado entre tenants.
    Referência: claude.md — Invariante 2 (Isolamento de PII)
    """

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    def _to_entity(self, model: ScanModel) -> Scan:
        return Scan(
            id=model.id,
            project_id=model.project_id,
            client_id=model.client_id,
            type=ScanType(model.type),
            status=ScanStatus(model.status),
            initiated_by=model.initiated_by,
            created_at=model.created_at,
            input_ref=model.input_ref,
            language=SupportedLanguage(model.language) if model.language else None,
            result_ref=model.result_ref,
            started_at=model.started_at,
            finished_at=model.finished_at,
            failure_reason=model.failure_reason,
            ownership_proof_id=model.ownership_proof_id,
        )

    async def get_by_id_and_client(self, scan_id: UUID, client_id: UUID | None) -> Scan:
        """
        Busca um scan por ID validando o escopo do tenant.

        Se client_id for informado e não bater com o client_id do scan,
        levanta ScanAccessDeniedError — nunca retorna dados de outro tenant.

        client_id=None é permitido apenas para workers internos que já
        tiveram o escopo validado na camada de API.

        Raises:
            ScanNotFoundError: se o scan não existir
            ScanAccessDeniedError: se client_id não corresponder ao dono do scan
        """
        stmt = select(ScanModel).where(ScanModel.id == scan_id)
        result = await self._session.execute(stmt)
        model = result.scalar_one_or_none()
        if model is None:
            raise ScanNotFoundError(f"Scan {scan_id} não encontrado.")
        if client_id is not None and model.client_id != client_id:
            raise ScanAccessDeniedError("Acesso negado ao scan solicitado.")
        return self._to_entity(model)

    async def create(self, scan: Scan) -> Scan:
        model = ScanModel(
            id=scan.id,
            project_id=scan.project_id,
            client_id=scan.client_id,
            type=scan.type.value,
            status=scan.status.value,
            initiated_by=scan.initiated_by,
            created_at=scan.created_at,
            input_ref=scan.input_ref,
            language=scan.language.value if scan.language else None,
            ownership_proof_id=scan.ownership_proof_id,
        )
        self._session.add(model)
        await self._session.flush()
        return self._to_entity(model)

    async def update_status(
        self,
        scan_id: UUID,
        status: ScanStatus,
        result_ref: str | None = None,
        failure_reason: str | None = None,
    ) -> None:
        values: dict = {"status": status.value}
        if status == ScanStatus.RUNNING:
            values["started_at"] = datetime.utcnow()
        if status in (ScanStatus.DONE, ScanStatus.FAILED, ScanStatus.BLOCKED):
            values["finished_at"] = datetime.utcnow()
        if result_ref:
            values["result_ref"] = result_ref
        if failure_reason:
            values["failure_reason"] = failure_reason
        await self._session.execute(
            update(ScanModel).where(ScanModel.id == scan_id).values(**values)
        )

    async def get_scans_past_retention(self) -> list[Scan]:
        cutoff = datetime.utcnow() - timedelta(hours=settings.scan_retention_hours)
        stmt = select(ScanModel).where(
            ScanModel.created_at < cutoff,
            ScanModel.input_ref.isnot(None),
            ScanModel.input_ref != _DELETED_INPUT_REF,
        )
        result = await self._session.execute(stmt)
        return [self._to_entity(m) for m in result.scalars().all()]

    async def anonymize(self, scan_id: UUID) -> None:
        await self._session.execute(
            update(ScanModel).where(ScanModel.id == scan_id).values(input_ref=_DELETED_INPUT_REF)
        )

    async def save_findings(self, findings: list[Finding]) -> None:
        for f in findings:
            model = FindingModel(
                id=f.id,
                scan_id=f.scan_id,
                severity=f.severity.value,
                category=f.category.value,
                lgpd_article=f.lgpd_article,
                description=f.description,
                remediation=f.remediation,
                raw_evidence_ref=f.raw_evidence_ref,
                location=(
                    {
                        "file": f.location.file,
                        "line_start": f.location.line_start,
                        "line_end": f.location.line_end,
                    }
                    if f.location
                    else None
                ),
            )
            self._session.add(model)
        await self._session.flush()

    async def get_findings(self, scan_id: UUID) -> list[Finding]:
        stmt = select(FindingModel).where(FindingModel.scan_id == scan_id)
        result = await self._session.execute(stmt)
        findings = []
        for m in result.scalars().all():
            location = (
                FindingLocation(
                    file=m.location["file"],
                    line_start=m.location["line_start"],
                    line_end=m.location["line_end"],
                )
                if m.location
                else None
            )
            findings.append(
                Finding(
                    id=m.id,
                    scan_id=m.scan_id,
                    severity=Severity(m.severity),
                    category=FindingCategory(m.category),
                    lgpd_article=m.lgpd_article,
                    description=m.description,
                    remediation=m.remediation,
                    raw_evidence_ref=m.raw_evidence_ref,
                    location=location,
                )
            )
        return findings
