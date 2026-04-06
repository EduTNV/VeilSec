from __future__ import annotations

from datetime import datetime
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException

from packages.domain.entities import Client
from packages.domain.enums import ScanStatus
from packages.domain.exceptions import ScanAccessDeniedError, ScanNotFoundError
from packages.infra.database.repositories.scan import ScanRepository
from packages.shared.dtos.report import FindingDTO, FindingLocationDTO, ReportResponse

from ..dependencies import get_current_client, get_scan_repo

router = APIRouter()


@router.get("/{scan_id}", response_model=ReportResponse)
async def get_report(
    scan_id: str,
    client: Client = Depends(get_current_client),
    scan_repo: ScanRepository = Depends(get_scan_repo),
):
    """
    Retorna o relatório de findings de um scan concluído.

    Valida que o scan pertence ao client autenticado (previne IDOR).
    O relatório só é disponibilizado quando o scan está em status DONE.
    Referência: claude.md — Invariante 2 (Isolamento de PII)
    """
    try:
        scan = await scan_repo.get_by_id_and_client(UUID(scan_id), client.id)
    except ScanNotFoundError:
        raise HTTPException(status_code=404, detail="Scan não encontrado.")
    except ScanAccessDeniedError:
        raise HTTPException(status_code=403, detail="Acesso negado.")
    if scan.status != ScanStatus.DONE:
        raise HTTPException(
            status_code=409, detail=f"Relatório não disponível. Status: {scan.status.value}"
        )
    findings_raw = await scan_repo.get_findings(scan.id)
    findings_dto = [
        FindingDTO(
            id=f.id,
            severity=f.severity,
            category=f.category,
            lgpd_article=f.lgpd_article,
            description=f.description,
            remediation=f.remediation,
            location=(
                FindingLocationDTO(
                    file=f.location.file,
                    line_start=f.location.line_start,
                    line_end=f.location.line_end,
                )
                if f.location
                else None
            ),
        )
        for f in findings_raw
    ]
    return ReportResponse.build(
        scan_id=scan.id, findings=findings_dto, generated_at=datetime.utcnow().isoformat()
    )
