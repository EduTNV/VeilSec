from __future__ import annotations

from datetime import datetime
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, HTTPException, status

from apps.worker_dast.tasks import run_dast_scan
from apps.worker_sast.tasks import run_sast_scan
from packages.domain.dast.ownership import OwnershipVerifier
from packages.domain.entities import Client, Scan
from packages.domain.enums import ScanStatus, ScanType
from packages.domain.exceptions import (
    InsufficientOwnershipProofError,
    OwnershipProofNotFoundError,
    OwnershipTokenExpiredError,
    ScanAccessDeniedError,
    ScanNotFoundError,
)
from packages.infra.database.repositories.ownership import OwnershipRepository
from packages.infra.database.repositories.scan import ScanRepository
from packages.infra.storage.s3 import S3StorageAdapter
from packages.shared.audit import ImmutableAuditLog
from packages.shared.dtos.scan import ScanStatusResponse, SubmitDASTRequest, SubmitSASTRequest
from packages.shared.settings import get_settings

from ..dependencies import (
    get_audit_log,
    get_current_client,
    get_ownership_repo,
    get_scan_repo,
    get_storage,
)

router = APIRouter()
settings = get_settings()


@router.post("/sast", status_code=status.HTTP_202_ACCEPTED)
async def submit_sast(
    body: SubmitSASTRequest,
    client: Client = Depends(get_current_client),
    scan_repo: ScanRepository = Depends(get_scan_repo),
    storage: S3StorageAdapter = Depends(get_storage),
    audit: ImmutableAuditLog = Depends(get_audit_log),
):
    """
    Submete código para análise SAST assíncrona.

    O código é salvo no S3 temporariamente e deletado em 24h.
    O código do usuário é tratado como dado — nunca executável.
    Referência: claude.md — Invariante 4 (Retenção) e Invariante 8 (Input nunca executa)
    """
    scan_id = uuid4()
    input_key = S3StorageAdapter.build_sast_input_key(client.id, scan_id)
    await storage.upload_text(input_key, body.code)
    scan = Scan(
        id=scan_id,
        project_id=body.project_id,
        client_id=client.id,
        type=ScanType.SAST,
        status=ScanStatus.PENDING,
        initiated_by=client.id,
        created_at=datetime.utcnow(),
        input_ref=input_key,
        language=body.language,
    )
    await scan_repo.create(scan)
    run_sast_scan.delay(str(scan_id))
    await audit.log(
        "scan.sast.submitted",
        scan_id=str(scan_id),
        client_id=str(client.id),
        language=body.language.value,
    )
    return {"scan_id": str(scan_id), "status": ScanStatus.PENDING, "message": "Scan SAST iniciado."}


@router.post("/dast", status_code=status.HTTP_202_ACCEPTED)
async def submit_dast(
    body: SubmitDASTRequest,
    client: Client = Depends(get_current_client),
    scan_repo: ScanRepository = Depends(get_scan_repo),
    ownership_repo: OwnershipRepository = Depends(get_ownership_repo),
    storage: S3StorageAdapter = Depends(get_storage),
    audit: ImmutableAuditLog = Depends(get_audit_log),
):
    """
    Submete URL para análise DAST assíncrona.

    Requer OwnershipProof válido e não expirado — sem ele, o scan é rejeitado.
    Valida que o proof pertence ao client solicitante (previne IDOR).
    Referência: claude.md — Invariante 1 (Zero DAST sem Ownership)
    """
    verifier = OwnershipVerifier(repo=ownership_repo, audit=audit)
    try:
        await verifier.assert_valid_for_scan(
            proof_id=body.ownership_proof_id,
            requesting_client_id=client.id,
        )
    except OwnershipProofNotFoundError:
        raise HTTPException(status_code=403, detail="Ownership proof não encontrado.")
    except InsufficientOwnershipProofError as e:
        raise HTTPException(status_code=403, detail=str(e))
    except OwnershipTokenExpiredError:
        raise HTTPException(status_code=403, detail="Ownership proof expirado.")
    except ScanAccessDeniedError:
        raise HTTPException(status_code=403, detail="Acesso negado.")
    scan_id = uuid4()
    input_key = S3StorageAdapter.build_sast_input_key(client.id, scan_id)
    await storage.upload_text(input_key, body.target_url)
    scan = Scan(
        id=scan_id,
        project_id=body.project_id,
        client_id=client.id,
        type=ScanType.DAST,
        status=ScanStatus.PENDING,
        initiated_by=client.id,
        created_at=datetime.utcnow(),
        input_ref=input_key,
        ownership_proof_id=body.ownership_proof_id,
    )
    await scan_repo.create(scan)
    run_dast_scan.delay(str(scan_id))
    await audit.log(
        "scan.dast.submitted",
        scan_id=str(scan_id),
        client_id=str(client.id),
        proof_id=str(body.ownership_proof_id),
    )
    return {"scan_id": str(scan_id), "status": ScanStatus.PENDING, "message": "Scan DAST iniciado."}


@router.get("/{scan_id}", response_model=ScanStatusResponse)
async def get_scan_status(
    scan_id: str,
    client: Client = Depends(get_current_client),
    scan_repo: ScanRepository = Depends(get_scan_repo),
):
    """
    Consulta o status de um scan por ID.

    Valida que o scan pertence ao client autenticado (previne IDOR).
    Referência: claude.md — Invariante 2 (Isolamento de PII)
    """
    try:
        scan = await scan_repo.get_by_id_and_client(UUID(scan_id), client.id)
    except ScanNotFoundError:
        raise HTTPException(status_code=404, detail="Scan não encontrado.")
    except ScanAccessDeniedError:
        raise HTTPException(status_code=403, detail="Acesso negado.")
    return ScanStatusResponse(
        scan_id=scan.id,
        type=scan.type,
        status=scan.status,
        created_at=scan.created_at.isoformat(),
        started_at=scan.started_at.isoformat() if scan.started_at else None,
        finished_at=scan.finished_at.isoformat() if scan.finished_at else None,
        failure_reason=scan.failure_reason,
    )
