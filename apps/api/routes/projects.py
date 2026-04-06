from __future__ import annotations

from datetime import datetime
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from packages.domain.dast.ownership import OwnershipVerifier
from packages.domain.entities import Client
from packages.domain.exceptions import (
    InsufficientOwnershipProofError,
    OwnershipProofNotFoundError,
    OwnershipTokenExpiredError,
)
from packages.infra.database.connection import get_session
from packages.infra.database.models import ProjectModel
from packages.infra.database.repositories.ownership import OwnershipRepository
from packages.shared.audit import ImmutableAuditLog
from packages.shared.dtos.project import (
    CreateProjectRequest,
    OwnershipChallengeResponse,
    OwnershipStatusResponse,
    ProjectResponse,
)

from ..dependencies import get_audit_log, get_current_client, get_ownership_repo

router = APIRouter()


@router.post("", response_model=ProjectResponse, status_code=status.HTTP_201_CREATED)
async def create_project(
    body: CreateProjectRequest,
    client: Client = Depends(get_current_client),
    session: AsyncSession = Depends(get_session),
    audit: ImmutableAuditLog = Depends(get_audit_log),
):
    """
    Cria um novo projeto associado ao cliente autenticado.

    O projeto pode opcionalmente incluir um domínio para DAST.
    O client_id é inferido da autenticação — nunca do body.
    Referência: claude.md — Invariante 2 (Isolamento de PII)
    """
    project = ProjectModel(
        id=uuid4(),
        client_id=client.id,
        name=body.name,
        domain=body.domain,
        created_at=datetime.utcnow(),
    )
    session.add(project)
    await session.flush()
    await audit.log("project.created", client_id=str(client.id), project_id=str(project.id))
    return ProjectResponse(
        id=project.id,
        name=project.name,
        domain=project.domain,
        ownership_verified=project.ownership_verified,
        created_at=project.created_at,
    )


@router.post("/{project_id}/verify-ownership")
async def start_ownership_verification(
    project_id: str,
    client: Client = Depends(get_current_client),
    session: AsyncSession = Depends(get_session),
    ownership_repo: OwnershipRepository = Depends(get_ownership_repo),
    audit: ImmutableAuditLog = Depends(get_audit_log),
):
    """
    Inicia o processo de verificação de ownership de um domínio.

    Gera um challenge (token) que o cliente deve colocar em:
    - DNS TXT record
    - .well-known/aegis-security.txt
    - HTTP header X-Aegis-Ownership

    Pelo menos 2 de 3 métodos devem ser verificados.
    Referência: claude.md — Invariante 1 (Zero DAST sem Ownership)
    """
    result = await session.execute(
        select(ProjectModel).where(
            ProjectModel.id == project_id, ProjectModel.client_id == client.id
        )
    )
    project = result.scalar_one_or_none()
    if not project:
        raise HTTPException(status_code=404, detail="Projeto não encontrado.")
    if not project.domain:
        raise HTTPException(status_code=422, detail="Projeto não possui domínio configurado.")
    verifier = OwnershipVerifier(repo=ownership_repo, audit=audit)
    proof = await verifier.generate_challenge(
        domain=project.domain, client=client, project_id=project.id
    )
    return OwnershipChallengeResponse.build(
        proof_id=proof.id,
        token=proof.token,
        expires_at=proof.token_expires_at,
        domain=project.domain,
    )


@router.get("/{project_id}/verify-ownership/status")
async def check_ownership_status(
    project_id: str,
    proof_id: str,
    client: Client = Depends(get_current_client),
    ownership_repo: OwnershipRepository = Depends(get_ownership_repo),
    audit: ImmutableAuditLog = Depends(get_audit_log),
):
    """
    Verifica o status de um challenge de ownership previamente criado.

    Tenta verificar os 3 métodos (DNS, .well-known, HTTP header)
    e retorna o resultado. Requer pelo menos 2 de 3 para validar.
    Referência: claude.md — Invariante 1 (Zero DAST sem Ownership)
    """
    verifier = OwnershipVerifier(repo=ownership_repo, audit=audit)
    try:
        is_valid = await verifier.verify(UUID(proof_id))
        proof = await ownership_repo.get(UUID(proof_id))
        return OwnershipStatusResponse(
            is_valid=is_valid,
            methods_verified=[m.value for m in proof.methods_verified],
            verified_at=proof.verified_at,
            message="Ownership verificado com sucesso.",
        )
    except OwnershipProofNotFoundError as e:
        return OwnershipStatusResponse(
            is_valid=False, methods_verified=[], verified_at=None, message=str(e)
        )
    except OwnershipTokenExpiredError as e:
        return OwnershipStatusResponse(
            is_valid=False, methods_verified=[], verified_at=None, message=str(e)
        )
    except InsufficientOwnershipProofError as e:
        return OwnershipStatusResponse(
            is_valid=False, methods_verified=[], verified_at=None, message=str(e)
        )
