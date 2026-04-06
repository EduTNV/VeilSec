from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status

from packages.domain.auth.client_service import ClientService
from packages.domain.auth.service import AuthService
from packages.domain.entities import Client
from packages.domain.exceptions import LGPDConsentRequiredError, VeilSecError
from packages.shared.audit import ImmutableAuditLog
from packages.shared.dtos.auth import (
    ConsentRequest,
    CreateAPIKeyResponse,
    RegisterRequest,
    RegisterResponse,
    RevokeAPIKeyResponse,
)

from ..dependencies import get_audit_log, get_auth_service, get_client_service, get_current_client

router = APIRouter()


@router.post("/register", response_model=RegisterResponse, status_code=status.HTTP_201_CREATED)
async def register(
    body: RegisterRequest,
    client_service: ClientService = Depends(get_client_service),
    audit: ImmutableAuditLog = Depends(get_audit_log),
):
    """
    Registra um novo cliente com consentimento LGPD obrigatório.

    A senha é hasheada com bcrypt antes da persistência.
    Referência: claude.md — Invariante 5 (Consentimento LGPD) e Invariante 6 (Segredos)
    """
    try:
        client = await client_service.register(
            email=body.email,
            password=body.password,
            lgpd_consent=body.lgpd_consent,
        )
    except LGPDConsentRequiredError:
        raise HTTPException(status_code=422, detail="Consentimento LGPD é obrigatório.")
    except VeilSecError as e:
        raise HTTPException(status_code=409, detail=str(e))
    await audit.log(
        "auth.client.registered",
        client_id=str(client.id),
    )
    return RegisterResponse(client_id=str(client.id))


@router.post("/api-keys", response_model=CreateAPIKeyResponse)
async def create_api_key(
    client: Client = Depends(get_current_client), auth: AuthService = Depends(get_auth_service)
):
    """
    Gera uma nova API key para o cliente autenticado.

    A key é retornada em texto claro APENAS nesta resposta.
    Após isso, somente o hash SHA-256 é armazenado.
    Referência: claude.md — Invariante 6 (Segredos)
    """
    raw_key, key_id = await auth.create_api_key(client.id)
    return CreateAPIKeyResponse(raw_key=raw_key, key_id=key_id)


@router.delete("/api-keys/{key_id}", response_model=RevokeAPIKeyResponse)
async def revoke_api_key(
    key_id: str,
    client: Client = Depends(get_current_client),
    auth: AuthService = Depends(get_auth_service),
):
    """Revoga uma API key existente do cliente autenticado."""
    await auth.revoke_api_key(key_id, client)
    return RevokeAPIKeyResponse(key_id=key_id)


@router.post("/consent")
async def update_consent(
    body: ConsentRequest,
    client: Client = Depends(get_current_client),
    client_service: ClientService = Depends(get_client_service),
    audit: ImmutableAuditLog = Depends(get_audit_log),
):
    """
    Atualiza o consentimento LGPD do cliente autenticado.

    Referência: claude.md — Invariante 5 (Consentimento LGPD)
    """
    if not body.lgpd_consent:
        raise HTTPException(
            status_code=422, detail="Consentimento não pode ser negado por este endpoint."
        )
    await client_service.update_consent(client.id, body.consent_version)
    await audit.log("lgpd.consent.updated", client_id=str(client.id), version=body.consent_version)
    return {"message": "Consentimento atualizado com sucesso."}
