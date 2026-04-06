from __future__ import annotations

from fastapi import Depends, Header, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from packages.domain.auth.client_service import ClientService
from packages.domain.auth.service import AuthService
from packages.domain.entities import Client
from packages.domain.exceptions import InvalidCredentialsError, LGPDConsentRequiredError
from packages.infra.ai.anthropic import AnthropicLLM
from packages.infra.ai.classifier import InjectionClassifier
from packages.infra.database.connection import get_session
from packages.infra.database.repositories.audit import AuditRepository
from packages.infra.database.repositories.client import ClientRepository
from packages.infra.database.repositories.ownership import OwnershipRepository
from packages.infra.database.repositories.scan import ScanRepository
from packages.infra.storage.s3 import S3StorageAdapter
from packages.shared.audit import ImmutableAuditLog
from packages.shared.settings import get_settings

settings = get_settings()


async def get_client_repo(session: AsyncSession = Depends(get_session)) -> ClientRepository:
    return ClientRepository(session)


async def get_scan_repo(session: AsyncSession = Depends(get_session)) -> ScanRepository:
    return ScanRepository(session)


async def get_ownership_repo(session: AsyncSession = Depends(get_session)) -> OwnershipRepository:
    return OwnershipRepository(session)


async def get_audit_log(session: AsyncSession = Depends(get_session)) -> ImmutableAuditLog:
    return ImmutableAuditLog(AuditRepository(session))


async def get_auth_service(
    repo: ClientRepository = Depends(get_client_repo),
    audit: ImmutableAuditLog = Depends(get_audit_log),
) -> AuthService:
    return AuthService(repo=repo, audit=audit, lgpd_consent_version=settings.lgpd_consent_version)


async def get_storage() -> S3StorageAdapter:
    return S3StorageAdapter()


async def get_client_service(
    session: AsyncSession = Depends(get_session),
) -> ClientService:
    return ClientService(session=session, lgpd_consent_version=settings.lgpd_consent_version)


async def get_llm() -> AnthropicLLM:
    return AnthropicLLM()


async def get_classifier() -> InjectionClassifier:
    return InjectionClassifier()


async def get_current_client(
    x_api_key: str = Header(..., description="API Key no formato vsk_..."),
    auth: AuthService = Depends(get_auth_service),
) -> Client:
    try:
        return await auth.verify_api_key(x_api_key)
    except LGPDConsentRequiredError as e:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(e))
    except InvalidCredentialsError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Credenciais inválidas.",
            headers={"WWW-Authenticate": "ApiKey"},
        )
