from __future__ import annotations

import hashlib
import secrets
from typing import Protocol
from uuid import UUID

import structlog

from packages.domain.entities import Client
from packages.domain.exceptions import InvalidCredentialsError, LGPDConsentRequiredError

log = structlog.get_logger()


class ClientRepository(Protocol):
    async def find_by_key_hash(self, key_hash: str) -> Client | None: ...
    async def save_api_key(self, key_id: str, key_hash: str, client_id: UUID) -> None: ...
    async def revoke_api_key(self, key_id: str, client_id: UUID) -> None: ...


class AuditLog(Protocol):
    async def log(self, event: str, **context) -> None: ...


class AuthService:
    def __init__(self, repo: ClientRepository, audit: AuditLog, lgpd_consent_version: str) -> None:
        self._repo = repo
        self._audit = audit
        self._lgpd_consent_version = lgpd_consent_version

    def _hash_key(self, raw_key: str) -> str:
        return hashlib.sha256(raw_key.encode()).hexdigest()

    async def create_api_key(self, client_id: UUID) -> tuple[str, str]:
        raw_key = secrets.token_urlsafe(32)
        key_id = f"vsk_{secrets.token_urlsafe(8)}"
        key_hash = self._hash_key(raw_key)
        await self._repo.save_api_key(key_id=key_id, key_hash=key_hash, client_id=client_id)
        await self._audit.log("auth.api_key.created", client_id=str(client_id), key_id=key_id)
        return raw_key, key_id

    async def verify_api_key(self, raw_key: str) -> Client:
        key_hash = self._hash_key(raw_key)
        client = await self._repo.find_by_key_hash(key_hash)
        if client is None:
            await self._audit.log("auth.failed", reason="key_not_found")
            raise InvalidCredentialsError("Credenciais inválidas.")
        if not client.has_valid_consent(self._lgpd_consent_version):
            raise LGPDConsentRequiredError("Consentimento LGPD necessário.")
        await self._audit.log("auth.success", client_id=str(client.id))
        return client

    async def revoke_api_key(self, key_id: str, client: Client) -> None:
        await self._repo.revoke_api_key(key_id=key_id, client_id=client.id)
        await self._audit.log("auth.api_key.revoked", client_id=str(client.id), key_id=key_id)
