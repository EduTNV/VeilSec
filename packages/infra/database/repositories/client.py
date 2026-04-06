from __future__ import annotations

from uuid import UUID

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from packages.domain.entities import Client
from packages.domain.enums import Plan
from packages.infra.database.models import ClientModel

# Sentinel para campos de hash após anonimização LGPD (Art. 18, VI)
_DELETED_HASH = "DELETED"


class ClientRepository:
    """
    Repositório de acesso a dados para a entidade Client.

    API keys são armazenadas exclusivamente como hash SHA-256.
    Nenhum método deste repositório retorna ou persiste a key em texto claro.
    Referência: claude.md — Invariante 6 (Gestão de Segredos)
    """

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    def _to_entity(self, model: ClientModel) -> Client:
        return Client(
            id=model.id,
            email=model.email,
            api_key_hash=model.api_key_hash or "",
            plan=Plan(model.plan),
            created_at=model.created_at,
            lgpd_consent_at=model.lgpd_consent_at,
            lgpd_consent_version=model.lgpd_consent_version,
        )

    async def find_by_key_hash(self, key_hash: str) -> Client | None:
        """
        Busca um client pelo hash SHA-256 da API key.

        A key original nunca é recebida nem armazenada — apenas o hash é comparado.
        Keys revogadas são automaticamente excluídas da busca.
        """
        stmt = select(ClientModel).where(
            ClientModel.api_key_hash == key_hash, ClientModel.api_key_revoked.is_(False)
        )
        result = await self._session.execute(stmt)
        model = result.scalar_one_or_none()
        return self._to_entity(model) if model else None

    async def find_by_id(self, client_id: UUID) -> Client | None:
        stmt = select(ClientModel).where(ClientModel.id == client_id)
        result = await self._session.execute(stmt)
        model = result.scalar_one_or_none()
        return self._to_entity(model) if model else None

    async def save_api_key(self, key_id: str, key_hash: str, client_id: UUID) -> None:
        stmt = (
            update(ClientModel)
            .where(ClientModel.id == client_id)
            .values(api_key_id=key_id, api_key_hash=key_hash, api_key_revoked=False)
        )
        await self._session.execute(stmt)

    async def revoke_api_key(self, key_id: str, client_id: UUID) -> None:
        stmt = (
            update(ClientModel)
            .where(ClientModel.api_key_id == key_id, ClientModel.id == client_id)
            .values(api_key_revoked=True)
        )
        await self._session.execute(stmt)

    async def anonymize(self, client_id: UUID) -> None:
        stmt = (
            update(ClientModel)
            .where(ClientModel.id == client_id)
            .values(
                email=f"deleted_{client_id}@anonymized.veilsec",
                password_hash=_DELETED_HASH,
                api_key_hash=None,
                api_key_id=None,
                lgpd_consent_at=None,
            )
        )
        await self._session.execute(stmt)
