from __future__ import annotations

from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from packages.domain.entities import AuditEntry
from packages.infra.database.models import AuditLogModel


class AuditRepository:
    """
    Repositório append-only para o AuditLog imutável.

    Este repositório possui APENAS o método insert().
    Não existe e nunca deve existir método de update ou delete nesta classe.
    A constraint append-only é enforced também via trigger no PostgreSQL.
    Referência: claude.md — Invariante 7 (Audit Log Imutável)
    """

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def insert(self, entry: AuditEntry) -> None:
        """
        Persiste uma entrada imutável no audit log.

        Este é o ÚNICO método de escrita disponível neste repositório.
        Não existe update() nem delete() por design — o audit log é append-only.
        """
        model = AuditLogModel(
            id=entry.id,
            event=entry.event,
            context=entry.context,
            integrity_hash=entry.integrity_hash,
            timestamp=entry.timestamp,
        )
        self._session.add(model)
        await self._session.flush()

    async def get_by_client(self, client_id: UUID) -> list[AuditEntry]:
        stmt = (
            select(AuditLogModel)
            .where(AuditLogModel.context["client_id"].as_string() == str(client_id))
            .order_by(AuditLogModel.timestamp.asc())
        )
        result = await self._session.execute(stmt)
        return [
            AuditEntry(
                id=m.id,
                event=m.event,
                timestamp=m.timestamp,
                context=m.context,
                integrity_hash=m.integrity_hash,
            )
            for m in result.scalars().all()
        ]
