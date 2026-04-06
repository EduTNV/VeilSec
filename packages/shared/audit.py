from __future__ import annotations

import hashlib
import json
from datetime import datetime
from typing import Protocol
from uuid import UUID, uuid4

import structlog

from packages.domain.entities import AuditEntry

log = structlog.get_logger(__name__)


class AuditRepository(Protocol):
    async def insert(self, entry: AuditEntry) -> None: ...
    async def get_by_client(self, client_id: UUID) -> list[AuditEntry]: ...


class ImmutableAuditLog:
    def __init__(self, repo: AuditRepository) -> None:
        self._repo = repo

    def _compute_hash(self, event: str, context: dict) -> str:
        payload = json.dumps(
            {"event": event, "context": context}, sort_keys=True, ensure_ascii=True
        )
        return hashlib.sha256(payload.encode()).hexdigest()

    async def log(self, event: str, **context) -> None:
        entry = AuditEntry(
            id=uuid4(),
            event=event,
            timestamp=datetime.utcnow(),
            context=context,
            integrity_hash=self._compute_hash(event, context),
        )
        await self._repo.insert(entry)
        log.debug("audit.entry.created", event=event, entry_id=str(entry.id))

    async def get_client_events(self, client_id: UUID) -> list[dict]:
        entries = await self._repo.get_by_client(client_id)
        return [
            {
                "id": str(e.id),
                "event": e.event,
                "timestamp": e.timestamp.isoformat(),
                "context": e.context,
            }
            for e in entries
        ]
