from __future__ import annotations

from datetime import datetime
from typing import Protocol
from uuid import UUID

import structlog

log = structlog.get_logger()


class LGPDRepository(Protocol):
    async def get_scans_past_retention(self) -> list: ...
    async def anonymize_scan(self, scan_id: UUID) -> None: ...
    async def anonymize_client(self, client_id: UUID) -> None: ...
    async def get_client_full_data(self, client_id: UUID) -> dict: ...


class StorageAdapter(Protocol):
    async def delete(self, ref: str) -> None: ...
    async def delete_all_for_client(self, client_id: UUID) -> None: ...


class AuditLog(Protocol):
    async def log(self, event: str, **context) -> None: ...
    async def get_client_events(self, client_id: UUID) -> list: ...


class LGPDComplianceService:
    def __init__(self, repo: LGPDRepository, storage: StorageAdapter, audit: AuditLog) -> None:
        self._repo = repo
        self._storage = storage
        self._audit = audit

    async def enforce_retention_policy(self) -> None:
        expired = await self._repo.get_scans_past_retention()
        for scan in expired:
            await self._storage.delete(scan.input_ref)
            await self._repo.anonymize_scan(scan.id)
            await self._audit.log("lgpd.retention.enforced", scan_id=str(scan.id))
        log.info("lgpd.retention.cycle.done", expired_count=len(expired))

    async def export_client_data(self, client_id: UUID) -> dict:
        data = await self._repo.get_client_full_data(client_id)
        audit_events = await self._audit.get_client_events(client_id)
        await self._audit.log("lgpd.data.exported", client_id=str(client_id))
        return {
            "exported_at": datetime.utcnow().isoformat(),
            "client": data,
            "audit_events": audit_events,
        }

    async def delete_client_data(self, client_id: UUID) -> None:
        await self._storage.delete_all_for_client(client_id)
        await self._repo.anonymize_client(client_id)
        await self._audit.log(
            "lgpd.client.deleted",
            client_id=str(client_id),
            deleted_at=datetime.utcnow().isoformat(),
        )
