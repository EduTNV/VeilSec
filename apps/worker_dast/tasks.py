from __future__ import annotations

import asyncio
from uuid import UUID

import structlog
from celery import Task

from packages.domain.enums import ScanStatus
from packages.domain.exceptions import (
    ConsecutiveErrorsExceededError,
    InsufficientOwnershipProofError,
    OwnershipProofNotFoundError,
    OwnershipTokenExpiredError,
    TargetDegradationDetectedError,
)
from packages.infra.cache.redis import get_redis
from packages.infra.database.connection import get_db_session
from packages.infra.database.repositories.audit import AuditRepository
from packages.infra.database.repositories.ownership import OwnershipRepository
from packages.infra.database.repositories.scan import ScanRepository
from packages.infra.storage.s3 import S3StorageAdapter
from packages.shared.audit import ImmutableAuditLog
from packages.shared.logging import setup_logging
from packages.shared.settings import get_settings

from .pipeline.orchestrator import DASTOrchestrator
from .worker import celery_app

settings = get_settings()
log = structlog.get_logger(__name__)


class DASTTask(Task):
    """
    Classe base para tasks DAST com retry automático.

    Faz retry com backoff exponencial (máx 2x, jitter habilitado)
    para falhas transitórias. Ownership errors não sofrem retry —
    são falhas de validação intencional (Invariante 1).
    """

    autoretry_for = (Exception,)
    max_retries = 2
    retry_backoff = True
    retry_backoff_max = 120
    retry_jitter = True


async def _build_orchestrator(session) -> DASTOrchestrator:
    """Constrói o orquestrador DAST com todas as dependências injetadas."""
    return DASTOrchestrator(
        scan_repo=ScanRepository(session),
        ownership_repo=OwnershipRepository(session),
        storage=S3StorageAdapter(),
        audit=ImmutableAuditLog(AuditRepository(session)),
        redis=await get_redis(),
    )


@celery_app.task(bind=True, base=DASTTask, name="apps.worker_dast.tasks.run_dast_scan")
def run_dast_scan(self, scan_id: str) -> dict:
    """
    Entry point Celery para execução assíncrona do pipeline DAST.

    Requer OwnershipProof válido e não expirado — sem ele, o scan
    é rejeitado antes de qualquer interação com o alvo.
    Referência: claude.md — Invariante 1 (Zero DAST sem Ownership)
    """
    setup_logging(settings.environment)
    log.info("dast.task.started", scan_id=scan_id)
    try:
        result = asyncio.get_event_loop().run_until_complete(_run_async(scan_id))
        log.info("dast.task.completed", scan_id=scan_id)
        return result
    except (
        InsufficientOwnershipProofError,
        OwnershipTokenExpiredError,
        OwnershipProofNotFoundError,
    ) as e:
        log.warning("dast.task.ownership_error", scan_id=scan_id, error=str(e))
        asyncio.get_event_loop().run_until_complete(_mark_failed(scan_id, str(e)))
        raise
    except (TargetDegradationDetectedError, ConsecutiveErrorsExceededError) as e:
        log.warning("dast.task.target_error", scan_id=scan_id, error=str(e))
        asyncio.get_event_loop().run_until_complete(_mark_failed(scan_id, str(e)))
        raise
    except Exception as e:
        log.error(
            "dast.task.error.unexpected",
            scan_id=scan_id,
            error=str(e),
            error_type=type(e).__name__,
        )
        asyncio.get_event_loop().run_until_complete(_mark_failed(scan_id, str(e)))
        raise


async def _run_async(scan_id: str) -> dict:
    """Executa o pipeline DAST dentro de um contexto async com sessão de banco."""
    async with get_db_session() as session:
        orchestrator = await _build_orchestrator(session)
        return await orchestrator.run(UUID(scan_id))


async def _mark_failed(scan_id: str, reason: str) -> None:
    """Marca o scan como FAILED persistindo o motivo da falha (truncado a 500 chars)."""
    async with get_db_session() as session:
        await ScanRepository(session).update_status(
            UUID(scan_id), ScanStatus.FAILED, failure_reason=reason[:500]
        )
