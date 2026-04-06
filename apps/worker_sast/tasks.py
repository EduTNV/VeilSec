from __future__ import annotations

import asyncio
from uuid import UUID

import structlog
from celery import Task

from packages.domain.enums import ScanStatus
from packages.domain.exceptions import (
    InputTooLargeError,
    LLMOutputValidationError,
    LLMUnavailableError,
    SecurityViolationError,
)
from packages.infra.ai.anthropic import AnthropicLLM
from packages.infra.ai.classifier import InjectionClassifier
from packages.infra.database.connection import get_db_session
from packages.infra.database.repositories.audit import AuditRepository
from packages.infra.database.repositories.scan import ScanRepository
from packages.infra.storage.s3 import S3StorageAdapter
from packages.shared.audit import ImmutableAuditLog
from packages.shared.logging import setup_logging
from packages.shared.settings import get_settings

from .pipeline.orchestrator import SASTOrchestrator
from .worker import celery_app

settings = get_settings()
log = structlog.get_logger(__name__)


class SASTTask(Task):
    """
    Classe base para tasks SAST com retry automático.

    Faz retry com backoff exponencial (máx 3x, jitter habilitado)
    para falhas transitórias. SecurityViolationError é tratado
    fora do autoretry — bloqueios da Camada 2 são intencionais.
    """

    autoretry_for = (Exception,)
    max_retries = 3
    retry_backoff = True
    retry_backoff_max = 60
    retry_jitter = True


def _build_orchestrator(session) -> SASTOrchestrator:
    """Constrói o orquestrador SAST com todas as dependências injetadas."""
    return SASTOrchestrator(
        scan_repo=ScanRepository(session),
        storage=S3StorageAdapter(),
        llm=AnthropicLLM(),
        classifier=InjectionClassifier(),
        audit=ImmutableAuditLog(AuditRepository(session)),
    )


@celery_app.task(bind=True, base=SASTTask, name="apps.worker_sast.tasks.run_sast_scan")
def run_sast_scan(self, scan_id: str) -> dict:
    """
    Entry point Celery para execução assíncrona do pipeline SAST.

    Não faz retry em SecurityViolationError — bloqueio intencional da Camada 2.
    Faz retry automático (máx 3x) para falhas transitórias.
    """
    setup_logging(settings.environment)
    log.info("sast.task.started", scan_id=scan_id)
    try:
        result = asyncio.get_event_loop().run_until_complete(_run_async(scan_id))
        log.info("sast.task.completed", scan_id=scan_id)
        return result
    except SecurityViolationError as e:
        log.warning("sast.task.blocked", scan_id=scan_id, reason=str(e))
        asyncio.get_event_loop().run_until_complete(_mark_blocked(scan_id, str(e)))
        return {"status": "blocked", "reason": str(e)}
    except (LLMUnavailableError, LLMOutputValidationError) as e:
        log.error("sast.task.error.llm", scan_id=scan_id, error=str(e))
        raise
    except InputTooLargeError as e:
        log.warning("sast.task.error.input", scan_id=scan_id, error=str(e))
        raise
    except Exception as e:
        log.error(
            "sast.task.error.unexpected",
            scan_id=scan_id,
            error=str(e),
            error_type=type(e).__name__,
        )
        raise


async def _run_async(scan_id: str) -> dict:
    """Executa o pipeline SAST dentro de um contexto async com sessão de banco."""
    async with get_db_session() as session:
        orchestrator = _build_orchestrator(session)
        return await orchestrator.run(UUID(scan_id))


async def _mark_blocked(scan_id: str, reason: str) -> None:
    """Marca o scan como BLOCKED quando a Camada 2 rejeita o input."""
    async with get_db_session() as session:
        await ScanRepository(session).update_status(
            UUID(scan_id), ScanStatus.BLOCKED, failure_reason=reason
        )
