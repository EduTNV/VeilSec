from __future__ import annotations

from datetime import datetime
from uuid import UUID

import httpx
import structlog

from packages.domain.enums import ScanStatus
from packages.domain.exceptions import (
    ConsecutiveErrorsExceededError,
    InsufficientOwnershipProofError,
    OwnershipTokenExpiredError,
    TargetDegradationDetectedError,
)
from packages.infra.cache.redis import TokenBucketRedis
from packages.infra.database.repositories.ownership import OwnershipRepository
from packages.infra.database.repositories.scan import ScanRepository
from packages.infra.storage.s3 import S3StorageAdapter
from packages.shared.audit import ImmutableAuditLog

from .runner import DASTRunner

log = structlog.get_logger(__name__)


class DASTOrchestrator:
    """
    Orquestrador do pipeline DAST com verificação Zero Trust de ownership.

    Antes de qualquer interação com o alvo, valida que o OwnershipProof
    está presente, válido e não expirado. Sem ownership verificado,
    nenhum payload é disparado contra o target.

    O rate limiting adaptativo (Token Bucket) protege o alvo de degradação.
    Referência: claude.md — Invariante 1 (Zero DAST sem Ownership)
    """

    def __init__(
        self,
        scan_repo: ScanRepository,
        ownership_repo: OwnershipRepository,
        storage: S3StorageAdapter,
        audit: ImmutableAuditLog,
        redis,
    ) -> None:
        self._scan_repo = scan_repo
        self._ownership_repo = ownership_repo
        self._storage = storage
        self._audit = audit
        self._redis = redis

    async def run(self, scan_id: UUID) -> dict:
        """
        Executa o pipeline DAST completo para um scan.

        Fluxo:
          1. Validação do OwnershipProof (is_valid + não expirado)
          2. Download da URL alvo (input_ref no S3)
          3. Medição de baseline do tempo de resposta
          4. Disparo de payloads com rate limiting adaptativo
          5. Persistência dos findings e cleanup do input

        Raises:
            InsufficientOwnershipProofError: proof inválido
            OwnershipTokenExpiredError: proof expirado
            TargetDegradationDetectedError: alvo degradou durante o scan
            ConsecutiveErrorsExceededError: muitos erros consecutivos
        """
        scan = await self._scan_repo.get_by_id_and_client(scan_id, None)
        proof = await self._ownership_repo.get(scan.ownership_proof_id)
        if not proof.is_valid:
            await self._scan_repo.update_status(
                scan_id, ScanStatus.FAILED, failure_reason="Ownership proof inválido."
            )
            raise InsufficientOwnershipProofError("Ownership inválido.")
        if proof.is_expired():
            await self._scan_repo.update_status(
                scan_id, ScanStatus.FAILED, failure_reason="Ownership proof expirado."
            )
            raise OwnershipTokenExpiredError("Ownership expirado.")
        await self._scan_repo.update_status(scan_id, ScanStatus.RUNNING)
        await self._audit.log("dast.scan.running", scan_id=str(scan_id))
        try:
            target_url = (await self._storage.download_text(scan.input_ref)).strip()
            bucket = TokenBucketRedis(self._redis, scan_id)
            runner = DASTRunner(
                scan_id=scan_id, client_id=scan.client_id, bucket=bucket, storage=self._storage
            )
            baseline_ms = await runner.measure_baseline(target_url)
            findings = await runner.run_all_payloads(target_url)
            if findings:
                await self._scan_repo.save_findings(findings)
            report_key = S3StorageAdapter.build_sast_report_key(scan.client_id, scan_id)
            await self._storage.upload_json(
                report_key,
                {
                    "scan_id": str(scan_id),
                    "findings_count": len(findings),
                    "baseline_ms": baseline_ms,
                    "generated_at": datetime.utcnow().isoformat(),
                },
            )
            await self._storage.delete(scan.input_ref)
            await self._scan_repo.update_status(scan_id, ScanStatus.DONE, result_ref=report_key)
            await self._audit.log(
                "dast.scan.done", scan_id=str(scan_id), findings_count=len(findings)
            )
            return {"status": "done", "findings": len(findings)}
        except (TargetDegradationDetectedError, ConsecutiveErrorsExceededError) as e:
            log.warning("dast.scan.target_error", scan_id=str(scan_id), error=str(e))
            await self._scan_repo.update_status(
                scan_id, ScanStatus.FAILED, failure_reason=str(e)[:500]
            )
            await self._audit.log("dast.scan.failed", scan_id=str(scan_id), error=type(e).__name__)
            raise
        except httpx.RequestError as e:
            log.error("dast.scan.network_error", scan_id=str(scan_id), error=str(e))
            await self._scan_repo.update_status(
                scan_id, ScanStatus.FAILED, failure_reason=str(e)[:500]
            )
            await self._audit.log("dast.scan.failed", scan_id=str(scan_id), error=type(e).__name__)
            raise
        except Exception as e:
            log.error(
                "dast.scan.error.unexpected",
                scan_id=str(scan_id),
                error=str(e),
                error_type=type(e).__name__,
            )
            await self._scan_repo.update_status(
                scan_id, ScanStatus.FAILED, failure_reason=str(e)[:500]
            )
            await self._audit.log("dast.scan.failed", scan_id=str(scan_id), error=type(e).__name__)
            raise
