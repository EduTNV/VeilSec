from __future__ import annotations

from datetime import datetime
from uuid import UUID, uuid4

import structlog

from packages.domain.ai.layer4_validator import OutputValidator
from packages.domain.entities import Finding, FindingLocation
from packages.domain.enums import FindingCategory, ScanStatus, Severity
from packages.domain.exceptions import (
    InputTooLargeError,
    LLMOutputValidationError,
    LLMUnavailableError,
    SecurityViolationError,
)
from packages.infra.ai.anthropic import AnthropicLLM
from packages.infra.ai.classifier import InjectionClassifier
from packages.infra.database.repositories.scan import ScanRepository
from packages.infra.storage.s3 import S3StorageAdapter
from packages.shared.audit import ImmutableAuditLog
from packages.shared.settings import get_settings

from .ast_parser import ASTParser
from .taint import TaintAnalyzer

settings = get_settings()
log = structlog.get_logger(__name__)


class SASTOrchestrator:
    """
    Orquestrador do pipeline SAST em 4 camadas.

    Executa o fluxo completo: Input → Camada 1 (AST/Taint) → Camada 2 (Classificador)
    → Camada 3 (LLM) → Camada 4 (Validação de output).

    Nenhum input cru chega ao LLM — todo dado passa pelo sanitizador AST
    e pelo classificador de injeção antes de ser enviado à Camada 3.
    Referência: claude.md — Invariante 3 (Pipeline de IA Rigorosa)
    """

    def __init__(
        self,
        scan_repo: ScanRepository,
        storage: S3StorageAdapter,
        llm: AnthropicLLM,
        classifier: InjectionClassifier,
        audit: ImmutableAuditLog,
    ) -> None:
        self._scan_repo = scan_repo
        self._storage = storage
        self._llm = llm
        self._classifier = classifier
        self._audit = audit
        self._ast_parser = ASTParser()
        self._taint_analyzer = TaintAnalyzer()

    async def run(self, scan_id: UUID) -> dict:
        """
        Executa o pipeline SAST completo para um scan.

        Fluxo:
          1. Download do código fonte (input_ref no S3)
          2. Camada 1 — Parse AST + análise de taint para fluxos PII
          3. Camada 2 — Classificador de injeção (bloqueia se score > threshold)
          4. Camada 3 — Análise LLM (Claude/GPT fallback)
          5. Camada 4 — Validação do output do LLM contra schema esperado
          6. Persistência dos findings e cleanup do input (retenção 24h)

        Raises:
            SecurityViolationError: input bloqueado pela Camada 2
            InputTooLargeError: código excede o limite de 500KB
            LLMUnavailableError: LLM principal e fallback indisponíveis
            LLMOutputValidationError: output do LLM não passa na Camada 4
        """
        scan = await self._scan_repo.get_by_id_and_client(scan_id, None)
        await self._scan_repo.update_status(scan_id, ScanStatus.RUNNING)
        await self._audit.log("sast.scan.running", scan_id=str(scan_id))
        try:
            code = await self._storage.download_text(scan.input_ref)
            if len(code.encode()) > settings.sast_max_input_bytes:
                raise InputTooLargeError("Input excede 500KB.")
            ast_data = self._ast_parser.parse(code=code, language=scan.language)
            pii_flows = self._taint_analyzer.find_pii_flows(ast_data)
            if not pii_flows:
                await self._storage.delete(scan.input_ref)
                await self._scan_repo.update_status(scan_id, ScanStatus.DONE)
                return {"status": "done", "findings": 0}
            subgraphs = self._taint_analyzer.build_subgraphs(pii_flows)
            injection_score = await self._classifier.score(subgraphs)
            if injection_score > settings.ai_classifier_threshold:
                await self._audit.log(
                    "security.injection_blocked", scan_id=str(scan_id), score=injection_score
                )
                raise SecurityViolationError(
                    f"Input bloqueado pela Camada 2 (score={injection_score:.2f})."
                )
            raw_output = await self._llm.analyze(subgraphs)
            findings = self._parse_and_validate(raw_output, scan_id)
            await self._scan_repo.save_findings(findings)
            report_key = S3StorageAdapter.build_sast_report_key(scan.client_id, scan_id)
            await self._storage.upload_json(
                report_key,
                {
                    "scan_id": str(scan_id),
                    "findings_count": len(findings),
                    "generated_at": datetime.utcnow().isoformat(),
                },
            )
            await self._storage.delete(scan.input_ref)
            await self._scan_repo.update_status(scan_id, ScanStatus.DONE, result_ref=report_key)
            await self._audit.log(
                "sast.scan.done", scan_id=str(scan_id), findings_count=len(findings)
            )
            return {"status": "done", "findings": len(findings)}
        except SecurityViolationError:
            raise
        except (LLMUnavailableError, LLMOutputValidationError) as e:
            log.error("sast.scan.error.llm", scan_id=str(scan_id), error=str(e))
            await self._scan_repo.update_status(scan_id, ScanStatus.FAILED, failure_reason=str(e))
            await self._audit.log("sast.scan.failed", scan_id=str(scan_id), error=type(e).__name__)
            raise
        except InputTooLargeError as e:
            log.warning("sast.scan.error.input", scan_id=str(scan_id), error=str(e))
            await self._scan_repo.update_status(scan_id, ScanStatus.FAILED, failure_reason=str(e))
            await self._audit.log("sast.scan.failed", scan_id=str(scan_id), error=type(e).__name__)
            raise
        except Exception as e:
            log.error(
                "sast.scan.error.unexpected",
                scan_id=str(scan_id),
                error=str(e),
                error_type=type(e).__name__,
            )
            await self._scan_repo.update_status(scan_id, ScanStatus.FAILED, failure_reason=str(e))
            await self._audit.log("sast.scan.failed", scan_id=str(scan_id), error=type(e).__name__)
            raise

    def _parse_and_validate(self, raw_output: str, scan_id: UUID) -> list[Finding]:
        """
        Camada 4 — Valida o output do LLM contra o schema esperado.

        Garante que o LLM não retornou dados malformados ou alucinações.
        Cada finding validado é convertido para a entidade de domínio.

        Raises:
            LLMOutputValidationError: se o output não seguir o schema JSON esperado
        """
        validator = OutputValidator()
        try:
            parsed = validator.parse(raw_output)
        except LLMOutputValidationError as e:
            log.error("sast.layer4.schema_violation", scan_id=str(scan_id), error=str(e))
            raise
        findings = []
        for f in parsed.findings:
            location = (
                FindingLocation(file="submitted_code", line_start=f.line_start, line_end=f.line_end)
                if f.line_start
                else None
            )
            findings.append(
                Finding(
                    id=uuid4(),
                    scan_id=scan_id,
                    severity=Severity(f.severity),
                    category=FindingCategory(f.category),
                    lgpd_article=f.lgpd_article,
                    description=f.description,
                    remediation=f.remediation,
                    raw_evidence_ref="redacted",
                    location=location,
                )
            )
        return findings
