from __future__ import annotations

import time
from dataclasses import dataclass
from uuid import UUID, uuid4

import httpx
import structlog

from packages.domain.entities import Finding
from packages.domain.enums import FindingCategory, Severity
from packages.domain.exceptions import (
    ConsecutiveErrorsExceededError,
    TargetDegradationDetectedError,
)
from packages.infra.cache.redis import TokenBucketRedis
from packages.infra.storage.s3 import S3StorageAdapter

from .payloads import Payload, PayloadCategory, get_all_payloads

log = structlog.get_logger(__name__)

SEVERITY_MAP = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
}
CATEGORY_MAP = {
    PayloadCategory.XSS: FindingCategory.INJECTION,
    PayloadCategory.SQLI: FindingCategory.INJECTION,
    PayloadCategory.PATH_TRAVERSAL: FindingCategory.SENSITIVE_EXPOSURE,
    PayloadCategory.PROMPT_INJECTION: FindingCategory.INJECTION,
    PayloadCategory.SSRF: FindingCategory.SENSITIVE_EXPOSURE,
    PayloadCategory.OPEN_REDIRECT: FindingCategory.SENSITIVE_EXPOSURE,
    PayloadCategory.HEADER_INJECTION: FindingCategory.INJECTION,
}


@dataclass
class PayloadResult:
    payload: Payload
    status_code: int
    response_time_ms: float
    response_snippet: str
    is_vulnerable: bool
    evidence: str


class DASTRunner:
    def __init__(
        self, scan_id: UUID, client_id: UUID, bucket: TokenBucketRedis, storage: S3StorageAdapter
    ) -> None:
        self._scan_id = scan_id
        self._client_id = client_id
        self._bucket = bucket
        self._storage = storage

    async def measure_baseline(self, target_url: str) -> float:
        import asyncio
        import statistics

        times = []
        async with httpx.AsyncClient(
            timeout=10.0,
            follow_redirects=False,
            headers={"User-Agent": "VeilSec-Scanner/0.1 (security-audit)"},
        ) as client:
            for i in range(5):
                try:
                    start = time.monotonic()
                    await client.head(target_url)
                    times.append((time.monotonic() - start) * 1000)
                    await asyncio.sleep(1)
                except httpx.RequestError:
                    pass
        if not times:
            raise RuntimeError("Não foi possível conectar ao alvo.")
        baseline = statistics.median(times)
        await self._bucket.initialize(baseline)
        log.info("dast.baseline.measured", baseline_ms=round(baseline, 2))
        return baseline

    async def run_all_payloads(self, target_url: str) -> list[Finding]:
        findings = []
        async with httpx.AsyncClient(
            timeout=10.0,
            follow_redirects=False,
            headers={"User-Agent": "VeilSec-Scanner/0.1 (security-audit)"},
            verify=True,
        ) as client:
            for payload in get_all_payloads():
                try:
                    result = await self._fire_payload(client, target_url, payload)
                    if result.is_vulnerable:
                        findings.append(await self._build_finding(result))
                        await self._bucket.record_success()
                except (TargetDegradationDetectedError, ConsecutiveErrorsExceededError) as e:
                    log.warning("dast.stopped", scan_id=str(self._scan_id), reason=str(e))
                    break
                except httpx.RequestError as e:
                    await self._bucket.record_error()
                    log.warning(
                        "dast.request_error", payload_category=payload.category, error=str(e)
                    )
        await self._bucket.cleanup()
        return findings

    async def _fire_payload(
        self, client: httpx.AsyncClient, target_url: str, payload: Payload
    ) -> PayloadResult:
        start = time.monotonic()
        response = await client.get(
            target_url,
            params={"q": payload.value, "input": payload.value},
            headers={"X-Test-Input": payload.value[:100]},
        )
        elapsed_ms = (time.monotonic() - start) * 1000
        await self._bucket.acquire(elapsed_ms)
        snippet = response.text[:200] if response.text else ""
        return PayloadResult(
            payload=payload,
            status_code=response.status_code,
            response_time_ms=elapsed_ms,
            response_snippet=snippet,
            is_vulnerable=self._detect_vulnerability(payload, response.status_code, response.text),
            evidence=(
                f"Status: {response.status_code} | "
                f"Time: {elapsed_ms:.0f}ms | "
                f"Snippet: {snippet[:100]}"
            ),
        )

    def _detect_vulnerability(self, payload: Payload, status_code: int, response_body: str) -> bool:
        body_lower = response_body.lower()
        if payload.category == PayloadCategory.XSS:
            return payload.value.lower() in body_lower
        if payload.category == PayloadCategory.SQLI:
            return any(
                e in body_lower
                for e in ["sql syntax", "mysql error", "ora-", "pg error", "sqlite", "syntax error"]
            )
        if payload.category == PayloadCategory.PATH_TRAVERSAL:
            return "root:x:" in response_body or "bin/bash" in response_body
        if payload.category == PayloadCategory.SSRF:
            return status_code == 200 and ("ami-id" in body_lower or "instance-id" in body_lower)
        if payload.category == PayloadCategory.PROMPT_INJECTION:
            return any(
                i in body_lower
                for i in [
                    "system prompt",
                    "instructions",
                    "openai",
                    "anthropic",
                    "i will now",
                    "maintenance mode",
                ]
            )
        if payload.category == PayloadCategory.OPEN_REDIRECT:
            return (
                status_code in (301, 302, 303, 307, 308)
                and "evil.veilsec-test.com" in response_body
            )
        return False

    async def _build_finding(self, result: PayloadResult) -> Finding:
        finding_id = uuid4()
        evidence_key = S3StorageAdapter.build_dast_evidence_key(
            self._client_id, self._scan_id, finding_id
        )
        await self._storage.upload_json(
            evidence_key,
            {
                "payload_category": result.payload.category,
                "status_code": result.status_code,
                "response_time_ms": result.response_time_ms,
                "evidence": result.evidence,
            },
        )
        lgpd_map = {
            PayloadCategory.SQLI: "Art. 46",
            PayloadCategory.XSS: "Art. 46",
            PayloadCategory.PATH_TRAVERSAL: "Art. 46",
            PayloadCategory.SSRF: "Art. 46",
            PayloadCategory.PROMPT_INJECTION: "Art. 46",
        }
        remediation_map = {
            PayloadCategory.XSS: (
                "Sanitize e escape todo output HTML. " "Use Content-Security-Policy."
            ),
            PayloadCategory.SQLI: (
                "Use prepared statements. " "Nunca concatene input em queries SQL."
            ),
            PayloadCategory.PATH_TRAVERSAL: (
                "Valide e normalize caminhos. " "Use allowlist de diretórios."
            ),
            PayloadCategory.SSRF: ("Bloqueie IPs internos e metadata endpoints. " "Use allowlist."),
            PayloadCategory.PROMPT_INJECTION: (
                "Nunca passe input direto ao LLM. " "Use delimitadores e schema validation."
            ),
            PayloadCategory.OPEN_REDIRECT: (
                "Use allowlist de URLs. " "Nunca redirecione para URLs do usuário."
            ),
            PayloadCategory.HEADER_INJECTION: (
                "Sanitize headers removendo CRLF. " "Valide todos os valores."
            ),
        }
        return Finding(
            id=finding_id,
            scan_id=self._scan_id,
            severity=SEVERITY_MAP.get(result.payload.severity, Severity.MEDIUM),
            category=CATEGORY_MAP.get(result.payload.category, FindingCategory.INJECTION),
            lgpd_article=lgpd_map.get(result.payload.category),
            description=result.payload.description,
            remediation=remediation_map.get(
                result.payload.category, "Consulte o relatório completo."
            ),
            raw_evidence_ref=evidence_key,
        )
