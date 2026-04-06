from __future__ import annotations

import asyncio
import hashlib
import hmac
import time
from datetime import datetime, timedelta
from typing import Protocol
from uuid import UUID, uuid4

import httpx
import structlog

from packages.domain.entities import Client, OwnershipProof
from packages.domain.enums import VerificationMethod
from packages.domain.exceptions import (
    InsufficientOwnershipProofError,
    OwnershipTokenExpiredError,
    ScanAccessDeniedError,
)
from packages.shared.settings import get_settings

settings = get_settings()
log = structlog.get_logger(__name__)


class OwnershipRepository(Protocol):
    async def get(self, proof_id: UUID) -> OwnershipProof: ...
    async def save(self, proof: OwnershipProof) -> None: ...


class AuditLog(Protocol):
    async def log(self, event: str, **context) -> None: ...


class OwnershipVerifier:
    def __init__(self, repo: OwnershipRepository, audit: AuditLog) -> None:
        self._repo = repo
        self._audit = audit

    def _generate_token(self, client_id: UUID, domain: str) -> str:
        msg = f"{client_id}:{domain}:{int(time.time())}"
        return hmac.new(
            key=settings.ownership_hmac_secret.encode(), msg=msg.encode(), digestmod=hashlib.sha256
        ).hexdigest()

    async def generate_challenge(
        self, domain: str, client: Client, project_id: UUID
    ) -> OwnershipProof:
        token = self._generate_token(client.id, domain)
        proof = OwnershipProof(
            id=uuid4(),
            project_id=project_id,
            client_id=client.id,
            domain=domain,
            token=token,
            token_expires_at=datetime.utcnow() + timedelta(hours=settings.dast_ownership_ttl_hours),
        )
        await self._repo.save(proof)
        await self._audit.log(
            "ownership.challenge.created",
            client_id=str(client.id),
            domain=domain,
            proof_id=str(proof.id),
        )
        return proof

    async def verify(self, proof_id: UUID) -> bool:
        proof = await self._repo.get(proof_id)
        if proof.is_expired():
            raise OwnershipTokenExpiredError("Token de ownership expirado.")
        results = await asyncio.gather(
            self._check_dns(proof),
            self._check_well_known(proof),
            self._check_header(proof),
            return_exceptions=True,
        )
        verified = [
            i
            for i, r in enumerate(
                [
                    VerificationMethod.DNS_TXT,
                    VerificationMethod.WELL_KNOWN,
                    VerificationMethod.HTTP_HEADER,
                ]
            )
            if results[i] is True
        ]
        if len(verified) < 2:
            raise InsufficientOwnershipProofError("Menos de 2 métodos verificados.")
        proof.methods_verified = [
            VerificationMethod.DNS_TXT,
            VerificationMethod.WELL_KNOWN,
            VerificationMethod.HTTP_HEADER,
        ][: len(verified)]
        proof.is_valid = True
        proof.verified_at = datetime.utcnow()
        await self._repo.save(proof)
        await self._audit.log("ownership.verified", proof_id=str(proof_id), domain=proof.domain)
        return True

    async def assert_valid_for_scan(
        self,
        proof_id: UUID,
        requesting_client_id: UUID,
    ) -> OwnershipProof:
        """
        Valida que o proof está apto para iniciar um scan DAST.

        Verifica 4 condições na ordem:
          1. Proof existe (OwnershipProofNotFoundError via repo.get)
          2. Proof é válido (is_valid == True)
          3. Proof não está expirado
          4. Proof pertence ao client solicitante (previne IDOR)

        Referência: claude.md — Invariante 1 (Zero DAST sem Ownership)

        Raises:
            OwnershipProofNotFoundError: se o proof não existir
            InsufficientOwnershipProofError: se proof não está válido
            OwnershipTokenExpiredError: se proof expirou
            ScanAccessDeniedError: se client_id não bate (IDOR)
        """
        proof = await self._repo.get(proof_id)
        if not proof.is_valid:
            raise InsufficientOwnershipProofError(
                "Ownership proof inválido. Complete a verificação antes do DAST."
            )
        if proof.is_expired():
            raise OwnershipTokenExpiredError("Ownership proof expirado.")
        if proof.client_id != requesting_client_id:
            await self._audit.log(
                "security.idor_attempt",
                client_id=str(requesting_client_id),
                proof_owner=str(proof.client_id),
            )
            raise ScanAccessDeniedError("Acesso negado ao ownership proof.")
        return proof

    async def _check_dns(self, proof: OwnershipProof) -> bool:
        try:
            import dns.resolver

            answers = dns.resolver.resolve(f"_aegis-verify.{proof.domain}", "TXT")
            for r in answers:
                if f"aegis-ownership={proof.token}" in str(r):
                    return True
        except Exception:
            pass
        return False

    async def _check_well_known(self, proof: OwnershipProof) -> bool:
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                resp = await client.get(f"https://{proof.domain}/.well-known/aegis-security.txt")
                return proof.token in resp.text
        except Exception:
            return False

    async def _check_header(self, proof: OwnershipProof) -> bool:
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                resp = await client.head(f"https://{proof.domain}")
                return resp.headers.get("X-Aegis-Ownership") == proof.token
        except Exception:
            return False
