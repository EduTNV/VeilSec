from __future__ import annotations

from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from packages.domain.entities import OwnershipProof
from packages.domain.enums import VerificationMethod
from packages.domain.exceptions import OwnershipProofNotFoundError
from packages.infra.database.models import OwnershipProofModel


class OwnershipRepository:
    """
    Repositório de acesso a dados para OwnershipProof.

    Proofs expirados ou inválidos nunca são retornados como válidos.
    A validação de expiração é responsabilidade do domínio (OwnershipProof.is_expired()),
    mas este repositório nunca silencia um proof não encontrado — sempre levanta exceção.
    Referência: claude.md — Invariante 1 (Zero DAST sem Ownership)
    """

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    def _to_entity(self, m: OwnershipProofModel) -> OwnershipProof:
        return OwnershipProof(
            id=m.id,
            project_id=m.project_id,
            client_id=m.client_id,
            domain=m.domain,
            token=m.token,
            token_expires_at=m.token_expires_at,
            methods_verified=[VerificationMethod(v) for v in (m.methods_verified or [])],
            verified_at=m.verified_at,
            is_valid=m.is_valid,
        )

    async def get(self, proof_id: UUID) -> OwnershipProof:
        """
        Busca um OwnershipProof por ID.

        Se o proof não existir, levanta OwnershipProofNotFoundError.
        Nunca retorna None — a ausência de proof é sempre um erro explícito.

        Raises:
            OwnershipProofNotFoundError: se o proof não existir no banco
        """
        stmt = select(OwnershipProofModel).where(OwnershipProofModel.id == proof_id)
        result = await self._session.execute(stmt)
        model = result.scalar_one_or_none()
        if not model:
            raise OwnershipProofNotFoundError(f"Proof {proof_id} não encontrado.")
        return self._to_entity(model)

    async def save(self, proof: OwnershipProof) -> None:
        stmt = select(OwnershipProofModel).where(OwnershipProofModel.id == proof.id)
        result = await self._session.execute(stmt)
        model = result.scalar_one_or_none()
        if model is None:
            model = OwnershipProofModel(
                id=proof.id,
                project_id=proof.project_id,
                client_id=proof.client_id,
                domain=proof.domain,
                token=proof.token,
                token_expires_at=proof.token_expires_at,
            )
            self._session.add(model)
        model.methods_verified = [m.value for m in proof.methods_verified]
        model.is_valid = proof.is_valid
        model.verified_at = proof.verified_at
        await self._session.flush()
