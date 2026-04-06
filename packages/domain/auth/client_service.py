from __future__ import annotations

from datetime import datetime
from typing import Protocol
from uuid import UUID, uuid4

import bcrypt
import structlog

from packages.domain.entities import Client
from packages.domain.exceptions import LGPDConsentRequiredError

log = structlog.get_logger(__name__)


class ClientRepository(Protocol):
    async def find_by_id(self, client_id: UUID) -> Client | None: ...


class SessionProtocol(Protocol):
    """Protocolo mínimo para operações de sessão do SQLAlchemy."""

    def add(self, instance) -> None: ...
    async def execute(self, statement) -> any: ...
    async def flush(self) -> None: ...


class ClientService:
    """
    Serviço de domínio para operações de ciclo de vida do Client.

    Responsável por registro, hashing de senha e gestão de consentimento LGPD.
    A senha nunca é armazenada em texto claro — apenas o bcrypt hash.
    Referência: claude.md — Invariante 5 (Consentimento LGPD) e Invariante 6 (Segredos)
    """

    def __init__(self, session, lgpd_consent_version: str) -> None:
        self._session = session
        self._lgpd_consent_version = lgpd_consent_version

    async def register(
        self,
        email: str,
        password: str,
        lgpd_consent: bool,
    ) -> Client:
        """
        Registra novo cliente com consentimento LGPD.

        Invariante: lgpd_consent=False levanta LGPDConsentRequiredError.
        A senha é hasheada com bcrypt antes da persistência.
        Referência: claude.md — Invariante 5

        Raises:
            LGPDConsentRequiredError: se lgpd_consent for False
            EmailAlreadyExistsError: se email já cadastrado
        """
        from sqlalchemy import select

        from packages.infra.database.models import ClientModel

        if not lgpd_consent:
            raise LGPDConsentRequiredError("Consentimento LGPD é obrigatório.")
        existing = await self._session.execute(
            select(ClientModel).where(ClientModel.email == email)
        )
        if existing.scalar_one_or_none():
            from packages.domain.exceptions import VeilSecError

            raise VeilSecError("Email já cadastrado.")
        password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
        client = ClientModel(
            id=uuid4(),
            email=email,
            password_hash=password_hash,
            lgpd_consent_at=datetime.utcnow(),
            lgpd_consent_version=self._lgpd_consent_version,
        )
        self._session.add(client)
        await self._session.flush()
        return client

    async def update_consent(self, client_id: UUID, consent_version: str) -> None:
        """
        Atualiza o consentimento LGPD de um cliente existente.

        Referência: claude.md — Invariante 5 (Consentimento LGPD)
        """
        from sqlalchemy import update

        from packages.infra.database.models import ClientModel

        await self._session.execute(
            update(ClientModel)
            .where(ClientModel.id == client_id)
            .values(lgpd_consent_at=datetime.utcnow(), lgpd_consent_version=consent_version)
        )
