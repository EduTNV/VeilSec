from __future__ import annotations

import asyncio
from datetime import datetime
from typing import AsyncGenerator
from unittest.mock import AsyncMock
from uuid import uuid4

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from packages.domain.entities import Client, OwnershipProof, Project, Scan
from packages.domain.enums import Plan, ScanStatus, ScanType, SupportedLanguage, VerificationMethod

TEST_DATABASE_URL = "sqlite+aiosqlite:///:memory:"
test_engine = create_async_engine(TEST_DATABASE_URL, echo=False)
TestSessionFactory = async_sessionmaker(
    bind=test_engine, class_=AsyncSession, expire_on_commit=False, autoflush=False
)


@pytest.fixture(scope="session")
def event_loop():
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


@pytest_asyncio.fixture(scope="function")
async def db_session() -> AsyncGenerator[AsyncSession, None]:
    from packages.infra.database.connection import Base

    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    async with TestSessionFactory() as session:
        yield session
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)


def make_client(lgpd_consent: bool = True, plan: Plan = Plan.FREE) -> Client:
    return Client(
        id=uuid4(),
        email=f"test_{uuid4().hex[:8]}@veilsec.test",
        api_key_hash="abc123hash",
        plan=plan,
        created_at=datetime.utcnow(),
        lgpd_consent_at=datetime.utcnow() if lgpd_consent else None,
        lgpd_consent_version="1.0" if lgpd_consent else None,
    )


def make_project(client_id=None, domain: str | None = None) -> Project:
    return Project(
        id=uuid4(),
        client_id=client_id or uuid4(),
        name="Projeto Teste",
        created_at=datetime.utcnow(),
        domain=domain,
    )


def make_ownership_proof(
    client_id=None,
    domain: str = "test.veilsec.com",
    is_valid: bool = True,
    methods: list | None = None,
    expired: bool = False,
) -> OwnershipProof:
    from datetime import timedelta

    return OwnershipProof(
        id=uuid4(),
        project_id=uuid4(),
        client_id=client_id or uuid4(),
        domain=domain,
        token="valid-hmac-token-abc123",
        token_expires_at=(
            datetime.utcnow() - timedelta(hours=1)
            if expired
            else datetime.utcnow() + timedelta(hours=23)
        ),
        methods_verified=methods or [VerificationMethod.DNS_TXT, VerificationMethod.WELL_KNOWN],
        is_valid=is_valid,
        verified_at=datetime.utcnow() if is_valid else None,
    )


def make_scan(
    client_id=None,
    scan_type: ScanType = ScanType.SAST,
    status: ScanStatus = ScanStatus.PENDING,
    ownership_proof_id=None,
) -> Scan:
    return Scan(
        id=uuid4(),
        project_id=uuid4(),
        client_id=client_id or uuid4(),
        type=scan_type,
        status=status,
        initiated_by=client_id or uuid4(),
        created_at=datetime.utcnow(),
        input_ref=f"clients/{uuid4()}/scans/{uuid4()}/input.txt",
        language=SupportedLanguage.PYTHON,
        ownership_proof_id=ownership_proof_id,
    )


@pytest.fixture
def mock_audit() -> AsyncMock:
    audit = AsyncMock()
    audit.log = AsyncMock()
    audit.get_client_events = AsyncMock(return_value=[])
    return audit


@pytest.fixture
def mock_storage() -> AsyncMock:
    storage = AsyncMock()
    storage.upload_text = AsyncMock(return_value="s3://bucket/key")
    storage.upload_json = AsyncMock(return_value="s3://bucket/key")
    storage.download_text = AsyncMock(return_value="def foo(): pass")
    storage.delete = AsyncMock()
    storage.delete_all_for_client = AsyncMock()
    return storage


_MOCK_LLM_RESPONSE = (
    '{"findings": ['
    '{"rule_id": "LGPD-001", '
    '"severity": "high", '
    '"lgpd_article": "Art. 46", '
    '"category": "PII_LEAK", '
    '"description": "PII exposto em log.", '
    '"remediation": "Remova PII dos logs.", '
    '"line_start": 3, '
    '"line_end": 3}], '
    '"lgpd_articles": ["Art. 46"], '
    '"severity": "high"}'
)


@pytest.fixture
def mock_llm() -> AsyncMock:
    llm = AsyncMock()
    llm.analyze = AsyncMock(return_value=_MOCK_LLM_RESPONSE)
    return llm


@pytest.fixture
def mock_classifier() -> AsyncMock:
    classifier = AsyncMock()
    classifier.score = AsyncMock(return_value=0.05)
    return classifier


@pytest_asyncio.fixture
async def api_client() -> AsyncGenerator[AsyncClient, None]:
    from apps.api.main import app

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        yield client
