from __future__ import annotations

import hashlib
from unittest.mock import AsyncMock
from uuid import uuid4

import pytest

from packages.domain.auth.service import AuthService
from packages.domain.exceptions import InvalidCredentialsError, LGPDConsentRequiredError
from tests.conftest import make_client


@pytest.fixture
def auth_service(mock_audit):
    repo = AsyncMock()
    return AuthService(repo=repo, audit=mock_audit, lgpd_consent_version="1.0"), repo


@pytest.mark.asyncio
async def test_create_api_key_returns_raw_and_id(auth_service):
    service, repo = auth_service
    repo.save_api_key = AsyncMock()
    raw_key, key_id = await service.create_api_key(uuid4())
    assert raw_key
    assert key_id.startswith("vsk_")
    repo.save_api_key.assert_called_once()


@pytest.mark.asyncio
async def test_api_key_never_stored_raw(auth_service):
    service, repo = auth_service
    captured = {}

    async def capture_save(**kwargs):
        captured.update(kwargs)

    repo.save_api_key = capture_save
    raw_key, _ = await service.create_api_key(uuid4())
    assert raw_key not in str(captured.values())
    assert captured["key_hash"] == hashlib.sha256(raw_key.encode()).hexdigest()


@pytest.mark.asyncio
async def test_verify_valid_key_returns_client(auth_service):
    service, repo = auth_service
    client = make_client(lgpd_consent=True)
    repo.find_by_key_hash = AsyncMock(return_value=client)
    result = await service.verify_api_key("valid-raw-key")
    assert result.id == client.id


@pytest.mark.asyncio
async def test_verify_invalid_key_raises(auth_service):
    service, repo = auth_service
    repo.find_by_key_hash = AsyncMock(return_value=None)
    with pytest.raises(InvalidCredentialsError):
        await service.verify_api_key("invalid-key")


@pytest.mark.asyncio
async def test_verify_key_without_lgpd_consent_raises(auth_service):
    service, repo = auth_service
    client = make_client(lgpd_consent=False)
    repo.find_by_key_hash = AsyncMock(return_value=client)
    with pytest.raises(LGPDConsentRequiredError):
        await service.verify_api_key("valid-key")
