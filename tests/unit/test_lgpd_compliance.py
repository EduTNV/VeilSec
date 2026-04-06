from __future__ import annotations

from unittest.mock import AsyncMock
from uuid import uuid4

import pytest

from packages.domain.lgpd.compliance import LGPDComplianceService
from tests.conftest import make_scan


@pytest.fixture
def lgpd_service(mock_audit):
    repo = AsyncMock()
    storage = AsyncMock()
    return LGPDComplianceService(repo=repo, storage=storage, audit=mock_audit), repo, storage


@pytest.mark.asyncio
async def test_enforce_retention_deletes_expired_inputs(lgpd_service):
    service, repo, storage = lgpd_service
    expired_scan = make_scan()
    expired_scan.input_ref = "clients/x/scans/y/input.txt"
    repo.get_scans_past_retention = AsyncMock(return_value=[expired_scan])
    repo.anonymize_scan = AsyncMock()
    await service.enforce_retention_policy()
    storage.delete.assert_called_once_with(expired_scan.input_ref)
    repo.anonymize_scan.assert_called_once_with(expired_scan.id)


@pytest.mark.asyncio
async def test_export_client_data_returns_complete_data(lgpd_service):
    service, repo, storage = lgpd_service
    client_id = uuid4()
    repo.get_client_full_data = AsyncMock(return_value={"id": str(client_id)})
    result = await service.export_client_data(client_id)
    assert "client" in result
    assert "audit_events" in result
    assert "exported_at" in result


@pytest.mark.asyncio
async def test_delete_client_data_logs_event(lgpd_service, mock_audit):
    service, repo, storage = lgpd_service
    repo.anonymize_client = AsyncMock()
    storage.delete_all_for_client = AsyncMock()
    await service.delete_client_data(uuid4())
    mock_audit.log.assert_called_once()
    assert mock_audit.log.call_args[0][0] == "lgpd.client.deleted"
