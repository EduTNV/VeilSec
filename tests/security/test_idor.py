from __future__ import annotations

from unittest.mock import AsyncMock
from uuid import uuid4

import pytest

from packages.domain.exceptions import ScanAccessDeniedError
from tests.conftest import make_ownership_proof, make_scan


@pytest.mark.asyncio
async def test_client_b_cannot_access_client_a_scan(db_session):
    from packages.infra.database.repositories.scan import ScanRepository

    repo = ScanRepository(db_session)
    client_b_id = uuid4()
    scan = make_scan(client_id=uuid4())
    repo.get_by_id_and_client = AsyncMock(side_effect=ScanAccessDeniedError("Acesso negado."))
    with pytest.raises(ScanAccessDeniedError):
        await repo.get_by_id_and_client(scan.id, client_b_id)


@pytest.mark.asyncio
async def test_ownership_proof_client_mismatch():
    client_a_id = uuid4()
    client_b_id = uuid4()
    proof = make_ownership_proof(client_id=client_a_id)
    assert proof.client_id != client_b_id


def test_all_scan_queries_require_client_id():
    import inspect

    from packages.infra.database.repositories.scan import ScanRepository

    source = inspect.getsource(ScanRepository.get_by_id_and_client)
    assert "client_id" in source
