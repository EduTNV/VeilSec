from __future__ import annotations

import pytest

from packages.domain.enums import VerificationMethod
from tests.conftest import make_ownership_proof


def test_expired_ownership_proof_rejected():
    proof = make_ownership_proof(expired=True)
    assert proof.is_expired() is True


def test_single_method_insufficient():
    proof = make_ownership_proof(methods=[VerificationMethod.DNS_TXT])
    assert proof.has_sufficient_verification() is False


def test_two_methods_sufficient():
    proof = make_ownership_proof(
        methods=[VerificationMethod.DNS_TXT, VerificationMethod.WELL_KNOWN]
    )
    assert proof.has_sufficient_verification() is True


def test_invalid_proof_not_released():
    proof = make_ownership_proof(is_valid=False)
    assert proof.is_valid is False


@pytest.mark.asyncio
async def test_hmac_token_uniqueness():
    from unittest.mock import AsyncMock, patch
    from packages.domain.dast.ownership import OwnershipVerifier
    from tests.conftest import make_client, make_project

    repo = AsyncMock()
    audit = AsyncMock()
    audit.log = AsyncMock()
    repo.save = AsyncMock()

    client = make_client()
    project = make_project(client_id=client.id, domain="test.com")
    verifier = OwnershipVerifier(repo=repo, audit=audit)

    tokens = set()
    # Mocka time.time para retornar valores diferentes a cada chamada
    with patch("packages.domain.dast.ownership.time") as mock_time:
        mock_time.time.side_effect = [1000, 2000, 3000, 4000, 5000]
        for _ in range(5):
            proof = await verifier.generate_challenge(
                domain="test.com",
                client=client,
                project_id=project.id,
            )
            tokens.add(proof.token)

    assert len(tokens) == 5, "Cada challenge deve ter token único"