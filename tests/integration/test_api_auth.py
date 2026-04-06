from __future__ import annotations

import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_health_endpoint_public(api_client: AsyncClient):
    resp = await api_client.get("/health")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"


@pytest.mark.asyncio
async def test_security_headers_present(api_client: AsyncClient):
    resp = await api_client.get("/health")
    assert "x-content-type-options" in resp.headers
    assert "x-frame-options" in resp.headers


@pytest.mark.asyncio
async def test_server_header_not_exposed(api_client: AsyncClient):
    resp = await api_client.get("/health")
    assert "server" not in resp.headers


@pytest.mark.asyncio
async def test_protected_endpoint_without_key_rejected(api_client: AsyncClient):
    resp = await api_client.post("/scans/sast", json={})
    assert resp.status_code in (401, 422)


@pytest.mark.asyncio
async def test_protected_endpoint_with_invalid_key_rejected(api_client: AsyncClient):
    resp = await api_client.post(
        "/scans/sast",
        json={"project_id": str(__import__("uuid").uuid4()), "code": "def foo(): pass"},
        headers={"X-API-Key": "invalid-key-xyz"},
    )
    assert resp.status_code == 401
