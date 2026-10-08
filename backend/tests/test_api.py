import pytest
from httpx import AsyncClient
from app.config import settings
from app.schemas.ioc import ProviderStatus


@pytest.mark.asyncio
async def test_health_endpoint(client: AsyncClient):
    resp = await client.get("/api/v1/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "healthy"
    assert data["project"] == "ThreatLens"


@pytest.mark.asyncio
async def test_detect_endpoint(client: AsyncClient):
    resp = await client.post("/api/v1/detect", json={"ioc": "1.1.1.1"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["is_valid"] is True
    assert data["detected_type"] == "ipv4"
    assert data["canonical_value"] == "1.1.1.1"


@pytest.mark.asyncio
async def test_providers_endpoint(client: AsyncClient):
    resp = await client.get("/api/v1/providers")
    assert resp.status_code == 200
    data = resp.json()
    assert len(data) == 15


@pytest.mark.asyncio
async def test_investigation_lifecycle(client: AsyncClient):
    # 1. Start investigation
    post_resp = await client.post(
        "/api/v1/investigations",
        json={"ioc": "8.8.8.8"},
    )
    assert post_resp.status_code == 201, f"Status {post_resp.status_code}: {post_resp.text}"
    inv = post_resp.json()
    inv_id = inv["id"]
    assert inv["root_ioc_value"] == "8.8.8.8"
    assert inv["root_ioc_type"] == "ipv4"
    assert len(inv["layer1"]["provider_results"]) >= 8
    assert len(inv["graph"]["nodes"]) >= 1

    # 2. Get details
    get_resp = await client.get(f"/api/v1/investigations/{inv_id}")
    assert get_resp.status_code == 200
    assert get_resp.json()["id"] == inv_id

    # 3. List investigations
    list_resp = await client.get("/api/v1/investigations")
    assert list_resp.status_code == 200
    items = list_resp.json()
    assert any(item["id"] == inv_id for item in items)

    # 4. Pivot from a child IOC
    pivot_resp = await client.post(
        f"/api/v1/investigations/{inv_id}/pivot",
        json={"target_ioc": "dns.google", "depth": 1},
    )
    assert pivot_resp.status_code == 200
    pivoted = pivot_resp.json()
    assert pivoted["pivot_depth"] >= 1


@pytest.mark.asyncio
async def test_investigation_in_live_mode_without_keys(client: AsyncClient, monkeypatch):
    """
    Verifies that when PROVIDER_MODE=live and no API keys are configured,
    the investigation still succeeds gracefully, persists to DB, and returns not_configured status.
    """
    monkeypatch.setattr(settings, "PROVIDER_MODE", "live")
    # Ensure keys are None
    monkeypatch.setattr(settings, "VT_API_KEY", None)
    monkeypatch.setattr(settings, "OTX_API_KEY", None)
    monkeypatch.setattr(settings, "SHODAN_API_KEY", None)
    monkeypatch.setattr(settings, "ABUSEIPDB_API_KEY", None)

    post_resp = await client.post(
        "/api/v1/investigations",
        json={"ioc": "8.8.8.8"},
    )
    assert post_resp.status_code == 201, f"Status {post_resp.status_code}: {post_resp.text}"
    inv = post_resp.json()
    assert inv["root_ioc_value"] == "8.8.8.8"

    # Verify that providers requiring keys report not_configured or public status without crashing
    results = inv["layer1"]["provider_results"]
    vt_res = next((r for r in results if r["provider_name"] == "virustotal"), None)
    assert vt_res is not None
    assert vt_res["status"] == "not_configured"
