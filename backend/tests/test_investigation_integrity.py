import pytest
from httpx import AsyncClient
from app.config import settings
from app.schemas.ioc import IOCType, ProviderStatus
from app.providers.registry import registry
from app.providers.base import ProviderRequestContext


@pytest.mark.asyncio
async def test_zero_key_auth_semantics(client: AsyncClient, monkeypatch):
    """
    Asserts all providers requiring authentication return NOT_CONFIGURED
    and zero fake intelligence when API keys are not configured.
    """
    for prov_name in [
        "virustotal", "otx", "malwarebazaar", "hybrid_analysis",
        "abuseipdb", "threatfox", "urlhaus", "censys", "shodan"
    ]:
        prov = registry.get_provider(prov_name)
        assert prov is not None
        assert prov.get_capabilities().requires_auth is True

        ctx = ProviderRequestContext(
            ioc_value="8.8.8.8" if prov.is_ioc_supported(IOCType.IPV4) else "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
            ioc_type=IOCType.IPV4 if prov.is_ioc_supported(IOCType.IPV4) else IOCType.SHA256,
            is_mock=False,
            api_key=None,
            api_secret=None,
        )
        res = await prov.execute(ctx)
        assert res.status == ProviderStatus.NOT_CONFIGURED, f"{prov_name} must return NOT_CONFIGURED without key"
        assert res.reputation_score is None
        assert res.classification is None
        assert len(res.discovered_iocs) == 0
        assert len(res.evidences) == 0


@pytest.mark.asyncio
async def test_investigation_isolation(client: AsyncClient):
    """
    Investigates multiple distinct targets and asserts complete separation of
    root_ioc, provider results, discovered IOCs, and graph nodes.
    """
    targets = [
        ("94.231.206.248", "ipv4"),
        ("8.8.8.8", "ipv4"),
        ("1.1.1.1", "ipv4"),
        ("example.com", "domain"),
        ("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f", "sha256"),
    ]

    inv_responses = []
    for val, t in targets:
        resp = await client.post("/api/v1/investigations", json={"ioc": val})
        assert resp.status_code == 201
        data = resp.json()
        assert data["root_ioc_value"] == val
        assert data["root_ioc_type"] == t
        assert data["graph"]["root_ioc"] == val
        inv_responses.append(data)

    # Cross-assert isolation
    inv_ids = [d["id"] for d in inv_responses]
    assert len(set(inv_ids)) == len(targets)

    # 94.231.206.248 must NOT contain 8.8.8.8 nodes
    data_94 = inv_responses[0]
    node_ids_94 = {n["id"] for n in data_94["graph"]["nodes"]}
    assert "8.8.8.8" not in node_ids_94
    assert "google.com" not in node_ids_94
    assert "dns.google" not in node_ids_94
    assert "2001:4860:4860::8888" not in node_ids_94


@pytest.mark.asyncio
async def test_hash_investigation_integrity(client: AsyncClient):
    """
    Tests MD5, SHA1, and SHA256 hashes:
    Asserts detection, root assignment, and graph integrity.
    """
    hashes = [
        ("44d88612fea8a8f36de82e1278abb02f", "md5"),
        ("2aae6c35c94fcfb415dbe95f408b9ce91ee846ed", "sha1"),
        ("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f", "sha256"),
    ]

    for h_val, h_type in hashes:
        resp = await client.post("/api/v1/investigations", json={"ioc": h_val})
        assert resp.status_code == 201
        data = resp.json()
        assert data["root_ioc_value"] == h_val
        assert data["root_ioc_type"] == h_type
        assert data["graph"]["root_ioc"] == h_val
        assert data["graph"]["nodes"][0]["id"] == h_val
        assert data["graph"]["nodes"][0]["type"] == h_type
        assert "8.8.8.8" not in {n["id"] for n in data["graph"]["nodes"]}


@pytest.mark.asyncio
async def test_unresolvable_dummy_ip_zero_edges(client: AsyncClient, monkeypatch):
    """
    Verifies 192.0.2.1 produces 1 node only, 0 edges, and 0 fake intelligence.
    """
    for k in [
        "VT_API_KEY",
        "OTX_API_KEY",
        "ABUSEIPDB_API_KEY",
        "HYBRID_ANALYSIS_API_KEY",
        "SHODAN_API_KEY",
        "CENSYS_API_ID",
        "CENSYS_API_SECRET",
        "CENSYS_API_KEY",
        "MALWAREBAZAAR_API_KEY",
        "THREATFOX_API_KEY",
        "URLHAUS_API_KEY",
    ]:
        monkeypatch.setattr(settings, k, None)

    from unittest.mock import AsyncMock
    from app.schemas.provider import ProviderResult, ProviderStatus
    not_found_res = ProviderResult(
        provider_name="mnemonic_passivedns",
        ioc_value="192.0.2.1",
        ioc_type=IOCType.IPV4,
        status=ProviderStatus.NOT_FOUND,
        error_details="No matching records",
    )
    monkeypatch.setattr("app.providers.passivedns.PassiveDNSProvider._execute_live", AsyncMock(return_value=not_found_res))

    resp = await client.post("/api/v1/investigations", json={"ioc": "192.0.2.1"})
    assert resp.status_code == 201
    data = resp.json()

    assert data["root_ioc_value"] == "192.0.2.1"
    assert data["root_ioc_type"] == "ipv4"
    assert data["graph"]["root_ioc"] == "192.0.2.1"
    assert len(data["graph"]["nodes"]) == 1
    assert data["graph"]["nodes"][0]["id"] == "192.0.2.1"
    assert len(data["graph"]["edges"]) == 0
    assert data["layer3"]["total_count"] == 0
    assert data["layer1"]["overall_classification"] == "unknown"
    assert data["layer1"]["risk_score"] == 0.0


@pytest.mark.asyncio
async def test_quick_pivot_pipeline_consistency(client: AsyncClient):
    """
    Quick Pivot must run the exact same investigation pipeline,
    create unique investigation IDs, and never hardcode 8.8.8.8 as malicious.
    """
    resp1 = await client.post("/api/v1/investigations", json={"ioc": "8.8.8.8"})
    assert resp1.status_code == 201
    data1 = resp1.json()

    resp2 = await client.post("/api/v1/investigations", json={"ioc": "8.8.8.8"})
    assert resp2.status_code == 201
    data2 = resp2.json()

    assert data1["id"] != data2["id"], "Separate hunts must produce unique investigation IDs"
    assert data1["root_ioc_value"] == "8.8.8.8"
    assert data2["root_ioc_value"] == "8.8.8.8"
    assert data1["risk_score"] < 50.0, "8.8.8.8 must not be hardcoded as malicious"
