import pytest
from httpx import AsyncClient
from app.config import settings


@pytest.mark.asyncio
async def test_live_dynamic_google_dns(client: AsyncClient, monkeypatch):
    monkeypatch.setattr(settings, "PROVIDER_MODE", "live")
    monkeypatch.setattr(settings, "VT_API_KEY", None)

    resp = await client.post("/api/v1/investigations", json={"ioc": "8.8.8.8"})
    assert resp.status_code == 201
    data = resp.json()

    assert data["root_ioc_value"] == "8.8.8.8"
    assert data["root_ioc_type"] == "ipv4"

    l2 = data["layer2"]["aggregated_infrastructure"]
    assert l2["ptr"] == "dns.google"
    assert "Google" in (l2["asn_name"] or "") or "15169" in (l2["asn"] or "")

    l3 = data["layer3"]
    ptr_matches = [d for d in l3["urls_and_domains"] if d["canonical_value"] == "dns.google"]
    assert len(ptr_matches) >= 1

    node_ids = {n["id"] for n in data["graph"]["nodes"]}
    assert "8.8.8.8" in node_ids
    assert "dns.google" in node_ids
    assert len(data["graph"]["edges"]) >= 1

    vt = next((p for p in data["layer1"]["provider_results"] if p["provider_name"] == "virustotal"), None)
    assert vt is not None
    assert vt["status"] == "not_configured"


@pytest.mark.asyncio
async def test_live_dynamic_cloudflare_dns(client: AsyncClient, monkeypatch):
    monkeypatch.setattr(settings, "PROVIDER_MODE", "live")

    resp = await client.post("/api/v1/investigations", json={"ioc": "1.1.1.1"})
    assert resp.status_code == 201
    data = resp.json()

    assert data["root_ioc_value"] == "1.1.1.1"
    assert data["root_ioc_type"] == "ipv4"

    l2 = data["layer2"]["aggregated_infrastructure"]
    assert l2["ptr"] == "one.one.one.one"
    assert "Cloudflare" in (l2["asn_name"] or "") or "13335" in (l2["asn"] or "")

    l3 = data["layer3"]
    ptr_matches = [d for d in l3["urls_and_domains"] if d["canonical_value"] == "one.one.one.one"]
    assert len(ptr_matches) >= 1

    node_ids = {n["id"] for n in data["graph"]["nodes"]}
    assert "1.1.1.1" in node_ids
    assert "one.one.one.one" in node_ids


@pytest.mark.asyncio
async def test_live_dynamic_domain_resolution(client: AsyncClient, monkeypatch):
    monkeypatch.setattr(settings, "PROVIDER_MODE", "live")

    resp = await client.post("/api/v1/investigations", json={"ioc": "example.com"})
    assert resp.status_code == 201
    data = resp.json()

    assert data["root_ioc_value"] == "example.com"
    assert data["root_ioc_type"] == "domain"

    l2 = data["layer2"]["aggregated_infrastructure"]
    dns_a = l2["dns_records"].get("A", [])
    assert len(dns_a) >= 1

    l3 = data["layer3"]
    discovered_ips = {d["canonical_value"] for d in l3["ips"]}
    assert any(ip in discovered_ips for ip in dns_a)

    node_ids = {n["id"] for n in data["graph"]["nodes"]}
    assert "example.com" in node_ids
    assert any(ip in node_ids for ip in dns_a)


@pytest.mark.asyncio
async def test_unresolvable_dummy_ip_clean_state(client: AsyncClient, monkeypatch):
    monkeypatch.setattr(settings, "PROVIDER_MODE", "live")
    monkeypatch.setattr(settings, "VT_API_KEY", None)
    monkeypatch.setattr(settings, "ABUSEIPDB_API_KEY", None)
    monkeypatch.setattr(settings, "OTX_API_KEY", None)
    monkeypatch.setattr(settings, "HYBRID_ANALYSIS_API_KEY", None)
    monkeypatch.setattr(settings, "SHODAN_API_KEY", None)
    monkeypatch.setattr(settings, "CENSYS_API_ID", None)
    monkeypatch.setattr(settings, "CENSYS_API_SECRET", None)
    monkeypatch.setattr(settings, "CENSYS_API_KEY", None)
    monkeypatch.setattr(settings, "MALWAREBAZAAR_API_KEY", None)
    monkeypatch.setattr(settings, "THREATFOX_API_KEY", None)
    monkeypatch.setattr(settings, "URLHAUS_API_KEY", None)

    from unittest.mock import AsyncMock
    from app.schemas.ioc import IOCType, ProviderStatus
    from app.schemas.provider import ProviderResult
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

    assert data["layer1"]["overall_classification"] == "unknown"
    assert data["layer1"]["risk_score"] == 0.0

    l2 = data["layer2"]["aggregated_infrastructure"]
    assert l2["ptr"] is None

    l3 = data["layer3"]
    assert len(l3["hashes"]) == 0
    assert len(l3["ips"]) == 0
    assert len(l3["urls_and_domains"]) == 0
    assert l3["total_count"] == 0

    assert len(data["graph"]["nodes"]) == 1
    assert data["graph"]["nodes"][0]["id"] == "192.0.2.1"
    assert len(data["graph"]["edges"]) == 0
