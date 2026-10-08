import pytest
from httpx import AsyncClient
from app.schemas.ioc import IOCType, ProviderStatus
from app.schemas.provider import (
    ProviderResult,
    InfrastructureData,
    ServiceInfo,
    CertInfo,
    VulnInfo,
    NetworkInfo,
    GeoInfo,
    DnsInfo,
    ShodanHostDetails,
)
from app.services.enrichment import (
    build_layer1_reputation,
    build_layer2_infrastructure,
    REPUTATION_PROVIDERS,
)
from app.providers.shodan import ShodanProvider
from app.providers.censys import CensysProvider
from app.providers.base import ProviderRequestContext


@pytest.mark.asyncio
async def test_shodan_and_censys_excluded_from_layer1():
    """
    Asserts that Shodan and Censys results are strictly excluded from Layer 1
    Reputation and do not influence the Layer 1 risk score.
    """
    shodan_prov = ShodanProvider()
    censys_prov = CensysProvider()

    ctx = ProviderRequestContext(ioc_value="198.51.100.44", ioc_type=IOCType.IPV4, is_mock=True)
    shodan_res = await shodan_prov.execute(ctx)
    censys_res = await censys_prov.execute(ctx)

    assert shodan_res.provider_name == "shodan"
    assert shodan_res.classification is None
    assert shodan_res.reputation_score is None

    assert censys_res.provider_name == "censys"
    assert censys_res.classification is None
    assert censys_res.reputation_score is None

    # When building Layer 1
    layer1 = build_layer1_reputation(
        root_ioc="198.51.100.44",
        root_type=IOCType.IPV4,
        provider_results=[shodan_res, censys_res],
    )

    # Shodan is excluded from Layer 1, but Censys is included for operator query status
    prov_names_l1 = [r.provider_name.lower() for r in layer1.provider_results]
    assert "shodan" not in prov_names_l1
    assert "censys" in prov_names_l1
    assert layer1.total_providers_queried == 1
    assert layer1.risk_score == 0.0
    assert layer1.overall_classification == "unknown"


@pytest.mark.asyncio
async def test_shodan_populates_rich_layer2_infrastructure():
    """
    Asserts that Shodan results correctly populate Layer 2 structured models:
    Network, Geo, DNS, Services, Certificates, Vulnerabilities, and Shodan Details.
    """
    shodan_prov = ShodanProvider()
    ctx = ProviderRequestContext(ioc_value="198.51.100.44", ioc_type=IOCType.IPV4, is_mock=True)
    shodan_res = await shodan_prov.execute(ctx)

    layer2 = build_layer2_infrastructure(
        root_ioc="198.51.100.44",
        root_type=IOCType.IPV4,
        provider_results=[shodan_res],
    )

    infra = layer2.aggregated_infrastructure
    assert infra is not None

    # Open ports & services detail
    assert 22 in infra.open_ports
    assert 443 in infra.open_ports
    assert len(infra.services_detail) >= 2
    svc_443 = next((s for s in infra.services_detail if s.port == 443), None)
    assert svc_443 is not None
    assert "shodan" in svc_443.sources
    assert svc_443.product == "nginx"

    # Certificates detail
    assert len(infra.certificates_detail) >= 1
    cert = infra.certificates_detail[0]
    assert cert.subject_cn == "mail-relay.darkthreat.org"
    assert "shodan" in cert.sources

    # Vulnerabilities
    assert len(infra.vulnerabilities) >= 2
    cve_ids = [v.cve_id for v in infra.vulnerabilities]
    assert "CVE-2021-44228" in cve_ids
    assert "shodan" in infra.vulnerabilities[0].sources

    # Network Identity
    assert infra.network is not None
    assert infra.network.asn == "AS14061"
    assert infra.network.org == "DigitalOcean, LLC"
    assert "shodan" in infra.network.sources

    # Geolocation
    assert infra.geo is not None
    assert infra.geo.country == "Germany"
    assert infra.geo.city == "Frankfurt am Main"
    assert "shodan" in infra.geo.sources

    # DNS Hostnames & Domains
    assert infra.dns is not None
    assert "mail-relay.darkthreat.org" in infra.dns.hostnames
    assert "darkthreat.org" in infra.dns.domains
    assert "shodan" in infra.dns.sources

    # Shodan host details
    assert infra.shodan_details is not None
    assert infra.shodan_details.os == "Linux 5.4.0"
    assert infra.shodan_details.total_ports >= 4
    assert infra.shodan_details.total_vulns >= 2


@pytest.mark.asyncio
async def test_multi_provider_deduplication_and_provenance():
    """
    Asserts that when multiple providers (e.g. Shodan and Censys) report the same
    infrastructure (port 443), it is merged with multi-source provenance.
    """
    shodan_prov = ShodanProvider()
    censys_prov = CensysProvider()

    ctx = ProviderRequestContext(ioc_value="198.51.100.44", ioc_type=IOCType.IPV4, is_mock=True)
    shodan_res = await shodan_prov.execute(ctx)
    censys_res = await censys_prov.execute(ctx)

    layer2 = build_layer2_infrastructure(
        root_ioc="198.51.100.44",
        root_type=IOCType.IPV4,
        provider_results=[shodan_res, censys_res],
    )

    infra = layer2.aggregated_infrastructure

    # Port 443 appears in both Shodan and Censys mock data
    services_443 = [s for s in infra.services_detail if s.port == 443]
    assert len(services_443) == 1, "Port 443 should be deduplicated into a single ServiceInfo"

    svc = services_443[0]
    assert "shodan" in svc.sources
    assert "censys" in svc.sources
    assert len(svc.sources) == 2, f"Expected sources ['censys', 'shodan'], got {svc.sources}"


@pytest.mark.asyncio
async def test_hash_investigation_layer2_isolation():
    """
    Asserts that hash investigations remain strictly isolated and do not inherit
    unrelated IP network infrastructure, reverse DNS, or open ports.
    """
    dummy_hash = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"

    # Dummy provider result with file metadata
    file_infra = InfrastructureData(
        file_type="Win32 EXE",
        file_size=68400,
    )
    res = ProviderResult(
        provider_name="malwarebazaar",
        ioc_value=dummy_hash,
        ioc_type=IOCType.SHA256,
        status=ProviderStatus.SUCCESS,
        classification="malicious",
        reputation_score=95.0,
        infrastructure=file_infra,
    )

    layer2 = build_layer2_infrastructure(
        root_ioc=dummy_hash,
        root_type=IOCType.SHA256,
        provider_results=[res],
    )

    infra = layer2.aggregated_infrastructure
    # File metadata must be preserved
    assert infra.file_type == "Win32 EXE"
    assert infra.file_size == 68400

    # IP / Network infrastructure MUST NOT be present
    assert infra.network is None
    assert infra.geo is None
    assert infra.dns is None
    assert infra.whois is None
    assert len(infra.open_ports) == 0
    assert len(infra.services_detail) == 0
    assert len(infra.certificates_detail) == 0


@pytest.mark.asyncio
async def test_api_investigation_layer_separation(client: AsyncClient):
    """
    Tests end-to-end via FastAPI client that an investigation excludes Shodan from
    Layer 1 and populates Layer 2 with structured submodels.
    """
    resp = await client.post("/api/v1/investigations", json={"ioc": "198.51.100.55"})
    assert resp.status_code == 201
    data = resp.json()

    # Layer 1
    l1_provs = [p["provider_name"].lower() for p in data["layer1"]["provider_results"]]
    assert "shodan" not in l1_provs
    assert "censys" in l1_provs

    # Layer 2
    l2 = data["layer2"]
    agg = l2["aggregated_infrastructure"]
    assert "services_detail" in agg
    assert "network" in agg
    assert "geo" in agg
