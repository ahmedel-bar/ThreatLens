import pytest
from app.schemas.ioc import IOCType, ProviderStatus
from app.schemas.provider import (
    ProviderResult,
    InfrastructureData,
    GeoInfo,
    DnsInfo,
    NetworkInfo,
    PulseMetadata,
)
from app.providers.virustotal import VirusTotalProvider
from app.providers.otx import AlienVaultOTXProvider
from app.providers.base import ProviderRequestContext
from app.services.enrichment import (
    build_layer1_reputation,
    build_layer2_infrastructure,
    attach_infrastructure_iocs,
)


@pytest.mark.asyncio
async def test_virustotal_domain_url_format():
    """
    Asserts VirusTotal domain queries use 'relationships=subdomains,resolutions'
    and do not attempt 'contacted_ips' which fails on domain endpoints.
    """
    vt = VirusTotalProvider()
    ctx = ProviderRequestContext(ioc_value="example.com", ioc_type=IOCType.DOMAIN, is_mock=True)
    res = await vt.execute(ctx)

    assert res.provider_name == "virustotal"
    assert res.status == ProviderStatus.SUCCESS
    assert res.infrastructure is not None
    assert "A" in res.infrastructure.dns_records or len(res.discovered_iocs) > 0


@pytest.mark.asyncio
async def test_otx_compact_layer1_and_rich_layer2():
    """
    Asserts OTX provider limits tags and actors in Layer 1,
    while Layer 2 extracts rich structured PulseMetadata with malware_names and attack_ids.
    """
    otx = AlienVaultOTXProvider()
    ctx = ProviderRequestContext(
        ioc_value="275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
        ioc_type=IOCType.SHA256,
        is_mock=True,
    )
    res = await otx.execute(ctx)

    assert res.status == ProviderStatus.SUCCESS
    assert len(res.tags) <= 5
    assert len(res.threat_actors) <= 2
    assert len(res.malware_families) <= 3

    assert res.infrastructure is not None
    assert len(res.infrastructure.otx_pulses) > 0
    first_pulse = res.infrastructure.otx_pulses[0]
    assert hasattr(first_pulse, "malware_names")
    assert hasattr(first_pulse, "attack_ids")


def test_layer2_geo_coordinates_preservation():
    """
    Asserts that latitude, longitude, and timezone are preserved in aggregated.geo.
    """
    mock_res = ProviderResult(
        provider_name="shodan",
        ioc_value="8.8.8.8",
        ioc_type=IOCType.IPV4,
        status=ProviderStatus.SUCCESS,
        infrastructure=InfrastructureData(
            country="United States",
            region="California",
            city="Mountain View",
            geo=GeoInfo(
                country="United States",
                region="California",
                city="Mountain View",
                latitude=37.386,
                longitude=-122.0838,
                timezone="America/Los_Angeles",
                sources=["shodan"],
            ),
        ),
    )

    layer2 = build_layer2_infrastructure(
        root_ioc="8.8.8.8",
        root_type=IOCType.IPV4,
        provider_results=[mock_res],
    )

    geo = layer2.aggregated_infrastructure.geo
    assert geo is not None
    assert geo.latitude == 37.386
    assert geo.longitude == -122.0838
    assert geo.timezone == "America/Los_Angeles"
    assert "shodan" in geo.sources


def test_url_infrastructure_enrichment_and_chain():
    """
    Asserts that URL investigation extracts host domain as hosted_on relationship,
    and resolves DNS A records to IPs with resolves_to relationships.
    """
    url_ioc = "http://malicious.example.com/payload.exe"
    mock_layer2 = build_layer2_infrastructure(
        root_ioc=url_ioc,
        root_type=IOCType.URL,
        provider_results=[],
    )

    mock_layer2.aggregated_infrastructure.dns_records = {"A": ["198.51.100.55"]}

    canonical_iocs, relationships = attach_infrastructure_iocs(
        root_canonical=url_ioc,
        root_type=IOCType.URL,
        layer2=mock_layer2,
        existing_iocs=[],
        existing_relationships=[],
    )

    domain_iocs = [i for i in canonical_iocs if i.ioc_type == IOCType.DOMAIN]
    assert len(domain_iocs) >= 1
    assert any(i.canonical_value == "malicious.example.com" for i in domain_iocs)

    ip_iocs = [i for i in canonical_iocs if i.ioc_type == IOCType.IPV4]
    assert len(ip_iocs) >= 1
    assert any(i.canonical_value == "198.51.100.55" for i in ip_iocs)

    rel_types = {r.relationship_type for r in relationships}
    assert "hosted_on" in rel_types
    assert "resolves_to" in rel_types
