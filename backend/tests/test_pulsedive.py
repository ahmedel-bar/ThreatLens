import pytest
from app.schemas.ioc import IOCType, ProviderStatus
from app.schemas.provider import ProviderResult
from app.providers.base import ProviderRequestContext
from app.providers.pulsedive import PulsediveProvider


@pytest.mark.asyncio
async def test_pulsedive_supported_types():
    provider = PulsediveProvider()
    assert provider.is_ioc_supported(IOCType.IPV4) is True
    assert provider.is_ioc_supported(IOCType.IPV6) is True
    assert provider.is_ioc_supported(IOCType.DOMAIN) is True
    assert provider.is_ioc_supported(IOCType.URL) is True
    assert provider.is_ioc_supported(IOCType.SHA256) is False
    assert provider.is_ioc_supported(IOCType.MD5) is False
    assert provider.is_ioc_supported(IOCType.SHA1) is False


@pytest.mark.asyncio
async def test_pulsedive_hash_unsupported():
    provider = PulsediveProvider()
    ctx = ProviderRequestContext(
        ioc_value="275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
        ioc_type=IOCType.SHA256,
        is_mock=True,
    )
    res = await provider.execute(ctx)
    assert res.status == ProviderStatus.UNSUPPORTED


@pytest.mark.asyncio
async def test_pulsedive_missing_key_live_mode():
    provider = PulsediveProvider()
    ctx = ProviderRequestContext(
        ioc_value="8.8.8.8",
        ioc_type=IOCType.IPV4,
        is_mock=False,
        api_key=None,
    )
    res = await provider.execute(ctx)
    assert res.status == ProviderStatus.NOT_CONFIGURED


@pytest.mark.asyncio
async def test_pulsedive_mock_ip_parsing():
    provider = PulsediveProvider()
    ctx = ProviderRequestContext(
        ioc_value="198.51.100.55",
        ioc_type=IOCType.IPV4,
        is_mock=True,
    )
    res = await provider.execute(ctx)
    assert res.status == ProviderStatus.SUCCESS
    assert res.provider_name == "pulsedive"
    assert res.reputation_score == 50.0
    assert res.classification in ("suspicious", "malicious")
    assert res.infrastructure is not None
    assert res.infrastructure.asn == "AS16509"
    assert res.infrastructure.country in ("US", "United States")
    assert "Cobalt Strike" in res.malware_families
    assert len(res.discovered_iocs) > 0


@pytest.mark.asyncio
async def test_pulsedive_mock_domain_parsing():
    provider = PulsediveProvider()
    ctx = ProviderRequestContext(
        ioc_value="malicious-domain.com",
        ioc_type=IOCType.DOMAIN,
        is_mock=True,
    )
    res = await provider.execute(ctx)
    assert res.status == ProviderStatus.SUCCESS
    assert res.provider_name == "pulsedive"
    assert res.infrastructure is not None
    assert len(res.discovered_iocs) > 0
    types = {ioc.ioc_type for ioc in res.discovered_iocs}
    assert IOCType.IPV4 in types or IOCType.DOMAIN in types


@pytest.mark.asyncio
async def test_pulsedive_parse_indicator_data():
    provider = PulsediveProvider()
    sample_data = {
        "iid": 12345,
        "indicator": "test-c2.org",
        "type": "domain",
        "risk": "critical",
        "threats": [
            {"name": "Emotet", "category": "malware"},
            {"name": "TA542", "category": "actor"},
        ],
        "properties": {
            "geo": {"country": "Germany", "countrycode": "DE", "city": "Frankfurt"},
            "dns": {"A": ["1.2.3.4"], "NS": ["ns1.test.org"]},
            "http": {"code": 200, "server": "nginx/1.18.0", "title": "Test Title"},
        },
    }
    sample_links = {
        "Active DNS": [{"indicator": "1.2.3.4", "type": "ip"}],
        "Name Servers": [{"indicator": "ns1.test.org", "type": "domain"}],
    }

    res = provider._parse_pulsedive_response(
        ioc_val="test-c2.org",
        ioc_type=IOCType.DOMAIN,
        data=sample_data,
        links_data=sample_links,
    )

    assert res.status == ProviderStatus.SUCCESS
    assert res.classification == "malicious"
    assert res.reputation_score == 100.0
    assert "Emotet" in res.malware_families
    assert "TA542" in res.threat_actors
    assert res.infrastructure.country == "Germany"
    assert res.infrastructure.http_server == "nginx/1.18.0"
    assert len(res.discovered_iocs) >= 2


@pytest.mark.asyncio
async def test_pulsedive_cache_hit():
    provider = PulsediveProvider()
    dummy = ProviderResult(
        provider_name="pulsedive",
        ioc_value="cached-ioc.com",
        ioc_type=IOCType.DOMAIN,
        status=ProviderStatus.SUCCESS,
    )
    provider._put_in_cache("cached-ioc.com", IOCType.DOMAIN, dummy)
    cached = provider._get_from_cache("cached-ioc.com", IOCType.DOMAIN)
    assert cached is not None
    assert cached.ioc_value == "cached-ioc.com"


@pytest.mark.asyncio
async def test_pulsedive_region_list_normalization():
    """
    Validates that Pulsedive responses with region as a list:
    region = ['North', 'Hauts-de-France']
    do not trigger validation errors, are preserved, and are joined into canonical comma-separated strings.
    """
    provider = PulsediveProvider()
    data = {
        "iid": 99999,
        "indicator": "195.154.122.50",
        "type": "ip",
        "risk": "medium",
        "properties": {
            "geo": {
                "country": "France",
                "countrycode": "FR",
                "region": ["North", "Hauts-de-France"],
                "city": ["Lille", "Roubaix"],
                "zip": "59000",
                "lat": "50.6292",
                "long": "3.0573",
                "asn": "AS12876",
                "org": "ONLINE S.A.S.",
            },
            "ssl": {
                "domain": ["node1.fr", "node2.fr"],
                "ip": ["195.154.122.50"],
            },
        },
    }

    res = provider._parse_pulsedive_response(
        ioc_val="195.154.122.50",
        ioc_type=IOCType.IPV4,
        data=data,
    )

    assert res.status == ProviderStatus.SUCCESS
    assert res.infrastructure is not None
    assert res.infrastructure.geo is not None
    assert res.infrastructure.geo.region == "North, Hauts-de-France"
    assert res.infrastructure.region == "North, Hauts-de-France"
    assert res.infrastructure.geo.city == "Lille, Roubaix"
    assert res.infrastructure.city == "Lille, Roubaix"
    assert res.infrastructure.geo.country == "France"
    assert res.infrastructure.asn == "AS12876"


def test_geoinfo_schema_tolerant_of_lists_and_nulls():
    """Validates GeoInfo and InfrastructureData schemas directly with various input shapes."""
    from app.schemas.provider import GeoInfo, InfrastructureData

    # List input
    geo = GeoInfo(
        country="France",
        region=["North", "Hauts-de-France"],
        city=["Paris", "Lyon"],
    )
    assert geo.region == "North, Hauts-de-France"
    assert geo.city == "Paris, Lyon"

    # Infrastructure flat fields
    infra = InfrastructureData(
        region=["North", "Hauts-de-France"],
        city="Paris",
        country=["France", "EU"],
    )
    assert infra.region == "North, Hauts-de-France"
    assert infra.country == "France, EU"

