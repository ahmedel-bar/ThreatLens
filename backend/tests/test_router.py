import pytest
from app.schemas.ioc import IOCType, ProviderStatus
from app.providers.registry import registry
from app.providers.router import ProviderRouter


def test_registry_contains_all_15_providers():
    all_providers = registry.get_all_providers()
    assert len(all_providers) == 15

    required = [
        "virustotal",
        "otx",
        "malwarebazaar",
        "hybrid_analysis",
        "abuseipdb",
        "threatfox",
        "urlhaus",
        "urlscan",
        "censys",
        "greynoise",
        "shodan",
        "pulsedive",
        "criminalip",
        "mnemonic_passivedns",
        "webcheck",
    ]
    for req in required:
        assert req in all_providers, f"Missing required provider: {req}"


def test_provider_capability_filtering():
    # AbuseIPDB must only support IPs
    abuseipdb = registry.get_provider("abuseipdb")
    assert abuseipdb.is_ioc_supported(IOCType.IPV4) is True
    assert abuseipdb.is_ioc_supported(IOCType.DOMAIN) is False
    assert abuseipdb.is_ioc_supported(IOCType.SHA256) is False

    # MalwareBazaar must only support hashes
    mb = registry.get_provider("malwarebazaar")
    assert mb.is_ioc_supported(IOCType.SHA256) is True
    assert mb.is_ioc_supported(IOCType.IPV4) is False
    assert mb.is_ioc_supported(IOCType.DOMAIN) is False

    # GreyNoise must only support IPv4
    gn = registry.get_provider("greynoise")
    assert gn.is_ioc_supported(IOCType.IPV4) is True
    assert gn.is_ioc_supported(IOCType.IPV6) is False
    assert gn.is_ioc_supported(IOCType.DOMAIN) is False

    # Censys supports IPv4, IPv6, Domain, and URL (strictly no Hashes)
    censys = registry.get_provider("censys")
    assert censys.is_ioc_supported(IOCType.IPV4) is True
    assert censys.is_ioc_supported(IOCType.IPV6) is True
    assert censys.is_ioc_supported(IOCType.DOMAIN) is True
    assert censys.is_ioc_supported(IOCType.URL) is True
    assert censys.is_ioc_supported(IOCType.SHA256) is False
    assert censys.is_ioc_supported(IOCType.MD5) is False

    # WebCheck supports Domain, URL, IPv4, and IPv6 (strictly no Hashes)
    webcheck = registry.get_provider("webcheck")
    assert webcheck.is_ioc_supported(IOCType.DOMAIN) is True
    assert webcheck.is_ioc_supported(IOCType.URL) is True
    assert webcheck.is_ioc_supported(IOCType.IPV4) is True
    assert webcheck.is_ioc_supported(IOCType.IPV6) is True
    assert webcheck.is_ioc_supported(IOCType.SHA256) is False
    assert webcheck.is_ioc_supported(IOCType.MD5) is False


@pytest.mark.asyncio
async def test_router_executes_mock_mode():
    router = ProviderRouter(is_mock=True)
    results = await router.route_ioc("8.8.8.8", IOCType.IPV4)
    # Providers supporting IPv4: VirusTotal, OTX, AbuseIPDB, ThreatFox, URLhaus, urlscan, Censys, GreyNoise, Shodan, HybridAnalysis
    assert len(results) >= 8
    success_results = [r for r in results if r.status == ProviderStatus.SUCCESS]
    assert len(success_results) >= 8
