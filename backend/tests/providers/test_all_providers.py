import pytest
from app.schemas.ioc import IOCType, ProviderStatus
from app.providers.base import ProviderRequestContext
from app.providers.virustotal import VirusTotalProvider
from app.providers.otx import AlienVaultOTXProvider
from app.providers.malwarebazaar import MalwareBazaarProvider
from app.providers.hybrid_analysis import HybridAnalysisProvider
from app.providers.abuseipdb import AbuseIPDBProvider
from app.providers.threatfox import ThreatFoxProvider
from app.providers.urlhaus import URLhausProvider
from app.providers.urlscan import URLScanProvider
from app.providers.censys import CensysProvider
from app.providers.greynoise import GreyNoiseProvider
from app.providers.shodan import ShodanProvider
from app.providers.webcheck import WebCheckProvider


@pytest.mark.asyncio
async def test_virustotal_parser():
    provider = VirusTotalProvider()
    ctx = ProviderRequestContext(ioc_value="8.8.8.8", ioc_type=IOCType.IPV4, is_mock=True)
    res = await provider.execute(ctx)
    assert res.status == ProviderStatus.SUCCESS
    assert res.provider_name == "virustotal"
    assert res.infrastructure is not None
    assert res.infrastructure.asn == "15169"


@pytest.mark.asyncio
async def test_otx_parser():
    provider = AlienVaultOTXProvider()
    ctx = ProviderRequestContext(ioc_value="c2.maliciousthreat.net", ioc_type=IOCType.DOMAIN, is_mock=True)
    res = await provider.execute(ctx)
    assert res.status == ProviderStatus.SUCCESS
    assert res.classification in ("suspicious", "malicious")
    assert len(res.discovered_iocs) > 0


@pytest.mark.asyncio
async def test_malwarebazaar_parser_and_unsupported():
    provider = MalwareBazaarProvider()

    # Supported hash
    ctx = ProviderRequestContext(ioc_value="275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f", ioc_type=IOCType.SHA256, is_mock=True)
    res = await provider.execute(ctx)
    assert res.status == ProviderStatus.SUCCESS
    assert res.classification == "malicious"
    assert "AgentTesla" in res.malware_families

    # Unsupported IP
    ctx_unsupported = ProviderRequestContext(ioc_value="8.8.8.8", ioc_type=IOCType.IPV4, is_mock=True)
    res_unsupported = await provider.execute(ctx_unsupported)
    assert res_unsupported.status == ProviderStatus.UNSUPPORTED


@pytest.mark.asyncio
async def test_hybrid_analysis_parser():
    provider = HybridAnalysisProvider()
    ctx = ProviderRequestContext(ioc_value="8c6976e5b5410415bde908bd4dee15dfb167a9c873fc745a116f5597320f4510", ioc_type=IOCType.SHA256, is_mock=True)
    res = await provider.execute(ctx)
    assert res.status == ProviderStatus.SUCCESS
    assert res.classification == "malicious"
    assert len(res.discovered_iocs) > 0


@pytest.mark.asyncio
async def test_abuseipdb_parser_and_unsupported():
    provider = AbuseIPDBProvider()

    # Supported IP
    ctx = ProviderRequestContext(ioc_value="198.51.100.1", ioc_type=IOCType.IPV4, is_mock=True)
    res = await provider.execute(ctx)
    assert res.status == ProviderStatus.SUCCESS
    assert res.reputation_score == 84.0

    # Unsupported Hash
    ctx_unsupported = ProviderRequestContext(ioc_value="d41d8cd98f00b204e9800998ecf8427e", ioc_type=IOCType.MD5, is_mock=True)
    res_unsupported = await provider.execute(ctx_unsupported)
    assert res_unsupported.status == ProviderStatus.UNSUPPORTED


@pytest.mark.asyncio
async def test_threatfox_parser():
    provider = ThreatFoxProvider()
    ctx = ProviderRequestContext(ioc_value="198.51.100.77", ioc_type=IOCType.IPV4, is_mock=True)
    res = await provider.execute(ctx)
    assert res.status == ProviderStatus.SUCCESS
    assert "RedLine Stealer" in res.malware_families


@pytest.mark.asyncio
async def test_urlhaus_parser():
    provider = URLhausProvider()
    ctx = ProviderRequestContext(ioc_value="http://malicious.link/bin.exe", ioc_type=IOCType.URL, is_mock=True)
    res = await provider.execute(ctx)
    assert res.status == ProviderStatus.SUCCESS
    assert res.classification == "malicious"
    assert len(res.discovered_iocs) > 0


@pytest.mark.asyncio
async def test_urlscan_parser():
    provider = URLScanProvider()
    ctx = ProviderRequestContext(ioc_value="secure-login.threat-portal.com", ioc_type=IOCType.DOMAIN, is_mock=True)
    res = await provider.execute(ctx)
    assert res.status == ProviderStatus.SUCCESS
    assert res.infrastructure.screenshot_url is not None


@pytest.mark.asyncio
async def test_censys_parser():
    provider = CensysProvider()

    # 1. IPv4
    ctx_v4 = ProviderRequestContext(ioc_value="198.51.100.22", ioc_type=IOCType.IPV4, is_mock=True)
    res_v4 = await provider.execute(ctx_v4)
    assert res_v4.status == ProviderStatus.SUCCESS
    assert res_v4.infrastructure is not None
    assert 443 in res_v4.infrastructure.open_ports
    assert len(res_v4.infrastructure.services_detail) > 0
    assert len(res_v4.infrastructure.certificates_detail) > 0
    assert res_v4.infrastructure.geo is not None
    assert res_v4.infrastructure.network is not None
    assert len(res_v4.discovered_iocs) > 0
    # Ensure no cert fingerprints are emitted as SHA256 file hashes
    for d in res_v4.discovered_iocs:
        assert d.ioc_type != IOCType.SHA256

    # 2. IPv6
    ctx_v6 = ProviderRequestContext(ioc_value="2001:4860:4860::8888", ioc_type=IOCType.IPV6, is_mock=True)
    res_v6 = await provider.execute(ctx_v6)
    assert res_v6.status == ProviderStatus.SUCCESS
    assert res_v6.infrastructure is not None

    # 3. Domain
    ctx_dom = ProviderRequestContext(ioc_value="example.com", ioc_type=IOCType.DOMAIN, is_mock=True)
    res_dom = await provider.execute(ctx_dom)
    assert res_dom.status == ProviderStatus.SUCCESS
    assert res_dom.infrastructure is not None
    assert 443 in res_dom.infrastructure.open_ports
    assert res_dom.infrastructure.dns is not None
    assert "142.251.41.78" in res_dom.infrastructure.dns_records.get("A", [])
    assert any(r.value == "142.251.41.78" for r in res_dom.infrastructure.dns.records)
    # Ensure resolved IPs are discovered as Layer 3 IOCs
    discovered_vals = [d.canonical_value for d in res_dom.discovered_iocs]
    assert "142.251.41.78" in discovered_vals

    # 4. Hashes must be rejected with UNSUPPORTED, while URLs are supported
    ctx_hash = ProviderRequestContext(ioc_value="275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f", ioc_type=IOCType.SHA256, is_mock=True)
    res_hash = await provider.execute(ctx_hash)
    assert res_hash.status == ProviderStatus.UNSUPPORTED

    ctx_url = ProviderRequestContext(ioc_value="https://example.com/test", ioc_type=IOCType.URL, is_mock=True)
    res_url = await provider.execute(ctx_url)
    assert res_url.status == ProviderStatus.SUCCESS
    assert res_url.infrastructure is not None


@pytest.mark.asyncio
async def test_greynoise_parser():
    provider = GreyNoiseProvider()
    ctx = ProviderRequestContext(ioc_value="198.51.100.33", ioc_type=IOCType.IPV4, is_mock=True)
    res = await provider.execute(ctx)
    assert res.status == ProviderStatus.SUCCESS
    assert res.classification == "malicious"
    assert "Mirai Operator" in res.threat_actors


@pytest.mark.asyncio
async def test_shodan_parser():
    provider = ShodanProvider()
    ctx = ProviderRequestContext(ioc_value="198.51.100.44", ioc_type=IOCType.IPV4, is_mock=True)
    res = await provider.execute(ctx)
    assert res.status == ProviderStatus.SUCCESS
    assert 22 in res.infrastructure.open_ports


@pytest.mark.asyncio
async def test_missing_api_key_returns_not_configured_in_live_mode():
    provider = VirusTotalProvider()
    # In live mode (is_mock=False) with no key provided
    ctx = ProviderRequestContext(ioc_value="8.8.8.8", ioc_type=IOCType.IPV4, is_mock=False, api_key=None)
    res = await provider.execute(ctx)
    assert res.status == ProviderStatus.NOT_CONFIGURED


@pytest.mark.asyncio
async def test_webcheck_parser_and_unsupported():
    provider = WebCheckProvider()

    # 1. Supported Domain
    ctx_dom = ProviderRequestContext(ioc_value="example.com", ioc_type=IOCType.DOMAIN, is_mock=True)
    res_dom = await provider.execute(ctx_dom)
    assert res_dom.status == ProviderStatus.SUCCESS
    assert res_dom.provider_name == "webcheck"
    assert res_dom.infrastructure is not None
    assert res_dom.infrastructure.http is not None
    assert "Nginx" in res_dom.infrastructure.http.technologies
    assert res_dom.infrastructure.dns is not None
    assert len(res_dom.discovered_iocs) > 0
    assert any(d.canonical_value == "1.2.3.4" for d in res_dom.discovered_iocs)

    # 2. Supported URL
    ctx_url = ProviderRequestContext(ioc_value="https://example.com/test", ioc_type=IOCType.URL, is_mock=True)
    res_url = await provider.execute(ctx_url)
    assert res_url.status == ProviderStatus.SUCCESS
    assert res_url.infrastructure is not None

    # 3. Supported IP (IPv4 / IPv6)
    ctx_ip = ProviderRequestContext(ioc_value="8.8.8.8", ioc_type=IOCType.IPV4, is_mock=True)
    res_ip = await provider.execute(ctx_ip)
    assert res_ip.status == ProviderStatus.SUCCESS
    assert res_ip.infrastructure is not None
    assert res_ip.infrastructure.network is not None
    assert res_ip.infrastructure.network.ip == "8.8.8.8"

    # 4. Unsupported Hash
    ctx_hash = ProviderRequestContext(ioc_value="275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f", ioc_type=IOCType.SHA256, is_mock=True)
    res_hash = await provider.execute(ctx_hash)
    assert res_hash.status == ProviderStatus.UNSUPPORTED


@pytest.mark.asyncio
async def test_webcheck_parse_results_for_ip():
    from app.providers.webcheck import _parse_results
    sample_results = {
        "get-ip": {"ip": "1.1.1.1"},
        "location": {
            "ip": "1.1.1.1",
            "city": "Sydney",
            "country": "Australia",
            "asn": "AS13335",
            "org": "Cloudflare",
            "lat": -33.8688,
            "lon": 151.2093,
        },
        "ports": {"openPorts": [80, 443]},
        "trace-route": {"hops": [{"hop": 1, "ip": "1.1.1.1", "rtt": "5ms"}]},
        "dns": {"PTR": ["one.one.one.one"]},
        "firewall": {"hasWaf": True, "waf": "Cloudflare"},
    }
    infra, discovered, evidences = _parse_results(sample_results, "1.1.1.1", IOCType.IPV4)
    assert infra.network is not None
    assert infra.network.ip == "1.1.1.1"
    assert infra.network.asn == "AS13335"
    assert infra.geo is not None
    assert infra.geo.city == "Sydney"
    assert infra.open_ports == [80, 443]
    assert "one.one.one.one" in infra.dns.hostnames
    assert "webcheck" in infra.extra


@pytest.mark.asyncio
async def test_censys_host_parsing_and_cves():
    provider = CensysProvider()
    ctx = ProviderRequestContext(ioc_value="198.51.100.44", ioc_type=IOCType.IPV4, is_mock=True)
    sample_censys = {
        "result": {
            "resource": {
                "ip": "198.51.100.44",
                "location": {"country": "Germany", "city": "Frankfurt"},
                "autonomous_system": {"asn": 14061, "name": "DigitalOcean"},
                "services": [
                    {
                        "port": 443,
                        "service_name": "https",
                        "transport_protocol": "tcp",
                        "software": [
                            {
                                "vendor": "Apache",
                                "product": "Log4j",
                                "version": "2.14.1",
                                "vulnerabilities": [
                                    {
                                        "cve_id": "CVE-2021-44228",
                                        "cvss": {"score": 10.0},
                                        "severity": "CRITICAL",
                                        "in_kev": True,
                                    }
                                ]
                            }
                        ],
                        "cert": {
                            "fingerprint_sha256": "abcdef1234567890",
                            "names": ["secure.example.com"],
                            "subject": {"common_name": []},
                        }
                    }
                ]
            }
        }
    }
    res = provider._parse_host_response(ctx, sample_censys)
    assert res.status == ProviderStatus.SUCCESS
    assert res.infrastructure is not None
    assert len(res.infrastructure.vulnerabilities) >= 1
    assert res.infrastructure.vulnerabilities[0].cve_id == "CVE-2021-44228"
    assert res.infrastructure.vulnerabilities[0].cvss == 10.0
    assert res.infrastructure.vulnerabilities[0].exploit is True
