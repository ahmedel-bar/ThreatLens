import pytest
from app.schemas.ioc import IOCType, ProviderStatus
from app.schemas.provider import ProviderResult
from app.providers.base import ProviderRequestContext
from app.providers.criminalip import CriminalIPProvider


@pytest.mark.asyncio
async def test_criminalip_supported_types():
    provider = CriminalIPProvider()
    assert provider.is_ioc_supported(IOCType.IPV4) is True
    assert provider.is_ioc_supported(IOCType.IPV6) is True
    assert provider.is_ioc_supported(IOCType.DOMAIN) is True
    assert provider.is_ioc_supported(IOCType.URL) is True
    assert provider.is_ioc_supported(IOCType.SHA256) is False
    assert provider.is_ioc_supported(IOCType.MD5) is False
    assert provider.is_ioc_supported(IOCType.SHA1) is False


@pytest.mark.asyncio
async def test_criminalip_hash_unsupported():
    provider = CriminalIPProvider()
    ctx = ProviderRequestContext(
        ioc_value="275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
        ioc_type=IOCType.SHA256,
        is_mock=True,
    )
    res = await provider.execute(ctx)
    assert res.status == ProviderStatus.UNSUPPORTED


@pytest.mark.asyncio
async def test_criminalip_missing_key_live_mode():
    provider = CriminalIPProvider()
    ctx = ProviderRequestContext(
        ioc_value="8.8.8.8",
        ioc_type=IOCType.IPV4,
        is_mock=False,
        api_key=None,
    )
    res = await provider.execute(ctx)
    assert res.status == ProviderStatus.NOT_CONFIGURED


@pytest.mark.asyncio
async def test_criminalip_mock_ip_parsing():
    provider = CriminalIPProvider()
    ctx = ProviderRequestContext(
        ioc_value="198.51.100.66",
        ioc_type=IOCType.IPV4,
        is_mock=True,
    )
    res = await provider.execute(ctx)
    assert res.status == ProviderStatus.SUCCESS
    assert res.provider_name == "criminalip"
    assert res.reputation_score == 92.5
    assert res.classification in ("suspicious", "malicious")
    assert res.infrastructure is not None
    assert 80 in res.infrastructure.open_ports
    assert 443 in res.infrastructure.open_ports
    assert len(res.infrastructure.vulnerabilities) > 0
    assert res.infrastructure.vulnerabilities[0].cve_id == "CVE-2021-44228"
    assert len(res.discovered_iocs) > 0


@pytest.mark.asyncio
async def test_criminalip_mock_domain_parsing():
    provider = CriminalIPProvider()
    ctx = ProviderRequestContext(
        ioc_value="phishing-target.net",
        ioc_type=IOCType.DOMAIN,
        is_mock=True,
    )
    res = await provider.execute(ctx)
    assert res.status == ProviderStatus.SUCCESS
    assert res.provider_name == "criminalip"
    assert res.reputation_score == 85.0
    assert res.classification == "malicious"
    assert len(res.discovered_iocs) > 0


@pytest.mark.asyncio
async def test_criminalip_parse_ip_report_with_cves_and_certs():
    provider = CriminalIPProvider()
    report_data = {
        "ip": "1.2.3.4",
        "score": {"inbound": "Dangerous", "outbound": "Critical"},
        "whois": {"as_name": "Cloudflare Inc.", "country_code": "US", "org_name": "Cloudflare"},
        "port": {
            "count": 2,
            "data": [
                {
                    "port": 443,
                    "protocol": "tcp",
                    "app_name": "nginx",
                    "app_version": "1.20.1",
                    "product": "nginx web server",
                    "banner": "HTTP/1.1 200 OK\r\nServer: nginx/1.20.1",
                    "vulnerability": [
                        {"cve_id": "CVE-2021-23017", "cvssv3_score": 9.8, "summary": "1-byte memory overwrite"}
                    ],
                }
            ],
        },
        "hostname": ["gateway.test.org"],
    }
    malicious_data = {
        "is_vpn": False,
        "is_tor": False,
        "is_proxy": False,
        "is_hosting": True,
        "is_scanner": True,
        "is_snort": True,
    }

    res = provider._parse_ip_response(
        ioc_val="1.2.3.4",
        ioc_type=IOCType.IPV4,
        report_data=report_data,
        malicious_data=malicious_data,
    )

    assert res.status == ProviderStatus.SUCCESS
    assert res.classification == "malicious"
    assert res.reputation_score == 92.5
    assert 443 in res.infrastructure.open_ports
    assert len(res.infrastructure.vulnerabilities) == 1
    assert res.infrastructure.vulnerabilities[0].cve_id == "CVE-2021-23017"
    assert "gateway.test.org" in res.infrastructure.dns.hostnames
    assert any(t.lower() == "scanner" for t in res.tags)


@pytest.mark.asyncio
async def test_criminalip_plan_restriction_handling():
    res = ProviderResult(
        provider_name="criminalip",
        ioc_value="1.2.3.4",
        ioc_type=IOCType.IPV4,
        status=ProviderStatus.PLAN_RESTRICTED,
        error_details="Criminal IP plan does not permit asset domain scanning",
    )
    assert res.status == ProviderStatus.PLAN_RESTRICTED
    assert "plan does not permit" in res.error_details


def test_criminalip_config_loading(monkeypatch):
    """
    Validates that Settings loads CRIMINALIP_API_KEY from environment,
    supports aliases, and cleans whitespace.
    """
    import os
    from app.config import Settings
    from app.providers.router import ProviderRouter

    # 1. Direct CRIMINALIP_API_KEY
    monkeypatch.setenv("CRIMINALIP_API_KEY", "test_cip_key_direct")
    s1 = Settings()
    assert s1.CRIMINALIP_API_KEY == "test_cip_key_direct"

    router = ProviderRouter(is_mock=True)
    key, _ = router._get_credentials_for_provider("criminalip")
    # router checks os.environ / settings
    assert key in ("test_cip_key_direct", s1.CRIMINALIP_API_KEY)

    # 2. Alias CRIMINAL_IP_API_KEY
    monkeypatch.delenv("CRIMINALIP_API_KEY", raising=False)
    monkeypatch.setenv("CRIMINAL_IP_API_KEY", "test_cip_key_alias")
    s2 = Settings()
    assert s2.CRIMINALIP_API_KEY == "test_cip_key_alias"

    key2, _ = router._get_credentials_for_provider("criminalip")
    assert key2 == "test_cip_key_alias"

    # 3. Clean whitespace / empty string becomes None
    monkeypatch.setenv("CRIMINALIP_API_KEY", "   ")
    s3 = Settings()
    assert s3.CRIMINALIP_API_KEY is None

