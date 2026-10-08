import pytest
from unittest.mock import AsyncMock, patch, MagicMock
from app.schemas.ioc import IOCType
from app.schemas.provider import (
    ProviderStatus,
    TTPTechnique,
    ThreatAttribution,
    PassiveDnsRecord,
)
from app.providers.passivedns import PassiveDNSProvider, format_pdns_timestamp
from app.providers.base import ProviderRequestContext
from app.providers.registry import registry
from app.services.enrichment import build_ttp_hierarchy
from app.services.mitre_attack import lookup_mitre_technique, ENTERPRISE_TACTICS_ORDER


def test_router_passivedns_routing():
    """Verify that Passive DNS only routes IP and Domain indicators, never Hashes or URLs."""
    provider = registry.get_provider("mnemonic_passivedns")
    assert provider is not None

    # Domain -> supported
    assert provider.is_ioc_supported(IOCType.DOMAIN) is True

    # IPv4 -> supported
    assert provider.is_ioc_supported(IOCType.IPV4) is True

    # IPv6 -> supported
    assert provider.is_ioc_supported(IOCType.IPV6) is True

    # Hashes -> NEVER supported
    assert provider.is_ioc_supported(IOCType.MD5) is False
    assert provider.is_ioc_supported(IOCType.SHA1) is False
    assert provider.is_ioc_supported(IOCType.SHA256) is False

    # URL -> NEVER supported
    assert provider.is_ioc_supported(IOCType.URL) is False

    # Also test alias 'passivedns'
    alias_provider = registry.get_provider("passivedns")
    assert alias_provider is not None
    assert alias_provider.name == "mnemonic_passivedns"


def test_passivedns_timestamp_formatting():
    """Verify millisecond timestamps format into human-readable UTC strings."""
    # 1715563860000 ms -> 2024-05-13 01:31:00 UTC
    formatted = format_pdns_timestamp(1715563860000)
    assert formatted is not None
    assert "May 13, 2024" in formatted
    assert "UTC" in formatted

    # Invalid / None / zero / negative handling
    assert format_pdns_timestamp(None) is None
    assert format_pdns_timestamp("not-a-number") is None
    assert format_pdns_timestamp(0) is None
    assert format_pdns_timestamp(-100) is None


@pytest.mark.asyncio
async def test_passivedns_rate_limiting_402():
    """Verify HTTP 402 or 429 maps to ProviderStatus.RATE_LIMITED with clear messaging."""
    provider = PassiveDNSProvider()

    mock_resp = MagicMock()
    mock_resp.status_code = 402
    mock_resp.json.return_value = {
        "responseCode": 402,
        "millisUntilResourcesAvailable": 60000,
        "messages": [{"message": "Exceeded public rate limit"}],
    }

    mock_client = MagicMock()
    mock_client.get = AsyncMock(return_value=mock_resp)

    ctx = ProviderRequestContext(
        ioc_value="rate-limited-test.com",
        ioc_type=IOCType.DOMAIN,
        is_mock=False,
        http_client=mock_client,
    )
    result = await provider.execute(ctx)

    assert result.status == ProviderStatus.RATE_LIMITED
    assert result.error_details is not None
    assert "mnemonic rate/resource quota exceeded" in result.error_details


@pytest.mark.asyncio
async def test_passivedns_not_found_empty():
    """Verify HTTP 404 or empty results map to ProviderStatus.NOT_FOUND."""
    provider = PassiveDNSProvider()

    mock_resp = MagicMock()
    mock_resp.status_code = 404
    mock_resp.json.return_value = {"responseCode": 404, "count": 0, "data": []}

    mock_client = MagicMock()
    mock_client.get = AsyncMock(return_value=mock_resp)

    ctx = ProviderRequestContext(
        ioc_value="notfound-domain.org",
        ioc_type=IOCType.DOMAIN,
        is_mock=False,
        http_client=mock_client,
    )
    result = await provider.execute(ctx)

    assert result.status == ProviderStatus.NOT_FOUND
    assert result.error_details is not None
    assert "No matching Passive DNS records found" in result.error_details


@pytest.mark.asyncio
async def test_passivedns_success_domain_ioc_extraction():
    """Verify successful Passive DNS response parses records and extracts canonical Layer 3 IOCs."""
    provider = PassiveDNSProvider()

    mock_payload = {
        "responseCode": 200,
        "count": 2,
        "data": [
            {
                "query": "malware.threatlens.test",
                "answer": "198.51.100.42",
                "rrtype": "a",
                "firstSeenTimestamp": 1715563860000,
                "lastSeenTimestamp": 1715650260000,
                "count": 14,
                "minTtl": 300,
                "maxTtl": 3600,
                "rrclass": "in",
                "tlp": "white",
            },
            {
                "query": "malware.threatlens.test",
                "answer": "cname.threatlens.test",
                "rrtype": "cname",
                "firstSeenTimestamp": 1715500000000,
                "lastSeenTimestamp": 1715600000000,
                "count": 5,
                "minTtl": 600,
                "maxTtl": 600,
                "rrclass": "in",
                "tlp": "white",
            },
        ],
    }

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = mock_payload

    mock_client = MagicMock()
    mock_client.get = AsyncMock(return_value=mock_resp)

    ctx = ProviderRequestContext(
        ioc_value="malware.threatlens.test",
        ioc_type=IOCType.DOMAIN,
        is_mock=False,
        http_client=mock_client,
    )
    result = await provider.execute(ctx)

    assert result.status == ProviderStatus.SUCCESS
    assert result.infrastructure is not None
    assert len(result.infrastructure.passive_dns) == 2

    rec1 = result.infrastructure.passive_dns[0]
    assert rec1.query == "malware.threatlens.test"
    assert rec1.answer == "198.51.100.42"
    assert rec1.rrtype == "A"
    assert rec1.observation_count == 14
    assert rec1.min_ttl == 300
    assert rec1.max_ttl == 3600
    assert "UTC" in rec1.first_seen
    assert "mnemonic_passivedns" in rec1.sources

    # Check Discovered IOCs in Layer 3:
    discovered = result.discovered_iocs
    assert len(discovered) == 2
    # IP indicator
    ip_ioc = next(i for i in discovered if i.canonical_value == "198.51.100.42")
    assert ip_ioc.ioc_type == IOCType.IPV4
    assert ip_ioc.relationship_type == "resolves_to"
    # Providers on DiscoveredIOC are added during Layer 3 aggregation, while single provider emits it directly

    # CNAME indicator
    cname_ioc = next(i for i in discovered if i.canonical_value == "cname.threatlens.test")
    assert cname_ioc.ioc_type == IOCType.DOMAIN
    assert cname_ioc.relationship_type == "resolves_to"


def test_mitre_attack_lookup_and_hierarchy():
    """Verify MITRE ATT&CK technique catalog lookups, tactic ordering, sub-technique nesting, and deduplication."""
    # Test lookup of parent technique
    t1003 = lookup_mitre_technique("T1003")
    assert t1003 is not None
    assert t1003.name == "OS Credential Dumping"
    assert t1003.primary_tactic_id == "TA0006"
    assert t1003.primary_tactic_name == "Credential Access"

    # Test lookup of sub-technique
    t1003_001 = lookup_mitre_technique("T1003.001")
    assert t1003_001 is not None
    assert t1003_001.name == "LSASS Memory"
    assert t1003_001.parent_id == "T1003"
    assert t1003_001.primary_tactic_id == "TA0006"

    # Build hierarchy with diverse techniques and sub-techniques across multiple providers
    ttps = [
        # Sub-technique from VirusTotal
        TTPTechnique(
            technique_id="T1059.001",
            technique_name="PowerShell",
            tactic="Execution",
            severity="HIGH",
            sources=["virustotal"],
        ),
        # Same sub-technique corroborated by MalwareBazaar
        TTPTechnique(
            technique_id="T1059.001",
            technique_name="PowerShell",
            tactic="Execution",
            severity="HIGH",
            sources=["malwarebazaar"],
        ),
        # Parent technique from ThreatFox
        TTPTechnique(
            technique_id="T1059",
            technique_name="Command and Scripting Interpreter",
            tactic="Execution",
            severity="HIGH",
            sources=["threatfox"],
        ),
        # Sub-technique under T1003 Credential Access
        TTPTechnique(
            technique_id="T1003.001",
            technique_name="LSASS Memory",
            tactic="Credential Access",
            severity="CRITICAL",
            sources=["virustotal"],
        ),
        # Discovery technique
        TTPTechnique(
            technique_id="T1082",
            technique_name="System Information Discovery",
            tactic="Discovery",
            severity="MEDIUM",
            sources=["pulsedive"],
        ),
    ]

    hierarchy = build_ttp_hierarchy(ttps, [])
    assert len(hierarchy) > 0

    # Ensure tactics follow canonical Enterprise Matrix order
    tactic_ids = [t.id for t in hierarchy]
    order_indices = [ENTERPRISE_TACTICS_ORDER.index(tid) for tid in tactic_ids if tid in ENTERPRISE_TACTICS_ORDER]
    assert order_indices == sorted(order_indices), "Tactics must be ordered by MITRE Enterprise Matrix order"

    # Verify Execution tactic (TA0002)
    exec_tactic = next(t for t in hierarchy if t.id == "TA0002")
    assert exec_tactic.name == "Execution"
    assert len(exec_tactic.techniques) == 1

    parent_tech = exec_tactic.techniques[0]
    assert parent_tech.id == "T1059"
    # Merged sources from parent and sub-technique
    assert "threatfox" in parent_tech.sources
    assert "virustotal" in parent_tech.sources
    assert "malwarebazaar" in parent_tech.sources

    # Sub-technique nested under T1059
    assert len(parent_tech.sub_techniques) == 1
    sub = parent_tech.sub_techniques[0]
    assert sub.id == "T1059.001"
    assert sub.name == "PowerShell"
    # Deduplicated and merged sources on sub-technique
    assert set(sub.sources) == {"virustotal", "malwarebazaar"}

    # Verify Credential Access tactic (TA0006)
    cred_tactic = next(t for t in hierarchy if t.id == "TA0006")
    assert cred_tactic.name == "Credential Access"
    tech_1003 = next(t for t in cred_tactic.techniques if t.id == "T1003")
    assert len(tech_1003.sub_techniques) == 1
    assert tech_1003.sub_techniques[0].id == "T1003.001"
