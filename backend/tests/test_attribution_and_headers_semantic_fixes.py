import pytest
from app.schemas.ioc import IOCType, ProviderStatus
from app.schemas.provider import (
    ProviderResult,
    InfrastructureData,
    ThreatAttribution,
    SecurityHeadersAnalysis,
    SecurityHeaderInfo,
    SecurityHeaderState,
)
from app.providers.pulsedive import PulsediveProvider
from app.providers.criminalip import CriminalIPProvider
from app.providers.otx import AlienVaultOTXProvider
from app.providers.base import ProviderRequestContext
from app.schemas.provider import PulseMetadata
from app.providers.webcheck import (
    WebCheckProvider,
    _parse_results,
    normalize_security_headers,
    SUPPORTED_SECURITY_HEADERS_SPEC,
)
from app.services.enrichment import build_layer2_infrastructure


# ============================================================================
# PART 1: THREAT & MALWARE ATTRIBUTION SEMANTIC TESTS
# ============================================================================

def test_pulsedive_tool_and_general_threat_parsing():
    """
    Tor Proxy (tool) -> TOOL (NOT Campaign)
    CryptoMining (general) -> THREAT_ASSOCIATION (NOT Campaign)
    SSH Brute Force (general) -> THREAT_ASSOCIATION (NOT Campaign)
    Operation Aurora (campaign) -> CAMPAIGN
    """
    provider = PulsediveProvider()
    data = {
        "iid": 12345,
        "indicator": "198.51.100.1",
        "type": "ip",
        "risk": "high",
        "threats": [
            {"name": "Tor Proxy", "category": "tool"},
            {"name": "CryptoMining", "category": "general"},
            {"name": "SSH Brute Force", "category": "general"},
            {"name": "Operation Aurora", "category": "campaign"},
            {"name": "Cobalt Strike", "category": "malware"},
            {"name": "APT29", "category": "actor"},
        ],
        "properties": {
            "geo": {"country": "United States", "countrycode": "US"},
        },
    }

    res = provider._parse_pulsedive_response(
        ioc_val="198.51.100.1",
        ioc_type=IOCType.IPV4,
        data=data,
    )

    assert res.status == ProviderStatus.SUCCESS
    assert res.infrastructure is not None
    attrs = res.infrastructure.threat_attributions
    assert len(attrs) == 6

    # 1. Tor Proxy -> TOOL
    tor_attrs = [a for a in attrs if a.canonical_name == "Tor Proxy" or a.tool == "Tor Proxy"]
    assert len(tor_attrs) == 1
    tor = tor_attrs[0]
    assert tor.entity_type == "tool"
    assert tor.tool == "Tor Proxy"
    assert tor.campaign is None  # MUST NOT be campaign
    assert tor.relationship_type == "associated_threat"
    assert tor.subtype == "tool"

    # 2. CryptoMining -> THREAT_ASSOCIATION
    crypto_attrs = [a for a in attrs if a.canonical_name == "CryptoMining" or a.threat_association == "CryptoMining"]
    assert len(crypto_attrs) == 1
    crypto = crypto_attrs[0]
    assert crypto.entity_type == "threat_association"
    assert crypto.threat_association == "CryptoMining"
    assert crypto.campaign is None  # MUST NOT be campaign
    assert crypto.relationship_type == "associated_threat"
    assert crypto.subtype == "general"

    # 3. SSH Brute Force -> THREAT_ASSOCIATION
    ssh_attrs = [a for a in attrs if a.canonical_name == "SSH Brute Force" or a.threat_association == "SSH Brute Force"]
    assert len(ssh_attrs) == 1
    ssh = ssh_attrs[0]
    assert ssh.entity_type == "threat_association"
    assert ssh.threat_association == "SSH Brute Force"
    assert ssh.campaign is None  # MUST NOT be campaign
    assert ssh.relationship_type == "associated_threat"
    assert ssh.subtype == "general"

    # 4. Operation Aurora -> CAMPAIGN
    camp_attrs = [a for a in attrs if a.canonical_name == "Operation Aurora" or a.campaign == "Operation Aurora"]
    assert len(camp_attrs) == 1
    camp = camp_attrs[0]
    assert camp.entity_type == "campaign"
    assert camp.campaign == "Operation Aurora"

    # 5. Cobalt Strike -> MALWARE_FAMILY
    mal_attrs = [a for a in attrs if a.canonical_name == "Cobalt Strike" or a.malware_family == "Cobalt Strike"]
    assert len(mal_attrs) == 1
    assert mal_attrs[0].entity_type == "malware_family"

    # 6. APT29 -> THREAT_ACTOR
    act_attrs = [a for a in attrs if a.canonical_name == "APT29" or a.threat_actor == "APT29"]
    assert len(act_attrs) == 1
    assert act_attrs[0].entity_type == "threat_actor"


def test_criminalip_threat_category_mapped_to_threat_association():
    """Criminal IP threat_category must map to THREAT_ASSOCIATION, not Campaign."""
    provider = CriminalIPProvider()
    data = {
        "ip": "203.0.113.5",
        "score": {"inbound": 80, "outbound": 60},
        "issues": {
            "is_vpn": True,
            "is_tor": False,
            "is_proxy": False,
            "is_cloud": False,
            "is_hosting": False,
            "is_darkweb": False,
            "is_scanner": True,
            "is_snort": False,
        },
        "whois": {"as_name": "TEST-AS", "org_name": "Test Org"},
        "country": "US",
        "city": "Dallas",
        "threat_category": "scanner",
    }

    res = provider._parse_ip_response("203.0.113.5", IOCType.IPV4, data)
    assert res.status == ProviderStatus.SUCCESS
    assert res.infrastructure is not None

    attrs = res.infrastructure.threat_attributions
    scanner_attrs = [a for a in attrs if a.canonical_name == "scanner" or a.threat_association == "scanner"]
    assert len(scanner_attrs) == 1
    scanner = scanner_attrs[0]
    assert scanner.entity_type == "threat_association"
    assert scanner.threat_association == "scanner"
    assert scanner.campaign is None  # MUST NOT be campaign
    assert scanner.relationship_type in ("associated_threat", "threat_category")
    assert scanner.subtype == "threat_category"


def test_corroboration_single_provider_vs_multiple_providers():
    """
    Multiple threat entries from a single provider (e.g. Pulsedive) do NOT corroborate.
    Genuine cross-provider corroboration requires >= 2 distinct providers.
    """
    # 1. Pulsedive reports Tor Proxy and CryptoMining
    pulse_res = ProviderResult(
        provider_name="pulsedive",
        ioc_value="198.51.100.1",
        ioc_type=IOCType.IPV4,
        status=ProviderStatus.SUCCESS,
        infrastructure=InfrastructureData(
            threat_attributions=[
                ThreatAttribution(
                    canonical_name="Tor Proxy",
                    entity_type="tool",
                    tool="Tor Proxy",
                    relationship_type="associated_threat",
                    sources=["Pulsedive"],
                    providers=["pulsedive"],
                ),
                ThreatAttribution(
                    canonical_name="CryptoMining",
                    entity_type="threat_association",
                    threat_association="CryptoMining",
                    relationship_type="associated_threat",
                    sources=["Pulsedive"],
                    providers=["pulsedive"],
                ),
            ]
        ),
    )

    l2_single = build_layer2_infrastructure(
        root_ioc="198.51.100.1",
        root_type=IOCType.IPV4,
        provider_results=[pulse_res],
    )
    single_attrs = l2_single.aggregated_infrastructure.threat_attributions
    for attr in single_attrs:
        assert attr.is_corroborated is False, f"{attr.canonical_name} should NOT be corroborated by a single provider"

    # 2. Pulsedive + Second Provider (e.g. AlienVault) reporting Tor Proxy
    alien_res = ProviderResult(
        provider_name="alienvault_otx",
        ioc_value="198.51.100.1",
        ioc_type=IOCType.IPV4,
        status=ProviderStatus.SUCCESS,
        infrastructure=InfrastructureData(
            threat_attributions=[
                ThreatAttribution(
                    canonical_name="Tor Proxy",
                    entity_type="tool",
                    tool="Tor Proxy",
                    relationship_type="tool_usage",
                    sources=["AlienVault OTX"],
                    providers=["alienvault_otx"],
                ),
            ]
        ),
    )

    l2_multi = build_layer2_infrastructure(
        root_ioc="198.51.100.1",
        root_type=IOCType.IPV4,
        provider_results=[pulse_res, alien_res],
    )
    multi_attrs = l2_multi.aggregated_infrastructure.threat_attributions
    tor_multi = [a for a in multi_attrs if a.canonical_name == "Tor Proxy"][0]
    assert tor_multi.is_corroborated is True, "Tor Proxy should be corroborated across 2 distinct providers"
    assert len(set(s.lower() for s in tor_multi.sources)) >= 2


# ============================================================================
# PART 2: HTTP SECURITY HEADERS SEMANTIC TESTS
# ============================================================================

def test_security_headers_10_canonical_spec_and_states():
    """
    Ensure all 10 canonical security headers are defined and evaluated.
    Verify semantic states: PRESENT (with value), MISSING, NOT_CHECKED, UNAVAILABLE, REQUEST_FAILED.
    """
    assert len(SUPPORTED_SECURITY_HEADERS_SPEC) == 10

    # Scenario 1: Only HSTS is present in HTTP response
    results_single_hsts = {
        "http-security": {
            "strict-transport-security": "max-age=31536000; includeSubDomains; preload",
        }
    }
    analysis = normalize_security_headers(results_single_hsts, sources=["Web-Check"])
    assert analysis is not None
    assert analysis.total_supported == 10
    assert analysis.evaluated_count == 10
    assert analysis.active_count == 1
    assert analysis.missing_count == 9
    assert analysis.summary == "1 / 10 Active"

    # Verify HSTS is PRESENT with raw value
    hsts = next(h for h in analysis.headers if h.name == "Strict-Transport-Security")
    assert hsts.state == SecurityHeaderState.PRESENT
    assert hsts.value == "max-age=31536000; includeSubDomains; preload"

    # Verify CSP is MISSING
    csp = next(h for h in analysis.headers if h.name == "Content-Security-Policy")
    assert csp.state == SecurityHeaderState.MISSING
    assert csp.value is None

    # Verify X-Frame-Options is MISSING
    xframe = next(h for h in analysis.headers if h.name == "X-Frame-Options")
    assert xframe.state == SecurityHeaderState.MISSING

    # Scenario 2: Zero headers present
    analysis_zero = normalize_security_headers({"http-security": {}}, sources=["Web-Check"])
    assert analysis_zero.active_count == 0
    assert analysis_zero.evaluated_count == 10
    assert analysis_zero.summary == "0 / 10 Active"

    # Scenario 3: Request failed / error
    analysis_failed = normalize_security_headers(
        {"http-security": {"error": "Connection timed out"}}, sources=["Web-Check"]
    )
    assert analysis_failed.request_failed_count == 10
    assert analysis_failed.active_count == 0
    assert analysis_failed.summary == "0 / 10 Active (10 Request Failed)"
    for h in analysis_failed.headers:
        assert h.state == SecurityHeaderState.REQUEST_FAILED

    # Scenario 4: Multiple headers present with proper values
    results_multi = {
        "http-security": {
            "strict-transport-security": "max-age=63072000",
            "content-security-policy": "default-src 'self'",
            "x-content-type-options": "nosniff",
            "x-frame-options": "DENY",
            "referrer-policy": "strict-origin-when-cross-origin",
        }
    }
    analysis_multi = normalize_security_headers(results_multi, sources=["Web-Check"])
    assert analysis_multi.active_count == 5
    assert analysis_multi.missing_count == 5
    assert analysis_multi.evaluated_count == 10
    assert analysis_multi.summary == "5 / 10 Active"


def test_webcheck_provider_attaches_security_headers_to_infrastructure():
    """WebCheck provider execute/mock attaches SecurityHeadersAnalysis to InfrastructureData."""
    results = {
        "http-security": {
            "strict-transport-security": "max-age=31536000",
        }
    }
    infra, _, _ = _parse_results(results, "example.com", IOCType.DOMAIN)
    assert infra.security_headers is not None
    assert infra.security_headers.active_count == 1
    assert infra.security_headers.evaluated_count == 10
    assert infra.security_headers.summary == "1 / 10 Active"


def test_layer2_infrastructure_aggregates_security_headers():
    """Layer 2 infrastructure properly preserves aggregated security headers."""
    webcheck_res = ProviderResult(
        provider_name="webcheck",
        ioc_value="secure-site.org",
        ioc_type=IOCType.DOMAIN,
        status=ProviderStatus.SUCCESS,
        infrastructure=InfrastructureData(
            security_headers=SecurityHeadersAnalysis(
                total_supported=10,
                evaluated_count=10,
                active_count=2,
                missing_count=8,
                summary="2 / 10 Active",
                headers=[
                    SecurityHeaderInfo(
                        name="Strict-Transport-Security",
                        key="strict-transport-security",
                        state=SecurityHeaderState.PRESENT,
                        value="max-age=31536000",
                        sources=["Web-Check"],
                    ),
                    SecurityHeaderInfo(
                        name="X-Content-Type-Options",
                        key="x-content-type-options",
                        state=SecurityHeaderState.PRESENT,
                        value="nosniff",
                        sources=["Web-Check"],
                    ),
                ]
            )
        )
    )

    l2 = build_layer2_infrastructure(
        root_ioc="secure-site.org",
        root_type=IOCType.DOMAIN,
        provider_results=[webcheck_res],
    )

    sec_hdr = l2.aggregated_infrastructure.security_headers
    assert sec_hdr is not None
    assert sec_hdr.active_count == 2
    assert sec_hdr.evaluated_count == 10
    assert sec_hdr.summary == "2 / 10 Active"
    active_keys = {h.key for h in sec_hdr.headers if h.state == SecurityHeaderState.PRESENT}
    assert "strict-transport-security" in active_keys
    assert "x-content-type-options" in active_keys


# ============================================================================
# PART 3: FOCUSED INTELLIGENCE & ATTRIBUTION SEMANTIC TESTS
# ============================================================================

def test_otx_pulse_title_is_never_campaign():
    """
    OTX Pulse title/description:
    'Iranian backed group steps up phishing campaigns against Israel, U.S.'
    MUST remain Pulse title/evidence/description.
    It MUST NOT become Campaign: Iranian backed group steps...
    """
    provider = AlienVaultOTXProvider()
    pulse_name = "Iranian backed group steps up phishing campaigns against Israel, U.S."
    mock_data = {
        "indicator": "198.51.100.22",
        "pulse_info": {
            "count": 1,
            "pulses": [
                {
                    "id": "pulse_iran_01",
                    "name": pulse_name,
                    "description": "Adversary group phishing campaign details targeting various entities.",
                    "adversary": "Charming Kitten",
                    "tags": ["phishing", "iran", "c2"],
                    "malware_families": [],
                    "indicators": [],
                }
            ],
        },
    }
    ctx = ProviderRequestContext(ioc_value="198.51.100.22", ioc_type=IOCType.IPV4, is_mock=True)
    res = provider._parse_response(ctx, mock_data)
    assert res.status == ProviderStatus.SUCCESS
    assert res.infrastructure is not None
    assert len(res.infrastructure.otx_pulses) == 1
    assert res.infrastructure.otx_pulses[0].pulse_name == pulse_name

    # Check provider threat attributions
    for attr in res.infrastructure.threat_attributions:
        assert attr.campaign is None, f"OTX pulse title must not be classified as Campaign: {attr.campaign}"
        assert attr.campaign != pulse_name

    # Verify through Layer 2 enrichment
    l2 = build_layer2_infrastructure(
        root_ioc="198.51.100.22",
        root_type=IOCType.IPV4,
        provider_results=[res],
    )
    for attr in l2.aggregated_infrastructure.threat_attributions:
        assert attr.campaign is None, f"Aggregated attribution must NOT have pulse title as campaign: {attr.campaign}"
        assert attr.campaign != pulse_name

    # Adversary remains Threat Actor
    actor_attr = [a for a in l2.aggregated_infrastructure.threat_attributions if a.threat_actor == "Charming Kitten"]
    assert len(actor_attr) == 1
    assert actor_attr[0].entity_type == "threat_actor"


def test_explicit_campaign_remains_campaign():
    """Explicit campaign identified by provider category must remain Campaign."""
    provider = PulsediveProvider()
    data = {
        "iid": 991,
        "indicator": "198.51.100.33",
        "type": "ip",
        "risk": "critical",
        "threats": [
            {"name": "Operation Ghost", "category": "campaign", "risk": "critical"},
        ],
    }
    res = provider._parse_pulsedive_response(ioc_val="198.51.100.33", ioc_type=IOCType.IPV4, data=data)
    assert res.status == ProviderStatus.SUCCESS
    attrs = res.infrastructure.threat_attributions
    assert len(attrs) == 1
    assert attrs[0].entity_type == "campaign"
    assert attrs[0].campaign == "Operation Ghost"

    l2 = build_layer2_infrastructure(
        root_ioc="198.51.100.33",
        root_type=IOCType.IPV4,
        provider_results=[res],
    )
    l2_attrs = l2.aggregated_infrastructure.threat_attributions
    camp = [a for a in l2_attrs if a.campaign == "Operation Ghost"]
    assert len(camp) == 1
    assert camp[0].entity_type == "campaign"


def test_explicit_malware_family_remains_family_and_not_aliased_to_peer_family():
    """
    If OTX explicitly returns 'Attack New' and 'MedusaLocker' in malware_families:
    - Both remain Malware Family
    - Neither becomes an alias of the other
    """
    r_otx = ProviderResult(
        provider_name="otx",
        status=ProviderStatus.SUCCESS,
        ioc_value="198.51.100.44",
        ioc_type=IOCType.IPV4,
        infrastructure=InfrastructureData(
            otx_pulses=[
                PulseMetadata(
                    pulse_id="p_attack_medusa",
                    pulse_name="Dual Threat Report",
                    malware_families=["Attack New", "MedusaLocker"],
                    sources=["otx"],
                )
            ]
        ),
    )

    l2 = build_layer2_infrastructure(
        root_ioc="198.51.100.44",
        root_type=IOCType.IPV4,
        provider_results=[r_otx],
    )
    attrs = l2.aggregated_infrastructure.threat_attributions

    attack_new_attrs = [a for a in attrs if "Attack New" in (a.malware_family or "")]
    medusa_attrs = [a for a in attrs if "MedusaLocker" in (a.malware_family or "")]

    assert len(attack_new_attrs) == 1
    assert len(medusa_attrs) == 1

    # Neither is an alias of the other
    assert "MedusaLocker" not in (attack_new_attrs[0].aliases or [])
    assert "Attack New" not in (medusa_attrs[0].aliases or [])


def test_pulsedive_apt42_general_is_threat_association_not_actor_or_campaign():
    """Pulsedive 'APT42 (general)' must remain Threat Association, NOT Threat Actor or Campaign."""
    provider = PulsediveProvider()
    data = {
        "iid": 992,
        "indicator": "198.51.100.55",
        "type": "ip",
        "risk": "high",
        "threats": [
            {"name": "APT42", "category": "general", "risk": "high"},
        ],
    }
    res = provider._parse_pulsedive_response(ioc_val="198.51.100.55", ioc_type=IOCType.IPV4, data=data)
    assert res.status == ProviderStatus.SUCCESS
    attrs = res.infrastructure.threat_attributions
    assert len(attrs) == 1
    apt42 = attrs[0]
    assert apt42.entity_type == "threat_association"
    assert apt42.threat_association == "APT42"
    assert apt42.threat_actor is None
    assert apt42.campaign is None

    l2 = build_layer2_infrastructure(
        root_ioc="198.51.100.55",
        root_type=IOCType.IPV4,
        provider_results=[res],
    )
    l2_apt42 = [a for a in l2.aggregated_infrastructure.threat_attributions if a.canonical_name == "APT42"][0]
    assert l2_apt42.entity_type == "threat_association"
    assert l2_apt42.threat_association == "APT42"
    assert l2_apt42.threat_actor is None
    assert l2_apt42.campaign is None


def test_cve_becomes_vulnerability_not_malware_or_actor():
    """CVE must remain Vulnerability / CVE, never Malware Family or Threat Actor."""
    r_vuln = ProviderResult(
        provider_name="hybrid_analysis",
        status=ProviderStatus.SUCCESS,
        ioc_value="sample.exe",
        ioc_type=IOCType.SHA256,
        malware_families=["CVE-2021-44228"],
        infrastructure=InfrastructureData(
            threat_attributions=[
                ThreatAttribution(
                    cves=["CVE-2021-44228"],
                    entity_type="vulnerability",
                    sources=["Hybrid Analysis"],
                )
            ]
        ),
    )
    l2 = build_layer2_infrastructure(
        root_ioc="sample.exe",
        root_type=IOCType.SHA256,
        provider_results=[r_vuln],
    )
    attrs = l2.aggregated_infrastructure.threat_attributions
    cve_attr = [a for a in attrs if "CVE-2021-44228" in (a.cves or [])][0]
    assert cve_attr.entity_type == "vulnerability"
    assert cve_attr.malware_family is None
    assert cve_attr.threat_actor is None
    assert cve_attr.campaign is None


def test_provider_detection_does_not_become_malware_family():
    """Provider detections/signatures like 'Trojan.Generic' or AV detections must remain Detection, not Malware Family."""
    r_det = ProviderResult(
        provider_name="virustotal",
        status=ProviderStatus.SUCCESS,
        ioc_value="sample.exe",
        ioc_type=IOCType.SHA256,
        malware_families=["Trojan.Generic.KD.12345"],
        infrastructure=InfrastructureData(
            threat_attributions=[
                ThreatAttribution(
                    detection_classification="Trojan.Generic",
                    entity_type="detection",
                    sources=["VirusTotal"],
                )
            ]
        ),
    )
    l2 = build_layer2_infrastructure(
        root_ioc="sample.exe",
        root_type=IOCType.SHA256,
        provider_results=[r_det],
    )
    attrs = l2.aggregated_infrastructure.threat_attributions
    assert all(a.malware_family != "Generic" for a in attrs)
    assert all(a.malware_family != "Trojan.Generic.KD.12345" for a in attrs)
    det_attrs = [a for a in attrs if a.entity_type == "detection" or a.detection_classification]
    assert len(det_attrs) >= 1


def test_cross_provider_corroboration_strictly_requires_two_independent_providers():
    """Single provider with multiple entries cannot corroborate; strictly requires 2+ independent providers."""
    # 3 entries from Pulsedive
    r_pulse = ProviderResult(
        provider_name="pulsedive",
        status=ProviderStatus.SUCCESS,
        ioc_value="198.51.100.66",
        ioc_type=IOCType.IPV4,
        infrastructure=InfrastructureData(
            threat_attributions=[
                ThreatAttribution(canonical_name="Tor Proxy", entity_type="tool", tool="Tor Proxy", sources=["Pulsedive"]),
                ThreatAttribution(canonical_name="CryptoMining", entity_type="threat_association", threat_association="CryptoMining", sources=["Pulsedive"]),
                ThreatAttribution(canonical_name="SSH Brute Force", entity_type="threat_association", threat_association="SSH Brute Force", sources=["Pulsedive"]),
            ]
        ),
    )
    l2_pulse = build_layer2_infrastructure(
        root_ioc="198.51.100.66",
        root_type=IOCType.IPV4,
        provider_results=[r_pulse],
    )
    for a in l2_pulse.aggregated_infrastructure.threat_attributions:
        assert a.is_corroborated is False

    # Second provider corroborating Tor Proxy
    r_otx = ProviderResult(
        provider_name="otx",
        status=ProviderStatus.SUCCESS,
        ioc_value="198.51.100.66",
        ioc_type=IOCType.IPV4,
        infrastructure=InfrastructureData(
            threat_attributions=[
                ThreatAttribution(canonical_name="Tor Proxy", entity_type="tool", tool="Tor Proxy", sources=["AlienVault OTX"]),
            ]
        ),
    )
    l2_multi = build_layer2_infrastructure(
        root_ioc="198.51.100.66",
        root_type=IOCType.IPV4,
        provider_results=[r_pulse, r_otx],
    )
    tor = [a for a in l2_multi.aggregated_infrastructure.threat_attributions if a.canonical_name == "Tor Proxy"][0]
    assert tor.is_corroborated is True
    assert len(set(s.lower() for s in tor.sources)) >= 2

