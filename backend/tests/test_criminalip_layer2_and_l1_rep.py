import pytest
from app.schemas.ioc import IOCType, ProviderStatus
from app.schemas.provider import (
    ProviderResult,
    InfrastructureData,
    ServiceInfo,
    VulnInfo,
    IpScoringInfo,
    DetectionInfo,
    SecurityIndicators,
)
from app.services.enrichment import (
    build_layer1_reputation,
    build_layer2_infrastructure,
)
from app.providers.criminalip import CriminalIPProvider
from app.providers.base import ProviderRequestContext


@pytest.mark.asyncio
async def test_criminalip_rich_layer2_infrastructure():
    cip_prov = CriminalIPProvider()
    ctx = ProviderRequestContext(ioc_value="185.220.101.5", ioc_type=IOCType.IPV4, is_mock=True)
    res = await cip_prov.execute(ctx)

    assert res.status == ProviderStatus.SUCCESS
    assert res.provider_name == "criminalip"
    assert res.classification == "malicious"

    infra = res.infrastructure
    assert infra is not None

    # IP Scoring
    assert infra.ip_scoring is not None
    assert infra.ip_scoring.inbound_score == "Dangerous"
    assert infra.ip_scoring.outbound_score == "Critical"
    assert infra.ip_scoring.critical_risk is True

    # Detection
    assert infra.detection is not None
    assert infra.detection.is_vpn is False
    assert infra.detection.is_tor is True
    assert infra.detection.is_proxy is True
    assert infra.detection.is_hosting is True
    assert infra.detection.is_scanner is False
    assert infra.detection.is_darkweb is True
    assert infra.detection.is_snort is True
    assert "tor" in infra.detection.ip_categories

    # Security Indicators
    assert infra.security is not None
    assert infra.security.user_search_count == 42
    assert infra.security.ids_alerts_count == 1
    assert "ET SCAN Suspicious Inbound Port Scan" in infra.security.ids_alert_signatures

    # Services Detail with CVEs and Scan Time
    assert len(infra.services_detail) >= 3
    svc_443 = next((s for s in infra.services_detail if s.port == 443), None)
    assert svc_443 is not None
    assert "criminalip" in svc_443.sources
    assert "CVE-2021-44228" in svc_443.vulnerabilities

    # Vulnerabilities Detail
    assert len(infra.vulnerabilities) >= 1
    cve = next((v for v in infra.vulnerabilities if v.cve_id == "CVE-2021-44228"), None)
    assert cve is not None
    assert cve.cwe_id == "CWE-502"
    assert cve.cvss_v3 == 10.0
    assert cve.severity == "CRITICAL"
    assert cve.attack_vector == "NETWORK"
    assert cve.affected_product == "Log4j"
    assert cve.affected_vendor == "Apache"
    assert cve.exploit is True
    assert "50592" in cve.exploit_details
    assert "criminalip" in cve.sources

    # Test Aggregation in build_layer2_infrastructure
    layer2 = build_layer2_infrastructure(
        root_ioc="185.220.101.5",
        root_type=IOCType.IPV4,
        provider_results=[res],
    )
    agg_infra = layer2.aggregated_infrastructure
    assert agg_infra.ip_scoring is not None
    assert agg_infra.ip_scoring.inbound_score == "Dangerous"
    assert agg_infra.detection is not None
    assert agg_infra.detection.is_tor is True
    assert agg_infra.security is not None
    assert agg_infra.security.user_search_count == 42
    assert agg_infra.security.vulnerabilities_count >= 1
    assert agg_infra.security.open_ports_count >= 3


def test_provider_based_layer1_aggregation():
    # 1. Successful VT (malicious=18 engines, but exactly 1 provider verdict: malicious)
    vt_res = ProviderResult(
        provider_name="virustotal",
        ioc_value="1.2.3.4",
        ioc_type=IOCType.IPV4,
        status=ProviderStatus.SUCCESS,
        classification="malicious",
        malicious_count=18,
        suspicious_count=2,
        vt_engine_counts={"malicious": 18, "suspicious": 2, "clean": 50, "undetected": 10, "total": 80},
    )

    # 2. Pulsedive clean
    pd_res = ProviderResult(
        provider_name="pulsedive",
        ioc_value="1.2.3.4",
        ioc_type=IOCType.IPV4,
        status=ProviderStatus.SUCCESS,
        classification="benign",
        reputation_score=0.0,
    )

    # 3. Criminal IP suspicious
    cip_res = ProviderResult(
        provider_name="criminalip",
        ioc_value="1.2.3.4",
        ioc_type=IOCType.IPV4,
        status=ProviderStatus.SUCCESS,
        classification="suspicious",
        reputation_score=50.0,
    )

    # 4. AbuseIPDB not found (must map to unknown verdict, NOT clean, but counts in denominator)
    abuse_res = ProviderResult(
        provider_name="abuseipdb",
        ioc_value="1.2.3.4",
        ioc_type=IOCType.IPV4,
        status=ProviderStatus.NOT_FOUND,
        classification="unknown",
    )

    # 5. AlienVault OTX unconfigured (must NOT count in denominator)
    otx_res = ProviderResult(
        provider_name="alienvault_otx",
        ioc_value="1.2.3.4",
        ioc_type=IOCType.IPV4,
        status=ProviderStatus.NOT_CONFIGURED,
    )

    # 6. Hybrid Analysis error/timeout (must NOT count in denominator)
    ha_res = ProviderResult(
        provider_name="hybrid_analysis",
        ioc_value="1.2.3.4",
        ioc_type=IOCType.IPV4,
        status=ProviderStatus.TIMEOUT,
    )

    # 7. Shodan (Layer 2 only provider, must NOT appear in Layer 1 at all)
    shodan_res = ProviderResult(
        provider_name="shodan",
        ioc_value="1.2.3.4",
        ioc_type=IOCType.IPV4,
        status=ProviderStatus.SUCCESS,
    )

    layer1 = build_layer1_reputation(
        root_ioc="1.2.3.4",
        root_type=IOCType.IPV4,
        provider_results=[vt_res, pd_res, cip_res, abuse_res, otx_res, ha_res, shodan_res],
    )

    # Evaluated denominator: vt, pulsedive, criminalip, abuseipdb = 4 providers
    assert layer1.applicable_providers_count == 4
    assert layer1.verdict_counts["malicious"] == 1
    assert layer1.verdict_counts["suspicious"] == 1
    assert layer1.verdict_counts["clean"] == 1
    assert layer1.verdict_counts["unknown"] == 1

    # Check that VT engine count is preserved
    assert layer1.vt_engine_counts is not None
    assert layer1.vt_engine_counts["malicious"] == 18
    assert layer1.vt_engine_counts["total"] == 80
