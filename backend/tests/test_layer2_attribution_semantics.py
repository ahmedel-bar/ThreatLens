import pytest
from app.schemas.provider import (
    IOCType,
    ProviderResult,
    ProviderStatus,
    InfrastructureData,
    ThreatAttribution,
)
from app.services.enrichment import (
    is_cve_identifier,
    is_generic_malware_classification,
    normalize_malware_name,
    normalize_threat_actor_name,
    build_layer2_infrastructure,
)


def test_is_cve_identifier():
    assert is_cve_identifier("CVE-2017-0147") is True
    assert is_cve_identifier("cve-2021-44228") is True
    assert is_cve_identifier("CVE-2020-0796") is True
    assert is_cve_identifier("BazarLoader") is False
    assert is_cve_identifier("Trojan.Generic") is False
    assert is_cve_identifier("Mirage") is False
    assert is_cve_identifier("") is False
    assert is_cve_identifier(None) is False


def test_is_generic_malware_classification():
    assert is_generic_malware_classification("Trojan.Generic") is True
    assert is_generic_malware_classification("Generic") is True
    assert is_generic_malware_classification("generic detection") is True
    assert is_generic_malware_classification("Generic Malware") is True
    assert is_generic_malware_classification("Unknown") is True
    assert is_generic_malware_classification("Malicious") is True
    assert is_generic_malware_classification("Suspicious") is True
    assert is_generic_malware_classification("BazarLoader") is False
    assert is_generic_malware_classification("WannaCry") is False
    assert is_generic_malware_classification("Mirage") is False


def test_test_a_cve():
    """TEST A — CVE: Provider returns family = 'CVE-2017-0147' -> Vulnerability/CVE, NOT Malware Family, NOT Threat Actor."""
    ha_attr = ThreatAttribution(
        cves=["CVE-2017-0147"],
        verdict="malicious",
        sources=["hybrid_analysis"],
        evidence_summary='Falcon Sandbox VX family: "CVE-2017-0147" (verdict: malicious)',
    )
    ha_infra = InfrastructureData(
        threat_attributions=[ha_attr],
    )
    ha_res = ProviderResult(
        provider_name="hybrid_analysis",
        ioc_value="sample.exe",
        ioc_type=IOCType.SHA256,
        status=ProviderStatus.SUCCESS,
        infrastructure=ha_infra,
        malware_families=["CVE-2017-0147"],  # Even if provider raw malware_families has CVE
    )

    l2 = build_layer2_infrastructure(
        root_ioc="sample.exe",
        root_type=IOCType.SHA256,
        provider_results=[ha_res],
    )

    attrs = l2.aggregated_infrastructure.threat_attributions
    assert len(attrs) > 0

    cve_attrs = [a for a in attrs if "CVE-2017-0147" in a.cves]
    assert len(cve_attrs) == 1
    cve_entity = cve_attrs[0]

    # MUST NOT be stored/rendered as Malware Family or Threat Actor
    assert cve_entity.malware_family != "CVE-2017-0147"
    assert cve_entity.malware_family is None
    assert cve_entity.threat_actor != "CVE-2017-0147"
    assert cve_entity.threat_actor is None
    assert "CVE-2017-0147" in cve_entity.cves
    assert "Hybrid Analysis" in cve_entity.sources


def test_test_b_generic_classification():
    """TEST B — Generic Classification: Provider returns family = 'Trojan.Generic' -> Provider Classification, NOT Malware Family: Generic, NOT Threat Actor: Generic."""
    ha_attr = ThreatAttribution(
        detection_classification="Trojan.Generic",
        verdict="malicious",
        sources=["hybrid_analysis"],
        evidence_summary="Falcon Sandbox classification 'Trojan.Generic' with verdict 'malicious'",
    )
    ha_infra = InfrastructureData(
        threat_attributions=[ha_attr],
    )
    ha_res = ProviderResult(
        provider_name="hybrid_analysis",
        ioc_value="sample.exe",
        ioc_type=IOCType.SHA256,
        status=ProviderStatus.SUCCESS,
        infrastructure=ha_infra,
        malware_families=["Trojan.Generic"],
    )

    l2 = build_layer2_infrastructure(
        root_ioc="sample.exe",
        root_type=IOCType.SHA256,
        provider_results=[ha_res],
    )

    attrs = l2.aggregated_infrastructure.threat_attributions
    assert len(attrs) > 0

    for a in attrs:
        assert a.malware_family != "Generic"
        assert a.malware_family != "Trojan.Generic"
        assert a.threat_actor != "Generic"

    class_attrs = [a for a in attrs if a.detection_classification == "Trojan.Generic"]
    assert len(class_attrs) == 1
    assert "Hybrid Analysis" in class_attrs[0].sources
    assert class_attrs[0].verdict == "malicious"


def test_test_c_explicit_threat_actor():
    """TEST C — Explicit Threat Actor: Provider returns actor = 'Mirage' -> Threat Actor: Mirage."""
    otx_res = ProviderResult(
        provider_name="otx",
        ioc_value="1.2.3.4",
        ioc_type=IOCType.IPV4,
        status=ProviderStatus.SUCCESS,
        threat_actors=["Mirage"],
    )

    l2 = build_layer2_infrastructure(
        root_ioc="1.2.3.4",
        root_type=IOCType.IPV4,
        provider_results=[otx_res],
    )

    attrs = l2.aggregated_infrastructure.threat_attributions
    actor_attrs = [a for a in attrs if a.threat_actor == "Mirage"]
    assert len(actor_attrs) == 1
    assert "OTX" in actor_attrs[0].sources


def test_test_d_multiple_provider_actor_corroboration():
    """TEST D — Multiple Provider Actor Corroboration: Provider A: actor = Mirage, Provider B: actor = Mirage -> one Threat Actor: Mirage with combined sources."""
    p_a = ProviderResult(
        provider_name="otx",
        ioc_value="1.2.3.4",
        ioc_type=IOCType.IPV4,
        status=ProviderStatus.SUCCESS,
        threat_actors=["Mirage"],
    )
    p_b = ProviderResult(
        provider_name="pulsedive",
        ioc_value="1.2.3.4",
        ioc_type=IOCType.IPV4,
        status=ProviderStatus.SUCCESS,
        threat_actors=["Mirage"],
    )

    l2 = build_layer2_infrastructure(
        root_ioc="1.2.3.4",
        root_type=IOCType.IPV4,
        provider_results=[p_a, p_b],
    )

    attrs = l2.aggregated_infrastructure.threat_attributions
    actor_attrs = [a for a in attrs if a.threat_actor == "Mirage"]
    # Must be exactly ONE Threat Actor Mirage
    assert len(actor_attrs) == 1
    assert "OTX" in actor_attrs[0].sources
    assert "Pulsedive" in actor_attrs[0].sources


def test_test_e_no_actor():
    """TEST E — No Actor: Provider returns Malware Family: BazarLoader, but no actor -> Threat Actor is absent."""
    mb_res = ProviderResult(
        provider_name="malwarebazaar",
        ioc_value="sample.exe",
        ioc_type=IOCType.SHA256,
        status=ProviderStatus.SUCCESS,
        malware_families=["BazarLoader"],
        threat_actors=[],
    )

    l2 = build_layer2_infrastructure(
        root_ioc="sample.exe",
        root_type=IOCType.SHA256,
        provider_results=[mb_res],
    )

    attrs = l2.aggregated_infrastructure.threat_attributions
    bazar_attrs = [a for a in attrs if a.malware_family == "BazarLoader"]
    assert len(bazar_attrs) == 1
    assert bazar_attrs[0].threat_actor is None


def test_test_f_tag():
    """TEST F — Tag: Provider returns #china -> Threat Tag: #china, NOT Threat Actor: China."""
    ha_attr = ThreatAttribution(
        threat_tags=["china", "DefenseEvasion"],
        sources=["hybrid_analysis"],
        evidence_summary="Falcon Sandbox tags",
    )
    ha_infra = InfrastructureData(
        threat_attributions=[ha_attr],
    )
    ha_res = ProviderResult(
        provider_name="hybrid_analysis",
        ioc_value="1.2.3.4",
        ioc_type=IOCType.IPV4,
        status=ProviderStatus.SUCCESS,
        tags=["#china", "#DefenseEvasion"],
        infrastructure=ha_infra,
    )

    l2 = build_layer2_infrastructure(
        root_ioc="1.2.3.4",
        root_type=IOCType.IPV4,
        provider_results=[ha_res],
    )

    attrs = l2.aggregated_infrastructure.threat_attributions
    for a in attrs:
        assert a.threat_actor != "China"
        assert a.threat_actor != "Chinese APT"
        assert a.threat_actor is None


def test_test_g_malware_alias():
    """TEST G — Malware Alias: Provider A: BazarLoader, Provider B: Baza Loader -> one canonical BazarLoader with alias Baza Loader."""
    mb_res = ProviderResult(
        provider_name="malwarebazaar",
        ioc_value="sample.exe",
        ioc_type=IOCType.SHA256,
        status=ProviderStatus.SUCCESS,
        malware_families=["BazarLoader"],
    )
    vt_res = ProviderResult(
        provider_name="virustotal",
        ioc_value="sample.exe",
        ioc_type=IOCType.SHA256,
        status=ProviderStatus.SUCCESS,
        malware_families=["Baza Loader"],
    )

    l2 = build_layer2_infrastructure(
        root_ioc="sample.exe",
        root_type=IOCType.SHA256,
        provider_results=[mb_res, vt_res],
    )

    attrs = l2.aggregated_infrastructure.threat_attributions
    bazar_attrs = [a for a in attrs if a.malware_family == "BazarLoader"]
    assert len(bazar_attrs) == 1
    assert "Baza Loader" in bazar_attrs[0].aliases or "Baza Loader" in bazar_attrs[0].malware_names
    assert "MalwareBazaar" in bazar_attrs[0].sources
    assert "VirusTotal" in bazar_attrs[0].sources


def test_test_h_separate_bazar():
    """TEST H — Separate Bazar: Provider returns Bazar and BazarLoader -> do not merge them automatically."""
    res = ProviderResult(
        provider_name="malwarebazaar",
        ioc_value="sample.exe",
        ioc_type=IOCType.SHA256,
        status=ProviderStatus.SUCCESS,
        malware_families=["Bazar", "BazarLoader"],
    )

    l2 = build_layer2_infrastructure(
        root_ioc="sample.exe",
        root_type=IOCType.SHA256,
        provider_results=[res],
    )

    attrs = l2.aggregated_infrastructure.threat_attributions
    families = {a.malware_family for a in attrs if a.malware_family}
    assert "Bazar" in families
    assert "BazarLoader" in families
    assert len([a for a in attrs if a.malware_family == "Bazar"]) == 1
    assert len([a for a in attrs if a.malware_family == "BazarLoader"]) == 1


def test_test_i_full_attribution():
    """TEST I — Full Attribution: Provider returns Threat Actor: Mirage, Malware Family: GlassRAT,
    Campaign: Peering into GlassRAT, CVE: CVE-2017-0147, Classification: Trojan.Generic -> all 5 remain correctly separated."""
    attr = ThreatAttribution(
        threat_actor="Mirage",
        malware_family="GlassRAT",
        campaign="Peering into GlassRAT",
        cves=["CVE-2017-0147"],
        detection_classification="Trojan.Generic",
        sources=["otx"],
        evidence_summary='OTX Pulse "Peering into GlassRAT"',
    )
    infra = InfrastructureData(
        threat_attributions=[attr],
    )
    res = ProviderResult(
        provider_name="otx",
        ioc_value="sample.exe",
        ioc_type=IOCType.SHA256,
        status=ProviderStatus.SUCCESS,
        infrastructure=infra,
    )

    l2 = build_layer2_infrastructure(
        root_ioc="sample.exe",
        root_type=IOCType.SHA256,
        provider_results=[res],
    )

    attrs = l2.aggregated_infrastructure.threat_attributions
    glassrat_attrs = [a for a in attrs if a.malware_family == "GlassRAT"]
    assert len(glassrat_attrs) == 1
    item = glassrat_attrs[0]

    # All five fields remain correctly separated and populated
    assert item.threat_actor == "Mirage"
    assert item.malware_family == "GlassRAT"
    assert item.campaign == "Peering into GlassRAT"
    assert "CVE-2017-0147" in item.cves
    assert item.detection_classification == "Trojan.Generic"
