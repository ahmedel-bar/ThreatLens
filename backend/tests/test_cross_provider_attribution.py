import pytest
from app.schemas.ioc import IOCType, ProviderStatus
from app.schemas.provider import ProviderResult, DiscoveredIOC
from app.services.deduplication import deduplicate_discovered_iocs
from app.services.enrichment import (
    normalize_malware_name,
    normalize_threat_actor_name,
    build_layer2_infrastructure,
    build_layer3_buckets,
)


def test_malware_name_normalization():
    assert normalize_malware_name("cobaltstrike") == "Cobalt Strike"
    assert normalize_malware_name("Cobalt Strike Beacon") == "Cobalt Strike"
    assert normalize_malware_name("emotet") == "Emotet"
    assert normalize_malware_name("agent_tesla") == "Agent Tesla"
    assert normalize_malware_name("redline") == "RedLine Stealer"
    assert normalize_malware_name("mirai") == "Mirai"
    assert normalize_malware_name("unknown_trojan") == "Unknown Trojan"


def test_threat_actor_normalization():
    assert normalize_threat_actor_name("wizard spider") == "Wizard Spider"
    assert normalize_threat_actor_name("ta542") == "TA542"
    assert normalize_threat_actor_name("lazarus group") == "Lazarus Group"
    assert normalize_threat_actor_name("apt29") == "APT29 (Cozy Bear)"


def test_cross_provider_attribution_consolidation():
    # Simulate results from Pulsedive, VirusTotal, and ThreatFox
    r_pulsedive = ProviderResult(
        provider_name="pulsedive",
        status=ProviderStatus.SUCCESS,
        ioc_value="198.51.100.99",
        ioc_type=IOCType.IPV4,
        malware_families=["Cobalt Strike"],
        threat_actors=["Wizard Spider"],
    )
    r_vt = ProviderResult(
        provider_name="virustotal",
        status=ProviderStatus.SUCCESS,
        ioc_value="198.51.100.99",
        ioc_type=IOCType.IPV4,
        malware_families=["CobaltStrike"],
    )
    r_threatfox = ProviderResult(
        provider_name="threatfox",
        status=ProviderStatus.SUCCESS,
        ioc_value="198.51.100.99",
        ioc_type=IOCType.IPV4,
        malware_families=["Cobalt Strike"],
        threat_actors=["Wizard Spider"],
    )

    layer2 = build_layer2_infrastructure(
        root_ioc="198.51.100.99",
        root_type=IOCType.IPV4,
        provider_results=[r_pulsedive, r_vt, r_threatfox],
    )

    agg = layer2.aggregated_infrastructure
    assert agg is not None
    assert len(agg.threat_attributions) > 0

    # Cobalt Strike must be aggregated into one canonical entry
    cobalt_attr = next((a for a in agg.threat_attributions if a.malware_family == "Cobalt Strike"), None)
    assert cobalt_attr is not None
    assert any("pulsedive" in s.lower() for s in cobalt_attr.sources)
    assert any("virustotal" in s.lower() for s in cobalt_attr.sources)
    assert any("threatfox" in s.lower() for s in cobalt_attr.sources)
    assert cobalt_attr.confidence >= 90.0


def test_cross_provider_layer3_deduplication():
    # Discovered IOC from Pulsedive and OTX
    r_pulsedive = ProviderResult(
        provider_name="pulsedive",
        status=ProviderStatus.SUCCESS,
        ioc_value="test-domain.com",
        ioc_type=IOCType.DOMAIN,
        discovered_iocs=[
            DiscoveredIOC(
                raw_value="198.51.100.123",
                canonical_value="198.51.100.123",
                ioc_type=IOCType.IPV4,
                relationship_type="Active DNS",
                confidence=85.0,
                evidence_desc="Pulsedive Active DNS",
            )
        ],
    )
    r_otx = ProviderResult(
        provider_name="otx",
        status=ProviderStatus.SUCCESS,
        ioc_value="test-domain.com",
        ioc_type=IOCType.DOMAIN,
        discovered_iocs=[
            DiscoveredIOC(
                raw_value="198.51.100.123",
                canonical_value="198.51.100.123",
                ioc_type=IOCType.IPV4,
                relationship_type="resolves_to",
                confidence=80.0,
                evidence_desc="OTX resolution",
            )
        ],
    )

    deduped_iocs, deduped_rels = deduplicate_discovered_iocs(
        root_canonical="test-domain.com",
        root_type=IOCType.DOMAIN,
        provider_results=[r_pulsedive, r_otx],
    )

    layer3 = build_layer3_buckets(deduped_iocs)

    # The IP 198.51.100.123 should be deduplicated
    ip_records = [i for i in layer3.ips if i.canonical_value == "198.51.100.123"]
    assert len(ip_records) == 1
    assert "pulsedive" in ip_records[0].providers
    assert "otx" in ip_records[0].providers


def test_wannacry_cross_provider_deduplication():
    from app.schemas.provider import InfrastructureData, ThreatAttribution, PulseMetadata, TTPTechnique

    # 1. VirusTotal returns "WannaCry" via popular threat classification
    vt_infra = InfrastructureData(
        threat_attributions=[
            ThreatAttribution(
                malware_family="WannaCry",
                malware_names=["wannacry", "wcry"],
                malware_type="ransomware",
                aliases=["wcry"],
                sources=["virustotal"],
                confidence=85.0,
                evidence_summary="VirusTotal popular threat label 'trojan.wannacry/wcry'",
            )
        ]
    )
    r_vt = ProviderResult(
        provider_name="virustotal",
        status=ProviderStatus.SUCCESS,
        ioc_value="ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa",
        ioc_type=IOCType.SHA256,
        malware_families=["wannacry"],
        infrastructure=vt_infra,
    )

    # 2. OTX returns "WannaCrypt" in a pulse with CVE-2017-0144 and T1486
    otx_infra = InfrastructureData(
        otx_pulses=[
            PulseMetadata(
                pulse_id="pulse_wannacry_1",
                pulse_name="WannaCry Outbreak Campaign",
                malware_families=["WannaCrypt"],
                adversary="Lazarus Group",
                tags=["CVE-2017-0144", "ransomware", "eternalblue"],
                attack_ids=["T1486"],
                sources=["otx"],
            )
        ]
    )
    r_otx = ProviderResult(
        provider_name="otx",
        status=ProviderStatus.SUCCESS,
        ioc_value="ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa",
        ioc_type=IOCType.SHA256,
        malware_families=["WannaCrypt"],
        threat_actors=["Lazarus Group"],
        infrastructure=otx_infra,
    )

    # 3. MalwareBazaar returns "WannaCryptor" signature
    mb_infra = InfrastructureData(
        threat_attributions=[
            ThreatAttribution(
                malware_family="WannaCryptor",
                malware_names=["WannaCryptor"],
                threat_tags=["ransomware", "wcry"],
                sources=["malwarebazaar"],
                confidence=95.0,
                evidence_summary="MalwareBazaar signature 'WannaCryptor'",
            )
        ]
    )
    r_mb = ProviderResult(
        provider_name="malwarebazaar",
        status=ProviderStatus.SUCCESS,
        ioc_value="ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa",
        ioc_type=IOCType.SHA256,
        malware_families=["WannaCryptor"],
        infrastructure=mb_infra,
    )

    # 4. ThreatFox returns "WannaCry ransomware"
    tf_infra = InfrastructureData(
        threat_attributions=[
            ThreatAttribution(
                malware_family="WannaCry ransomware",
                malware_names=["WannaCry ransomware"],
                malware_type="ransomware",
                threat_tags=["ransomware", "worm"],
                sources=["threatfox"],
                confidence=90.0,
                evidence_summary="ThreatFox payload delivery",
            )
        ]
    )
    r_tf = ProviderResult(
        provider_name="threatfox",
        status=ProviderStatus.SUCCESS,
        ioc_value="ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa",
        ioc_type=IOCType.SHA256,
        malware_families=["WannaCry ransomware"],
        infrastructure=tf_infra,
    )

    # Build Layer 2
    layer2 = build_layer2_infrastructure(
        root_ioc="ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa",
        root_type=IOCType.SHA256,
        provider_results=[r_vt, r_otx, r_mb, r_tf],
    )

    agg = layer2.aggregated_infrastructure
    assert agg is not None
    assert len(agg.threat_attributions) > 0

    # Exactly ONE canonical entry for WannaCry
    wannacry_matches = [a for a in agg.threat_attributions if a.malware_family == "WannaCry"]
    assert len(wannacry_matches) == 1
    w_attr = wannacry_matches[0]

    # Verify cross-provider provenance
    for expected_src in ["virustotal", "otx", "malwarebazaar", "threatfox"]:
        assert any(expected_src in s.lower() for s in w_attr.sources), f"Source '{expected_src}' missing from sources {w_attr.sources}"

    # Verify confidence corroborated
    assert w_attr.confidence >= 95.0

    # Verify malware_type resolved to ransomware
    assert w_attr.malware_type == "ransomware"

    # Verify aliases preserved
    assert any("wannacrypt" in a.lower() for a in w_attr.aliases)
    assert any("wannacryptor" in a.lower() for a in w_attr.aliases)

    # Verify associated CVEs extracted from OTX pulse
    assert any("CVE-2017-0144" in c.upper() for c in w_attr.cves)

    # Verify associated TTPs
    assert any(t.technique_id == "T1486" for t in w_attr.ttps)

    # Verify Threat Actor attribution also merged
    lazarus_matches = [a for a in agg.threat_attributions if a.threat_actor and "Lazarus" in a.threat_actor]
    assert len(lazarus_matches) == 1
    assert any("otx" in s.lower() for s in lazarus_matches[0].sources)


def test_attribution_across_all_ioc_types():
    from app.schemas.provider import InfrastructureData, ThreatAttribution

    # Test IP, Domain, and URL IOC types
    test_cases = [
        ("198.51.100.55", IOCType.IPV4),
        ("c2-malicious-domain.com", IOCType.DOMAIN),
        ("http://bad-link.ru/login.php", IOCType.URL),
    ]

    for ioc_val, ioc_type in test_cases:
        r1 = ProviderResult(
            provider_name="virustotal",
            status=ProviderStatus.SUCCESS,
            ioc_value=ioc_val,
            ioc_type=ioc_type,
            malware_families=["RedLine Stealer"],
        )
        r2 = ProviderResult(
            provider_name="threatfox",
            status=ProviderStatus.SUCCESS,
            ioc_value=ioc_val,
            ioc_type=ioc_type,
            malware_families=["win.redline_stealer"],
        )

        layer2 = build_layer2_infrastructure(
            root_ioc=ioc_val,
            root_type=ioc_type,
            provider_results=[r1, r2],
        )

        agg = layer2.aggregated_infrastructure
        assert len(agg.threat_attributions) > 0
        redline = next((a for a in agg.threat_attributions if a.malware_family == "RedLine Stealer"), None)
        assert redline is not None, f"Failed for {ioc_type}: RedLine Stealer not canonicalized"
        assert any("virustotal" in s.lower() for s in redline.sources)
        assert any("threatfox" in s.lower() for s in redline.sources)
        assert redline.malware_type == "infostealer"


def test_bazarloader_variants_and_generic_classification():
    from app.schemas.provider import InfrastructureData, ThreatAttribution

    # 1. VirusTotal returns "BazarLoader"
    vt_infra = InfrastructureData(
        threat_attributions=[
            ThreatAttribution(
                malware_family="BazarLoader",
                sources=["virustotal"],
                confidence=85.0,
                evidence_summary="VirusTotal — malware family detection",
            )
        ]
    )
    r_vt = ProviderResult(
        provider_name="virustotal",
        status=ProviderStatus.SUCCESS,
        ioc_value="test_hash_123",
        ioc_type=IOCType.SHA256,
        malware_families=["BazarLoader"],
        infrastructure=vt_infra,
    )

    # 2. MalwareBazaar returns "BazaLoader" and "Bazloader"
    mb_infra = InfrastructureData(
        threat_attributions=[
            ThreatAttribution(
                malware_family="BazaLoader",
                sources=["malwarebazaar"],
                confidence=90.0,
                evidence_summary='MalwareBazaar — verified signature "BazaLoader"',
            ),
            ThreatAttribution(
                malware_family="Bazloader",
                sources=["malwarebazaar"],
                confidence=90.0,
                evidence_summary='MalwareBazaar — verified signature "Bazloader"',
            ),
        ]
    )
    r_mb = ProviderResult(
        provider_name="malwarebazaar",
        status=ProviderStatus.SUCCESS,
        ioc_value="test_hash_123",
        ioc_type=IOCType.SHA256,
        infrastructure=mb_infra,
    )

    # 3. Provider returns "Bazar" (must remain separate)
    r_bazar = ProviderResult(
        provider_name="threatfox",
        status=ProviderStatus.SUCCESS,
        ioc_value="test_hash_123",
        ioc_type=IOCType.SHA256,
        malware_families=["Bazar"],
    )

    # 4. Hybrid Analysis returns "Trojan.Generic"
    ha_infra = InfrastructureData(
        threat_attributions=[
            ThreatAttribution(
                detection_classification="Trojan.Generic",
                verdict="malicious",
                sources=["hybrid_analysis"],
                confidence=85.0,
                evidence_summary="Falcon Sandbox classification 'Trojan.Generic' with verdict 'malicious'",
            )
        ]
    )
    r_ha = ProviderResult(
        provider_name="hybrid_analysis",
        status=ProviderStatus.SUCCESS,
        ioc_value="test_hash_123",
        ioc_type=IOCType.SHA256,
        infrastructure=ha_infra,
    )

    layer2 = build_layer2_infrastructure(
        root_ioc="test_hash_123",
        root_type=IOCType.SHA256,
        provider_results=[r_vt, r_mb, r_bazar, r_ha],
    )

    agg = layer2.aggregated_infrastructure
    assert agg is not None
    attrs = agg.threat_attributions

    # 1. Exactly ONE canonical entry for BazarLoader
    bazarloader_matches = [a for a in attrs if a.malware_family == "BazarLoader"]
    assert len(bazarloader_matches) == 1
    bl = bazarloader_matches[0]
    assert any("virustotal" in s.lower() for s in bl.sources)
    assert any("malwarebazaar" in s.lower() for s in bl.sources)
    assert any("bazloader" in a.lower() for a in bl.aliases)
    assert any("bazaloader" in a.lower() for a in bl.aliases)

    # 2. Bazar is a separate card, NOT merged into BazarLoader
    bazar_matches = [a for a in attrs if a.malware_family == "Bazar"]
    assert len(bazar_matches) == 1
    assert bazar_matches[0].malware_family != bl.malware_family

    # 3. NO card has malware_family == "Generic" or "Trojan.Generic"
    generic_malware_families = [a for a in attrs if a.malware_family and "generic" in a.malware_family.lower()]
    assert len(generic_malware_families) == 0

    # 4. Trojan.Generic is preserved under detection_classification
    generic_classifications = [a for a in attrs if a.detection_classification and "generic" in a.detection_classification.lower()]
    assert len(generic_classifications) == 1
    assert generic_classifications[0].verdict == "malicious"
    assert generic_classifications[0].malware_family is None


