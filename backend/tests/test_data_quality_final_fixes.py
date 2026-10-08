import pytest
from app.schemas.ioc import IOCType, ProviderStatus
from app.schemas.provider import (
    ProviderResult,
    InfrastructureData,
    GeoInfo,
    DnsInfo,
    DnsRecordItem,
    ThreatAttribution,
    ServiceInfo,
    CertInfo,
)
from app.services.enrichment import (
    build_layer2_infrastructure,
    attach_infrastructure_iocs,
    is_valid_hostname_or_domain,
    _is_ip_str,
    is_av_signature,
)


def test_is_valid_hostname_or_domain_and_ip_check():
    assert _is_ip_str("45.135.193.63") is True
    assert _is_ip_str("2606:4700:4700::1111") is True
    assert _is_ip_str("example.com") is False
    assert _is_ip_str("mx1.example.com") is False

    assert is_valid_hostname_or_domain("example.com") is True
    assert is_valid_hostname_or_domain("mx1-usg2.ppe-hosted.com") is True
    assert is_valid_hostname_or_domain("45.135.193.63") is False
    assert is_valid_hostname_or_domain("2606:4700:4700::1111") is False
    assert is_valid_hostname_or_domain("localhost.localdomain") is False
    assert is_valid_hostname_or_domain("test.local") is False


def test_av_signature_detection():
    assert is_av_signature("Mal/HTMLGen-A") is True
    assert is_av_signature("Mal HTML Gen A") is True
    assert is_av_signature("Win32/Trojan.Generic") is True
    assert is_av_signature("HEUR:Trojan.Script") is True
    assert is_av_signature("BazarLoader") is False
    assert is_av_signature("GlassRAT") is False
    assert is_av_signature("Cobalt Strike") is False


def test_dns_mx_synchronization_to_mail_config():
    """
    Ensures that canonical DNS MX records are synchronized into WebCheck mail-config
    so that ThreatLens never displays 'No MX mail exchange servers routed to this target'
    when DNS records contain MX entries.
    """
    prov_res = ProviderResult(
        provider_name="securitytrails",
        ioc_value="example.com",
        ioc_type=IOCType.DOMAIN,
        status=ProviderStatus.SUCCESS,
        infrastructure=InfrastructureData(
            dns_records={
                "MX": ["10 mx1-usg2.ppe-hosted.com", "20 mx2-usg2.ppe-hosted.com"]
            },
            dns=DnsInfo(
                hostnames=["example.com"],
                domains=["example.com"],
                records=[
                    DnsRecordItem(record_type="MX", value="10 mx1-usg2.ppe-hosted.com", sources=["securitytrails"]),
                    DnsRecordItem(record_type="MX", value="20 mx2-usg2.ppe-hosted.com", sources=["securitytrails"]),
                ],
                sources=["securitytrails"],
            ),
            extra={"webcheck": {"mail-config": {"mx": []}}}
        )
    )

    layer2 = build_layer2_infrastructure("example.com", IOCType.DOMAIN, [prov_res])
    agg = layer2.aggregated_infrastructure

    assert "MX" in agg.dns_records
    assert len(agg.dns_records["MX"]) == 2

    # Check webcheck extra synchronization
    webcheck_mail = agg.extra.get("webcheck", {}).get("mail-config", {})
    assert "mx" in webcheck_mail
    assert len(webcheck_mail["mx"]) == 2
    assert webcheck_mail["mx"][0]["exchange"] == "mx1-usg2.ppe-hosted.com"
    assert webcheck_mail["mx"][0]["priority"] == 10
    assert webcheck_mail["mx"][1]["exchange"] == "mx2-usg2.ppe-hosted.com"
    assert webcheck_mail["mx"][1]["priority"] == 20


def test_geolocation_source_isolation_and_alternatives():
    """
    Ensures that geolocation fields from different providers are never mixed.
    Censys observation (US, CA, SF) and Criminal IP observation (CA, Ontario, Toronto)
    must remain internally consistent, with Criminal IP preserved in alternative_geolocations.
    """
    censys_res = ProviderResult(
        provider_name="censys",
        ioc_value="1.2.3.4",
        ioc_type=IOCType.IPV4,
        status=ProviderStatus.SUCCESS,
        infrastructure=InfrastructureData(
            geo=GeoInfo(
                country="US",
                region="California",
                city="San Francisco",
                latitude=37.7749,
                longitude=-122.4194,
                sources=["censys"],
            )
        )
    )

    criminalip_res = ProviderResult(
        provider_name="criminalip",
        ioc_value="1.2.3.4",
        ioc_type=IOCType.IPV4,
        status=ProviderStatus.SUCCESS,
        infrastructure=InfrastructureData(
            geo=GeoInfo(
                country="Canada",
                region="Ontario",
                city="Toronto",
                latitude=43.6532,
                longitude=-79.3832,
                sources=["criminalip"],
            )
        )
    )

    layer2 = build_layer2_infrastructure("1.2.3.4", IOCType.IPV4, [censys_res, criminalip_res])
    agg = layer2.aggregated_infrastructure

    # Primary geo must be 100% self-consistent (Censys preferred by priority)
    assert agg.geo is not None
    assert agg.geo.country == "US"
    assert agg.geo.region == "California"
    assert agg.geo.city == "San Francisco"
    assert agg.geo.latitude == 37.7749
    assert agg.geo.longitude == -122.4194
    assert "censys" in agg.geo.sources

    # Alternative observation must preserve Criminal IP observation without field mixing
    assert len(agg.alternative_geolocations) >= 1
    alt = next(g for g in agg.alternative_geolocations if "criminalip" in g.sources)
    assert alt.country == "Canada"
    assert alt.region == "Ontario"
    assert alt.city == "Toronto"
    assert alt.latitude == 43.6532
    assert alt.longitude == -79.3832
    assert "criminalip" in alt.sources


def test_ip_address_not_emitted_as_hostname_or_domain():
    """
    Strict IOC type validation: raw IP addresses must never appear as hostnames or domains
    in Layer 2 DNS data or Layer 3 canonical IOCs.
    """
    criminalip_res = ProviderResult(
        provider_name="criminalip",
        ioc_value="45.135.193.63",
        ioc_type=IOCType.IPV4,
        status=ProviderStatus.SUCCESS,
        infrastructure=InfrastructureData(
            ptr="45.135.193.63",  # Malformed PTR returned as IP string
            dns=DnsInfo(
                hostnames=["45.135.193.63", "valid-host.com"],
                domains=["45.135.193.63", "valid-host.com"],
                sources=["criminalip"],
            ),
            dns_records={
                "A": ["45.135.193.63"],
                "MX": ["10 45.135.193.63", "10 mail.valid-host.com"],
            }
        )
    )

    layer2 = build_layer2_infrastructure("45.135.193.63", IOCType.IPV4, [criminalip_res])
    agg = layer2.aggregated_infrastructure

    # Verify IP filtered from hostnames and domains
    assert agg.dns is not None
    assert "45.135.193.63" not in agg.dns.hostnames
    assert "valid-host.com" in agg.dns.hostnames
    assert "45.135.193.63" not in agg.dns.domains
    assert "valid-host.com" in agg.dns.domains

    # Verify Layer 3 IOC creation never types an IP as a DOMAIN
    iocs, rels = attach_infrastructure_iocs(
        root_canonical="45.135.193.63",
        root_type=IOCType.IPV4,
        layer2=layer2,
        existing_iocs=[],
        existing_relationships=[],
    )

    domain_iocs = [i for i in iocs if i.ioc_type == IOCType.DOMAIN]
    for d_ioc in domain_iocs:
        assert _is_ip_str(d_ioc.canonical_value) is False
        assert d_ioc.canonical_value != "45.135.193.63"


def test_av_signature_routed_to_detection_name_not_family():
    """
    AV signatures like 'Mal/HTMLGen-A' must not become canonical malware families.
    They must be routed to provider_detection_name.
    """
    vt_res = ProviderResult(
        provider_name="virustotal",
        ioc_value="example.com",
        ioc_type=IOCType.DOMAIN,
        status=ProviderStatus.SUCCESS,
        infrastructure=InfrastructureData(
            threat_attributions=[
                ThreatAttribution(
                    malware_family="Mal/HTMLGen-A",
                    sources=["virustotal"],
                )
            ]
        )
    )

    layer2 = build_layer2_infrastructure("example.com", IOCType.DOMAIN, [vt_res])
    agg = layer2.aggregated_infrastructure

    assert len(agg.threat_attributions) == 1
    attr = agg.threat_attributions[0]
    assert attr.malware_family is None
    assert attr.provider_detection_name == "Mal/HTMLGen-A"
    assert attr.is_corroborated is False  # Only 1 provider


def test_corroborated_attribution_evidence_based():
    """
    Corroboration is evidence-based: only entities with >= 2 independent sources
    receive the is_corroborated flag.
    """
    res1 = ProviderResult(
        provider_name="virustotal",
        ioc_value="1.2.3.4",
        ioc_type=IOCType.IPV4,
        status=ProviderStatus.SUCCESS,
        infrastructure=InfrastructureData(
            threat_attributions=[
                ThreatAttribution(
                    malware_family="BazarLoader",
                    sources=["virustotal"],
                )
            ]
        )
    )

    res2 = ProviderResult(
        provider_name="shodan",
        ioc_value="1.2.3.4",
        ioc_type=IOCType.IPV4,
        status=ProviderStatus.SUCCESS,
        infrastructure=InfrastructureData(
            threat_attributions=[
                ThreatAttribution(
                    malware_family="BazarLoader",
                    sources=["shodan"],
                )
            ]
        )
    )

    # 1 source -> is_corroborated is False
    layer2_single = build_layer2_infrastructure("1.2.3.4", IOCType.IPV4, [res1])
    assert layer2_single.aggregated_infrastructure.threat_attributions[0].is_corroborated is False

    # 2 independent sources -> is_corroborated is True
    layer2_multi = build_layer2_infrastructure("1.2.3.4", IOCType.IPV4, [res1, res2])
    attr_multi = layer2_multi.aggregated_infrastructure.threat_attributions[0]
    assert attr_multi.is_corroborated is True
    assert {s.lower() for s in attr_multi.sources} == {"virustotal", "shodan"}
    assert attr_multi.confidence >= 80.0  # Dynamic multi-provider boost
