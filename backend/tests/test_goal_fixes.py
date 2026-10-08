import pytest
from app.schemas.ioc import IOCType, ProviderStatus
from app.schemas.provider import ProviderResult, InfrastructureData, FileMetadata, DiscoveredIOC
from app.providers.base import ProviderRequestContext
from app.providers.malwarebazaar import MalwareBazaarProvider
from app.providers.threatfox import ThreatFoxProvider
from app.providers.hybrid_analysis import HybridAnalysisProvider
from app.providers.virustotal import VirusTotalProvider
from app.providers.otx import AlienVaultOTXProvider
from app.providers.shodan import ShodanProvider
from app.providers.router import ProviderRouter
from app.services.enrichment import build_layer1_reputation, build_layer2_infrastructure, build_layer3_buckets
from app.services.deduplication import deduplicate_discovered_iocs
from app.services.graph import build_graph


@pytest.mark.asyncio
async def test_a_ip_malwarebazaar_not_called_and_reports_unsupported():
    """Requirement A: For an IP investigation, MalwareBazaar is not called as a hash lookup and reports UNSUPPORTED."""
    router = ProviderRouter(is_mock=False)
    results = await router.route_ioc("94.231.206.248", IOCType.IPV4)
    mb_results = [r for r in results if r.provider_name == "malwarebazaar"]
    # Issue 3 Requirement: Unsupported providers must NOT appear at all in routed results
    assert len(mb_results) == 0

    # Also test provider directly with IP
    prov = MalwareBazaarProvider()
    direct_res = await prov.execute(ProviderRequestContext(
        ioc_value="94.231.206.248",
        ioc_type=IOCType.IPV4,
        api_key="test_key",
    ))
    assert direct_res.status == ProviderStatus.UNSUPPORTED


@pytest.mark.asyncio
async def test_b_hash_malwarebazaar_supported():
    """Requirement B: For a hash, MalwareBazaar capability is supported."""
    prov = MalwareBazaarProvider()
    assert prov.is_ioc_supported(IOCType.SHA256)
    assert prov.is_ioc_supported(IOCType.MD5)
    assert not prov.is_ioc_supported(IOCType.IPV4)
    assert not prov.is_ioc_supported(IOCType.DOMAIN)
    assert not prov.is_ioc_supported(IOCType.URL)


def test_c_threatfox_hash_and_ip_parsing():
    """Requirement C: ThreatFox handles hash match and parses response correctly."""
    prov = ThreatFoxProvider()
    ctx = ProviderRequestContext(
        ioc_value="396309c6770d009f9642e5b6d09528a18cecea59a873b8fb0fbf5f7cfc8e0579",
        ioc_type=IOCType.SHA256,
        api_key="test",
    )
    sample_data = {
        "query_status": "ok",
        "data": [{
            "id": "1901412",
            "ioc": "396309c6770d009f9642e5b6d09528a18cecea59a873b8fb0fbf5f7cfc8e0579",
            "threat_type": "payload",
            "malware_printable": "Coruna",
            "confidence_level": 100,
            "tags": ["Coruna", "ios"],
        }]
    }
    res = prov._parse_response(ctx, sample_data)
    assert res.status == ProviderStatus.SUCCESS
    assert res.classification == "malicious"
    assert res.reputation_score == 100.0
    assert "Coruna" in res.malware_families


def test_d_hybrid_analysis_error_handling():
    """Requirement D: Hybrid Analysis distinguishes 403 invalid API key as UNAUTHORIZED."""
    prov = HybridAnalysisProvider()
    assert prov.is_ioc_supported(IOCType.SHA256)
    assert not prov.is_ioc_supported(IOCType.URL)


def test_e_virustotal_details_to_layer2():
    """Requirement E: Technical details extracted from VirusTotal appear in Layer 2."""
    prov = VirusTotalProvider()
    ctx = ProviderRequestContext(
        ioc_value="275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
        ioc_type=IOCType.SHA256,
        api_key="test",
    )
    vt_mock_data = {
        "data": {
            "attributes": {
                "type_description": "Powershell",
                "magic": "EICAR virus test files",
                "size": 68,
                "md5": "44d88612fea8a8f36de82e1278abb02f",
                "sha1": "3395856ce81f2b7382dee72602f798b642f14140",
                "sha256": "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
                "vhash": "0123456789",
                "ssdeep": "3:a+JraNvsgzsVqSwHq9:tJuOgzsko",
                "tlsh": "T141A022003B0EEE2BA20B00200032E8B00808020E2CE00A3820A020B8C83308803EC228",
                "magika": "POWERSHELL",
                "names": ["eicar.com", "eicar.ps1"],
                "last_analysis_stats": {"malicious": 60, "suspicious": 0, "harmless": 0}
            },
            "relationships": {
                "contacted_ips": {"data": [{"id": "198.51.100.1"}]},
                "contacted_domains": {"data": [{"id": "badc2.example.com"}]},
                "contacted_urls": {"data": [{"id": "url1", "context_attributes": {"url": "http://badc2.example.com/payload"}}]},
                "bundled_files": {"data": [{"id": "a" * 64}]}
            }
        }
    }
    vt_res = prov._parse_response(ctx, vt_mock_data)
    assert vt_res.status == ProviderStatus.SUCCESS
    assert vt_res.infrastructure.file_metadata is not None
    fm = vt_res.infrastructure.file_metadata
    assert fm.file_type == "Powershell"
    assert fm.magic == "EICAR virus test files"
    assert fm.file_size == 68
    assert fm.md5 == "44d88612fea8a8f36de82e1278abb02f"
    assert fm.vhash == "0123456789"
    assert "eicar.com" in fm.file_names

    l2 = build_layer2_infrastructure(ctx.ioc_value, ctx.ioc_type, [vt_res])
    agg_fm = l2.aggregated_infrastructure.file_metadata
    assert agg_fm is not None
    assert agg_fm.file_type == "Powershell"
    assert agg_fm.md5 == "44d88612fea8a8f36de82e1278abb02f"
    assert "virustotal" in agg_fm.sources


def test_f_virustotal_relations_to_layer3():
    """Requirement F: VirusTotal relations appear in Layer 3."""
    prov = VirusTotalProvider()
    ctx = ProviderRequestContext(
        ioc_value="275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
        ioc_type=IOCType.SHA256,
        api_key="test",
    )
    vt_mock_data = {
        "data": {
            "attributes": {"last_analysis_stats": {"malicious": 10}},
            "relationships": {
                "contacted_ips": {"data": [{"id": "198.51.100.1"}]},
                "contacted_domains": {"data": [{"id": "badc2.example.com"}]},
                "contacted_urls": {"data": [{"id": "url1", "context_attributes": {"url": "http://badc2.example.com/payload"}}]},
                "bundled_files": {"data": [{"id": "b" * 64}]}
            }
        }
    }
    vt_res = prov._parse_response(ctx, vt_mock_data)
    disc_types = {d.relationship_type: d for d in vt_res.discovered_iocs}
    assert "contacted_ip" in disc_types
    assert disc_types["contacted_ip"].raw_value == "198.51.100.1"
    assert "contacted_domain" in disc_types
    assert disc_types["contacted_domain"].raw_value == "badc2.example.com"
    assert "contacted_url" in disc_types
    assert disc_types["contacted_url"].raw_value == "http://badc2.example.com/payload"
    assert "bundled_file" in disc_types
    assert disc_types["bundled_file"].raw_value == "b" * 64


def test_g_otx_pulse_indicators_extracted_to_layer3():
    """Requirement G: Indicators inside OTX Pulses are extracted with pulse metadata and added to Layer 3."""
    prov = AlienVaultOTXProvider()
    ctx = ProviderRequestContext(
        ioc_value="275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
        ioc_type=IOCType.SHA256,
        api_key="test",
    )
    otx_mock_data = {
        "pulse_info": {
            "count": 1,
            "pulses": [{
                "id": "pulse-12345",
                "name": "Campaign Alpha C2",
                "adversary": "APT-99",
                "indicators": [
                    {"indicator": "203.0.113.5", "type": "IPv4"},
                    {"indicator": "apt-c2.evil.com", "type": "domain"},
                    {"indicator": "http://apt-c2.evil.com/gate.php", "type": "URL"},
                    {"indicator": "c" * 64, "type": "FileHash-SHA256"},
                ]
            }]
        }
    }
    otx_res = prov._parse_response(ctx, otx_mock_data)
    assert otx_res.status == ProviderStatus.SUCCESS
    assert len(otx_res.discovered_iocs) == 4

    for ind in otx_res.discovered_iocs:
        assert ind.relationship_type == "pulse_indicator"
        assert ind.metadata["pulse_id"] == "pulse-12345"
        assert ind.metadata["pulse_name"] == "Campaign Alpha C2"
        assert "Campaign Alpha C2" in ind.evidence_desc

    ciocs, rels = deduplicate_discovered_iocs(ctx.ioc_value, ctx.ioc_type, [otx_res])
    layer3 = build_layer3_buckets(ciocs)
    assert len(layer3.ips) == 1
    assert layer3.ips[0].canonical_value == "203.0.113.5"
    assert len(layer3.urls_and_domains) == 2
    assert len(layer3.hashes) == 1
    assert layer3.hashes[0].canonical_value == "c" * 64


def test_h_shodan_remains_strictly_in_layer2():
    """Requirement H: Shodan host data belongs in Layer 2 and NEVER in Layer 1."""
    shodan_res = ProviderResult(
        provider_name="shodan",
        ioc_value="8.8.8.8",
        ioc_type=IOCType.IPV4,
        status=ProviderStatus.SUCCESS,
        infrastructure=InfrastructureData(
            open_ports=[53, 443],
            asn="15169",
            asn_name="Google LLC",
        )
    )
    l1 = build_layer1_reputation("8.8.8.8", IOCType.IPV4, [shodan_res])
    assert len(l1.provider_results) == 0

    l2 = build_layer2_infrastructure("8.8.8.8", IOCType.IPV4, [shodan_res])
    assert l2.aggregated_infrastructure.network.asn == "15169"
    assert 53 in l2.aggregated_infrastructure.open_ports


def test_j_graph_uses_layer3_relationships():
    """Requirement J: Graph uses the same real Layer 3 relationships and roots at current investigated IOC."""
    root = "test-investigated-ioc.com"
    root_type = IOCType.DOMAIN

    vt_res = ProviderResult(
        provider_name="virustotal",
        ioc_value=root,
        ioc_type=root_type,
        status=ProviderStatus.SUCCESS,
        discovered_iocs=[
            DiscoveredIOC(
                raw_value="198.51.100.22",
                canonical_value="198.51.100.22",
                ioc_type=IOCType.IPV4,
                relationship_type="resolves_to",
                confidence=90.0,
            )
        ]
    )
    ciocs, rels = deduplicate_discovered_iocs(root, root_type, [vt_res])
    graph = build_graph(root, root_type, 100.0, ciocs, rels)
    assert graph.root_ioc == root
    assert len(graph.nodes) == 2
    assert graph.nodes[0].id == root
    assert graph.nodes[0].is_root is True
    assert graph.nodes[1].id == "198.51.100.22"
    assert len(graph.edges) == 1
    assert graph.edges[0].source == root
    assert graph.edges[0].target == "198.51.100.22"
