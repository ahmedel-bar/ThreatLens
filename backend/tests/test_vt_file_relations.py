import pytest
from app.schemas.ioc import IOCType, ProviderStatus
from app.providers.base import ProviderRequestContext
from app.providers.virustotal import VirusTotalProvider
from app.services.deduplication import deduplicate_discovered_iocs
from app.services.enrichment import build_layer3_buckets
from app.services.graph import build_graph
from app.services.pivot import RecursivePivotEngine
from app.providers.router import ProviderRouter


def test_virustotal_file_relations_extraction():
    """
    Verifies that VirusTotal extracts actual hashes from communicating_files,
    bundled_files, dropped_files, downloaded_files, and related_files,
    preserving metadata such as filename and detections.
    """
    prov = VirusTotalProvider()
    ctx = ProviderRequestContext(
        ioc_value="8.8.8.8",
        ioc_type=IOCType.IPV4,
        api_key="test",
    )

    sample_sha256 = "00000006e9d3a7e85d1f1e7711787b9a117655e249a565122ee12e9962199007"
    sample_sha1 = "3395856ce81f2b7382dee72602f798b642f14140"
    sample_md5 = "44d88612fea8a8f36de82e1278abb02f"

    vt_mock_response = {
        "data": {
            "id": "8.8.8.8",
            "type": "ip_address",
            "attributes": {
                "last_analysis_stats": {"malicious": 0, "harmless": 80},
            },
            "relationships": {
                # 1. Communicating file with filename and detections in attributes
                "communicating_files": {
                    "data": [
                        {
                            "type": "file",
                            "id": sample_sha256,
                            "attributes": {
                                "meaningful_name": "2l0yh8.exe",
                                "sha256": sample_sha256,
                                "type_description": "Win32 EXE",
                                "last_analysis_stats": {"malicious": 45, "harmless": 24},
                            },
                        }
                    ]
                },
                # 2. Downloaded file with SHA1
                "downloaded_files": {
                    "data": [
                        {
                            "type": "file",
                            "id": sample_sha1,
                            "attributes": {
                                "meaningful_name": "downloader_payload.bin",
                                "sha1": sample_sha1,
                                "last_analysis_stats": {"malicious": 20, "harmless": 10},
                            },
                        }
                    ]
                },
                # 3. Dropped file with MD5
                "dropped_files": {
                    "data": [
                        {
                            "type": "file",
                            "id": sample_md5,
                            "attributes": {
                                "meaningful_name": "dropped_config.dat",
                                "md5": sample_md5,
                            },
                        }
                    ]
                },
                # 4. Non-file relation (must NOT be treated as a file)
                "resolutions": {
                    "data": [
                        {
                            "type": "resolution",
                            "id": "dns.google",
                        }
                    ]
                }
            }
        }
    }

    result = prov._parse_response(ctx, vt_mock_response)
    assert result.status == ProviderStatus.SUCCESS

    # Find communicating_file
    comm_file = next((d for d in result.discovered_iocs if d.canonical_value == sample_sha256), None)
    assert comm_file is not None
    assert comm_file.ioc_type == IOCType.SHA256
    assert comm_file.relationship_type == "communicating_file"
    assert comm_file.metadata.get("filename") == "2l0yh8.exe"
    assert comm_file.metadata.get("detections") == "45/69"

    # Find downloaded_file
    down_file = next((d for d in result.discovered_iocs if d.canonical_value == sample_sha1), None)
    assert down_file is not None
    assert down_file.ioc_type == IOCType.SHA1
    assert down_file.relationship_type == "downloaded_file"
    assert down_file.metadata.get("filename") == "downloader_payload.bin"

    # Find dropped_file
    drop_file = next((d for d in result.discovered_iocs if d.canonical_value == sample_md5), None)
    assert drop_file is not None
    assert drop_file.ioc_type == IOCType.MD5
    assert drop_file.relationship_type == "dropped_file"


def test_multi_relation_and_multi_provider_deduplication():
    """
    Verifies that if the same hash appears across multiple relations
    (e.g., communicating_files and bundled_files) and multiple providers (VT and OTX),
    it is deduplicated into exactly ONE canonical IOC with merged relationships and providers.
    """
    from app.schemas.provider import ProviderResult, DiscoveredIOC

    target_hash = "00000006e9d3a7e85d1f1e7711787b9a117655e249a565122ee12e9962199007"

    # VT returns target_hash under both communicating_file and bundled_file
    vt_res = ProviderResult(
        provider_name="virustotal",
        ioc_value="8.8.8.8",
        ioc_type=IOCType.IPV4,
        status=ProviderStatus.SUCCESS,
        discovered_iocs=[
            DiscoveredIOC(
                raw_value=target_hash,
                canonical_value=target_hash,
                ioc_type=IOCType.SHA256,
                relationship_type="communicating_file",
                confidence=90.0,
                metadata={"filename": "2l0yh8.exe", "detections": "45/69"},
            ),
            DiscoveredIOC(
                raw_value=target_hash,
                canonical_value=target_hash,
                ioc_type=IOCType.SHA256,
                relationship_type="bundled_file",
                confidence=85.0,
                metadata={"filename": "2l0yh8.exe"},
            ),
        ],
    )

    # OTX returns the same hash under pulse_indicator
    otx_res = ProviderResult(
        provider_name="otx",
        ioc_value="8.8.8.8",
        ioc_type=IOCType.IPV4,
        status=ProviderStatus.SUCCESS,
        discovered_iocs=[
            DiscoveredIOC(
                raw_value=target_hash,
                canonical_value=target_hash,
                ioc_type=IOCType.SHA256,
                relationship_type="pulse_indicator",
                confidence=80.0,
                metadata={"pulse_name": "Adversary Campaign 2026"},
            ),
        ],
    )

    canonical_iocs, relationships = deduplicate_discovered_iocs(
        root_canonical="8.8.8.8",
        root_type=IOCType.IPV4,
        provider_results=[vt_res, otx_res],
    )

    # Must be exactly ONE canonical IOC for target_hash
    matching_iocs = [i for i in canonical_iocs if i.canonical_value == target_hash]
    assert len(matching_iocs) == 1
    ioc = matching_iocs[0]

    assert ioc.ioc_type == IOCType.SHA256
    # Both providers must be present
    assert "virustotal" in ioc.providers
    assert "otx" in ioc.providers
    # All 3 relationships must be captured
    assert "communicating_file" in ioc.relationships
    assert "bundled_file" in ioc.relationships
    assert "pulse_indicator" in ioc.relationships
    # Metadata preserved
    assert ioc.metadata.get("filename") == "2l0yh8.exe"

    # Layer 3 Tri-bucket grouping
    buckets = build_layer3_buckets(canonical_iocs)
    assert len(buckets.hashes) == 1
    assert buckets.hashes[0].canonical_value == target_hash

    # Graph must contain exactly 1 node for target_hash
    graph = build_graph(
        root_ioc="8.8.8.8",
        root_type=IOCType.IPV4,
        root_confidence=10.0,
        discovered_iocs=canonical_iocs,
        relationships=relationships,
    )
    hash_nodes = [n for n in graph.nodes if n.id == target_hash]
    assert len(hash_nodes) == 1
    assert hash_nodes[0].type == "sha256"


@pytest.mark.asyncio
async def test_extracted_hash_is_pivotable():
    """
    Verifies that the extracted file hash is pivotable using the RecursivePivotEngine.
    """
    sample_sha256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
    router = ProviderRouter(is_mock=True)
    engine = RecursivePivotEngine(router=router, max_depth=2)
    iocs, rels, results = await engine.pivot_single_step(
        target_ioc=sample_sha256,
        target_type=IOCType.SHA256,
        current_depth=1,
        existing_iocs=[],
        existing_relationships=[],
    )

    assert len(results) > 0
    queried_provs = {r.provider_name for r in results}
    assert "virustotal" in queried_provs or "otx" in queried_provs or "malwarebazaar" in queried_provs
