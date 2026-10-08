import pytest
from app.schemas.ioc import IOCType, ProviderStatus
from app.schemas.provider import ProviderResult, DiscoveredIOC
from app.services.deduplication import deduplicate_discovered_iocs
from app.services.enrichment import build_layer3_buckets


def test_global_ioc_and_relationship_deduplication():
    """
    If:
    VirusTotal -> example.com
    urlscan -> example.com
    OTX -> example.com
    then the application MUST show example.com ONCE.
    And relationships merged with multiple providers!
    """
    res1 = ProviderResult(
        provider_name="virustotal",
        ioc_value="192.0.2.1",
        ioc_type=IOCType.IPV4,
        status=ProviderStatus.SUCCESS,
        discovered_iocs=[
            DiscoveredIOC(
                raw_value="example.com",
                canonical_value="example.com",
                ioc_type=IOCType.DOMAIN,
                relationship_type="resolves_to",
                confidence=80.0,
                evidence_desc="VT DNS resolution",
            )
        ],
    )
    res2 = ProviderResult(
        provider_name="urlscan",
        ioc_value="192.0.2.1",
        ioc_type=IOCType.IPV4,
        status=ProviderStatus.SUCCESS,
        discovered_iocs=[
            DiscoveredIOC(
                raw_value="EXAMPLE.COM",  # non-normalized
                canonical_value="example.com",
                ioc_type=IOCType.DOMAIN,
                relationship_type="resolves_to",
                confidence=85.0,
                evidence_desc="urlscan DOM domain",
            )
        ],
    )
    res3 = ProviderResult(
        provider_name="otx",
        ioc_value="192.0.2.1",
        ioc_type=IOCType.IPV4,
        status=ProviderStatus.SUCCESS,
        discovered_iocs=[
            DiscoveredIOC(
                raw_value="example.com",
                canonical_value="example.com",
                ioc_type=IOCType.DOMAIN,
                relationship_type="resolves_to",
                confidence=70.0,
                evidence_desc="OTX passive DNS",
            ),
            DiscoveredIOC(
                raw_value="d41d8cd98f00b204e9800998ecf8427e",
                canonical_value="d41d8cd98f00b204e9800998ecf8427e",
                ioc_type=IOCType.MD5,
                relationship_type="downloads",
                confidence=90.0,
                evidence_desc="OTX related sample",
            ),
        ],
    )

    canonical_iocs, relationships = deduplicate_discovered_iocs(
        root_canonical="192.0.2.1",
        root_type=IOCType.IPV4,
        provider_results=[res1, res2, res3],
        current_depth=1,
    )

    # Must have exactly 2 canonical IOCs: example.com and the MD5 hash
    assert len(canonical_iocs) == 2

    # Check example.com is present once with 3 contributing providers
    example_ioc = next(i for i in canonical_iocs if i.canonical_value == "example.com")
    assert set(example_ioc.providers) == {"virustotal", "urlscan", "otx"}

    # Check relationship deduplication
    resolves_rel = next(r for r in relationships if r.target_value == "example.com")
    assert set(resolves_rel.providers) == {"virustotal", "urlscan", "otx"}
    assert resolves_rel.evidence_count == 3


def test_layer3_tri_bucket_classification():
    from app.schemas.investigation import CanonicalIOCResponse

    iocs = [
        CanonicalIOCResponse(
            id="1", canonical_value="d41d8cd98f00b204e9800998ecf8427e", ioc_type=IOCType.MD5, is_root=False, depth=1, confidence=80
        ),
        CanonicalIOCResponse(
            id="2", canonical_value="8.8.8.8", ioc_type=IOCType.IPV4, is_root=False, depth=1, confidence=80
        ),
        CanonicalIOCResponse(
            id="3", canonical_value="evil.com", ioc_type=IOCType.DOMAIN, is_root=False, depth=1, confidence=80
        ),
        CanonicalIOCResponse(
            id="4", canonical_value="http://evil.com/mal.exe", ioc_type=IOCType.URL, is_root=False, depth=1, confidence=80
        ),
    ]

    buckets = build_layer3_buckets(iocs)
    assert len(buckets.hashes) == 1
    assert len(buckets.ips) == 1
    assert len(buckets.urls_and_domains) == 2
    assert buckets.total_count == 4
