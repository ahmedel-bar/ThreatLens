import pytest
import httpx
from unittest.mock import AsyncMock, patch
from app.schemas.ioc import IOCType, ProviderStatus
from app.providers.base import ProviderRequestContext
from app.providers.virustotal import VirusTotalProvider
from app.services.deduplication import deduplicate_discovered_iocs
from app.services.enrichment import build_layer3_buckets, build_layer2_infrastructure
from app.services.graph import build_graph


def _generate_mock_file(index: int, rel_type: str = "referrer_files") -> dict:
    """Generates a unique mock VirusTotal file object with valid SHA256."""
    sha256 = f"{index:064x}"
    return {
        "id": sha256,
        "type": "file",
        "attributes": {
            "meaningful_name": f"sample_{index}.exe",
            "sha256": sha256,
            "type_description": "Win32 EXE",
            "size": 1024 * (index + 1),
            "last_analysis_stats": {"malicious": 10 + (index % 50), "harmless": 20},
            "first_submission_date": 1600000000 + index * 100,
            "last_submission_date": 1700000000 + index * 100,
        },
    }


@pytest.mark.asyncio
async def test_virustotal_pagination_147_items():
    """
    Tests full 4-page pagination: 40 + 40 + 40 + 27 = 147 items.
    Verifies that all 147 items are retrieved, materialized, deduplicated,
    and structured into Layer 3 and Threat Graph.
    """
    prov = VirusTotalProvider()
    ctx = ProviderRequestContext(
        ioc_value="1.2.3.4",
        ioc_type=IOCType.IPV4,
        api_key="mock_vt_key",
    )

    page1_files = [_generate_mock_file(i) for i in range(1, 41)]  # 40 items
    page2_files = [_generate_mock_file(i) for i in range(41, 81)]  # 40 items
    page3_files = [_generate_mock_file(i) for i in range(81, 121)]  # 40 items
    page4_files = [_generate_mock_file(i) for i in range(121, 148)]  # 27 items

    base_entity_resp = {
        "data": {
            "id": "1.2.3.4",
            "type": "ip_address",
            "attributes": {
                "reputation": -50,
                "last_analysis_stats": {"malicious": 15, "harmless": 20},
            },
            "relationships": {
                "referrer_files": {
                    "data": page1_files,
                    "meta": {"count": 147, "cursor": "cursor_page2"},
                    "links": {
                        "self": "https://www.virustotal.com/api/v3/ip_addresses/1.2.3.4/relationships/referrer_files",
                        "next": "https://www.virustotal.com/api/v3/ip_addresses/1.2.3.4/relationships/referrer_files?cursor=cursor_page2&limit=40",
                    },
                }
            },
        }
    }

    page2_resp = {
        "data": page2_files,
        "meta": {"count": 147, "cursor": "cursor_page3"},
        "links": {
            "self": "https://www.virustotal.com/api/v3/ip_addresses/1.2.3.4/relationships/referrer_files?cursor=cursor_page2&limit=40",
            "next": "https://www.virustotal.com/api/v3/ip_addresses/1.2.3.4/relationships/referrer_files?cursor=cursor_page3&limit=40",
        },
    }

    page3_resp = {
        "data": page3_files,
        "meta": {"count": 147, "cursor": "cursor_page4"},
        "links": {
            "self": "https://www.virustotal.com/api/v3/ip_addresses/1.2.3.4/relationships/referrer_files?cursor=cursor_page3&limit=40",
            "next": "https://www.virustotal.com/api/v3/ip_addresses/1.2.3.4/relationships/referrer_files?cursor=cursor_page4&limit=40",
        },
    }

    page4_resp = {
        "data": page4_files,
        "meta": {"count": 147},
        "links": {
            "self": "https://www.virustotal.com/api/v3/ip_addresses/1.2.3.4/relationships/referrer_files?cursor=cursor_page4&limit=40",
        },
    }

    async def mock_get(url, *args, **kwargs):
        req = httpx.Request("GET", url)
        if "cursor_page2" in str(url):
            return httpx.Response(200, json=page2_resp, request=req)
        elif "cursor_page3" in str(url):
            return httpx.Response(200, json=page3_resp, request=req)
        elif "cursor_page4" in str(url):
            return httpx.Response(200, json=page4_resp, request=req)
        else:
            return httpx.Response(200, json=base_entity_resp, request=req)

    mock_client = AsyncMock(spec=httpx.AsyncClient)
    mock_client.get = AsyncMock(side_effect=mock_get)
    ctx.http_client = mock_client

    result = await prov.execute(ctx)
    assert result.status == ProviderStatus.SUCCESS

    # 1. Total materialized items check
    assert len(result.discovered_iocs) == 147

    # 2. Differentiate reported vs materialized counts
    assert result.infrastructure is not None
    assert result.infrastructure.extra["vt_reported_counts"]["referrer_files"] == 147
    assert result.infrastructure.extra["vt_materialized_counts"]["referrer_files"] == 147

    # 3. Deduplication pipeline
    ciocs, rels = deduplicate_discovered_iocs("1.2.3.4", IOCType.IPV4, [result])
    assert len(ciocs) == 147
    assert len(rels) == 147

    # 4. Layer 3 Bucketing
    l3 = build_layer3_buckets(ciocs)
    assert len(l3.hashes) == 147
    assert len(l3.ips) == 0
    assert len(l3.urls_and_domains) == 0

    # 5. Threat Graph Generation
    graph = build_graph("1.2.3.4", IOCType.IPV4, 85.0, ciocs, rels)
    assert len(graph.nodes) == 148  # 1 root + 147 discovered hashes
    assert len(graph.edges) == 147


@pytest.mark.asyncio
async def test_virustotal_pagination_rate_limit_preserves_pages():
    """
    Tests graceful HTTP 429 handling mid-pagination:
    Page 1 returns 40 items, Page 2 returns 40 items, Page 3 returns 429.
    Verifies that the 80 items retrieved so far are preserved and not lost.
    """
    prov = VirusTotalProvider()
    ctx = ProviderRequestContext(
        ioc_value="1.2.3.4",
        ioc_type=IOCType.IPV4,
        api_key="mock_vt_key",
    )

    page1_files = [_generate_mock_file(i) for i in range(1, 41)]
    page2_files = [_generate_mock_file(i) for i in range(41, 81)]

    base_entity_resp = {
        "data": {
            "id": "1.2.3.4",
            "type": "ip_address",
            "attributes": {"reputation": -20},
            "relationships": {
                "referrer_files": {
                    "data": page1_files,
                    "meta": {"count": 147, "cursor": "cursor_page2"},
                    "links": {
                        "next": "https://www.virustotal.com/api/v3/ip_addresses/1.2.3.4/relationships/referrer_files?cursor=cursor_page2",
                    },
                }
            },
        }
    }

    page2_resp = {
        "data": page2_files,
        "meta": {"count": 147, "cursor": "cursor_page3"},
        "links": {
            "next": "https://www.virustotal.com/api/v3/ip_addresses/1.2.3.4/relationships/referrer_files?cursor=cursor_page3",
        },
    }

    async def mock_get(url, *args, **kwargs):
        req = httpx.Request("GET", url)
        if "cursor_page2" in str(url):
            return httpx.Response(200, json=page2_resp, request=req)
        elif "cursor_page3" in str(url):
            # HTTP 429 rate limit on page 3
            return httpx.Response(429, json={"error": {"message": "Rate limit exceeded"}}, request=req)
        else:
            return httpx.Response(200, json=base_entity_resp, request=req)

    mock_client = AsyncMock(spec=httpx.AsyncClient)
    mock_client.get = AsyncMock(side_effect=mock_get)
    ctx.http_client = mock_client

    result = await prov.execute(ctx)
    assert result.status == ProviderStatus.SUCCESS

    # Should have preserved pages 1 and 2 (80 items total)
    assert len(result.discovered_iocs) == 80
    assert result.infrastructure.extra["vt_reported_counts"]["referrer_files"] == 147
    assert result.infrastructure.extra["vt_materialized_counts"]["referrer_files"] == 80

    # Evidence description should note that 80 of 147 were materialized
    first_ioc = result.discovered_iocs[0]
    assert "80 of 147 materialized" in first_ioc.evidence_desc
    assert first_ioc.metadata.get("vt_reported_count") == 147
    assert first_ioc.metadata.get("vt_materialized_count") == 80


@pytest.mark.asyncio
async def test_virustotal_duplicate_cursor_loop_prevention():
    """
    Tests that a duplicate cursor or URL in links.next does not cause an infinite loop.
    """
    prov = VirusTotalProvider()
    ctx = ProviderRequestContext(
        ioc_value="1.2.3.4",
        ioc_type=IOCType.IPV4,
        api_key="mock_vt_key",
    )

    file_item = _generate_mock_file(1)

    base_entity_resp = {
        "data": {
            "id": "1.2.3.4",
            "type": "ip_address",
            "attributes": {"reputation": 0},
            "relationships": {
                "referrer_files": {
                    "data": [file_item],
                    "meta": {"count": 10, "cursor": "loop_cursor"},
                    "links": {
                        "next": "https://www.virustotal.com/api/v3/ip_addresses/1.2.3.4/relationships/referrer_files?cursor=loop_cursor",
                    },
                }
            },
        }
    }

    loop_page_resp = {
        "data": [_generate_mock_file(2)],
        "meta": {"count": 10, "cursor": "loop_cursor"},  # Same cursor returned
        "links": {
            "next": "https://www.virustotal.com/api/v3/ip_addresses/1.2.3.4/relationships/referrer_files?cursor=loop_cursor",
        },
    }

    pagination_fetch_count = 0

    async def mock_get(url, *args, **kwargs):
        nonlocal pagination_fetch_count
        req = httpx.Request("GET", url)
        if "loop_cursor" in str(url):
            pagination_fetch_count += 1
            return httpx.Response(200, json=loop_page_resp, request=req)
        elif "/relationships/" in str(url) or "?" in str(url):
            return httpx.Response(404, json={"error": {"code": "NotFoundError"}}, request=req)
        return httpx.Response(200, json=base_entity_resp, request=req)

    mock_client = AsyncMock(spec=httpx.AsyncClient)
    mock_client.get = AsyncMock(side_effect=mock_get)
    ctx.http_client = mock_client

    result = await prov.execute(ctx)
    assert result.status == ProviderStatus.SUCCESS
    # Loop should be terminated after detecting duplicate URL/cursor, exactly 1 pagination page fetched
    assert pagination_fetch_count == 1
    assert len(result.discovered_iocs) == 2


@pytest.mark.asyncio
async def test_virustotal_cross_relationship_hash_deduplication():
    """
    Tests that when the same file hash appears in both referrer_files and communicating_files,
    deduplicate_discovered_iocs collapses them into a single canonical IOC with both relationships.
    """
    prov = VirusTotalProvider()
    ctx = ProviderRequestContext(
        ioc_value="1.2.3.4",
        ioc_type=IOCType.IPV4,
        api_key="mock_vt_key",
    )

    shared_hash = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    shared_file = {
        "id": shared_hash,
        "type": "file",
        "attributes": {
            "meaningful_name": "shared_payload.exe",
            "sha256": shared_hash,
            "type_description": "Win32 EXE",
            "last_analysis_stats": {"malicious": 35, "harmless": 5},
        },
    }

    base_entity_resp = {
        "data": {
            "id": "1.2.3.4",
            "type": "ip_address",
            "attributes": {"reputation": -40},
            "relationships": {
                "referrer_files": {
                    "data": [shared_file],
                    "meta": {"count": 1},
                    "links": {},
                },
                "communicating_files": {
                    "data": [shared_file],
                    "meta": {"count": 1},
                    "links": {},
                },
            },
        }
    }

    mock_client = AsyncMock(spec=httpx.AsyncClient)
    mock_client.get = AsyncMock(return_value=httpx.Response(200, json=base_entity_resp, request=httpx.Request("GET", "https://vt.test")))
    ctx.http_client = mock_client

    result = await prov.execute(ctx)
    assert result.status == ProviderStatus.SUCCESS
    assert len(result.discovered_iocs) == 2  # 1 from referrer, 1 from communicating

    ciocs, rels = deduplicate_discovered_iocs("1.2.3.4", IOCType.IPV4, [result])
    # Must deduplicate to exactly 1 canonical IOC
    assert len(ciocs) == 1
    assert ciocs[0].canonical_value == shared_hash
    assert sorted(ciocs[0].relationships) == ["communicating_file", "referrer_file"]

    # Relationship must also be merged
    assert len(rels) == 1
    assert "communicating_file" in rels[0].relationship_type
    assert "referrer_file" in rels[0].relationship_type


@pytest.mark.asyncio
async def test_virustotal_same_hash_across_multiple_pages():
    """
    Tests that if the same file hash appears on multiple pages of the same relationship,
    deduplicate_discovered_iocs collapses them into a single canonical IOC.
    """
    prov = VirusTotalProvider()
    ctx = ProviderRequestContext(
        ioc_value="1.2.3.4",
        ioc_type=IOCType.IPV4,
        api_key="mock_vt_key",
    )

    duplicate_file = _generate_mock_file(99)

    base_entity_resp = {
        "data": {
            "id": "1.2.3.4",
            "type": "ip_address",
            "attributes": {"reputation": -10},
            "relationships": {
                "referrer_files": {
                    "data": [duplicate_file],
                    "meta": {"count": 2, "cursor": "page2_cursor"},
                    "links": {
                        "next": "https://www.virustotal.com/api/v3/ip_addresses/1.2.3.4/relationships/referrer_files?cursor=page2_cursor",
                    },
                }
            },
        }
    }

    page2_resp = {
        "data": [duplicate_file],  # Duplicate file on page 2
        "meta": {"count": 2},
        "links": {},
    }

    async def mock_get(url, *args, **kwargs):
        req = httpx.Request("GET", url)
        if "page2_cursor" in str(url):
            return httpx.Response(200, json=page2_resp, request=req)
        return httpx.Response(200, json=base_entity_resp, request=req)

    mock_client = AsyncMock(spec=httpx.AsyncClient)
    mock_client.get = AsyncMock(side_effect=mock_get)
    ctx.http_client = mock_client

    result = await prov.execute(ctx)
    assert len(result.discovered_iocs) == 2

    ciocs, rels = deduplicate_discovered_iocs("1.2.3.4", IOCType.IPV4, [result])
    # Deduplicated to 1 canonical IOC
    assert len(ciocs) == 1
    assert ciocs[0].canonical_value == duplicate_file["id"]


@pytest.mark.asyncio
async def test_virustotal_url_entity_referrer_files_pagination():
    """
    Tests pagination of referrer_files for an IOCType.URL entity.
    """
    prov = VirusTotalProvider()
    ctx = ProviderRequestContext(
        ioc_value="http://evil-example.com/payload.php",
        ioc_type=IOCType.URL,
        api_key="mock_vt_key",
    )

    page1_files = [_generate_mock_file(i) for i in range(1, 11)]
    page2_files = [_generate_mock_file(i) for i in range(11, 21)]

    base_entity_resp = {
        "data": {
            "id": prov._get_url_id(ctx.ioc_value),
            "type": "url",
            "attributes": {"last_analysis_stats": {"malicious": 5, "harmless": 10}},
            "relationships": {
                "referrer_files": {
                    "data": page1_files,
                    "meta": {"count": 20, "cursor": "url_p2"},
                    "links": {
                        "next": f"https://www.virustotal.com/api/v3/urls/{prov._get_url_id(ctx.ioc_value)}/relationships/referrer_files?cursor=url_p2",
                    },
                }
            },
        }
    }

    page2_resp = {
        "data": page2_files,
        "meta": {"count": 20},
        "links": {},
    }

    async def mock_get(url, *args, **kwargs):
        req = httpx.Request("GET", url)
        if "url_p2" in str(url):
            return httpx.Response(200, json=page2_resp, request=req)
        return httpx.Response(200, json=base_entity_resp, request=req)

    mock_client = AsyncMock(spec=httpx.AsyncClient)
    mock_client.get = AsyncMock(side_effect=mock_get)
    ctx.http_client = mock_client

    result = await prov.execute(ctx)
    assert result.status == ProviderStatus.SUCCESS
    assert len(result.discovered_iocs) == 20
    assert result.infrastructure.extra["vt_reported_counts"]["referrer_files"] == 20
    assert result.infrastructure.extra["vt_materialized_counts"]["referrer_files"] == 20


@pytest.mark.asyncio
async def test_virustotal_full_canonical_hash_pivot_ready():
    """
    Verifies that all discovered file hashes are 64-char lowercase hex strings,
    properly typed as SHA256, and ready for pivoting.
    """
    prov = VirusTotalProvider()
    ctx = ProviderRequestContext(
        ioc_value="8.8.8.8",
        ioc_type=IOCType.IPV4,
        api_key="mock_vt_key",
    )

    raw_hash = "B3D5E4166E0C7A9E58A350EF7484B6F306A80C51F33B6D8D701201B4B6EBE29F"
    base_entity_resp = {
        "data": {
            "id": "8.8.8.8",
            "type": "ip_address",
            "attributes": {},
            "relationships": {
                "referrer_files": {
                    "data": [
                        {
                            "id": raw_hash,
                            "type": "file",
                            "attributes": {
                                "sha256": raw_hash,
                                "meaningful_name": "malware.exe",
                            },
                        }
                    ],
                }
            },
        }
    }

    mock_client = AsyncMock(spec=httpx.AsyncClient)
    mock_client.get = AsyncMock(return_value=httpx.Response(200, json=base_entity_resp, request=httpx.Request("GET", "https://vt.test")))
    ctx.http_client = mock_client

    result = await prov.execute(ctx)
    assert len(result.discovered_iocs) == 1
    ioc = result.discovered_iocs[0]

    # Full canonical lowercase hash
    assert ioc.canonical_value == raw_hash.lower()
    assert len(ioc.canonical_value) == 64
    assert ioc.ioc_type == IOCType.SHA256

    ciocs, rels = deduplicate_discovered_iocs("8.8.8.8", IOCType.IPV4, [result])
    assert len(ciocs) == 1
    assert ciocs[0].canonical_value == raw_hash.lower()
    assert ciocs[0].ioc_type == IOCType.SHA256


@pytest.mark.asyncio
async def test_virustotal_fetches_all_applicable_relationships_independently_including_communicating_files():
    """
    Verifies that VirusTotal independently queries applicable relationships (such as
    communicating_files and referrer_files) even when not present in the base entity response,
    and materializes hashes from both with distinct relationship types.
    """
    prov = VirusTotalProvider()
    ctx = ProviderRequestContext(
        ioc_value="1.2.3.4",
        ioc_type=IOCType.IPV4,
        api_key="mock_vt_key",
    )

    base_resp = {
        "data": {
            "id": "1.2.3.4",
            "type": "ip_address",
            "attributes": {"reputation": -30},
        }
    }

    comm_files = [_generate_mock_file(101, rel_type="communicating_files"), _generate_mock_file(102, rel_type="communicating_files")]
    ref_files = [_generate_mock_file(201, rel_type="referrer_files"), _generate_mock_file(202, rel_type="referrer_files"), _generate_mock_file(203, rel_type="referrer_files")]

    comm_resp = {"data": comm_files, "meta": {"count": 2}, "links": {}}
    ref_resp = {"data": ref_files, "meta": {"count": 3}, "links": {}}

    requested_endpoints = []

    async def mock_get(url, *args, **kwargs):
        url_str = str(url)
        requested_endpoints.append(url_str)
        req = httpx.Request("GET", url)
        if "/communicating_files" in url_str:
            return httpx.Response(200, json=comm_resp, request=req)
        elif "/referrer_files" in url_str:
            return httpx.Response(200, json=ref_resp, request=req)
        elif any(ep in url_str for ep in ["/historical_whois", "/resolutions", "/comments"]):
            return httpx.Response(200, json={"data": []}, request=req)
        return httpx.Response(200, json=base_resp, request=req)

    mock_client = AsyncMock(spec=httpx.AsyncClient)
    mock_client.get = AsyncMock(side_effect=mock_get)
    ctx.http_client = mock_client

    result = await prov.execute(ctx)
    assert result.status == ProviderStatus.SUCCESS

    # Verify that communicating_files endpoint was queried explicitly
    assert any("/communicating_files" in ep for ep in requested_endpoints)
    assert any("/referrer_files" in ep for ep in requested_endpoints)

    # Verify discovered IOCs contains 2 communicating files and 3 referrer files
    assert len(result.discovered_iocs) == 5
    comm_iocs = [ioc for ioc in result.discovered_iocs if ioc.relationship_type == "communicating_file"]
    ref_iocs = [ioc for ioc in result.discovered_iocs if ioc.relationship_type == "referrer_file"]
    assert len(comm_iocs) == 2
    assert len(ref_iocs) == 3

    # Deduplicate and test Layer 3 and graph
    ciocs, rels = deduplicate_discovered_iocs("1.2.3.4", IOCType.IPV4, [result])
    assert len(ciocs) == 5
    l3 = build_layer3_buckets(ciocs)
    assert len(l3.hashes) == 5

    graph = build_graph("1.2.3.4", IOCType.IPV4, 75.0, ciocs, rels)
    assert len(graph.nodes) == 6  # 1 root + 5 hashes
    assert len(graph.edges) == 5


@pytest.mark.asyncio
async def test_virustotal_historical_whois_layer2_and_layer3_pivotable_only():
    """
    Tests that VirusTotal historical_whois records are populated in Layer 2 with human-readable
    UTC timestamps, and that ONLY valid pivotable infrastructure IOCs (name servers) are added to
    Layer 3, while WHOIS metadata (registrar names, organization names, dates) are strictly excluded.
    """
    prov = VirusTotalProvider()
    ctx = ProviderRequestContext(
        ioc_value="evil-domain.com",
        ioc_type=IOCType.DOMAIN,
        api_key="mock_vt_key",
    )

    base_resp = {
        "data": {
            "id": "evil-domain.com",
            "type": "domain",
            "attributes": {"reputation": -100},
        }
    }

    whois_records = [
        {
            "id": "whois_rec_1",
            "type": "whois",
            "attributes": {
                "first_seen_date": 1609459200,  # 2021-01-01T00:00:00Z
                "last_updated_date": 1640995200,  # 2022-01-01T00:00:00Z
                "registrar": "Shady Registrar LLC",
                "registrar_url": "https://shadyreg.com",
                "whois_server": "whois.shadyreg.com",
                "creation_date": 1577836800,  # 2020-01-01T00:00:00Z
                "updated_date": 1640995200,
                "expiry_date": 1704067200,  # 2024-01-01T00:00:00Z
                "registrant": {
                    "name": "John Doe",
                    "organization": "Malicious Corp Inc",
                    "country": "RU",
                    "email": "badguy@evil.com",
                },
                "name_servers": ["ns1.evil-dns-provider.net", "ns2.evil-dns-provider.net"],
                "status": ["clientTransferProhibited", "active"],
                "origin_as": "AS12345",
            },
        }
    ]

    async def mock_get(url, *args, **kwargs):
        url_str = str(url)
        req = httpx.Request("GET", url)
        if "/historical_whois" in url_str:
            return httpx.Response(200, json={"data": whois_records, "meta": {"count": 1}}, request=req)
        elif "/relationships/" in url_str or "?" in url_str:
            return httpx.Response(200, json={"data": []}, request=req)
        return httpx.Response(200, json=base_resp, request=req)

    mock_client = AsyncMock(spec=httpx.AsyncClient)
    mock_client.get = AsyncMock(side_effect=mock_get)
    ctx.http_client = mock_client

    result = await prov.execute(ctx)
    assert result.status == ProviderStatus.SUCCESS

    # 1. Layer 2 Infrastructure Verification
    assert result.infrastructure is not None
    assert len(result.infrastructure.historical_whois) == 1
    hw = result.infrastructure.historical_whois[0]
    assert hw.registrar == "Shady Registrar LLC"
    assert hw.registrant_organization == "Malicious Corp Inc"
    assert hw.registrant_country == "RU"
    assert "2021-01-01" in hw.first_seen
    assert "2022-01-01" in hw.last_updated
    assert hw.nameservers == ["ns1.evil-dns-provider.net", "ns2.evil-dns-provider.net"]
    assert hw.origin_as == "AS12345"

    # Aggregated Layer 2 test
    l2 = build_layer2_infrastructure("evil-domain.com", IOCType.DOMAIN, [result])
    assert len(l2.historical_whois) == 1
    assert l2.historical_whois[0].registrar == "Shady Registrar LLC"

    # 2. Layer 3 Discovered IOCs Verification: ONLY valid pivotable domains/IPs
    discovered_values = [ioc.canonical_value for ioc in result.discovered_iocs]
    assert "ns1.evil-dns-provider.net" in discovered_values
    assert "ns2.evil-dns-provider.net" in discovered_values

    # Strictly check that WHOIS metadata is NOT in discovered IOCs
    assert "Shady Registrar LLC" not in discovered_values
    assert "Malicious Corp Inc" not in discovered_values
    assert "John Doe" not in discovered_values
    assert "RU" not in discovered_values
    assert "AS12345" not in discovered_values

    for ioc in result.discovered_iocs:
        if ioc.relationship_type == "whois_name_server":
            assert ioc.ioc_type == IOCType.DOMAIN


@pytest.mark.asyncio
async def test_virustotal_relationship_failure_isolation():
    """
    Tests that HTTP 403 (e.g. Enterprise-only relationship) or HTTP 400 on one relationship
    does NOT crash the provider or prevent other valid relationships from materializing.
    """
    prov = VirusTotalProvider()
    ctx = ProviderRequestContext(
        ioc_value="1.2.3.4",
        ioc_type=IOCType.IPV4,
        api_key="mock_vt_key",
    )

    base_resp = {
        "data": {
            "id": "1.2.3.4",
            "type": "ip_address",
            "attributes": {"reputation": -5},
        }
    }

    comm_files = [_generate_mock_file(10)]
    ref_files = [_generate_mock_file(20)]

    async def mock_get(url, *args, **kwargs):
        url_str = str(url)
        req = httpx.Request("GET", url)
        if "/communicating_files" in url_str:
            return httpx.Response(200, json={"data": comm_files}, request=req)
        elif "/referrer_files" in url_str:
            return httpx.Response(200, json={"data": ref_files}, request=req)
        elif "/downloaded_files" in url_str:
            # 403 Forbidden on Enterprise-only relationship
            return httpx.Response(403, json={"error": {"code": "ForbiddenError", "message": "Enterprise only"}}, request=req)
        elif "/historical_whois" in url_str:
            # 400 Bad Request
            return httpx.Response(400, json={"error": {"code": "BadRequestError"}}, request=req)
        elif "/relationships/" in url_str or "?" in url_str:
            return httpx.Response(404, json={"error": {"code": "NotFoundError"}}, request=req)
        return httpx.Response(200, json=base_resp, request=req)

    mock_client = AsyncMock(spec=httpx.AsyncClient)
    mock_client.get = AsyncMock(side_effect=mock_get)
    ctx.http_client = mock_client

    result = await prov.execute(ctx)
    # Failure isolation: overall provider status must be SUCCESS
    assert result.status == ProviderStatus.SUCCESS
    # Both communicating_files and referrer_files must have been collected
    assert len(result.discovered_iocs) == 2
    rel_types = {ioc.relationship_type for ioc in result.discovered_iocs}
    assert rel_types == {"communicating_file", "referrer_file"}


@pytest.mark.asyncio
async def test_virustotal_embedded_sample_triggers_dedicated_fetch_and_multi_relationship_materialization():
    """
    Tests that when an entity response has an embedded sample (e.g. 1 communicating file, meta count: 11)
    without links.next, ThreatLens detects that it is incomplete and queries the dedicated endpoint
    to retrieve ALL 11 communicating files alongside 147 referrer files.
    Also verifies cross-relationship deduplication (partial hash overlap) merges relationships
    into the canonical IOCs, Layer 3, and the Threat Graph.
    """
    prov = VirusTotalProvider()
    ctx = ProviderRequestContext(
        ioc_value="1.2.3.4",
        ioc_type=IOCType.IPV4,
        api_key="mock_vt_key",
    )

    # 11 communicating files: index 1 to 11
    comm_files = [_generate_mock_file(i, "communicating_files") for i in range(1, 12)]

    # 147 referrer files: index 9 to 155 (indices 9, 10, 11 overlap with communicating files!)
    # Total unique hashes across both: 155 (1..8 only comm, 9..11 both, 12..155 only ref)
    ref_page1 = [_generate_mock_file(i, "referrer_files") for i in range(9, 49)]    # 40 items
    ref_page2 = [_generate_mock_file(i, "referrer_files") for i in range(49, 89)]   # 40 items
    ref_page3 = [_generate_mock_file(i, "referrer_files") for i in range(89, 129)]  # 40 items
    ref_page4 = [_generate_mock_file(i, "referrer_files") for i in range(129, 156)] # 27 items

    # Base entity response embeds only 1 sample communicating file with meta count = 11, NO links.next
    base_entity_resp = {
        "data": {
            "id": "1.2.3.4",
            "type": "ip_address",
            "attributes": {
                "reputation": -60,
                "last_analysis_stats": {"malicious": 20, "harmless": 10},
            },
            "relationships": {
                "communicating_files": {
                    "data": [comm_files[0]],  # Only 1 sample item embedded!
                    "meta": {"count": 11},
                    "links": {
                        "self": "https://www.virustotal.com/api/v3/ip_addresses/1.2.3.4/relationships/communicating_files",
                    },
                }
            },
        }
    }

    # Dedicated endpoint responses
    comm_endpoint_resp = {
        "data": comm_files,
        "meta": {"count": 11},
        "links": {
            "self": "https://www.virustotal.com/api/v3/ip_addresses/1.2.3.4/communicating_files?limit=40",
        },
    }

    ref_endpoint_resp_p1 = {
        "data": ref_page1,
        "meta": {"count": 147, "cursor": "ref_cur_p2"},
        "links": {
            "self": "https://www.virustotal.com/api/v3/ip_addresses/1.2.3.4/referrer_files?limit=40",
            "next": "https://www.virustotal.com/api/v3/ip_addresses/1.2.3.4/referrer_files?cursor=ref_cur_p2&limit=40",
        },
    }
    ref_endpoint_resp_p2 = {
        "data": ref_page2,
        "meta": {"count": 147, "cursor": "ref_cur_p3"},
        "links": {
            "self": "https://www.virustotal.com/api/v3/ip_addresses/1.2.3.4/referrer_files?cursor=ref_cur_p2&limit=40",
            "next": "https://www.virustotal.com/api/v3/ip_addresses/1.2.3.4/referrer_files?cursor=ref_cur_p3&limit=40",
        },
    }
    ref_endpoint_resp_p3 = {
        "data": ref_page3,
        "meta": {"count": 147, "cursor": "ref_cur_p4"},
        "links": {
            "self": "https://www.virustotal.com/api/v3/ip_addresses/1.2.3.4/referrer_files?cursor=ref_cur_p3&limit=40",
            "next": "https://www.virustotal.com/api/v3/ip_addresses/1.2.3.4/referrer_files?cursor=ref_cur_p4&limit=40",
        },
    }
    ref_endpoint_resp_p4 = {
        "data": ref_page4,
        "meta": {"count": 147},
        "links": {
            "self": "https://www.virustotal.com/api/v3/ip_addresses/1.2.3.4/referrer_files?cursor=ref_cur_p4&limit=40",
        },
    }

    async def mock_get(url, *args, **kwargs):
        url_str = str(url)
        req = httpx.Request("GET", url)
        if "/communicating_files" in url_str:
            return httpx.Response(200, json=comm_endpoint_resp, request=req)
        elif "ref_cur_p2" in url_str:
            return httpx.Response(200, json=ref_endpoint_resp_p2, request=req)
        elif "ref_cur_p3" in url_str:
            return httpx.Response(200, json=ref_endpoint_resp_p3, request=req)
        elif "ref_cur_p4" in url_str:
            return httpx.Response(200, json=ref_endpoint_resp_p4, request=req)
        elif "/referrer_files" in url_str:
            return httpx.Response(200, json=ref_endpoint_resp_p1, request=req)
        elif "/ip_addresses/1.2.3.4" in url_str:
            return httpx.Response(200, json=base_entity_resp, request=req)
        return httpx.Response(404, json={"error": {"code": "NotFoundError"}}, request=req)

    mock_client = AsyncMock(spec=httpx.AsyncClient)
    mock_client.get = AsyncMock(side_effect=mock_get)
    ctx.http_client = mock_client

    result = await prov.execute(ctx)
    assert result.status == ProviderStatus.SUCCESS

    # Discovered IOCs: 11 communicating + 147 referrer = 158 raw observations
    assert len(result.discovered_iocs) == 158

    comm_iocs = [d for d in result.discovered_iocs if d.relationship_type == "communicating_file"]
    ref_iocs = [d for d in result.discovered_iocs if d.relationship_type == "referrer_file"]
    assert len(comm_iocs) == 11
    assert len(ref_iocs) == 147

    # Infrastructure reported & materialized counts
    assert result.infrastructure.extra["vt_reported_counts"]["communicating_files"] == 11
    assert result.infrastructure.extra["vt_materialized_counts"]["communicating_files"] == 11
    assert result.infrastructure.extra["vt_reported_counts"]["referrer_files"] == 147
    assert result.infrastructure.extra["vt_materialized_counts"]["referrer_files"] == 147

    # Normalization & Deduplication:
    # 11 communicating files + 147 referrer files with 3 overlapping = exactly 155 unique canonical IOCs
    ciocs, rels = deduplicate_discovered_iocs("1.2.3.4", IOCType.IPV4, [result])
    assert len(ciocs) == 155
    assert len(rels) == 155

    # Check that the 3 overlapping hashes have both relationships merged
    overlapping_hashes = {_generate_mock_file(i)["id"] for i in (9, 10, 11)}
    for cioc in ciocs:
        if cioc.canonical_value in overlapping_hashes:
            assert sorted(cioc.relationships) == ["communicating_file", "referrer_file"]
            assert cioc.metadata.get("relationships") == ["communicating_file", "referrer_file"]

    # Layer 3 Bucketing: exactly 155 hashes
    l3 = build_layer3_buckets(ciocs)
    assert len(l3.hashes) == 155

    # Threat Graph: 1 root + 155 discovered IOCs = 156 nodes, 155 edges
    graph = build_graph("1.2.3.4", IOCType.IPV4, 90.0, ciocs, rels)
    assert len(graph.nodes) == 156
    assert len(graph.edges) == 155

    # Check that overlapping edges have both relationships in their label
    overlapping_edges = [e for e in graph.edges if e.target in overlapping_hashes]
    assert len(overlapping_edges) == 3
    for edge in overlapping_edges:
        assert "communicating_file" in edge.label
        assert "referrer_file" in edge.label

