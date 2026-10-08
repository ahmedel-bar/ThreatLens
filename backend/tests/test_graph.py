from app.schemas.ioc import IOCType
from app.schemas.investigation import CanonicalIOCResponse, RelationshipResponse
from app.services.graph import build_graph


def test_build_graph():
    root = "8.8.8.8"
    root_type = IOCType.IPV4

    discovered = [
        CanonicalIOCResponse(
            id="ioc-1",
            canonical_value="dns.google",
            ioc_type=IOCType.DOMAIN,
            is_root=False,
            depth=1,
            confidence=85.0,
            relationships=["resolves_to"],
            providers=["virustotal"],
        )
    ]

    rels = [
        RelationshipResponse(
            id="rel-1",
            source_value="8.8.8.8",
            source_type="ipv4",
            target_value="dns.google",
            target_type="domain",
            relationship_type="resolves_to",
            confidence=85.0,
            providers=["virustotal"],
            evidence_count=1,
            depth=1,
        )
    ]

    graph = build_graph(root, root_type, 10.0, discovered, rels)
    assert len(graph.nodes) == 2
    assert len(graph.edges) == 1

    root_node = next(n for n in graph.nodes if n.id == "8.8.8.8")
    assert root_node.is_root is True
    assert root_node.type == "ipv4"

    edge = graph.edges[0]
    assert edge.source == "8.8.8.8"
    assert edge.target == "dns.google"
    assert edge.label == "resolves_to"
