from typing import List, Dict, Set
from app.schemas.investigation import (
    GraphNode,
    GraphEdge,
    GraphResponse,
    CanonicalIOCResponse,
    RelationshipResponse,
)
from app.schemas.ioc import IOCType


def build_graph(
    root_ioc: str,
    root_type: IOCType,
    root_confidence: float,
    discovered_iocs: List[CanonicalIOCResponse],
    relationships: List[RelationshipResponse],
) -> GraphResponse:
    nodes_dict: Dict[str, GraphNode] = {}
    edges_list: List[GraphEdge] = []
    seen_edge_keys: Set[str] = set()

    # 1. Add root node
    nodes_dict[root_ioc] = GraphNode(
        id=root_ioc,
        label=root_ioc,
        type=root_type.value,
        confidence=root_confidence,
        depth=0,
        is_root=True,
        metadata={"root": True, "ioc_type": root_type.value},
    )

    # 2. Add discovered IOC nodes
    for ioc in discovered_iocs:
        if ioc.canonical_value not in nodes_dict:
            nodes_dict[ioc.canonical_value] = GraphNode(
                id=ioc.canonical_value,
                label=ioc.canonical_value,
                type=ioc.ioc_type.value,
                confidence=ioc.confidence,
                depth=ioc.depth,
                is_root=False,
                metadata={
                    "providers": ioc.providers,
                    "relationships": ioc.relationships,
                    "first_seen": ioc.first_seen,
                    "last_seen": ioc.last_seen,
                    **(ioc.metadata or {}),
                },
            )

    # 3. Add edges
    for rel in relationships:
        src = rel.source_value
        tgt = rel.target_value
        edge_key = f"{src}->{tgt}"

        # Ensure both source and target exist in nodes dict
        if src not in nodes_dict:
            nodes_dict[src] = GraphNode(
                id=src,
                label=src,
                type=rel.source_type,
                confidence=rel.confidence,
                depth=rel.depth - 1 if rel.depth > 0 else 0,
                is_root=False,
            )
        if tgt not in nodes_dict:
            nodes_dict[tgt] = GraphNode(
                id=tgt,
                label=tgt,
                type=rel.target_type,
                confidence=rel.confidence,
                depth=rel.depth,
                is_root=False,
            )

        if edge_key not in seen_edge_keys:
            seen_edge_keys.add(edge_key)
            edges_list.append(
                GraphEdge(
                    id=f"e_{len(edges_list)+1}_{src}_{tgt}",
                    source=src,
                    target=tgt,
                    label=rel.relationship_type,
                    confidence=rel.confidence,
                    providers=rel.providers,
                    evidence_count=rel.evidence_count,
                )
            )

    return GraphResponse(
        root_ioc=root_ioc,
        nodes=list(nodes_dict.values()),
        edges=edges_list,
    )
