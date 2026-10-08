import asyncio
from typing import List, Dict, Set, Tuple, Optional
from collections import deque
from app.config import settings
from app.schemas.ioc import IOCType
from app.schemas.provider import ProviderResult
from app.schemas.investigation import CanonicalIOCResponse, RelationshipResponse
from app.providers.router import ProviderRouter
from app.services.ioc import normalize_ioc
from app.services.deduplication import deduplicate_discovered_iocs
from app.services.enrichment import build_layer2_infrastructure, attach_infrastructure_iocs


class RecursivePivotEngine:
    def __init__(
        self,
        router: Optional[ProviderRouter] = None,
        max_depth: Optional[int] = None,
        max_nodes: Optional[int] = None,
        max_requests: Optional[int] = None,
    ):
        self.router = router or ProviderRouter()
        self.max_depth = max_depth if max_depth is not None else settings.MAX_PIVOT_DEPTH
        self.max_nodes = max_nodes if max_nodes is not None else settings.MAX_PIVOT_NODES
        self.max_requests = max_requests if max_requests is not None else settings.MAX_PROVIDER_REQUESTS

        # Safety tracking
        self.visited_nodes: Set[Tuple[str, str]] = set()
        self.requests_count = 0
        self.nodes_count = 0

    async def pivot_single_step(
        self,
        target_ioc: str,
        target_type: IOCType,
        current_depth: int,
        existing_iocs: List[CanonicalIOCResponse],
        existing_relationships: List[RelationshipResponse],
    ) -> Tuple[List[CanonicalIOCResponse], List[RelationshipResponse], List[ProviderResult]]:
        """
        Executes a controlled single pivot step from a target node, respecting budget and cycles.
        """
        norm = normalize_ioc(target_ioc, target_type)
        if not norm.is_valid:
            return existing_iocs, existing_relationships, []

        canon_val = norm.canonical_value
        canon_type = norm.ioc_type

        # Cycle & visited check
        node_key = (canon_val, canon_type.value)
        if node_key in self.visited_nodes:
            # Already pivoted from this node
            return existing_iocs, existing_relationships, []

        self.visited_nodes.add(node_key)

        # Budget checks
        if current_depth > self.max_depth:
            return existing_iocs, existing_relationships, []

        if self.requests_count >= self.max_requests or len(existing_iocs) >= self.max_nodes:
            return existing_iocs, existing_relationships, []

        # Route to capable providers
        provider_results = await self.router.route_ioc(canon_val, canon_type)
        self.requests_count += len(provider_results)

        # Deduplicate newly discovered IOCs and relationships
        new_iocs, new_rels = deduplicate_discovered_iocs(
            root_canonical=canon_val,
            root_type=canon_type,
            provider_results=provider_results,
            current_depth=current_depth,
        )

        layer2 = build_layer2_infrastructure(canon_val, canon_type, provider_results)
        new_iocs, new_rels = attach_infrastructure_iocs(
            root_canonical=canon_val,
            root_type=canon_type,
            layer2=layer2,
            existing_iocs=new_iocs,
            existing_relationships=new_rels,
            current_depth=current_depth,
        )

        # Merge with existing collection
        existing_keys = {(i.canonical_value, i.ioc_type.value) for i in existing_iocs}
        merged_iocs = list(existing_iocs)
        for ioc in new_iocs:
            if (ioc.canonical_value, ioc.ioc_type.value) not in existing_keys:
                if len(merged_iocs) < self.max_nodes:
                    existing_keys.add((ioc.canonical_value, ioc.ioc_type.value))
                    merged_iocs.append(ioc)

        existing_rel_keys = {(r.source_value, r.target_value, r.relationship_type) for r in existing_relationships}
        merged_rels = list(existing_relationships)
        for rel in new_rels:
            rel_key = (rel.source_value, rel.target_value, rel.relationship_type)
            if rel_key not in existing_rel_keys:
                existing_rel_keys.add(rel_key)
                merged_rels.append(rel)

        return merged_iocs, merged_rels, provider_results

    async def execute_recursive_exploration(
        self,
        root_ioc: str,
        root_type: IOCType,
        depth_limit: int = 1,
    ) -> Tuple[List[CanonicalIOCResponse], List[RelationshipResponse], List[ProviderResult]]:
        """
        Executes bounded recursive traversal up to depth_limit or safety limits.
        """
        queue: deque[Tuple[str, IOCType, int]] = deque([(root_ioc, root_type, 1)])
        all_iocs: List[CanonicalIOCResponse] = []
        all_rels: List[RelationshipResponse] = []
        all_results: List[ProviderResult] = []

        while queue and len(all_iocs) < self.max_nodes and self.requests_count < self.max_requests:
            curr_val, curr_type, curr_depth = queue.popleft()

            if curr_depth > min(self.max_depth, depth_limit):
                continue

            prev_ioc_count = len(all_iocs)
            all_iocs, all_rels, step_results = await self.pivot_single_step(
                target_ioc=curr_val,
                target_type=curr_type,
                current_depth=curr_depth,
                existing_iocs=all_iocs,
                existing_relationships=all_rels,
            )
            all_results.extend(step_results)

            # Queue newly discovered nodes for next depth level if allowed
            if curr_depth + 1 <= min(self.max_depth, depth_limit):
                newly_added = all_iocs[prev_ioc_count:]
                for added in newly_added:
                    k = (added.canonical_value, added.ioc_type.value)
                    if k not in self.visited_nodes:
                        queue.append((added.canonical_value, added.ioc_type, curr_depth + 1))

        return all_iocs, all_rels, all_results
