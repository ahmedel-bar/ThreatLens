from typing import List, Dict, Tuple, Any
from app.schemas.ioc import IOCType, ProviderStatus
from app.schemas.provider import DiscoveredIOC, ProviderResult
from app.schemas.investigation import CanonicalIOCResponse, RelationshipResponse
from app.services.ioc import normalize_ioc
from app.services.confidence import calculate_ioc_confidence


class DeduplicatedIOC:
    def __init__(self, canonical_value: str, ioc_type: IOCType, is_root: bool = False, depth: int = 1):
        self.canonical_value = canonical_value
        self.ioc_type = ioc_type
        self.is_root = is_root
        self.depth = depth
        self.providers: set[str] = set()
        self.relationships: set[str] = set()
        self.raw_confidences: List[float] = []
        self.evidence_descriptions: List[str] = []
        self.first_seen: str | None = None
        self.last_seen: str | None = None
        self.metadata: Dict[str, Any] = {}

    def add_observation(
        self,
        provider_name: str,
        relationship_type: str,
        confidence: float,
        evidence_desc: str | None = None,
        first_seen: str | None = None,
        last_seen: str | None = None,
        metadata: Dict[str, Any] | None = None,
    ):
        self.providers.add(provider_name)
        if relationship_type:
            for part in str(relationship_type).split(","):
                part = part.strip()
                if part:
                    self.relationships.add(part)
        self.raw_confidences.append(confidence)
        if evidence_desc:
            self.evidence_descriptions.append(evidence_desc)
        if first_seen and not self.first_seen:
            self.first_seen = first_seen
        if last_seen:
            self.last_seen = last_seen
        if metadata:
            for k, v in metadata.items():
                if k in ("relationship", "relationships", "provider", "providers"):
                    continue
                if v is not None or k not in self.metadata:
                    self.metadata[k] = v

    def to_schema(self, ioc_id: str) -> CanonicalIOCResponse:
        final_conf = calculate_ioc_confidence(
            providers=list(self.providers),
            raw_confidences=self.raw_confidences,
            relationship_types=list(self.relationships),
        )
        return CanonicalIOCResponse(
            id=ioc_id,
            canonical_value=self.canonical_value,
            ioc_type=self.ioc_type,
            is_root=self.is_root,
            depth=self.depth,
            confidence=final_conf,
            first_seen=self.first_seen,
            last_seen=self.last_seen,
            metadata={
                **self.metadata,
                "evidence_notes": self.evidence_descriptions,
                "relationships": sorted(list(self.relationships)),
                "providers": sorted(list(self.providers)),
            },
            relationships=sorted(list(self.relationships)),
            providers=sorted(list(self.providers)),
        )


class DeduplicatedRelationship:
    def __init__(
        self,
        source_value: str,
        source_type: str,
        target_value: str,
        target_type: str,
        relationship_type: str,
        depth: int = 1,
    ):
        self.source_value = source_value
        self.source_type = source_type
        self.target_value = target_value
        self.target_type = target_type
        self.relationship_types: set[str] = set()
        if relationship_type:
            for part in str(relationship_type).split(","):
                part = part.strip()
                if part:
                    self.relationship_types.add(part)
        self.depth = depth
        self.providers: set[str] = set()
        self.raw_confidences: List[float] = []
        self.evidences: List[str] = []

    def add_provider_evidence(self, provider_name: str, relationship_type: str, confidence: float, evidence_desc: str | None = None):
        self.providers.add(provider_name)
        if relationship_type:
            for part in str(relationship_type).split(","):
                part = part.strip()
                if part:
                    self.relationship_types.add(part)
        self.raw_confidences.append(confidence)
        if evidence_desc:
            self.evidences.append(f"[{provider_name}] ({relationship_type}) {evidence_desc}")

    def to_schema(self, rel_id: str) -> RelationshipResponse:
        final_conf = calculate_ioc_confidence(
            providers=list(self.providers),
            raw_confidences=self.raw_confidences,
            relationship_types=list(self.relationship_types),
        )
        combined_rel = ", ".join(sorted(list(self.relationship_types)))
        return RelationshipResponse(
            id=rel_id,
            source_value=self.source_value,
            source_type=self.source_type,
            target_value=self.target_value,
            target_type=self.target_type,
            relationship_type=combined_rel,
            confidence=final_conf,
            providers=sorted(list(self.providers)),
            evidence_count=len(self.providers),
            evidence_summary="; ".join(self.evidences[:3]) if self.evidences else None,
            depth=self.depth,
        )


def deduplicate_discovered_iocs(
    root_canonical: str,
    root_type: IOCType,
    provider_results: List[ProviderResult],
    current_depth: int = 1,
) -> Tuple[List[CanonicalIOCResponse], List[RelationshipResponse]]:
    """
    Global Normalization and Deduplication Engine:
    Maps multiple provider findings to singular canonical IOCs and relationships with aggregated provenance.
    """
    ioc_map: Dict[Tuple[str, str], DeduplicatedIOC] = {}
    rel_map: Dict[Tuple[str, str], DeduplicatedRelationship] = {}

    for res in provider_results:
        if res.status != ProviderStatus.SUCCESS or not res.discovered_iocs:
            continue
        p_name = res.provider_name
        for item in res.discovered_iocs:
            # 1. Normalize discovered IOC
            norm = normalize_ioc(item.raw_value, item.ioc_type)
            if not norm.is_valid or not norm.canonical_value:
                continue

            canon_val = norm.canonical_value
            canon_type = norm.ioc_type

            # Don't recreate root as discovered child pointing to itself
            if canon_val == root_canonical and canon_type == root_type:
                continue

            # 2. Add or merge into canonical IOC
            ioc_key = (canon_val, canon_type.value)
            if ioc_key not in ioc_map:
                ioc_map[ioc_key] = DeduplicatedIOC(
                    canonical_value=canon_val,
                    ioc_type=canon_type,
                    is_root=False,
                    depth=current_depth,
                )

            ioc_map[ioc_key].add_observation(
                provider_name=p_name,
                relationship_type=item.relationship_type,
                confidence=item.confidence,
                evidence_desc=item.evidence_desc,
                first_seen=item.first_seen,
                last_seen=item.last_seen,
                metadata=item.metadata,
            )

            # 3. Add or merge into canonical Relationship (single edge between source and target)
            rel_key = (root_canonical, canon_val)
            if rel_key not in rel_map:
                rel_map[rel_key] = DeduplicatedRelationship(
                    source_value=root_canonical,
                    source_type=root_type.value,
                    target_value=canon_val,
                    target_type=canon_type.value,
                    relationship_type=item.relationship_type,
                    depth=current_depth,
                )

            rel_map[rel_key].add_provider_evidence(
                provider_name=p_name,
                relationship_type=item.relationship_type,
                confidence=item.confidence,
                evidence_desc=item.evidence_desc,
            )

    import uuid

    canonical_iocs = [
        obj.to_schema(ioc_id=str(uuid.uuid4()))
        for obj in ioc_map.values()
    ]
    relationships = [
        obj.to_schema(rel_id=str(uuid.uuid4()))
        for obj in rel_map.values()
    ]

    return canonical_iocs, relationships
