import uuid
from typing import List, Optional
from datetime import datetime, timezone
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc
from sqlalchemy.orm import selectinload

from app.models.models import (
    Investigation,
    IOCRecord,
    ProviderResultRecord,
    RelationshipRecord,
    InvestigationEventRecord,
    PivotRunRecord,
)
from app.schemas.ioc import IOCType
from app.schemas.provider import ProviderResult, InfrastructureData, VirusTotalDetectionStats
from app.schemas.investigation import (
    InvestigationDetailResponse,
    InvestigationSummaryResponse,
    InvestigationEventResponse,
    Layer1ReputationResponse,
    Layer2InfrastructureResponse,
    Layer3DiscoveredIOCsResponse,
    CanonicalIOCResponse,
    RelationshipResponse,
    GraphResponse,
)
from app.services.ioc import normalize_ioc
from app.providers.router import ProviderRouter
from app.services.deduplication import deduplicate_discovered_iocs
from app.services.enrichment import (
    build_layer1_reputation,
    build_layer2_infrastructure,
    build_layer3_buckets,
    attach_infrastructure_iocs,
)
from app.services.graph import build_graph
from app.services.pivot import RecursivePivotEngine


class InvestigationService:
    def __init__(self, db: AsyncSession):
        self.db = db
        self.router = ProviderRouter()

    async def start_investigation(
        self,
        raw_ioc: str,
        ioc_type: Optional[IOCType] = None,
        max_depth: int = 1,
        provider_names: Optional[List[str]] = None,
    ) -> InvestigationDetailResponse:
        # 1. Normalize
        norm = normalize_ioc(raw_ioc, ioc_type)
        if not norm.is_valid:
            raise ValueError(f"Invalid IOC: {norm.error}")

        root_canonical = norm.canonical_value
        root_type = norm.ioc_type

        # 2. Create DB Investigation Record
        inv_id = str(uuid.uuid4())
        inv = Investigation(
            id=inv_id,
            root_ioc_value=root_canonical,
            root_ioc_type=root_type.value,
            status="running",
            pivot_depth=0,
        )
        self.db.add(inv)
        await self.db.flush()

        # Log event: started
        self._record_event(inv_id, "investigation_started", f"Investigation started for {root_type.value.upper()}: {root_canonical}")

        # 3. Save root IOC record
        root_record = IOCRecord(
            id=str(uuid.uuid4()),
            investigation_id=inv_id,
            canonical_value=root_canonical,
            ioc_type=root_type.value,
            is_root=True,
            depth=0,
            confidence=100.0,
        )
        self.db.add(root_record)

        # 4. Route IOC to providers
        self._record_event(inv_id, "provider_routing", "Routing IOC to supported threat intelligence and infrastructure providers.")
        provider_results = await self.router.route_ioc(
            ioc_value=root_canonical,
            ioc_type=root_type,
            provider_names=provider_names,
        )

        # 5. Save Provider Results to DB
        for pres in provider_results:
            p_rec = ProviderResultRecord(
                id=str(uuid.uuid4()),
                investigation_id=inv_id,
                provider_name=pres.provider_name,
                ioc_value=pres.ioc_value,
                ioc_type=pres.ioc_type.value,
                status=pres.status.value,
                execution_time_ms=pres.execution_time_ms,
                reputation_score=pres.reputation_score,
                classification=pres.classification,
                malicious_count=pres.malicious_count,
                suspicious_count=pres.suspicious_count,
                harmless_count=pres.harmless_count,
                tags=pres.tags,
                threat_actors=pres.threat_actors,
                malware_families=pres.malware_families,
                infrastructure_data=pres.infrastructure.model_dump() if pres.infrastructure else None,
                raw_data=pres.raw_data,
                error_details=pres.error_details,
            )
            self.db.add(p_rec)

        # 6. Global Deduplication and Relationship creation
        self._record_event(inv_id, "deduplication", "Normalizing and deduplicating discovered IOCs and infrastructure relationships.")
        canonical_iocs, relationships = deduplicate_discovered_iocs(
            root_canonical=root_canonical,
            root_type=root_type,
            provider_results=provider_results,
            current_depth=1,
        )

        # 7. Build Layers & Aggregate Infrastructure
        layer1 = build_layer1_reputation(root_canonical, root_type, provider_results)
        layer2 = build_layer2_infrastructure(root_canonical, root_type, provider_results)

        # 8. Attach dynamically resolved infrastructure IOCs (PTR, DNS A/AAAA)
        canonical_iocs, relationships = attach_infrastructure_iocs(
            root_canonical=root_canonical,
            root_type=root_type,
            layer2=layer2,
            existing_iocs=canonical_iocs,
            existing_relationships=relationships,
            current_depth=1,
        )

        # Save discovered IOCs and Relationships to DB
        for cioc in canonical_iocs:
            ioc_db = IOCRecord(
                id=cioc.id,
                investigation_id=inv_id,
                canonical_value=cioc.canonical_value,
                ioc_type=cioc.ioc_type.value,
                is_root=False,
                depth=cioc.depth,
                confidence=cioc.confidence,
                first_seen=cioc.first_seen,
                last_seen=cioc.last_seen,
                metadata_json=cioc.metadata,
            )
            self.db.add(ioc_db)

        for rel in relationships:
            rel_db = RelationshipRecord(
                id=rel.id,
                investigation_id=inv_id,
                source_value=rel.source_value,
                source_type=rel.source_type,
                target_value=rel.target_value,
                target_type=rel.target_type,
                relationship_type=rel.relationship_type,
                confidence=rel.confidence,
                providers=rel.providers,
                evidence_count=rel.evidence_count,
                evidence_summary=rel.evidence_summary,
                depth=rel.depth,
            )
            self.db.add(rel_db)

        # Build Layer 3 Buckets & Interactive Threat Graph
        layer3 = build_layer3_buckets(canonical_iocs)
        graph = build_graph(
            root_ioc=root_canonical,
            root_type=root_type,
            root_confidence=layer1.risk_score,
            discovered_iocs=canonical_iocs,
            relationships=relationships,
        )

        # 8. Update Investigation status
        inv.status = "complete" if layer1.providers_failed == 0 else "partial"
        inv.risk_score = layer1.risk_score
        inv.updated_at = datetime.now(timezone.utc)
        self._record_event(inv_id, "investigation_completed", f"Investigation completed with risk score {layer1.risk_score}/100.")

        await self.db.commit()

        # Return full details
        return await self.get_investigation_details(inv_id)

    async def pivot(
        self,
        investigation_id: str,
        target_ioc: str,
        target_type: Optional[IOCType] = None,
    ) -> InvestigationDetailResponse:
        # Retrieve existing investigation
        stmt = select(Investigation).where(Investigation.id == investigation_id)
        res = await self.db.execute(stmt)
        inv = res.scalar_one_or_none()
        if not inv:
            raise ValueError(f"Investigation {investigation_id} not found.")

        norm = normalize_ioc(target_ioc, target_type)
        if not norm.is_valid:
            raise ValueError(f"Invalid pivot target: {norm.error}")

        target_canon = norm.canonical_value
        target_t = norm.ioc_type

        # Log pivot event
        self._record_event(investigation_id, "pivot_started", f"Recursive pivot requested from {target_t.value.upper()}: {target_canon}")

        # Fetch existing IOCs and relationships from DB
        iocs_stmt = select(IOCRecord).where(IOCRecord.investigation_id == investigation_id)
        existing_iocs_db = (await self.db.execute(iocs_stmt)).scalars().all()

        rels_stmt = select(RelationshipRecord).where(RelationshipRecord.investigation_id == investigation_id)
        existing_rels_db = (await self.db.execute(rels_stmt)).scalars().all()

        existing_iocs = [
            CanonicalIOCResponse(
                id=i.id,
                canonical_value=i.canonical_value,
                ioc_type=IOCType(i.ioc_type),
                is_root=i.is_root,
                depth=i.depth,
                confidence=i.confidence,
                first_seen=i.first_seen,
                last_seen=i.last_seen,
                metadata=i.metadata_json or {},
            )
            for i in existing_iocs_db
        ]

        existing_rels = [
            RelationshipResponse(
                id=r.id,
                source_value=r.source_value,
                source_type=r.source_type,
                target_value=r.target_value,
                target_type=r.target_type,
                relationship_type=r.relationship_type,
                confidence=r.confidence,
                providers=r.providers or [],
                evidence_count=r.evidence_count,
                evidence_summary=r.evidence_summary,
                depth=r.depth,
            )
            for r in existing_rels_db
        ]

        # Execute Pivot Step
        pivot_engine = RecursivePivotEngine(router=self.router)
        new_depth = inv.pivot_depth + 1

        merged_iocs, merged_rels, step_results = await pivot_engine.pivot_single_step(
            target_ioc=target_canon,
            target_type=target_t,
            current_depth=new_depth,
            existing_iocs=existing_iocs,
            existing_relationships=existing_rels,
        )

        # Save new IOCs
        existing_ids = {i.id for i in existing_iocs_db}
        for mioc in merged_iocs:
            if mioc.id not in existing_ids:
                new_ioc_rec = IOCRecord(
                    id=mioc.id,
                    investigation_id=investigation_id,
                    canonical_value=mioc.canonical_value,
                    ioc_type=mioc.ioc_type.value,
                    is_root=False,
                    depth=mioc.depth,
                    confidence=mioc.confidence,
                    first_seen=mioc.first_seen,
                    last_seen=mioc.last_seen,
                    metadata_json=mioc.metadata,
                )
                self.db.add(new_ioc_rec)

        # Save new relationships
        existing_rel_ids = {r.id for r in existing_rels_db}
        for mrel in merged_rels:
            if mrel.id not in existing_rel_ids:
                new_rel_rec = RelationshipRecord(
                    id=mrel.id,
                    investigation_id=investigation_id,
                    source_value=mrel.source_value,
                    source_type=mrel.source_type,
                    target_value=mrel.target_value,
                    target_type=mrel.target_type,
                    relationship_type=mrel.relationship_type,
                    confidence=mrel.confidence,
                    providers=mrel.providers,
                    evidence_count=mrel.evidence_count,
                    evidence_summary=mrel.evidence_summary,
                    depth=mrel.depth,
                )
                self.db.add(new_rel_rec)

        # Record Pivot Run
        pivot_run = PivotRunRecord(
            id=str(uuid.uuid4()),
            investigation_id=investigation_id,
            parent_ioc=inv.root_ioc_value,
            child_ioc=target_canon,
            depth=new_depth,
            status="completed",
        )
        self.db.add(pivot_run)

        inv.pivot_depth = new_depth
        inv.updated_at = datetime.now(timezone.utc)
        self._record_event(investigation_id, "pivot_completed", f"Pivot completed to depth {new_depth}.")

        await self.db.commit()
        return await self.get_investigation_details(investigation_id)

    async def get_investigation_details(self, investigation_id: str) -> InvestigationDetailResponse:
        stmt = (
            select(Investigation)
            .where(Investigation.id == investigation_id)
            .options(
                selectinload(Investigation.iocs),
                selectinload(Investigation.provider_results),
                selectinload(Investigation.relationships),
                selectinload(Investigation.events),
            )
        )
        res = await self.db.execute(stmt)
        inv = res.scalar_one_or_none()
        if not inv:
            raise ValueError(f"Investigation {investigation_id} not found.")

        # Reconstruct Provider Results
        p_results: List[ProviderResult] = []
        for pr in inv.provider_results:
            infra = InfrastructureData(**pr.infrastructure_data) if pr.infrastructure_data else None
            pr_vt_counts = None
            if pr.provider_name.lower() == "virustotal":
                raw = pr.raw_data if isinstance(pr.raw_data, dict) else {}
                data_obj = raw.get("data", {}) if isinstance(raw, dict) else {}
                attrs = data_obj.get("attributes", {}) if isinstance(data_obj, dict) else {}
                stats = attrs.get("last_analysis_stats") or raw.get("last_analysis_stats") or {}
                if stats and isinstance(stats, dict):
                    pr_vt_counts = VirusTotalDetectionStats.from_api_stats(stats).to_dict()
            p_results.append(
                ProviderResult(
                    provider_name=pr.provider_name,
                    ioc_value=pr.ioc_value,
                    ioc_type=IOCType(pr.ioc_type),
                    status=pr.status,
                    execution_time_ms=pr.execution_time_ms,
                    reputation_score=pr.reputation_score,
                    classification=pr.classification,
                    malicious_count=pr.malicious_count,
                    suspicious_count=pr.suspicious_count,
                    harmless_count=pr.harmless_count,
                    vt_engine_counts=pr_vt_counts,
                    tags=pr.tags or [],
                    threat_actors=pr.threat_actors or [],
                    malware_families=pr.malware_families or [],
                    infrastructure=infra,
                    raw_data=pr.raw_data,
                    error_details=pr.error_details,
                )
            )

        # Reconstruct Relationships
        relationships: List[RelationshipResponse] = [
            RelationshipResponse(
                id=r.id,
                source_value=r.source_value,
                source_type=r.source_type,
                target_value=r.target_value,
                target_type=r.target_type,
                relationship_type=r.relationship_type,
                confidence=r.confidence,
                providers=r.providers or [],
                evidence_count=r.evidence_count,
                evidence_summary=r.evidence_summary,
                depth=r.depth,
            )
            for r in inv.relationships
        ]

        rel_map_by_target: dict[str, set[str]] = {}
        prov_map_by_target: dict[str, set[str]] = {}
        for r in relationships:
            for part in (r.relationship_type or "").split(","):
                part = part.strip()
                if part:
                    rel_map_by_target.setdefault(r.target_value, set()).add(part)
            for p in r.providers:
                prov_map_by_target.setdefault(r.target_value, set()).add(p)

        # Reconstruct Canonical IOCs
        canonical_iocs: List[CanonicalIOCResponse] = []
        for i in inv.iocs:
            if i.is_root:
                continue
            meta = i.metadata_json or {}
            rels = set(rel_map_by_target.get(i.canonical_value, set()))
            if "relationship" in meta and meta["relationship"]:
                for part in str(meta["relationship"]).split(","):
                    part = part.strip()
                    if part:
                        rels.add(part)
            if "relationships" in meta and isinstance(meta["relationships"], list):
                for r_item in meta["relationships"]:
                    if isinstance(r_item, str):
                        for part in r_item.split(","):
                            part = part.strip()
                            if part:
                                rels.add(part)
            provs = set(prov_map_by_target.get(i.canonical_value, set()))
            if "provider" in meta and meta["provider"]:
                provs.add(meta["provider"])
            if "providers" in meta and isinstance(meta["providers"], list):
                for p_item in meta["providers"]:
                    if isinstance(p_item, str) and p_item.strip():
                        provs.add(p_item.strip())
            canonical_iocs.append(
                CanonicalIOCResponse(
                    id=i.id,
                    canonical_value=i.canonical_value,
                    ioc_type=IOCType(i.ioc_type),
                    is_root=i.is_root,
                    depth=i.depth,
                    confidence=i.confidence,
                    first_seen=i.first_seen,
                    last_seen=i.last_seen,
                    metadata=meta,
                    relationships=sorted(list(rels)),
                    providers=sorted(list(provs)),
                )
            )

        # Build Layers & Graph
        layer1 = build_layer1_reputation(inv.root_ioc_value, IOCType(inv.root_ioc_type), p_results)
        layer2 = build_layer2_infrastructure(inv.root_ioc_value, IOCType(inv.root_ioc_type), p_results)
        layer3 = build_layer3_buckets(canonical_iocs)
        graph = build_graph(
            root_ioc=inv.root_ioc_value,
            root_type=IOCType(inv.root_ioc_type),
            root_confidence=inv.risk_score,
            discovered_iocs=canonical_iocs,
            relationships=relationships,
        )

        events_resp = [
            InvestigationEventResponse(
                id=e.id,
                event_type=e.event_type,
                message=e.message,
                details=e.details,
                created_at=e.created_at,
            )
            for e in inv.events
        ]

        return InvestigationDetailResponse(
            id=inv.id,
            root_ioc_value=inv.root_ioc_value,
            root_ioc_type=inv.root_ioc_type,
            status=inv.status,
            error_message=inv.error_message,
            risk_score=inv.risk_score,
            pivot_depth=inv.pivot_depth,
            created_at=inv.created_at,
            updated_at=inv.updated_at,
            layer1=layer1,
            layer2=layer2,
            layer3=layer3,
            graph=graph,
            events=events_resp,
        )

    async def list_investigations(self, limit: int = 50, offset: int = 0) -> List[InvestigationSummaryResponse]:
        stmt = (
            select(Investigation)
            .options(
                selectinload(Investigation.iocs),
                selectinload(Investigation.provider_results),
                selectinload(Investigation.relationships),
            )
            .order_by(desc(Investigation.created_at))
            .limit(limit)
            .offset(offset)
        )
        res = await self.db.execute(stmt)
        invs = res.scalars().all()

        summaries = []
        for inv in invs:
            summaries.append(
                InvestigationSummaryResponse(
                    id=inv.id,
                    root_ioc_value=inv.root_ioc_value,
                    root_ioc_type=inv.root_ioc_type,
                    status=inv.status,
                    risk_score=inv.risk_score,
                    pivot_depth=inv.pivot_depth,
                    discovered_iocs_count=len([i for i in inv.iocs if not i.is_root]),
                    total_relationships=len(inv.relationships),
                    providers_queried=len(inv.provider_results),
                    created_at=inv.created_at,
                    updated_at=inv.updated_at,
                )
            )
        return summaries

    def _record_event(self, investigation_id: str, event_type: str, message: str, details: dict = None):
        ev = InvestigationEventRecord(
            id=str(uuid.uuid4()),
            investigation_id=investigation_id,
            event_type=event_type,
            message=message,
            details=details or {},
        )
        self.db.add(ev)
