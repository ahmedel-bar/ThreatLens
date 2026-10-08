from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from typing import List, Optional
from app.db.session import get_db
from app.schemas.investigation import (
    StartInvestigationRequest,
    PivotRequest,
    InvestigationDetailResponse,
    InvestigationSummaryResponse,
    Layer1ReputationResponse,
    Layer3DiscoveredIOCsResponse,
    RelationshipResponse,
    GraphResponse,
)
from app.schemas.ioc import IOCDetectionResult
from app.services.ioc import process_ioc_input
from app.services.investigation import InvestigationService

router = APIRouter(prefix="/investigations", tags=["investigations"])


@router.post("", response_model=InvestigationDetailResponse, status_code=201)
async def create_investigation(
    req: StartInvestigationRequest,
    db: AsyncSession = Depends(get_db),
):
    """
    Starts an investigation from a single IOC:
    Detection -> Normalization -> Provider Capability Evaluation -> Routing -> Layer 1/2/3 -> Graph.
    """
    svc = InvestigationService(db)
    try:
        return await svc.start_investigation(
            raw_ioc=req.ioc,
            ioc_type=req.ioc_type,
            max_depth=req.max_depth or 1,
            provider_names=req.providers,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Investigation failed: {str(e)}")


@router.get("", response_model=List[InvestigationSummaryResponse])
async def list_investigations(
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db),
):
    """Lists past investigations for investigation history."""
    svc = InvestigationService(db)
    return await svc.list_investigations(limit=limit, offset=offset)


@router.get("/{investigation_id}", response_model=InvestigationDetailResponse)
async def get_investigation(
    investigation_id: str,
    db: AsyncSession = Depends(get_db),
):
    """Returns the complete investigation details including all 3 layers and graph."""
    svc = InvestigationService(db)
    try:
        return await svc.get_investigation_details(investigation_id)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@router.get("/{investigation_id}/providers", response_model=Layer1ReputationResponse)
async def get_investigation_providers(
    investigation_id: str,
    db: AsyncSession = Depends(get_db),
):
    """Returns Layer 1 provider results and statuses."""
    svc = InvestigationService(db)
    try:
        details = await svc.get_investigation_details(investigation_id)
        return details.layer1
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@router.get("/{investigation_id}/iocs", response_model=Layer3DiscoveredIOCsResponse)
async def get_investigation_iocs(
    investigation_id: str,
    db: AsyncSession = Depends(get_db),
):
    """Returns Layer 3 discovered IOCs in the 3 required buckets (Hashes, IPs, URLs & Domains)."""
    svc = InvestigationService(db)
    try:
        details = await svc.get_investigation_details(investigation_id)
        return details.layer3
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@router.get("/{investigation_id}/relationships", response_model=List[RelationshipResponse])
async def get_investigation_relationships(
    investigation_id: str,
    db: AsyncSession = Depends(get_db),
):
    """Returns all deduplicated relationships with provenance."""
    svc = InvestigationService(db)
    try:
        details = await svc.get_investigation_details(investigation_id)
        return [
            RelationshipResponse(
                id=e.id,
                source_value=e.source,
                source_type=next((n.type for n in details.graph.nodes if n.id == e.source), "unknown"),
                target_value=e.target,
                target_type=next((n.type for n in details.graph.nodes if n.id == e.target), "unknown"),
                relationship_type=e.label,
                confidence=e.confidence,
                providers=e.providers,
                evidence_count=e.evidence_count,
                depth=1,
            )
            for e in details.graph.edges
        ]
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@router.get("/{investigation_id}/graph", response_model=GraphResponse)
async def get_investigation_graph(
    investigation_id: str,
    db: AsyncSession = Depends(get_db),
):
    """Returns graph representation ready for React Flow."""
    svc = InvestigationService(db)
    try:
        details = await svc.get_investigation_details(investigation_id)
        return details.graph
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@router.post("/{investigation_id}/pivot", response_model=InvestigationDetailResponse)
async def pivot_investigation(
    investigation_id: str,
    req: PivotRequest,
    db: AsyncSession = Depends(get_db),
):
    """
    Pivots from a selected IOC in the investigation, expanding the graph and related IOCs.
    """
    svc = InvestigationService(db)
    try:
        return await svc.pivot(
            investigation_id=investigation_id,
            target_ioc=req.target_ioc,
            target_type=req.target_type,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Pivot failed: {str(e)}")
