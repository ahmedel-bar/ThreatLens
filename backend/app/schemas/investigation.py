from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from datetime import datetime
from app.schemas.ioc import IOCType
from app.schemas.provider import (
    ProviderResult,
    InfrastructureData,
    ProviderEvidence,
    TTPTechnique,
    PulseMetadata,
    PassiveDnsRecord,
    TTPTacticNode,
    HistoricalWhoisRecord,
)


class StartInvestigationRequest(BaseModel):
    ioc: str
    ioc_type: Optional[IOCType] = None
    max_depth: Optional[int] = None
    providers: Optional[List[str]] = None


class PivotRequest(BaseModel):
    target_ioc: str
    target_type: Optional[IOCType] = None
    depth: Optional[int] = 1


class CanonicalIOCResponse(BaseModel):
    id: str
    canonical_value: str
    ioc_type: IOCType
    is_root: bool
    depth: int
    confidence: float
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)
    relationships: List[str] = Field(default_factory=list)
    providers: List[str] = Field(default_factory=list)


class RelationshipResponse(BaseModel):
    id: str
    source_value: str
    source_type: str
    target_value: str
    target_type: str
    relationship_type: str
    confidence: float
    providers: List[str]
    evidence_count: int
    evidence_summary: Optional[str] = None
    depth: int


class Layer1ReputationResponse(BaseModel):
    root_ioc: str
    root_type: IOCType
    overall_classification: str
    risk_score: float
    total_providers_queried: int
    applicable_providers_count: int = 0  # Clean denominator of providers supporting this IOC
    providers_success: int
    providers_failed: int
    providers_not_found: int = 0
    verdict_counts: Dict[str, int] = Field(default_factory=dict)  # {"malicious": X, "suspicious": Y, "clean": Z, "unknown": W}
    vt_engine_counts: Optional[Dict[str, int]] = None  # VirusTotal's internal security engines
    provider_results: List[ProviderResult] = Field(default_factory=list)
    ttps: List[TTPTechnique] = Field(default_factory=list)



class Layer2InfrastructureResponse(BaseModel):
    root_ioc: str
    root_type: IOCType
    aggregated_infrastructure: InfrastructureData
    provider_contributions: Dict[str, InfrastructureData] = Field(default_factory=dict)
    ttps: List[TTPTechnique] = Field(default_factory=list)
    otx_pulses: List[PulseMetadata] = Field(default_factory=list)
    passive_dns: List[PassiveDnsRecord] = Field(default_factory=list)
    ttp_hierarchy: List[TTPTacticNode] = Field(default_factory=list)
    historical_whois: List[HistoricalWhoisRecord] = Field(default_factory=list)


class Layer3DiscoveredIOCsResponse(BaseModel):
    hashes: List[CanonicalIOCResponse] = Field(default_factory=list)
    ips: List[CanonicalIOCResponse] = Field(default_factory=list)
    urls_and_domains: List[CanonicalIOCResponse] = Field(default_factory=list)
    total_count: int = 0


class GraphNode(BaseModel):
    id: str
    label: str
    type: str  # ip, domain, url, hash, asn, cert, actor, malware
    confidence: float
    depth: int
    is_root: bool = False
    metadata: Dict[str, Any] = Field(default_factory=dict)


class GraphEdge(BaseModel):
    id: str
    source: str
    target: str
    label: str  # relationship_type
    confidence: float
    providers: List[str]
    evidence_count: int


class GraphResponse(BaseModel):
    root_ioc: str
    nodes: List[GraphNode]
    edges: List[GraphEdge]


class InvestigationEventResponse(BaseModel):
    id: str
    event_type: str
    message: str
    details: Optional[Dict[str, Any]] = None
    created_at: datetime


class InvestigationSummaryResponse(BaseModel):
    id: str
    root_ioc_value: str
    root_ioc_type: str
    status: str
    risk_score: float
    pivot_depth: int
    discovered_iocs_count: int
    total_relationships: int
    providers_queried: int
    created_at: datetime
    updated_at: datetime


class InvestigationDetailResponse(BaseModel):
    id: str
    root_ioc_value: str
    root_ioc_type: str
    status: str
    error_message: Optional[str] = None
    risk_score: float
    pivot_depth: int
    created_at: datetime
    updated_at: datetime
    layer1: Layer1ReputationResponse
    layer2: Layer2InfrastructureResponse
    layer3: Layer3DiscoveredIOCsResponse
    graph: GraphResponse
    events: List[InvestigationEventResponse] = Field(default_factory=list)
