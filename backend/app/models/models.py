import uuid
from datetime import datetime, timezone
from sqlalchemy import (
    Column,
    String,
    Integer,
    Float,
    Boolean,
    DateTime,
    ForeignKey,
    Text,
    JSON,
    Index,
)
from sqlalchemy.orm import relationship
from app.db.session import Base


def generate_uuid() -> str:
    return str(uuid.uuid4())


def utc_now() -> datetime:
    """Returns timezone-aware UTC datetime."""
    return datetime.now(timezone.utc)


class Investigation(Base):
    __tablename__ = "investigations"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    root_ioc_value = Column(String(1024), nullable=False, index=True)
    root_ioc_type = Column(String(32), nullable=False)
    status = Column(String(32), nullable=False, default="running")  # running, complete, partial, failed
    error_message = Column(Text, nullable=True)
    risk_score = Column(Float, default=0.0)
    pivot_depth = Column(Integer, default=0)
    created_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)
    updated_at = Column(DateTime(timezone=True), default=utc_now, onupdate=utc_now, nullable=False)

    # Relationships
    iocs = relationship("IOCRecord", back_populates="investigation", cascade="all, delete-orphan")
    provider_results = relationship("ProviderResultRecord", back_populates="investigation", cascade="all, delete-orphan")
    relationships = relationship("RelationshipRecord", back_populates="investigation", cascade="all, delete-orphan")
    events = relationship("InvestigationEventRecord", back_populates="investigation", cascade="all, delete-orphan")


class IOCRecord(Base):
    __tablename__ = "iocs"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    investigation_id = Column(String(36), ForeignKey("investigations.id", ondelete="CASCADE"), nullable=False, index=True)
    canonical_value = Column(String(1024), nullable=False, index=True)
    ioc_type = Column(String(32), nullable=False, index=True)
    is_root = Column(Boolean, default=False)
    depth = Column(Integer, default=0)
    confidence = Column(Float, default=50.0)
    first_seen = Column(String(64), nullable=True)
    last_seen = Column(String(64), nullable=True)
    metadata_json = Column(JSON, nullable=True)
    created_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)

    investigation = relationship("Investigation", back_populates="iocs")

    __table_args__ = (
        Index("idx_ioc_investigation_canon_type", "investigation_id", "canonical_value", "ioc_type"),
    )


class ProviderResultRecord(Base):
    __tablename__ = "provider_results"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    investigation_id = Column(String(36), ForeignKey("investigations.id", ondelete="CASCADE"), nullable=False, index=True)
    provider_name = Column(String(64), nullable=False, index=True)
    ioc_value = Column(String(1024), nullable=False)
    ioc_type = Column(String(32), nullable=False)
    status = Column(String(32), nullable=False)  # ProviderStatus string
    execution_time_ms = Column(Integer, default=0)
    reputation_score = Column(Float, nullable=True)
    classification = Column(String(32), nullable=True)
    malicious_count = Column(Integer, default=0)
    suspicious_count = Column(Integer, default=0)
    harmless_count = Column(Integer, default=0)
    tags = Column(JSON, nullable=True)
    threat_actors = Column(JSON, nullable=True)
    malware_families = Column(JSON, nullable=True)
    infrastructure_data = Column(JSON, nullable=True)
    raw_data = Column(JSON, nullable=True)
    error_details = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)

    investigation = relationship("Investigation", back_populates="provider_results")


class RelationshipRecord(Base):
    __tablename__ = "relationships"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    investigation_id = Column(String(36), ForeignKey("investigations.id", ondelete="CASCADE"), nullable=False, index=True)
    source_value = Column(String(1024), nullable=False, index=True)
    source_type = Column(String(32), nullable=False)
    target_value = Column(String(1024), nullable=False, index=True)
    target_type = Column(String(32), nullable=False)
    relationship_type = Column(String(64), nullable=False, index=True)
    confidence = Column(Float, default=50.0)
    providers = Column(JSON, nullable=False)  # List of provider names
    evidence_count = Column(Integer, default=1)
    evidence_summary = Column(Text, nullable=True)
    depth = Column(Integer, default=0)
    created_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)

    investigation = relationship("Investigation", back_populates="relationships")

    __table_args__ = (
        Index("idx_rel_src_tgt_type", "investigation_id", "source_value", "target_value", "relationship_type"),
    )


class InvestigationEventRecord(Base):
    __tablename__ = "investigation_events"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    investigation_id = Column(String(36), ForeignKey("investigations.id", ondelete="CASCADE"), nullable=False, index=True)
    event_type = Column(String(64), nullable=False)
    message = Column(Text, nullable=False)
    details = Column(JSON, nullable=True)
    created_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)

    investigation = relationship("Investigation", back_populates="events")


class PivotRunRecord(Base):
    __tablename__ = "pivot_runs"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    investigation_id = Column(String(36), ForeignKey("investigations.id", ondelete="CASCADE"), nullable=False, index=True)
    parent_ioc = Column(String(1024), nullable=False)
    child_ioc = Column(String(1024), nullable=False)
    depth = Column(Integer, default=0)
    status = Column(String(32), default="completed")
    created_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)
