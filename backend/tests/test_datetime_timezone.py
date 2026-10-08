import pytest
from datetime import datetime, timezone
from sqlalchemy import select
from app.models.models import (
    Investigation,
    IOCRecord,
    ProviderResultRecord,
    RelationshipRecord,
    InvestigationEventRecord,
    PivotRunRecord,
    utc_now,
)


@pytest.mark.asyncio
async def test_utc_now_is_timezone_aware():
    now = utc_now()
    assert now.tzinfo is not None
    assert now.tzinfo == timezone.utc


@pytest.mark.asyncio
async def test_investigation_timezone_aware_lifecycle(db_session):
    # 1. Create investigation with timezone-aware datetimes
    now = datetime.now(timezone.utc)
    inv = Investigation(
        root_ioc_value="8.8.8.8",
        root_ioc_type="ipv4",
        status="running",
        created_at=now,
        updated_at=now,
    )
    db_session.add(inv)
    await db_session.commit()
    await db_session.refresh(inv)

    assert inv.id is not None
    assert inv.created_at is not None

    # 2. Update investigation with a new timezone-aware datetime (regression for asyncpg offset-naive vs aware bug)
    later = datetime.now(timezone.utc)
    inv.updated_at = later
    inv.status = "complete"
    inv.risk_score = 75.0
    await db_session.commit()
    await db_session.refresh(inv)

    # 3. Retrieve and verify
    stmt = select(Investigation).where(Investigation.id == inv.id)
    res = await db_session.execute(stmt)
    retrieved = res.scalar_one()

    assert retrieved.status == "complete"
    assert retrieved.risk_score == 75.0


@pytest.mark.asyncio
async def test_all_models_timezone_aware_persistence(db_session):
    now = datetime.now(timezone.utc)
    inv = Investigation(
        root_ioc_value="1.1.1.1",
        root_ioc_type="ipv4",
        status="running",
        created_at=now,
        updated_at=now,
    )
    db_session.add(inv)
    await db_session.flush()

    ioc = IOCRecord(
        investigation_id=inv.id,
        canonical_value="1.1.1.1",
        ioc_type="ipv4",
        created_at=now,
    )
    db_session.add(ioc)

    prov = ProviderResultRecord(
        investigation_id=inv.id,
        provider_name="virustotal",
        ioc_value="1.1.1.1",
        ioc_type="ipv4",
        status="success",
        created_at=now,
    )
    db_session.add(prov)

    rel = RelationshipRecord(
        investigation_id=inv.id,
        source_value="1.1.1.1",
        source_type="ipv4",
        target_value="one.one.one.one",
        target_type="domain",
        relationship_type="resolves_to",
        providers=["virustotal"],
        created_at=now,
    )
    db_session.add(rel)

    event = InvestigationEventRecord(
        investigation_id=inv.id,
        event_type="test_event",
        message="Testing timezone awareness",
        created_at=now,
    )
    db_session.add(event)

    pivot = PivotRunRecord(
        investigation_id=inv.id,
        parent_ioc="1.1.1.1",
        child_ioc="one.one.one.one",
        depth=1,
        created_at=now,
    )
    db_session.add(pivot)

    await db_session.commit()
    # All records committed successfully without datetime conversion errors
    assert inv.id is not None
    assert ioc.id is not None
    assert prov.id is not None
    assert rel.id is not None
    assert event.id is not None
    assert pivot.id is not None
