import pytest
from app.schemas.ioc import IOCType
from app.services.pivot import RecursivePivotEngine
from app.providers.router import ProviderRouter


@pytest.mark.asyncio
async def test_pivot_depth_and_cycle_prevention():
    router = ProviderRouter(is_mock=True)
    engine = RecursivePivotEngine(
        router=router,
        max_depth=2,
        max_nodes=10,
        max_requests=15,
    )

    # First traversal
    all_iocs, all_rels, all_results = await engine.execute_recursive_exploration(
        root_ioc="8.8.8.8",
        root_type=IOCType.IPV4,
        depth_limit=1,
    )

    assert len(all_iocs) > 0
    assert engine.requests_count <= 15
    assert len(all_iocs) <= 10

    # Test cycle: pivoting from 8.8.8.8 again should do nothing because it is in visited_nodes
    iocs2, rels2, res2 = await engine.pivot_single_step(
        target_ioc="8.8.8.8",
        target_type=IOCType.IPV4,
        current_depth=1,
        existing_iocs=all_iocs,
        existing_relationships=all_rels,
    )
    assert len(res2) == 0  # no new queries made
