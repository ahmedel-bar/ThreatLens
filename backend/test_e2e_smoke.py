import asyncio
import sys
from pathlib import Path

# Add backend directory to sys.path
backend_dir = Path(__file__).resolve().parent
sys.path.insert(0, str(backend_dir))

from app.db.session import init_db, AsyncSessionLocal
from app.services.investigation import InvestigationService
from app.schemas.ioc import IOCType


async def main():
    print("=== ThreatLens End-to-End Smoke Test ===")
    await init_db()
    print("[1/5] Database initialized successfully.")

    async with AsyncSessionLocal() as session:
        svc = InvestigationService(session)

        # 1. Start Investigation from IPv4
        print("[2/5] Starting investigation on 8.8.8.8...")
        inv = await svc.start_investigation("8.8.8.8")
        print(f"       Investigation ID: {inv.id}")
        print(f"       Root IOC: {inv.root_ioc_value} ({inv.root_ioc_type})")
        print(f"       Status: {inv.status}")
        print(f"       Risk Score: {inv.risk_score}")
        print(f"       Layer 1 Providers Queried: {inv.layer1.total_providers_queried} (Success: {inv.layer1.providers_success})")
        print(f"       Layer 2 Open Ports: {inv.layer2.aggregated_infrastructure.open_ports}")
        print(f"       Layer 3 Discovered Hashes: {len(inv.layer3.hashes)}")
        print(f"       Layer 3 Discovered IPs: {len(inv.layer3.ips)}")
        print(f"       Layer 3 Discovered URLs & Domains: {len(inv.layer3.urls_and_domains)}")
        print(f"       Graph Nodes: {len(inv.graph.nodes)}, Edges: {len(inv.graph.edges)}")

        assert inv.status in ("complete", "partial")
        assert len(inv.layer1.provider_results) >= 8
        assert len(inv.graph.nodes) >= 1

        # 2. Pivot from a child IOC if available
        child_target = "dns.google"
        child_type = IOCType.DOMAIN
        if inv.layer3.urls_and_domains:
            child_target = inv.layer3.urls_and_domains[0].canonical_value
            child_type = inv.layer3.urls_and_domains[0].ioc_type

        print(f"[3/5] Pivoting from discovered IOC: {child_target} ({child_type.value})...")
        pivoted_inv = await svc.pivot(inv.id, child_target, child_type)
        print(f"       New Pivot Depth: {pivoted_inv.pivot_depth}")
        print(f"       Updated Graph Nodes: {len(pivoted_inv.graph.nodes)}, Edges: {len(pivoted_inv.graph.edges)}")
        assert pivoted_inv.pivot_depth == 1

        # 3. Investigation History
        print("[4/5] Listing investigation history...")
        history = await svc.list_investigations()
        print(f"       Total investigations in history: {len(history)}")
        assert len(history) >= 1
        assert history[0].id == inv.id

    print("[5/5] Smoke test completed with 100% SUCCESS!")


if __name__ == "__main__":
    asyncio.run(main())
