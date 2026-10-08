"""
mnemonic Passive DNS Provider Adapter.
Integrates the official mnemonic PassiveDNS Public API:
GET https://api.mnemonic.no/pdns/v3/<query>?limit=50
Supports IPv4, IPv6, and Domain indicators. Excludes hashes.
"""

import time
import httpx
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any

from app.schemas.ioc import IOCType, ProviderStatus
from app.schemas.provider import (
    ProviderCapability,
    ProviderResult,
    InfrastructureData,
    DiscoveredIOC,
    PassiveDnsRecord,
)
from app.providers.base import BaseProvider, ProviderRequestContext
from app.services.ioc import normalize_ioc


def format_pdns_timestamp(ts_ms: Optional[int]) -> Optional[str]:
    """
    Converts millisecond epoch timestamp to readable UTC string:
    e.g. 'May 13, 2025 — 01:31 UTC'
    """
    if ts_ms is None or not isinstance(ts_ms, (int, float)) or ts_ms <= 0:
        return None
    try:
        dt = datetime.fromtimestamp(ts_ms / 1000.0, tz=timezone.utc)
        month_name = dt.strftime("%B")
        return f"{month_name} {dt.day}, {dt.year} — {dt.strftime('%H:%M')} UTC"
    except Exception:
        return None


class PassiveDNSProvider(BaseProvider):
    @property
    def name(self) -> str:
        return "mnemonic_passivedns"

    @property
    def display_name(self) -> str:
        return "mnemonic Passive DNS"

    def get_capabilities(self) -> ProviderCapability:
        return ProviderCapability(
            name=self.name,
            display_name=self.display_name,
            description="mnemonic PassiveDNS Public API providing historical DNS query and answer records.",
            supported_iocs=[IOCType.IPV4, IOCType.IPV6, IOCType.DOMAIN],
            provides_reputation=False,
            provides_infrastructure=True,
            provides_relationships=True,
            requires_auth=False,
            free_tier=True,
            rate_limit_per_minute=10,
            rate_limit_desc="10 requests/minute, 1,000 requests/day",
            doc_url="https://docs.mnemonic.no/service-integration-guides/passivedns/docs/public/01-public_api.html",
        )

    async def _execute_live(self, ctx: ProviderRequestContext) -> ProviderResult:
        base_url = "https://api.mnemonic.no/pdns/v3"
        query_val = ctx.ioc_value.strip().lower()
        url = f"{base_url}/{query_val}"
        params = {"limit": 50}

        headers = {"Accept": "application/json"}
        if ctx.api_key and ctx.api_key.strip():
            headers["Argus-API-Key"] = ctx.api_key.strip()

        client = ctx.http_client or httpx.AsyncClient(timeout=ctx.timeout_seconds)
        should_close = ctx.http_client is None

        try:
            resp = await client.get(url, params=params, headers=headers)

            if resp.status_code in (402, 429):
                retry_sec = 60
                try:
                    body = resp.json()
                    millis = body.get("millisUntilResourcesAvailable")
                    if millis:
                        retry_sec = max(1, int(millis / 1000))
                except Exception:
                    pass
                return ProviderResult(
                    provider_name=self.name,
                    ioc_value=ctx.ioc_value,
                    ioc_type=ctx.ioc_type,
                    status=ProviderStatus.RATE_LIMITED,
                    error_details=f"mnemonic rate/resource quota exceeded. Resets in {retry_sec}s.",
                )

            if resp.status_code == 404:
                return ProviderResult(
                    provider_name=self.name,
                    ioc_value=ctx.ioc_value,
                    ioc_type=ctx.ioc_type,
                    status=ProviderStatus.NOT_FOUND,
                    error_details="No matching Passive DNS records found.",
                )

            resp.raise_for_status()
            payload = resp.json()

            response_code = payload.get("responseCode", 200)
            if response_code in (402, 429):
                millis = payload.get("millisUntilResourcesAvailable", 60000)
                retry_sec = max(1, int(millis / 1000))
                return ProviderResult(
                    provider_name=self.name,
                    ioc_value=ctx.ioc_value,
                    ioc_type=ctx.ioc_type,
                    status=ProviderStatus.RATE_LIMITED,
                    error_details=f"mnemonic resource quota exceeded. Resets in {retry_sec}s.",
                )

            data_list = payload.get("data", [])
            count = payload.get("count", len(data_list))

            if count == 0 or not data_list:
                return ProviderResult(
                    provider_name=self.name,
                    ioc_value=ctx.ioc_value,
                    ioc_type=ctx.ioc_type,
                    status=ProviderStatus.NOT_FOUND,
                    error_details="No matching Passive DNS records found.",
                )

            pdns_records: List[PassiveDnsRecord] = []
            discovered_iocs: List[DiscoveredIOC] = []
            seen_iocs = set()

            for item in data_list:
                if not isinstance(item, dict):
                    continue

                q_val = str(item.get("query") or "").strip()
                ans_val = str(item.get("answer") or "").strip()
                if not q_val or not ans_val:
                    continue

                rrtype = str(item.get("rrtype") or "").strip().upper()
                rrclass = str(item.get("rrclass") or "IN").strip().upper()
                first_ts = item.get("firstSeenTimestamp")
                last_ts = item.get("lastSeenTimestamp")
                times = item.get("times") if item.get("times") is not None else item.get("count")
                min_ttl = item.get("minTtl")
                max_ttl = item.get("maxTtl")
                tlp_val = item.get("tlp") or "white"

                rec = PassiveDnsRecord(
                    query=q_val,
                    answer=ans_val,
                    rrtype=rrtype,
                    rrclass=rrclass,
                    first_seen=format_pdns_timestamp(first_ts),
                    last_seen=format_pdns_timestamp(last_ts),
                    first_seen_timestamp=first_ts if isinstance(first_ts, int) else None,
                    last_seen_timestamp=last_ts if isinstance(last_ts, int) else None,
                    observation_count=times if isinstance(times, int) else None,
                    min_ttl=min_ttl if isinstance(min_ttl, int) else None,
                    max_ttl=max_ttl if isinstance(max_ttl, int) else None,
                    tlp=str(tlp_val),
                    sources=[self.name],
                )
                pdns_records.append(rec)

                # Layer 3 Canonical Pivotable IOC Extraction
                if ctx.ioc_type == IOCType.DOMAIN:
                    if rrtype in ("A", "AAAA"):
                        cand_type = IOCType.IPV4 if "." in ans_val else IOCType.IPV6
                        norm = normalize_ioc(ans_val, cand_type)
                        if norm.is_valid and norm.canonical_value:
                            k = (norm.canonical_value, norm.ioc_type.value)
                            if k not in seen_iocs and norm.canonical_value != ctx.ioc_value:
                                seen_iocs.add(k)
                                discovered_iocs.append(
                                    DiscoveredIOC(
                                        raw_value=norm.canonical_value,
                                        canonical_value=norm.canonical_value,
                                        ioc_type=norm.ioc_type,
                                        relationship_type="resolves_to",
                                        confidence=85.0,
                                        evidence_desc=f"Passive DNS {rrtype} record mapping {q_val} -> {norm.canonical_value} ({times or 1} observations)",
                                        first_seen=format_pdns_timestamp(first_ts),
                                        last_seen=format_pdns_timestamp(last_ts),
                                    )
                                )
                    elif rrtype == "CNAME":
                        norm = normalize_ioc(ans_val, IOCType.DOMAIN)
                        if norm.is_valid and norm.canonical_value:
                            k = (norm.canonical_value, norm.ioc_type.value)
                            if k not in seen_iocs and norm.canonical_value != ctx.ioc_value:
                                seen_iocs.add(k)
                                discovered_iocs.append(
                                    DiscoveredIOC(
                                        raw_value=norm.canonical_value,
                                        canonical_value=norm.canonical_value,
                                        ioc_type=norm.ioc_type,
                                        relationship_type="resolves_to",
                                        confidence=85.0,
                                        evidence_desc=f"Passive DNS CNAME alias {q_val} -> {norm.canonical_value}",
                                        first_seen=format_pdns_timestamp(first_ts),
                                        last_seen=format_pdns_timestamp(last_ts),
                                    )
                                )
                    elif rrtype == "NS":
                        norm = normalize_ioc(ans_val, IOCType.DOMAIN)
                        if norm.is_valid and norm.canonical_value:
                            k = (norm.canonical_value, norm.ioc_type.value)
                            if k not in seen_iocs and norm.canonical_value != ctx.ioc_value:
                                seen_iocs.add(k)
                                discovered_iocs.append(
                                    DiscoveredIOC(
                                        raw_value=norm.canonical_value,
                                        canonical_value=norm.canonical_value,
                                        ioc_type=norm.ioc_type,
                                        relationship_type="shares_nameserver",
                                        confidence=80.0,
                                        evidence_desc=f"Passive DNS authoritative nameserver {norm.canonical_value}",
                                        first_seen=format_pdns_timestamp(first_ts),
                                        last_seen=format_pdns_timestamp(last_ts),
                                    )
                                )
                elif ctx.ioc_type in (IOCType.IPV4, IOCType.IPV6):
                    cand_domain = q_val
                    norm = normalize_ioc(cand_domain, IOCType.DOMAIN)
                    if norm.is_valid and norm.canonical_value:
                        k = (norm.canonical_value, norm.ioc_type.value)
                        if k not in seen_iocs and norm.canonical_value != ctx.ioc_value:
                            seen_iocs.add(k)
                            discovered_iocs.append(
                                DiscoveredIOC(
                                    raw_value=norm.canonical_value,
                                    canonical_value=norm.canonical_value,
                                    ioc_type=norm.ioc_type,
                                    relationship_type="observed_with",
                                    confidence=85.0,
                                    evidence_desc=f"Passive DNS historically resolved domain {norm.canonical_value} to {ctx.ioc_value} ({times or 1} observations)",
                                    first_seen=format_pdns_timestamp(first_ts),
                                    last_seen=format_pdns_timestamp(last_ts),
                                )
                            )

            infra_data = InfrastructureData(
                passive_dns=pdns_records,
                extra={"mnemonic_count": count, "mnemonic_records_returned": len(pdns_records)},
            )

            return ProviderResult(
                provider_name=self.name,
                ioc_value=ctx.ioc_value,
                ioc_type=ctx.ioc_type,
                status=ProviderStatus.SUCCESS,
                classification="unknown",
                reputation_score=None,
                infrastructure=infra_data,
                discovered_iocs=discovered_iocs,
                raw_data={"count": count, "limit": payload.get("limit"), "sample": data_list[:5]},
            )

        finally:
            if should_close:
                await client.aclose()

    async def _execute_mock(self, ctx: ProviderRequestContext) -> ProviderResult:
        ioc = ctx.ioc_value.strip().lower()
        now_ms = int(time.time() * 1000)
        past_ms = now_ms - (365 * 24 * 3600 * 1000)

        pdns_records: List[PassiveDnsRecord] = []
        discovered_iocs: List[DiscoveredIOC] = []

        if ctx.ioc_type in (IOCType.IPV4, IOCType.IPV6):
            domains = [f"domain-{i}.example.org" for i in range(1, 4)]
            for d in domains:
                pdns_records.append(
                    PassiveDnsRecord(
                        query=d,
                        answer=ioc,
                        rrtype="A" if ctx.ioc_type == IOCType.IPV4 else "AAAA",
                        rrclass="IN",
                        first_seen=format_pdns_timestamp(past_ms),
                        last_seen=format_pdns_timestamp(now_ms),
                        first_seen_timestamp=past_ms,
                        last_seen_timestamp=now_ms,
                        observation_count=1240,
                        min_ttl=300,
                        max_ttl=3600,
                        tlp="white",
                        sources=[self.name],
                    )
                )
                discovered_iocs.append(
                    DiscoveredIOC(
                        raw_value=d,
                        canonical_value=d,
                        ioc_type=IOCType.DOMAIN,
                        relationship_type="observed_with",
                        confidence=85.0,
                        evidence_desc=f"Passive DNS historically resolved domain {d} to {ioc}",
                        first_seen=format_pdns_timestamp(past_ms),
                        last_seen=format_pdns_timestamp(now_ms),
                    )
                )
        else:
            ips = ["198.51.100.25", "203.0.113.88"]
            for ip in ips:
                pdns_records.append(
                    PassiveDnsRecord(
                        query=ioc,
                        answer=ip,
                        rrtype="A",
                        rrclass="IN",
                        first_seen=format_pdns_timestamp(past_ms),
                        last_seen=format_pdns_timestamp(now_ms),
                        first_seen_timestamp=past_ms,
                        last_seen_timestamp=now_ms,
                        observation_count=3450,
                        min_ttl=60,
                        max_ttl=600,
                        tlp="white",
                        sources=[self.name],
                    )
                )
                discovered_iocs.append(
                    DiscoveredIOC(
                        raw_value=ip,
                        canonical_value=ip,
                        ioc_type=IOCType.IPV4,
                        relationship_type="resolves_to",
                        confidence=85.0,
                        evidence_desc=f"Passive DNS A record mapping {ioc} to {ip}",
                        first_seen=format_pdns_timestamp(past_ms),
                        last_seen=format_pdns_timestamp(now_ms),
                    )
                )

        infra_data = InfrastructureData(
            passive_dns=pdns_records,
            extra={"mnemonic_count": len(pdns_records)},
        )

        return ProviderResult(
            provider_name=self.name,
            ioc_value=ctx.ioc_value,
            ioc_type=ctx.ioc_type,
            status=ProviderStatus.SUCCESS,
            classification="unknown",
            infrastructure=infra_data,
            discovered_iocs=discovered_iocs,
            raw_data={"count": len(pdns_records), "mock": True},
        )
