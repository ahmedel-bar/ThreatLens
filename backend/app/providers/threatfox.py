import httpx
from typing import Dict, Any, List
from app.providers.base import BaseProvider, ProviderRequestContext
from app.schemas.ioc import IOCType, ProviderStatus
from app.schemas.provider import (
    ProviderCapability,
    ProviderResult,
    InfrastructureData,
    DiscoveredIOC,
    ProviderEvidence,
    ThreatAttribution,
)


class ThreatFoxProvider(BaseProvider):
    @property
    def name(self) -> str:
        return "threatfox"

    @property
    def display_name(self) -> str:
        return "ThreatFox"

    def get_capabilities(self) -> ProviderCapability:
        return ProviderCapability(
            name=self.name,
            display_name=self.display_name,
            description="Abuse.ch community platform for sharing indicators of compromise (IOCs) associated with malware campaigns.",
            supported_iocs=[
                IOCType.IPV4,
                IOCType.IPV6,
                IOCType.DOMAIN,
                IOCType.URL,
                IOCType.MD5,
                IOCType.SHA1,
                IOCType.SHA256,
            ],
            requires_auth=True,
            free_tier=True,
            rate_limit_desc="Community open API via Abuse.ch Auth-Key",
            provides_reputation=True,
            provides_infrastructure=False,
            provides_relationships=True,
            doc_url="https://threatfox.abuse.ch/api/",
        )

    async def _execute_live(self, ctx: ProviderRequestContext) -> ProviderResult:
        url = "https://threatfox-api.abuse.ch/api/v1/"
        headers = {}
        if ctx.api_key:
            headers["Auth-Key"] = ctx.api_key.strip()

        client = ctx.http_client or httpx.AsyncClient(timeout=ctx.timeout_seconds)
        should_close = ctx.http_client is None
        try:
            if ctx.ioc_type in (IOCType.MD5, IOCType.SHA1, IOCType.SHA256):
                # In ThreatFox, hashes submitted as IOCs match 'search_ioc', while sample associations match 'search_hash'
                payload_ioc = {"query": "search_ioc", "search_term": ctx.ioc_value}
                resp = await client.post(url, json=payload_ioc, headers=headers)
                resp.raise_for_status()
                data = resp.json()
                if data.get("query_status") == "ok" and isinstance(data.get("data"), list):
                    return self._parse_response(ctx, data)

                # Fallback to search_hash
                payload_hash = {"query": "search_hash", "hash": ctx.ioc_value}
                resp2 = await client.post(url, json=payload_hash, headers=headers)
                resp2.raise_for_status()
                data2 = resp2.json()
                return self._parse_response(ctx, data2)
            else:
                # Do not force exact_match=True because ThreatFox indexes IPs with ports (e.g. 1.2.3.4:443)
                payload = {"query": "search_ioc", "search_term": ctx.ioc_value}
                resp = await client.post(url, json=payload, headers=headers)
                resp.raise_for_status()
                data = resp.json()
                return self._parse_response(ctx, data)
        finally:
            if should_close:
                await client.aclose()

    def _parse_response(self, ctx: ProviderRequestContext, data: Dict[str, Any]) -> ProviderResult:
        status = data.get("query_status")
        if status in ("no_result", "hash_not_found"):
            return ProviderResult(
                provider_name=self.name,
                ioc_value=ctx.ioc_value,
                ioc_type=ctx.ioc_type,
                status=ProviderStatus.NOT_FOUND,
                classification="unknown",
                reputation_score=0.0,
                raw_data=data,
            )

        if status != "ok" or not data.get("data"):
            return ProviderResult(
                provider_name=self.name,
                ioc_value=ctx.ioc_value,
                ioc_type=ctx.ioc_type,
                status=ProviderStatus.INVALID_RESPONSE,
                error_details=f"Unexpected query_status: {status}",
                raw_data=data,
            )

        entries = data["data"]
        malware_families = set()
        threat_actors = set()
        tags = set()
        confidence_levels = []
        tf_attributions: List[ThreatAttribution] = []
        seen_tf_fams = set()

        discovered: List[DiscoveredIOC] = []

        for item in entries:
            actor = item.get("threat_actor")
            if actor and isinstance(actor, str) and actor.strip():
                threat_actors.add(actor.strip())

            mal = item.get("malware_printable")
            if mal:
                malware_families.add(mal)
                if mal not in seen_tf_fams:
                    seen_tf_fams.add(mal)
                    raw_alias = item.get("malware_alias")
                    raw_mal = item.get("malware")
                    aliases = []
                    if raw_alias and raw_alias != mal:
                        aliases.append(raw_alias)
                    if raw_mal and raw_mal != mal and raw_mal not in aliases:
                        aliases.append(raw_mal)

                    tf_attributions.append(
                        ThreatAttribution(
                            malware_family=mal,
                            malware_names=[mal],
                            malware_type=item.get("threat_type"),
                            threat_actor=item.get("threat_actor"),
                            aliases=aliases,
                            threat_tags=item.get("tags") or [],
                            sources=["threatfox"],
                            confidence=float(item.get("confidence_level") or 80),
                            evidence_summary=f"ThreatFox indexed IOC with threat '{item.get('threat_type')}'",
                        )
                    )
            elif actor and isinstance(actor, str) and actor.strip():
                tf_attributions.append(
                    ThreatAttribution(
                        threat_actor=actor.strip(),
                        malware_type=item.get("threat_type"),
                        threat_tags=item.get("tags") or [],
                        sources=["threatfox"],
                        confidence=float(item.get("confidence_level") or 80),
                        evidence_summary=f"ThreatFox indexed threat actor '{actor.strip()}'",
                    )
                )
            for t in item.get("tags") or []:
                tags.add(t)
            conf = item.get("confidence_level")
            if conf is not None:
                confidence_levels.append(float(conf))

            # Discovered IOC from entry if different
            entry_ioc = item.get("ioc")
            if entry_ioc and entry_ioc != ctx.ioc_value:
                # If entry_ioc has port (e.g., 1.2.3.4:443), extract IP
                clean_entry = entry_ioc.split(":")[0] if ":" in entry_ioc and not entry_ioc.startswith("http") else entry_ioc
                discovered.append(
                    DiscoveredIOC(
                        raw_value=clean_entry,
                        canonical_value=clean_entry.lower(),
                        ioc_type=ctx.ioc_type,
                        relationship_type="associated_with",
                        confidence=float(conf or 75),
                        evidence_desc=f"ThreatFox entry threat: {item.get('threat_type')}",
                    )
                )

        avg_conf = sum(confidence_levels) / len(confidence_levels) if confidence_levels else 80.0

        evidences = [
            ProviderEvidence(
                provider_name=self.name,
                evidence_type="threatfox_malware_attribution",
                description=f"Indexed in ThreatFox with attribution to {', '.join(malware_families) or 'malware campaign'} (Confidence: {avg_conf}%).",
                confidence=avg_conf,
            )
        ]

        infra = InfrastructureData(
            threat_attribution=tf_attributions[0] if tf_attributions else None,
            threat_attributions=tf_attributions,
            extra={
                "threat_types": list({i.get("threat_type") for i in entries if i.get("threat_type")}),
                "first_seen": entries[0].get("first_seen") if entries else None,
            }
        )

        return ProviderResult(
            provider_name=self.name,
            ioc_value=ctx.ioc_value,
            ioc_type=ctx.ioc_type,
            status=ProviderStatus.SUCCESS,
            reputation_score=avg_conf,
            classification="malicious",
            malicious_count=len(entries),
            suspicious_count=0,
            harmless_count=0,
            tags=list(tags),
            malware_families=list(malware_families),
            threat_actors=sorted(list(threat_actors)),
            infrastructure=infra,
            discovered_iocs=discovered,
            evidences=evidences,
            raw_data=data,
        )

    async def _execute_mock(self, ctx: ProviderRequestContext) -> ProviderResult:
        mock_data = {
            "query_status": "ok",
            "data": [
                {
                    "id": "123456",
                    "ioc": f"{ctx.ioc_value}:8080" if ctx.ioc_type == IOCType.IPV4 else ctx.ioc_value,
                    "threat_type": "botnet_cc",
                    "threat_type_desc": "Botnet C&C server",
                    "ioc_type": "ip:port" if ctx.ioc_type == IOCType.IPV4 else "domain",
                    "malware": "win.redline_stealer",
                    "malware_printable": "RedLine Stealer",
                    "confidence_level": 85,
                    "first_seen": "2026-02-10 12:00:00 UTC",
                    "reporter": "abuse_ch",
                    "tags": ["RedLine", "c2", "stealer"],
                }
            ],
        }
        return self._parse_response(ctx, mock_data)
