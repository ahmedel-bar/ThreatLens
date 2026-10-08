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


class GreyNoiseProvider(BaseProvider):
    @property
    def name(self) -> str:
        return "greynoise"

    @property
    def display_name(self) -> str:
        return "GreyNoise"

    def get_capabilities(self) -> ProviderCapability:
        return ProviderCapability(
            name=self.name,
            display_name=self.display_name,
            description="Internet-wide scanner intelligence and RIOT service distinguishing malicious attackers from opportunistic noise and benign cloud crawlers.",
            supported_iocs=[
                IOCType.IPV4,
            ],
            requires_auth=False,
            free_tier=True,
            rate_limit_desc="10,000 lookups/week on v3 community endpoint",
            provides_reputation=True,
            provides_infrastructure=True,
            provides_relationships=True,
            doc_url="https://docs.greynoise.io/reference/get_v3-ip-ip",
        )

    async def _execute_live(self, ctx: ProviderRequestContext) -> ProviderResult:
        headers = {}
        if ctx.api_key:
            headers["key"] = ctx.api_key
            url = f"https://api.greynoise.io/v3/ip/{ctx.ioc_value}"
        else:
            url = f"https://api.greynoise.io/v3/community/ip/{ctx.ioc_value}"

        client = ctx.http_client or httpx.AsyncClient(timeout=ctx.timeout_seconds)
        should_close = ctx.http_client is None
        try:
            resp = await client.get(url, headers=headers)
            resp.raise_for_status()
            data = resp.json()
            return self._parse_response(ctx, data)
        finally:
            if should_close:
                await client.aclose()

    def _parse_response(self, ctx: ProviderRequestContext, data: Dict[str, Any]) -> ProviderResult:
        message = data.get("message")
        if message == "IP not observed" or data.get("noise") is False and not data.get("riot"):
            return ProviderResult(
                provider_name=self.name,
                ioc_value=ctx.ioc_value,
                ioc_type=ctx.ioc_type,
                status=ProviderStatus.SUCCESS,
                classification="benign" if data.get("riot") else "unknown",
                reputation_score=0.0,
                tags=["not-observed-scanning"] if not data.get("riot") else ["riot-service"],
                raw_data=data,
            )

        classification = (data.get("classification") or "unknown").lower()
        noise = data.get("noise", False)
        riot = data.get("riot", False)
        actor = data.get("actor") or "Unknown Scanner"
        bot = data.get("bot")
        vpn = data.get("vpn")
        tags = data.get("tags") or []
        cve_list = data.get("cve") or []
        meta = data.get("metadata") or {}

        reputation_score = 10.0
        if classification == "malicious":
            reputation_score = 85.0
        elif classification == "benign" or riot:
            reputation_score = 5.0
            classification = "benign"
        elif noise:
            reputation_score = 45.0
            classification = "suspicious"

        # Infrastructure
        asn = str(meta.get("asn")) if meta.get("asn") else None
        org = meta.get("organization")
        country = meta.get("country")
        city = meta.get("city")
        rdns = meta.get("rdns")

        threat_actors = [actor] if actor and actor.lower() not in ("unknown scanner", "unknown", "none", "n/a") else []
        gn_attributions: List[ThreatAttribution] = []
        if threat_actors:
            gn_attributions.append(
                ThreatAttribution(
                    threat_actor=threat_actors[0],
                    cves=cve_list if isinstance(cve_list, list) else [],
                    sources=["greynoise"],
                    confidence=80.0,
                    evidence_summary=f"GreyNoise actor '{threat_actors[0]}'",
                )
            )

        infra = InfrastructureData(
            asn=asn,
            org=org,
            country=country,
            city=city,
            ptr=rdns,
            threat_attribution=gn_attributions[0] if gn_attributions else None,
            threat_attributions=gn_attributions,
            extra={
                "noise": noise,
                "riot": riot,
                "bot": bot,
                "vpn": vpn,
                "cve": cve_list,
                "last_seen": data.get("last_seen"),
            },
        )

        discovered: List[DiscoveredIOC] = []
        if rdns and rdns != ctx.ioc_value:
            discovered.append(
                DiscoveredIOC(
                    raw_value=rdns,
                    canonical_value=rdns.lower().rstrip("."),
                    ioc_type=IOCType.DOMAIN,
                    relationship_type="associated_domain",
                    confidence=80.0,
                    evidence_desc="GreyNoise reverse DNS record",
                )
            )

        evidences = [
            ProviderEvidence(
                provider_name=self.name,
                evidence_type="internet_scanning_behavior",
                description=f"GreyNoise v3 classified IP as '{classification.upper()}' (Noise: {noise}, RIOT: {riot}, Actor: {actor}).",
                confidence=reputation_score,
            )
        ]

        return ProviderResult(
            provider_name=self.name,
            ioc_value=ctx.ioc_value,
            ioc_type=ctx.ioc_type,
            status=ProviderStatus.SUCCESS,
            reputation_score=reputation_score,
            classification=classification,
            malicious_count=1 if classification == "malicious" else 0,
            suspicious_count=1 if classification == "suspicious" else 0,
            harmless_count=1 if classification == "benign" else 0,
            tags=tags if isinstance(tags, list) else [tags],
            threat_actors=threat_actors,
            infrastructure=infra,
            discovered_iocs=discovered,
            evidences=evidences,
            raw_data=data,
        )

    async def _execute_mock(self, ctx: ProviderRequestContext) -> ProviderResult:
        mock_data = {
            "ip": ctx.ioc_value,
            "noise": True,
            "riot": False,
            "classification": "malicious",
            "actor": "Mirai Operator",
            "bot": "Mirai Variant",
            "vpn": False,
            "last_seen": "2026-02-18",
            "tags": ["Telnet Bruteforcer", "Mirai", "Worm"],
            "cve": ["CVE-2017-17215", "CVE-2014-8361"],
            "metadata": {
                "asn": "AS4134",
                "organization": "CHINANET-BACKBONE",
                "country": "China",
                "city": "Hangzhou",
                "rdns": "scan-node-china.telnet-prober.net",
            },
        }
        return self._parse_response(ctx, mock_data)
