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


class URLhausProvider(BaseProvider):
    @property
    def name(self) -> str:
        return "urlhaus"

    @property
    def display_name(self) -> str:
        return "URLhaus"

    def get_capabilities(self) -> ProviderCapability:
        return ProviderCapability(
            name=self.name,
            display_name=self.display_name,
            description="Abuse.ch database for tracking and sharing malicious URLs used for malware distribution.",
            supported_iocs=[
                IOCType.URL,
                IOCType.DOMAIN,
                IOCType.IPV4,
                IOCType.MD5,
                IOCType.SHA256,
            ],
            requires_auth=True,
            free_tier=True,
            rate_limit_desc="Community open API via Abuse.ch Auth-Key",
            provides_reputation=True,
            provides_infrastructure=True,
            provides_relationships=True,
            doc_url="https://urlhaus.abuse.ch/api/",
        )

    async def _execute_live(self, ctx: ProviderRequestContext) -> ProviderResult:
        base_url = "https://urlhaus-api.abuse.ch/v1"
        headers = {}
        if ctx.api_key:
            headers["Auth-Key"] = ctx.api_key

        if ctx.ioc_type == IOCType.URL:
            endpoint = f"{base_url}/url/"
            payload = {"url": ctx.ioc_value}
        elif ctx.ioc_type in (IOCType.DOMAIN, IOCType.IPV4):
            endpoint = f"{base_url}/host/"
            payload = {"host": ctx.ioc_value}
        elif ctx.ioc_type == IOCType.MD5:
            endpoint = f"{base_url}/payload/"
            payload = {"md5": ctx.ioc_value}
        elif ctx.ioc_type == IOCType.SHA256:
            endpoint = f"{base_url}/payload/"
            payload = {"sha256": ctx.ioc_value}
        else:
            return ProviderResult(
                provider_name=self.name,
                ioc_value=ctx.ioc_value,
                ioc_type=ctx.ioc_type,
                status=ProviderStatus.UNSUPPORTED,
            )

        client = ctx.http_client or httpx.AsyncClient(timeout=ctx.timeout_seconds)
        should_close = ctx.http_client is None
        try:
            resp = await client.post(endpoint, data=payload, headers=headers)
            resp.raise_for_status()
            data = resp.json()
            return self._parse_response(ctx, data)
        finally:
            if should_close:
                await client.aclose()

    def _parse_response(self, ctx: ProviderRequestContext, data: Dict[str, Any]) -> ProviderResult:
        query_status = data.get("query_status")
        if query_status in ("no_results", "url_not_found", "host_not_found"):
            return ProviderResult(
                provider_name=self.name,
                ioc_value=ctx.ioc_value,
                ioc_type=ctx.ioc_type,
                status=ProviderStatus.NOT_FOUND,
                classification="unknown",
                reputation_score=0.0,
                raw_data=data,
            )

        if query_status != "ok":
            return ProviderResult(
                provider_name=self.name,
                ioc_value=ctx.ioc_value,
                ioc_type=ctx.ioc_type,
                status=ProviderStatus.INVALID_RESPONSE,
                error_details=f"Unexpected query_status: {query_status}",
                raw_data=data,
            )

        url_status = data.get("url_status")
        threat = data.get("threat")
        tags = data.get("tags") or []
        first_seen = data.get("date_added") or data.get("firstseen")
        payloads = data.get("payloads", [])

        # Extract malware families and threat attributions
        urlhaus_malware_families: List[str] = []
        urlhaus_attributions: List[ThreatAttribution] = []
        seen_uh_sigs = set()
        for p in payloads:
            sig = p.get("signature")
            if sig and sig not in seen_uh_sigs:
                seen_uh_sigs.add(sig)
                urlhaus_malware_families.append(sig)
                urlhaus_attributions.append(
                    ThreatAttribution(
                        malware_family=sig,
                        malware_names=[sig],
                        threat_tags=tags,
                        sources=["urlhaus"],
                        confidence=90.0,
                        evidence_summary=f"URLhaus delivered payload signature '{sig}'",
                    )
                )

        for t in tags:
            if t and t not in seen_uh_sigs:
                t_low = t.lower()
                if any(k in t_low for k in ["mozi", "mirai", "emotet", "qakbot", "redline", "stealer", "rat", "botnet", "ransom"]):
                    seen_uh_sigs.add(t)
                    urlhaus_malware_families.append(t)
                    urlhaus_attributions.append(
                        ThreatAttribution(
                            malware_family=t,
                            malware_names=[t],
                            threat_tags=tags,
                            sources=["urlhaus"],
                            confidence=85.0,
                            evidence_summary=f"URLhaus tag '{t}'",
                        )
                    )

        # Infrastructure
        asn = str(data.get("asn", "")) if data.get("asn") else None
        as_name = data.get("as_name")
        country = data.get("country")

        infra = InfrastructureData(
            asn=asn,
            asn_name=as_name,
            country=country,
            threat_attribution=urlhaus_attributions[0] if urlhaus_attributions else None,
            threat_attributions=urlhaus_attributions,
            extra={
                "url_status": url_status,
                "threat": threat,
                "first_seen": first_seen,
            },
        )

        discovered: List[DiscoveredIOC] = []
        for p in payloads[:5]:
            sha256 = p.get("response_sha256")
            md5 = p.get("response_md5")
            sig = p.get("signature")
            if sha256:
                discovered.append(
                    DiscoveredIOC(
                        raw_value=sha256,
                        canonical_value=sha256.lower(),
                        ioc_type=IOCType.SHA256,
                        relationship_type="downloads",
                        confidence=90.0,
                        evidence_desc=f"URLhaus delivered malware payload ({sig or 'malware'})",
                    )
                )
            if md5:
                discovered.append(
                    DiscoveredIOC(
                        raw_value=md5,
                        canonical_value=md5.lower(),
                        ioc_type=IOCType.MD5,
                        relationship_type="downloads",
                        confidence=90.0,
                        evidence_desc="URLhaus delivered malware payload MD5",
                    )
                )

        # Hosted URLs
        urls = data.get("urls", [])
        for u in urls[:5]:
            u_val = u.get("url")
            if u_val and u_val != ctx.ioc_value:
                discovered.append(
                    DiscoveredIOC(
                        raw_value=u_val,
                        canonical_value=u_val,
                        ioc_type=IOCType.URL,
                        relationship_type="hosts",
                        confidence=85.0,
                        evidence_desc="URLhaus hosted malware distribution URL",
                    )
                )

        # If URL, extract resolved IP
        lhost = data.get("lhost")
        if lhost and lhost != ctx.ioc_value:
            discovered.append(
                DiscoveredIOC(
                    raw_value=lhost,
                    canonical_value=lhost,
                    ioc_type=IOCType.IPV4,
                    relationship_type="resolves_to",
                    confidence=85.0,
                    evidence_desc="URLhaus observed landing host IP",
                )
            )

        evidences = [
            ProviderEvidence(
                provider_name=self.name,
                evidence_type="malware_distribution",
                description=f"Confirmed active malware distribution source (Status: {url_status or 'active'}, Threat: {threat or 'malware_download'}).",
                confidence=90.0,
            )
        ]

        return ProviderResult(
            provider_name=self.name,
            ioc_value=ctx.ioc_value,
            ioc_type=ctx.ioc_type,
            status=ProviderStatus.SUCCESS,
            reputation_score=90.0,
            classification="malicious",
            malicious_count=1 + len(payloads) + len(urls),
            suspicious_count=0,
            harmless_count=0,
            tags=tags,
            malware_families=urlhaus_malware_families,
            infrastructure=infra,
            discovered_iocs=discovered,
            evidences=evidences,
            raw_data=data,
        )

    async def _execute_mock(self, ctx: ProviderRequestContext) -> ProviderResult:
        mock_data = {
            "query_status": "ok",
            "id": "1849201",
            "url": ctx.ioc_value if ctx.ioc_type == IOCType.URL else f"http://{ctx.ioc_value}/bin/update.exe",
            "url_status": "online",
            "threat": "malware_download",
            "tags": ["Mozi", "botnet", "elf"],
            "date_added": "2026-02-14 09:12:33 UTC",
            "lhost": "198.51.100.12",
            "asn": "13335",
            "as_name": "Cloudflare, Inc.",
            "country": "US",
            "payloads": [
                {
                    "response_sha256": "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8",
                    "response_md5": "e99a18c428cb38d5f260853678922e03",
                    "signature": "Mozi.m",
                    "file_type": "elf",
                }
            ],
            "urls": [
                {"url": f"http://{ctx.ioc_value}/panel/gate.php"}
            ] if ctx.ioc_type != IOCType.URL else [],
        }
        return self._parse_response(ctx, mock_data)
