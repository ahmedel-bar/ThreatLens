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
)


class AbuseIPDBProvider(BaseProvider):
    @property
    def name(self) -> str:
        return "abuseipdb"

    @property
    def display_name(self) -> str:
        return "AbuseIPDB"

    def get_capabilities(self) -> ProviderCapability:
        return ProviderCapability(
            name=self.name,
            display_name=self.display_name,
            description="Crowdsourced IP reputation and abuse reporting database tracking malicious network activities.",
            supported_iocs=[
                IOCType.IPV4,
                IOCType.IPV6,
            ],
            requires_auth=True,
            free_tier=True,
            rate_limit_desc="1,000 checks/day on free personal API key",
            provides_reputation=True,
            provides_infrastructure=True,
            provides_relationships=True,
            doc_url="https://docs.abuseipdb.com/",
        )

    async def _execute_live(self, ctx: ProviderRequestContext) -> ProviderResult:
        base_url = "https://api.abuseipdb.com/api/v2/check"
        headers = {
            "Key": ctx.api_key or "",
            "Accept": "application/json",
        }
        params = {
            "ipAddress": ctx.ioc_value,
            "maxAgeInDays": "90",
            "verbose": "",
        }

        client = ctx.http_client or httpx.AsyncClient(timeout=ctx.timeout_seconds)
        should_close = ctx.http_client is None
        try:
            resp = await client.get(base_url, headers=headers, params=params)
            resp.raise_for_status()
            data = resp.json()
            return self._parse_response(ctx, data)
        finally:
            if should_close:
                await client.aclose()

    def _parse_response(self, ctx: ProviderRequestContext, data: Dict[str, Any]) -> ProviderResult:
        ip_data = data.get("data", {})
        if not ip_data:
            return ProviderResult(
                provider_name=self.name,
                ioc_value=ctx.ioc_value,
                ioc_type=ctx.ioc_type,
                status=ProviderStatus.NOT_FOUND,
                error_details="No IP data returned by AbuseIPDB.",
                raw_data=data,
            )

        abuse_score = float(ip_data.get("abuseConfidenceScore", 0))
        total_reports = ip_data.get("totalReports", 0)
        is_whitelisted = ip_data.get("isWhitelisted", False)
        isp = ip_data.get("isp")
        domain = ip_data.get("domain")
        country_code = ip_data.get("countryCode")
        country_name = ip_data.get("countryName")
        usage_type = ip_data.get("usageType")
        hostnames = ip_data.get("hostnames", [])

        if is_whitelisted or abuse_score == 0:
            classification = "benign"
        elif abuse_score >= 50:
            classification = "malicious"
        else:
            classification = "suspicious"

        infra = InfrastructureData(
            asn_name=isp,
            org=usage_type,
            country=country_code or country_name,
            extra={
                "domain": domain,
                "is_whitelisted": is_whitelisted,
                "total_reports": total_reports,
                "last_reported_at": ip_data.get("lastReportedAt"),
            },
        )

        discovered: List[DiscoveredIOC] = []

        # Associated hostnames
        for h in hostnames:
            if h and h != ctx.ioc_value:
                discovered.append(
                    DiscoveredIOC(
                        raw_value=h,
                        canonical_value=h.lower().rstrip("."),
                        ioc_type=IOCType.DOMAIN,
                        relationship_type="associated_domain",
                        confidence=80.0,
                        evidence_desc="AbuseIPDB associated reverse DNS hostname",
                    )
                )

        # Domain associated with ISP or server
        if domain and domain not in [d.canonical_value for d in discovered]:
            discovered.append(
                DiscoveredIOC(
                    raw_value=domain,
                    canonical_value=domain.lower().rstrip("."),
                    ioc_type=IOCType.DOMAIN,
                    relationship_type="associated_domain",
                    confidence=70.0,
                    evidence_desc="AbuseIPDB reported hosting domain",
                )
            )

        evidences = [
            ProviderEvidence(
                provider_name=self.name,
                evidence_type="abuse_reports",
                description=f"Abuse Confidence Score is {abuse_score}% across {total_reports} security reports in the last 90 days.",
                confidence=abuse_score,
            )
        ]

        return ProviderResult(
            provider_name=self.name,
            ioc_value=ctx.ioc_value,
            ioc_type=ctx.ioc_type,
            status=ProviderStatus.SUCCESS,
            reputation_score=abuse_score,
            classification=classification,
            malicious_count=total_reports if abuse_score > 25 else 0,
            suspicious_count=1 if 0 < abuse_score <= 25 else 0,
            harmless_count=1 if abuse_score == 0 else 0,
            tags=[usage_type] if usage_type else [],
            infrastructure=infra,
            discovered_iocs=discovered,
            evidences=evidences,
            raw_data=data,
        )

    async def _execute_mock(self, ctx: ProviderRequestContext) -> ProviderResult:
        mock_data = {
            "data": {
                "ipAddress": ctx.ioc_value,
                "isPublic": True,
                "ipVersion": 4,
                "isWhitelisted": False,
                "abuseConfidenceScore": 84,
                "countryCode": "RU",
                "countryName": "Russian Federation",
                "usageType": "Data Center/Web Hosting/Transit",
                "isp": "Hostkey B.V.",
                "domain": "hostkey.ru",
                "hostnames": ["scan-node-04.threat-net.org"],
                "totalReports": 42,
                "numDistinctUsers": 19,
                "lastReportedAt": "2026-02-18T10:14:22+00:00",
            }
        }
        return self._parse_response(ctx, mock_data)
