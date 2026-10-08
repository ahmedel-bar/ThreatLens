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


class URLScanProvider(BaseProvider):
    @property
    def name(self) -> str:
        return "urlscan"

    @property
    def display_name(self) -> str:
        return "urlscan.io"

    def get_capabilities(self) -> ProviderCapability:
        return ProviderCapability(
            name=self.name,
            display_name=self.display_name,
            description="Web browser scanning and threat analysis engine extracting DOM snapshots, server technologies, certificates, and contacted resources.",
            supported_iocs=[
                IOCType.DOMAIN,
                IOCType.IPV4,
                IOCType.URL,
                IOCType.SHA256,
            ],
            requires_auth=False,
            free_tier=True,
            rate_limit_desc="Public search API without key (higher quota with free key)",
            provides_reputation=True,
            provides_infrastructure=True,
            provides_relationships=True,
            doc_url="https://urlscan.io/docs/api/",
        )

    def _build_search_query(self, ctx: ProviderRequestContext) -> str:
        if ctx.ioc_type == IOCType.DOMAIN:
            return f"domain:{ctx.ioc_value}"
        elif ctx.ioc_type == IOCType.IPV4:
            return f"ip:{ctx.ioc_value}"
        elif ctx.ioc_type == IOCType.URL:
            return f'page.url:"{ctx.ioc_value}"'
        elif ctx.ioc_type == IOCType.SHA256:
            return f"hash:{ctx.ioc_value}"
        return ctx.ioc_value

    async def _execute_live(self, ctx: ProviderRequestContext) -> ProviderResult:
        base_url = "https://urlscan.io/api/v1/search/"
        query = self._build_search_query(ctx)
        headers = {}
        if ctx.api_key:
            headers["API-Key"] = ctx.api_key

        params = {"q": query, "size": 10}

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
        results = data.get("results", [])
        total = data.get("total", 0)

        if not results or total == 0:
            return ProviderResult(
                provider_name=self.name,
                ioc_value=ctx.ioc_value,
                ioc_type=ctx.ioc_type,
                status=ProviderStatus.NOT_FOUND,
                classification="unknown",
                reputation_score=0.0,
                raw_data=data,
            )

        top = results[0]
        page = top.get("page", {})
        task = top.get("task", {})
        stats = top.get("stats", {})

        page_ip = page.get("ip")
        page_domain = page.get("domain")
        page_url = page.get("url")
        server = page.get("server")
        asn = str(page.get("asn")) if page.get("asn") else None
        asnname = page.get("asnname")
        country = page.get("country")
        ptr = page.get("ptr")
        title = page.get("title")
        screenshot = top.get("screenshot")

        # Determine verdict
        verdicts = top.get("verdicts", {})
        overall_score = verdicts.get("overall", {}).get("score", 0)
        malicious_bool = verdicts.get("overall", {}).get("malicious", False)
        categories = verdicts.get("overall", {}).get("categories", [])

        # For IP investigations, page attributes and page verdicts only belong to target IP if page_ip == target IP
        if ctx.ioc_type in (IOCType.IPV4, IOCType.IPV6):
            if page_ip and page_ip != ctx.ioc_value:
                asn = None
                asnname = None
                country = None
                ptr = None
                overall_score = 0
                malicious_bool = False
                categories = []

        if malicious_bool or overall_score >= 50 or "malicious" in categories or "phishing" in categories:
            classification = "malicious"
        elif overall_score > 0 or "suspicious" in categories:
            classification = "suspicious"
        elif verdicts.get("overall", {}).get("hasVerdicts") is False or (overall_score == 0 and not categories):
            classification = "unknown"
        else:
            classification = "benign"

        infra = InfrastructureData(
            asn=asn,
            asn_name=asnname,
            country=country,
            ptr=ptr,
            http_server=server,
            http_title=title,
            screenshot_url=screenshot,
            extra={
                "total_scans": total,
                "scan_time": task.get("time"),
                "scan_uuid": task.get("uuid"),
            },
        )

        discovered: List[DiscoveredIOC] = []

        if page_ip and page_ip != ctx.ioc_value:
            ip_type = IOCType.IPV6 if ":" in page_ip else IOCType.IPV4
            discovered.append(
                DiscoveredIOC(
                    raw_value=page_ip,
                    canonical_value=page_ip,
                    ioc_type=ip_type,
                    relationship_type="resolves_to",
                    confidence=85.0,
                    evidence_desc="urlscan observed page host IP",
                )
            )

        if page_domain and page_domain != ctx.ioc_value:
            discovered.append(
                DiscoveredIOC(
                    raw_value=page_domain,
                    canonical_value=page_domain.lower().rstrip("."),
                    ioc_type=IOCType.DOMAIN,
                    relationship_type="associated_domain",
                    confidence=85.0,
                    evidence_desc="urlscan observed page domain",
                )
            )

        if page_url and page_url != ctx.ioc_value:
            discovered.append(
                DiscoveredIOC(
                    raw_value=page_url,
                    canonical_value=page_url,
                    ioc_type=IOCType.URL,
                    relationship_type="observed_with",
                    confidence=80.0,
                    evidence_desc="urlscan recorded landing page URL",
                )
            )

        evidences = [
            ProviderEvidence(
                provider_name=self.name,
                evidence_type="browser_scan",
                description=f"urlscan indexed {total} scans. Server: {server or 'N/A'}, Title: '{title or 'N/A'}' (Malicious score: {overall_score}).",
                confidence=float(overall_score if overall_score > 0 else 60.0),
            )
        ]

        return ProviderResult(
            provider_name=self.name,
            ioc_value=ctx.ioc_value,
            ioc_type=ctx.ioc_type,
            status=ProviderStatus.SUCCESS,
            reputation_score=float(overall_score),
            classification=classification,
            malicious_count=1 if classification == "malicious" else 0,
            suspicious_count=1 if classification == "suspicious" else 0,
            harmless_count=1 if classification == "benign" else 0,
            tags=verdicts.get("overall", {}).get("tags", []),
            infrastructure=infra,
            discovered_iocs=discovered,
            evidences=evidences,
            raw_data=data,
        )

    async def _execute_mock(self, ctx: ProviderRequestContext) -> ProviderResult:
        mock_data = {
            "total": 5,
            "results": [
                {
                    "verdicts": {
                        "overall": {
                            "score": 75,
                            "malicious": True,
                            "tags": ["phishing", "credential-theft"],
                        }
                    },
                    "task": {
                        "uuid": "018e472a-c215-7798-8b92-95889b7b9f56",
                        "time": "2026-02-17T15:22:11.192Z",
                        "url": "https://secure-login.threat-portal.com/auth",
                    },
                    "page": {
                        "url": "https://secure-login.threat-portal.com/auth",
                        "domain": "secure-login.threat-portal.com",
                        "ip": "198.51.100.88",
                        "asn": 16509,
                        "asnname": "AMAZON-02",
                        "country": "US",
                        "server": "cloudflare",
                        "ptr": "ec2-198-51-100-88.compute-1.amazonaws.com",
                        "title": "Microsoft 365 Account Login",
                    },
                    "screenshot": "https://urlscan.io/screenshots/018e472a-c215-7798-8b92-95889b7b9f56.png",
                }
            ],
        }
        return self._parse_response(ctx, mock_data)
