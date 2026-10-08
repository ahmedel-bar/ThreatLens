"""
Web-Check provider for ThreatLens.

Integrates the self-hosted Lissy93/web-check service as a Web Intelligence
provider for Domain and URL investigations.  It fans out to all relevant
web-check API endpoints concurrently, normalises results into the ThreatLens
InfrastructureData / ProviderResult schema, and extracts Layer-3 IOCs
(resolved IPs, subdomains, redirect destinations, external linked pages).

Only Domain and URL IOC types are supported.  No authentication is required
for the core checks; optional enrichment keys are passed through to the
web-check container via its own environment variables.
"""

from __future__ import annotations

import asyncio
import logging
import re
import urllib.parse
from typing import Any, Dict, List, Optional, Set, Tuple

import httpx

from app.providers.base import BaseProvider, ProviderRequestContext
from app.schemas.ioc import IOCType, ProviderStatus
from app.schemas.provider import (
    CertInfo,
    DnsInfo,
    DnsRecordItem,
    DiscoveredIOC,
    GeoInfo,
    HttpInfo,
    InfrastructureData,
    NetworkInfo,
    ProviderCapability,
    ProviderEvidence,
    ProviderResult,
    ServiceInfo,
    TemporalInfo,
    TlsInfo,
    WhoisInfo,
    SecurityHeaderInfo,
    SecurityHeadersAnalysis,
)
from app.config import settings
from app.services.ioc import normalize_ioc

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_WEBCHECK_ENDPOINTS = [
    "get-ip",
    "dns",
    "dnssec",
    "ssl",
    "tls-connection",
    "headers",
    "http-security",
    "hsts",
    "cookies",
    "redirects",
    "status",
    "firewall",
    "robots-txt",
    "sitemap",
    "linked-pages",
    "trackers",
    "tech-stack",
    "location",
    "whois",
    "social-tags",
    "mail-config",
    "security-txt",
    "dns-server",
    "txt-records",
    "block-lists",
    "subdomains",
    "threats",
    "trace-route",
    "ports",
    "archives",
    "breaches",
    "rank",
    "carbon",
    "quality",
    "screenshot",
    "tls-labs",
    "social-presence",
]

# Per-endpoint timeout in seconds (some checks are slow: Puppeteer, traceroute)
_ENDPOINT_TIMEOUT = 45.0
# Overall provider timeout (we run all endpoints concurrently so this is the wall-clock max)
_PROVIDER_TIMEOUT = 60.0

_IP_PATTERN = re.compile(
    r"^((25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(25[0-5]|2[0-4]\d|[01]?\d\d?)$"
)
_DOMAIN_PATTERN = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
)


def _is_ip(value: str) -> bool:
    return bool(_IP_PATTERN.match(value.strip()))


def _is_public_domain(value: str) -> bool:
    return bool(_DOMAIN_PATTERN.match(value.strip()))


def _safe_str(v: Any) -> Optional[str]:
    if v is None:
        return None
    s = str(v).strip()
    return s if s else None


def _safe_list_str(lst: Any) -> List[str]:
    if not isinstance(lst, list):
        return []
    return [str(x).strip() for x in lst if x is not None and str(x).strip()]


def _extract_hostname(url_or_domain: str) -> str:
    """Return just the hostname from a URL or a bare domain."""
    if "://" in url_or_domain:
        parsed = urllib.parse.urlparse(url_or_domain)
        return parsed.hostname or url_or_domain
    return url_or_domain.split("/")[0]


# ---------------------------------------------------------------------------
# Supported Security Headers Specification & Normalization
# ---------------------------------------------------------------------------

SUPPORTED_SECURITY_HEADERS_SPEC = [
    {
        "id": "hsts",
        "name": "Strict-Transport-Security",
        "display_name": "HSTS",
        "header_names": ["strict-transport-security"],
        "webcheck_keys": ["strictTransportPolicy", "strict-transport-security", "hsts"],
    },
    {
        "id": "csp",
        "name": "Content-Security-Policy",
        "display_name": "CSP",
        "header_names": ["content-security-policy"],
        "webcheck_keys": ["contentSecurityPolicy", "content-security-policy", "csp"],
    },
    {
        "id": "x_frame",
        "name": "X-Frame-Options",
        "display_name": "X-Frame",
        "header_names": ["x-frame-options"],
        "webcheck_keys": ["xFrameOptions", "x-frame-options"],
    },
    {
        "id": "x_content_type",
        "name": "X-Content-Type-Options",
        "display_name": "X-Content-Type",
        "header_names": ["x-content-type-options"],
        "webcheck_keys": ["xContentTypeOptions", "x-content-type-options"],
    },
    {
        "id": "x_xss",
        "name": "X-XSS-Protection",
        "display_name": "X-XSS",
        "header_names": ["x-xss-protection"],
        "webcheck_keys": ["xXSSProtection", "x-xss-protection"],
    },
    {
        "id": "referrer_policy",
        "name": "Referrer-Policy",
        "display_name": "Referrer",
        "header_names": ["referrer-policy"],
        "webcheck_keys": ["referrerPolicy", "referrer-policy"],
    },
    {
        "id": "permissions_policy",
        "name": "Permissions-Policy",
        "display_name": "Permissions",
        "header_names": ["permissions-policy", "feature-policy"],
        "webcheck_keys": ["permissionsPolicy", "permissions-policy", "featurePolicy"],
    },
    {
        "id": "coop",
        "name": "Cross-Origin-Opener-Policy",
        "display_name": "COOP",
        "header_names": ["cross-origin-opener-policy"],
        "webcheck_keys": ["crossOriginOpenerPolicy", "cross-origin-opener-policy", "coop"],
    },
    {
        "id": "corp",
        "name": "Cross-Origin-Resource-Policy",
        "display_name": "CORP",
        "header_names": ["cross-origin-resource-policy"],
        "webcheck_keys": ["crossOriginResourcePolicy", "cross-origin-resource-policy", "corp"],
    },
    {
        "id": "coep",
        "name": "Cross-Origin-Embedder-Policy",
        "display_name": "COEP",
        "header_names": ["cross-origin-embedder-policy"],
        "webcheck_keys": ["crossOriginEmbedderPolicy", "cross-origin-embedder-policy", "coep"],
    },
]


def normalize_security_headers(
    results: Dict[str, Any],
    sources: Optional[List[str]] = None,
) -> SecurityHeadersAnalysis:
    """
    Normalizes HTTP security headers into an explicit semantic state model.
    States: PRESENT, MISSING, NOT_CHECKED, UNAVAILABLE, REQUEST_FAILED.
    """
    prov_sources = sources or ["webcheck"]
    headers_data = results.get("headers")
    http_security_data = results.get("http-security")
    status_data = results.get("status")

    # If results itself contains header keys directly (e.g. passed a raw header dict in tests or mocks)
    direct_headers: Dict[str, str] = {}
    for k, v in results.items():
        if k and v is not None and isinstance(v, (str, int, float, bool)):
            k_low = str(k).lower().strip()
            if any(k_low in spec["header_names"] for spec in SUPPORTED_SECURITY_HEADERS_SPEC):
                direct_headers[k_low] = str(v).strip()

    # Determine failure / check states
    headers_failed = (
        isinstance(headers_data, dict) and bool(headers_data.get("error"))
    ) or (headers_data is None and "headers" in results)

    http_sec_failed = (
        isinstance(http_security_data, dict) and bool(http_security_data.get("error"))
    ) or (http_security_data is None and "http-security" in results)

    headers_not_queried = ("headers" not in results) and not direct_headers
    http_sec_not_queried = ("http-security" not in results) and not direct_headers

    lower_headers: Dict[str, str] = dict(direct_headers)
    if isinstance(headers_data, dict) and not headers_data.get("error"):
        for k, v in headers_data.items():
            if k and v is not None:
                lower_headers[str(k).lower().strip()] = str(v).strip()

    if not lower_headers and isinstance(results.get("raw_headers"), dict):
        for k, v in results["raw_headers"].items():
            if k and v is not None:
                lower_headers[str(k).lower().strip()] = str(v).strip()

    sec_dict: Dict[str, Any] = {}
    if isinstance(http_security_data, dict) and not http_security_data.get("error"):
        sec_dict = http_security_data

    # An HTTP response was inspected if we observed response headers, or status endpoint returned code, or http-security was evaluated
    response_inspected = (
        bool(lower_headers)
        or bool(sec_dict)
        or ("http-security" in results and isinstance(http_security_data, dict) and not http_sec_failed)
        or (isinstance(status_data, dict) and bool(status_data.get("status") or status_data.get("statusCode") or status_data.get("isUp")))
    )

    header_infos: List[SecurityHeaderInfo] = []

    for spec in SUPPORTED_SECURITY_HEADERS_SPEC:
        h_name = spec["name"]
        d_name = spec["display_name"]
        state: str = "NOT_CHECKED"
        val: Optional[str] = None
        evidence: Optional[str] = None

        # Check 1: Direct observation in HTTP response headers
        for raw_k in spec["header_names"]:
            if raw_k in lower_headers:
                val = lower_headers[raw_k]
                state = "PRESENT"
                evidence = f"Observed in HTTP response: {h_name}: {val}"
                break

        # Check 2: web-check http-security analysis data if not in lower_headers
        if state != "PRESENT" and sec_dict:
            for wk in spec["webcheck_keys"]:
                if wk in sec_dict:
                    wk_val = sec_dict[wk]
                    if isinstance(wk_val, dict):
                        is_present = wk_val.get("present") or wk_val.get("active") or wk_val.get("isFound")
                        if is_present:
                            state = "PRESENT"
                            val = str(wk_val.get("value") or wk_val.get("header") or wk_val.get("raw") or "configured")
                            evidence = f"Web-Check security check confirmed active: {val}"
                        elif is_present is False or wk_val.get("present") is False or wk_val.get("active") is False:
                            state = "MISSING"
                            evidence = "Web-Check security check: header absent"
                    elif isinstance(wk_val, bool):
                        if wk_val is True:
                            state = "PRESENT"
                            val = "configured"
                            evidence = "Web-Check security check: active"
                        else:
                            state = "MISSING"
                            evidence = "Web-Check security check: absent"
                    elif isinstance(wk_val, str) and wk_val.strip():
                        state = "PRESENT"
                        val = wk_val.strip()
                        evidence = f"Web-Check security header: {val}"
                    break

        # Check 3: Check failure, not checked, unavailable, or missing from inspected response
        if state not in ("PRESENT", "MISSING"):
            if results.get(spec["id"]) == "UNAVAILABLE" or results.get(spec["name"]) == "UNAVAILABLE":
                state = "UNAVAILABLE"
                evidence = "Provider does not support evaluation of this header"
            elif (headers_failed or http_sec_failed) and not response_inspected:
                state = "REQUEST_FAILED"
                evidence = "HTTP request/endpoint check failed"
            elif response_inspected:
                state = "MISSING"
                evidence = "HTTP response inspected; header absent"
            elif headers_not_queried and http_sec_not_queried:
                state = "NOT_CHECKED"
                evidence = "Check not executed"
            else:
                state = "UNAVAILABLE"
                evidence = "Provider does not support evaluation for this target"

        header_infos.append(
            SecurityHeaderInfo(
                name=h_name,
                display_name=d_name,
                key=spec["header_names"][0] if spec.get("header_names") else spec["id"],
                id=spec["id"],
                state=state,
                value=val,
                evidence=evidence,
                sources=prov_sources,
            )
        )

    active_cnt = sum(1 for h in header_infos if h.state == "PRESENT")
    missing_cnt = sum(1 for h in header_infos if h.state == "MISSING")
    eval_cnt = sum(1 for h in header_infos if h.state in ("PRESENT", "MISSING"))
    not_checked_cnt = sum(1 for h in header_infos if h.state == "NOT_CHECKED")
    unavail_cnt = sum(1 for h in header_infos if h.state == "UNAVAILABLE")
    failed_cnt = sum(1 for h in header_infos if h.state == "REQUEST_FAILED")

    if failed_cnt > 0 and eval_cnt == 0:
        summary_str = f"{active_cnt} / {len(header_infos)} Active ({failed_cnt} Request Failed)"
    elif not_checked_cnt > 0 or unavail_cnt > 0:
        summary_str = f"{active_cnt} / {eval_cnt or len(header_infos)} Active"
    else:
        summary_str = f"{active_cnt} / {len(header_infos)} Active"

    return SecurityHeadersAnalysis(
        headers=header_infos,
        active_count=active_cnt,
        evaluated_count=eval_cnt or (len(header_infos) if failed_cnt == 0 else 0),
        total_supported=len(header_infos),
        missing_count=missing_cnt,
        not_checked_count=not_checked_cnt,
        unavailable_count=unavail_cnt,
        request_failed_count=failed_cnt,
        summary=summary_str,
        sources=prov_sources,
    )


# ---------------------------------------------------------------------------
# Provider class
# ---------------------------------------------------------------------------


class WebCheckProvider(BaseProvider):
    """Self-hosted Lissy93/web-check Web Intelligence provider."""

    # ------------------------------------------------------------------
    # BaseProvider interface
    # ------------------------------------------------------------------

    @property
    def name(self) -> str:
        return "webcheck"

    @property
    def display_name(self) -> str:
        return "Web-Check"

    def get_capabilities(self) -> ProviderCapability:
        return ProviderCapability(
            name=self.name,
            display_name=self.display_name,
            description=(
                "Self-hosted web intelligence provider (Lissy93/web-check). "
                "Performs DNS, SSL/TLS, HTTP, WAF, mail-config, WHOIS, subdomains, "
                "trackers, tech-stack, redirect chain, security headers, and more."
            ),
            supported_iocs=[IOCType.DOMAIN, IOCType.URL, IOCType.IPV4, IOCType.IPV6],
            requires_auth=False,
            free_tier=True,
            rate_limit_desc="Self-hosted; no external rate limit",
            provides_reputation=False,
            provides_infrastructure=True,
            provides_relationships=True,
            doc_url="https://github.com/Lissy93/web-check",
        )

    # ------------------------------------------------------------------
    # Live execution
    # ------------------------------------------------------------------

    async def _execute_live(self, ctx: ProviderRequestContext) -> ProviderResult:
        base_url = (getattr(settings, "WEBCHECK_URL", None) or "http://web-check:3000").rstrip("/")

        # Determine the target URL to send to web-check
        if ctx.ioc_type == IOCType.URL:
            target_url = ctx.ioc_value
        else:
            # Domain — web-check normalises bare domains internally
            target_url = ctx.ioc_value

        # Fan out to all endpoints concurrently
        async with httpx.AsyncClient(timeout=_ENDPOINT_TIMEOUT) as client:
            tasks = {
                ep: _fetch_endpoint(client, base_url, ep, target_url)
                for ep in _WEBCHECK_ENDPOINTS
            }
            results: Dict[str, Any] = {}
            try:
                gathered = await asyncio.wait_for(
                    asyncio.gather(*tasks.values(), return_exceptions=True),
                    timeout=_PROVIDER_TIMEOUT,
                )
                for ep, result in zip(tasks.keys(), gathered):
                    if isinstance(result, Exception):
                        logger.debug("web-check endpoint %s failed: %s", ep, result)
                        results[ep] = None
                    else:
                        results[ep] = result
            except asyncio.TimeoutError:
                logger.warning("web-check overall timeout for %s", target_url)
                # Use whatever partial results we have
                results = {ep: None for ep in tasks}

        # Parse results
        infrastructure, discovered_iocs, evidences = _parse_results(
            results, ctx.ioc_value, ctx.ioc_type
        )

        # Build extra dict with all raw web-check data
        extra: Dict[str, Any] = {"webcheck": {ep: results.get(ep) for ep in _WEBCHECK_ENDPOINTS}}

        if infrastructure.extra is None:
            infrastructure.extra = {}
        infrastructure.extra.update(extra)

        # Determine status
        success_count = sum(1 for v in results.values() if v is not None)
        if success_count == 0:
            status = ProviderStatus.NOT_FOUND
            error_details: Optional[str] = "All web-check endpoints returned no data."
        else:
            status = ProviderStatus.SUCCESS
            error_details = None

        return ProviderResult(
            provider_name=self.name,
            ioc_value=ctx.ioc_value,
            ioc_type=ctx.ioc_type,
            status=status,
            error_details=error_details,
            reputation_score=None,
            classification=None,
            malicious_count=0,
            suspicious_count=0,
            harmless_count=0,
            tags=[],
            threat_actors=[],
            malware_families=[],
            infrastructure=infrastructure,
            discovered_iocs=discovered_iocs,
            evidences=evidences,
            raw_data={"endpoints_fetched": success_count, "endpoints_total": len(_WEBCHECK_ENDPOINTS)},
        )

    # ------------------------------------------------------------------
    # Mock execution
    # ------------------------------------------------------------------

    async def _execute_mock(self, ctx: ProviderRequestContext) -> ProviderResult:
        is_ip_ioc = ctx.ioc_type in (IOCType.IPV4, IOCType.IPV6)
        target_ip = ctx.ioc_value if is_ip_ioc else "1.2.3.4"
        domain = f"host-{target_ip.replace('.', '-').replace(':', '-')}.example.com" if is_ip_ioc else _extract_hostname(ctx.ioc_value)

        infra = InfrastructureData(
            http=HttpInfo(
                server="nginx",
                title=f"Mock title for {ctx.ioc_value}",
                status_code=200,
                headers={"content-type": "text/html", "x-frame-options": "SAMEORIGIN"},
                technologies=["Nginx", "WordPress"],
                sources=["webcheck"],
            ),
            dns=DnsInfo(
                hostnames=[] if is_ip_ioc else [domain],
                domains=[] if is_ip_ioc else [domain],
                records=[
                    DnsRecordItem(record_type="PTR", value=f"ptr.{domain}", sources=["webcheck"]),
                ] if is_ip_ioc else [
                    DnsRecordItem(record_type="A", value="1.2.3.4", sources=["webcheck"]),
                    DnsRecordItem(record_type="MX", value=f"mail.{domain}", sources=["webcheck"]),
                ],
                sources=["webcheck"],
            ),
            whois=WhoisInfo(
                registrar="ARIN" if is_ip_ioc else "Mock Registrar Inc.",
                creation_date="2020-01-01",
                expiration_date="2030-01-01",
                nameservers=[] if is_ip_ioc else [f"ns1.{domain}", f"ns2.{domain}"],
                status=["active"] if is_ip_ioc else ["clientTransferProhibited"],
                registrant_org="Cloudflare, Inc." if is_ip_ioc else None,
                registrant_country="US",
                sources=["webcheck"],
            ),
            open_ports=[80, 443, 8080],
            network=NetworkInfo(
                ip=target_ip,
                ip_version="IPv6" if (is_ip_ioc and ":" in target_ip) else "IPv4",
                asn="AS13335",
                org="Cloudflare, Inc.",
                isp="Cloudflare",
                sources=["webcheck"],
            ),
            geo=GeoInfo(
                country="United States",
                country_code="US",
                city="San Francisco",
                region="California",
                latitude=37.7749,
                longitude=-122.4194,
                timezone="America/Los_Angeles",
                sources=["webcheck"],
            ),
            services_detail=[
                ServiceInfo(port=80, transport="tcp", service_name="http", sources=["webcheck"]),
                ServiceInfo(port=443, transport="tcp", service_name="https", sources=["webcheck"]),
                ServiceInfo(port=8080, transport="tcp", service_name="http-proxy", sources=["webcheck"]),
            ],
            temporal=TemporalInfo(
                first_seen="2018-05-12T10:00:00Z",
                last_seen="2026-03-01T15:30:00Z",
                sources=["webcheck"],
            ),
            extra={
                "webcheck": {
                    "firewall": {"hasWaf": True, "waf": "Cloudflare"},
                    "ports": {"openPorts": [80, 443, 8080], "failedPorts": [22, 25, 3306]},
                    "archives": {
                        "firstScan": "2018-05-12T10:00:00Z",
                        "lastScan": "2026-03-01T15:30:00Z",
                        "totalScans": 342,
                        "changeCount": 48,
                        "averagePageSize": 45120,
                    },
                    "rank": {"ranks": [{"rank": 1420, "date": "2026-03-01"}]},
                    "carbon": {"cleanerThan": 78, "green": True, "co2": 0.18},
                    "dnssec": {"isDnssec": True} if not is_ip_ioc else None,
                    "cookies": [{"name": "__cf_bm", "secure": True, "httpOnly": True, "sameSite": "None"}],
                    "security-txt": {"isFound": True, "content": "Contact: mailto:security@example.com\nExpires: 2027-12-31"},
                    "robots-txt": {"robots": "User-agent: *\nDisallow: /admin\nSitemap: https://example.com/sitemap.xml"},
                    "trace-route": {"hops": [{"hop": 1, "ip": "1.1.1.1", "rtt": "4.2ms"}, {"hop": 2, "ip": target_ip, "rtt": "12.8ms"}]},
                    "http-security": {
                        "strictTransportPolicy": True,
                        "contentSecurityPolicy": True,
                        "xFrameOptions": True,
                        "xContentTypeOptions": True,
                    },
                    "mail-config": {
                        "spf": {"record": f"v=spf1 include:_spf.{domain} ~all", "valid": True},
                        "dmarc": {"record": f"v=DMARC1; p=reject; rua=mailto:dmarc@{domain}", "policy": "reject"},
                    } if not is_ip_ioc else {},
                    "status": {"isUp": True, "responseCode": 200, "responseTime": 124},
                    "location": {
                        "ip": target_ip,
                        "city": "San Francisco",
                        "region": "California",
                        "country": "United States",
                        "countryCode": "US",
                        "lat": 37.7749,
                        "lon": -122.4194,
                        "timezone": "America/Los_Angeles",
                        "isp": "Cloudflare",
                        "org": "Cloudflare, Inc.",
                        "asn": "AS13335",
                    },
                    "tech-stack": {
                        "technologies": [
                            {"name": "Nginx", "version": "1.20.1", "categories": [{"name": "Web Servers"}]},
                            {"name": "WordPress", "version": "6.4", "categories": [{"name": "CMS"}]},
                        ]
                    },
                    "subdomains": {
                        "subdomains": [f"api.{domain}", f"cdn.{domain}", f"mail.{domain}"],
                    } if not is_ip_ioc else {"subdomains": []},
                    "redirects": {
                        "redirects": [ctx.ioc_value, f"https://{domain}/login", f"https://{domain}/dashboard"] if ctx.ioc_type == IOCType.URL else []
                    },
                    "linked-pages": {
                        "internal": [f"https://{domain}/about", f"https://{domain}/contact"],
                        "external": ["https://github.com/example", "https://twitter.com/example"],
                    },
                    "trackers": {
                        "trackers": [{"name": "Google Analytics", "category": "Analytics"}]
                    },
                    "social-presence": {
                        "twitter": {"isFound": True, "url": f"https://twitter.com/{domain.split('.')[0]}"},
                        "github": {"isFound": True, "url": f"https://github.com/{domain.split('.')[0]}"},
                    },
                    "social-tags": {
                        "title": f"Portal - {domain}",
                        "description": "Enterprise Security Dashboard",
                        "ogTitle": f"Portal - {domain}",
                    },
                    "ssl": {
                        "subject": {"CN": domain, "O": "Example Corp"},
                        "issuer": {"CN": "Let's Encrypt Authority X3", "O": "Let's Encrypt"},
                        "fingerprint256": "4b6f634bc3d6741b058a59beea7c92b23f8b051ef4943fcf3e61c56ab83e843e",
                        "valid_from": "2024-01-01",
                        "valid_to": "2025-01-01",
                        "subjectaltname": f"DNS:{domain}, DNS:www.{domain}",
                    },
                    "tls-connection": {
                        "protocol": "TLSv1.3",
                        "cipher": {"name": "TLS_AES_256_GCM_SHA384"},
                    },
                    "tls-labs": {
                        "grade": "A+",
                        "hasWarnings": False,
                    },
                    "breaches": {
                        "domain": domain,
                        "breaches": [
                            {
                                "name": "Adobe",
                                "title": "Adobe Data Breach",
                                "domain": domain,
                                "date": "2013-10-04",
                                "accounts": 152445165,
                                "exposed": ["Email addresses", "Passwords", "Usernames"],
                                "description": "In October 2013, Adobe was breached...",
                                "verified": True,
                            }
                        ] if not is_ip_ioc else [],
                    },
                }
            },
        )
        infra.security_headers = normalize_security_headers(infra.extra.get("webcheck") or {}, sources=["webcheck"])
        if is_ip_ioc:
            discovered = [
                DiscoveredIOC(
                    raw_value=f"ptr.{domain}",
                    canonical_value=f"ptr.{domain}",
                    ioc_type=IOCType.DOMAIN,
                    relationship_type="reverse_dns",
                    confidence=0.85,
                    evidence_desc=f"web-check resolved PTR for {target_ip}",
                )
            ]
        else:
            mock_ip = "1.2.3.4"
            discovered = [
                DiscoveredIOC(
                    raw_value=mock_ip,
                    canonical_value=mock_ip,
                    ioc_type=IOCType.IPV4,
                    relationship_type="resolves_to",
                    confidence=0.9,
                    evidence_desc=f"web-check resolved {domain} to {mock_ip}",
                )
            ]
        return ProviderResult(
            provider_name=self.name,
            ioc_value=ctx.ioc_value,
            ioc_type=ctx.ioc_type,
            status=ProviderStatus.SUCCESS,
            infrastructure=infra,
            discovered_iocs=discovered,
            evidences=[],
            tags=[],
            threat_actors=[],
            malware_families=[],
        )


# ---------------------------------------------------------------------------
# Helpers — network fetch
# ---------------------------------------------------------------------------


async def _fetch_endpoint(
    client: httpx.AsyncClient,
    base_url: str,
    endpoint: str,
    target: str,
) -> Optional[Any]:
    """Fetch a single web-check API endpoint.  Returns parsed JSON or None."""
    url = f"{base_url}/api/{endpoint}"
    params = {"url": target}
    try:
        resp = await client.get(url, params=params)
        if resp.status_code == 200:
            try:
                return resp.json()
            except Exception:
                return None
        # 400/404/5xx — endpoint skipped or data unavailable
        return None
    except Exception as exc:
        logger.debug("web-check %s error: %s", endpoint, exc)
        return None


# ---------------------------------------------------------------------------
# Helpers — result parsing
# ---------------------------------------------------------------------------


def _parse_results(
    results: Dict[str, Any],
    ioc_value: str,
    ioc_type: IOCType,
) -> Tuple[InfrastructureData, List[DiscoveredIOC], List[ProviderEvidence]]:
    """Parse all endpoint results into ThreatLens schema objects."""

    hostname = _extract_hostname(ioc_value)
    discovered_iocs: List[DiscoveredIOC] = []
    evidences: List[ProviderEvidence] = []
    seen_iocs: Set[str] = set()

    def _add_ioc(raw: str, ioc_t: IOCType, rel: str, conf: float, desc: str):
        key = f"{ioc_t.value}:{raw}"
        if key in seen_iocs:
            return
        seen_iocs.add(key)
        try:
            norm = normalize_ioc(raw)
            canonical = norm.canonical_value if norm and norm.is_valid else raw
        except Exception:
            canonical = raw
        discovered_iocs.append(
            DiscoveredIOC(
                raw_value=raw,
                canonical_value=canonical,
                ioc_type=ioc_t,
                relationship_type=rel,
                confidence=conf,
                evidence_desc=desc,
            )
        )

    # ---- get-ip ------------------------------------------------------------
    get_ip_data = results.get("get-ip") or {}
    resolved_ip: Optional[str] = None
    if isinstance(get_ip_data, dict):
        resolved_ip = _safe_str(get_ip_data.get("ip"))
        if resolved_ip and _is_ip(resolved_ip):
            ip_type = IOCType.IPV6 if ":" in resolved_ip else IOCType.IPV4
            _add_ioc(resolved_ip, ip_type, "resolves_to", 0.95,
                     f"web-check: {hostname} resolves to {resolved_ip}")

    is_ip_ioc = ioc_type in (IOCType.IPV4, IOCType.IPV6)
    target_ip = resolved_ip or (ioc_value if is_ip_ioc else None)
    dns_data = results.get("dns") or {}
    dns_records: List[DnsRecordItem] = []
    dns_hostnames: List[str] = [] if is_ip_ioc else [hostname]
    dns_domains: List[str] = [] if is_ip_ioc else [hostname]
    if isinstance(dns_data, dict):
        for rtype in ("A", "AAAA", "MX", "TXT", "NS", "CNAME", "SOA", "SRV", "PTR"):
            vals = dns_data.get(rtype, [])
            if not isinstance(vals, list):
                vals = [vals] if vals else []
            for v in vals:
                if not v:
                    continue
                val_str = str(v).strip()
                dns_records.append(DnsRecordItem(record_type=rtype, value=val_str, sources=["webcheck"]))
                if rtype in ("A", "AAAA") and _is_ip(val_str):
                    ip_type = IOCType.IPV6 if ":" in val_str else IOCType.IPV4
                    _add_ioc(val_str, ip_type, "resolves_to", 0.9,
                             f"web-check DNS {rtype} record: {hostname} → {val_str}")
                elif rtype == "NS" and _is_public_domain(val_str):
                    _add_ioc(val_str, IOCType.DOMAIN, "uses_nameserver", 0.7,
                             f"web-check DNS NS: {hostname} uses nameserver {val_str}")
                elif rtype == "MX":
                    # MX entries often include priority prefix e.g. "10 mail.example.com"
                    parts = val_str.split()
                    mx_host = parts[-1].rstrip(".") if parts else val_str.rstrip(".")
                    if _is_public_domain(mx_host):
                        _add_ioc(mx_host, IOCType.DOMAIN, "mail_exchange", 0.7,
                                 f"web-check DNS MX: {hostname} → {mx_host}")
                elif rtype == "PTR":
                    ptr_host = val_str.rstrip(".")
                    if _is_public_domain(ptr_host):
                        if ptr_host not in dns_hostnames:
                            dns_hostnames.append(ptr_host)
                        _add_ioc(ptr_host, IOCType.DOMAIN, "reverse_dns", 0.85,
                                 f"web-check DNS PTR: {ioc_value} → {ptr_host}")

    # ---- ssl / certificates ------------------------------------------------
    ssl_data = results.get("ssl") or {}
    certs_detail: List[CertInfo] = []
    if isinstance(ssl_data, dict) and ssl_data:
        raw_fp = _safe_str(ssl_data.get("fingerprint256") or ssl_data.get("fingerprint") or ssl_data.get("fingerprint_sha256"))
        clean_fp = raw_fp.replace(":", "").strip().lower() if raw_fp else None

        subj_raw = ssl_data.get("subject") or {}
        subj_cn = _safe_str(subj_raw.get("CN") if isinstance(subj_raw, dict) else subj_raw)
        subj_org = _safe_str(subj_raw.get("O") if isinstance(subj_raw, dict) else None)

        iss_raw = ssl_data.get("issuer") or {}
        iss_cn = _safe_str(iss_raw.get("CN") if isinstance(iss_raw, dict) else iss_raw)
        iss_org = _safe_str(iss_raw.get("O") if isinstance(iss_raw, dict) else None)

        serial = _safe_str(ssl_data.get("serialNumber") or ssl_data.get("serial_number"))

        sans: List[str] = []
        san_raw = ssl_data.get("subjectaltname") or ssl_data.get("sans") or []
        if isinstance(san_raw, str):
            for part in san_raw.split(","):
                part_clean = part.strip()
                if part_clean.startswith("DNS:"):
                    part_clean = part_clean[4:].strip()
                elif part_clean.startswith("IP Address:"):
                    part_clean = part_clean[11:].strip()
                if part_clean and part_clean not in sans:
                    sans.append(part_clean)
        elif isinstance(san_raw, list):
            for part in san_raw:
                p_str = str(part).strip()
                if p_str.startswith("DNS:"):
                    p_str = p_str[4:].strip()
                if p_str and p_str not in sans:
                    sans.append(p_str)

        cert = CertInfo(
            fingerprint_sha256=clean_fp,
            subject_cn=subj_cn,
            subject_org=subj_org,
            issuer_cn=iss_cn,
            issuer_org=iss_org,
            valid_from=_safe_str(ssl_data.get("valid_from")),
            valid_to=_safe_str(ssl_data.get("valid_to")),
            serial_number=serial,
            sans=sans,
            tls_versions=[],
            ciphers=[],
            sources=["webcheck"],
        )
        certs_detail.append(cert)

        # Extract SAN domains as Layer 3 IOCs
        for san_name in sans:
            if san_name and san_name != hostname and _is_public_domain(san_name):
                _add_ioc(san_name, IOCType.DOMAIN, "shares_certificate", 0.8,
                         f"web-check SSL certificate SAN: {san_name}")

    # ---- tls-connection ----------------------------------------------------
    tls_data = results.get("tls-connection") or {}
    tls_info: Optional[TlsInfo] = None
    if isinstance(tls_data, dict):
        protocol = _safe_str(tls_data.get("protocol"))
        cipher_obj = tls_data.get("cipher") or {}
        cipher_name = _safe_str(cipher_obj.get("name") if isinstance(cipher_obj, dict) else cipher_obj)
        tls_info = TlsInfo(
            supported_versions=[protocol] if protocol else [],
            ciphers=[cipher_name] if cipher_name else [],
            sources=["webcheck"],
        )

    # ---- headers -----------------------------------------------------------
    headers_data = results.get("headers") or {}
    raw_headers: Dict[str, str] = {}
    if isinstance(headers_data, dict):
        raw_headers = {k: str(v) for k, v in headers_data.items() if k and v is not None}

    # ---- status ------------------------------------------------------------
    status_data = results.get("status") or {}
    http_status_code: Optional[int] = None
    if isinstance(status_data, dict):
        http_status_code = status_data.get("status") or status_data.get("statusCode")

    # ---- http-security -----------------------------------------------------
    http_security_data = results.get("http-security") or {}
    # Stored in extra["webcheck"]["http-security"]

    # ---- firewall ----------------------------------------------------------
    firewall_data = results.get("firewall") or {}
    waf: Optional[str] = None
    if isinstance(firewall_data, dict):
        waf = _safe_str(firewall_data.get("waf"))

    # ---- tech-stack --------------------------------------------------------
    tech_stack_data = results.get("tech-stack") or {}
    technologies: List[str] = []
    if isinstance(tech_stack_data, dict):
        techs = tech_stack_data.get("technologies") or []
        if isinstance(techs, list):
            for t in techs:
                if isinstance(t, dict):
                    name = _safe_str(t.get("name"))
                    if name:
                        technologies.append(name)
                elif isinstance(t, str):
                    technologies.append(t)

    # ---- location ----------------------------------------------------------
    location_data = results.get("location") or {}
    location_ip: Optional[str] = None
    if isinstance(location_data, dict):
        location_ip = _safe_str(location_data.get("ip"))
        if location_ip and _is_ip(location_ip):
            ip_type = IOCType.IPV6 if ":" in location_ip else IOCType.IPV4
            _add_ioc(location_ip, ip_type, "resolves_to", 0.85,
                     f"web-check location: {hostname} IP is {location_ip}")

    # ---- whois -------------------------------------------------------------
    whois_data = results.get("whois") or {}
    whois_info: Optional[WhoisInfo] = None
    ns_list: List[str] = []
    if isinstance(whois_data, dict) and whois_data:
        ns_raw = whois_data.get("nameservers") or []
        ns_list = _safe_list_str(ns_raw) if isinstance(ns_raw, list) else ([_safe_str(ns_raw)] if ns_raw else [])
        ns_list = [n.lower().rstrip(".") for n in ns_list if n]
        status_raw = whois_data.get("status") or []
        status_list = _safe_list_str(status_raw) if isinstance(status_raw, list) else ([_safe_str(status_raw)] if status_raw else [])

        reg_url = _safe_str(whois_data.get("registrarUrl") or whois_data.get("registrar_url"))
        whois_srv = _safe_str(whois_data.get("whoisServer") or whois_data.get("whois_server") or whois_data.get("registrar_whois_server"))
        reg_id = _safe_str(whois_data.get("registryDomainId") or whois_data.get("registry_domain_id") or whois_data.get("domainId"))
        dnssec_val = _safe_str(whois_data.get("dnssec") or whois_data.get("DNSSEC"))

        registrant_raw = whois_data.get("registrant") or {}
        reg_org = None
        reg_country = None
        if isinstance(registrant_raw, dict):
            reg_org = _safe_str(registrant_raw.get("organization") or registrant_raw.get("org"))
            reg_country = _safe_str(registrant_raw.get("country"))
        elif isinstance(registrant_raw, str):
            reg_org = registrant_raw

        whois_info = WhoisInfo(
            registrar=_safe_str(whois_data.get("registrar")),
            creation_date=_safe_str(whois_data.get("created")),
            updated_date=_safe_str(whois_data.get("updated")),
            expiration_date=_safe_str(whois_data.get("expires")),
            nameservers=ns_list,
            status=status_list,
            registrant_org=reg_org,
            registrant_country=reg_country,
            registrar_url=reg_url,
            registrar_whois_server=whois_srv,
            registry_domain_id=reg_id,
            dnssec=dnssec_val,
            sources=["webcheck"],
        )
        # Add nameservers as domain IOCs
        for ns in ns_list:
            if _is_public_domain(ns):
                _add_ioc(ns, IOCType.DOMAIN, "uses_nameserver", 0.7,
                         f"web-check WHOIS: {hostname} nameserver {ns}")

    # ---- redirects ---------------------------------------------------------
    redirects_data = results.get("redirects") or {}
    redirect_chain: List[str] = []
    if isinstance(redirects_data, dict):
        chain = redirects_data.get("redirects") or []
        if isinstance(chain, list):
            redirect_chain = [str(u).strip() for u in chain if u]
            for redir_url in redirect_chain:
                if redir_url.startswith("http"):
                    _add_ioc(redir_url, IOCType.URL, "redirects_to", 0.85,
                             f"web-check redirect chain: {ioc_value} → {redir_url}")
                    # Also extract the hostname as a domain pivot
                    redir_host = _extract_hostname(redir_url)
                    if redir_host and redir_host != hostname and _is_public_domain(redir_host):
                        _add_ioc(redir_host, IOCType.DOMAIN, "redirects_to_domain", 0.8,
                                 f"web-check redirect: {hostname} → {redir_host}")

    # ---- linked-pages ------------------------------------------------------
    linked_data = results.get("linked-pages") or {}
    if isinstance(linked_data, dict):
        external_links = linked_data.get("external") or []
        if isinstance(external_links, list):
            for link in external_links:
                link_str = str(link).strip()
                if not link_str.startswith("http"):
                    continue
                link_host = _extract_hostname(link_str)
                if link_host and link_host != hostname and _is_public_domain(link_host):
                    _add_ioc(link_str, IOCType.URL, "links_to", 0.6,
                             f"web-check linked-pages: {hostname} links to {link_str}")

    # ---- subdomains --------------------------------------------------------
    subdomains_data = results.get("subdomains") or {}
    if isinstance(subdomains_data, dict):
        subs = subdomains_data.get("subdomains") or []
        if isinstance(subs, list):
            for sub in subs:
                sub_str = str(sub).strip().lower()
                if sub_str and _is_public_domain(sub_str) and sub_str != hostname:
                    _add_ioc(sub_str, IOCType.DOMAIN, "subdomain", 0.8,
                             f"web-check subdomains: {sub_str} is a subdomain of {hostname}")

    # ---- mail-config -------------------------------------------------------
    mail_data = results.get("mail-config") or {}
    if isinstance(mail_data, dict):
        # MX
        mail_mx = mail_data.get("mx") or []
        if isinstance(mail_mx, list):
            for mx_entry in mail_mx:
                mx_val = None
                if isinstance(mx_entry, dict):
                    mx_val = _safe_str(mx_entry.get("exchange") or mx_entry.get("host"))
                elif isinstance(mx_entry, str):
                    mx_val = mx_entry.strip()
                if mx_val and not any(r.record_type == "MX" and r.value == mx_val for r in dns_records):
                    dns_records.append(DnsRecordItem(record_type="MX", value=mx_val, sources=["webcheck"]))
                    parts = mx_val.split()
                    mx_host = parts[-1].rstrip(".") if parts else mx_val.rstrip(".")
                    if _is_public_domain(mx_host):
                        _add_ioc(mx_host, IOCType.DOMAIN, "mail_exchange", 0.7,
                                 f"web-check mail-config MX: {hostname} → {mx_host}")
        # SPF
        spf_entry = mail_data.get("spf")
        if isinstance(spf_entry, dict) and spf_entry.get("raw"):
            spf_val = str(spf_entry["raw"]).strip()
            if not any(r.record_type == "TXT" and r.value == spf_val for r in dns_records):
                dns_records.append(DnsRecordItem(record_type="TXT", value=spf_val, sources=["webcheck"]))
        # DMARC
        dmarc_entry = mail_data.get("dmarc")
        if isinstance(dmarc_entry, dict) and dmarc_entry.get("record"):
            dmarc_val = str(dmarc_entry["record"]).strip()
            if not any(r.record_type == "TXT" and r.value == dmarc_val for r in dns_records):
                dns_records.append(DnsRecordItem(record_type="TXT", value=dmarc_val, sources=["webcheck"]))

    # ---- threats -----------------------------------------------------------
    threats_data = results.get("threats") or {}
    threat_tags: List[str] = []
    if isinstance(threats_data, dict):
        sb = threats_data.get("safeBrowsing") or {}
        if isinstance(sb, dict) and sb.get("isFound"):
            threat_tags.append("google-safe-browsing-flagged")
            evidences.append(ProviderEvidence(
                provider_name="webcheck",
                evidence_type="threat_intel",
                description=f"Google Safe Browsing flagged {hostname}",
                confidence=80.0,
            ))
        urlhaus = threats_data.get("urlHaus") or {}
        if isinstance(urlhaus, dict) and urlhaus.get("isFound"):
            threat_tags.append("urlhaus-listed")
            evidences.append(ProviderEvidence(
                provider_name="webcheck",
                evidence_type="threat_intel",
                description=f"URLhaus listed {hostname}",
                confidence=85.0,
            ))
        phishtank = threats_data.get("phishTank") or {}
        if isinstance(phishtank, dict) and phishtank.get("isFound"):
            threat_tags.append("phishtank-listed")
            evidences.append(ProviderEvidence(
                provider_name="webcheck",
                evidence_type="threat_intel",
                description=f"PhishTank listed {hostname}",
                confidence=85.0,
            ))

    # ---- block-lists -------------------------------------------------------
    blocklists_data = results.get("block-lists") or {}
    blocked_by: List[str] = []
    if isinstance(blocklists_data, dict):
        bl_items = blocklists_data.get("blocklists") or blocklists_data.get("results") or []
        if isinstance(bl_items, list):
            for bl in bl_items:
                if isinstance(bl, dict) and (bl.get("isBlocked") or bl.get("blocked")):
                    srv = bl.get("server") or bl.get("name") or bl.get("blocklist")
                    if srv:
                        blocked_by.append(str(srv).strip())
                elif isinstance(bl, str):
                    blocked_by.append(bl.strip())
        elif isinstance(blocklists_data.get("blockedBy"), list):
            blocked_by.extend([str(x).strip() for x in blocklists_data["blockedBy"] if x])
    elif isinstance(blocklists_data, list):
        for bl in blocklists_data:
            if isinstance(bl, dict) and (bl.get("isBlocked") or bl.get("blocked")):
                srv = bl.get("server") or bl.get("name")
                if srv:
                    blocked_by.append(str(srv).strip())
            elif isinstance(bl, str):
                blocked_by.append(bl.strip())

    for bl_srv in blocked_by:
        evidences.append(ProviderEvidence(
            provider_name="webcheck",
            evidence_type="blocklist",
            description=f"{hostname} is listed on blocklist: {bl_srv}",
            confidence=85.0,
        ))

    # ---- breaches (Have I Been Pwned) --------------------------------------
    breaches_data = results.get("breaches") or {}
    if isinstance(breaches_data, dict):
        breaches_list = breaches_data.get("breaches") or []
        if isinstance(breaches_list, list):
            for b in breaches_list:
                if isinstance(b, dict) and b.get("name"):
                    b_title = b.get("title") or b.get("name")
                    b_date = b.get("date") or "historical"
                    evidences.append(ProviderEvidence(
                        provider_name="webcheck",
                        evidence_type="data_breach",
                        description=f"Domain involved in '{b_title}' breach ({b_date})",
                        confidence=85.0,
                    ))

    # ---- txt-records -------------------------------------------------------
    txt_data = results.get("txt-records")
    if isinstance(txt_data, list):
        for item in txt_data:
            if isinstance(item, str) and item.strip():
                dns_records.append(DnsRecordItem(record_type="TXT", value=item.strip(), sources=["webcheck"]))
            elif isinstance(item, dict) and item.get("record"):
                dns_records.append(DnsRecordItem(record_type="TXT", value=str(item["record"]).strip(), sources=["webcheck"]))
    elif isinstance(txt_data, dict):
        rec_list = txt_data.get("records") or txt_data.get("txt") or []
        if isinstance(rec_list, list):
            for item in rec_list:
                if item:
                    dns_records.append(DnsRecordItem(record_type="TXT", value=str(item).strip(), sources=["webcheck"]))

    # ---- ports -------------------------------------------------------------
    ports_data = results.get("ports") or {}
    open_ports_list: List[int] = []
    services_detail: List[ServiceInfo] = []
    if isinstance(ports_data, dict):
        raw_ports = ports_data.get("openPorts") or []
        if isinstance(raw_ports, list):
            for p in raw_ports:
                try:
                    p_int = int(p)
                    if p_int not in open_ports_list:
                        open_ports_list.append(p_int)
                        services_detail.append(
                            ServiceInfo(
                                port=p_int,
                                transport="tcp",
                                service_name="open-port",
                                sources=["webcheck"],
                            )
                        )
                except Exception:
                    pass

    # ---- archives (Wayback Machine) ----------------------------------------
    archives_data = results.get("archives") or {}
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    if isinstance(archives_data, dict):
        first_seen = _safe_str(archives_data.get("firstScan"))
        last_seen = _safe_str(archives_data.get("lastScan"))

    temporal_info: Optional[TemporalInfo] = (
        TemporalInfo(
            first_seen=first_seen,
            last_seen=last_seen,
            sources=["webcheck"],
        )
        if (first_seen or last_seen)
        else None
    )

    # ---- location & network ------------------------------------------------
    geo_info: Optional[GeoInfo] = None
    network_info: Optional[NetworkInfo] = None
    loc_asn: Optional[str] = None
    loc_org: Optional[str] = None
    loc_isp: Optional[str] = None
    loc_country: Optional[str] = None
    loc_city: Optional[str] = None
    loc_region: Optional[str] = None
    if isinstance(location_data, dict) and location_data:
        loc_city = _safe_str(location_data.get("city"))
        loc_region = _safe_str(location_data.get("region"))
        loc_country = _safe_str(location_data.get("country"))
        loc_country_code = _safe_str(location_data.get("countryCode") or location_data.get("country_code"))
        loc_lat = None
        if location_data.get("lat") is not None:
            try:
                loc_lat = float(location_data["lat"])
            except (ValueError, TypeError):
                loc_lat = None
        loc_lon = None
        if location_data.get("lon") is not None:
            try:
                loc_lon = float(location_data["lon"])
            except (ValueError, TypeError):
                loc_lon = None
        loc_tz = _safe_str(location_data.get("timezone"))
        loc_isp = _safe_str(location_data.get("isp"))
        loc_org = _safe_str(location_data.get("org"))
        loc_asn = _safe_str(location_data.get("asn"))
        if not loc_asn and location_data.get("as"):
            as_val = str(location_data.get("as"))
            loc_asn = as_val.split()[0] if as_val.startswith("AS") else as_val

        if loc_country or loc_city or loc_lat is not None:
            geo_info = GeoInfo(
                city=loc_city,
                region=loc_region,
                country=loc_country,
                country_code=loc_country_code,
                latitude=loc_lat,
                longitude=loc_lon,
                timezone=loc_tz,
                sources=["webcheck"],
            )

        if loc_asn or loc_org or loc_isp or target_ip:
            network_info = NetworkInfo(
                ip=target_ip,
                ip_version="IPv6" if (target_ip and ":" in target_ip) else ("IPv4" if target_ip else None),
                asn=loc_asn,
                org=loc_org,
                isp=loc_isp,
                sources=["webcheck"],
            )

    if not network_info and (target_ip or is_ip_ioc):
        ip_v = target_ip or ioc_value
        network_info = NetworkInfo(
            ip=ip_v,
            ip_version="IPv6" if (ip_v and ":" in ip_v) else "IPv4",
            asn=loc_asn,
            org=loc_org,
            isp=loc_isp,
            sources=["webcheck"],
        )

    # ---- screenshot --------------------------------------------------------
    screenshot_data = results.get("screenshot")
    screenshot_url: Optional[str] = None
    if isinstance(screenshot_data, str) and screenshot_data.strip():
        s_val = screenshot_data.strip()
        if s_val.startswith("http") or s_val.startswith("data:image"):
            screenshot_url = s_val
        elif len(s_val) > 100:
            screenshot_url = f"data:image/png;base64,{s_val}"
    elif isinstance(screenshot_data, dict) and screenshot_data.get("data"):
        screenshot_url = f"data:image/png;base64,{str(screenshot_data['data']).strip()}"

    # ---- Build HttpInfo ----------------------------------------------------
    http_info = HttpInfo(
        server=_safe_str(raw_headers.get("server") or raw_headers.get("Server")),
        title=None,  # populated if social-tags has og:title
        status_code=int(http_status_code) if http_status_code else None,
        headers=raw_headers or {},
        technologies=technologies,
        screenshot_url=screenshot_url,
        sources=["webcheck"],
    )

    # ---- social-tags -------------------------------------------------------
    social_data = results.get("social-tags") or {}
    if isinstance(social_data, dict):
        title = _safe_str(social_data.get("title") or social_data.get("ogTitle"))
        if title and http_info:
            http_info.title = title

    # ---- Build DnsInfo -----------------------------------------------------
    dns_info = DnsInfo(
        hostnames=list(dict.fromkeys(dns_hostnames)),
        domains=list(dict.fromkeys(dns_domains)),
        records=dns_records,
        sources=["webcheck"],
    ) if (dns_records or dns_hostnames or dns_domains) else None

    # ---- Assemble InfrastructureData ---------------------------------------
    infra = InfrastructureData(
        asn=loc_asn,
        org=loc_org,
        country=loc_country,
        region=loc_region,
        city=loc_city,
        open_ports=open_ports_list,
        services=[{"port": p, "service_name": "open-port"} for p in open_ports_list],
        certificates=[{"fingerprint": c.fingerprint_sha256, "names": c.sans} for c in certs_detail if c.fingerprint_sha256],
        registrar=whois_info.registrar if whois_info else None,
        whois_creation=whois_info.creation_date if whois_info else None,
        whois_expiration=whois_info.expiration_date if whois_info else None,
        nameservers=ns_list if whois_info else [],
        http_server=http_info.server if http_info else None,
        http_title=http_info.title if http_info else None,
        network=network_info,
        geo=geo_info,
        http=http_info,
        dns=dns_info,
        tls=tls_info,
        certificates_detail=certs_detail if any(
            c.fingerprint_sha256 or c.subject_cn or c.valid_from for c in certs_detail
        ) else [],
        services_detail=services_detail,
        whois=whois_info,
        temporal=temporal_info,
        screenshot_url=screenshot_url,
        extra={},
    )

    # ---- Add all raw endpoint data to extra["webcheck"] --------------------
    webcheck_extra: Dict[str, Any] = {}
    for ep in _WEBCHECK_ENDPOINTS:
        d = results.get(ep)
        if d is not None:
            webcheck_extra[ep] = d

    infra.extra["webcheck"] = webcheck_extra
    infra.security_headers = normalize_security_headers(results, sources=["webcheck"])

    # Additional convenience keys in extra
    if waf:
        infra.extra["webcheck_waf"] = waf
    if threat_tags:
        infra.extra["webcheck_threat_tags"] = threat_tags
    if blocked_by:
        infra.extra["webcheck_blocked_by"] = blocked_by
    if redirect_chain:
        infra.extra["webcheck_redirect_chain"] = redirect_chain
    if open_ports_list:
        infra.extra["webcheck_open_ports"] = open_ports_list

    return infra, discovered_iocs, evidences
