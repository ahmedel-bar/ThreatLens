import asyncio
import time
import ipaddress
import httpx
from urllib.parse import urlparse
from typing import Optional, List, Dict, Any, Tuple
from app.providers.base import BaseProvider, ProviderRequestContext
from app.schemas.ioc import IOCType, ProviderStatus

def _is_ip(val: str) -> bool:
    try:
        ipaddress.ip_address(val.strip())
        return True
    except (ValueError, AttributeError):
        return False

from app.schemas.provider import (
    ProviderCapability,
    ProviderResult,
    InfrastructureData,
    DiscoveredIOC,
    NetworkInfo,
    GeoInfo,
    WhoisInfo,
    ServiceInfo,
    VulnInfo,
    CertInfo,
    ThreatAttribution,
    DnsInfo,
    IpScoringInfo,
    DetectionInfo,
    SecurityIndicators,
    ProviderEvidence,
)
from app.services.ioc import normalize_ioc
from app.config import settings



class CriminalIPProvider(BaseProvider):
    def __init__(self):
        self._cache: Dict[Tuple[str, str], Tuple[float, ProviderResult]] = {}
        self._lock = asyncio.Lock()
        self._last_request_time = 0.0
        self._min_request_interval = 1.0

    @property
    def name(self) -> str:
        return "criminalip"

    @property
    def display_name(self) -> str:
        return "Criminal IP"

    def get_capabilities(self) -> ProviderCapability:
        return ProviderCapability(
            name=self.name,
            display_name=self.display_name,
            description="Cyber threat intelligence and attack surface management search engine identifying malicious IPs, open ports, banners, and vulnerabilities.",
            supported_iocs=[IOCType.IPV4, IOCType.IPV6, IOCType.DOMAIN, IOCType.URL],
            requires_auth=True,
            free_tier=True,
            rate_limit_desc="Plan-dependent rate limits with in-memory caching and plan-restriction handling",
            provides_reputation=True,
            provides_infrastructure=True,
            provides_relationships=True,
            doc_url="https://www.criminalip.io/developer/api",
        )

    def _get_from_cache(self, ioc_val: str, ioc_type: IOCType) -> Optional[ProviderResult]:
        key = (ioc_val, ioc_type.value)
        if key in self._cache:
            ts, res = self._cache[key]
            if time.time() - ts < settings.CACHE_TTL:
                return res.model_copy(deep=True)
            del self._cache[key]
        return None

    def _put_in_cache(self, ioc_val: str, ioc_type: IOCType, res: ProviderResult):
        key = (ioc_val, ioc_type.value)
        self._cache[key] = (time.time(), res.model_copy(deep=True))

    async def _execute_live(self, ctx: ProviderRequestContext) -> ProviderResult:
        cached = self._get_from_cache(ctx.ioc_value, ctx.ioc_type)
        if cached:
            return cached

        headers = {
            "x-api-key": ctx.api_key.strip() if ctx.api_key else "",
            "User-Agent": "ThreatLens/1.0",
            "Accept": "application/json",
        }
        client = ctx.http_client or httpx.AsyncClient(timeout=ctx.timeout_seconds)

        try:
            if ctx.ioc_type in (IOCType.IPV4, IOCType.IPV6):
                return await self._execute_ip_live(ctx, client, headers)
            elif ctx.ioc_type in (IOCType.DOMAIN, IOCType.URL):
                return await self._execute_domain_live(ctx, client, headers)
            else:
                return ProviderResult(
                    provider_name=self.name,
                    ioc_value=ctx.ioc_value,
                    ioc_type=ctx.ioc_type,
                    status=ProviderStatus.UNSUPPORTED,
                    error_details="IOC type not supported by Criminal IP.",
                )
        finally:
            if not ctx.http_client:
                await client.aclose()

    async def _execute_ip_live(
        self,
        ctx: ProviderRequestContext,
        client: httpx.AsyncClient,
        headers: Dict[str, str],
    ) -> ProviderResult:
        ip = ctx.ioc_value
        report_url = f"https://api.criminalip.io/v1/asset/ip/report?ip={ip}&full=true"
        malicious_url = f"https://api.criminalip.io/v1/feature/ip/malicious-info?ip={ip}"

        resp = await client.get(report_url, headers=headers)

        if resp.status_code == 401:
            return ProviderResult(
                provider_name=self.name,
                ioc_value=ctx.ioc_value,
                ioc_type=ctx.ioc_type,
                status=ProviderStatus.UNAUTHORIZED,
                error_details="Invalid Criminal IP API key.",
            )
        if resp.status_code in (402, 403):
            err_msg = resp.text[:200]
            status = ProviderStatus.PLAN_RESTRICTED if "plan" in err_msg.lower() else ProviderStatus.FORBIDDEN
            return ProviderResult(
                provider_name=self.name,
                ioc_value=ctx.ioc_value,
                ioc_type=ctx.ioc_type,
                status=status,
                error_details=f"Criminal IP plan restricted: {err_msg}",
            )
        if resp.status_code == 404:
            return ProviderResult(
                provider_name=self.name,
                ioc_value=ctx.ioc_value,
                ioc_type=ctx.ioc_type,
                status=ProviderStatus.NOT_FOUND,
                error_details="IP not found in Criminal IP database.",
            )
        if resp.status_code == 429:
            return ProviderResult(
                provider_name=self.name,
                ioc_value=ctx.ioc_value,
                ioc_type=ctx.ioc_type,
                status=ProviderStatus.RATE_LIMITED,
                error_details="Criminal IP rate limit exceeded.",
            )
        if resp.status_code >= 500:
            return ProviderResult(
                provider_name=self.name,
                ioc_value=ctx.ioc_value,
                ioc_type=ctx.ioc_type,
                status=ProviderStatus.SERVER_ERROR,
                error_details=f"Criminal IP server error (HTTP {resp.status_code}).",
            )

        resp.raise_for_status()
        report_data = resp.json()

        # Check for message error in 200 responses
        if isinstance(report_data, dict):
            status_code_in_body = report_data.get("status")
            body_msg = str(report_data.get("message", "")).lower()
            if status_code_in_body == 404 or "no data" in body_msg:
                return ProviderResult(
                    provider_name=self.name,
                    ioc_value=ctx.ioc_value,
                    ioc_type=ctx.ioc_type,
                    status=ProviderStatus.NOT_FOUND,
                    error_details="No record found for this IP.",
                )
            if status_code_in_body in (401, 403) and ("check access failed" in body_msg or "unauthorized" in body_msg):
                return ProviderResult(
                    provider_name=self.name,
                    ioc_value=ctx.ioc_value,
                    ioc_type=ctx.ioc_type,
                    status=ProviderStatus.UNAUTHORIZED,
                    error_details="Invalid Criminal IP API key.",
                )
            if status_code_in_body in (402, 403) or "plan" in body_msg:
                return ProviderResult(
                    provider_name=self.name,
                    ioc_value=ctx.ioc_value,
                    ioc_type=ctx.ioc_type,
                    status=ProviderStatus.PLAN_RESTRICTED,
                    error_details=str(report_data.get("message", "Plan restricted")),
                )
            if status_code_in_body == 500 or "internal server error" in body_msg:
                return ProviderResult(
                    provider_name=self.name,
                    ioc_value=ctx.ioc_value,
                    ioc_type=ctx.ioc_type,
                    status=ProviderStatus.SERVER_ERROR,
                    error_details=f"Criminal IP service internal error: {report_data.get('message', 'Internal server error')}",
                )

        # Optional malicious-info query
        malicious_data: Optional[Dict[str, Any]] = None
        try:
            mal_resp = await client.get(malicious_url, headers=headers)
            if mal_resp.status_code == 200:
                m_json = mal_resp.json()
                if isinstance(m_json, dict) and not m_json.get("message"):
                    malicious_data = m_json
        except Exception:
            malicious_data = None

        result = self._parse_ip_response(ctx.ioc_value, ctx.ioc_type, report_data, malicious_data)
        self._put_in_cache(ctx.ioc_value, ctx.ioc_type, result)
        return result

    async def _execute_domain_live(
        self,
        ctx: ProviderRequestContext,
        client: httpx.AsyncClient,
        headers: Dict[str, str],
    ) -> ProviderResult:
        target = ctx.ioc_value
        if ctx.ioc_type == IOCType.URL:
            parsed = urlparse(target)
            target = parsed.hostname or target

        # Query domain reports or quick malicious view with domain param
        quick_url = f"https://api.criminalip.io/v1/domain/quick/malicious/view?domain={target}"
        reports_url = f"https://api.criminalip.io/v1/domain/reports?query={target}&offset=0"

        domain_data: Dict[str, Any] = {}
        try:
            rep_resp = await client.get(reports_url, headers=headers)
            if rep_resp.status_code == 200:
                domain_data = rep_resp.json()
        except Exception:
            pass

        if not domain_data or domain_data.get("status") in (404, 500):
            try:
                resp = await client.get(quick_url, headers=headers)
                if resp.status_code == 200:
                    domain_data = resp.json()
                elif resp.status_code == 401:
                    return ProviderResult(
                        provider_name=self.name,
                        ioc_value=ctx.ioc_value,
                        ioc_type=ctx.ioc_type,
                        status=ProviderStatus.UNAUTHORIZED,
                        error_details="Invalid Criminal IP API key.",
                    )
                elif resp.status_code in (402, 403):
                    err_msg = resp.text[:200]
                    status = ProviderStatus.PLAN_RESTRICTED if "plan" in err_msg.lower() else ProviderStatus.FORBIDDEN
                    return ProviderResult(
                        provider_name=self.name,
                        ioc_value=ctx.ioc_value,
                        ioc_type=ctx.ioc_type,
                        status=status,
                        error_details=f"Criminal IP plan restricted: {err_msg}",
                    )
            except Exception:
                pass

        if isinstance(domain_data, dict):
            status_code_in_body = domain_data.get("status")
            body_msg = str(domain_data.get("message", "")).lower()
            if status_code_in_body in (401, 403) and ("check access failed" in body_msg or "unauthorized" in body_msg):
                return ProviderResult(
                    provider_name=self.name,
                    ioc_value=ctx.ioc_value,
                    ioc_type=ctx.ioc_type,
                    status=ProviderStatus.UNAUTHORIZED,
                    error_details="Invalid Criminal IP API key.",
                )
            if status_code_in_body in (402, 403) or "plan" in body_msg:
                return ProviderResult(
                    provider_name=self.name,
                    ioc_value=ctx.ioc_value,
                    ioc_type=ctx.ioc_type,
                    status=ProviderStatus.PLAN_RESTRICTED,
                    error_details=str(domain_data.get("message", "Plan restricted")),
                )
            if status_code_in_body == 404 or "no data" in body_msg:
                return ProviderResult(
                    provider_name=self.name,
                    ioc_value=ctx.ioc_value,
                    ioc_type=ctx.ioc_type,
                    status=ProviderStatus.NOT_FOUND,
                    error_details="No record found for this domain.",
                )
            if status_code_in_body == 500 or "internal server error" in body_msg:
                return ProviderResult(
                    provider_name=self.name,
                    ioc_value=ctx.ioc_value,
                    ioc_type=ctx.ioc_type,
                    status=ProviderStatus.SERVER_ERROR,
                    error_details=f"Criminal IP service internal error: {domain_data.get('message', 'Internal server error')}",
                )

        result = self._parse_domain_response(ctx.ioc_value, ctx.ioc_type, domain_data)
        self._put_in_cache(ctx.ioc_value, ctx.ioc_type, result)
        return result

        return result

    def _parse_ip_response(
        self,
        ioc_val: str,
        ioc_type: IOCType,
        report_data: Dict[str, Any],
        malicious_data: Optional[Dict[str, Any]] = None,
    ) -> ProviderResult:
        tags: List[str] = []
        threat_attributions: List[ThreatAttribution] = []
        malware_families: List[str] = []

        # Issues & detection flags
        issues_dict = report_data.get("issues") or {}
        if not isinstance(issues_dict, dict):
            issues_dict = {}

        is_vpn = bool(issues_dict.get("is_vpn") or report_data.get("is_vpn"))
        is_tor = bool(issues_dict.get("is_tor") or report_data.get("is_tor"))
        is_proxy = bool(issues_dict.get("is_proxy") or report_data.get("is_proxy"))
        is_hosting = bool(issues_dict.get("is_hosting") or report_data.get("is_hosting"))
        is_cloud = bool(issues_dict.get("is_cloud") or report_data.get("is_cloud"))
        is_mobile = bool(issues_dict.get("is_mobile") or report_data.get("is_mobile"))
        is_cdn = bool(issues_dict.get("is_cdn") or report_data.get("is_cdn"))
        is_scanner = bool(issues_dict.get("is_scanner") or report_data.get("is_scanner"))
        is_darkweb = bool(issues_dict.get("is_darkweb") or report_data.get("is_darkweb"))
        is_snort = bool(issues_dict.get("is_snort") or report_data.get("is_snort"))

        # Risk scoring
        score_val: Optional[float] = None
        score_dict = report_data.get("score") or {}
        inbound_str: Optional[str] = None
        outbound_str: Optional[str] = None
        if isinstance(score_dict, dict):
            inbound_val = score_dict.get("inbound")
            outbound_val = score_dict.get("outbound")
            inbound_str = str(inbound_val) if inbound_val is not None else None
            outbound_str = str(outbound_val) if outbound_val is not None else None

            scores_to_avg = []
            for s in (inbound_val, outbound_val):
                if isinstance(s, (int, float)):
                    scores_to_avg.append(float(s))
                elif isinstance(s, str):
                    s_low = s.lower().strip()
                    if s_low == "critical": scores_to_avg.append(100.0)
                    elif s_low == "dangerous": scores_to_avg.append(85.0)
                    elif s_low == "moderate": scores_to_avg.append(50.0)
                    elif s_low == "low": scores_to_avg.append(25.0)
                    elif s_low == "safe": scores_to_avg.append(0.0)
            if scores_to_avg:
                score_val = sum(scores_to_avg) / len(scores_to_avg)

        is_malicious = False
        t_cat = None
        if malicious_data and isinstance(malicious_data, dict):
            is_malicious = is_malicious or bool(malicious_data.get("is_malicious"))
            is_vpn = is_vpn or bool(malicious_data.get("is_vpn"))
            is_tor = is_tor or bool(malicious_data.get("is_tor"))
            is_proxy = is_proxy or bool(malicious_data.get("is_proxy"))
            is_hosting = is_hosting or bool(malicious_data.get("is_hosting"))
            is_scanner = is_scanner or bool(malicious_data.get("is_scanner"))
            t_cat = malicious_data.get("threat_category")
        if not t_cat:
            t_cat = report_data.get("threat_category") or issues_dict.get("threat_category")

        if t_cat:
            cat_list = t_cat if isinstance(t_cat, list) else [t_cat]
            for cat in cat_list:
                if cat and str(cat) not in tags:
                    tags.append(str(cat))
                    threat_attributions.append(
                        ThreatAttribution(
                            canonical_name=str(cat),
                            entity_type="threat_association",
                            relationship_type="associated_threat",
                            subtype="threat_category",
                            threat_association=str(cat),
                            sources=["criminalip"],
                            confidence=80.0,
                            evidence_summary=f"Criminal IP threat category: {cat}",
                        )
                    )

        # Categories & VPN providers
        vpn_raw = report_data.get("vpn") or {}
        vpn_items = vpn_raw.get("data", []) if isinstance(vpn_raw, dict) else (vpn_raw if isinstance(vpn_raw, list) else [])
        vpn_providers = [str(x.get("vpn_name") or x) for x in vpn_items if isinstance(x, (dict, str))]

        cat_raw = report_data.get("ip_category") or {}
        cat_items = cat_raw.get("data", []) if isinstance(cat_raw, dict) else (cat_raw if isinstance(cat_raw, list) else [])
        ip_categories = [str(x.get("category") or x) for x in cat_items if isinstance(x, (dict, str))]
        for c in ip_categories:
            if c and c not in tags:
                tags.append(c)

        special_issues: List[str] = []
        if is_tor:
            special_issues.append("Tor Exit Node")
            tags.append("TOR")
        if is_vpn:
            special_issues.append("VPN Endpoint")
            tags.append("VPN")
        if is_proxy:
            special_issues.append("Proxy Service")
            tags.append("Proxy")
        if is_hosting:
            special_issues.append("Hosting / Datacenter")
            tags.append("Hosting")
        if is_cloud:
            special_issues.append("Cloud Infrastructure")
            tags.append("Cloud")
        if is_scanner:
            special_issues.append("Active Vulnerability Scanner")
            tags.append("Scanner")
        if is_darkweb:
            special_issues.append("Darkweb Activity")
            tags.append("Darkweb")
        if is_snort:
            special_issues.append("IDS Snort Alert Detected")
            tags.append("IDS Alert")

        # Classification
        inbound_upper = (inbound_str or "").upper()
        outbound_upper = (outbound_str or "").upper()
        has_critical = inbound_upper in ("CRITICAL", "DANGEROUS") or outbound_upper in ("CRITICAL", "DANGEROUS")
        has_moderate = inbound_upper == "MODERATE" or outbound_upper == "MODERATE"

        if is_malicious or has_critical or (score_val is not None and score_val >= 70.0):
            classification = "malicious"
            mal_count = 1
            susp_count = 0
            harm_count = 0
        elif has_moderate or is_tor or is_vpn or is_proxy or is_scanner or is_snort or is_darkweb or (score_val is not None and score_val >= 35.0):
            classification = "suspicious"
            mal_count = 0
            susp_count = 1
            harm_count = 0
        elif (inbound_upper == "SAFE" and outbound_upper == "SAFE") or (score_val is not None and score_val < 35.0 and not special_issues):
            classification = "benign"
            mal_count = 0
            susp_count = 0
            harm_count = 1
        else:
            classification = "unknown"
            mal_count = 0
            susp_count = 0
            harm_count = 0

        # Build Infrastructure
        infra = InfrastructureData()

        # IP Scoring Model
        infra.ip_scoring = IpScoringInfo(
            inbound_score=inbound_str,
            outbound_score=outbound_str,
            reputation_score=score_val,
            classification=classification,
            critical_risk=has_critical,
            abuse_indicators=special_issues,
            sources=["criminalip"],
        )

        # Detection Model
        infra.detection = DetectionInfo(
            is_vpn=is_vpn,
            is_tor=is_tor,
            is_proxy=is_proxy,
            is_hosting=is_hosting,
            is_cloud=is_cloud,
            is_mobile=is_mobile,
            is_cdn=is_cdn,
            is_scanner=is_scanner,
            is_darkweb=is_darkweb,
            is_snort=is_snort,
            is_anonymous_vpn=bool(is_vpn and any("anon" in p.lower() for p in vpn_providers)),
            vpn_providers=vpn_providers,
            ip_categories=ip_categories,
            special_issues=special_issues,
            sources=["criminalip"],
        )

        # IDS alert details
        ids_raw = report_data.get("ids") or {}
        ids_items = ids_raw.get("data", []) if isinstance(ids_raw, dict) else (ids_raw if isinstance(ids_raw, list) else [])
        ids_signatures = [str(item.get("signature") or item) for item in ids_items if isinstance(item, (dict, str))]
        ids_count = ids_raw.get("count", len(ids_signatures)) if isinstance(ids_raw, dict) else len(ids_signatures)
        if is_snort and ids_count == 0:
            ids_count = 1

        # WHOIS & Geo & Network
        whois_raw = report_data.get("whois") or {}
        if isinstance(whois_raw, dict):
            if "data" in whois_raw and isinstance(whois_raw["data"], list):
                first_whois = whois_raw["data"][0] if whois_raw["data"] and isinstance(whois_raw["data"][0], dict) else {}
            else:
                first_whois = whois_raw
        elif isinstance(whois_raw, list) and whois_raw and isinstance(whois_raw[0], dict):
            first_whois = whois_raw[0]
        else:
            first_whois = {}

        asn_str = str(first_whois.get("asn") or report_data.get("asn") or "") or None
        as_name = first_whois.get("as_name") or report_data.get("as_name")
        org_name = first_whois.get("org_name") or report_data.get("org_name")
        isp_name = first_whois.get("isp") or report_data.get("isp")
        country = first_whois.get("country") or report_data.get("country")
        country_code = first_whois.get("country_code") or report_data.get("country_code")
        city = first_whois.get("city") or report_data.get("city")
        region = first_whois.get("region") or report_data.get("region")
        postal_code = first_whois.get("postal_code") or report_data.get("postal_code")
        lat_raw = first_whois.get("latitude") if first_whois.get("latitude") is not None else report_data.get("latitude")
        lon_raw = first_whois.get("longitude") if first_whois.get("longitude") is not None else report_data.get("longitude")

        # Hostnames & Reverse DNS (PTR)
        hostname_raw = report_data.get("hostname") or {}
        if isinstance(hostname_raw, dict):
            host_items = hostname_raw.get("data", [])
            raw_hostnames = [str(item.get("hostname") or item) for item in host_items if item]
        elif isinstance(hostname_raw, list):
            raw_hostnames = [str(h) for h in hostname_raw if h]
        elif isinstance(hostname_raw, str) and hostname_raw:
            raw_hostnames = [hostname_raw]
        else:
            raw_hostnames = []

        extracted_hostnames: List[str] = []
        for h in raw_hostnames:
            h_str = h.strip()
            if h_str and not _is_ip(h_str) and h_str not in extracted_hostnames:
                extracted_hostnames.append(h_str)

        ptr_val = extracted_hostnames[0] if extracted_hostnames else None

        infra.network = NetworkInfo(
            ip=ioc_val,
            asn=asn_str,
            asn_name=as_name,
            org=org_name,
            isp=isp_name,
            ptr=ptr_val,
            sources=["criminalip"],
        )
        if asn_str: infra.asn = asn_str
        if as_name: infra.asn_name = as_name
        if org_name: infra.org = org_name
        if ptr_val: infra.ptr = ptr_val

        lat = None
        lon = None
        try:
            if lat_raw is not None: lat = float(lat_raw)
            if lon_raw is not None: lon = float(lon_raw)
        except (ValueError, TypeError):
            lat = None
            lon = None

        infra.geo = GeoInfo(
            country=country,
            country_code=country_code,
            region=region,
            city=city,
            postal_code=postal_code,
            latitude=lat,
            longitude=lon,
            sources=["criminalip"],
        )
        if country: infra.country = country
        if region: infra.region = region
        if city: infra.city = city

        if first_whois:
            infra.whois = WhoisInfo(
                registrar=first_whois.get("registrar"),
                registrant_org=first_whois.get("org_name"),
                registrant_country=first_whois.get("country"),
                creation_date=first_whois.get("creation_date"),
                updated_date=first_whois.get("updated_date"),
                sources=["criminalip"],
            )
            if first_whois.get("registrar"):
                infra.registrar = first_whois.get("registrar")

        # Services & Ports
        port_raw = report_data.get("port") or {}
        port_items = port_raw.get("data", []) if isinstance(port_raw, dict) else (port_raw if isinstance(port_raw, list) else [])

        services_map: Dict[int, ServiceInfo] = {}
        vulns_map: Dict[str, VulnInfo] = {}

        for p in port_items:
            if not isinstance(p, dict):
                continue
            port_num = p.get("port")
            if not isinstance(port_num, int):
                continue
            if port_num not in infra.open_ports:
                infra.open_ports.append(port_num)

            cpe_list = []
            raw_cpe = p.get("cpe") or p.get("list_cpe")
            if isinstance(raw_cpe, list):
                cpe_list = [str(c) for c in raw_cpe if c]
            elif isinstance(raw_cpe, str) and raw_cpe:
                cpe_list = [raw_cpe]

            p_vulns = []
            for v in (p.get("vulnerability") or []):
                if isinstance(v, dict) and v.get("cve_id"):
                    cve_id = v["cve_id"]
                    p_vulns.append(cve_id)
                    if cve_id not in vulns_map:
                        cvss_val = None
                        try:
                            if v.get("cvssv3_score") is not None:
                                cvss_val = float(v["cvssv3_score"])
                            elif v.get("cvssv2_score") is not None:
                                cvss_val = float(v["cvssv2_score"])
                        except (ValueError, TypeError):
                            cvss_val = None
                        sev = None
                        if cvss_val is not None:
                            if cvss_val >= 9.0: sev = "CRITICAL"
                            elif cvss_val >= 7.0: sev = "HIGH"
                            elif cvss_val >= 4.0: sev = "MEDIUM"
                            else: sev = "LOW"
                        vulns_map[cve_id] = VulnInfo(
                            cve_id=cve_id,
                            cvss=cvss_val,
                            severity=sev,
                            summary=v.get("description") or v.get("summary"),
                            port=port_num,
                            sources=["criminalip"],
                        )
                    else:
                        if not vulns_map[cve_id].port:
                            vulns_map[cve_id].port = port_num
                elif isinstance(v, str):
                    p_vulns.append(v)

            svc_info = ServiceInfo(
                port=port_num,
                transport=str(p.get("protocol") or p.get("socket") or "tcp").lower(),
                service_name=p.get("app_name") or p.get("product"),
                product=p.get("app_name") or p.get("product"),
                version=p.get("app_version"),
                banner=p.get("banner"),
                cpe=cpe_list,
                vulnerabilities=p_vulns,
                scan_time=p.get("confirmed_time") or p.get("scan_time"),
                sources=["criminalip"],
            )
            services_map[port_num] = svc_info

            # SSL from port
            ssl_dict = p.get("ssl")
            if isinstance(ssl_dict, dict) and (ssl_dict.get("subject_common_name") or ssl_dict.get("issuer_common_name")):
                infra.certificates_detail.append(
                    CertInfo(
                        subject_cn=ssl_dict.get("subject_common_name"),
                        issuer_cn=ssl_dict.get("issuer_common_name"),
                        valid_from=ssl_dict.get("valid_from"),
                        valid_to=ssl_dict.get("valid_to"),
                        sources=["criminalip"],
                    )
                )

        # Vulnerabilities section
        vuln_raw = report_data.get("vulnerability") or {}
        vuln_items = vuln_raw.get("data", []) if isinstance(vuln_raw, dict) else (vuln_raw if isinstance(vuln_raw, list) else [])

        for v in vuln_items:
            if not isinstance(v, dict) or not v.get("cve_id"):
                continue

            cve_id = v["cve_id"]
            cvss_v2 = None
            cvss_v3 = None
            try:
                if v.get("cvssv2_score") is not None and float(v["cvssv2_score"]) > 0:
                    cvss_v2 = float(v["cvssv2_score"])
            except (ValueError, TypeError):
                pass
            try:
                if v.get("cvssv3_score") is not None and float(v["cvssv3_score"]) > 0:
                    cvss_v3 = float(v["cvssv3_score"])
            except (ValueError, TypeError):
                pass

            cvss = cvss_v3 if cvss_v3 is not None else cvss_v2

            # CWE
            cwe_id = None
            cwe_list = v.get("list_cwe") or []
            if isinstance(cwe_list, list) and cwe_list:
                first_cwe = cwe_list[0]
                if isinstance(first_cwe, dict) and first_cwe.get("cwe_id"):
                    cwe_id = f"CWE-{first_cwe['cwe_id']}"
                elif isinstance(first_cwe, (int, str)):
                    cwe_id = f"CWE-{first_cwe}"

            # CPE list
            cpe_list = []
            raw_cpe = v.get("list_cpe") or v.get("cpe")
            if isinstance(raw_cpe, list):
                cpe_list = [str(c) for c in raw_cpe if c]
            elif isinstance(raw_cpe, str) and raw_cpe:
                cpe_list = [raw_cpe]

            # Exploit DB
            edb_list = v.get("list_edb") or []
            has_exploit = bool(edb_list)
            exploit_details = None
            if edb_list and isinstance(edb_list, list):
                edb_ids = [str(e.get("edb_id") if isinstance(e, dict) else e) for e in edb_list]
                exploit_details = f"Exploit Database: {', '.join(edb_ids)}"

            # Related products
            child_list = v.get("list_child") or []
            related_products = []
            if isinstance(child_list, list):
                for child in child_list:
                    if isinstance(child, dict):
                        p_name = child.get("app_name") or child.get("product")
                        p_ver = child.get("app_version") or child.get("version")
                        p_vendor = child.get("vendor")
                        label = " ".join(x for x in (p_vendor, p_name, p_ver) if x)
                        if label and label not in related_products:
                            related_products.append(label)

            # Associated port
            port_num: Optional[int] = None
            open_port_no = v.get("open_port_no") or []
            if isinstance(open_port_no, list) and open_port_no:
                first_p = open_port_no[0]
                if isinstance(first_p, dict) and isinstance(first_p.get("port"), int):
                    port_num = first_p["port"]
            elif isinstance(v.get("open_port_no_list"), dict):
                tcp_ports = v["open_port_no_list"].get("TCP") or []
                if tcp_ports and isinstance(tcp_ports[0], int):
                    port_num = tcp_ports[0]

            if port_num is not None:
                if port_num not in infra.open_ports:
                    infra.open_ports.append(port_num)
                if port_num in services_map:
                    if cve_id not in services_map[port_num].vulnerabilities:
                        services_map[port_num].vulnerabilities.append(cve_id)
                else:
                    services_map[port_num] = ServiceInfo(
                        port=port_num,
                        transport="tcp",
                        service_name=v.get("app_name"),
                        product=v.get("app_name"),
                        version=v.get("app_version"),
                        cpe=cpe_list[:5],
                        vulnerabilities=[cve_id],
                        sources=["criminalip"],
                    )

            # Severity
            severity = None
            if cvss is not None:
                if cvss >= 9.0: severity = "CRITICAL"
                elif cvss >= 7.0: severity = "HIGH"
                elif cvss >= 4.0: severity = "MEDIUM"
                else: severity = "LOW"

            if cve_id in vulns_map:
                existing = vulns_map[cve_id]
                if cwe_id and not existing.cwe_id: existing.cwe_id = cwe_id
                if cvss_v2 is not None and existing.cvss_v2 is None: existing.cvss_v2 = cvss_v2
                if cvss_v3 is not None and existing.cvss_v3 is None: existing.cvss_v3 = cvss_v3
                if cvss is not None and (existing.cvss is None or cvss > (existing.cvss or 0)): existing.cvss = cvss
                if severity and (not existing.severity or severity == "CRITICAL"): existing.severity = severity
                if v.get("cvssv3_vector") or v.get("cvssv2_vector"): existing.attack_vector = v.get("cvssv3_vector") or v.get("cvssv2_vector")
                if v.get("app_name"): existing.affected_product = v.get("app_name")
                if v.get("vendor"): existing.affected_vendor = v.get("vendor")
                if v.get("cve_description") or v.get("description"): existing.summary = v.get("cve_description") or v.get("description")
                if related_products: existing.related_products = list(dict.fromkeys(existing.related_products + related_products))
                if port_num is not None and not existing.port: existing.port = port_num
                if has_exploit: existing.exploit = True
                if exploit_details: existing.exploit_details = exploit_details
                if cpe_list: existing.cpe = list(dict.fromkeys(existing.cpe + cpe_list))
            else:
                vulns_map[cve_id] = VulnInfo(
                    cve_id=cve_id,
                    cwe_id=cwe_id,
                    cpe=cpe_list[:10],
                    cvss=cvss,
                    cvss_v2=cvss_v2,
                    cvss_v3=cvss_v3,
                    severity=severity,
                    attack_vector=v.get("cvssv3_vector") or v.get("cvssv2_vector"),
                    affected_product=v.get("app_name"),
                    affected_vendor=v.get("vendor"),
                    summary=v.get("cve_description") or v.get("description"),
                    related_products=related_products[:10],
                    port=port_num,
                    exploit=has_exploit,
                    exploit_details=exploit_details,
                    sources=["criminalip"],
                )

        infra.vulnerabilities = list(vulns_map.values())
        infra.services_detail = list(services_map.values())
        infra.open_ports = sorted(list(set(infra.open_ports)))

        # Security Indicators Model
        infra.security = SecurityIndicators(
            abuse_record_count=1 if (is_snort or is_darkweb) else 0,
            user_search_count=int(report_data.get("user_search_count") or 0),
            honeypot_detected=bool(report_data.get("honeypot", {}).get("count") if isinstance(report_data.get("honeypot"), dict) else False),
            webcam_detected=bool(report_data.get("webcam", {}).get("count") if isinstance(report_data.get("webcam"), dict) else False),
            ids_alerts_count=ids_count,
            ids_alert_signatures=ids_signatures,
            vulnerabilities_count=len(infra.vulnerabilities),
            open_ports_count=len(infra.open_ports),
            invalid_ssl=False,
            admin_page_detected=bool(issues_dict.get("is_admin_page")),
            policy_violations=[],
            sources=["criminalip"],
        )

        # Threat Attribution
        infra.threat_attributions = threat_attributions
        if threat_attributions:
            infra.threat_attribution = threat_attributions[0]

        # Layer 3 Discovered IOCs
        discovered_iocs: List[DiscoveredIOC] = []
        seen_canonical: set[str] = {ioc_val.lower()}

        # 1. Connected domains
        dom_raw = report_data.get("domain") or report_data.get("connected_domain") or []
        dom_items = dom_raw.get("data", []) if isinstance(dom_raw, dict) else (dom_raw if isinstance(dom_raw, list) else [])
        for d in dom_items:
            d_val = d.get("domain") or d.get("url") if isinstance(d, dict) else (d if isinstance(d, str) else None)
            if d_val and isinstance(d_val, str):
                norm = normalize_ioc(d_val, IOCType.DOMAIN)
                if norm.is_valid and norm.canonical_value not in seen_canonical:
                    seen_canonical.add(norm.canonical_value)
                    discovered_iocs.append(
                        DiscoveredIOC(
                            raw_value=d_val,
                            canonical_value=norm.canonical_value,
                            ioc_type=IOCType.DOMAIN,
                            relationship_type="associated_domain",
                            confidence=score_val or 50.0,
                            evidence_desc="Criminal IP connected domain",
                            metadata={"provider": self.name, "relationship": "associated_domain"},
                        )
                    )

        # 2. Reverse DNS hostname
        if extracted_hostnames:
            infra.dns = DnsInfo(
                hostnames=extracted_hostnames,
                sources=["criminalip"],
            )
            for h in extracted_hostnames:
                norm = normalize_ioc(h, IOCType.DOMAIN)
                if norm.is_valid and norm.canonical_value not in seen_canonical:
                    seen_canonical.add(norm.canonical_value)
                    discovered_iocs.append(
                        DiscoveredIOC(
                            raw_value=h,
                            canonical_value=norm.canonical_value,
                            ioc_type=IOCType.DOMAIN,
                            relationship_type="resolves_to",
                            confidence=score_val or 50.0,
                            evidence_desc="Criminal IP PTR hostname",
                            metadata={"provider": self.name, "relationship": "resolves_to"},
                        )
                    )

        return ProviderResult(
            provider_name=self.name,
            ioc_value=ioc_val,
            ioc_type=ioc_type,
            status=ProviderStatus.SUCCESS,
            reputation_score=score_val,
            classification=classification,
            malicious_count=mal_count,
            suspicious_count=susp_count,
            harmless_count=harm_count,
            tags=tags[:15],
            threat_actors=[],
            malware_families=malware_families,
            infrastructure=infra,
            discovered_iocs=discovered_iocs,
            raw_data={"report": report_data, "malicious": malicious_data},
        )

    def _parse_domain_response(
        self,
        ioc_val: str,
        ioc_type: IOCType,
        data: Dict[str, Any],
    ) -> ProviderResult:
        is_malicious = bool(data.get("is_malicious"))
        is_phishing = bool(data.get("is_phishing"))
        tags: List[str] = []
        if is_malicious: tags.append("Malicious")
        if is_phishing: tags.append("Phishing")

        score = 85.0 if is_malicious else 60.0 if is_phishing else 10.0
        classification = "malicious" if is_malicious else "suspicious" if is_phishing else "benign"

        infra = InfrastructureData()
        discovered_iocs: List[DiscoveredIOC] = []
        seen_canonical: set[str] = {ioc_val.lower()}

        # Connected IPs / mapped IPs
        for ip in (data.get("connected_ip") or data.get("mapped_ip") or []):
            if ip and isinstance(ip, str):
                norm = normalize_ioc(ip, IOCType.IPV4 if ":" not in ip else IOCType.IPV6)
                if norm.is_valid and norm.canonical_value not in seen_canonical:
                    seen_canonical.add(norm.canonical_value)
                    discovered_iocs.append(
                        DiscoveredIOC(
                            raw_value=ip,
                            canonical_value=norm.canonical_value,
                            ioc_type=norm.ioc_type,
                            relationship_type="resolves_to",
                            confidence=score,
                            evidence_desc="Criminal IP connected IP",
                            metadata={"provider": self.name, "relationship": "resolves_to"},
                        )
                    )

        return ProviderResult(
            provider_name=self.name,
            ioc_value=ioc_val,
            ioc_type=ioc_type,
            status=ProviderStatus.SUCCESS,
            reputation_score=score,
            classification=classification,
            malicious_count=1 if is_malicious else 0,
            suspicious_count=1 if (is_phishing and not is_malicious) else 0,
            harmless_count=1 if classification == "benign" else 0,
            tags=tags,
            threat_actors=[],
            malware_families=[],
            infrastructure=infra,
            discovered_iocs=discovered_iocs,
            raw_data=data,
        )

    async def _execute_mock(self, ctx: ProviderRequestContext) -> ProviderResult:
        """Returns realistic mock data covering IP and Domain."""
        if ctx.ioc_type in (IOCType.IPV4, IOCType.IPV6):
            mock_report = {
                "ip": ctx.ioc_value,
                "asn": 16509,
                "as_name": "AMAZON-02",
                "org_name": "Amazon.com, Inc.",
                "isp": "Amazon Technologies Inc.",
                "country": "United States",
                "country_code": "US",
                "city": "Ashburn",
                "region": "Virginia",
                "postal_code": "20149",
                "latitude": 39.0438,
                "longitude": -77.4874,
                "hostname": f"ec2-host.{ctx.ioc_value}.compute-1.amazonaws.com",
                "score": {
                    "inbound": "Dangerous",
                    "outbound": "Critical",
                },
                "issues": {
                    "is_vpn": False,
                    "is_tor": True,
                    "is_proxy": True,
                    "is_cloud": True,
                    "is_hosting": True,
                    "is_mobile": False,
                    "is_scanner": False,
                    "is_darkweb": True,
                    "is_snort": True,
                },
                "user_search_count": 42,
                "ids": {
                    "count": 1,
                    "data": [{"signature": "ET SCAN Suspicious Inbound Port Scan"}],
                },
                "ip_category": {
                    "count": 2,
                    "data": [{"category": "tor"}, {"category": "proxy"}],
                },
                "vpn": {
                    "count": 0,
                    "data": [],
                },
                "whois": {
                    "count": 1,
                    "data": [
                        {
                            "as_name": "AMAZON-02",
                            "asn": 16509,
                            "org_name": "Amazon.com, Inc.",
                            "country": "United States",
                            "country_code": "US",
                            "city": "Ashburn",
                            "region": "Virginia",
                            "postal_code": "20149",
                            "latitude": 39.0438,
                            "longitude": -77.4874,
                            "registrar": "ARIN",
                            "creation_date": "1995-01-23",
                            "updated_date": "2023-08-11",
                        }
                    ],
                },
                "port": [
                    {
                        "port": 80,
                        "protocol": "tcp",
                        "app_name": "nginx",
                        "app_version": "1.18.0",
                        "banner": "HTTP/1.1 200 OK\r\nServer: nginx/1.18.0",
                        "cpe": ["cpe:2.3:a:igor_sysoev:nginx:1.18.0:*:*:*:*:*:*:*"],
                        "has_vulnerability": False,
                    },
                    {
                        "port": 443,
                        "protocol": "tcp",
                        "app_name": "OpenSSL",
                        "app_version": "1.1.1k",
                        "banner": "TLSv1.3 OpenSSL",
                        "cpe": ["cpe:2.3:a:openssl:openssl:1.1.1k:*:*:*:*:*:*:*"],
                        "has_vulnerability": True,
                        "vulnerability": [
                            {
                                "cve_id": "CVE-2021-44228",
                                "cvssv3_score": 10.0,
                                "description": "Apache Log4j2 JNDI features do not protect against attacker controlled LDAP.",
                            }
                        ],
                        "ssl": {
                            "subject_common_name": f"vpn.{ctx.ioc_value}.net",
                            "issuer_common_name": "Let's Encrypt Authority X3",
                            "valid_from": "2026-01-01",
                            "valid_to": "2026-04-01",
                        },
                    },
                    {
                        "port": 9001,
                        "protocol": "tcp",
                        "app_name": "Tor",
                        "app_version": "0.4.7",
                        "banner": "Tor Relay Service",
                        "cpe": ["cpe:2.3:a:torproject:tor:0.4.7:*:*:*:*:*:*:*"],
                        "has_vulnerability": False,
                    },
                ],
                "vulnerability": [
                    {
                        "cve_id": "CVE-2021-44228",
                        "cvssv3_score": 10.0,
                        "cvssv2_score": 9.3,
                        "cvssv3_vector": "NETWORK",
                        "app_name": "Log4j",
                        "vendor": "Apache",
                        "cve_description": "Apache Log4j2 JNDI features do not protect against attacker controlled LDAP.",
                        "list_cpe": ["cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*"],
                        "list_cwe": [{"cwe_id": 502, "cwe_name": "Deserialization of Untrusted Data"}],
                        "list_edb": [{"edb_id": "50592"}],
                        "open_port_no": [{"port": 443, "socket": "tcp"}],
                        "list_child": [{"app_name": "log4j-core", "app_version": "2.14.1", "vendor": "Apache"}],
                    }
                ],
                "connected_domain": [
                    {"domain": "darknet-service.org"},
                    {"domain": "tor-exit-node.net"},
                ],
            }
            mock_malicious = {
                "is_malicious": True,
                "is_vpn": False,
                "is_tor": True,
                "is_proxy": True,
                "is_cloud": True,
                "is_hosting": True,
                "is_scanner": False,
                "threat_category": ["TOR Exit Node", "C2 Infrastructure"],
            }
            return self._parse_ip_response(ctx.ioc_value, ctx.ioc_type, mock_report, mock_malicious)

        elif ctx.ioc_type == IOCType.DOMAIN:
            mock_domain = {
                "domain": ctx.ioc_value,
                "is_malicious": True,
                "is_phishing": True,
                "connected_ip": ["198.51.100.77", "203.0.113.88"],
            }
            return self._parse_domain_response(ctx.ioc_value, ctx.ioc_type, mock_domain)

        else:  # URL
            mock_domain = {
                "domain": ctx.ioc_value,
                "is_malicious": True,
                "is_phishing": False,
                "connected_ip": ["198.51.100.123"],
            }
            return self._parse_domain_response(ctx.ioc_value, ctx.ioc_type, mock_domain)
