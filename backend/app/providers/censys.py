import asyncio
import httpx
import re
import ipaddress
import urllib.parse
from typing import Dict, Any, List, Optional, Set, Tuple
from app.providers.base import BaseProvider, ProviderRequestContext
from app.schemas.ioc import IOCType, ProviderStatus
from app.schemas.provider import (
    ProviderCapability,
    ProviderResult,
    InfrastructureData,
    DiscoveredIOC,
    ProviderEvidence,
    NetworkInfo,
    GeoInfo,
    DnsInfo,
    DnsRecordItem,
    ServiceInfo,
    CertInfo,
    HttpInfo,
    TlsInfo,
    VulnInfo,
    WhoisInfo,
    TemporalInfo,
    CensysHostDetails,
)


def _is_ip(val: str) -> bool:
    try:
        ipaddress.ip_address(val.strip())
        return True
    except (ValueError, AttributeError):
        return False


def _safe_first(val: Any) -> Optional[str]:
    if val is None:
        return None
    if isinstance(val, list):
        for item in val:
            if item is not None and str(item).strip():
                return str(item).strip()
        return None
    s = str(val).strip()
    return s if s else None


def _safe_float(val: Any) -> Optional[float]:
    if val is None:
        return None
    try:
        return float(val)
    except (ValueError, TypeError):
        return None


def _normalize_http_server(val: Any) -> Optional[str]:
    if val is None:
        return None
    if isinstance(val, str):
        s = val.strip()
        return s if s else None
    if isinstance(val, dict):
        hdrs = val.get("headers")
        if isinstance(hdrs, list) and hdrs:
            first = _safe_first(hdrs)
            if first:
                return first
        for key in ("value", "server", "name", "description", "raw", "text"):
            if key in val and val[key]:
                res = _normalize_http_server(val[key])
                if res:
                    return res
        for sub_v in val.values():
            res = _normalize_http_server(sub_v)
            if res:
                return res
        return None
    if isinstance(val, (list, tuple, set)):
        return _safe_first(list(val))
    s = str(val).strip()
    return s if s else None


def _normalize_http_title(val: Any) -> Optional[str]:
    if val is None:
        return None
    if isinstance(val, str):
        s = val.strip()
        return s if s else None
    if isinstance(val, dict):
        for key in ("title", "html_title", "value", "text", "raw"):
            if key in val and val[key]:
                res = _normalize_http_title(val[key])
                if res:
                    return res
        for sub_v in val.values():
            res = _normalize_http_title(sub_v)
            if res:
                return res
        return None
    if isinstance(val, (list, tuple, set)):
        return _safe_first(list(val))
    s = str(val).strip()
    return s if s else None


def _extract_cve_id(v: Any) -> Optional[str]:
    if isinstance(v, str):
        s = v.strip().upper()
        if "CVE-" in s:
            m = re.search(r"CVE-\d{4}-\d+", s)
            if m:
                return m.group(0)
    elif isinstance(v, dict):
        for k in ("cve_id", "id", "cve", "name", "vulnerability_id", "vuln_id"):
            val = v.get(k)
            if val and isinstance(val, str):
                s = val.strip().upper()
                if "CVE-" in s:
                    m = re.search(r"CVE-\d{4}-\d+", s)
                    if m:
                        return m.group(0)
        for val in v.values():
            if isinstance(val, str) and "CVE-" in val.upper():
                m = re.search(r"CVE-\d{4}-\d+", val.upper())
                if m:
                    return m.group(0)
    return None


def _extract_cvss(v: Any) -> Optional[float]:
    if not isinstance(v, dict):
        return None
    raw = v.get("cvss")
    if raw is not None:
        if isinstance(raw, (int, float)):
            return float(raw)
        if isinstance(raw, str):
            try:
                return float(raw)
            except ValueError:
                pass
        if isinstance(raw, dict):
            for sk in ("score", "base_score", "cvss_score", "value"):
                if sk in raw and isinstance(raw[sk], (int, float, str)):
                    try:
                        return float(raw[sk])
                    except ValueError:
                        pass
    for sk in ("cvss_score", "cvss_v3", "cvss_v2", "base_score", "score"):
        if sk in v:
            val = v[sk]
            if isinstance(val, (int, float)):
                return float(val)
            if isinstance(val, str):
                try:
                    return float(val)
                except ValueError:
                    pass
            if isinstance(val, dict):
                score = val.get("score") or val.get("base_score")
                if score is not None:
                    try:
                        return float(score)
                    except ValueError:
                        pass
    return None


def _collect_censys_vulns(
    raw_vulns: Any,
    port: Optional[int] = None,
    default_product: Optional[str] = None,
    default_vendor: Optional[str] = None,
) -> Tuple[List[str], List[VulnInfo]]:
    cve_ids: List[str] = []
    items: List[VulnInfo] = []
    if not raw_vulns:
        return cve_ids, items

    if isinstance(raw_vulns, dict):
        if any(isinstance(k, str) and k.upper().startswith("CVE-") for k in raw_vulns.keys()):
            vuln_list = [{"cve_id": k, **(v if isinstance(v, dict) else {"cvss": v})} for k, v in raw_vulns.items()]
        elif "cves" in raw_vulns and isinstance(raw_vulns["cves"], list):
            vuln_list = raw_vulns["cves"]
        elif "vulnerabilities" in raw_vulns and isinstance(raw_vulns["vulnerabilities"], list):
            vuln_list = raw_vulns["vulnerabilities"]
        elif "vulns" in raw_vulns and isinstance(raw_vulns["vulns"], list):
            vuln_list = raw_vulns["vulns"]
        else:
            vuln_list = [raw_vulns]
    elif isinstance(raw_vulns, list):
        vuln_list = raw_vulns
    elif isinstance(raw_vulns, str):
        vuln_list = [raw_vulns]
    else:
        vuln_list = []

    for v in vuln_list:
        cve_id = _extract_cve_id(v)
        if not cve_id:
            continue
        cve_ids.append(cve_id)
        if isinstance(v, dict):
            cvss = _extract_cvss(v)
            cwe = v.get("cwe_id")
            if not cwe and v.get("cwe"):
                cwe_val = v.get("cwe")
                cwe = cwe_val[0] if isinstance(cwe_val, list) and cwe_val else str(cwe_val)
            severity = v.get("severity")
            if not severity and cvss is not None:
                severity = (
                    "CRITICAL" if cvss >= 9.0
                    else ("HIGH" if cvss >= 7.0
                    else ("MEDIUM" if cvss >= 4.0
                    else "LOW"))
                )
            prod = v.get("affected_product") or default_product
            vendor = v.get("affected_vendor") or default_vendor
            summary = v.get("summary") or v.get("description")
            refs = v.get("references", [])
            if not isinstance(refs, list):
                refs = [refs] if refs else []
            refs = [str(r) for r in refs if r]
            is_exploit = bool(v.get("in_kev") or v.get("kev") or v.get("cisa_kev") or v.get("known_exploited"))
            exploit_details = "Listed in CISA Known Exploited Vulnerabilities (KEV)" if is_exploit else None
            items.append(
                VulnInfo(
                    cve_id=cve_id,
                    cwe_id=cwe,
                    cvss=cvss,
                    severity=severity,
                    affected_product=prod,
                    affected_vendor=vendor,
                    summary=summary,
                    references=refs,
                    port=port,
                    exploit=is_exploit if is_exploit else None,
                    exploit_details=exploit_details,
                    sources=["censys"],
                )
            )
        else:
            items.append(
                VulnInfo(
                    cve_id=cve_id,
                    port=port,
                    affected_product=default_product,
                    affected_vendor=default_vendor,
                    sources=["censys"],
                )
            )
    return cve_ids, items


class CensysProvider(BaseProvider):
    @property
    def name(self) -> str:
        return "censys"

    @property
    def display_name(self) -> str:
        return "Censys"

    def get_capabilities(self) -> ProviderCapability:
        return ProviderCapability(
            name=self.name,
            display_name=self.display_name,
            description="Internet-wide scanning engine mapping exposed network hosts, services, banners, and TLS certificates via Censys Platform API (v3).",
            supported_iocs=[
                IOCType.IPV4,
                IOCType.IPV6,
                IOCType.DOMAIN,
                IOCType.URL,
            ],
            requires_auth=True,
            free_tier=True,
            rate_limit_desc="Censys Platform API (v3) with Personal Access Token (PAT)",
            provides_reputation=False,
            provides_infrastructure=True,
            provides_relationships=True,
            doc_url="https://docs.censys.com",
        )

    async def _execute_live(self, ctx: ProviderRequestContext) -> ProviderResult:
        base_url = "https://api.platform.censys.io/v3"

        # Censys Platform API (v3) uses Bearer Token (Personal Access Token)
        if ctx.api_secret and ctx.api_secret.startswith("censys_"):
            token = ctx.api_secret
        elif ctx.api_key and ctx.api_key.startswith("censys_"):
            token = ctx.api_key
        else:
            token = ctx.api_key or ctx.api_secret or ""
        token = token.strip()

        if not token:
            return ProviderResult(
                provider_name=self.name,
                ioc_value=ctx.ioc_value,
                ioc_type=ctx.ioc_type,
                status=ProviderStatus.NOT_CONFIGURED,
                error_details="Censys PAT token is not configured.",
            )

        target_val = ctx.ioc_value
        target_type = ctx.ioc_type
        if target_type == IOCType.URL:
            parsed = urllib.parse.urlparse(target_val)
            host = parsed.hostname or target_val.split("/")[0]
            target_val = host
            target_type = IOCType.IPV6 if ":" in host else (IOCType.IPV4 if _is_ip(host) else IOCType.DOMAIN)

        client = ctx.http_client or httpx.AsyncClient(timeout=ctx.timeout_seconds)
        should_close = ctx.http_client is None
        try:
            # 1. IP / Host (IPv4 / IPv6)
            if target_type in (IOCType.IPV4, IOCType.IPV6):
                endpoint = f"{base_url}/global/asset/host/{target_val}"
                headers = {
                    "Authorization": f"Bearer {token}",
                    "Accept": "application/vnd.censys.api.v3.host.v1+json",
                }
                resp = await client.get(endpoint, headers=headers)

                if resp.status_code == 404:
                    return ProviderResult(
                        provider_name=self.name,
                        ioc_value=ctx.ioc_value,
                        ioc_type=ctx.ioc_type,
                        status=ProviderStatus.NOT_FOUND,
                        raw_data=resp.json() if resp.headers.get("content-type", "").startswith("application/json") else None,
                    )
                if resp.status_code == 401:
                    return ProviderResult(
                        provider_name=self.name,
                        ioc_value=ctx.ioc_value,
                        ioc_type=ctx.ioc_type,
                        status=ProviderStatus.UNAUTHORIZED,
                        error_details="Invalid Censys PAT token.",
                    )
                if resp.status_code == 403:
                    return ProviderResult(
                        provider_name=self.name,
                        ioc_value=ctx.ioc_value,
                        ioc_type=ctx.ioc_type,
                        status=ProviderStatus.FORBIDDEN,
                        error_details="Censys API access forbidden or plan restricted.",
                    )
                if resp.status_code == 429:
                    return ProviderResult(
                        provider_name=self.name,
                        ioc_value=ctx.ioc_value,
                        ioc_type=ctx.ioc_type,
                        status=ProviderStatus.RATE_LIMITED,
                        error_details="Censys API rate limit exceeded.",
                    )
                if resp.status_code == 422:
                    err_msg = "insufficient balance"
                    try:
                        err_json = resp.json()
                        errors = err_json.get("errors", [])
                        if errors and isinstance(errors[0], dict):
                            err_msg = errors[0].get("message", err_msg)
                    except Exception:
                        err_json = None
                    return ProviderResult(
                        provider_name=self.name,
                        ioc_value=ctx.ioc_value,
                        ioc_type=ctx.ioc_type,
                        status=ProviderStatus.RATE_LIMITED,
                        error_details=f"Censys API quota/balance exhausted: {err_msg}.",
                        raw_data=err_json,
                    )

                resp.raise_for_status()
                try:
                    data = resp.json()
                except Exception:
                    return ProviderResult(
                        provider_name=self.name,
                        ioc_value=ctx.ioc_value,
                        ioc_type=ctx.ioc_type,
                        status=ProviderStatus.INVALID_RESPONSE,
                        error_details="Failed to decode JSON from Censys response.",
                    )

                return self._parse_host_response(ctx, data)

            # 2. Domain / FQDN (Web Properties)
            elif target_type == IOCType.DOMAIN:
                headers = {
                    "Authorization": f"Bearer {token}",
                    "Accept": "application/vnd.censys.api.v3.webproperty.v1+json",
                }
                ports = [443, 80]
                tasks = [
                    client.get(f"{base_url}/global/asset/webproperty/{target_val}:{p}", headers=headers)
                    for p in ports
                ]
                responses = await asyncio.gather(*tasks, return_exceptions=True)

                valid_wp_resources: List[Dict[str, Any]] = []
                raw_responses: Dict[str, Any] = {}
                status_codes: List[int] = []

                for p, r in zip(ports, responses):
                    if isinstance(r, Exception):
                        continue
                    status_codes.append(r.status_code)
                    if r.status_code == 200:
                        try:
                            wp_json = r.json()
                            raw_responses[str(p)] = wp_json
                            res = wp_json.get("result", {}).get("resource", {})
                            # Verify resource contains actual observed data
                            if any(k in res for k in ("scan_time", "endpoints", "cert", "software", "tls", "labels", "vulnerabilities")):
                                valid_wp_resources.append(res)
                        except Exception:
                            pass

                if not valid_wp_resources:
                    if any(s == 401 for s in status_codes):
                        return ProviderResult(
                            provider_name=self.name,
                            ioc_value=ctx.ioc_value,
                            ioc_type=ctx.ioc_type,
                            status=ProviderStatus.UNAUTHORIZED,
                            error_details="Invalid Censys PAT token.",
                        )
                    if any(s == 403 for s in status_codes):
                        return ProviderResult(
                            provider_name=self.name,
                            ioc_value=ctx.ioc_value,
                            ioc_type=ctx.ioc_type,
                            status=ProviderStatus.FORBIDDEN,
                            error_details="Censys API access forbidden or plan restricted.",
                        )
                    if any(s == 429 for s in status_codes):
                        return ProviderResult(
                            provider_name=self.name,
                            ioc_value=ctx.ioc_value,
                            ioc_type=ctx.ioc_type,
                            status=ProviderStatus.RATE_LIMITED,
                            error_details="Censys API rate limit exceeded.",
                        )
                    if any(s == 422 for s in status_codes):
                        return ProviderResult(
                            provider_name=self.name,
                            ioc_value=ctx.ioc_value,
                            ioc_type=ctx.ioc_type,
                            status=ProviderStatus.RATE_LIMITED,
                            error_details="Censys API quota/balance exhausted: insufficient balance.",
                            raw_data=raw_responses or None,
                        )
                    return ProviderResult(
                        provider_name=self.name,
                        ioc_value=ctx.ioc_value,
                        ioc_type=ctx.ioc_type,
                        status=ProviderStatus.NOT_FOUND,
                        raw_data=raw_responses or None,
                    )

                return self._parse_domain_response(ctx, valid_wp_resources, raw_responses)

            # 3. Unsupported Types (Hashes, etc.)
            else:
                return ProviderResult(
                    provider_name=self.name,
                    ioc_value=ctx.ioc_value,
                    ioc_type=ctx.ioc_type,
                    status=ProviderStatus.UNSUPPORTED,
                    error_details="Censys provider supports IPv4, IPv6, Domain, and URL IOCs only.",
                )

        finally:
            if should_close:
                await client.aclose()

    def _parse_host_response(self, ctx: ProviderRequestContext, data: Dict[str, Any]) -> ProviderResult:
        if not data or not isinstance(data, dict):
            return ProviderResult(
                provider_name=self.name,
                ioc_value=ctx.ioc_value,
                ioc_type=ctx.ioc_type,
                status=ProviderStatus.NOT_FOUND,
                raw_data=data,
            )

        # 1. Resolve host container: Platform API v3 nests under result.resource; v2 under result
        result = data.get("result", {})
        if not isinstance(result, dict):
            result = {}

        resource = result.get("resource", {})
        if not isinstance(resource, dict):
            resource = {}

        host_data = resource if resource else result
        if not host_data and "hits" in result:
            hits = result.get("hits", [])
            if hits and isinstance(hits[0], dict):
                host_data = hits[0]

        if not host_data:
            return ProviderResult(
                provider_name=self.name,
                ioc_value=ctx.ioc_value,
                ioc_type=ctx.ioc_type,
                status=ProviderStatus.NOT_FOUND,
                raw_data=data,
            )

        # 2. Extract Identity & Host Labels
        ip_val = host_data.get("ip") or ctx.ioc_value
        host_labels = host_data.get("labels", []) if isinstance(host_data.get("labels"), list) else []
        service_count = host_data.get("service_count")
        os_info = host_data.get("operating_system")

        # 3. Extract Geolocation
        loc = host_data.get("location", {}) if isinstance(host_data.get("location"), dict) else {}
        country = loc.get("country")
        country_code = loc.get("country_code")
        region = loc.get("province") or loc.get("region")
        city = loc.get("city")
        postal_code = loc.get("postal_code")
        timezone = loc.get("timezone")
        coords = loc.get("coordinates", {}) if isinstance(loc.get("coordinates"), dict) else {}
        latitude = None
        if coords.get("latitude") is not None:
            try:
                latitude = float(coords["latitude"])
            except (ValueError, TypeError):
                latitude = None
        longitude = None
        if coords.get("longitude") is not None:
            try:
                longitude = float(coords["longitude"])
            except (ValueError, TypeError):
                longitude = None

        geo_model = GeoInfo(
            country=country,
            country_code=country_code,
            region=region,
            city=city,
            postal_code=postal_code,
            continent=loc.get("continent"),
            timezone=timezone,
            latitude=latitude,
            longitude=longitude,
            sources=["censys"],
        ) if (country or city or region or coords or loc.get("continent")) else None

        # 4. Extract Network & ASN Routing
        asn_obj = host_data.get("autonomous_system", {}) if isinstance(host_data.get("autonomous_system"), dict) else {}
        asn_val = str(asn_obj.get("asn")) if asn_obj.get("asn") else None
        asn_name = asn_obj.get("name") or asn_obj.get("description")
        bgp_prefix = asn_obj.get("bgp_prefix") or host_data.get("routed_prefix")

        whois_obj = host_data.get("whois", {}) if isinstance(host_data.get("whois"), dict) else {}
        whois_net = whois_obj.get("network", {}) if isinstance(whois_obj.get("network"), dict) else {}
        whois_org = whois_obj.get("organization", {}) if isinstance(whois_obj.get("organization"), dict) else {}
        net_name = whois_net.get("name")
        org_name = whois_org.get("name") or net_name or asn_name
        cidrs = whois_net.get("cidrs", []) if isinstance(whois_net.get("cidrs"), list) else []
        cidr_val = cidrs[0] if cidrs else bgp_prefix

        network_model = NetworkInfo(
            ip=ip_val,
            ip_version="IPv4" if ctx.ioc_type == IOCType.IPV4 else ("IPv6" if ctx.ioc_type == IOCType.IPV6 else None),
            asn=asn_val,
            asn_name=asn_name,
            cidr=cidr_val,
            org=org_name,
            bgp_prefix=bgp_prefix,
            sources=["censys"],
        ) if (asn_val or asn_name or cidr_val or org_name or bgp_prefix) else None

        whois_model = WhoisInfo(
            registrant_org=whois_org.get("name") or whois_net.get("name"),
            registrar=whois_net.get("handle"),
            sources=["censys"],
        ) if (whois_org.get("name") or whois_net.get("name") or whois_net.get("handle")) else None

        # 5. Extract DNS & Hostnames
        dns_obj = host_data.get("dns", {}) if isinstance(host_data.get("dns"), dict) else {}
        dns_reverse = dns_obj.get("reverse_dns", {}) if isinstance(dns_obj.get("reverse_dns"), dict) else {}
        reverse_names = dns_reverse.get("names", []) if isinstance(dns_reverse.get("names"), list) else []
        forward_obj = dns_obj.get("forward_dns", {}) if isinstance(dns_obj.get("forward_dns"), dict) else {}
        forward_names = forward_obj.get("names", []) if isinstance(forward_obj.get("names"), list) else []
        raw_names = dns_obj.get("names", []) if isinstance(dns_obj.get("names"), list) else []

        all_dns_names: List[str] = []
        for n in reverse_names + forward_names + raw_names:
            clean_n = str(n).strip()
            if clean_n and not _is_ip(clean_n) and clean_n not in all_dns_names:
                all_dns_names.append(clean_n)

        primary_ptr = str(reverse_names[0]).strip() if (reverse_names and not _is_ip(str(reverse_names[0]))) else None
        dns_record_items: List[DnsRecordItem] = []
        if primary_ptr:
            dns_record_items.append(DnsRecordItem(record_type="PTR", value=primary_ptr, sources=["censys"]))
        for r_name in reverse_names:
            clean_r = str(r_name).strip()
            if clean_r and not _is_ip(clean_r) and clean_r != primary_ptr:
                dns_record_items.append(DnsRecordItem(record_type="PTR", value=clean_r, sources=["censys"]))

        dns_model = DnsInfo(
            hostnames=all_dns_names,
            domains=[n for n in all_dns_names if not n.startswith("*")],
            records=dns_record_items,
            sources=["censys"],
        ) if all_dns_names else None

        # 6. Extract Services (ALL returned services, zero slicing)
        services_raw = host_data.get("services", [])
        open_ports: List[int] = []
        services_legacy = []
        services_detail: List[ServiceInfo] = []
        certificates_legacy = []
        certificates_detail: List[CertInfo] = []
        vulns_detail: List[VulnInfo] = []
        discovered: List[DiscoveredIOC] = []
        seen_discovered: Set[str] = set()

        http_server_found: Optional[str] = None
        http_title_found: Optional[str] = None
        http_status_found: Optional[int] = None
        http_headers_found: Dict[str, str] = {}
        http_technologies: List[str] = []
        all_tls_versions: List[str] = []
        all_ciphers: List[str] = []
        all_jarm: Optional[str] = None

        for s in services_raw:
            port = s.get("port")
            svc_name = s.get("protocol") or s.get("service_name") or s.get("extended_service_name")
            transport = (s.get("transport_protocol") or "tcp").lower()
            banner = s.get("banner_hex") or s.get("banner")
            scan_time = s.get("scan_time")

            # Extract software & technology list
            software_raw = s.get("software", []) if isinstance(s.get("software"), list) else []
            software_names: List[str] = []
            software_cpes: List[str] = []
            for sw in software_raw:
                if isinstance(sw, dict):
                    prod = sw.get("product")
                    vendor = sw.get("vendor")
                    ver = sw.get("version")
                    cpe_str = sw.get("cpe") or sw.get("cpe23")
                    if cpe_str and cpe_str not in software_cpes:
                        software_cpes.append(cpe_str)
                    name_parts = [p for p in (vendor, prod, ver) if p]
                    if name_parts:
                        full_name = " ".join(str(p) for p in name_parts)
                        if full_name not in software_names:
                            software_names.append(full_name)

            # Check HTTP in service directly or within endpoints
            http_obj = s.get("http", {}) if isinstance(s.get("http"), dict) else {}
            http_resp = http_obj.get("response", {}) if isinstance(http_obj.get("response"), dict) else {}
            http_title = _normalize_http_title(http_resp.get("html_title"))
            http_headers = http_resp.get("headers", {}) if isinstance(http_resp.get("headers"), dict) else {}
            http_server = _normalize_http_server(http_headers.get("Server") or http_headers.get("server"))
            http_code = http_resp.get("status_code")

            # If not in service root, inspect endpoints
            endpoints_raw = s.get("endpoints", []) if isinstance(s.get("endpoints"), list) else []
            for ep in endpoints_raw:
                ep_http = ep.get("http", {}) if isinstance(ep.get("http"), dict) else {}
                ep_resp = ep_http.get("response", {}) if isinstance(ep_http.get("response"), dict) else ep_http
                if not http_title and ep_resp.get("html_title"):
                    http_title = _normalize_http_title(ep_resp.get("html_title"))
                if not http_server:
                    ep_headers = ep_resp.get("headers", {}) if isinstance(ep_resp.get("headers"), dict) else {}
                    http_server = _normalize_http_server(ep_headers.get("Server") or ep_headers.get("server"))
                if http_code is None and ep_resp.get("status_code"):
                    http_code = ep_resp.get("status_code")
                # Extract URL if endpoint provides an explicit URI
                ep_uri = ep_http.get("uri")
                if ep_uri and isinstance(ep_uri, str) and ep_uri.startswith(("http://", "https://")):
                    if ep_uri not in seen_discovered and ep_uri != ctx.ioc_value:
                        seen_discovered.add(ep_uri)
                        discovered.append(
                            DiscoveredIOC(
                                raw_value=ep_uri,
                                canonical_value=ep_uri,
                                ioc_type=IOCType.URL,
                                relationship_type="exposes_url",
                                confidence=80.0,
                                evidence_desc=f"Censys HTTP service endpoint on port {port}",
                            )
                        )

            if http_server and not http_server_found:
                http_server_found = http_server
            if http_title and not http_title_found:
                http_title_found = http_title
            if http_code is not None and http_status_found is None:
                http_status_found = http_code
            if http_headers and not http_headers_found:
                clean_hdrs = {}
                for k, v in http_headers.items():
                    if k and v is not None:
                        clean_v = _normalize_http_server(v) if isinstance(v, (dict, list)) else str(v)
                        if clean_v:
                            clean_hdrs[str(k)] = clean_v
                http_headers_found = clean_hdrs
            for sn in software_names:
                if sn not in http_technologies:
                    http_technologies.append(sn)

            # Software details
            sw_first = software_raw[0] if (software_raw and isinstance(software_raw[0], dict)) else {}
            sw_prod = sw_first.get("product") or (software_names[0] if software_names else None)
            sw_vendor = sw_first.get("vendor")
            sw_ver = sw_first.get("version")

            # Vulnerabilities attached to service or nested under software
            service_cve_ids: List[str] = []
            raw_svc_vulns = s.get("vulnerabilities") or s.get("vulns") or s.get("threat_intel", {}).get("vulnerabilities")
            if raw_svc_vulns:
                cids, vitems = _collect_censys_vulns(raw_svc_vulns, port=port, default_product=sw_prod, default_vendor=sw_vendor)
                for cid in cids:
                    if cid not in service_cve_ids:
                        service_cve_ids.append(cid)
                for vi in vitems:
                    if not any(x.cve_id == vi.cve_id and x.port == vi.port for x in vulns_detail):
                        vulns_detail.append(vi)

            for sw in software_raw:
                if isinstance(sw, dict):
                    sw_v = sw.get("vulnerabilities") or sw.get("vulns")
                    if sw_v:
                        cids, vitems = _collect_censys_vulns(sw_v, port=port, default_product=sw.get("product") or sw_prod, default_vendor=sw.get("vendor") or sw_vendor)
                        for cid in cids:
                            if cid not in service_cve_ids:
                                service_cve_ids.append(cid)
                        for vi in vitems:
                            if not any(x.cve_id == vi.cve_id and x.port == vi.port for x in vulns_detail):
                                vulns_detail.append(vi)

            tls_obj = s.get("tls", {}) if isinstance(s.get("tls"), dict) else {}
            svc_tls_ver = tls_obj.get("version")
            svc_cipher = tls_obj.get("cipher_suite")
            svc_ja3s = tls_obj.get("ja3s")
            svc_jarm = tls_obj.get("jarm")
            svc_alpn = tls_obj.get("alpn") if isinstance(tls_obj.get("alpn"), list) else ([tls_obj["alpn"]] if tls_obj.get("alpn") else [])
            svc_devtype = s.get("device_type") or host_data.get("device_type")

            if svc_tls_ver and svc_tls_ver not in all_tls_versions:
                all_tls_versions.append(svc_tls_ver)
            if svc_cipher and svc_cipher not in all_ciphers:
                all_ciphers.append(svc_cipher)
            if svc_jarm and not all_jarm:
                all_jarm = svc_jarm

            if port:
                open_ports.append(port)
                services_legacy.append({
                    "port": port,
                    "service_name": svc_name,
                    "banner": banner[:120] if banner else None,
                })
                services_detail.append(
                    ServiceInfo(
                        port=port,
                        transport=transport,
                        protocol=svc_name,
                        service_name=svc_name,
                        product=sw_prod,
                        version=sw_ver,
                        vendor=sw_vendor,
                        devicetype=svc_devtype,
                        cpe=software_cpes,
                        banner=banner[:500] if banner else None,
                        http_title=http_title,
                        http_server=http_server,
                        http_status=http_code,
                        tls_version=svc_tls_ver,
                        cipher=svc_cipher,
                        ja3s=svc_ja3s,
                        jarm=svc_jarm,
                        alpn=svc_alpn,
                        vulnerabilities=service_cve_ids,
                        scan_time=scan_time,
                        sources=["censys"],
                    )
                )

            # Check TLS certificate: in v3 under "cert", in v2 under "certificate"
            cert = s.get("cert") or s.get("certificate")
            if isinstance(cert, dict):
                fp = cert.get("fingerprint_sha256")
                names = cert.get("names", []) if isinstance(cert.get("names"), list) else []
                parsed = cert.get("parsed", {}) if isinstance(cert.get("parsed"), dict) else {}

                subj = parsed.get("subject", {}) or cert.get("subject", {})
                subj_cn = _safe_first(subj.get("common_name")) if isinstance(subj, dict) else None
                subj_org = _safe_first(subj.get("organization")) if isinstance(subj, dict) else None

                iss = parsed.get("issuer", {}) or cert.get("issuer", {})
                iss_cn = _safe_first(iss.get("common_name")) if isinstance(iss, dict) else None
                iss_org = _safe_first(iss.get("organization")) if isinstance(iss, dict) else None

                val = parsed.get("validity_period", {}) or cert.get("validity", {})
                valid_from = val.get("not_before") or val.get("start")
                valid_to = val.get("not_after") or val.get("end")

                serial = str(parsed.get("serial_number") or cert.get("serial_number") or "") or None

                tls_versions = [svc_tls_ver] if svc_tls_ver else []
                ciphers = [svc_cipher] if svc_cipher else []
                sig_alg = parsed.get("signature", {}).get("signature_algorithm") or cert.get("signature_algorithm")

                certificates_legacy.append({"fingerprint": fp, "names": names})
                certificates_detail.append(
                    CertInfo(
                        fingerprint_sha256=fp,
                        subject_cn=subj_cn,
                        subject_org=subj_org,
                        issuer_cn=iss_cn,
                        issuer_org=iss_org,
                        sans=names,
                        valid_from=valid_from,
                        valid_to=valid_to,
                        serial_number=serial,
                        tls_versions=tls_versions,
                        ciphers=ciphers,
                        ja3s=svc_ja3s,
                        jarm=svc_jarm,
                        sig_alg=sig_alg,
                        port=port,
                        protocol=svc_name,
                        service_name=svc_name,
                        observation_time=scan_time,
                        sources=["censys"],
                    )
                )

                # Extract SANs as Layer 3 domain or IP IOCs (NOT file hash)
                for name in names:
                    if not name or name == ctx.ioc_value:
                        continue
                    clean_name = str(name).strip()
                    # Check if IP address or domain
                    is_ip_san = any(c.isdigit() for c in clean_name) and ("." in clean_name or ":" in clean_name) and not any(c in clean_name for c in ("*", "a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m", "n", "o", "p", "q", "r", "s", "t", "u", "v", "w", "x", "y", "z"))
                    san_type = IOCType.IPV4 if (is_ip_san and "." in clean_name) else (IOCType.IPV6 if (is_ip_san and ":" in clean_name) else IOCType.DOMAIN)
                    canon_val = clean_name.lower().rstrip(".")
                    key = f"{san_type}:{canon_val}"
                    if key not in seen_discovered and canon_val != ctx.ioc_value:
                        seen_discovered.add(key)
                        discovered.append(
                            DiscoveredIOC(
                                raw_value=clean_name,
                                canonical_value=canon_val,
                                ioc_type=san_type,
                                relationship_type="shares_certificate",
                                confidence=85.0,
                                evidence_desc=f"Censys certificate SAN on port {port}",
                            )
                        )

        # 7. Add DNS Hostnames as Layer 3 Discovered IOCs
        for name in all_dns_names:
            clean_d = name.strip().lower().rstrip(".")
            key = f"domain:{clean_d}"
            if clean_d and key not in seen_discovered and clean_d != ctx.ioc_value:
                seen_discovered.add(key)
                discovered.append(
                    DiscoveredIOC(
                        raw_value=name,
                        canonical_value=clean_d,
                        ioc_type=IOCType.DOMAIN,
                        relationship_type="has_hostname",
                        confidence=85.0,
                        evidence_desc="Censys reverse/forward DNS hostname",
                    )
                )

        # 8. Host-level Vulnerabilities (if any)
        host_vulns_raw = host_data.get("vulnerabilities") or host_data.get("vulns")
        if host_vulns_raw:
            cids, vitems = _collect_censys_vulns(host_vulns_raw)
            for vi in vitems:
                if not any(x.cve_id == vi.cve_id for x in vulns_detail):
                    vulns_detail.append(vi)

        # 9. HTTP Model
        http_model = HttpInfo(
            server=http_server_found,
            title=http_title_found,
            status_code=http_status_found,
            headers=http_headers_found,
            technologies=http_technologies,
            sources=["censys"],
        ) if (http_server_found or http_title_found or http_status_found is not None) else None

        # 10. TLS Model
        tls_model = TlsInfo(
            supported_versions=all_tls_versions,
            ciphers=all_ciphers,
            jarm=all_jarm,
            sources=["censys"],
        ) if (all_tls_versions or all_ciphers or all_jarm) else None

        # 11. Temporal Info
        last_observed = host_data.get("last_observed_at") or (services_raw[0].get("scan_time") if (services_raw and isinstance(services_raw[0], dict)) else None)
        temporal_model = TemporalInfo(
            last_scan=last_observed,
            sources=["censys"],
        ) if last_observed else None

        # 12. Structured Censys Details Model
        os_str = None
        if isinstance(os_info, dict):
            parts = [os_info.get("vendor"), os_info.get("product"), os_info.get("version")]
            os_str = " ".join(str(p) for p in parts if p) or None
        elif os_info:
            os_str = str(os_info)

        censys_details_model = CensysHostDetails(
            ip=ip_val,
            hostname=primary_ptr,
            autonomous_system=asn_obj,
            asn=asn_val,
            asn_name=asn_name,
            bgp_prefix=bgp_prefix,
            location=loc,
            continent=loc.get("continent"),
            country=country,
            country_code=country_code,
            city=city,
            region=region,
            postal_code=postal_code,
            timezone=timezone,
            coordinates=coords,
            latitude=latitude,
            longitude=longitude,
            os=os_str,
            host_labels=host_labels,
            service_count=service_count or len(services_detail),
            total_vulns=len(vulns_detail),
            dns_names=all_dns_names,
            last_observed_at=last_observed,
            sources=["censys"],
        )

        # 13. Extra Metadata
        extra_data = {
            "censys": {
                "host_labels": host_labels,
                "service_count": service_count or len(services_detail),
                "operating_system": os_info,
                "routed_prefix": host_data.get("routed_prefix"),
                "autonomous_system": asn_obj,
                "location": loc,
                "whois": whois_obj,
            }
        }

        infra = InfrastructureData(
            asn=asn_val,
            asn_name=asn_name,
            org=org_name,
            country=country,
            region=region,
            city=city,
            cidr=cidr_val,
            ptr=primary_ptr,
            open_ports=sorted(list(set(open_ports))),
            services=services_legacy,
            certificates=certificates_legacy,
            http_server=http_server_found,
            http_title=http_title_found,
            extra=extra_data,
            network=network_model,
            geo=geo_model,
            dns=dns_model,
            whois=whois_model,
            services_detail=services_detail,
            certificates_detail=certificates_detail,
            http=http_model,
            tls=tls_model,
            vulnerabilities=vulns_detail,
            temporal=temporal_model,
            censys_details=censys_details_model,
        )

        evidences = [
            ProviderEvidence(
                provider_name=self.name,
                evidence_type="exposed_services",
                description=f"Censys indexed {len(open_ports)} exposed ports, {len(certificates_detail)} TLS certificates, and {len(discovered)} related IOCs.",
                confidence=85.0,
            )
        ]

        return ProviderResult(
            provider_name=self.name,
            ioc_value=ctx.ioc_value,
            ioc_type=ctx.ioc_type,
            status=ProviderStatus.SUCCESS,
            classification=None,
            reputation_score=None,
            malicious_count=0,
            suspicious_count=0,
            harmless_count=0,
            infrastructure=infra,
            discovered_iocs=discovered,
            evidences=evidences,
            raw_data=data,
        )

    def _parse_domain_response(
        self,
        ctx: ProviderRequestContext,
        web_properties: List[Dict[str, Any]],
        raw_data: Any,
    ) -> ProviderResult:
        open_ports: List[int] = []
        services_legacy = []
        services_detail: List[ServiceInfo] = []
        certificates_legacy = []
        certificates_detail: List[CertInfo] = []
        vulns_detail: List[VulnInfo] = []
        discovered: List[DiscoveredIOC] = []
        seen_discovered: Set[str] = set()

        resolved_ipv4s: List[str] = []
        resolved_ipv6s: List[str] = []

        all_tls_versions: List[str] = []
        all_ciphers: List[str] = []
        all_labels: List[str] = []

        primary_http_server: Optional[str] = None
        primary_http_title: Optional[str] = None
        primary_status_code: Optional[int] = None
        primary_headers: Dict[str, str] = {}
        all_technologies: List[str] = []
        latest_scan_time: Optional[str] = None

        primary_asn: Optional[str] = None
        primary_asn_name: Optional[str] = None
        primary_org: Optional[str] = None
        primary_country: Optional[str] = None
        primary_city: Optional[str] = None
        primary_region: Optional[str] = None
        primary_geo: Optional[GeoInfo] = None

        wp_summaries = []

        for wp in web_properties:
            port = wp.get("port")
            hostname = wp.get("hostname") or ctx.ioc_value
            scan_time = wp.get("scan_time")
            if scan_time and (not latest_scan_time or scan_time > latest_scan_time):
                latest_scan_time = scan_time

            for lbl in wp.get("labels", []) if isinstance(wp.get("labels"), list) else []:
                if lbl and lbl not in all_labels:
                    all_labels.append(str(lbl))

            proto = "HTTPS" if port == 443 else ("HTTP" if port == 80 else f"HTTP/{port}")
            if port:
                open_ports.append(port)

            # Software
            software_raw = wp.get("software", []) if isinstance(wp.get("software"), list) else []
            sw_names: List[str] = []
            sw_cpes: List[str] = []
            for sw in software_raw:
                if isinstance(sw, dict):
                    prod = sw.get("product")
                    vendor = sw.get("vendor")
                    ver = sw.get("version")
                    cpe_str = sw.get("cpe") or sw.get("cpe23")
                    if cpe_str and cpe_str not in sw_cpes:
                        sw_cpes.append(cpe_str)
                    name_parts = [p for p in (vendor, prod, ver) if p]
                    if name_parts:
                        full_name = " ".join(str(p) for p in name_parts)
                        if full_name not in sw_names:
                            sw_names.append(full_name)
                        if full_name not in all_technologies:
                            all_technologies.append(full_name)

            first_sw = software_raw[0] if software_raw and isinstance(software_raw[0], dict) else {}
            sw_prod = first_sw.get("product") or (sw_names[0] if sw_names else None)
            sw_ver = first_sw.get("version")
            sw_vendor = first_sw.get("vendor")

            # Endpoints
            endpoints_raw = wp.get("endpoints", []) if isinstance(wp.get("endpoints"), list) else []
            wp_title: Optional[str] = None
            wp_server: Optional[str] = None
            wp_status: Optional[int] = None

            for ep in endpoints_raw:
                ep_ip = ep.get("ip")
                if ep_ip and isinstance(ep_ip, str):
                    clean_ip = ep_ip.strip()
                    if ":" in clean_ip and clean_ip not in resolved_ipv6s:
                        resolved_ipv6s.append(clean_ip)
                        key = f"ipv6:{clean_ip}"
                        if key not in seen_discovered:
                            seen_discovered.add(key)
                            discovered.append(
                                DiscoveredIOC(
                                    raw_value=clean_ip,
                                    canonical_value=clean_ip.lower(),
                                    ioc_type=IOCType.IPV6,
                                    relationship_type="resolves_to",
                                    confidence=90.0,
                                    evidence_desc=f"Censys web property endpoint IPv6 on port {port}",
                                )
                            )
                    elif "." in clean_ip and clean_ip not in resolved_ipv4s:
                        resolved_ipv4s.append(clean_ip)
                        key = f"ipv4:{clean_ip}"
                        if key not in seen_discovered:
                            seen_discovered.add(key)
                            discovered.append(
                                DiscoveredIOC(
                                    raw_value=clean_ip,
                                    canonical_value=clean_ip,
                                    ioc_type=IOCType.IPV4,
                                    relationship_type="resolves_to",
                                    confidence=90.0,
                                    evidence_desc=f"Censys web property endpoint IP on port {port}",
                                )
                            )

                # HTTP in endpoint
                ep_http = ep.get("http", {}) if isinstance(ep.get("http"), dict) else {}
                ep_resp = ep_http.get("response", {}) if isinstance(ep_http.get("response"), dict) else ep_http
                if not wp_title and ep_resp.get("html_title"):
                    wp_title = _normalize_http_title(ep_resp.get("html_title"))
                if not wp_server:
                    ep_headers = ep_resp.get("headers", {}) if isinstance(ep_resp.get("headers"), dict) else {}
                    wp_server = _normalize_http_server(ep_headers.get("Server") or ep_headers.get("server"))
                if wp_status is None and ep_resp.get("status_code"):
                    wp_status = ep_resp.get("status_code")

                # Endpoint URI
                ep_uri = ep_http.get("uri")
                if ep_uri and isinstance(ep_uri, str) and ep_uri.startswith(("http://", "https://")):
                    key = f"url:{ep_uri}"
                    if key not in seen_discovered:
                        seen_discovered.add(key)
                        discovered.append(
                            DiscoveredIOC(
                                raw_value=ep_uri,
                                canonical_value=ep_uri,
                                ioc_type=IOCType.URL,
                                relationship_type="hosts_url",
                                confidence=85.0,
                                evidence_desc=f"Censys web property URI on port {port}",
                            )
                        )

                # Geolocation and ASN from endpoint if available
                ep_loc = ep.get("location", {}) if isinstance(ep.get("location"), dict) else {}
                if ep_loc and not primary_country and ep_loc.get("country"):
                    primary_country = ep_loc.get("country")
                    primary_city = ep_loc.get("city")
                    primary_region = ep_loc.get("province") or ep_loc.get("region")
                    coords = ep_loc.get("coordinates", {}) if isinstance(ep_loc.get("coordinates"), dict) else {}
                    primary_geo = GeoInfo(
                        country=primary_country,
                        country_code=ep_loc.get("country_code"),
                        region=primary_region,
                        city=primary_city,
                        latitude=_safe_float(coords.get("latitude")),
                        longitude=_safe_float(coords.get("longitude")),
                        timezone=ep_loc.get("timezone"),
                        sources=["censys"],
                    )

                ep_asn = ep.get("autonomous_system", {}) if isinstance(ep.get("autonomous_system"), dict) else {}
                if ep_asn and not primary_asn and ep_asn.get("asn"):
                    primary_asn = str(ep_asn.get("asn"))
                    primary_asn_name = ep_asn.get("name") or ep_asn.get("description")
                    primary_org = primary_asn_name

            if wp_server and not primary_http_server:
                primary_http_server = wp_server
            if wp_title and not primary_http_title:
                primary_http_title = wp_title
            if wp_status is not None and primary_status_code is None:
                primary_status_code = wp_status

            tls_obj = wp.get("tls", {}) if isinstance(wp.get("tls"), dict) else {}
            wp_tls_ver = tls_obj.get("version")
            wp_cipher = tls_obj.get("cipher_suite")
            if wp_tls_ver and wp_tls_ver not in all_tls_versions:
                all_tls_versions.append(wp_tls_ver)
            if wp_cipher and wp_cipher not in all_ciphers:
                all_ciphers.append(wp_cipher)

            # Web property vulnerabilities
            wp_cve_ids: List[str] = []
            wp_vulns_raw = wp.get("vulnerabilities") or wp.get("vulns")
            if wp_vulns_raw:
                cids, vitems = _collect_censys_vulns(wp_vulns_raw, port=port, default_product=sw_prod, default_vendor=sw_vendor)
                for cid in cids:
                    if cid not in wp_cve_ids:
                        wp_cve_ids.append(cid)
                for vi in vitems:
                    if not any(x.cve_id == vi.cve_id and x.port == vi.port for x in vulns_detail):
                        vulns_detail.append(vi)

            for sw in software_raw:
                if isinstance(sw, dict):
                    sw_v = sw.get("vulnerabilities") or sw.get("vulns")
                    if sw_v:
                        cids, vitems = _collect_censys_vulns(sw_v, port=port, default_product=sw.get("product") or sw_prod, default_vendor=sw.get("vendor") or sw_vendor)
                        for cid in cids:
                            if cid not in wp_cve_ids:
                                wp_cve_ids.append(cid)
                        for vi in vitems:
                            if not any(x.cve_id == vi.cve_id and x.port == vi.port for x in vulns_detail):
                                vulns_detail.append(vi)

            if port:
                services_legacy.append({
                    "port": port,
                    "service_name": proto,
                    "banner": None,
                })
                services_detail.append(
                    ServiceInfo(
                        port=port,
                        transport="tcp",
                        protocol=proto,
                        service_name=proto,
                        product=sw_prod,
                        version=sw_ver,
                        vendor=sw_vendor,
                        cpe=sw_cpes,
                        http_title=wp_title,
                        http_server=wp_server,
                        http_status=wp_status,
                        tls_version=wp_tls_ver,
                        cipher=wp_cipher,
                        vulnerabilities=wp_cve_ids,
                        scan_time=scan_time,
                        sources=["censys"],
                    )
                )

            # TLS & Certificates
            cert = wp.get("cert") or wp.get("certificate")
            if isinstance(cert, dict):
                fp = cert.get("fingerprint_sha256")
                names = cert.get("names", []) if isinstance(cert.get("names"), list) else []
                parsed = cert.get("parsed", {}) if isinstance(cert.get("parsed"), dict) else {}

                subj = parsed.get("subject", {}) or cert.get("subject", {})
                subj_cn = _safe_first(subj.get("common_name")) if isinstance(subj, dict) else None
                subj_org = _safe_first(subj.get("organization")) if isinstance(subj, dict) else None

                iss = parsed.get("issuer", {}) or cert.get("issuer", {})
                iss_cn = _safe_first(iss.get("common_name")) if isinstance(iss, dict) else None
                iss_org = _safe_first(iss.get("organization")) if isinstance(iss, dict) else None

                val = parsed.get("validity_period", {}) or cert.get("validity", {})
                valid_from = val.get("not_before") or val.get("start")
                valid_to = val.get("not_after") or val.get("end")

                serial = str(parsed.get("serial_number") or cert.get("serial_number") or "") or None

                tls_versions = [wp_tls_ver] if wp_tls_ver else []
                ciphers = [wp_cipher] if wp_cipher else []

                certificates_legacy.append({"fingerprint": fp, "names": names})
                certificates_detail.append(
                    CertInfo(
                        fingerprint_sha256=fp,
                        subject_cn=subj_cn,
                        subject_org=subj_org,
                        issuer_cn=iss_cn,
                        issuer_org=iss_org,
                        sans=names,
                        valid_from=valid_from,
                        valid_to=valid_to,
                        serial_number=serial,
                        tls_versions=tls_versions,
                        ciphers=ciphers,
                        port=port,
                        protocol=proto,
                        service_name=proto,
                        observation_time=scan_time,
                        sources=["censys"],
                    )
                )

                # Extract SAN domains as Layer 3 IOCs
                for name in names:
                    if not name or name == ctx.ioc_value:
                        continue
                    clean_name = str(name).strip().lower().rstrip(".")
                    key = f"domain:{clean_name}"
                    if key not in seen_discovered and clean_name != ctx.ioc_value:
                        seen_discovered.add(key)
                        discovered.append(
                            DiscoveredIOC(
                                raw_value=name,
                                canonical_value=clean_name,
                                ioc_type=IOCType.DOMAIN,
                                relationship_type="shares_certificate",
                                confidence=80.0,
                                evidence_desc=f"Censys TLS certificate SAN on port {port}",
                            )
                        )

            wp_summaries.append({
                "port": port,
                "protocol": proto,
                "hostname": hostname,
                "http_title": wp_title,
                "http_server": wp_server,
                "http_status": wp_status,
                "software": sw_names,
                "endpoints_count": len(endpoints_raw),
                "resolved_ips": [ep.get("ip") for ep in endpoints_raw if ep.get("ip")],
                "scan_time": scan_time,
                "labels": wp.get("labels", []),
            })

        # DNS Model
        dns_records: Dict[str, List[str]] = {}
        dns_record_items: List[DnsRecordItem] = []
        if resolved_ipv4s:
            dns_records["A"] = resolved_ipv4s
            for ip in resolved_ipv4s:
                dns_record_items.append(DnsRecordItem(record_type="A", value=ip, sources=["censys"]))
        if resolved_ipv6s:
            dns_records["AAAA"] = resolved_ipv6s
            for ip in resolved_ipv6s:
                dns_record_items.append(DnsRecordItem(record_type="AAAA", value=ip, sources=["censys"]))

        dns_model = DnsInfo(
            hostnames=[ctx.ioc_value],
            domains=[ctx.ioc_value],
            records=dns_record_items,
            sources=["censys"],
        ) if (resolved_ipv4s or resolved_ipv6s) else None

        # Network Model
        network_model = NetworkInfo(
            asn=primary_asn,
            asn_name=primary_asn_name,
            org=primary_org,
            sources=["censys"],
        ) if (primary_asn or primary_asn_name or primary_org) else None

        # HTTP Model
        http_model = HttpInfo(
            server=primary_http_server,
            title=primary_http_title,
            status_code=primary_status_code,
            headers=primary_headers,
            technologies=all_technologies,
            sources=["censys"],
        ) if (primary_http_server or primary_http_title or primary_status_code is not None) else None

        # TLS Model
        tls_model = TlsInfo(
            supported_versions=all_tls_versions,
            ciphers=all_ciphers,
            sources=["censys"],
        ) if (all_tls_versions or all_ciphers) else None

        temporal_model = TemporalInfo(
            last_scan=latest_scan_time,
            sources=["censys"],
        ) if latest_scan_time else None

        censys_details_model = CensysHostDetails(
            hostname=ctx.ioc_value,
            asn=primary_asn,
            asn_name=primary_asn_name,
            country=primary_country,
            city=primary_city,
            region=primary_region,
            host_labels=all_labels,
            service_count=len(open_ports),
            total_vulns=len(vulns_detail),
            dns_names=[ctx.ioc_value],
            last_observed_at=latest_scan_time,
            web_properties=wp_summaries,
            sources=["censys"],
        )

        extra_data = {
            "censys": {
                "web_properties": wp_summaries,
                "resolved_ips": resolved_ipv4s + resolved_ipv6s,
                "open_ports": sorted(list(set(open_ports))),
                "technologies": all_technologies,
                "host_labels": all_labels,
            }
        }

        infra = InfrastructureData(
            asn=primary_asn,
            asn_name=primary_asn_name,
            org=primary_org,
            country=primary_country,
            region=primary_region,
            city=primary_city,
            open_ports=sorted(list(set(open_ports))),
            services=services_legacy,
            certificates=certificates_legacy,
            http_server=primary_http_server,
            http_title=primary_http_title,
            dns_records=dns_records,
            extra=extra_data,
            network=network_model,
            geo=primary_geo,
            dns=dns_model,
            services_detail=services_detail,
            certificates_detail=certificates_detail,
            http=http_model,
            tls=tls_model,
            vulnerabilities=vulns_detail,
            temporal=temporal_model,
            censys_details=censys_details_model,
        )

        evidences = [
            ProviderEvidence(
                provider_name=self.name,
                evidence_type="web_properties",
                description=f"Censys indexed {len(web_properties)} web properties on ports {sorted(list(set(open_ports)))}, resolving to {len(resolved_ipv4s + resolved_ipv6s)} IPs.",
                confidence=85.0,
            )
        ]

        return ProviderResult(
            provider_name=self.name,
            ioc_value=ctx.ioc_value,
            ioc_type=ctx.ioc_type,
            status=ProviderStatus.SUCCESS,
            classification=None,
            reputation_score=None,
            malicious_count=0,
            suspicious_count=0,
            harmless_count=0,
            infrastructure=infra,
            discovered_iocs=discovered,
            evidences=evidences,
            raw_data=raw_data,
        )

    async def _execute_mock(self, ctx: ProviderRequestContext) -> ProviderResult:
        target_val = ctx.ioc_value
        target_type = ctx.ioc_type
        if target_type == IOCType.URL:
            parsed = urllib.parse.urlparse(target_val)
            host = parsed.hostname or target_val.split("/")[0]
            target_val = host
            target_type = IOCType.IPV6 if ":" in host else (IOCType.IPV4 if _is_ip(host) else IOCType.DOMAIN)

        if target_type in (IOCType.IPV4, IOCType.IPV6):
            mock_data = {
                "code": 200,
                "status": "OK",
                "result": {
                    "resource": {
                        "ip": target_val,
                        "location": {
                            "country": "Netherlands",
                            "province": "North Holland",
                            "city": "Amsterdam",
                            "coordinates": {"latitude": 52.374, "longitude": 4.8897},
                        },
                        "autonomous_system": {
                            "asn": 49981,
                            "name": "WorldStream B.V.",
                            "description": "WorldStream B.V. Autonomous System",
                            "bgp_prefix": "198.51.100.0/24",
                        },
                        "whois": {
                            "organization": {
                                "name": "WorldStream B.V.",
                            },
                            "network": {
                                "cidrs": ["198.51.100.0/24"],
                                "handle": "NET-198-51-100-0-1",
                            },
                        },
                        "dns": {
                            "reverse_dns": {
                                "names": ["c2-relay-nl.darkthreat.org"],
                            },
                            "names": ["c2-relay-nl.darkthreat.org"],
                        },
                        "services": [
                            {
                                "port": 443,
                                "protocol": "HTTPS",
                                "transport_protocol": "tcp",
                                "cert": {
                                    "fingerprint_sha256": "4b6f634bc3d6741b058a59beea7c92b23f8b051ef4943fcf3e61c56ab83e843e",
                                    "names": ["c2-relay-nl.darkthreat.org", "api.darkthreat.org"],
                                    "parsed": {
                                        "subject": {"common_name": "c2-relay-nl.darkthreat.org"},
                                        "issuer": {"common_name": "Let's Encrypt Authority X3"},
                                    },
                                },
                                "software": [{"vendor": "nginx", "product": "nginx", "version": "1.20.1"}],
                                "vulnerabilities": [
                                    {
                                        "cve_id": "CVE-2021-23017",
                                        "cvss": 7.5,
                                        "severity": "HIGH",
                                        "summary": "1-byte memory overwrite in resolver",
                                        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2021-23017"],
                                    }
                                ],
                            },
                            {
                                "port": 8080,
                                "protocol": "HTTP",
                                "transport_protocol": "tcp",
                                "software": [{"vendor": "apache", "product": "httpd", "version": "2.4.41"}],
                                "vulnerabilities": [
                                    {
                                        "cve_id": "CVE-2021-41773",
                                        "cvss": 7.5,
                                        "severity": "HIGH",
                                        "summary": "Path traversal and file disclosure in Apache HTTP Server",
                                        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2021-41773"],
                                        "in_kev": True,
                                    }
                                ],
                            },
                        ],
                    },
                },
            }
            return self._parse_host_response(ctx, mock_data)

        elif target_type == IOCType.DOMAIN:
            mock_wp = [
                {
                    "hostname": target_val,
                    "port": 443,
                    "scan_time": "2026-09-21T12:00:00Z",
                    "cert": {
                        "fingerprint_sha256": "27a025f5b23fc825b7bf72416c486a75bcc80dc344112796cefb613d59347306",
                        "names": [f"*.{target_val}", target_val, f"api.{target_val}"],
                        "parsed": {
                            "subject": {"common_name": target_val},
                            "issuer": {"common_name": "Google Trust Services"},
                        },
                    },
                    "software": [{"vendor": "google", "product": "web_server"}],
                    "endpoints": [
                        {
                            "ip": "142.251.41.78",
                            "http": {
                                "status_code": 200,
                                "html_title": f"{target_val} - Welcome",
                                "headers": {"Server": "gws"},
                                "uri": f"https://{target_val}/",
                            },
                            "location": {"country": "United States", "city": "Mountain View"},
                            "autonomous_system": {"asn": 15169, "name": "Google LLC"},
                        }
                    ],
                }
            ]
            return self._parse_domain_response(ctx, mock_wp, {"mock": True})

        else:
            return ProviderResult(
                provider_name=self.name,
                ioc_value=ctx.ioc_value,
                ioc_type=ctx.ioc_type,
                status=ProviderStatus.UNSUPPORTED,
                error_details="Censys provider supports IPv4, IPv6, Domain, and URL IOCs only.",
            )
