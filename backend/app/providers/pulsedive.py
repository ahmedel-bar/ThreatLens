import asyncio
import time
import httpx
from typing import Optional, List, Dict, Any, Tuple
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
    WhoisInfo,
    CertInfo,
    HttpInfo,
    TemporalInfo,
    ThreatAttribution,
    TTPTechnique,
)
from app.services.ioc import normalize_ioc
from app.config import settings


def _safe_str(val: Any) -> Optional[str]:
    if val is None:
        return None
    if isinstance(val, list):
        items = [str(x).strip() for x in val if x is not None and str(x).strip()]
        return ", ".join(items) if items else None
    if isinstance(val, dict):
        v = val.get("name") or val.get("value") or val.get("label") or str(val)
        s = str(v).strip()
        return s if s else None
    s = str(val).strip()
    return s if s else None


class PulsediveProvider(BaseProvider):
    def __init__(self):
        self._cache: Dict[Tuple[str, str], Tuple[float, ProviderResult]] = {}
        self._lock = asyncio.Lock()
        self._last_request_time = 0.0
        self._min_request_interval = 2.5  # Seconds between live calls to prevent 429 burst limits

    @property
    def name(self) -> str:
        return "pulsedive"

    @property
    def display_name(self) -> str:
        return "Pulsedive"

    def get_capabilities(self) -> ProviderCapability:
        return ProviderCapability(
            name=self.name,
            display_name=self.display_name,
            description="Community threat intelligence platform analyzing IOCs, threats, feeds, and infrastructure properties.",
            supported_iocs=[IOCType.IPV4, IOCType.IPV6, IOCType.DOMAIN, IOCType.URL],
            requires_auth=True,
            free_tier=True,
            rate_limit_desc="30 requests/min, bounded requests with request pacing and in-memory TTL caching",
            provides_reputation=True,
            provides_infrastructure=True,
            provides_relationships=True,
            doc_url="https://pulsedive.com/api/",
        )

    async def _pace_request(self):
        """Enforces minimum delay between outbound calls to protect against rate limits."""
        async with self._lock:
            now = time.monotonic()
            elapsed = now - self._last_request_time
            if elapsed < self._min_request_interval:
                await asyncio.sleep(self._min_request_interval - elapsed)
            self._last_request_time = time.monotonic()

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
        # Check cache
        cached = self._get_from_cache(ctx.ioc_value, ctx.ioc_type)
        if cached:
            return cached

        headers = {
            "User-Agent": "ThreatLens/1.0",
            "Accept": "application/json",
        }
        client = ctx.http_client or httpx.AsyncClient(timeout=ctx.timeout_seconds)

        try:
            # 1. Indicator info lookup
            await self._pace_request()
            url = f"https://pulsedive.com/api/info.php?indicator={ctx.ioc_value}&key={ctx.api_key}&pretty=1"
            resp = await client.get(url, headers=headers)

            if resp.status_code == 401:
                return ProviderResult(
                    provider_name=self.name,
                    ioc_value=ctx.ioc_value,
                    ioc_type=ctx.ioc_type,
                    status=ProviderStatus.UNAUTHORIZED,
                    error_details="Pulsedive API key is invalid or expired.",
                )
            if resp.status_code == 403:
                return ProviderResult(
                    provider_name=self.name,
                    ioc_value=ctx.ioc_value,
                    ioc_type=ctx.ioc_type,
                    status=ProviderStatus.PLAN_RESTRICTED,
                    error_details="Access forbidden or restricted by current Pulsedive account tier.",
                )
            if resp.status_code == 404:
                return ProviderResult(
                    provider_name=self.name,
                    ioc_value=ctx.ioc_value,
                    ioc_type=ctx.ioc_type,
                    status=ProviderStatus.NOT_FOUND,
                    error_details="Indicator not found in Pulsedive database.",
                )
            if resp.status_code == 429:
                return ProviderResult(
                    provider_name=self.name,
                    ioc_value=ctx.ioc_value,
                    ioc_type=ctx.ioc_type,
                    status=ProviderStatus.RATE_LIMITED,
                    error_details="Pulsedive API rate limit exceeded.",
                )

            resp.raise_for_status()
            data = resp.json()

            # Pulsedive returns {"error": "Indicator not found."} on missing records
            if isinstance(data, dict) and data.get("error"):
                err = str(data["error"])
                if "not found" in err.lower():
                    return ProviderResult(
                        provider_name=self.name,
                        ioc_value=ctx.ioc_value,
                        ioc_type=ctx.ioc_type,
                        status=ProviderStatus.NOT_FOUND,
                        error_details=err,
                    )
                return ProviderResult(
                    provider_name=self.name,
                    ioc_value=ctx.ioc_value,
                    ioc_type=ctx.ioc_type,
                    status=ProviderStatus.SERVER_ERROR,
                    error_details=err,
                )

            # 2. Links lookup (Optional/Defensive: attempt with error suppression so rate limits don't break main lookup)
            links_data: Optional[Dict[str, Any]] = None
            try:
                await self._pace_request()
                links_url = f"https://pulsedive.com/api/info.php?indicator={ctx.ioc_value}&get=links&key={ctx.api_key}&pretty=1"
                links_resp = await client.get(links_url, headers=headers)
                if links_resp.status_code == 200:
                    parsed_links = links_resp.json()
                    if isinstance(parsed_links, dict) and not parsed_links.get("error"):
                        links_data = parsed_links
            except Exception:
                # If links fetch fails or rate limits, proceed with main indicator data
                links_data = None

            result = self._parse_pulsedive_response(ctx.ioc_value, ctx.ioc_type, data, links_data)
            self._put_in_cache(ctx.ioc_value, ctx.ioc_type, result)
            return result
        finally:
            if not ctx.http_client:
                await client.aclose()

    def _parse_pulsedive_response(
        self,
        ioc_val: str,
        ioc_type: IOCType,
        data: Dict[str, Any],
        links_data: Optional[Dict[str, Any]] = None,
    ) -> ProviderResult:
        risk_str = (data.get("risk") or "unknown").lower()
        risk_map = {
            "critical": 100.0,
            "high": 75.0,
            "medium": 50.0,
            "low": 25.0,
            "none": 0.0,
        }
        score = risk_map.get(risk_str)

        if risk_str in ("critical", "high"):
            classification = "malicious"
            mal_count = 1
            susp_count = 0
            harm_count = 0
        elif risk_str == "medium":
            classification = "suspicious"
            mal_count = 0
            susp_count = 1
            harm_count = 0
        elif risk_str in ("low", "none"):
            classification = "benign"
            mal_count = 0
            susp_count = 0
            harm_count = 1
        else:
            classification = "unknown"
            mal_count = 0
            susp_count = 0
            harm_count = 0

        # Tags collection
        tags: List[str] = []
        attrs = data.get("attributes") or {}
        if isinstance(attrs, dict):
            for k, val_list in attrs.items():
                if isinstance(val_list, list):
                    for v in val_list:
                        if v and str(v) not in tags:
                            tags.append(str(v))
        for rf in (data.get("riskfactors") or []):
            if isinstance(rf, dict) and rf.get("description") and rf["description"] not in tags:
                tags.append(rf["description"])
        for feed in (data.get("feeds") or []):
            if isinstance(feed, dict) and feed.get("name") and feed["name"] not in tags:
                tags.append(f"Feed: {feed['name']}")

        # Threats & Threat Actors
        malware_families: List[str] = []
        threat_actors: List[str] = []
        threat_attributions: List[ThreatAttribution] = []

        raw_threats = data.get("threats") or []
        if isinstance(raw_threats, list):
            for t in raw_threats:
                if not isinstance(t, dict):
                    continue
                tname = t.get("name")
                if not tname:
                    continue
                tcat = (t.get("category") or "general").lower()
                trisk = (t.get("risk") or "unknown").lower()
                t_score = risk_map.get(trisk, 50.0)

                if tcat in ("actor", "adversary", "threat actor", "group", "apt"):
                    if tname not in threat_actors:
                        threat_actors.append(tname)
                    threat_attributions.append(
                        ThreatAttribution(
                            canonical_name=tname,
                            entity_type="threat_actor",
                            relationship_type="associated_threat",
                            subtype=tcat,
                            threat_actor=tname,
                            sources=["pulsedive"],
                            confidence=t_score,
                            evidence_summary=f"Pulsedive associated adversary ({trisk} risk)",
                        )
                    )
                elif tcat in ("malware", "botnet", "trojan", "ransomware", "miner"):
                    if tname not in malware_families:
                        malware_families.append(tname)
                    threat_attributions.append(
                        ThreatAttribution(
                            canonical_name=tname,
                            entity_type="malware_family",
                            relationship_type="associated_threat",
                            subtype=tcat,
                            malware_family=tname,
                            malware_names=[tname],
                            malware_type=tcat,
                            sources=["pulsedive"],
                            confidence=t_score,
                            evidence_summary=f"Pulsedive associated threat ({tcat}, risk={trisk})",
                        )
                    )
                elif tcat in ("tool",):
                    threat_attributions.append(
                        ThreatAttribution(
                            canonical_name=tname,
                            entity_type="tool",
                            relationship_type="associated_threat",
                            subtype="tool",
                            tool=tname,
                            sources=["pulsedive"],
                            confidence=t_score,
                            evidence_summary=f"Pulsedive associated threat: {tname} (tool)",
                        )
                    )
                elif tcat in ("campaign", "operation"):
                    threat_attributions.append(
                        ThreatAttribution(
                            canonical_name=tname,
                            entity_type="campaign",
                            relationship_type="associated_threat",
                            subtype=tcat,
                            campaign=tname,
                            sources=["pulsedive"],
                            confidence=t_score,
                            evidence_summary=f"Pulsedive associated campaign: {tname}",
                        )
                    )
                else:
                    # General threat classification -> THREAT_ASSOCIATION (Never infer Campaign)
                    threat_attributions.append(
                        ThreatAttribution(
                            canonical_name=tname,
                            entity_type="threat_association",
                            relationship_type="associated_threat",
                            subtype=tcat,
                            threat_association=tname,
                            sources=["pulsedive"],
                            confidence=t_score,
                            evidence_summary=f"Pulsedive associated threat: {tname} ({tcat})",
                        )
                    )

        # Infrastructure Extraction from Properties
        props = data.get("properties") or {}
        infra = InfrastructureData()

        # WHOIS
        whois_p = props.get("whois") or {}
        if isinstance(whois_p, dict) and whois_p:
            reg_date = whois_p.get("regdate")
            if isinstance(reg_date, list) and reg_date:
                reg_date = str(reg_date[-1])
            elif reg_date is not None:
                reg_date = str(reg_date)

            upd_date = whois_p.get("updated")
            if isinstance(upd_date, list) and upd_date:
                upd_date = str(upd_date[-1])
            elif upd_date is not None:
                upd_date = str(upd_date)

            org_name = whois_p.get("organization") or whois_p.get("orgname") or whois_p.get("++registrant")
            country = whois_p.get("country")
            infra.whois = WhoisInfo(
                registrar=whois_p.get("registrar"),
                registrant_org=str(org_name) if org_name else None,
                registrant_country=str(country) if country else None,
                creation_date=reg_date,
                updated_date=upd_date,
                sources=["pulsedive"],
            )
            infra.registrar = whois_p.get("registrar")
            infra.whois_creation = reg_date
            infra.org = str(org_name) if org_name else None
            infra.country = str(country) if country else None
            if whois_p.get("cidr"):
                infra.cidr = str(whois_p.get("cidr"))

        # GEO
        geo_p = props.get("geo") or {}
        if isinstance(geo_p, dict) and geo_p:
            lat = None
            lon = None
            try:
                if geo_p.get("lat") is not None:
                    lat = float(geo_p["lat"])
                if geo_p.get("long") is not None:
                    lon = float(geo_p["long"])
            except (ValueError, TypeError):
                lat = None
                lon = None

            c_val = _safe_str(geo_p.get("country"))
            cc_val = _safe_str(geo_p.get("countrycode"))
            reg_val = _safe_str(geo_p.get("region"))
            city_val = _safe_str(geo_p.get("city"))
            zip_val = _safe_str(geo_p.get("zip") or geo_p.get("postal_code"))

            infra.geo = GeoInfo(
                country=c_val,
                country_code=cc_val,
                region=reg_val,
                city=city_val,
                postal_code=zip_val,
                latitude=lat,
                longitude=lon,
                sources=["pulsedive"],
            )
            if not infra.country and c_val:
                infra.country = c_val
            if not infra.region and reg_val:
                infra.region = reg_val
            if not infra.city and city_val:
                infra.city = city_val

        # NETWORK
        asn_val = _safe_str(geo_p.get("asn") or props.get("asn"))
        org_val = _safe_str(geo_p.get("org") or whois_p.get("organization"))
        dns_p = props.get("dns") or {}
        ptr_val = _safe_str(dns_p.get("ptr") if isinstance(dns_p, dict) else None)

        infra.network = NetworkInfo(
            ip=ioc_val if ioc_type in (IOCType.IPV4, IOCType.IPV6) else None,
            asn=asn_val,
            org=org_val,
            cidr=infra.cidr,
            ptr=ptr_val,
            sources=["pulsedive"],
        )
        if asn_val:
            infra.asn = asn_val
        if ptr_val:
            infra.ptr = ptr_val

        # HTTP
        http_p = props.get("http") or {}
        meta_p = props.get("meta") or {}
        dom_p = props.get("dom") or {}
        if isinstance(http_p, dict) and http_p:
            code = None
            try:
                if http_p.get("++code"):
                    code = int(http_p["++code"])
            except (ValueError, TypeError):
                code = None

            title = meta_p.get("++title") if isinstance(meta_p, dict) else None
            screenshot = dom_p.get("screenshot") if isinstance(dom_p, dict) else None

            infra.http = HttpInfo(
                server=http_p.get("server"),
                title=title,
                status_code=code,
                screenshot_url=screenshot,
                technologies=attrs.get("technology", []) if isinstance(attrs, dict) else [],
                sources=["pulsedive"],
            )
            infra.http_server = http_p.get("server")
            infra.http_title = title
            infra.screenshot_url = screenshot

        # SSL
        ssl_p = props.get("ssl") or {}
        if isinstance(ssl_p, dict) and ssl_p:
            sans = []
            raw_ssl_domains = ssl_p.get("domain") or []
            if isinstance(raw_ssl_domains, list):
                sans.extend([str(d).strip() for d in raw_ssl_domains if d and str(d).strip()])
            elif raw_ssl_domains:
                sans.append(str(raw_ssl_domains).strip())

            infra.certificates_detail.append(
                CertInfo(
                    fingerprint_sha256=ssl_p.get("fingerprint"),
                    subject_cn=ssl_p.get("subject"),
                    issuer_cn=ssl_p.get("issuer"),
                    issuer_org=ssl_p.get("org"),
                    sans=sans,
                    valid_from=ssl_p.get("valid"),
                    valid_to=ssl_p.get("expires"),
                    tls_versions=[ssl_p["version"]] if ssl_p.get("version") else [],
                    sources=["pulsedive"],
                )
            )

        # TEMPORAL
        infra.temporal = TemporalInfo(
            first_seen=data.get("stamp_added"),
            last_seen=data.get("stamp_seen"),
            last_scan=data.get("stamp_probed"),
            sources=["pulsedive"],
        )

        # Threat Attribution model attachment
        infra.threat_attributions = threat_attributions
        if threat_attributions:
            infra.threat_attribution = threat_attributions[0]

        # Layer 3 Discovered IOC Extraction
        discovered_iocs: List[DiscoveredIOC] = []
        seen_canonical: set[str] = {ioc_val.lower()}

        # 1. From SSL SANs (domains and IPs)
        if isinstance(ssl_p, dict):
            raw_domains = ssl_p.get("domain") or []
            domain_items = raw_domains if isinstance(raw_domains, list) else [raw_domains]
            for d in domain_items:
                if d and isinstance(d, str):
                    clean_d = d.replace("*.", "").strip()
                    norm = normalize_ioc(clean_d, IOCType.DOMAIN)
                    if norm.is_valid and norm.canonical_value not in seen_canonical:
                        seen_canonical.add(norm.canonical_value)
                        discovered_iocs.append(
                            DiscoveredIOC(
                                raw_value=clean_d,
                                canonical_value=norm.canonical_value,
                                ioc_type=IOCType.DOMAIN,
                                relationship_type="ssl_subject_alt_name",
                                confidence=score or 50.0,
                                first_seen=data.get("stamp_added"),
                                last_seen=data.get("stamp_seen"),
                                evidence_desc="Pulsedive SSL SAN domain",
                                metadata={"provider": self.name, "relationship": "ssl_subject_alt_name"},
                            )
                        )
            raw_ips = ssl_p.get("ip") or []
            ip_items = raw_ips if isinstance(raw_ips, list) else [raw_ips]
            for ip_s in ip_items:
                if ip_s and isinstance(ip_s, str):
                    norm = normalize_ioc(ip_s, IOCType.IPV4 if ":" not in ip_s else IOCType.IPV6)
                    if norm.is_valid and norm.canonical_value not in seen_canonical:
                        seen_canonical.add(norm.canonical_value)
                        discovered_iocs.append(
                            DiscoveredIOC(
                                raw_value=ip_s,
                                canonical_value=norm.canonical_value,
                                ioc_type=norm.ioc_type,
                                relationship_type="ssl_subject_alt_name",
                                confidence=score or 50.0,
                                first_seen=data.get("stamp_added"),
                                last_seen=data.get("stamp_seen"),
                                evidence_desc="Pulsedive SSL SAN IP",
                                metadata={"provider": self.name, "relationship": "ssl_subject_alt_name"},
                            )
                        )

        # 2. From DNS PTR
        if ptr_val and isinstance(ptr_val, str):
            norm = normalize_ioc(ptr_val, IOCType.DOMAIN)
            if norm.is_valid and norm.canonical_value not in seen_canonical:
                seen_canonical.add(norm.canonical_value)
                discovered_iocs.append(
                    DiscoveredIOC(
                        raw_value=ptr_val,
                        canonical_value=norm.canonical_value,
                        ioc_type=IOCType.DOMAIN,
                        relationship_type="resolves_to",
                        confidence=score or 50.0,
                        evidence_desc="Pulsedive DNS PTR hostname",
                        metadata={"provider": self.name, "relationship": "resolves_to"},
                    )
                )

        # 3. From HTTP Redirects / Targets
        if isinstance(http_p, dict):
            for target_field in ("++redirect", "++target"):
                turl = http_p.get(target_field)
                if turl and isinstance(turl, str) and turl.startswith("http"):
                    norm = normalize_ioc(turl, IOCType.URL)
                    if norm.is_valid and norm.canonical_value not in seen_canonical:
                        seen_canonical.add(norm.canonical_value)
                        discovered_iocs.append(
                            DiscoveredIOC(
                                raw_value=turl,
                                canonical_value=norm.canonical_value,
                                ioc_type=IOCType.URL,
                                relationship_type="redirects_to",
                                confidence=score or 50.0,
                                evidence_desc=f"Pulsedive HTTP {target_field}",
                                metadata={"provider": self.name, "relationship": "redirects_to"},
                            )
                        )

        # 4. From Links data (Active DNS, Reverse DNS, Name Servers, Redirects, Related URLs)
        if links_data and isinstance(links_data, dict):
            link_rel_map = {
                "Active DNS": ("domain", "passive_dns"),
                "Reverse DNS": ("ip", "resolves_to"),
                "Name Servers": ("domain", "nameserver"),
                "Redirects": ("url", "redirects_to"),
                "Related URLs": ("url", "links_to"),
                "Sources": ("url", "links_to"),
            }
            for cat_name, (expected_type, rel_type) in link_rel_map.items():
                items = links_data.get(cat_name) or []
                if not isinstance(items, list):
                    continue
                # Bounded extraction to prevent thousands of links overwhelming Layer 3
                for item in items[:15]:
                    if not isinstance(item, dict):
                        continue
                    indicator_val = item.get("indicator")
                    if not indicator_val:
                        continue
                    itype_str = (item.get("type") or expected_type).lower()

                    target_ioc_type = IOCType.DOMAIN
                    if itype_str == "ip":
                        target_ioc_type = IOCType.IPV4 if ":" not in indicator_val else IOCType.IPV6
                    elif itype_str == "url":
                        target_ioc_type = IOCType.URL

                    norm = normalize_ioc(indicator_val, target_ioc_type)
                    if norm.is_valid and norm.canonical_value not in seen_canonical:
                        seen_canonical.add(norm.canonical_value)
                        discovered_iocs.append(
                            DiscoveredIOC(
                                raw_value=indicator_val,
                                canonical_value=norm.canonical_value,
                                ioc_type=norm.ioc_type,
                                relationship_type=rel_type,
                                confidence=score or 50.0,
                                first_seen=item.get("stamp_linked"),
                                last_seen=item.get("stamp_linked"),
                                evidence_desc=f"Pulsedive {cat_name} link ({item.get('risk', 'unknown')} risk)",
                                metadata={
                                    "provider": self.name,
                                    "relationship": rel_type,
                                    "link_category": cat_name,
                                    "pulsedive_iid": item.get("iid"),
                                },
                            )
                        )

        return ProviderResult(
            provider_name=self.name,
            ioc_value=ioc_val,
            ioc_type=ioc_type,
            status=ProviderStatus.SUCCESS,
            reputation_score=score,
            classification=classification,
            malicious_count=mal_count,
            suspicious_count=susp_count,
            harmless_count=harm_count,
            tags=tags[:15],
            threat_actors=threat_actors,
            malware_families=malware_families,
            infrastructure=infra,
            discovered_iocs=discovered_iocs,
            raw_data={"indicator": data, "links_count": len(discovered_iocs)},
        )

    async def _execute_mock(self, ctx: ProviderRequestContext) -> ProviderResult:
        """Returns realistic mock data covering IP, Domain, and URL."""
        if ctx.ioc_type in (IOCType.IPV4, IOCType.IPV6):
            mock_data = {
                "iid": 111601,
                "indicator": ctx.ioc_value,
                "type": "ip",
                "risk": "medium",
                "stamp_added": "2020-10-15 13:23:37",
                "stamp_updated": "2026-09-10 11:42:38",
                "stamp_seen": "2026-09-10 11:42:38",
                "stamp_probed": "2026-09-10 11:42:38",
                "threats": [
                    {"tid": 108, "name": "Cobalt Strike", "category": "malware", "risk": "high", "stamp_linked": "2023-01-10 10:00:00"},
                    {"tid": 204, "name": "APT29", "category": "actor", "risk": "critical", "stamp_linked": "2023-01-10 10:00:00"},
                ],
                "feeds": [
                    {"fid": 69, "name": "C2 Infrastructure Feed", "category": "botnet", "organization": "ThreatIntel Org"}
                ],
                "attributes": {
                    "port": ["80", "443", "8080"],
                    "protocol": ["HTTP", "HTTPS"],
                    "technology": ["Nginx", "OpenSSL"],
                },
                "properties": {
                    "whois": {
                        "organization": "Hosting Services Inc",
                        "country": "US",
                        "regdate": "2018-05-12",
                        "updated": "2023-04-10",
                        "cidr": f"{ctx.ioc_value}/24",
                        "registrar": "ARIN",
                    },
                    "geo": {
                        "country": "United States",
                        "countrycode": "US",
                        "city": "Chicago",
                        "region": "IL",
                        "asn": "AS16509",
                        "org": "Hosting Services Inc",
                        "lat": "41.8781",
                        "long": "-87.6298",
                    },
                    "http": {
                        "server": "nginx/1.24.0",
                        "++code": "200",
                        "++target": f"https://{ctx.ioc_value}/",
                    },
                    "meta": {
                        "++title": "Default Web Server Page"
                    },
                    "ssl": {
                        "version": "TLSv1.3",
                        "domain": [f"c2-node.{ctx.ioc_value}.nip.io", "malicious-domain.com"],
                        "ip": [ctx.ioc_value, "198.51.100.42"],
                        "subject": f"/CN=c2-node.{ctx.ioc_value}.nip.io",
                        "issuer": "/C=US/O=Let's Encrypt/CN=R3",
                        "valid": "2026-01-01 00:00:00",
                        "expires": "2026-04-01 00:00:00",
                        "fingerprint": "a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef123456",
                    },
                    "dns": {
                        "ptr": f"host.{ctx.ioc_value}.ptr.domain.com"
                    },
                    "dom": {
                        "screenshot": f"https://sandbox.pulsedive.com/screenshots/{ctx.ioc_value}.jpeg"
                    },
                },
            }
            mock_links = {
                "Active DNS": [
                    {"iid": 201, "indicator": "c2-node.example.org", "type": "domain", "risk": "high", "stamp_linked": "2026-01-01 00:00:00"},
                    {"iid": 202, "indicator": "botnet-beacon.net", "type": "domain", "risk": "medium", "stamp_linked": "2026-01-02 00:00:00"},
                ],
                "Reverse DNS": [
                    {"iid": 301, "indicator": "203.0.113.10", "type": "ip", "risk": "low", "stamp_linked": "2026-01-03 00:00:00"}
                ],
                "Related URLs": [
                    {"iid": 401, "indicator": f"http://{ctx.ioc_value}/beacon.php", "type": "url", "risk": "high", "stamp_linked": "2026-01-04 00:00:00"}
                ],
            }
            return self._parse_pulsedive_response(ctx.ioc_value, ctx.ioc_type, mock_data, mock_links)

        elif ctx.ioc_type == IOCType.DOMAIN:
            mock_data = {
                "iid": 222333,
                "indicator": ctx.ioc_value,
                "type": "domain",
                "risk": "high",
                "stamp_added": "2021-03-01 10:00:00",
                "stamp_seen": "2026-09-01 12:00:00",
                "threats": [
                    {"tid": 305, "name": "Agent Tesla", "category": "malware", "risk": "high", "stamp_linked": "2023-05-10 10:00:00"}
                ],
                "attributes": {
                    "technology": ["Cloudflare", "PHP"],
                    "port": ["80", "443"],
                },
                "properties": {
                    "whois": {
                        "registrar": "NameCheap, Inc.",
                        "regdate": "2021-03-01",
                        "updated": "2026-02-15",
                        "country": "US",
                        "organization": "Privacy Protection Inc",
                    },
                    "geo": {
                        "country": "United States",
                        "countrycode": "US",
                        "city": "San Jose",
                        "region": "CA",
                    },
                    "http": {
                        "server": "cloudflare",
                        "++code": "200",
                        "++target": f"https://{ctx.ioc_value}/login",
                    },
                    "meta": {
                        "++title": f"Welcome to {ctx.ioc_value}"
                    },
                    "ssl": {
                        "domain": [ctx.ioc_value, f"www.{ctx.ioc_value}"],
                        "issuer": "/C=US/O=Cloudflare, Inc./CN=Cloudflare Inc ECC CA-3",
                        "valid": "2026-01-01 00:00:00",
                        "expires": "2026-12-31 23:59:59",
                        "fingerprint": "9876543210abcdef9876543210abcdef9876543210abcdef9876543210abcdef",
                    },
                },
            }
            mock_links = {
                "Active DNS": [
                    {"iid": 501, "indicator": f"sub.{ctx.ioc_value}", "type": "domain", "risk": "medium", "stamp_linked": "2026-02-01 00:00:00"}
                ],
                "Reverse DNS": [
                    {"iid": 502, "indicator": "198.51.100.99", "type": "ip", "risk": "low", "stamp_linked": "2026-02-01 00:00:00"}
                ],
                "Related URLs": [
                    {"iid": 503, "indicator": f"https://{ctx.ioc_value}/gate.php", "type": "url", "risk": "high", "stamp_linked": "2026-02-01 00:00:00"}
                ],
            }
            return self._parse_pulsedive_response(ctx.ioc_value, ctx.ioc_type, mock_data, mock_links)

        else:  # URL
            mock_data = {
                "iid": 333444,
                "indicator": ctx.ioc_value,
                "type": "url",
                "risk": "critical",
                "stamp_added": "2026-08-10 10:00:00",
                "stamp_seen": "2026-09-01 12:00:00",
                "threats": [
                    {"tid": 401, "name": "RedLine Stealer", "category": "malware", "risk": "critical", "stamp_linked": "2026-08-10 10:00:00"}
                ],
                "attributes": {
                    "technology": ["Apache"],
                },
                "properties": {
                    "http": {
                        "server": "Apache/2.4.52",
                        "++code": "200",
                        "++redirect": "https://malicious-payload-drop.org/payload.exe",
                    },
                },
            }
            mock_links = {
                "Active DNS": [
                    {"iid": 601, "indicator": "malicious-payload-drop.org", "type": "domain", "risk": "critical", "stamp_linked": "2026-08-10 10:00:00"}
                ],
                "Reverse DNS": [
                    {"iid": 602, "indicator": "203.0.113.250", "type": "ip", "risk": "high", "stamp_linked": "2026-08-10 10:00:00"}
                ],
            }
            return self._parse_pulsedive_response(ctx.ioc_value, ctx.ioc_type, mock_data, mock_links)
