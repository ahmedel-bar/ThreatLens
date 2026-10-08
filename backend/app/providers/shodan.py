import httpx
from typing import Dict, Any, List, Optional
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
    ServiceInfo,
    CertInfo,
    HttpInfo,
    TlsInfo,
    VulnInfo,
    TemporalInfo,
    ShodanHostDetails,
)


def _safe_float(v: Any) -> Optional[float]:
    if v is None:
        return None
    try:
        return float(v)
    except (ValueError, TypeError):
        return None


def _safe_int(v: Any) -> Optional[int]:
    if v is None:
        return None
    try:
        return int(v)
    except (ValueError, TypeError):
        return None


class ShodanProvider(BaseProvider):
    @property
    def name(self) -> str:
        return "shodan"

    @property
    def display_name(self) -> str:
        return "Shodan"

    def get_capabilities(self) -> ProviderCapability:
        return ProviderCapability(
            name=self.name,
            display_name=self.display_name,
            description="Search engine for Internet-connected devices, indexing open ports, services, operating systems, and vulnerabilities.",
            supported_iocs=[
                IOCType.IPV4,
                IOCType.IPV6,
                IOCType.DOMAIN,
            ],
            requires_auth=True,
            free_tier=True,
            rate_limit_desc="1 request/second API limit",
            provides_reputation=False,
            provides_infrastructure=True,
            provides_relationships=True,
            doc_url="https://developer.shodan.io/api",
        )

    async def _execute_live(self, ctx: ProviderRequestContext) -> ProviderResult:
        base_url = "https://api.shodan.io"
        params = {"key": ctx.api_key or ""}

        client = ctx.http_client or httpx.AsyncClient(timeout=ctx.timeout_seconds)
        should_close = ctx.http_client is None
        try:
            if ctx.ioc_type in (IOCType.IPV4, IOCType.IPV6):
                endpoint = f"{base_url}/shodan/host/{ctx.ioc_value}"
                resp = await client.get(endpoint, params=params)
            elif ctx.ioc_type == IOCType.DOMAIN:
                endpoint = f"{base_url}/dns/resolve"
                resp = await client.get(endpoint, params={"hostnames": ctx.ioc_value, **params})
            else:
                return ProviderResult(
                    provider_name=self.name,
                    ioc_value=ctx.ioc_value,
                    ioc_type=ctx.ioc_type,
                    status=ProviderStatus.UNSUPPORTED,
                )

            resp.raise_for_status()
            data = resp.json()
            return self._parse_response(ctx, data)
        finally:
            if should_close:
                await client.aclose()

    def _parse_response(self, ctx: ProviderRequestContext, data: Dict[str, Any]) -> ProviderResult:
        if "error" in data:
            err = data.get("error", "")
            if "not found" in err.lower():
                return ProviderResult(
                    provider_name=self.name,
                    ioc_value=ctx.ioc_value,
                    ioc_type=ctx.ioc_type,
                    status=ProviderStatus.NOT_FOUND,
                    error_details=err,
                    raw_data=data,
                )
            return ProviderResult(
                provider_name=self.name,
                ioc_value=ctx.ioc_value,
                ioc_type=ctx.ioc_type,
                status=ProviderStatus.INVALID_RESPONSE,
                error_details=err,
                raw_data=data,
            )

        # Handle domain resolve response
        if ctx.ioc_type == IOCType.DOMAIN and isinstance(data, dict) and ctx.ioc_value in data:
            resolved_ip = data[ctx.ioc_value]
            discovered = []
            if resolved_ip:
                discovered.append(
                    DiscoveredIOC(
                        raw_value=resolved_ip,
                        canonical_value=resolved_ip,
                        ioc_type=IOCType.IPV4,
                        relationship_type="resolves_to",
                        confidence=90.0,
                        evidence_desc="Shodan DNS resolution",
                    )
                )
            return ProviderResult(
                provider_name=self.name,
                ioc_value=ctx.ioc_value,
                ioc_type=ctx.ioc_type,
                status=ProviderStatus.SUCCESS,
                discovered_iocs=discovered,
                raw_data=data,
            )

        ports = data.get("ports", [])
        hostnames = [h for h in data.get("hostnames", []) if h]
        domains = [d for d in data.get("domains", []) if d]
        org = data.get("org")
        isp = data.get("isp")
        asn = str(data.get("asn")) if data.get("asn") else None
        country = data.get("country_name") or data.get("country_code")
        country_code = data.get("country_code")
        city = data.get("city")
        region = data.get("region_code")

        services_raw = data.get("data", [])
        services_legacy = []
        services_detail: List[ServiceInfo] = []
        certificates_legacy = []
        certificates_detail: List[CertInfo] = []
        vulns_detail: List[VulnInfo] = []
        discovered: List[DiscoveredIOC] = []

        # 1. Parse services and embedded SSL/HTTP telemetry
        all_tls_versions: List[str] = []
        all_ciphers: List[str] = []
        all_jarm: Optional[str] = None
        http_servers: List[str] = []
        http_titles: List[str] = []
        http_statuses: List[int] = []
        http_technologies: List[str] = []
        service_timestamps: List[str] = []

        host_device_type = data.get("devicetype")

        for s in services_raw:
            p = s.get("port")
            if not p:
                continue
            transport = s.get("transport") or "tcp"
            mod = s.get("_shodan", {}).get("module")
            prod = s.get("product")
            ver = s.get("version")
            devtype = s.get("devicetype") or host_device_type
            if devtype and not host_device_type:
                host_device_type = devtype
            vendor = s.get("vendor")
            if not vendor and prod:
                vendor = prod.split()[0] if prod else None

            cpe_raw = s.get("cpe23") or s.get("cpe") or []
            cpes = [cpe_raw] if isinstance(cpe_raw, str) else ([str(c) for c in cpe_raw] if isinstance(cpe_raw, list) else [])
            banner_text = (s.get("data") or "")[:1000]
            scan_time = s.get("timestamp")
            if scan_time:
                service_timestamps.append(str(scan_time))

            http_obj = s.get("http", {}) if isinstance(s.get("http"), dict) else {}
            http_title = http_obj.get("title")
            http_server = http_obj.get("server")
            http_status = http_obj.get("status")
            if http_server and http_server not in http_servers:
                http_servers.append(http_server)
            if http_title and http_title not in http_titles:
                http_titles.append(http_title)
            if http_status and http_status not in http_statuses:
                try:
                    http_statuses.append(int(http_status))
                except Exception:
                    pass
            components = http_obj.get("components", {})
            if isinstance(components, dict):
                for comp_name in components.keys():
                    if comp_name and comp_name not in http_technologies:
                        http_technologies.append(comp_name)

            svc_name = prod or mod or "unknown"
            services_legacy.append({"port": p, "service_name": svc_name, "banner": banner_text[:120]})

            # SSL certificate parsing
            ssl_info = s.get("ssl", {}).get("cert", {}) if isinstance(s.get("ssl"), dict) else {}
            ja3s = s.get("ssl", {}).get("ja3s") if isinstance(s.get("ssl"), dict) else None
            jarm = s.get("ssl", {}).get("jarm") if isinstance(s.get("ssl"), dict) else None
            if jarm and not all_jarm:
                all_jarm = jarm
            alpn = s.get("ssl", {}).get("alpn", []) if isinstance(s.get("ssl"), dict) and isinstance(s.get("ssl", {}).get("alpn"), list) else []
            tls_vers = s.get("ssl", {}).get("versions", []) if isinstance(s.get("ssl"), dict) and isinstance(s.get("ssl", {}).get("versions"), list) else []
            for tv in tls_vers:
                if tv and tv not in all_tls_versions:
                    all_tls_versions.append(tv)
            cipher_name = s.get("ssl", {}).get("cipher", {}).get("name") if isinstance(s.get("ssl"), dict) and isinstance(s.get("ssl", {}).get("cipher"), dict) else None
            if cipher_name and cipher_name not in all_ciphers:
                all_ciphers.append(cipher_name)

            if ssl_info:
                fingerprint = ssl_info.get("fingerprint", {}).get("sha256")
                subject_obj = ssl_info.get("subject", {})
                subject_cn = subject_obj.get("CN")
                subject_org = subject_obj.get("O")
                issuer_obj = ssl_info.get("issuer", {})
                issuer_cn = issuer_obj.get("CN")
                issuer_org = issuer_obj.get("O")
                valid_from = ssl_info.get("issued")
                valid_to = ssl_info.get("expires")
                serial_num = str(ssl_info.get("serial")) if ssl_info.get("serial") else None
                sig_alg = ssl_info.get("sig_alg")

                sans_list = []
                ext = ssl_info.get("extensions")
                if isinstance(ext, dict) and ext.get("subjectAltName"):
                    sans_list = [san.strip() for san in ext.get("subjectAltName", "").split(",") if san.strip()]

                ciphers_list = [cipher_name] if cipher_name else []

                certificates_legacy.append({
                    "fingerprint": fingerprint,
                    "names": sans_list if sans_list else ([subject_cn] if subject_cn else []),
                })

                certificates_detail.append(
                    CertInfo(
                        fingerprint_sha256=fingerprint,
                        subject_cn=subject_cn,
                        subject_org=subject_org,
                        issuer_cn=issuer_cn,
                        issuer_org=issuer_org,
                        sans=sans_list,
                        valid_from=valid_from,
                        valid_to=valid_to,
                        serial_number=serial_num,
                        tls_versions=tls_vers,
                        ciphers=ciphers_list,
                        ja3s=ja3s,
                        jarm=jarm,
                        sig_alg=sig_alg,
                        sources=["shodan"],
                    )
                )

                if fingerprint:
                    discovered.append(
                        DiscoveredIOC(
                            raw_value=fingerprint,
                            canonical_value=fingerprint.lower(),
                            ioc_type=IOCType.SHA256,
                            relationship_type="shares_certificate",
                            confidence=90.0,
                            evidence_desc=f"Shodan observed SSL certificate on port {p}",
                        )
                    )
                if subject_cn and subject_cn != ctx.ioc_value:
                    discovered.append(
                        DiscoveredIOC(
                            raw_value=subject_cn,
                            canonical_value=subject_cn.lower().rstrip("."),
                            ioc_type=IOCType.DOMAIN,
                            relationship_type="associated_domain",
                            confidence=80.0,
                            evidence_desc="Shodan SSL cert CommonName",
                        )
                    )

            # Service-level vulnerabilities
            svc_cves: List[str] = []
            svc_vulns = s.get("vulns") or s.get("opts", {}).get("vulns")
            if isinstance(svc_vulns, dict):
                for cve_key, cve_data in svc_vulns.items():
                    cve_clean = str(cve_key).strip().upper()
                    if not cve_clean.startswith("CVE-"):
                        continue
                    svc_cves.append(cve_clean)
                    if isinstance(cve_data, dict):
                        cvss = cve_data.get("cvss")
                        summ = cve_data.get("summary")
                        refs = cve_data.get("references", [])
                    elif isinstance(cve_data, (int, float)):
                        cvss = cve_data
                        summ = None
                        refs = []
                    else:
                        cvss = None
                        summ = None
                        refs = []
                    cvss_val = _safe_float(cvss)
                    severity = (
                        "CRITICAL" if cvss_val is not None and cvss_val >= 9.0
                        else ("HIGH" if cvss_val is not None and cvss_val >= 7.0
                        else ("MEDIUM" if cvss_val is not None and cvss_val >= 4.0
                        else ("LOW" if cvss_val is not None else None)))
                    )
                    vulns_detail.append(
                        VulnInfo(
                            cve_id=cve_clean,
                            cvss=cvss_val,
                            severity=severity,
                            summary=summ,
                            references=refs if isinstance(refs, list) else [],
                            port=p,
                            affected_product=prod,
                            sources=["shodan"],
                        )
                    )
            elif isinstance(svc_vulns, list):
                for cve_item in svc_vulns:
                    cve_clean = str(cve_item).strip().upper()
                    if cve_clean.startswith("CVE-"):
                        svc_cves.append(cve_clean)
                        vulns_detail.append(
                            VulnInfo(
                                cve_id=cve_clean,
                                port=p,
                                affected_product=prod,
                                sources=["shodan"],
                            )
                        )

            services_detail.append(
                ServiceInfo(
                    port=p,
                    transport=transport,
                    protocol=mod,
                    service_name=svc_name,
                    product=prod,
                    version=ver,
                    vendor=vendor,
                    devicetype=devtype,
                    cpe=cpes,
                    banner=banner_text,
                    http_title=http_title,
                    http_server=http_server,
                    http_status=int(http_status) if http_status else None,
                    tls_version=tls_vers[0] if tls_vers else None,
                    cipher=cipher_name,
                    ja3s=ja3s,
                    jarm=jarm,
                    alpn=alpn,
                    vulnerabilities=svc_cves,
                    scan_time=scan_time,
                    sources=["shodan"],
                )
            )

        # 2. Host-level vulnerabilities (if any returned)
        host_vulns_raw = data.get("vulns")
        known_cves = {v.cve_id for v in vulns_detail}
        if isinstance(host_vulns_raw, dict):
            for cve_key, cve_data in host_vulns_raw.items():
                cve_clean = str(cve_key).strip().upper()
                if not cve_clean.startswith("CVE-"):
                    continue
                if cve_clean not in known_cves:
                    known_cves.add(cve_clean)
                    if isinstance(cve_data, dict):
                        cvss = cve_data.get("cvss")
                        summ = cve_data.get("summary")
                        refs = cve_data.get("references", [])
                    elif isinstance(cve_data, (int, float)):
                        cvss = cve_data
                        summ = None
                        refs = []
                    else:
                        cvss = None
                        summ = None
                        refs = []
                    cvss_val = _safe_float(cvss)
                    severity = (
                        "CRITICAL" if cvss_val is not None and cvss_val >= 9.0
                        else ("HIGH" if cvss_val is not None and cvss_val >= 7.0
                        else ("MEDIUM" if cvss_val is not None and cvss_val >= 4.0
                        else ("LOW" if cvss_val is not None else None)))
                    )
                    vulns_detail.append(
                        VulnInfo(
                            cve_id=cve_clean,
                            cvss=cvss_val,
                            severity=severity,
                            summary=summ,
                            references=refs if isinstance(refs, list) else [],
                            sources=["shodan"],
                        )
                    )
        elif isinstance(host_vulns_raw, list):
            for cve_key in host_vulns_raw:
                cve_clean = str(cve_key).strip().upper()
                if cve_clean.startswith("CVE-") and cve_clean not in known_cves:
                    known_cves.add(cve_clean)
                    vulns_detail.append(
                        VulnInfo(
                            cve_id=cve_clean,
                            sources=["shodan"],
                        )
                    )

        # 3. Add hostnames and domains as discovered IOCs
        for h in hostnames:
            if h and h != ctx.ioc_value:
                discovered.append(
                    DiscoveredIOC(
                        raw_value=h,
                        canonical_value=h.lower().rstrip("."),
                        ioc_type=IOCType.DOMAIN,
                        relationship_type="associated_domain",
                        confidence=85.0,
                        evidence_desc="Shodan associated hostname",
                    )
                )

        for d in domains:
            if d and d != ctx.ioc_value:
                discovered.append(
                    DiscoveredIOC(
                        raw_value=d,
                        canonical_value=d.lower().rstrip("."),
                        ioc_type=IOCType.DOMAIN,
                        relationship_type="associated_domain",
                        confidence=85.0,
                        evidence_desc="Shodan associated domain",
                    )
                )

        # 4. Construct rich structured models
        network_model = NetworkInfo(
            ip=ctx.ioc_value if ctx.ioc_type in (IOCType.IPV4, IOCType.IPV6) else None,
            ip_version="IPv4" if ctx.ioc_type == IOCType.IPV4 else ("IPv6" if ctx.ioc_type == IOCType.IPV6 else None),
            asn=asn,
            asn_name=isp,
            org=org,
            isp=isp,
            sources=["shodan"],
        )

        geo_lat = _safe_float(data.get("latitude"))
        geo_lon = _safe_float(data.get("longitude"))

        geo_model = GeoInfo(
            country=country,
            country_code=country_code,
            region=region,
            city=city,
            latitude=geo_lat,
            longitude=geo_lon,
            sources=["shodan"],
        ) if (country or city or region or geo_lat is not None) else None

        dns_model = DnsInfo(
            hostnames=hostnames,
            domains=domains,
            sources=["shodan"],
        ) if (hostnames or domains) else None

        # Temporal model with earliest and latest observations
        sorted_times = sorted(service_timestamps)
        first_seen = sorted_times[0] if sorted_times else None
        last_seen = data.get("last_update") or (sorted_times[-1] if sorted_times else None)
        temporal_model = TemporalInfo(
            first_seen=str(first_seen) if first_seen else None,
            last_seen=str(last_seen) if last_seen else None,
            last_scan=str(data.get("last_update")) if data.get("last_update") else (str(last_seen) if last_seen else None),
            sources=["shodan"],
        ) if (first_seen or last_seen or data.get("last_update")) else None

        shodan_details_model = ShodanHostDetails(
            os=data.get("os"),
            device_type=host_device_type,
            tags=data.get("tags", []) if isinstance(data.get("tags"), list) else [],
            total_ports=len(ports),
            services_count=len(services_raw),
            total_vulns=len(vulns_detail),
            domains=domains,
            hostnames=hostnames,
            asn=asn,
            isp=isp,
            org=org,
            city=city,
            country=country,
            latitude=geo_lat,
            longitude=geo_lon,
            last_update=str(data.get("last_update")) if data.get("last_update") else None,
            sources=["shodan"],
        )

        http_model = HttpInfo(
            server=http_servers[0] if http_servers else None,
            title=http_titles[0] if http_titles else None,
            status_code=http_statuses[0] if http_statuses else None,
            technologies=http_technologies,
            sources=["shodan"],
        ) if (http_servers or http_titles or http_statuses or http_technologies) else None

        tls_model = TlsInfo(
            supported_versions=all_tls_versions,
            ciphers=all_ciphers,
            jarm=all_jarm,
            sources=["shodan"],
        ) if (all_tls_versions or all_ciphers or all_jarm) else None

        vuln_cve_names = [v.cve_id for v in vulns_detail]

        infra = InfrastructureData(
            asn=asn,
            asn_name=isp,
            org=org,
            country=country,
            region=region,
            city=city,
            open_ports=ports,
            services=services_legacy,
            certificates=certificates_legacy,
            extra={
                "vulns": vuln_cve_names,
                "os": data.get("os"),
                "device_type": host_device_type,
                "services_count": len(services_raw),
                "last_update": data.get("last_update"),
            },
            network=network_model,
            geo=geo_model,
            dns=dns_model,
            services_detail=services_detail,
            certificates_detail=certificates_detail,
            vulnerabilities=vulns_detail,
            http=http_model,
            tls=tls_model,
            temporal=temporal_model,
            shodan_details=shodan_details_model,
        )

        evidences = [
            ProviderEvidence(
                provider_name=self.name,
                evidence_type="shodan_service_discovery",
                description=f"Shodan indexed {len(ports)} open ports and {len(vulns_detail)} detected CVEs.",
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

    async def _execute_mock(self, ctx: ProviderRequestContext) -> ProviderResult:
        if ctx.ioc_type == IOCType.DOMAIN:
            mock_data = {ctx.ioc_value: "198.51.100.33"}
            return self._parse_response(ctx, mock_data)

        mock_data = {
            "ip_str": ctx.ioc_value,
            "ports": [22, 80, 443, 8080],
            "hostnames": ["mail-relay.darkthreat.org"],
            "domains": ["darkthreat.org"],
            "org": "DigitalOcean, LLC",
            "isp": "DigitalOcean",
            "asn": "AS14061",
            "country_name": "Germany",
            "city": "Frankfurt am Main",
            "os": "Linux 5.4.0",
            "devicetype": "general",
            "last_update": "2024-03-01T12:00:00.000000",
            "tags": ["cloud", "vpn"],
            "vulns": {
                "CVE-2021-44228": {"cvss": 10.0, "summary": "Log4j Remote Code Execution", "references": ["https://nvd.nist.gov/vuln/detail/CVE-2021-44228"]},
                "CVE-2023-4863": {"cvss": 8.8, "summary": "Heap buffer overflow in libwebp", "references": ["https://nvd.nist.gov/vuln/detail/CVE-2023-4863"]},
            },
            "data": [
                {
                    "port": 443,
                    "product": "nginx",
                    "version": "1.18.0",
                    "transport": "tcp",
                    "timestamp": "2024-03-01T11:58:00.000000",
                    "data": "HTTP/1.1 200 OK\r\nServer: nginx\r\n",
                    "http": {
                        "title": "Threat Relay Portal",
                        "server": "nginx/1.18.0",
                        "status": 200,
                        "components": {"Nginx": {}, "OpenSSL": {}},
                    },
                    "ssl": {
                        "cert": {
                            "fingerprint": {
                                "sha256": "3a2b1c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b"
                            },
                            "subject": {"CN": "mail-relay.darkthreat.org", "O": "DarkThreat Org"},
                            "issuer": {"CN": "Let's Encrypt Authority X3", "O": "Let's Encrypt"},
                            "issued": "2024-01-01T00:00:00",
                            "expires": "2024-04-01T00:00:00",
                        },
                        "cipher": {"name": "TLS_AES_256_GCM_SHA384"},
                        "versions": ["TLSv1.2", "TLSv1.3"],
                    },
                },
                {
                    "port": 22,
                    "product": "OpenSSH",
                    "version": "8.2p1",
                    "transport": "tcp",
                    "timestamp": "2024-02-28T09:30:00.000000",
                    "data": "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5\r\n",
                },
            ],
        }
        return self._parse_response(ctx, mock_data)
