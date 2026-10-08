import base64
import logging
import re
from datetime import datetime, timezone
import httpx
from typing import Dict, Any, List, Optional
from app.providers.base import BaseProvider, ProviderRequestContext

logger = logging.getLogger(__name__)
from app.schemas.ioc import IOCType, ProviderStatus
from app.schemas.provider import (
    ProviderCapability,
    ProviderResult,
    InfrastructureData,
    FileMetadata,
    CertInfo,
    DiscoveredIOC,
    ProviderEvidence,
    TTPTechnique,
    ThreatAttribution,
    HistoricalWhoisRecord,
    VirusTotalDetectionStats,
)
from app.services.ioc import normalize_ioc


VT_RELATIONSHIPS_BY_TYPE: Dict[IOCType, List[str]] = {
    IOCType.IPV4: [
        "communicating_files",
        "referrer_files",
        "historical_whois",
        "resolutions",
        "downloaded_files",
    ],
    IOCType.IPV6: [
        "communicating_files",
        "referrer_files",
        "historical_whois",
        "resolutions",
        "downloaded_files",
    ],
    IOCType.DOMAIN: [
        "communicating_files",
        "referrer_files",
        "historical_whois",
        "resolutions",
        "subdomains",
        "downloaded_files",
        "siblings",
    ],
    IOCType.URL: [
        "communicating_files",
        "referrer_files",
        "downloaded_files",
        "contacted_ips",
        "contacted_domains",
    ],
    IOCType.MD5: [
        "bundled_files",
        "dropped_files",
        "execution_parents",
        "contacted_ips",
        "contacted_domains",
        "contacted_urls",
        "related_files",
        "pe_resource_parents",
        "overlay_parents",
        "pcap_parents",
    ],
    IOCType.SHA1: [
        "bundled_files",
        "dropped_files",
        "execution_parents",
        "contacted_ips",
        "contacted_domains",
        "contacted_urls",
        "related_files",
        "pe_resource_parents",
        "overlay_parents",
        "pcap_parents",
    ],
    IOCType.SHA256: [
        "bundled_files",
        "dropped_files",
        "execution_parents",
        "contacted_ips",
        "contacted_domains",
        "contacted_urls",
        "related_files",
        "pe_resource_parents",
        "overlay_parents",
        "pcap_parents",
    ],
}


class VirusTotalProvider(BaseProvider):
    @property
    def name(self) -> str:
        return "virustotal"

    @property
    def display_name(self) -> str:
        return "VirusTotal"

    def get_capabilities(self) -> ProviderCapability:
        return ProviderCapability(
            name=self.name,
            display_name=self.display_name,
            description="Crowdsourced malware intelligence, multi-engine AV detection, passive DNS, and infrastructure metadata.",
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
            rate_limit_desc="4 requests/min, 500 requests/day (Public API)",
            provides_reputation=True,
            provides_infrastructure=True,
            provides_relationships=True,
            doc_url="https://docs.virustotal.com/reference/overview",
        )

    def _get_url_id(self, url: str) -> str:
        """VirusTotal v3 requires base64url encoded string without padding"""
        return base64.urlsafe_b64encode(url.encode()).decode().strip("=")

    async def _execute_live(self, ctx: ProviderRequestContext) -> ProviderResult:
        base_url = "https://www.virustotal.com/api/v3"
        headers = {"x-apikey": ctx.api_key or ""}

        if ctx.ioc_type in (IOCType.IPV4, IOCType.IPV6):
            collection_path = "ip_addresses"
            entity_id = ctx.ioc_value
        elif ctx.ioc_type == IOCType.DOMAIN:
            collection_path = "domains"
            entity_id = ctx.ioc_value
        elif ctx.ioc_type == IOCType.URL:
            collection_path = "urls"
            entity_id = self._get_url_id(ctx.ioc_value)
        elif ctx.ioc_type in (IOCType.MD5, IOCType.SHA1, IOCType.SHA256):
            collection_path = "files"
            entity_id = ctx.ioc_value
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
            # 1. Fetch base entity
            base_endpoint = f"{base_url}/{collection_path}/{entity_id}"
            resp = await client.get(base_endpoint, headers=headers)
            if resp.status_code == 404:
                return ProviderResult(
                    provider_name=self.name,
                    ioc_value=ctx.ioc_value,
                    ioc_type=ctx.ioc_type,
                    status=ProviderStatus.NOT_FOUND,
                    reputation_score=0.0,
                    classification="unknown",
                    raw_data=resp.json() if resp.text.startswith("{") else {},
                )
            elif resp.status_code in (401, 403):
                return ProviderResult(
                    provider_name=self.name,
                    ioc_value=ctx.ioc_value,
                    ioc_type=ctx.ioc_type,
                    status=ProviderStatus.UNAUTHORIZED,
                    error_details="VirusTotal authentication failed: invalid or unauthorized API key.",
                )
            elif resp.status_code == 429:
                return ProviderResult(
                    provider_name=self.name,
                    ioc_value=ctx.ioc_value,
                    ioc_type=ctx.ioc_type,
                    status=ProviderStatus.RATE_LIMITED,
                    error_details="VirusTotal rate limit exceeded (public API: 4 requests/minute).",
                )
            resp.raise_for_status()
            data = resp.json()

            data_obj = data.setdefault("data", {})
            relationships = data_obj.setdefault("relationships", {})

            # 2. Fetch every applicable relationship independently
            applicable_rels = VT_RELATIONSHIPS_BY_TYPE.get(ctx.ioc_type, [])
            paginated_rels: set[str] = set()

            for rel_name in applicable_rels:
                rel_obj = relationships.get(rel_name)
                needs_dedicated_fetch = True

                if isinstance(rel_obj, dict):
                    data_items = rel_obj.get("data")
                    meta_obj = rel_obj.get("meta") or {}
                    rep_count = meta_obj.get("count")
                    links_obj = rel_obj.get("links") or {}
                    has_next = bool(links_obj.get("next") or meta_obj.get("cursor"))

                    if has_next:
                        # Has pagination link/cursor (e.g. from mock test or previous fetch)
                        await self._paginate_single_relationship(
                            client,
                            headers,
                            rel_name,
                            rel_obj,
                            base_rel_url=f"{base_url}/{collection_path}/{entity_id}/{rel_name}",
                        )
                        paginated_rels.add(rel_name)
                        if rep_count is None or len(rel_obj.get("data", [])) >= rep_count or rel_obj.get("rate_limited"):
                            needs_dedicated_fetch = False
                    elif isinstance(data_items, list) and len(data_items) > 0:
                        # Embedded data without next link or cursor
                        # If rep_count is None or satisfied, no need to fetch dedicated
                        if rep_count is None or len(data_items) >= rep_count:
                            needs_dedicated_fetch = False
                            paginated_rels.add(rel_name)
                    elif rep_count == 0:
                        needs_dedicated_fetch = False
                        paginated_rels.add(rel_name)

                if not needs_dedicated_fetch:
                    continue

                # Query the dedicated relationship endpoint
                rel_url = f"{base_url}/{collection_path}/{entity_id}/{rel_name}?limit=40"
                try:
                    rel_resp = await client.get(rel_url, headers=headers)
                    if rel_resp.status_code == 200:
                        rel_json = rel_resp.json()
                        if isinstance(rel_json, dict) and isinstance(rel_json.get("data"), list):
                            relationships[rel_name] = rel_json
                            await self._paginate_single_relationship(
                                client,
                                headers,
                                rel_name,
                                rel_json,
                                base_rel_url=f"{base_url}/{collection_path}/{entity_id}/{rel_name}",
                            )
                            paginated_rels.add(rel_name)
                    elif rel_resp.status_code == 429:
                        logger.warning(f"VirusTotal rate limit (429) encountered while requesting relationship '{rel_name}'. Preserving collected data.")
                        break
                    elif rel_resp.status_code in (401, 403):
                        logger.debug(f"VirusTotal relationship '{rel_name}' forbidden/unauthorized (status {rel_resp.status_code}).")
                    else:
                        logger.debug(f"VirusTotal relationship '{rel_name}' returned status {rel_resp.status_code}.")
                except Exception as exc:
                    logger.warning(f"Error requesting VirusTotal relationship '{rel_name}': {exc}")

            # Also paginate any relationships present in relationships that were not in applicable_rels
            for ex_key, ex_obj in list(relationships.items()):
                if ex_key not in paginated_rels and isinstance(ex_obj, dict):
                    await self._paginate_single_relationship(
                        client,
                        headers,
                        ex_key,
                        ex_obj,
                        base_rel_url=f"{base_url}/{collection_path}/{entity_id}/{ex_key}",
                    )

            behaviour_data = None
            if ctx.ioc_type in (IOCType.MD5, IOCType.SHA1, IOCType.SHA256):
                try:
                    b_resp = await client.get(f"{base_url}/files/{ctx.ioc_value}/behaviour_summary", headers=headers)
                    if b_resp.status_code == 200:
                        behaviour_data = b_resp.json().get("data", {})
                except Exception:
                    pass

            return self._parse_response(ctx, data, behaviour_data=behaviour_data)
        finally:
            if should_close:
                await client.aclose()

    async def _paginate_single_relationship(
        self,
        client: httpx.AsyncClient,
        headers: Dict[str, str],
        rel_key: str,
        rel_obj: Dict[str, Any],
        max_pages: int = 10,
        max_items_per_rel: int = 250,
        base_rel_url: Optional[str] = None,
    ) -> None:
        """
        Paginates a single VirusTotal v3 relationship following links.next or meta.cursor.
        Handles rate limits (429) gracefully by preserving all previously fetched items.
        Guards against duplicate cursors and infinite loops.
        """
        if not isinstance(rel_obj, dict):
            return

        if "data" not in rel_obj or not isinstance(rel_obj["data"], list):
            rel_obj["data"] = []

        visited_urls: set[str] = set()
        visited_cursors: set[str] = set()
        pages_fetched = 0

        # Initial cursor from meta if present
        init_meta = rel_obj.get("meta") or {}
        if init_meta.get("cursor"):
            visited_cursors.add(str(init_meta.get("cursor")))

        # Determine initial next_url
        next_url = (rel_obj.get("links") or {}).get("next")
        if not next_url and init_meta.get("cursor"):
            self_url = (rel_obj.get("links") or {}).get("self") or base_rel_url
            if self_url:
                sep = "&" if "?" in self_url else "?"
                next_url = f"{self_url}{sep}cursor={init_meta.get('cursor')}&limit=40"

        while next_url and pages_fetched < max_pages and len(rel_obj["data"]) < max_items_per_rel:
            # Normalize relative next_url if needed
            if next_url.startswith("/"):
                next_url = f"https://www.virustotal.com{next_url}"
            elif not next_url.startswith("http"):
                next_url = f"https://www.virustotal.com/api/v3/{next_url.lstrip('/')}"

            if next_url in visited_urls:
                logger.debug(f"VirusTotal pagination loop detected for {rel_key} (URL already visited: {next_url}). Breaking.")
                break
            visited_urls.add(next_url)

            try:
                page_resp = await client.get(next_url, headers=headers)
                if page_resp.status_code == 429:
                    logger.warning(
                        f"VirusTotal rate limit (429) hit during relationship pagination for {rel_key}. "
                        f"Retaining {len(rel_obj['data'])} materialized items."
                    )
                    rel_obj["rate_limited"] = True
                    break
                elif page_resp.status_code != 200:
                    logger.warning(
                        f"VirusTotal relationship pagination returned status {page_resp.status_code} for {rel_key}. "
                        f"Retaining {len(rel_obj['data'])} materialized items."
                    )
                    break

                page_json = page_resp.json()
                page_items = page_json.get("data", [])
                if not page_items or not isinstance(page_items, list):
                    break

                rel_obj["data"].extend(page_items)
                pages_fetched += 1

                page_links = page_json.get("links") or {}
                page_meta = page_json.get("meta") or {}

                next_cursor = page_meta.get("cursor")
                if next_cursor:
                    cursor_str = str(next_cursor)
                    if cursor_str in visited_cursors:
                        logger.debug(f"VirusTotal pagination loop detected for {rel_key} (cursor already visited: {cursor_str}). Breaking.")
                        break
                    visited_cursors.add(cursor_str)

                next_url = page_links.get("next")
                if not next_url and next_cursor:
                    self_url = page_links.get("self") or (rel_obj.get("links") or {}).get("self") or base_rel_url
                    if self_url:
                        sep = "&" if "?" in self_url else "?"
                        next_url = f"{self_url}{sep}cursor={next_cursor}&limit=40"

            except Exception as exc:
                logger.warning(
                    f"Error during VirusTotal relationship pagination for {rel_key}: {exc}. "
                    f"Retaining {len(rel_obj['data'])} materialized items."
                )
                break

    async def _paginate_relationships(
        self,
        client: httpx.AsyncClient,
        headers: Dict[str, str],
        data: Dict[str, Any],
        max_pages: int = 10,
        max_items_per_rel: int = 250,
    ) -> None:
        data_obj = data.get("data")
        if not isinstance(data_obj, dict):
            return
        relationships = data_obj.get("relationships")
        if not isinstance(relationships, dict):
            return
        for rel_key, rel_obj in list(relationships.items()):
            if isinstance(rel_obj, dict):
                await self._paginate_single_relationship(client, headers, rel_key, rel_obj, max_pages, max_items_per_rel)

    def _parse_response(
        self,
        ctx: ProviderRequestContext,
        data: Dict[str, Any],
        behaviour_data: Optional[Dict[str, Any]] = None,
    ) -> ProviderResult:
        data_obj = data.get("data", {})
        attrs = data_obj.get("attributes", {})
        rels = data_obj.get("relationships", {})
        stats_raw = attrs.get("last_analysis_stats")
        vt_stats_obj = VirusTotalDetectionStats.from_api_stats(stats_raw if isinstance(stats_raw, dict) else {})
        malicious = vt_stats_obj.malicious
        suspicious = vt_stats_obj.suspicious
        harmless = vt_stats_obj.harmless
        reputation = attrs.get("reputation", 0)

        # Determine classification
        if malicious > 3:
            classification = "malicious"
        elif malicious > 0 or suspicious > 2:
            classification = "suspicious"
        elif harmless > 10:
            classification = "benign"
        else:
            classification = "unknown"

        tags = attrs.get("tags", [])
        is_hash = ctx.ioc_type in (IOCType.MD5, IOCType.SHA1, IOCType.SHA256)

        # Build Rich Layer 2 File Details when investigating files/hashes
        file_meta = None
        if is_hash or attrs.get("size") or attrs.get("type_description"):
            ts_dict = {}
            if attrs.get("first_submission_date"):
                ts_dict["first_submission"] = str(attrs["first_submission_date"])
            if attrs.get("last_submission_date"):
                ts_dict["last_submission"] = str(attrs["last_submission_date"])
            if attrs.get("creation_date"):
                ts_dict["creation_date"] = str(attrs["creation_date"])
            if attrs.get("last_analysis_date"):
                ts_dict["last_analysis"] = str(attrs["last_analysis_date"])
            if attrs.get("times_submitted"):
                ts_dict["times_submitted"] = str(attrs["times_submitted"])
            if isinstance(attrs.get("signature_info"), dict):
                sig = attrs["signature_info"]
                sig_date = sig.get("signing date") or sig.get("signing_date") or sig.get("date")
                if sig_date:
                    ts_dict["signature_date"] = str(sig_date)

            trid_list = []
            for tr in (attrs.get("trid") or []):
                if isinstance(tr, dict):
                    trid_list.append(tr)
                elif isinstance(tr, str):
                    trid_list.append({"file_type": tr})

            pe_info = attrs.get("pe_info")
            imphash = pe_info.get("imphash") if isinstance(pe_info, dict) else attrs.get("imphash")
            rich_pe_header_hash = pe_info.get("rich_pe_header_hash") if isinstance(pe_info, dict) else None
            compiler_info = pe_info.get("compiler_product") if isinstance(pe_info, dict) else None

            # Extract MITRE ATT&CK TTPs
            vt_ttps: List[TTPTechnique] = []
            seen_tech_ids = set()
            if behaviour_data:
                for item in behaviour_data.get("mitre_attack_techniques", []):
                    t_id = item.get("id")
                    if t_id and t_id not in seen_tech_ids:
                        seen_tech_ids.add(t_id)
                        vt_ttps.append(TTPTechnique(
                            technique_id=t_id,
                            description=item.get("signature_description"),
                            severity=item.get("severity"),
                            sources=["virustotal"],
                        ))
                for t_id, t_items in (behaviour_data.get("attack_techniques") or {}).items():
                    if t_id and t_id not in seen_tech_ids:
                        seen_tech_ids.add(t_id)
                        desc = None
                        sev = None
                        if isinstance(t_items, list) and t_items:
                            desc = t_items[0].get("description")
                            sev = t_items[0].get("severity")
                        vt_ttps.append(TTPTechnique(
                            technique_id=t_id,
                            description=desc,
                            severity=sev,
                            sources=["virustotal"],
                        ))

            file_meta = FileMetadata(
                file_type=attrs.get("type_description") or attrs.get("type_tag"),
                magic=attrs.get("magic"),
                file_size=attrs.get("size"),
                md5=attrs.get("md5"),
                sha1=attrs.get("sha1"),
                sha256=attrs.get("sha256"),
                vhash=attrs.get("vhash"),
                authentihash=attrs.get("authentihash"),
                imphash=imphash,
                rich_pe_header_hash=rich_pe_header_hash,
                ssdeep=attrs.get("ssdeep"),
                tlsh=attrs.get("tlsh"),
                trid=trid_list,
                detectiteasy=attrs.get("detectiteasy") if isinstance(attrs.get("detectiteasy"), dict) else None,
                magika=attrs.get("magika"),
                pe_info=pe_info if isinstance(pe_info, dict) else None,
                compiler_info=compiler_info,
                timestamps=ts_dict,
                file_names=attrs.get("names", [])[:25] if isinstance(attrs.get("names"), list) else [],
                signature_info=attrs.get("signature_info") if isinstance(attrs.get("signature_info"), dict) else None,
                ttps=vt_ttps,
                sources=["virustotal"],
            )

        # Extract DNS records and Nameservers
        vt_dns_records: Dict[str, List[str]] = {}
        vt_nameservers: List[str] = []
        for rec in attrs.get("last_dns_records", []):
            rtype = rec.get("type")
            rval = rec.get("value")
            if rtype and rval:
                if rtype not in vt_dns_records:
                    vt_dns_records[rtype] = []
                if rval not in vt_dns_records[rtype]:
                    vt_dns_records[rtype].append(rval)
                if rtype == "NS" and rval not in vt_nameservers:
                    vt_nameservers.append(rval)

        # Extract HTTPS Certificate from last_https_certificate
        vt_certs_detail: List[CertInfo] = []
        last_cert = attrs.get("last_https_certificate")
        if isinstance(last_cert, dict):
            fp = last_cert.get("thumbprint_sha256") or last_cert.get("thumbprint")
            subj = last_cert.get("subject", {})
            iss = last_cert.get("issuer", {})
            val = last_cert.get("validity", {})
            ext = last_cert.get("extensions", {})
            sans = []
            san_raw = ext.get("subject_alternative_name")
            if isinstance(san_raw, list):
                sans = [s.strip() for s in san_raw if isinstance(s, str) and s.strip()]
            elif isinstance(san_raw, str):
                sans = [s.strip() for s in san_raw.split(",") if s.strip()]

            vt_certs_detail.append(CertInfo(
                fingerprint_sha256=fp,
                subject_cn=subj.get("CN"),
                subject_org=subj.get("O"),
                issuer_cn=iss.get("CN"),
                issuer_org=iss.get("O"),
                sans=sans,
                valid_from=val.get("not_before"),
                valid_to=val.get("not_after"),
                serial_number=str(last_cert.get("serial_number")) if last_cert.get("serial_number") else None,
                sources=["virustotal"],
            ))

        # Extract HTTP metadata for URLs
        last_headers = attrs.get("last_http_response_headers", {})
        http_server = last_headers.get("server") if isinstance(last_headers, dict) else None
        http_title = attrs.get("title")

        # Extract VirusTotal Threat Attribution (Popular threat classification & threat names)
        vt_malware_families: List[str] = []
        vt_threat_actors: List[str] = []
        vt_threat_attributions: List[ThreatAttribution] = []

        pop_threat = attrs.get("popular_threat_classification") or {}
        suggested_threat_label = pop_threat.get("suggested_threat_label")
        pop_names = pop_threat.get("popular_threat_name") or []
        pop_cats = pop_threat.get("popular_threat_category") or []

        top_cat = None
        if isinstance(pop_cats, list) and pop_cats:
            first_cat = pop_cats[0]
            top_cat = first_cat.get("value") if isinstance(first_cat, dict) else str(first_cat)

        all_names: List[str] = []
        if isinstance(pop_names, list):
            for item in pop_names:
                if isinstance(item, dict):
                    val = item.get("value")
                    if val and str(val) not in all_names:
                        all_names.append(str(val))
                elif isinstance(item, str) and item not in all_names:
                    all_names.append(item)

        # Fallback to threat_names or popular_threat_names
        for tn in (attrs.get("threat_names") or attrs.get("popular_threat_names") or []):
            if tn and str(tn) not in all_names:
                all_names.append(str(tn))

        # Check tags for malware or actor indicators
        for t in (tags or []):
            t_low = t.lower()
            if any(k in t_low for k in ["ransomware", "trojan", "stealer", "rat", "botnet", "c2", "miner", "apt", "bear", "spider"]):
                if t not in all_names:
                    all_names.append(t)

        if all_names:
            primary_family = all_names[0]
            for n in all_names:
                if n not in vt_malware_families:
                    vt_malware_families.append(n)

            alias_list = [n for n in all_names if n != primary_family]
            evidence_label = suggested_threat_label or primary_family
            vt_threat_attributions.append(
                ThreatAttribution(
                    malware_family=primary_family,
                    malware_names=all_names,
                    malware_type=top_cat,
                    aliases=alias_list,
                    threat_tags=[t for t in tags if t in all_names or "malware" in t.lower() or "trojan" in t.lower()],
                    ttps=file_meta.ttps if file_meta else [],
                    sources=["virustotal"],
                    confidence=min(95.0, 60.0 + len(all_names) * 5),
                    evidence_summary=f"VirusTotal popular threat classification '{evidence_label}'"
                )
            )
        elif suggested_threat_label:
            vt_malware_families.append(suggested_threat_label)
            vt_threat_attributions.append(
                ThreatAttribution(
                    malware_family=suggested_threat_label,
                    malware_names=[suggested_threat_label],
                    malware_type=top_cat,
                    ttps=file_meta.ttps if file_meta else [],
                    sources=["virustotal"],
                    confidence=75.0,
                    evidence_summary=f"VirusTotal suggested threat label '{suggested_threat_label}'"
                )
            )

        # Extract Historical WHOIS records
        hw_container = rels.get("historical_whois")
        historical_whois_records: List[HistoricalWhoisRecord] = []
        if isinstance(hw_container, dict):
            hw_items = hw_container.get("data", [])
            if isinstance(hw_items, list):
                for hw in hw_items:
                    if not isinstance(hw, dict):
                        continue
                    hw_attrs = hw.get("attributes", {})
                    whois_map = hw_attrs.get("whois_map") or {}

                    fs = hw_attrs.get("first_seen_date") or hw_attrs.get("first_seen")
                    lu = hw_attrs.get("last_updated_date") or hw_attrs.get("last_updated")
                    fs_str = None
                    lu_str = None
                    fs_ts = None
                    lu_ts = None
                    if fs:
                        try:
                            if isinstance(fs, (int, float)):
                                fs_ts = int(fs)
                                fs_str = datetime.fromtimestamp(fs_ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
                            else:
                                fs_str = str(fs)
                        except Exception:
                            fs_str = str(fs)
                    if lu:
                        try:
                            if isinstance(lu, (int, float)):
                                lu_ts = int(lu)
                                lu_str = datetime.fromtimestamp(lu_ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
                            else:
                                lu_str = str(lu)
                        except Exception:
                            lu_str = str(lu)

                    def _get_map_val(keys: List[str]) -> Optional[str]:
                        for k in keys:
                            for mk, mv in whois_map.items():
                                if mk.lower() == k.lower() and mv:
                                    if isinstance(mv, list):
                                        return ", ".join(str(x) for x in mv if x)
                                    return str(mv).strip()
                        return None

                    def _get_map_list(keys: List[str]) -> List[str]:
                        res = []
                        for k in keys:
                            for mk, mv in whois_map.items():
                                if mk.lower() == k.lower() and mv:
                                    if isinstance(mv, list):
                                        for x in mv:
                                            if str(x).strip():
                                                res.append(str(x).strip())
                                    elif isinstance(mv, str):
                                        for line in mv.replace(",", "\n").split("\n"):
                                            s = line.strip()
                                            if s and s not in res:
                                                res.append(s)
                        return res

                    registrar = _get_map_val(["Registrar", "Sponsoring Registrar", "registrar_name"]) or hw_attrs.get("registrar")
                    registrar_url = _get_map_val(["Registrar URL", "registrar_url"]) or hw_attrs.get("registrar_url")
                    registrar_whois_server = _get_map_val(["Registrar WHOIS Server", "whois_server"]) or hw_attrs.get("whois_server")
                    creation_date = _get_map_val(["Creation Date", "Created Date", "Registration Time"]) or (str(hw_attrs.get("creation_date")) if hw_attrs.get("creation_date") else None)
                    updated_date = _get_map_val(["Updated Date", "Last Updated On"]) or (str(hw_attrs.get("updated_date")) if hw_attrs.get("updated_date") else None)
                    expiry_date = _get_map_val(["Registry Expiry Date", "Expiration Date", "Registrar Registration Expiration Date"]) or (str(hw_attrs.get("expiry_date")) if hw_attrs.get("expiry_date") else None)

                    reg_obj = hw_attrs.get("registrant") if isinstance(hw_attrs.get("registrant"), dict) else {}
                    reg_org = _get_map_val(["Registrant Organization", "Organization", "Tech Organization", "Admin Organization"]) or reg_obj.get("organization") or hw_attrs.get("registrant_organization")
                    reg_country = _get_map_val(["Registrant Country", "Country"]) or reg_obj.get("country") or hw_attrs.get("registrant_country")
                    reg_name = _get_map_val(["Registrant Name"]) or reg_obj.get("name") or hw_attrs.get("registrant_name")
                    reg_email = _get_map_val(["Registrant Email"]) or reg_obj.get("email") or hw_attrs.get("registrant_email")
                    origin_as = _get_map_val(["OriginAS", "Origin AS", "origin_as"]) or hw_attrs.get("origin_as")

                    nameservers = _get_map_list(["Name Server", "Name Servers", "nserver"])
                    if not nameservers and hw_attrs.get("name_servers"):
                        ns_attr = hw_attrs.get("name_servers")
                        if isinstance(ns_attr, list):
                            nameservers = [str(x).strip() for x in ns_attr if str(x).strip()]
                        elif isinstance(ns_attr, str):
                            nameservers = [x.strip() for x in ns_attr.split(",") if x.strip()]

                    domain_status = _get_map_list(["Domain Status", "status"])
                    if not domain_status and hw_attrs.get("status"):
                        st_attr = hw_attrs.get("status")
                        if isinstance(st_attr, list):
                            domain_status = [str(x).strip() for x in st_attr if str(x).strip()]
                        elif isinstance(st_attr, str):
                            domain_status = [x.strip() for x in st_attr.split(",") if x.strip()]

                    hw_rec = HistoricalWhoisRecord(
                        id=hw.get("id"),
                        first_seen=fs_str,
                        last_updated=lu_str,
                        first_seen_timestamp=fs_ts,
                        last_updated_timestamp=lu_ts,
                        registrar=registrar,
                        registrar_url=registrar_url,
                        registrar_whois_server=registrar_whois_server,
                        creation_date=creation_date,
                        updated_date=updated_date,
                        expiry_date=expiry_date,
                        registrant_organization=reg_org,
                        registrant_country=reg_country,
                        registrant_name=reg_name,
                        registrant_email=reg_email,
                        nameservers=nameservers,
                        domain_status=domain_status,
                        origin_as=origin_as,
                        raw_map=whois_map,
                        sources=["virustotal"],
                    )
                    historical_whois_records.append(hw_rec)

        # Extract reported and materialized relationship counts
        vt_reported_counts: Dict[str, int] = {}
        vt_materialized_counts: Dict[str, int] = {}
        for rel_k, rel_v in rels.items():
            if isinstance(rel_v, dict):
                m = rel_v.get("meta") or {}
                if m.get("count") is not None:
                    try:
                        vt_reported_counts[rel_k] = int(m.get("count"))
                    except (ValueError, TypeError):
                        pass
                if "data" in rel_v and isinstance(rel_v["data"], list):
                    vt_materialized_counts[rel_k] = len(rel_v["data"])

        # Infrastructure
        infra = InfrastructureData(
            asn=str(attrs.get("asn")) if (attrs.get("asn") and not is_hash) else None,
            asn_name=attrs.get("as_owner") if not is_hash else None,
            country=attrs.get("country") if not is_hash else None,
            cidr=attrs.get("network") if not is_hash else None,
            registrar=attrs.get("registrar") if not is_hash else None,
            whois_creation=str(attrs.get("creation_date")) if (attrs.get("creation_date") and not is_hash) else None,
            whois_expiration=str(attrs.get("expiration_date")) if (attrs.get("expiration_date") and not is_hash) else None,
            nameservers=vt_nameservers,
            dns_records=vt_dns_records,
            certificates_detail=vt_certs_detail,
            http_title=http_title,
            http_server=http_server,
            file_type=attrs.get("type_description") or attrs.get("type_tag"),
            file_size=attrs.get("size"),
            file_metadata=file_meta,
            ttps=file_meta.ttps if file_meta else [],
            threat_attribution=vt_threat_attributions[0] if vt_threat_attributions else None,
            threat_attributions=vt_threat_attributions,
            historical_whois=historical_whois_records,
            extra={
                "reputation": reputation,
                "community_votes": attrs.get("total_votes", {}),
                "jarm": attrs.get("jarm"),
                "magic": attrs.get("magic"),
                "md5": attrs.get("md5"),
                "sha1": attrs.get("sha1"),
                "sha256": attrs.get("sha256"),
                "vhash": attrs.get("vhash"),
                "ssdeep": attrs.get("ssdeep"),
                "tlsh": attrs.get("tlsh"),
                "vt_reported_counts": vt_reported_counts,
                "vt_materialized_counts": vt_materialized_counts,
            },
        )

        # Discovered IOCs (Layer 3 Relations)
        discovered: List[DiscoveredIOC] = []

        # Historical WHOIS Layer 3 IOC Extraction (Nameservers & infrastructure)
        seen_whois_iocs = set()
        for hw_rec in historical_whois_records:
            for ns in hw_rec.nameservers:
                ns_clean = ns.split()[0].rstrip(".").lower()
                norm = normalize_ioc(ns_clean, IOCType.DOMAIN)
                if norm.is_valid and norm.canonical_value != ctx.ioc_value.lower() and norm.canonical_value not in seen_whois_iocs:
                    seen_whois_iocs.add(norm.canonical_value)
                    discovered.append(
                        DiscoveredIOC(
                            raw_value=ns_clean,
                            canonical_value=norm.canonical_value,
                            ioc_type=IOCType.DOMAIN,
                            relationship_type="whois_name_server",
                            confidence=80.0,
                            first_seen=hw_rec.first_seen,
                            last_seen=hw_rec.last_updated,
                            evidence_desc=f"VirusTotal historical WHOIS observed name server {norm.canonical_value}",
                            metadata={
                                "relationship": "whois_name_server",
                                "provider": "virustotal",
                                "first_seen": hw_rec.first_seen,
                                "last_seen": hw_rec.last_updated,
                                "registrar": hw_rec.registrar,
                            },
                        )
                    )

        # 1. Contacted IPs
        cip_meta = rels.get("contacted_ips", {}).get("meta", {}) if isinstance(rels.get("contacted_ips"), dict) else {}
        cip_rep = cip_meta.get("count")
        cip_mat = len(rels.get("contacted_ips", {}).get("data", [])) if isinstance(rels.get("contacted_ips"), dict) else 0
        for item in rels.get("contacted_ips", {}).get("data", []):
            ip_val = item.get("id")
            if ip_val and ip_val != ctx.ioc_value:
                discovered.append(
                    DiscoveredIOC(
                        raw_value=ip_val,
                        canonical_value=ip_val,
                        ioc_type=IOCType.IPV6 if ":" in ip_val else IOCType.IPV4,
                        relationship_type="contacted_ip",
                        confidence=85.0,
                        evidence_desc="VirusTotal dynamic sandbox observed contacted IP",
                        metadata={
                            "relationship": "contacted_ip",
                            "provider": "virustotal",
                            **({"vt_reported_count": int(cip_rep)} if cip_rep is not None else {}),
                            "vt_materialized_count": cip_mat,
                        },
                    )
                )

        # 2. Contacted Domains
        cdom_meta = rels.get("contacted_domains", {}).get("meta", {}) if isinstance(rels.get("contacted_domains"), dict) else {}
        cdom_rep = cdom_meta.get("count")
        cdom_mat = len(rels.get("contacted_domains", {}).get("data", [])) if isinstance(rels.get("contacted_domains"), dict) else 0
        for item in rels.get("contacted_domains", {}).get("data", []):
            dom_val = item.get("id")
            if dom_val and dom_val != ctx.ioc_value:
                discovered.append(
                    DiscoveredIOC(
                        raw_value=dom_val,
                        canonical_value=dom_val.lower().rstrip("."),
                        ioc_type=IOCType.DOMAIN,
                        relationship_type="contacted_domain",
                        confidence=85.0,
                        evidence_desc="VirusTotal dynamic sandbox observed contacted domain",
                        metadata={
                            "relationship": "contacted_domain",
                            "provider": "virustotal",
                            **({"vt_reported_count": int(cdom_rep)} if cdom_rep is not None else {}),
                            "vt_materialized_count": cdom_mat,
                        },
                    )
                )

        # 3. Subdomains from relationships
        sub_meta = rels.get("subdomains", {}).get("meta", {}) if isinstance(rels.get("subdomains"), dict) else {}
        sub_rep = sub_meta.get("count")
        sub_mat = len(rels.get("subdomains", {}).get("data", [])) if isinstance(rels.get("subdomains"), dict) else 0
        for item in rels.get("subdomains", {}).get("data", []):
            sub_val = item.get("id")
            if sub_val and sub_val.lower() != ctx.ioc_value.lower():
                discovered.append(
                    DiscoveredIOC(
                        raw_value=sub_val,
                        canonical_value=sub_val.lower().rstrip("."),
                        ioc_type=IOCType.DOMAIN,
                        relationship_type="subdomain",
                        confidence=85.0,
                        evidence_desc="VirusTotal enumerated subdomain",
                        metadata={
                            "relationship": "subdomain",
                            "provider": "virustotal",
                            **({"vt_reported_count": int(sub_rep)} if sub_rep is not None else {}),
                            "vt_materialized_count": sub_mat,
                        },
                    )
                )

        # 4. Contacted URLs
        curl_meta = rels.get("contacted_urls", {}).get("meta", {}) if isinstance(rels.get("contacted_urls"), dict) else {}
        curl_rep = curl_meta.get("count")
        curl_mat = len(rels.get("contacted_urls", {}).get("data", [])) if isinstance(rels.get("contacted_urls"), dict) else 0
        for item in rels.get("contacted_urls", {}).get("data", []):
            ctx_attrs = item.get("context_attributes", {})
            url_val = ctx_attrs.get("url") or item.get("id")
            if url_val and url_val != ctx.ioc_value and url_val.startswith("http"):
                discovered.append(
                    DiscoveredIOC(
                        raw_value=url_val,
                        canonical_value=url_val,
                        ioc_type=IOCType.URL,
                        relationship_type="contacted_url",
                        confidence=85.0,
                        evidence_desc="VirusTotal dynamic sandbox observed contacted URL",
                        metadata={
                            "relationship": "contacted_url",
                            "provider": "virustotal",
                            **({"vt_reported_count": int(curl_rep)} if curl_rep is not None else {}),
                            "vt_materialized_count": curl_mat,
                        },
                    )
                )

        # 5. URL Outgoing Links
        for link in (attrs.get("outgoing_links") or [])[:10]:
            if link and isinstance(link, str) and link.startswith("http") and link != ctx.ioc_value:
                discovered.append(
                    DiscoveredIOC(
                        raw_value=link,
                        canonical_value=link,
                        ioc_type=IOCType.URL,
                        relationship_type="links_to",
                        confidence=80.0,
                        evidence_desc="VirusTotal observed outgoing link",
                    )
                )

        # 6. Passive DNS Resolutions
        res_meta = rels.get("resolutions", {}).get("meta", {}) if isinstance(rels.get("resolutions"), dict) else {}
        res_rep = res_meta.get("count")
        res_mat = len(rels.get("resolutions", {}).get("data", [])) if isinstance(rels.get("resolutions"), dict) else 0
        for item in (rels.get("resolutions", {}).get("data", []) if isinstance(rels.get("resolutions"), dict) else []):
            if not isinstance(item, dict):
                continue
            r_attrs = item.get("attributes", {})
            host_name = r_attrs.get("host_name")
            ip_addr = r_attrs.get("ip_address")
            date_val = r_attrs.get("date")
            date_str = None
            if date_val:
                try:
                    if isinstance(date_val, (int, float)):
                        date_str = datetime.fromtimestamp(int(date_val), tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
                    else:
                        date_str = str(date_val)
                except Exception:
                    date_str = str(date_val)

            target_val = None
            target_ioc_type = None
            if host_name:
                norm_h = normalize_ioc(host_name, IOCType.DOMAIN)
                if norm_h.is_valid and norm_h.canonical_value != ctx.ioc_value.lower():
                    target_val = norm_h.canonical_value
                    target_ioc_type = IOCType.DOMAIN
            elif ip_addr:
                norm_ip = normalize_ioc(ip_addr, IOCType.IPV4 if ":" not in ip_addr else IOCType.IPV6)
                if norm_ip.is_valid and norm_ip.canonical_value != ctx.ioc_value:
                    target_val = norm_ip.canonical_value
                    target_ioc_type = norm_ip.ioc_type

            if target_val and target_ioc_type:
                discovered.append(
                    DiscoveredIOC(
                        raw_value=target_val,
                        canonical_value=target_val,
                        ioc_type=target_ioc_type,
                        relationship_type="resolves_to",
                        confidence=85.0,
                        first_seen=date_str,
                        last_seen=date_str,
                        evidence_desc="VirusTotal passive DNS resolution",
                        metadata={
                            "relationship": "resolves_to",
                            "provider": "virustotal",
                            **({"vt_reported_count": int(res_rep)} if res_rep is not None else {}),
                            "vt_materialized_count": res_mat,
                            **({"resolution_date": date_str} if date_str else {}),
                        },
                    )
                )

        # 7. File-bearing relationships (communicating_files, bundled_files, dropped_files, downloaded_files, related_files, execution_parents, referrer_files, etc.)
        FILE_RELATION_MAP = {
            "communicating_files": "communicating_file",
            "bundled_files": "bundled_file",
            "dropped_files": "dropped_file",
            "downloaded_files": "downloaded_file",
            "related_files": "related_file",
            "execution_parents": "execution_parent",
            "referrer_files": "referrer_file",
            "pe_resource_parents": "pe_resource_parent",
            "overlay_parents": "overlay_parent",
            "pcap_parents": "pcap_parent",
        }

        for rel_key, rel_container in rels.items():
            is_file_rel = (
                rel_key in FILE_RELATION_MAP
                or rel_key.endswith("_files")
                or rel_key.endswith("_parents")
                or "file" in rel_key
            )
            rel_items = rel_container.get("data", []) if isinstance(rel_container, dict) else []
            if not isinstance(rel_items, list):
                continue

            rel_meta = rel_container.get("meta") or {} if isinstance(rel_container, dict) else {}
            rel_reported_count = rel_meta.get("count")
            rel_materialized_count = len(rel_items)

            for item in rel_items:
                if not isinstance(item, dict):
                    continue

                item_type = item.get("type")
                # Ensure object represents a file: either explicit type "file", or member of known file relations without conflicting non-file type
                if not (item_type == "file" or (is_file_rel and item_type not in ("ip_address", "domain", "url", "resolution"))):
                    continue

                item_attrs = item.get("attributes") or {}
                item_ctx = item.get("context_attributes") or {}

                sha256 = item_attrs.get("sha256") or item.get("sha256") or item_ctx.get("sha256")
                sha1 = item_attrs.get("sha1") or item.get("sha1") or item_ctx.get("sha1")
                md5 = item_attrs.get("md5") or item.get("md5") or item_ctx.get("md5")
                item_id = (item.get("id") or "").strip()

                target_hash = None
                target_type = None

                # Prefer SHA256 -> SHA1 -> MD5
                if sha256 and re.match(r"^[0-9a-fA-F]{64}$", str(sha256)):
                    target_hash = str(sha256).lower()
                    target_type = IOCType.SHA256
                elif sha1 and re.match(r"^[0-9a-fA-F]{40}$", str(sha1)):
                    target_hash = str(sha1).lower()
                    target_type = IOCType.SHA1
                elif md5 and re.match(r"^[0-9a-fA-F]{32}$", str(md5)):
                    target_hash = str(md5).lower()
                    target_type = IOCType.MD5
                elif item_id and re.match(r"^[0-9a-fA-F]{64}$", item_id):
                    target_hash = item_id.lower()
                    target_type = IOCType.SHA256
                elif item_id and re.match(r"^[0-9a-fA-F]{40}$", item_id):
                    target_hash = item_id.lower()
                    target_type = IOCType.SHA1
                elif item_id and re.match(r"^[0-9a-fA-F]{32}$", item_id):
                    target_hash = item_id.lower()
                    target_type = IOCType.MD5

                # Skip if no valid hash or points to the root indicator itself
                if not target_hash or target_hash == ctx.ioc_value.lower():
                    continue

                # Map relationship label
                if rel_key in FILE_RELATION_MAP:
                    rel_type = FILE_RELATION_MAP[rel_key]
                elif rel_key.endswith("s"):
                    rel_type = rel_key[:-1]
                else:
                    rel_type = rel_key

                # Extract useful metadata
                meaningful_name = item_attrs.get("meaningful_name")
                names_list = item_attrs.get("names") or []
                ctx_fname = item_ctx.get("filename")
                item_fname = item.get("filename") or item.get("file_name") or item.get("name")
                filename = meaningful_name or (names_list[0] if names_list else None) or ctx_fname or item_fname
                if filename and re.match(r"^[0-9a-fA-F]{32,64}$", filename):
                    filename = None  # don't duplicate hash as filename

                file_type_desc = (
                    item_attrs.get("type_description")
                    or item_attrs.get("type_tag")
                    or item_attrs.get("magika")
                    or item.get("file_type")
                )

                # Detections
                item_stats = item_attrs.get("last_analysis_stats") or item.get("last_analysis_stats") or item_ctx.get("last_analysis_stats")
                detections_str = None
                is_malicious = False
                if isinstance(item_stats, dict):
                    mal = item_stats.get("malicious", 0) + item_stats.get("suspicious", 0)
                    total = sum(v for v in item_stats.values() if isinstance(v, (int, float)))
                    if total > 0:
                        detections_str = f"{mal}/{total}"
                    is_malicious = mal > 0
                elif item.get("detections"):
                    detections_str = str(item.get("detections"))
                    if "/" in detections_str:
                        try:
                            m_count = int(detections_str.split("/")[0])
                            is_malicious = m_count > 0
                        except Exception:
                            pass

                # First / last seen
                first_seen = item_attrs.get("first_submission_date") or item_ctx.get("first_seen_date") or item.get("first_seen")
                last_seen = item_attrs.get("last_submission_date") or item_attrs.get("last_analysis_date") or item.get("last_seen")

                first_seen_str = None
                if first_seen:
                    try:
                        if isinstance(first_seen, (int, float)):
                            first_seen_str = datetime.fromtimestamp(first_seen, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
                        else:
                            first_seen_str = str(first_seen)
                    except Exception:
                        first_seen_str = str(first_seen)

                last_seen_str = None
                if last_seen:
                    try:
                        if isinstance(last_seen, (int, float)):
                            last_seen_str = datetime.fromtimestamp(last_seen, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
                        else:
                            last_seen_str = str(last_seen)
                    except Exception:
                        last_seen_str = str(last_seen)

                # Metadata dict
                meta: Dict[str, Any] = {
                    "relationship": rel_type,
                    "provider": "virustotal",
                }
                if rel_reported_count is not None:
                    try:
                        meta["vt_reported_count"] = int(rel_reported_count)
                    except (ValueError, TypeError):
                        pass
                meta["vt_materialized_count"] = rel_materialized_count
                if filename:
                    meta["filename"] = filename
                if file_type_desc:
                    meta["file_type"] = file_type_desc
                if detections_str:
                    meta["detections"] = detections_str
                if item_id:
                    meta["vt_object_id"] = item_id
                if first_seen_str:
                    meta["first_seen"] = first_seen_str
                if last_seen_str:
                    meta["last_seen"] = last_seen_str

                # Evidence description
                desc_rel = rel_type.replace('_', ' ')
                if rel_reported_count is not None:
                    try:
                        rep_val = int(rel_reported_count)
                        if rep_val > rel_materialized_count:
                            desc_parts = [f"VirusTotal {desc_rel} ({rel_materialized_count} of {rep_val} materialized)"]
                        else:
                            desc_parts = [f"VirusTotal {desc_rel} ({rep_val} reported)"]
                    except (ValueError, TypeError):
                        desc_parts = [f"VirusTotal {desc_rel}"]
                else:
                    desc_parts = [f"VirusTotal {desc_rel}"]

                if filename:
                    desc_parts.append(f"file: {filename}")
                if detections_str:
                    desc_parts.append(f"detections: {detections_str}")
                evidence_desc = " - ".join(desc_parts)

                discovered.append(
                    DiscoveredIOC(
                        raw_value=target_hash,
                        canonical_value=target_hash,
                        ioc_type=target_type,
                        relationship_type=rel_type,
                        confidence=90.0 if is_malicious else 80.0,
                        first_seen=first_seen_str,
                        last_seen=last_seen_str,
                        evidence_desc=evidence_desc,
                        metadata=meta,
                    )
                )

        # 5. Cross-Hashes (MD5, SHA1, SHA256)
        if is_hash:
            for h_type, h_key in [(IOCType.MD5, "md5"), (IOCType.SHA1, "sha1"), (IOCType.SHA256, "sha256")]:
                h_val = attrs.get(h_key)
                if h_val and h_val.lower() != ctx.ioc_value.lower() and ctx.ioc_type != h_type:
                    discovered.append(
                        DiscoveredIOC(
                            raw_value=h_val,
                            canonical_value=h_val.lower(),
                            ioc_type=h_type,
                            relationship_type="associated_hash",
                            confidence=95.0,
                            evidence_desc=f"VirusTotal cryptographic digest ({h_key.upper()})",
                        )
                    )

        # 6. DNS Records for Domain/IP
        last_dns = attrs.get("last_dns_records", [])
        for rec in last_dns:
            rec_type = rec.get("type")
            rec_val = rec.get("value")
            if not rec_val:
                continue
            if rec_type in ("A", "AAAA"):
                discovered.append(
                    DiscoveredIOC(
                        raw_value=rec_val,
                        canonical_value=rec_val,
                        ioc_type=IOCType.IPV4 if rec_type == "A" else IOCType.IPV6,
                        relationship_type="resolves_to",
                        confidence=85.0,
                        evidence_desc="VirusTotal observed DNS resolution",
                    )
                )
            elif rec_type in ("NS", "MX", "CNAME"):
                discovered.append(
                    DiscoveredIOC(
                        raw_value=rec_val,
                        canonical_value=rec_val.lower().rstrip("."),
                        ioc_type=IOCType.DOMAIN,
                        relationship_type=f"shares_{rec_type.lower()}",
                        confidence=75.0,
                        evidence_desc=f"VirusTotal {rec_type} record",
                    )
                )

        evidences = [
            ProviderEvidence(
                provider_name=self.name,
                evidence_type="antivirus_detections",
                description=f"{malicious} security engines detected this IOC as malicious ({suspicious} suspicious).",
                confidence=min(100.0, float(malicious * 10 + 30)),
            )
        ]

        vt_engines_map = vt_stats_obj.to_dict()

        return ProviderResult(
            provider_name=self.name,
            ioc_value=ctx.ioc_value,
            ioc_type=ctx.ioc_type,
            status=ProviderStatus.SUCCESS,
            reputation_score=float(reputation),
            classification=classification,
            malicious_count=malicious,
            suspicious_count=suspicious,
            harmless_count=harmless,
            vt_engine_counts=vt_engines_map,
            tags=tags,
            threat_actors=vt_threat_actors,
            malware_families=vt_malware_families,
            infrastructure=infra,
            discovered_iocs=discovered,
            evidences=evidences,
            raw_data=data,
        )


    async def _execute_mock(self, ctx: ProviderRequestContext) -> ProviderResult:
        """Returns realistic mock data according to IOC type"""
        if ctx.ioc_type == IOCType.IPV4:
            mock_data = {
                "data": {
                    "id": ctx.ioc_value,
                    "type": "ip_address",
                    "attributes": {
                        "asn": 15169,
                        "as_owner": "Google LLC",
                        "country": "US",
                        "network": "8.8.8.0/24",
                        "last_analysis_stats": {"malicious": 0, "suspicious": 0, "harmless": 85, "undetected": 5},
                        "reputation": 45,
                        "tags": ["dns-server", "anycast"],
                        "last_dns_records": [
                            {"type": "PTR", "value": "dns.google"},
                        ],
                    },
                    "relationships": {
                        "communicating_files": {
                            "data": [
                                {
                                    "type": "file",
                                    "id": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                                    "attributes": {
                                        "meaningful_name": "dns_query_tool.exe",
                                        "last_analysis_stats": {"malicious": 12, "harmless": 55},
                                    },
                                }
                            ]
                        }
                    },
                }
            }
        elif ctx.ioc_type == IOCType.DOMAIN:
            mock_data = {
                "data": {
                    "id": ctx.ioc_value,
                    "type": "domain",
                    "attributes": {
                        "registrar": "MarkMonitor, Inc.",
                        "creation_date": 874306800,
                        "last_analysis_stats": {"malicious": 2, "suspicious": 1, "harmless": 70, "undetected": 10},
                        "reputation": -5,
                        "tags": ["suspicious", "c2-domain"],
                        "last_dns_records": [
                            {"type": "A", "value": "198.51.100.24"},
                            {"type": "NS", "value": "ns1.cloudflare.com"},
                        ],
                    },
                    "relationships": {
                        "communicating_files": {
                            "data": [
                                {
                                    "type": "file",
                                    "id": "018ad8d9a1b58cebebeb3edaebf8bd331a07245bb65f339b6543728cc4260290",
                                    "attributes": {
                                        "meaningful_name": "c2_beacon.exe",
                                        "last_analysis_stats": {"malicious": 45, "harmless": 20},
                                    },
                                }
                            ]
                        }
                    },
                }
            }
        elif ctx.ioc_type in (IOCType.MD5, IOCType.SHA1, IOCType.SHA256):
            mock_data = {
                "data": {
                    "id": ctx.ioc_value,
                    "type": "file",
                    "attributes": {
                        "meaningful_name": "malicious_payload.exe",
                        "size": 154824,
                        "last_analysis_stats": {"malicious": 58, "suspicious": 2, "harmless": 0, "undetected": 10},
                        "reputation": -75,
                        "tags": ["trojan", "stealer", "redline"],
                        "last_dns_records": [],
                    },
                    "relationships": {
                        "bundled_files": {
                            "data": [
                                {
                                    "type": "file",
                                    "id": "44d88612fea8a8f36de82e1278abb02f" * 2,
                                    "attributes": {
                                        "meaningful_name": "bundled_payload.dll",
                                        "last_analysis_stats": {"malicious": 35, "harmless": 30},
                                    },
                                }
                            ]
                        },
                        "dropped_files": {
                            "data": [
                                {
                                    "type": "file",
                                    "id": "a" * 64,
                                    "attributes": {
                                        "meaningful_name": "dropped_loader.exe",
                                        "last_analysis_stats": {"malicious": 50, "harmless": 15},
                                    },
                                }
                            ]
                        },
                    },
                }
            }
        else:
            mock_data = {
                "data": {
                    "id": self._get_url_id(ctx.ioc_value),
                    "type": "url",
                    "attributes": {
                        "url": ctx.ioc_value,
                        "last_analysis_stats": {"malicious": 14, "suspicious": 3, "harmless": 30, "undetected": 20},
                        "reputation": -20,
                        "tags": ["phishing", "credential-harvesting"],
                        "last_dns_records": [
                            {"type": "A", "value": "203.0.113.50"}
                        ],
                    },
                }
            }

        return self._parse_response(ctx, mock_data)
