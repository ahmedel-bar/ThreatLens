import re
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
    TTPTechnique,
    FileMetadata,
    PulseMetadata,
    ThreatAttribution,
)


class AlienVaultOTXProvider(BaseProvider):
    @property
    def name(self) -> str:
        return "otx"

    @property
    def display_name(self) -> str:
        return "AlienVault OTX"

    def get_capabilities(self) -> ProviderCapability:
        return ProviderCapability(
            name=self.name,
            display_name=self.display_name,
            description="Open Threat Exchange community pulses, adversary attribution, and passive DNS history.",
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
            rate_limit_desc="10,000 requests/hour with registered free key",
            provides_reputation=True,
            provides_infrastructure=True,
            provides_relationships=True,
            doc_url="https://otx.alienvault.com/api",
        )

    def _get_section_path(self, ioc_type: IOCType) -> str:
        if ioc_type == IOCType.IPV4:
            return "IPv4"
        elif ioc_type == IOCType.IPV6:
            return "IPv6"
        elif ioc_type == IOCType.DOMAIN:
            return "domain"
        elif ioc_type == IOCType.URL:
            return "url"
        else:
            return "file"

    async def _execute_live(self, ctx: ProviderRequestContext) -> ProviderResult:
        section = self._get_section_path(ctx.ioc_type)
        base_url = f"https://otx.alienvault.com/api/v1/indicators/{section}/{ctx.ioc_value}/general"
        headers = {"X-OTX-API-KEY": ctx.api_key or ""}

        client = ctx.http_client or httpx.AsyncClient(timeout=ctx.timeout_seconds)
        should_close = ctx.http_client is None
        try:
            resp = await client.get(base_url, headers=headers)
            resp.raise_for_status()
            data = resp.json()
            return self._parse_response(ctx, data)
        finally:
            if should_close:
                await client.aclose()

    def _parse_response(self, ctx: ProviderRequestContext, data: Dict[str, Any]) -> ProviderResult:
        pulse_info = data.get("pulse_info", {})
        pulses = pulse_info.get("pulses", [])
        pulse_count = pulse_info.get("count", 0)

        threat_actors = set()
        malware_families = set()
        tags = set()
        otx_ttps: List[TTPTechnique] = []
        seen_ttp_ids = set()

        for pulse in pulses:
            adversary = pulse.get("adversary")
            if adversary and isinstance(adversary, str) and adversary.strip():
                clean_adv = adversary.strip()
                if clean_adv.lower() not in ("none", "unknown", "n/a"):
                    threat_actors.add(clean_adv)

            for raw_tag in pulse.get("tags", []):
                if isinstance(raw_tag, str):
                    for sub_tag in raw_tag.split(","):
                        clean_tag = sub_tag.strip().lower()
                        if clean_tag and len(clean_tag) > 1 and not clean_tag.startswith("cve-"):
                            tags.add(clean_tag)

            for mal in pulse.get("malware_families", []):
                name = mal.get("display_name") if isinstance(mal, dict) else (mal if isinstance(mal, str) else None)
                if name and isinstance(name, str) and name.strip():
                    malware_families.add(name.strip())

            # Extract attack_ids (MITRE ATT&CK TTPs)
            for att in pulse.get("attack_ids", []):
                t_id = None
                t_name = None
                if isinstance(att, dict):
                    t_id = att.get("id")
                    t_name = att.get("name") or att.get("display_name")
                elif isinstance(att, str):
                    t_id = att
                if t_id and t_id not in seen_ttp_ids:
                    seen_ttp_ids.add(t_id)
                    otx_ttps.append(TTPTechnique(
                        technique_id=t_id,
                        technique_name=t_name,
                        sources=["otx"],
                    ))

        # Classification
        if pulse_count >= 5:
            classification = "malicious"
        elif pulse_count > 0:
            classification = "suspicious"
        else:
            classification = "benign"

        is_hash = ctx.ioc_type in (IOCType.MD5, IOCType.SHA1, IOCType.SHA256)

        # Infrastructure
        asn = str(data.get("asn", "")) if data.get("asn") else None
        country = data.get("country_code") or data.get("country_name")
        city = data.get("city")

        file_meta = None
        if is_hash:
            file_meta = FileMetadata(
                ttps=otx_ttps,
                sources=["otx"],
            )

        # Extract structured pulse metadata for Layer 2 presentation
        otx_pulses_list: List[PulseMetadata] = []
        for pulse in pulses[:20]:
            p_id = str(pulse.get("id") or "")
            p_name = pulse.get("name") or "Threat Pulse"
            author = (
                pulse.get("author_name")
                or (pulse.get("author", {}).get("username") if isinstance(pulse.get("author"), dict) else str(pulse.get("author") or ""))
            )
            tags_p: List[str] = []
            for raw_t in pulse.get("tags", []):
                if isinstance(raw_t, str):
                    for sub_t in raw_t.split(","):
                        ct = sub_t.strip()
                        if ct and ct not in tags_p:
                            tags_p.append(ct)

            mal_p: List[str] = []
            for m in pulse.get("malware_families", []):
                m_name = m.get("display_name") if isinstance(m, dict) else (str(m) if m else None)
                if m_name and m_name.strip() and m_name.strip() not in mal_p:
                    mal_p.append(m_name.strip())

            pulse_attack_ids = []
            for att in pulse.get("attack_ids", []):
                t_id = att.get("id") if isinstance(att, dict) else (str(att) if att else None)
                if t_id and t_id not in pulse_attack_ids:
                    pulse_attack_ids.append(t_id)

            adv_raw = pulse.get("adversary")
            clean_pulse_adv = adv_raw.strip() if isinstance(adv_raw, str) and adv_raw.strip() and adv_raw.strip().lower() not in ("none", "unknown", "n/a") else None

            refs = [str(r) for r in pulse.get("references", []) if r]
            t_countries = [str(c) for c in pulse.get("targeted_countries", []) if c]
            inds = pulse.get("indicators", [])

            otx_pulses_list.append(
                PulseMetadata(
                    pulse_id=p_id,
                    pulse_name=p_name,
                    description=pulse.get("description"),
                    author=author if author else None,
                    created=pulse.get("created"),
                    modified=pulse.get("modified"),
                    tags=tags_p[:15],
                    malware_families=mal_p,
                    malware_names=mal_p,
                    adversary=clean_pulse_adv,
                    targeted_countries=t_countries,
                    references=refs[:10],
                    attack_ids=pulse_attack_ids,
                    indicator_count=len(inds),
                    sources=["otx"],
                )
            )

        # Build structured Threat Attributions from Pulses
        otx_threat_attributions: List[ThreatAttribution] = []
        for pulse in otx_pulses_list:
            pulse_cves = [t for t in pulse.tags if re.match(r'^CVE-\d{4}-\d+$', t, re.IGNORECASE)]
            pulse_ttps = [TTPTechnique(technique_id=tid, sources=["otx"]) for tid in pulse.attack_ids]
            # NEVER classify an OTX pulse name, title, or description as a Campaign.
            # Only set campaign if explicitly identified as such by the provider.
            explicit_campaign = None
            if pulse.adversary:
                otx_threat_attributions.append(
                    ThreatAttribution(
                        canonical_name=pulse.adversary,
                        entity_type="threat_actor",
                        threat_actor=pulse.adversary,
                        campaign=explicit_campaign,
                        threat_tags=pulse.tags[:5],
                        ttps=pulse_ttps,
                        cves=pulse_cves,
                        sources=["otx"],
                        confidence=80.0,
                        evidence_summary=f"OTX Pulse '{pulse.pulse_name}' adversary",
                    )
                )
            for mf in pulse.malware_families:
                otx_threat_attributions.append(
                    ThreatAttribution(
                        canonical_name=mf,
                        entity_type="malware_family",
                        malware_family=mf,
                        threat_actor=pulse.adversary,
                        campaign=explicit_campaign,
                        threat_tags=pulse.tags[:5],
                        ttps=pulse_ttps,
                        cves=pulse_cves,
                        sources=["otx"],
                        confidence=75.0,
                        evidence_summary=f"OTX Pulse '{pulse.pulse_name}' malware family",
                    )
                )
            if not pulse.adversary and not pulse.malware_families and pulse_cves:
                for cve in pulse_cves:
                    otx_threat_attributions.append(
                        ThreatAttribution(
                            canonical_name=cve,
                            entity_type="vulnerability",
                            cves=[cve],
                            sources=["otx"],
                            confidence=75.0,
                            evidence_summary=f"OTX Pulse '{pulse.pulse_name}' vulnerability tag",
                        )
                    )

        infra = InfrastructureData(
            asn=asn if not is_hash else None,
            country=country if not is_hash else None,
            city=city if not is_hash else None,
            file_metadata=file_meta,
            ttps=otx_ttps,
            otx_pulses=otx_pulses_list,
            threat_attribution=otx_threat_attributions[0] if otx_threat_attributions else None,
            threat_attributions=otx_threat_attributions,
            extra={
                "pulse_count": pulse_count,
                "references": pulse_info.get("references", []),
            },
        )

        discovered: List[DiscoveredIOC] = []

        # Extract related indicators from pulses
        seen_indicators = set()
        for pulse in pulses[:15]:
            pulse_id = str(pulse.get("id") or "")
            pulse_name = pulse.get("name") or "Threat Pulse"
            indicators = pulse.get("indicators", [])

            for ind in indicators:
                ind_val = ind.get("indicator")
                ind_type_raw = (ind.get("type") or "").lower()
                if not ind_val or ind_val == ctx.ioc_value:
                    continue

                mapped_type = None
                if "ipv4" in ind_type_raw:
                    mapped_type = IOCType.IPV4
                elif "ipv6" in ind_type_raw:
                    mapped_type = IOCType.IPV6
                elif "domain" in ind_type_raw or "hostname" in ind_type_raw:
                    mapped_type = IOCType.DOMAIN
                elif "url" in ind_type_raw or "uri" in ind_type_raw:
                    mapped_type = IOCType.URL
                elif "sha256" in ind_type_raw:
                    mapped_type = IOCType.SHA256
                elif "sha1" in ind_type_raw:
                    mapped_type = IOCType.SHA1
                elif "md5" in ind_type_raw:
                    mapped_type = IOCType.MD5
                else:
                    continue

                canon_val = ind_val.lower() if mapped_type != IOCType.URL else ind_val
                ind_key = (canon_val, mapped_type.value)
                if ind_key in seen_indicators:
                    continue
                seen_indicators.add(ind_key)

                discovered.append(
                    DiscoveredIOC(
                        raw_value=ind_val,
                        canonical_value=canon_val,
                        ioc_type=mapped_type,
                        relationship_type="pulse_indicator",
                        confidence=75.0,
                        evidence_desc=f"OTX Pulse '{pulse_name}' (ID: {pulse_id}) indicator",
                        metadata={
                            "pulse_id": pulse_id,
                            "pulse_name": pulse_name,
                            "adversary": pulse.get("adversary"),
                        },
                    )
                )

        evidences = [
            ProviderEvidence(
                provider_name=self.name,
                evidence_type="threat_pulses",
                description=f"Identified in {pulse_count} AlienVault OTX threat intelligence pulses.",
                confidence=min(100.0, float(pulse_count * 15 + 20)),
            )
        ]

        return ProviderResult(
            provider_name=self.name,
            ioc_value=ctx.ioc_value,
            ioc_type=ctx.ioc_type,
            status=ProviderStatus.SUCCESS,
            reputation_score=float(min(100, pulse_count * 20)),
            classification=classification,
            malicious_count=pulse_count,
            suspicious_count=0,
            harmless_count=0 if pulse_count > 0 else 1,
            tags=sorted(list(tags)),
            threat_actors=sorted(list(threat_actors)),
            malware_families=sorted(list(malware_families)),
            infrastructure=infra,
            discovered_iocs=discovered,
            evidences=evidences,
            raw_data=data,
        )

    async def _execute_mock(self, ctx: ProviderRequestContext) -> ProviderResult:
        mock_data = {
            "indicator": ctx.ioc_value,
            "asn": "AS13335 Cloudflare, Inc.",
            "country_code": "US",
            "city": "San Francisco",
            "pulse_info": {
                "count": 3,
                "pulses": [
                    {
                        "id": "pulse_001",
                        "name": "Cobalt Strike C2 Infrastructure Campaign",
                        "adversary": "APT29",
                        "tags": ["c2", "cobalt-strike", "apt29"],
                        "malware_families": [{"display_name": "Cobalt Strike"}],
                        "indicators": [
                            {"indicator": "198.51.100.77", "type": "IPv4"},
                            {"indicator": "c2.maliciousthreat.net", "type": "domain"},
                            {"indicator": "44d88612fea8a8f36de82e1278abb02f", "type": "FileHash-MD5"},
                        ],
                    }
                ],
            },
        }
        return self._parse_response(ctx, mock_data)
