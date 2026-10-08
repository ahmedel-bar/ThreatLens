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
    FileMetadata,
    TTPTechnique,
    ThreatAttribution,
)


class HybridAnalysisProvider(BaseProvider):
    @property
    def name(self) -> str:
        return "hybrid_analysis"

    @property
    def display_name(self) -> str:
        return "Hybrid Analysis"

    def get_capabilities(self) -> ProviderCapability:
        return ProviderCapability(
            name=self.name,
            display_name=self.display_name,
            description="CrowdStrike Falcon Sandbox automated malware analysis and behavioral IOC extraction.",
            supported_iocs=[
                IOCType.SHA256,
                IOCType.DOMAIN,
                IOCType.IPV4,
            ],
            requires_auth=True,
            free_tier=True,
            rate_limit_desc="Free key allows ~200 requests/hour",
            provides_reputation=True,
            provides_infrastructure=False,
            provides_relationships=True,
            doc_url="https://www.hybrid-analysis.com/docs/api/v2",
        )

    async def _execute_live(self, ctx: ProviderRequestContext) -> ProviderResult:
        base_url = "https://hybrid-analysis.com/api/v2"
        api_key = (ctx.api_key or "").strip()
        headers = {
            "api-key": api_key,
            "User-Agent": "Falcon Sandbox",
            "accept": "application/json",
            "Content-Type": "application/x-www-form-urlencoded",
        }

        client = ctx.http_client or httpx.AsyncClient(timeout=ctx.timeout_seconds)
        should_close = ctx.http_client is None
        try:
            if ctx.ioc_type == IOCType.SHA256:
                endpoint = f"{base_url}/overview/{ctx.ioc_value}"
                resp = await client.get(endpoint, headers=headers, follow_redirects=True)
            elif ctx.ioc_type in (IOCType.DOMAIN, IOCType.IPV4):
                endpoint = f"{base_url}/search/terms"
                key = "host" if ctx.ioc_type == IOCType.IPV4 else "domain"
                resp = await client.post(endpoint, data={key: ctx.ioc_value}, headers=headers, follow_redirects=True)
            else:
                return ProviderResult(
                    provider_name=self.name,
                    ioc_value=ctx.ioc_value,
                    ioc_type=ctx.ioc_type,
                    status=ProviderStatus.UNSUPPORTED,
                    error_details=f"Hybrid Analysis does not support IOC type '{ctx.ioc_type.value}'.",
                )

            # Specific HTTP status error handling according to specification
            if resp.status_code == 403:
                body_text = resp.text
                if "Invalid API key" in body_text or "API key is missing" in body_text:
                    return ProviderResult(
                        provider_name=self.name,
                        ioc_value=ctx.ioc_value,
                        ioc_type=ctx.ioc_type,
                        status=ProviderStatus.UNAUTHORIZED,
                        error_details="Authentication failed: Invalid API key. Please verify your credentials.",
                    )
                return ProviderResult(
                    provider_name=self.name,
                    ioc_value=ctx.ioc_value,
                    ioc_type=ctx.ioc_type,
                    status=ProviderStatus.FORBIDDEN,
                    error_details="Access denied by Hybrid Analysis API (account permissions or endpoint restriction).",
                )
            elif resp.status_code == 404:
                return ProviderResult(
                    provider_name=self.name,
                    ioc_value=ctx.ioc_value,
                    ioc_type=ctx.ioc_type,
                    status=ProviderStatus.NOT_FOUND,
                    reputation_score=0.0,
                    classification="unknown",
                )
            elif resp.status_code == 429:
                return ProviderResult(
                    provider_name=self.name,
                    ioc_value=ctx.ioc_value,
                    ioc_type=ctx.ioc_type,
                    status=ProviderStatus.RATE_LIMITED,
                    error_details="Hybrid Analysis API rate limit exceeded.",
                )

            resp.raise_for_status()
            data = resp.json()
            return self._parse_response(ctx, data)
        finally:
            if should_close:
                await client.aclose()

    def _parse_response(self, ctx: ProviderRequestContext, data: Any) -> ProviderResult:
        if isinstance(data, dict) and "sha256" in data:
            report = data
        else:
            reports = data if isinstance(data, list) else data.get("result", [])
            if not reports:
                return ProviderResult(
                    provider_name=self.name,
                    ioc_value=ctx.ioc_value,
                    ioc_type=ctx.ioc_type,
                    status=ProviderStatus.NOT_FOUND,
                    classification="unknown",
                    reputation_score=0.0,
                    raw_data={"result": data},
                )
            report = reports[0] if isinstance(reports, list) else reports

        threat_score = report.get("threat_score", 0) or 0
        verdict = (report.get("verdict") or "unknown").lower()
        vx_family = report.get("vx_family")
        av_detect = report.get("av_detect")

        if threat_score >= 70 or verdict == "malicious":
            classification = "malicious"
        elif threat_score >= 30 or verdict == "suspicious":
            classification = "suspicious"
        elif verdict == "whitelisted" or verdict == "no specific threat":
            classification = "benign"
        else:
            classification = "unknown"

        tags = report.get("tags") or []
        from app.services.enrichment import is_generic_malware_classification, is_cve_identifier
        is_cve_family = is_cve_identifier(vx_family) if vx_family else False
        is_generic_family = is_generic_malware_classification(vx_family) if vx_family else False
        malware_families = [vx_family] if (vx_family and not is_generic_family and not is_cve_family) else []

        discovered: List[DiscoveredIOC] = []

        # Extract network IOCs contacted during sandbox execution
        hosts = report.get("hosts", [])
        for h in hosts[:5]:
            if h and h != ctx.ioc_value:
                discovered.append(
                    DiscoveredIOC(
                        raw_value=h,
                        canonical_value=h,
                        ioc_type=IOCType.IPV4,
                        relationship_type="communicates_with",
                        confidence=85.0,
                        evidence_desc="Dynamic sandbox contacted network host",
                    )
                )

        domains = report.get("domains", [])
        for d in domains[:5]:
            if d and d != ctx.ioc_value:
                discovered.append(
                    DiscoveredIOC(
                        raw_value=d,
                        canonical_value=d.lower().rstrip("."),
                        ioc_type=IOCType.DOMAIN,
                        relationship_type="communicates_with",
                        confidence=85.0,
                        evidence_desc="Dynamic sandbox queried DNS domain",
                    )
                )

        # Cross-hash extraction
        sha256 = report.get("sha256")
        if sha256 and ctx.ioc_type != IOCType.SHA256:
            discovered.append(
                DiscoveredIOC(
                    raw_value=sha256,
                    canonical_value=sha256.lower(),
                    ioc_type=IOCType.SHA256,
                    relationship_type="associated_hash",
                    confidence=100.0,
                    evidence_desc="Falcon Sandbox sample sha256",
                )
            )

        evidences = [
            ProviderEvidence(
                provider_name=self.name,
                evidence_type="sandbox_verdict",
                description=f"Falcon Sandbox threat score {threat_score}/100 with verdict '{verdict}' (AV detection: {av_detect or 'N/A'}).",
                confidence=float(threat_score),
            )
        ]

        # Extract observed filenames
        observed_fnames: List[str] = []
        if report.get("last_file_name"):
            observed_fnames.append(report["last_file_name"])
        for fn in (report.get("other_file_name") or report.get("other_file_names") or []):
            if fn and fn not in observed_fnames:
                observed_fnames.append(fn)

        # Extract TTPs
        ha_ttps: List[TTPTechnique] = []
        mitre_raw = report.get("mitre_attcks") or report.get("mitre_attack_techniques") or []
        for m in mitre_raw:
            if isinstance(m, dict) and (m.get("technique_id") or m.get("id")):
                ha_ttps.append(TTPTechnique(
                    technique_id=m.get("technique_id") or m.get("id"),
                    technique_name=m.get("technique_name") or m.get("name"),
                    tactic=m.get("tactic"),
                    description=m.get("description") or m.get("signature_description"),
                    severity=m.get("severity"),
                    sources=[self.name],
                ))

        file_meta = None
        if ctx.ioc_type in (IOCType.MD5, IOCType.SHA1, IOCType.SHA256) or report.get("sha256"):
            file_meta = FileMetadata(
                file_type=report.get("type") or report.get("type_short"),
                file_size=report.get("size"),
                sha256=report.get("sha256"),
                file_names=observed_fnames,
                ttps=ha_ttps,
                sources=[self.name],
            )

        ha_attributions: List[ThreatAttribution] = []
        if vx_family:
            if is_cve_family:
                ha_attributions.append(
                    ThreatAttribution(
                        cves=[vx_family.strip().upper()],
                        verdict=verdict,
                        threat_tags=tags,
                        ttps=ha_ttps,
                        sources=["hybrid_analysis"],
                        confidence=float(threat_score) if threat_score else 85.0,
                        evidence_summary=f'Falcon Sandbox VX family: "{vx_family.strip().upper()}" (verdict: {verdict})',
                    )
                )
            elif is_generic_family:
                ha_attributions.append(
                    ThreatAttribution(
                        detection_classification=vx_family,
                        verdict=verdict,
                        threat_tags=tags,
                        ttps=ha_ttps,
                        sources=["hybrid_analysis"],
                        confidence=float(threat_score) if threat_score else 85.0,
                        evidence_summary=f"Falcon Sandbox classification '{vx_family}' with verdict '{verdict}'",
                    )
                )
            else:
                ha_attributions.append(
                    ThreatAttribution(
                        malware_family=vx_family,
                        malware_names=malware_families,
                        threat_tags=tags,
                        ttps=ha_ttps,
                        sources=["hybrid_analysis"],
                        confidence=float(threat_score) if threat_score else 85.0,
                        evidence_summary=f"Falcon Sandbox VX family '{vx_family}' with verdict '{verdict}'",
                    )
                )

        infra = InfrastructureData(
            file_type=report.get("type"),
            file_size=report.get("size"),
            file_metadata=file_meta,
            ttps=ha_ttps,
            threat_attribution=ha_attributions[0] if ha_attributions else None,
            threat_attributions=ha_attributions,
            extra={
                "environment": report.get("environment_description"),
                "av_detect": av_detect,
                "threat_level": report.get("threat_level_human"),
            },
        )

        return ProviderResult(
            provider_name=self.name,
            ioc_value=ctx.ioc_value,
            ioc_type=ctx.ioc_type,
            status=ProviderStatus.SUCCESS,
            reputation_score=float(threat_score),
            classification=classification,
            malicious_count=1 if classification == "malicious" else 0,
            suspicious_count=1 if classification == "suspicious" else 0,
            harmless_count=1 if classification == "benign" else 0,
            tags=tags,
            malware_families=malware_families,
            infrastructure=infra,
            discovered_iocs=discovered,
            evidences=evidences,
            raw_data={"report": report},
        )

    async def _execute_mock(self, ctx: ProviderRequestContext) -> ProviderResult:
        mock_data = [
            {
                "sha256": "8c6976e5b5410415bde908bd4dee15dfb167a9c873fc745a116f5597320f4510",
                "vx_family": "FormBook",
                "threat_score": 88,
                "verdict": "malicious",
                "av_detect": "42/70",
                "type": "PE32 executable (GUI) Intel 80386, for MS Windows",
                "size": 182272,
                "environment_description": "Windows 10 64 bit",
                "tags": ["stealer", "formbook", "keylogger"],
                "hosts": ["185.220.101.5", "194.26.29.112"],
                "domains": ["api.dropphone.top", "gate.formbookc2.com"],
            }
        ]
        return self._parse_response(ctx, mock_data)
