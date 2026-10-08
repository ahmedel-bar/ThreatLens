from enum import Enum
from pydantic import BaseModel, Field, field_validator
from typing import Optional, List, Dict, Any
from app.schemas.ioc import IOCType, ProviderStatus


class ProviderCapability(BaseModel):
    name: str
    display_name: str
    description: str
    supported_iocs: List[IOCType]
    requires_auth: bool
    free_tier: bool
    rate_limit_desc: str
    provides_reputation: bool = True
    provides_infrastructure: bool = False
    provides_relationships: bool = False
    doc_url: str


class DiscoveredIOC(BaseModel):
    raw_value: str
    canonical_value: str
    ioc_type: IOCType
    relationship_type: str
    confidence: float = 50.0
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    evidence_desc: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)


class NetworkInfo(BaseModel):
    ip: Optional[str] = None
    ip_version: Optional[str] = None  # IPv4, IPv6
    asn: Optional[str] = None
    asn_name: Optional[str] = None
    cidr: Optional[str] = None
    org: Optional[str] = None
    isp: Optional[str] = None
    bgp_prefix: Optional[str] = None
    ptr: Optional[str] = None
    sources: List[str] = Field(default_factory=list)


class GeoInfo(BaseModel):
    country: Optional[str] = None
    country_code: Optional[str] = None
    region: Optional[str] = None
    city: Optional[str] = None
    postal_code: Optional[str] = None
    continent: Optional[str] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    timezone: Optional[str] = None
    sources: List[str] = Field(default_factory=list)

    @field_validator(
        "country",
        "country_code",
        "region",
        "city",
        "postal_code",
        "continent",
        "timezone",
        mode="before",
    )
    @classmethod
    def _normalize_geo_field(cls, v: Any) -> Optional[str]:
        if v is None:
            return None
        if isinstance(v, list):
            items = [str(x).strip() for x in v if x is not None and str(x).strip()]
            return ", ".join(items) if items else None
        if isinstance(v, dict):
            val = v.get("name") or v.get("value") or v.get("label") or str(v)
            s = str(val).strip()
            return s if s else None
        s = str(v).strip()
        return s if s else None


class DnsRecordItem(BaseModel):
    record_type: str  # A, AAAA, CNAME, MX, NS, PTR, TXT, SOA
    value: str
    ttl: Optional[int] = None
    sources: List[str] = Field(default_factory=list)


class DnsInfo(BaseModel):
    hostnames: List[str] = Field(default_factory=list)
    domains: List[str] = Field(default_factory=list)
    records: List[DnsRecordItem] = Field(default_factory=list)
    sources: List[str] = Field(default_factory=list)


class WhoisInfo(BaseModel):
    registrar: Optional[str] = None
    registrar_url: Optional[str] = None
    registrar_whois_server: Optional[str] = None
    registry_domain_id: Optional[str] = None
    registrant_org: Optional[str] = None
    registrant_country: Optional[str] = None
    creation_date: Optional[str] = None
    updated_date: Optional[str] = None
    expiration_date: Optional[str] = None
    nameservers: List[str] = Field(default_factory=list)
    status: List[str] = Field(default_factory=list)
    dnssec: Optional[str] = None
    sources: List[str] = Field(default_factory=list)


def _coerce_to_str(v: Any) -> Optional[str]:
    if v is None:
        return None
    if isinstance(v, str):
        s = v.strip()
        return s if s else None
    if isinstance(v, (int, float, bool)):
        return str(v)
    if isinstance(v, dict):
        for k in ("headers", "value", "name", "server", "title", "product", "version", "raw", "description", "text", "html_title"):
            if k in v and v[k]:
                res = _coerce_to_str(v[k])
                if res:
                    return res
        for val in v.values():
            res = _coerce_to_str(val)
            if res:
                return res
        return None
    if isinstance(v, (list, tuple, set)):
        items = [_coerce_to_str(x) for x in v if x is not None]
        items = [x for x in items if x]
        if items:
            return ", ".join(items)
        return None
    s = str(v).strip()
    return s if s else None


class CertInfo(BaseModel):
    fingerprint_sha256: Optional[str] = None
    subject_cn: Optional[str] = None
    subject_org: Optional[str] = None
    issuer_cn: Optional[str] = None
    issuer_org: Optional[str] = None
    sans: List[str] = Field(default_factory=list)
    valid_from: Optional[str] = None
    valid_to: Optional[str] = None
    serial_number: Optional[str] = None
    tls_versions: List[str] = Field(default_factory=list)
    ciphers: List[str] = Field(default_factory=list)
    ja3s: Optional[str] = None
    jarm: Optional[str] = None
    sig_alg: Optional[str] = None
    port: Optional[int] = None
    protocol: Optional[str] = None
    service_name: Optional[str] = None
    observation_time: Optional[str] = None
    sources: List[str] = Field(default_factory=list)

    @field_validator(
        "fingerprint_sha256",
        "subject_cn",
        "subject_org",
        "issuer_cn",
        "issuer_org",
        "valid_from",
        "valid_to",
        "serial_number",
        "ja3s",
        "jarm",
        "sig_alg",
        "protocol",
        "service_name",
        "observation_time",
        mode="before",
    )
    @classmethod
    def _coerce_cert_str_field(cls, v: Any) -> Optional[str]:
        return _coerce_to_str(v)


class ServiceInfo(BaseModel):
    port: int
    transport: str = "tcp"  # tcp, udp
    protocol: Optional[str] = None  # http, https, ssh, dns, etc.
    service_name: Optional[str] = None
    product: Optional[str] = None
    version: Optional[str] = None
    vendor: Optional[str] = None
    devicetype: Optional[str] = None
    cpe: List[str] = Field(default_factory=list)
    banner: Optional[str] = None
    http_title: Optional[str] = None
    http_server: Optional[str] = None
    http_status: Optional[int] = None
    tls_version: Optional[str] = None
    cipher: Optional[str] = None
    ja3s: Optional[str] = None
    jarm: Optional[str] = None
    alpn: List[str] = Field(default_factory=list)
    vulnerabilities: List[str] = Field(default_factory=list)
    scan_time: Optional[str] = None
    sources: List[str] = Field(default_factory=list)

    @field_validator(
        "protocol",
        "service_name",
        "product",
        "version",
        "vendor",
        "devicetype",
        "banner",
        "http_title",
        "http_server",
        "tls_version",
        "cipher",
        "ja3s",
        "jarm",
        "scan_time",
        mode="before",
    )
    @classmethod
    def _coerce_service_str_field(cls, v: Any) -> Optional[str]:
        return _coerce_to_str(v)

    @field_validator("vulnerabilities", mode="before")
    @classmethod
    def _coerce_service_vulns(cls, v: Any) -> List[str]:
        if not v:
            return []
        items = v if isinstance(v, (list, tuple, set)) else [v]
        res: List[str] = []
        for item in items:
            if not item:
                continue
            if isinstance(item, str):
                res.append(item.strip())
            elif hasattr(item, "cve_id"):
                res.append(str(item.cve_id).strip())
            elif isinstance(item, dict):
                cve = item.get("cve_id") or item.get("cve") or item.get("id") or str(item)
                if cve:
                    res.append(str(cve).strip())
            else:
                res.append(str(item).strip())
        return res



class HttpInfo(BaseModel):
    server: Optional[str] = None
    title: Optional[str] = None
    status_code: Optional[int] = None
    headers: Optional[Dict[str, str]] = Field(default_factory=dict)
    technologies: List[str] = Field(default_factory=list)
    screenshot_url: Optional[str] = None
    sources: List[str] = Field(default_factory=list)

    @field_validator("server", "title", "screenshot_url", mode="before")
    @classmethod
    def _coerce_http_str_field(cls, v: Any) -> Optional[str]:
        return _coerce_to_str(v)

    @field_validator("headers", mode="before")
    @classmethod
    def _coerce_headers_dict(cls, v: Any) -> Dict[str, str]:
        if not isinstance(v, dict):
            return {}
        cleaned = {}
        for k, val in v.items():
            if k is not None:
                str_val = _coerce_to_str(val)
                if str_val is not None:
                    cleaned[str(k)] = str_val
        return cleaned


class TlsInfo(BaseModel):
    supported_versions: List[str] = Field(default_factory=list)
    ciphers: List[str] = Field(default_factory=list)
    ja3: Optional[str] = None
    ja3s: Optional[str] = None
    jarm: Optional[str] = None
    sources: List[str] = Field(default_factory=list)


class HostingInfo(BaseModel):
    hosting_provider: Optional[str] = None
    datacenter: Optional[str] = None
    is_cloud: Optional[bool] = None
    cloud_provider: Optional[str] = None
    sources: List[str] = Field(default_factory=list)


class VulnInfo(BaseModel):
    cve_id: str
    cwe_id: Optional[str] = None
    cpe: List[str] = Field(default_factory=list)
    cvss: Optional[float] = None
    cvss_v2: Optional[float] = None
    cvss_v3: Optional[float] = None
    severity: Optional[str] = None
    attack_vector: Optional[str] = None
    affected_product: Optional[str] = None
    affected_vendor: Optional[str] = None
    summary: Optional[str] = None
    related_products: List[str] = Field(default_factory=list)
    references: List[str] = Field(default_factory=list)
    port: Optional[int] = None
    exploit: Optional[bool] = None
    exploit_details: Optional[str] = None
    sources: List[str] = Field(default_factory=list)

    @field_validator(
        "cwe_id",
        "severity",
        "attack_vector",
        "affected_product",
        "affected_vendor",
        "summary",
        "exploit_details",
        mode="before",
    )
    @classmethod
    def _coerce_vuln_str_field(cls, v: Any) -> Optional[str]:
        return _coerce_to_str(v)


class IpScoringInfo(BaseModel):
    inbound_score: Optional[str] = None
    outbound_score: Optional[str] = None
    reputation_score: Optional[float] = None
    classification: Optional[str] = None
    critical_risk: bool = False
    abuse_indicators: List[str] = Field(default_factory=list)
    sources: List[str] = Field(default_factory=list)


class DetectionInfo(BaseModel):
    is_vpn: bool = False
    is_tor: bool = False
    is_proxy: bool = False
    is_hosting: bool = False
    is_cloud: bool = False
    is_mobile: bool = False
    is_cdn: bool = False
    is_scanner: bool = False
    is_darkweb: bool = False
    is_snort: bool = False
    is_anonymous_vpn: bool = False
    vpn_providers: List[str] = Field(default_factory=list)
    ip_categories: List[str] = Field(default_factory=list)
    special_issues: List[str] = Field(default_factory=list)
    sources: List[str] = Field(default_factory=list)


class SecurityIndicators(BaseModel):
    abuse_record_count: int = 0
    user_search_count: int = 0
    honeypot_detected: bool = False
    webcam_detected: bool = False
    ids_alerts_count: int = 0
    ids_alert_signatures: List[str] = Field(default_factory=list)
    vulnerabilities_count: int = 0
    open_ports_count: int = 0
    invalid_ssl: bool = False
    admin_page_detected: bool = False
    policy_violations: List[str] = Field(default_factory=list)
    sources: List[str] = Field(default_factory=list)



class TemporalInfo(BaseModel):
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    last_scan: Optional[str] = None
    sources: List[str] = Field(default_factory=list)


class ShodanHostDetails(BaseModel):
    os: Optional[str] = None
    device_type: Optional[str] = None
    tags: List[str] = Field(default_factory=list)
    total_ports: int = 0
    total_vulns: int = 0
    services_count: int = 0
    domains: List[str] = Field(default_factory=list)
    hostnames: List[str] = Field(default_factory=list)
    asn: Optional[str] = None
    isp: Optional[str] = None
    org: Optional[str] = None
    city: Optional[str] = None
    country: Optional[str] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    last_update: Optional[str] = None
    sources: List[str] = Field(default_factory=lambda: ["shodan"])


class CensysHostDetails(BaseModel):
    ip: Optional[str] = None
    hostname: Optional[str] = None
    autonomous_system: Optional[Dict[str, Any]] = None
    asn: Optional[str] = None
    asn_name: Optional[str] = None
    bgp_prefix: Optional[str] = None
    location: Optional[Dict[str, Any]] = None
    continent: Optional[str] = None
    country: Optional[str] = None
    country_code: Optional[str] = None
    city: Optional[str] = None
    region: Optional[str] = None
    postal_code: Optional[str] = None
    timezone: Optional[str] = None
    coordinates: Optional[Dict[str, Any]] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    os: Optional[str] = None
    host_labels: List[str] = Field(default_factory=list)
    service_count: int = 0
    total_vulns: int = 0
    services: List[Dict[str, Any]] = Field(default_factory=list)
    dns_names: List[str] = Field(default_factory=list)
    web_properties: List[Dict[str, Any]] = Field(default_factory=list)
    last_observed_at: Optional[str] = None
    sources: List[str] = Field(default_factory=lambda: ["censys"])


class PassiveDnsRecord(BaseModel):
    query: str
    answer: str
    rrtype: str
    rrclass: Optional[str] = "IN"
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    first_seen_timestamp: Optional[int] = None
    last_seen_timestamp: Optional[int] = None
    observation_count: Optional[int] = None
    min_ttl: Optional[int] = None
    max_ttl: Optional[int] = None
    tlp: Optional[str] = "white"
    sources: List[str] = Field(default_factory=lambda: ["mnemonic Passive DNS"])


class TTPSubTechnique(BaseModel):
    id: str
    name: str
    description: Optional[str] = None
    severity: Optional[str] = None
    sources: List[str] = Field(default_factory=list)
    evidence: List[str] = Field(default_factory=list)
    associated_malware: List[str] = Field(default_factory=list)
    associated_actors: List[str] = Field(default_factory=list)


class TTPTechniqueNode(BaseModel):
    id: str
    name: str
    description: Optional[str] = None
    severity: Optional[str] = None
    sources: List[str] = Field(default_factory=list)
    evidence: List[str] = Field(default_factory=list)
    associated_malware: List[str] = Field(default_factory=list)
    associated_actors: List[str] = Field(default_factory=list)
    sub_techniques: List[TTPSubTechnique] = Field(default_factory=list)


class TTPTacticNode(BaseModel):
    id: str
    name: str
    order: int
    techniques: List[TTPTechniqueNode] = Field(default_factory=list)


class TTPTechnique(BaseModel):
    technique_id: str
    technique_name: Optional[str] = None
    tactic: Optional[str] = None
    description: Optional[str] = None
    severity: Optional[str] = None
    sources: List[str] = Field(default_factory=list)


class PulseMetadata(BaseModel):
    pulse_id: str
    pulse_name: str
    description: Optional[str] = None
    author: Optional[str] = None
    created: Optional[str] = None
    modified: Optional[str] = None
    tags: List[str] = Field(default_factory=list)
    malware_families: List[str] = Field(default_factory=list)
    malware_names: List[str] = Field(default_factory=list)
    adversary: Optional[str] = None
    targeted_countries: List[str] = Field(default_factory=list)
    references: List[str] = Field(default_factory=list)
    attack_ids: List[str] = Field(default_factory=list)
    indicator_count: int = 0
    sources: List[str] = Field(default_factory=lambda: ["otx"])


class FileMetadata(BaseModel):
    file_type: Optional[str] = None
    magic: Optional[str] = None
    file_size: Optional[int] = None
    md5: Optional[str] = None
    sha1: Optional[str] = None
    sha256: Optional[str] = None
    vhash: Optional[str] = None
    authentihash: Optional[str] = None
    imphash: Optional[str] = None
    rich_pe_header_hash: Optional[str] = None
    ssdeep: Optional[str] = None
    tlsh: Optional[str] = None
    trid: List[Dict[str, Any]] = Field(default_factory=list)
    detectiteasy: Optional[Dict[str, Any]] = None
    magika: Optional[str] = None
    pe_info: Optional[Dict[str, Any]] = None
    compiler_info: Optional[str] = None
    timestamps: Dict[str, Any] = Field(default_factory=dict)
    file_names: List[str] = Field(default_factory=list)
    signature_info: Optional[Dict[str, Any]] = None
    ttps: List[TTPTechnique] = Field(default_factory=list)
    sources: List[str] = Field(default_factory=list)


class ThreatAttribution(BaseModel):
    canonical_name: Optional[str] = None
    entity_type: Optional[str] = None  # threat_actor, malware_family, campaign, tool, threat_association, provider_classification, vulnerability, tag
    subtype: Optional[str] = None
    relationship_type: Optional[str] = None  # associated_threat, uses_tool, attribution, indicator_of, etc.
    malware_family: Optional[str] = None
    malware_names: List[str] = Field(default_factory=list)
    malware_type: Optional[str] = None  # ransomware, trojan, botnet, stealer, rat, miner, backdoor, etc.
    threat_actor: Optional[str] = None
    threat_actor_aliases: List[str] = Field(default_factory=list)
    campaign: Optional[str] = None
    tool: Optional[str] = None
    threat_association: Optional[str] = None
    aliases: List[str] = Field(default_factory=list)
    threat_tags: List[str] = Field(default_factory=list)
    ttps: List[TTPTechnique] = Field(default_factory=list)
    cves: List[str] = Field(default_factory=list)
    sources: List[str] = Field(default_factory=list)
    providers: List[str] = Field(default_factory=list)
    source_records: List[Dict[str, Any]] = Field(default_factory=list)
    confidence: float = 50.0
    evidence_summary: Optional[str] = None
    evidence: List[str] = Field(default_factory=list)
    detection_classification: Optional[str] = None
    verdict: Optional[str] = None
    provider_detection_name: Optional[str] = None
    is_corroborated: bool = False
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None


class SecurityHeaderState(str, Enum):
    PRESENT = "PRESENT"
    MISSING = "MISSING"
    NOT_CHECKED = "NOT_CHECKED"
    UNAVAILABLE = "UNAVAILABLE"
    REQUEST_FAILED = "REQUEST_FAILED"


class SecurityHeaderInfo(BaseModel):
    name: str
    display_name: str = ""
    key: Optional[str] = None
    id: Optional[str] = None
    state: str = SecurityHeaderState.NOT_CHECKED.value
    value: Optional[str] = None
    evidence: Optional[str] = None
    sources: List[str] = Field(default_factory=list)

    def model_post_init(self, __context: Any) -> None:
        if not self.display_name:
            self.display_name = self.name


class SecurityHeadersAnalysis(BaseModel):
    headers: List[SecurityHeaderInfo] = Field(default_factory=list)
    active_count: int = 0
    evaluated_count: int = 0
    total_supported: int = 10
    missing_count: int = 0
    not_checked_count: int = 0
    unavailable_count: int = 0
    request_failed_count: int = 0
    summary: Optional[str] = None
    sources: List[str] = Field(default_factory=list)
class HistoricalWhoisRecord(BaseModel):
    id: Optional[str] = None
    first_seen: Optional[str] = None
    last_updated: Optional[str] = None
    first_seen_timestamp: Optional[int] = None
    last_updated_timestamp: Optional[int] = None
    registrar: Optional[str] = None
    registrar_url: Optional[str] = None
    registrar_whois_server: Optional[str] = None
    creation_date: Optional[str] = None
    updated_date: Optional[str] = None
    expiry_date: Optional[str] = None
    registrant_organization: Optional[str] = None
    registrant_country: Optional[str] = None
    registrant_name: Optional[str] = None
    registrant_email: Optional[str] = None
    nameservers: List[str] = Field(default_factory=list)
    domain_status: List[str] = Field(default_factory=list)
    origin_as: Optional[str] = None
    raw_map: Dict[str, Any] = Field(default_factory=dict)
    sources: List[str] = Field(default_factory=list)


class InfrastructureData(BaseModel):
    # Flat backward-compatible fields
    asn: Optional[str] = None
    asn_name: Optional[str] = None
    org: Optional[str] = None
    country: Optional[str] = None
    region: Optional[str] = None
    city: Optional[str] = None
    cidr: Optional[str] = None
    ptr: Optional[str] = None
    registrar: Optional[str] = None
    whois_creation: Optional[str] = None
    whois_expiration: Optional[str] = None

    @field_validator(
        "asn",
        "asn_name",
        "org",
        "country",
        "region",
        "city",
        "cidr",
        "ptr",
        "registrar",
        "whois_creation",
        "whois_expiration",
        mode="before",
    )
    @classmethod
    def _normalize_flat_field(cls, v: Any) -> Optional[str]:
        if v is None:
            return None
        if isinstance(v, list):
            items = [str(x).strip() for x in v if x is not None and str(x).strip()]
            return ", ".join(items) if items else None
        if isinstance(v, dict):
            val = v.get("name") or v.get("value") or v.get("label") or str(v)
            s = str(val).strip()
            return s if s else None
        s = str(v).strip()
        return s if s else None
    nameservers: List[str] = Field(default_factory=list)
    dns_records: Dict[str, List[str]] = Field(default_factory=dict)
    open_ports: List[int] = Field(default_factory=list)
    services: List[Dict[str, Any]] = Field(default_factory=list)
    certificates: List[Dict[str, Any]] = Field(default_factory=list)
    http_server: Optional[str] = None
    http_title: Optional[str] = None
    screenshot_url: Optional[str] = None
    file_type: Optional[str] = None
    file_size: Optional[int] = None
    extra: Dict[str, Any] = Field(default_factory=dict)

    # Rich structured normalized models with provenance
    network: Optional[NetworkInfo] = None
    geo: Optional[GeoInfo] = None
    dns: Optional[DnsInfo] = None
    whois: Optional[WhoisInfo] = None
    certificates_detail: List[CertInfo] = Field(default_factory=list)
    services_detail: List[ServiceInfo] = Field(default_factory=list)
    http: Optional[HttpInfo] = None
    tls: Optional[TlsInfo] = None
    hosting: Optional[HostingInfo] = None
    vulnerabilities: List[VulnInfo] = Field(default_factory=list)
    temporal: Optional[TemporalInfo] = None
    shodan_details: Optional[ShodanHostDetails] = None
    censys_details: Optional[CensysHostDetails] = None
    file_metadata: Optional[FileMetadata] = None
    ttps: List[TTPTechnique] = Field(default_factory=list)
    otx_pulses: List[PulseMetadata] = Field(default_factory=list)
    threat_attribution: Optional[ThreatAttribution] = None
    threat_attributions: List[ThreatAttribution] = Field(default_factory=list)
    ip_scoring: Optional[IpScoringInfo] = None
    detection: Optional[DetectionInfo] = None
    security: Optional[SecurityIndicators] = None
    passive_dns: List[PassiveDnsRecord] = Field(default_factory=list)
    ttp_hierarchy: List[TTPTacticNode] = Field(default_factory=list)
    historical_whois: List[HistoricalWhoisRecord] = Field(default_factory=list)
    alternative_geolocations: List[GeoInfo] = Field(default_factory=list)
    security_headers: Optional[SecurityHeadersAnalysis] = None




class ProviderEvidence(BaseModel):
    provider_name: str
    evidence_type: str
    description: str
    raw_data: Optional[Dict[str, Any]] = None
    confidence: float = 50.0


class VirusTotalDetectionStats(BaseModel):
    malicious: int = 0
    suspicious: int = 0
    undetected: int = 0
    harmless: int = 0
    timeout: int = 0
    confirmed_timeout: int = 0
    type_unsupported: int = 0
    failure: int = 0
    total: int = 0

    @classmethod
    def from_api_stats(cls, stats: Optional[Dict[str, Any]]) -> "VirusTotalDetectionStats":
        if not stats or not isinstance(stats, dict):
            return cls()

        malicious = int(stats.get("malicious", 0) or 0)
        suspicious = int(stats.get("suspicious", 0) or 0)
        undetected = int(stats.get("undetected", 0) or 0)
        harmless = int(stats.get("harmless", stats.get("clean", 0)) or 0)
        timeout = int(stats.get("timeout", 0) or 0)
        confirmed_timeout = int(stats.get("confirmed-timeout", stats.get("confirmed_timeout", 0)) or 0)
        type_unsupported = int(stats.get("type-unsupported", stats.get("type_unsupported", 0)) or 0)
        failure = int(stats.get("failure", 0) or 0)

        # Total is the sum of all actual evaluated verdict categories returned by VirusTotal
        total = sum(int(v) for v in stats.values() if isinstance(v, (int, float)))
        if total == 0:
            total = malicious + suspicious + undetected + harmless + timeout + confirmed_timeout + type_unsupported + failure

        return cls(
            malicious=malicious,
            suspicious=suspicious,
            undetected=undetected,
            harmless=harmless,
            timeout=timeout,
            confirmed_timeout=confirmed_timeout,
            type_unsupported=type_unsupported,
            failure=failure,
            total=total,
        )

    def to_dict(self) -> Dict[str, int]:
        d = {
            "malicious": self.malicious,
            "suspicious": self.suspicious,
            "undetected": self.undetected,
            "harmless": self.harmless,
            "timeout": self.timeout + self.confirmed_timeout,
            "type_unsupported": self.type_unsupported,
            "failure": self.failure,
            "total": self.total,
        }
        if self.harmless > 0:
            d["clean"] = self.harmless
        return d


class ProviderResult(BaseModel):
    provider_name: str
    ioc_value: str
    ioc_type: IOCType
    status: ProviderStatus
    execution_time_ms: int = 0
    reputation_score: Optional[float] = None
    classification: Optional[str] = None  # malicious, suspicious, benign, unknown
    malicious_count: int = 0
    suspicious_count: int = 0
    harmless_count: int = 0
    vt_engine_counts: Optional[Dict[str, int]] = None
    tags: List[str] = Field(default_factory=list)
    threat_actors: List[str] = Field(default_factory=list)
    malware_families: List[str] = Field(default_factory=list)
    infrastructure: Optional[InfrastructureData] = None
    discovered_iocs: List[DiscoveredIOC] = Field(default_factory=list)
    evidences: List[ProviderEvidence] = Field(default_factory=list)
    raw_data: Optional[Dict[str, Any]] = None
    error_details: Optional[str] = None


