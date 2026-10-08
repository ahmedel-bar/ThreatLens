export type IOCType = 'ipv4' | 'ipv6' | 'domain' | 'url' | 'md5' | 'sha1' | 'sha256';

export type ProviderStatus =
  | 'success'
  | 'not_found'
  | 'unsupported'
  | 'rate_limited'
  | 'unauthorized'
  | 'forbidden'
  | 'timeout'
  | 'server_error'
  | 'invalid_response'
  | 'disabled'
  | 'not_configured'
  | 'network_error'
  | 'parse_error'
  | 'plan_restricted';

export interface ProviderCapability {
  name: string;
  display_name: string;
  description: string;
  supported_iocs: IOCType[];
  requires_auth: boolean;
  free_tier: boolean;
  rate_limit_desc: string;
  provides_reputation: boolean;
  provides_infrastructure: boolean;
  provides_relationships: boolean;
  doc_url: string;
}

export interface NetworkInfo {
  ip?: string;
  ip_version?: string;
  asn?: string;
  asn_name?: string;
  cidr?: string;
  org?: string;
  isp?: string;
  bgp_prefix?: string;
  ptr?: string;
  sources: string[];
}

export interface GeoInfo {
  country?: string;
  country_code?: string;
  region?: string;
  city?: string;
  postal_code?: string;
  continent?: string;
  latitude?: number;
  longitude?: number;
  timezone?: string;
  sources: string[];
}

export interface DnsRecordItem {
  record_type: string;
  value: string;
  ttl?: number;
  sources: string[];
}

export interface DnsInfo {
  hostnames: string[];
  domains: string[];
  records: DnsRecordItem[];
  sources: string[];
}

export interface WhoisInfo {
  registrar?: string;
  registrar_url?: string;
  registrar_whois_server?: string;
  registry_domain_id?: string;
  registrant_org?: string;
  registrant_country?: string;
  creation_date?: string;
  updated_date?: string;
  expiration_date?: string;
  nameservers: string[];
  status: string[];
  dnssec?: string;
  sources: string[];
}

export interface CertInfo {
  fingerprint_sha256?: string;
  subject_cn?: string;
  subject_org?: string;
  issuer_cn?: string;
  issuer_org?: string;
  sans: string[];
  valid_from?: string;
  valid_to?: string;
  serial_number?: string;
  tls_versions: string[];
  ciphers: string[];
  ja3s?: string;
  jarm?: string;
  sig_alg?: string;
  port?: number;
  protocol?: string;
  service_name?: string;
  observation_time?: string;
  sources: string[];
}

export interface ServiceInfo {
  port: number;
  transport: string;
  protocol?: string;
  service_name?: string;
  product?: string;
  version?: string;
  vendor?: string;
  devicetype?: string;
  cpe: string[];
  banner?: string;
  http_title?: string;
  http_server?: string;
  http_status?: number;
  tls_version?: string;
  cipher?: string;
  ja3s?: string;
  jarm?: string;
  alpn?: string[];
  vulnerabilities?: string[];
  scan_time?: string;
  sources: string[];
}

export interface HttpInfo {
  server?: string;
  title?: string;
  status_code?: number;
  headers?: Record<string, string>;
  technologies: string[];
  screenshot_url?: string;
  sources: string[];
}

export interface TlsInfo {
  supported_versions: string[];
  ciphers: string[];
  ja3?: string;
  ja3s?: string;
  jarm?: string;
  sources: string[];
}

export interface HostingInfo {
  hosting_provider?: string;
  datacenter?: string;
  is_cloud?: boolean;
  cloud_provider?: string;
  sources: string[];
}

export interface VulnInfo {
  cve_id: string;
  cwe_id?: string;
  cpe?: string[];
  cvss?: number;
  cvss_v2?: number;
  cvss_v3?: number;
  severity?: string;
  attack_vector?: string;
  affected_product?: string;
  affected_vendor?: string;
  summary?: string;
  related_products?: string[];
  references: string[];
  port?: number;
  exploit?: boolean;
  exploit_details?: string;
  sources: string[];
}

export interface IpScoringInfo {
  inbound_score?: string;
  outbound_score?: string;
  reputation_score?: number;
  classification?: string;
  critical_risk?: boolean;
  abuse_indicators?: string[];
  sources: string[];
}

export interface DetectionInfo {
  is_vpn?: boolean;
  is_tor?: boolean;
  is_proxy?: boolean;
  is_hosting?: boolean;
  is_cloud?: boolean;
  is_mobile?: boolean;
  is_cdn?: boolean;
  is_scanner?: boolean;
  is_darkweb?: boolean;
  is_snort?: boolean;
  is_anonymous_vpn?: boolean;
  vpn_providers?: string[];
  ip_categories?: string[];
  special_issues?: string[];
  sources: string[];
}

export interface SecurityIndicators {
  abuse_record_count?: number;
  user_search_count?: number;
  honeypot_detected?: boolean;
  webcam_detected?: boolean;
  ids_alerts_count?: number;
  ids_alert_signatures?: string[];
  vulnerabilities_count?: number;
  open_ports_count?: number;
  invalid_ssl?: boolean;
  admin_page_detected?: boolean;
  policy_violations?: string[];
  sources: string[];
}

export interface TemporalInfo {
  first_seen?: string;
  last_seen?: string;
  last_scan?: string;
  sources: string[];
}

export interface ShodanHostDetails {
  os?: string;
  device_type?: string;
  tags: string[];
  total_ports: number;
  total_vulns: number;
  services_count?: number;
  domains?: string[];
  hostnames?: string[];
  asn?: string;
  isp?: string;
  org?: string;
  city?: string;
  country?: string;
  latitude?: number;
  longitude?: number;
  last_update?: string;
  sources: string[];
}

export interface CensysHostDetails {
  ip?: string;
  hostname?: string;
  autonomous_system?: Record<string, any>;
  asn?: string;
  asn_name?: string;
  bgp_prefix?: string;
  location?: Record<string, any>;
  continent?: string;
  country?: string;
  country_code?: string;
  city?: string;
  region?: string;
  postal_code?: string;
  timezone?: string;
  coordinates?: { latitude?: number; longitude?: number };
  latitude?: number;
  longitude?: number;
  os?: string;
  host_labels?: string[];
  service_count?: number;
  total_vulns?: number;
  services?: Array<Record<string, any>>;
  dns_names?: string[];
  web_properties?: Array<Record<string, any>>;
  last_observed_at?: string;
  sources: string[];
}

export interface PassiveDnsRecord {
  query: string;
  answer: string;
  rrtype: string;
  rrclass?: string;
  first_seen?: string;
  last_seen?: string;
  first_seen_timestamp?: number;
  last_seen_timestamp?: number;
  observation_count?: number;
  min_ttl?: number;
  max_ttl?: number;
  tlp?: string;
  sources: string[];
}

export interface TTPSubTechnique {
  id: string;
  name: string;
  description?: string;
  severity?: string;
  sources: string[];
  evidence?: string[];
  associated_malware?: string[];
  associated_actors?: string[];
}

export interface TTPTechniqueNode {
  id: string;
  name: string;
  description?: string;
  severity?: string;
  sources: string[];
  evidence?: string[];
  associated_malware?: string[];
  associated_actors?: string[];
  sub_techniques: TTPSubTechnique[];
}

export interface TTPTacticNode {
  id: string;
  name: string;
  order: number;
  techniques: TTPTechniqueNode[];
}

export interface TTPTechnique {
  technique_id: string;
  technique_name?: string;
  tactic?: string;
  description?: string;
  severity?: string;
  sources: string[];
}

export interface FileMetadata {
  file_type?: string;
  magic?: string;
  file_size?: number;
  md5?: string;
  sha1?: string;
  sha256?: string;
  vhash?: string;
  authentihash?: string;
  imphash?: string;
  rich_pe_header_hash?: string;
  ssdeep?: string;
  tlsh?: string;
  trid?: Array<Record<string, any>>;
  detectiteasy?: Record<string, any>;
  magika?: string;
  pe_info?: Record<string, any>;
  compiler_info?: string;
  timestamps?: Record<string, any>;
  file_names?: string[];
  signature_info?: Record<string, any>;
  ttps?: TTPTechnique[];
  sources: string[];
}

export interface PulseMetadata {
  pulse_id: string;
  pulse_name: string;
  description?: string;
  author?: string;
  created?: string;
  modified?: string;
  tags: string[];
  malware_families: string[];
  malware_names?: string[];
  adversary?: string;
  targeted_countries: string[];
  references: string[];
  attack_ids?: string[];
  indicator_count: number;
  sources: string[];
}

export type SecurityHeaderState = 'PRESENT' | 'MISSING' | 'NOT_CHECKED' | 'UNAVAILABLE' | 'REQUEST_FAILED';

export interface SecurityHeaderInfo {
  name: string;
  display_name: string;
  state: SecurityHeaderState;
  value?: string;
  evidence?: string;
  sources: string[];
}

export interface SecurityHeadersAnalysis {
  headers: SecurityHeaderInfo[];
  active_count: number;
  evaluated_count: number;
  total_supported: number;
  not_checked_count: number;
  unavailable_count: number;
  request_failed_count: number;
  sources: string[];
}

export interface ThreatAttribution {
  canonical_name?: string;
  entity_type?: string;
  subtype?: string;
  relationship_type?: string;
  malware_family?: string;
  malware_names?: string[];
  malware_type?: string;
  threat_actor?: string;
  threat_actor_aliases?: string[];
  campaign?: string;
  tool?: string;
  threat_association?: string;
  aliases: string[];
  threat_tags?: string[];
  ttps?: TTPTechnique[];
  cves?: string[];
  sources: string[];
  confidence?: string | number;
  evidence?: string[];
  evidence_summary?: string;
  detection_classification?: string;
  verdict?: string;
  provider_detection_name?: string;
  is_corroborated?: boolean;
  providers?: string[];
  source_records?: Array<Record<string, any>>;
  first_seen?: string;
  last_seen?: string;
}

export interface HistoricalWhoisRecord {
  id?: string;
  first_seen?: string;
  last_updated?: string;
  first_seen_timestamp?: number;
  last_updated_timestamp?: number;
  registrar?: string;
  registrar_url?: string;
  registrar_whois_server?: string;
  creation_date?: string;
  updated_date?: string;
  expiry_date?: string;
  registrant_organization?: string;
  registrant_country?: string;
  registrant_name?: string;
  registrant_email?: string;
  nameservers: string[];
  domain_status: string[];
  origin_as?: string;
  raw_map: Record<string, any>;
  sources: string[];
}

export interface InfrastructureData {
  asn?: string;
  asn_name?: string;
  org?: string;
  country?: string;
  region?: string;
  city?: string;
  cidr?: string;
  ptr?: string;
  registrar?: string;
  whois_creation?: string;
  whois_expiration?: string;
  nameservers: string[];
  dns_records: Record<string, string[]>;
  open_ports: number[];
  services: Array<{ port: number; service_name?: string; banner?: string }>;
  certificates: Array<{ fingerprint?: string; names?: string[] }>;
  http_server?: string;
  http_title?: string;
  screenshot_url?: string;
  file_type?: string;
  file_size?: number;
  extra: Record<string, any>;

  network?: NetworkInfo;
  geo?: GeoInfo;
  dns?: DnsInfo;
  whois?: WhoisInfo;
  certificates_detail?: CertInfo[];
  services_detail?: ServiceInfo[];
  http?: HttpInfo;
  tls?: TlsInfo;
  hosting?: HostingInfo;
  vulnerabilities?: VulnInfo[];
  temporal?: TemporalInfo;
  shodan_details?: ShodanHostDetails;
  censys_details?: CensysHostDetails;
  file_metadata?: FileMetadata;
  ttps?: TTPTechnique[];
  otx_pulses?: PulseMetadata[];
  threat_attribution?: ThreatAttribution;
  threat_attributions?: ThreatAttribution[];
  ip_scoring?: IpScoringInfo;
  detection?: DetectionInfo;
  security?: SecurityIndicators;
  passive_dns?: PassiveDnsRecord[];
  ttp_hierarchy?: TTPTacticNode[];
  historical_whois?: HistoricalWhoisRecord[];
  alternative_geolocations?: GeoInfo[];
  security_headers?: SecurityHeadersAnalysis;
}

export interface ProviderEvidence {
  provider_name: string;
  evidence_type: string;
  description: string;
  raw_data?: Record<string, any>;
  confidence: number;
}

export interface ProviderResult {
  provider_name: string;
  ioc_value: string;
  ioc_type: IOCType;
  status: ProviderStatus;
  execution_time_ms: number;
  reputation_score?: number;
  classification?: string;
  malicious_count: number;
  suspicious_count: number;
  harmless_count: number;
  vt_engine_counts?: Record<string, number>;
  tags: string[];
  threat_actors: string[];
  malware_families: string[];
  infrastructure?: InfrastructureData;
  evidences: ProviderEvidence[];
  raw_data?: Record<string, any>;
  error_details?: string;
}

export interface CanonicalIOC {
  id: string;
  canonical_value: string;
  ioc_type: IOCType;
  is_root: boolean;
  depth: number;
  confidence: number;
  first_seen?: string;
  last_seen?: string;
  metadata?: Record<string, any>;
  relationships: string[];
  providers: string[];
}

export interface Relationship {
  id: string;
  source_value: string;
  source_type: string;
  target_value: string;
  target_type: string;
  relationship_type: string;
  confidence: number;
  providers: string[];
  evidence_count: number;
  evidence_summary?: string;
  depth: number;
}

export interface Layer1Reputation {
  root_ioc: string;
  root_type: IOCType;
  overall_classification: string;
  risk_score: number;
  total_providers_queried: number;
  applicable_providers_count?: number;
  providers_success: number;
  providers_failed: number;
  providers_not_found?: number;
  verdict_counts?: Record<string, number>;
  vt_engine_counts?: Record<string, number>;
  provider_results: ProviderResult[];
  ttps?: TTPTechnique[];
}

export interface Layer2Infrastructure {
  root_ioc: string;
  root_type: IOCType;
  aggregated_infrastructure: InfrastructureData;
  provider_contributions: Record<string, InfrastructureData>;
  ttps?: TTPTechnique[];
  otx_pulses?: PulseMetadata[];
  passive_dns?: PassiveDnsRecord[];
  ttp_hierarchy?: TTPTacticNode[];
  historical_whois?: HistoricalWhoisRecord[];
}

export interface Layer3DiscoveredIOCs {
  hashes: CanonicalIOC[];
  ips: CanonicalIOC[];
  urls_and_domains: CanonicalIOC[];
  total_count: number;
}

export interface GraphNode {
  id: string;
  label: string;
  type: string;
  confidence: number;
  depth: number;
  is_root: boolean;
  metadata?: Record<string, any>;
}

export interface GraphEdge {
  id: string;
  source: string;
  target: string;
  label: string;
  confidence: number;
  providers: string[];
  evidence_count: number;
}

export interface GraphResponse {
  root_ioc: string;
  nodes: GraphNode[];
  edges: GraphEdge[];
}

export interface InvestigationEvent {
  id: string;
  event_type: string;
  message: string;
  details?: Record<string, any>;
  created_at: string;
}

export interface InvestigationSummary {
  id: string;
  root_ioc_value: string;
  root_ioc_type: string;
  status: string;
  risk_score: number;
  pivot_depth: number;
  discovered_iocs_count: number;
  total_relationships: number;
  providers_queried: number;
  created_at: string;
  updated_at: string;
}

export interface InvestigationDetail {
  id: string;
  root_ioc_value: string;
  root_ioc_type: string;
  status: string;
  error_message?: string;
  risk_score: number;
  pivot_depth: number;
  created_at: string;
  updated_at: string;
  layer1: Layer1Reputation;
  layer2: Layer2Infrastructure;
  layer3: Layer3DiscoveredIOCs;
  graph: GraphResponse;
  events: InvestigationEvent[];
}

export interface IOCDetectionResult {
  input_value: string;
  detected_type?: IOCType;
  canonical_value?: string;
  is_valid: boolean;
  message?: string;
}
