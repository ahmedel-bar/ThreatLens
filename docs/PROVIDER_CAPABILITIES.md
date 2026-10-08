# Provider Capabilities Matrix

This document provides the official technical specification and capability matrix for all 11 threat intelligence and infrastructure hunting providers integrated into **ThreatLens**.

---

## 1. VirusTotal

- **Official Source / Docs**: [https://docs.virustotal.com/reference/overview](https://docs.virustotal.com/reference/overview) (API v3)
- **Authentication Method**: API Key passed via HTTP Header: `x-apikey: <VT_API_KEY>`
- **Supported IOC Types**: IPv4, IPv6, Domain, URL, MD5, SHA1, SHA256
- **Lookup Endpoints**:
  - IP: `GET https://www.virustotal.com/api/v3/ip_addresses/{ip}`
  - Domain: `GET https://www.virustotal.com/api/v3/domains/{domain}`
  - URL: `GET https://www.virustotal.com/api/v3/urls/{id}` where `{id}` is URL-safe Base64 encoded without padding (`base64.urlsafe_b64encode(url.encode()).decode().strip("=")`)
  - File/Hash: `GET https://www.virustotal.com/api/v3/files/{hash}`
- **Search Endpoints**:
  - `GET https://www.virustotal.com/api/v3/search?query={query}` (Premium / restricted quota)
- **Enrichment Capabilities**:
  - Malicious / Suspicious / Harmless / Undetected analysis statistics
  - Detailed engine breakdown (e.g. CrowdStrike, Kaspersky, Microsoft)
  - Reputation score, community votes, tags, categories
  - First submission and last analysis timestamps
- **Relationship Capabilities**:
  - IP: resolutions, communicating files, downloaded files
  - Domain: subdomains, historical DNS, communicating files
  - Hash: contacted IPs, contacted domains, bundled files, execution parents
- **Infrastructure Capabilities**:
  - Autonomous System (ASN and AS owner)
  - Regional registry, country code, network CIDR
  - WHOIS records and registrar data
  - Last DNS records (A, AAAA, MX, NS, TXT, CNAME)
- **Rate Limits & Free-Tier Restrictions**:
  - Public API: 4 requests/minute, 500 requests/day, 15.5k requests/month.
  - No commercial use with public API keys.
- **Premium-Only Functionality**:
  - Live hunting, retroactive search, enterprise graph API expansions, high-frequency rate limits.
- **Unsupported Operations**:
  - Arbitrary raw packet capture downloads on free tier.
- **Notes**: URL IDs must strictly omit `=` padding characters.
- **Implementation Status**: Fully Implemented (Real Adapter + Mock Mode + Fixture Tests).

---

## 2. AlienVault OTX (Open Threat Exchange)

- **Official Source / Docs**: [https://otx.alienvault.com/api](https://otx.alienvault.com/api)
- **Authentication Method**: API Key passed via HTTP Header: `X-OTX-API-KEY: <OTX_API_KEY>`
- **Supported IOC Types**: IPv4, IPv6, Domain, URL, MD5, SHA1, SHA256
- **Lookup Endpoints**:
  - IP: `GET https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general`, `.../passive_dns`
  - Domain: `GET https://otx.alienvault.com/api/v1/indicators/domain/{domain}/general`, `.../passive_dns`
  - URL: `GET https://otx.alienvault.com/api/v1/indicators/url/{url}/general`
  - File: `GET https://otx.alienvault.com/api/v1/indicators/file/{hash}/general`, `.../analysis`
- **Search Endpoints**:
  - `GET https://otx.alienvault.com/api/v1/search/pulses?q={query}`
- **Enrichment Capabilities**:
  - Associated pulses, pulse count, threat categories, tags, adversary/actor names, targeted industries.
  - Threat family attribution and validation indicators.
- **Relationship Capabilities**:
  - Pulse-associated indicators (co-occurring IOCs in same campaigns)
  - Passive DNS historical resolutions (domains pointing to IP, IPs resolving to domain)
- **Infrastructure Capabilities**:
  - ASN, CIDR, Country code, city, coordinates
  - Historical passive DNS records with first/last seen
- **Rate Limits & Free-Tier Restrictions**:
  - Generous free community tier (~10,000 requests/hour with registered key).
- **Premium-Only Functionality**:
  - AT&T Cybersecurity commercial threat stream feeds.
- **Unsupported Operations**:
  - Deep dynamic sandbox execution via standard OTX indicator endpoints.
- **Notes**: Indicator type paths in URL are case-sensitive (`IPv4`, `domain`, `file`, `url`).
- **Implementation Status**: Fully Implemented (Real Adapter + Mock Mode + Fixture Tests).

---

## 3. MalwareBazaar (Abuse.ch)

- **Official Source / Docs**: [https://bazaar.abuse.ch/api/](https://bazaar.abuse.ch/api/)
- **Authentication Method**: API Key passed via HTTP Header: `Auth-Key: <MALWAREBAZAAR_API_KEY>`
- **Supported IOC Types**: MD5, SHA1, SHA256 (Hashes ONLY)
- **Lookup Endpoints**:
  - Hash info: `POST https://mb-api.abuse.ch/api/v1/` with body `query=get_info&hash={hash}`
- **Search Endpoints**:
  - `POST https://mb-api.abuse.ch/api/v1/` with body `query=get_taginfo&tag={tag}`
  - `POST https://mb-api.abuse.ch/api/v1/` with body `query=get_siginfo&signature={signature}`
- **Enrichment Capabilities**:
  - Malware signature / family (e.g. AgentTesla, RedLine, Cobalt Strike)
  - File type (exe, dll, docx, elf, apk), file size, file names
  - First seen, last seen, delivery method, tags
  - Code signing status, YARA rule hits, vendor threat intel (ReversingLabs, ClamAV, UnpacMe)
- **Relationship Capabilities**:
  - Cross-hash relationships (MD5 <-> SHA1 <-> SHA256)
  - Delivery URLs and reporting sample origins
- **Infrastructure Capabilities**:
  - Not directly an infrastructure provider; maps payloads to delivery sources.
- **Rate Limits & Free-Tier Restrictions**:
  - Free community service provided by abuse.ch. Fair use policy; Auth-Key registration required.
- **Premium-Only Functionality**:
  - None (community open project).
- **Unsupported Operations**:
  - Direct IP, Domain, and URL reputation queries (will strictly return `unsupported`).
- **Notes**: Returns `query_status: "hash_not_found"` when no malware sample is indexed.
- **Implementation Status**: Fully Implemented (Real Adapter + Mock Mode + Fixture Tests).

---

## 4. Hybrid Analysis (Falcon Sandbox)

- **Official Source / Docs**: [https://www.hybrid-analysis.com/docs/api/v2](https://www.hybrid-analysis.com/docs/api/v2)
- **Authentication Method**: HTTP Headers: `api-key: <HYBRID_ANALYSIS_API_KEY>` and `User-Agent: Falcon Sandbox`
- **Supported IOC Types**: MD5, SHA1, SHA256, Domain, IPv4
- **Lookup Endpoints**:
  - Hash lookup: `POST https://www.hybrid-analysis.com/api/v2/search/hash` (form data `hash={hash}`)
  - Report overview: `GET https://www.hybrid-analysis.com/api/v2/overview/{sha256}`
  - Quick search terms: `POST https://www.hybrid-analysis.com/api/v2/search/terms`
- **Search Endpoints**:
  - `POST https://www.hybrid-analysis.com/api/v2/search/terms` with host or domain filters
- **Enrichment Capabilities**:
  - Threat score (0-100), verdict (malicious, suspicious, no specific threat, whitelisted)
  - VX family attribution, AV detection rate, MITRE ATT&CK tactics & techniques
  - Environment details (Windows 10 64-bit, Android, Linux)
- **Relationship Capabilities**:
  - Contacted hosts/IPs from dynamic detonation
  - Contacted DNS domains, dropped files, child processes
- **Infrastructure Capabilities**:
  - Network traffic capture metadata (extracted C2 IPs and domains)
- **Rate Limits & Free-Tier Restrictions**:
  - Free API key allows ~200 requests/hour; file submissions limited.
- **Premium-Only Functionality**:
  - High-volume bulk querying, private/hidden sandbox detonations.
- **Unsupported Operations**:
  - Arbitrary URL search without scanning or existing sandbox task.
- **Notes**: Must provide valid `User-Agent` header.
- **Implementation Status**: Fully Implemented (Real Adapter + Mock Mode + Fixture Tests).

---

## 5. AbuseIPDB

- **Official Source / Docs**: [https://docs.abuseipdb.com/](https://docs.abuseipdb.com/)
- **Authentication Method**: HTTP Headers: `Key: <ABUSEIPDB_API_KEY>`, `Accept: application/json`
- **Supported IOC Types**: IPv4, IPv6 ONLY
- **Lookup Endpoints**:
  - Check IP: `GET https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90&verbose`
- **Search Endpoints**:
  - `GET https://api.abuseipdb.com/api/v2/check-block` (CIDR check)
- **Enrichment Capabilities**:
  - Abuse confidence score (0-100%)
  - Total reported incidents, distinct users reporting
  - Whitelist status, Tor exit node indicator
  - Usage type (Data Center/Web Hosting/Transit, Commercial, ISP, etc.)
  - Individual reporter comment logs and attack categories (e.g., SSH brute force, Port Scan, DDoS)
- **Relationship Capabilities**:
  - Associated hostnames, reverse DNS hostnames
- **Infrastructure Capabilities**:
  - ISP name, Domain name, Country code, Country name
- **Rate Limits & Free-Tier Restrictions**:
  - Free API key: 1,000 requests/day.
- **Premium-Only Functionality**:
  - Up to 500,000+ checks/day, downloadable IP blacklist feeds.
- **Unsupported Operations**:
  - Domains, URLs, File hashes (returns `unsupported` immediately without hitting API).
- **Notes**: Strict IP-only service; never submit domains or hashes.
- **Implementation Status**: Fully Implemented (Real Adapter + Mock Mode + Fixture Tests).

---

## 6. ThreatFox (Abuse.ch)

- **Official Source / Docs**: [https://threatfox.abuse.ch/api/](https://threatfox.abuse.ch/api/)
- **Authentication Method**: HTTP Header: `Auth-Key: <THREATFOX_API_KEY>`
- **Supported IOC Types**: IPv4, IPv6, Domain, URL, MD5, SHA1, SHA256
- **Lookup Endpoints**:
  - IOC Search: `POST https://threatfox-api.abuse.ch/api/v1/` with JSON `{"query": "search_ioc", "search_term": "{ioc}", "exact_match": true}`
  - Hash Search: `POST https://threatfox-api.abuse.ch/api/v1/` with JSON `{"query": "search_hash", "hash": "{hash}"}`
- **Search Endpoints**:
  - `POST https://threatfox-api.abuse.ch/api/v1/` with JSON `{"query": "tag_info", "tag": "{tag}"}`
- **Enrichment Capabilities**:
  - Threat type (botnet_cc, payload_delivery, etc.)
  - Malware printable name, malware alias, malware ID
  - Reporter attribution, reporter rating
  - Confidence level (0-100)
  - First seen and last seen UTC timestamps
- **Relationship Capabilities**:
  - Associated malware tags, shared threat actors
- **Infrastructure Capabilities**:
  - Port associated with IP:Port C2 indicators
- **Rate Limits & Free-Tier Restrictions**:
  - Free community tier by abuse.ch. Fair use applies. Free auth token via auth.abuse.ch.
  - ThreatFox expires IOCs older than 6 months from API query response.
- **Premium-Only Functionality**:
  - Commercial bulk partner feeds.
- **Unsupported Operations**:
  - Raw WHOIS, certificate discovery.
- **Notes**: Handles both network IOCs (IP, domain, URL) and hashes.
- **Implementation Status**: Fully Implemented (Real Adapter + Mock Mode + Fixture Tests).

---

## 7. URLhaus (Abuse.ch)

- **Official Source / Docs**: [https://urlhaus.abuse.ch/api/](https://urlhaus.abuse.ch/api/)
- **Authentication Method**: HTTP Header: `Auth-Key: <URLHAUS_API_KEY>`
- **Supported IOC Types**: URL, Domain, IPv4, MD5, SHA256
- **Lookup Endpoints**:
  - URL: `POST https://urlhaus-api.abuse.ch/v1/url/` (Form: `url={url}`)
  - Host (Domain or IP): `POST https://urlhaus-api.abuse.ch/v1/host/` (Form: `host={host}`)
  - Payload (Hash): `POST https://urlhaus-api.abuse.ch/v1/payload/` (Form: `md5={hash}` or `sha256={hash}`)
- **Search Endpoints**:
  - `POST https://urlhaus-api.abuse.ch/v1/tag/` (Form: `tag={tag}`)
- **Enrichment Capabilities**:
  - URL status (`online`, `offline`, `unknown`)
  - Threat classification (e.g. malware_download)
  - Blacklist status (Surbl, Spamhaus DBL)
  - Reporter, date added, expiration
- **Relationship Capabilities**:
  - Delivered malware payloads (MD5, SHA256 hashes, file types, signatures)
  - Hosted URLs on the same IP or domain
- **Infrastructure Capabilities**:
  - AS Number, AS Name, Country code of hosting provider
- **Rate Limits & Free-Tier Restrictions**:
  - Free open community API; requires abuse.ch Auth-Key.
- **Premium-Only Functionality**:
  - None.
- **Unsupported Operations**:
  - SHA1 hash payload lookup (URLhaus uses MD5 and SHA256).
- **Notes**: Returns `query_status: "no_results"` or `"url_not_found"` when IOC is clean/untracked.
- **Implementation Status**: Fully Implemented (Real Adapter + Mock Mode + Fixture Tests).

---

## 8. urlscan.io

- **Official Source / Docs**: [https://urlscan.io/docs/api/](https://urlscan.io/docs/api/)
- **Authentication Method**: HTTP Header: `API-Key: <URLSCAN_API_KEY>`
- **Supported IOC Types**: Domain, IPv4, URL, SHA256 (hash)
- **Lookup & Search Endpoints**:
  - Search: `GET https://urlscan.io/api/v1/search/?q={query}&size=10`
    - IP query: `ip:"{ip}"`
    - Domain query: `domain:"{domain}"`
    - URL query: `page.url:"{url}"`
    - Hash query: `hash:"{hash}"`
  - Result details: `GET https://urlscan.io/api/v1/result/{uuid}/`
- **Enrichment Capabilities**:
  - Page title, HTTP status code, server software header
  - Screenshot URL and DOM snapshot links
  - Technology detections (CMS, frameworks, analytics)
  - Malicious verdict and score
- **Relationship Capabilities**:
  - Contacted IPs, domains, and outbound links during page load
  - TLS certificates and certificate SANs
  - Downloaded resource hashes
- **Infrastructure Capabilities**:
  - ASN, ASN name, country, server IP, reverse DNS PTR
  - TLS issuer, subject, valid dates
- **Rate Limits & Free-Tier Restrictions**:
  - Free API key: 100 search requests/day, 5,000 search requests/month, 60 requests/minute.
- **Premium-Only Functionality**:
  - Live scanning private submissions, higher search quotas, live websocket feed.
- **Unsupported Operations**:
  - MD5 / SHA1 standalone lookups (urlscan indexes SHA256).
- **Notes**: Search endpoint returns historical scans; does not consume active scan quota.
- **Implementation Status**: Fully Implemented (Real Adapter + Mock Mode + Fixture Tests).

---

## 9. Censys

- **Official Source / Docs**: [https://docs.censys.com](https://docs.censys.com) (Platform API v3)
- **Authentication Method**: Bearer Token (`CENSYS_API_KEY` / `CENSYS_API_SECRET` Personal Access Token)
- **Supported IOC Types**: IPv4, IPv6, SHA256 (TLS fingerprint), Domain (search)
- **Lookup Endpoints**:
  - Host: `GET https://api.platform.censys.io/v3/global/asset/host/{ip}`
  - Certificate: `POST https://api.platform.censys.io/v3/global/asset/certificate`
- **Enrichment Capabilities**:
  - Discovered services, open TCP/UDP ports, service names, protocol banners
  - TLS/SSL cipher suites, certificate fingerprints, validity periods
  - Operating system fingerprinting
- **Relationship Capabilities**:
  - Associated hostnames, domains in certificate SANs, IP-to-ASN mappings
- **Infrastructure Capabilities**:
  - Autonomous System Number (ASN), AS Organization, CIDR routing
  - Physical geolocation (country, region, city, coordinates)
  - Reverse DNS, nameserver information
- **Rate Limits & Free-Tier Restrictions**:
  - Free community tier: 250 search queries/month.
- **Premium-Only Functionality**:
  - Advanced search query language, bulk raw data downloads, high-volume query limits.
- **Unsupported Operations**:
  - URL scans, malware hash lookups (except certificate fingerprints).
- **Notes**: Requires both API ID and API Secret as Basic Auth credentials.
- **Implementation Status**: Fully Implemented (Real Adapter + Mock Mode + Fixture Tests).

---

## 10. GreyNoise

- **Official Source / Docs**: [https://docs.greynoise.io/reference/get_v3-ip-ip](https://docs.greynoise.io/reference/get_v3-ip-ip) (API v3)
- **Authentication Method**: HTTP Header: `key: <GREYNOISE_API_KEY>`
- **Supported IOC Types**: IPv4 ONLY
- **Lookup Endpoints**:
  - IP Context (v3): `GET https://api.greynoise.io/v3/ip/{ip}`
  - Community IP Context (v3): `GET https://api.greynoise.io/v3/community/ip/{ip}`
- **Search Endpoints**:
  - GNQL Query: `GET https://api.greynoise.io/v2/experimental/gnql?query={query}` (Enterprise)
- **Enrichment Capabilities**:
  - `noise`: Boolean indicating opportunistic mass Internet scanning
  - `riot`: Boolean indicating Rule-It-Out (trusted business service, CDN, cloud provider)
  - `classification`: `malicious`, `benign`, `unknown`
  - `actor`: Known threat group or scanning organization
  - `bot`: Known botnet affiliation
  - `vpn`: Known VPN provider exit
  - `tags`: Specific attack signatures (e.g. Log4j scanner, Mirai spreader)
  - `cve`: List of exploited CVE identifiers
- **Relationship Capabilities**:
  - Threat actor attribution, botnet group mapping
- **Infrastructure Capabilities**:
  - ASN, Organization, Country, City, Reverse DNS (RDNS)
- **Rate Limits & Free-Tier Restrictions**:
  - Community free tier: 10,000 lookups/week on `/v3/community/ip/{ip}`.
- **Premium-Only Functionality**:
  - Full GNQL searching, raw packet capture patterns, timeline trends.
- **Unsupported Operations**:
  - IPv6, Domains, URLs, Hashes (strictly returns `unsupported`).
- **Notes**: Deprecated v2 `/v2/noise/context/` has been avoided in favor of modern `/v3/` unified endpoints.
- **Implementation Status**: Fully Implemented (Real Adapter + Mock Mode + Fixture Tests).

---

## 11. Shodan

- **Official Source / Docs**: [https://developer.shodan.io/api](https://developer.shodan.io/api)
- **Authentication Method**: Query Parameter: `?key=<SHODAN_API_KEY>`
- **Supported IOC Types**: IPv4, IPv6, Domain
- **Lookup Endpoints**:
  - Host Lookup: `GET https://api.shodan.io/shodan/host/{ip}?key={key}&minify=false`
  - DNS Resolve: `GET https://api.shodan.io/dns/resolve?hostnames={domain}&key={key}`
  - Reverse DNS: `GET https://api.shodan.io/dns/reverse?ips={ip}&key={key}`
- **Search Endpoints**:
  - Search: `GET https://api.shodan.io/shodan/host/search?key={key}&query={query}`
- **Enrichment Capabilities**:
  - Open ports, transport protocols (TCP/UDP), service software versions
  - Service banners, HTML titles, HTTP components
  - Known CVE vulnerabilities detected on exposed services
  - SSL/TLS certificate details (subject, issuer, serial, SANs)
- **Relationship Capabilities**:
  - Hostnames associated with IP, domains resolving to IP, certificates linking hosts
- **Infrastructure Capabilities**:
  - ISP, Organization, Autonomous System (ASN), Country, City, Geolocation coordinates
- **Rate Limits & Free-Tier Restrictions**:
  - Free/API plan: 1 request/second query limit; scan credits required for active queries.
- **Premium-Only Functionality**:
  - Enterprise streaming firehose, exploit database queries, network alerts.
- **Unsupported Operations**:
  - Hashes and URLs directly for host lookup (returns `unsupported`).
- **Notes**: Respects 1 req/sec rate limit with backoff.
- **Implementation Status**: Fully Implemented (Real Adapter + Mock Mode + Fixture Tests).
