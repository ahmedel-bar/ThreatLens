import re
import ipaddress
from typing import List, Dict, Any, Tuple, Optional, Set
from app.schemas.ioc import IOCType, ProviderStatus
from app.schemas.provider import (
    ProviderResult,
    InfrastructureData,
    TTPTechnique,
    PassiveDnsRecord,
    TTPSubTechnique,
    TTPTechniqueNode,
    TTPTacticNode,
    ThreatAttribution,
    VirusTotalDetectionStats,
    SecurityHeaderInfo,
    SecurityHeadersAnalysis,
)
from app.providers.webcheck import normalize_security_headers
from app.schemas.investigation import (
    Layer1ReputationResponse,
    Layer2InfrastructureResponse,
    Layer3DiscoveredIOCsResponse,
    CanonicalIOCResponse,
    RelationshipResponse,
)
from app.services.confidence import calculate_overall_risk
from app.services.ioc import normalize_ioc
from app.services.mitre_attack import (
    MITRE_TACTICS,
    MITRE_CATALOG,
    TACTIC_NAME_TO_ID,
    lookup_mitre_technique,
)


MITRE_ATTACK_NAMES: Dict[str, str] = {
    "T1055": "Process Injection",
    "T1027": "Obfuscated Files or Information",
    "T1082": "System Information Discovery",
    "T1059": "Command and Scripting Interpreter",
    "T1070": "Indicator Removal on Host",
    "T1105": "Ingress Tool Transfer",
    "T1083": "File and Directory Discovery",
    "T1012": "Query Registry",
    "T1112": "Modify Registry",
    "T1057": "Process Discovery",
    "T1497": "Virtualization/Sandbox Evasion",
    "T1036": "Masquerading",
    "T1547": "Boot or Logon Autostart Execution",
    "T1041": "Exfiltration Over C2 Channel",
    "T1071": "Application Layer Protocol",
    "T1090": "Proxy",
    "T1566": "Phishing",
    "T1204": "User Execution",
    "T1486": "Data Encrypted for Impact",
    "T1218": "System Binary Proxy Execution",
    "T1562": "Impair Defenses",
    "T1021": "Remote Services",
    "T1003": "OS Credential Dumping",
    "T1053": "Scheduled Task/Job",
    "T1543": "Create or Modify System Process",
    "T1078": "Valid Accounts",
    "T1574": "Hijack Execution Flow",
    "T1046": "Network Service Discovery",
    "T1134": "Access Token Manipulation",
    "T1555": "Credentials from Password Stores",
    "T1074": "Data Staged",
    "T1005": "Data from Local System",
    "T1020": "Automated Exfiltration",
    "T1048": "Exfiltration Over Alternative Protocol",
    "T1113": "Screen Capture",
    "T1056": "Input Capture",
    "T1140": "Deobfuscate/Decode Files or Information",
    "T1016": "System Network Configuration Discovery",
    "T1049": "System Network Connections Discovery",
    "T1033": "System Owner/User Discovery",
    "T1489": "Service Stop",
    "T1490": "Inhibit System Recovery",
    "T1222": "File and Directory Permissions Modification",
    "T1087": "Account Discovery",
    "T1573": "Encrypted Channel",
    "T1569": "System Services",
    "T1571": "Non-Standard Port",
    "T1572": "Protocol Tunneling",
    "T1110": "Brute Force",
    "T1505": "Server Software Component",
    "T1190": "Exploit Public-Facing Application",
    "T1210": "Exploitation of Remote Services",
    "T1068": "Exploitation for Privilege Escalation",
    "T1211": "Exploitation for Defense Evasion",
    "T1212": "Exploitation for Credential Access",
    "T1548": "Abuse Elevation Control Mechanism",
    "T1553": "Subvert Trust Controls",
    "T1564": "Hide Artifacts",
    "T1202": "Indirect Command Execution",
    "T1560": "Archive Collected Data",
    "T1072": "Software Deployment Tools",
    "T1124": "System Time Discovery",
    "T1499": "Endpoint Denial of Service",
    "T1498": "Network Denial of Service",
}


REPUTATION_PROVIDERS = {
    "virustotal",
    "otx",
    "abuseipdb",
    "greynoise",
    "threatfox",
    "urlhaus",
    "urlscan",
    "hybrid_analysis",
    "malwarebazaar",
    "pulsedive",
    "criminalip",
}

INFRASTRUCTURE_PROVIDERS = {
    "shodan",
    "censys",
    "urlscan",
    "pulsedive",
    "criminalip",
    "mnemonic_passivedns",
    "passivedns",
    "webcheck",
}


def build_ttp_hierarchy(
    ttps: List[TTPTechnique],
    attributions: Optional[List[ThreatAttribution]] = None,
) -> List[TTPTacticNode]:
    """
    Constructs a canonical 3-tier MITRE Enterprise ATT&CK hierarchy:
    Tactic -> Technique -> Sub-technique
    Groups deduplicated techniques and sub-techniques under authoritative tactics
    ordered according to the official Enterprise Matrix stages.
    """
    if not ttps:
        return []

    tactic_groups: Dict[str, Dict[str, TTPTechniqueNode]] = {}

    malware_names: List[str] = []
    actor_names: List[str] = []
    if attributions:
        for attr in attributions:
            if attr.malware_family and attr.malware_family not in malware_names:
                malware_names.append(attr.malware_family)
            if attr.threat_actor and attr.threat_actor not in actor_names:
                actor_names.append(attr.threat_actor)

    for ttp in ttps:
        raw_id = ttp.technique_id.strip().upper()
        if not raw_id:
            continue
        catalog_item = lookup_mitre_technique(raw_id)

        tactic_id = "TA0002"
        tactic_name = "Execution"
        if catalog_item:
            tactic_id = catalog_item.primary_tactic_id
            tactic_name = catalog_item.primary_tactic_name
        elif ttp.tactic:
            t_lower = ttp.tactic.lower().strip()
            if ttp.tactic.upper() in MITRE_TACTICS:
                tactic_id = ttp.tactic.upper()
                tactic_name = MITRE_TACTICS[tactic_id].name
            elif t_lower in TACTIC_NAME_TO_ID:
                tactic_id = TACTIC_NAME_TO_ID[t_lower]
                tactic_name = MITRE_TACTICS[tactic_id].name

        if tactic_id not in tactic_groups:
            tactic_groups[tactic_id] = {}

        is_sub = catalog_item.is_subtechnique if catalog_item else ("." in raw_id)
        parent_id = catalog_item.parent_id if (catalog_item and catalog_item.parent_id) else (raw_id.split(".")[0] if is_sub else None)

        evidence_list = [ttp.description] if ttp.description else []

        if is_sub and parent_id:
            if parent_id not in tactic_groups[tactic_id]:
                parent_catalog = lookup_mitre_technique(parent_id)
                parent_name = parent_catalog.name if parent_catalog else f"Technique {parent_id}"
                tactic_groups[tactic_id][parent_id] = TTPTechniqueNode(
                    id=parent_id,
                    name=parent_name,
                    description=None,
                    severity=ttp.severity,
                    sources=list(ttp.sources),
                    evidence=[],
                    associated_malware=malware_names,
                    associated_actors=actor_names,
                    sub_techniques=[],
                )
            else:
                parent_node = tactic_groups[tactic_id][parent_id]
                for s in ttp.sources:
                    if s not in parent_node.sources:
                        parent_node.sources.append(s)

            parent_node = tactic_groups[tactic_id][parent_id]
            sub_exists = next((st for st in parent_node.sub_techniques if st.id == raw_id), None)
            tech_name = catalog_item.name if catalog_item else (ttp.technique_name or raw_id)
            if not sub_exists:
                parent_node.sub_techniques.append(
                    TTPSubTechnique(
                        id=raw_id,
                        name=tech_name,
                        description=ttp.description,
                        severity=ttp.severity,
                        sources=list(ttp.sources),
                        evidence=evidence_list,
                        associated_malware=malware_names,
                        associated_actors=actor_names,
                    )
                )
            else:
                for s in ttp.sources:
                    if s not in sub_exists.sources:
                        sub_exists.sources.append(s)
                if not sub_exists.description and ttp.description:
                    sub_exists.description = ttp.description
                if not sub_exists.severity and ttp.severity:
                    sub_exists.severity = ttp.severity
        else:
            tech_name = catalog_item.name if catalog_item else (ttp.technique_name or raw_id)
            if raw_id not in tactic_groups[tactic_id]:
                tactic_groups[tactic_id][raw_id] = TTPTechniqueNode(
                    id=raw_id,
                    name=tech_name,
                    description=ttp.description,
                    severity=ttp.severity,
                    sources=list(ttp.sources),
                    evidence=evidence_list,
                    associated_malware=malware_names,
                    associated_actors=actor_names,
                    sub_techniques=[],
                )
            else:
                existing_node = tactic_groups[tactic_id][raw_id]
                for s in ttp.sources:
                    if s not in existing_node.sources:
                        existing_node.sources.append(s)
                if not existing_node.name and tech_name:
                    existing_node.name = tech_name
                if not existing_node.description and ttp.description:
                    existing_node.description = ttp.description
                if not existing_node.severity and ttp.severity:
                    existing_node.severity = ttp.severity

    result_tactics: List[TTPTacticNode] = []
    for tactic_id, techniques_dict in tactic_groups.items():
        tactic_meta = MITRE_TACTICS.get(tactic_id)
        order = tactic_meta.order if tactic_meta else 99
        t_name = tactic_meta.name if tactic_meta else f"Tactic {tactic_id}"

        sorted_techniques = sorted(techniques_dict.values(), key=lambda t: t.id)
        for tech in sorted_techniques:
            tech.sub_techniques.sort(key=lambda st: st.id)

        result_tactics.append(
            TTPTacticNode(
                id=tactic_id,
                name=t_name,
                order=order,
                techniques=sorted_techniques,
            )
        )

    result_tactics.sort(key=lambda tn: tn.order)
    return result_tactics


def build_layer1_reputation(
    root_ioc: str,
    root_type: IOCType,
    provider_results: List[ProviderResult],
) -> Layer1ReputationResponse:
    # Strictly isolate Layer 1 to Threat Intelligence & Reputation providers that support the IOC
    rep_results = [
        r for r in provider_results
        if r.provider_name.lower() in REPUTATION_PROVIDERS and r.status != ProviderStatus.UNSUPPORTED
    ]

    risk_score, overall_class = calculate_overall_risk(rep_results)
    success_count = sum(1 for r in rep_results if r.status == ProviderStatus.SUCCESS)
    not_found_count = sum(1 for r in rep_results if r.status == ProviderStatus.NOT_FOUND)
    failed_count = sum(
        1 for r in rep_results
        if r.status not in (ProviderStatus.SUCCESS, ProviderStatus.NOT_FOUND, ProviderStatus.UNSUPPORTED)
    )

    # Provider-based Global Reputation Model (Disambiguated from engine counts)
    # Denominator N = only providers supporting the IOC type and successfully evaluated.
    # Exclude unsupported, not queried, unconfigured, timeout, server error, rate-limited.
    # NOT_FOUND != CLEAN, UNSUPPORTED != CLEAN, NOT_CONFIGURED != CLEAN.
    evaluated_providers = [r for r in rep_results if r.status in (ProviderStatus.SUCCESS, ProviderStatus.NOT_FOUND)]
    verdict_counts: Dict[str, int] = {"malicious": 0, "suspicious": 0, "clean": 0, "unknown": 0}

    for r in evaluated_providers:
        if r.status == ProviderStatus.SUCCESS:
            if r.classification == "malicious" or r.malicious_count > 0:
                verdict_counts["malicious"] += 1
            elif r.classification == "suspicious" or r.suspicious_count > 0:
                verdict_counts["suspicious"] += 1
            elif r.classification in ("benign", "clean") or r.harmless_count > 0:
                verdict_counts["clean"] += 1
            else:
                verdict_counts["unknown"] += 1
        elif r.status == ProviderStatus.NOT_FOUND:
            # NOT_FOUND is an evaluated provider that has no record, but NOT an affirmative clean certificate
            verdict_counts["unknown"] += 1

    # VirusTotal engine count isolation
    vt_res = next((r for r in rep_results if r.provider_name.lower() == "virustotal"), None)
    vt_engine_counts = None
    if vt_res:
        if vt_res.vt_engine_counts:
            vt_engine_counts = vt_res.vt_engine_counts
        else:
            raw = vt_res.raw_data if isinstance(vt_res.raw_data, dict) else {}
            data_obj = raw.get("data", {}) if isinstance(raw, dict) else {}
            attrs = data_obj.get("attributes", {}) if isinstance(data_obj, dict) else {}
            stats = attrs.get("last_analysis_stats") or raw.get("last_analysis_stats") or {}
            if stats and isinstance(stats, dict):
                vt_stats_obj = VirusTotalDetectionStats.from_api_stats(stats)
                vt_engine_counts = vt_stats_obj.to_dict()
                vt_res.vt_engine_counts = vt_engine_counts
            elif vt_res.status == ProviderStatus.SUCCESS:
                total = vt_res.malicious_count + vt_res.suspicious_count + vt_res.harmless_count
                vt_engine_counts = {
                    "malicious": vt_res.malicious_count,
                    "suspicious": vt_res.suspicious_count,
                    "undetected": 0,
                    "harmless": vt_res.harmless_count,
                    "timeout": 0,
                    "type_unsupported": 0,
                    "failure": 0,
                    "total": total,
                }
                vt_res.vt_engine_counts = vt_engine_counts

    # Collect TTPs from reputation providers
    l1_ttps_map: Dict[str, TTPTechnique] = {}
    for r in rep_results:
        p_name = r.provider_name.lower()
        if r.infrastructure:
            for ttp in (r.infrastructure.ttps or []):
                tid = ttp.technique_id.strip().upper()
                if not tid:
                    continue
                if tid not in l1_ttps_map:
                    l1_ttps_map[tid] = ttp.model_copy(deep=True)
                    if not l1_ttps_map[tid].technique_name and tid in MITRE_ATTACK_NAMES:
                        l1_ttps_map[tid].technique_name = MITRE_ATTACK_NAMES[tid]
                else:
                    if p_name not in l1_ttps_map[tid].sources:
                        l1_ttps_map[tid].sources.append(p_name)
                    if not l1_ttps_map[tid].technique_name and ttp.technique_name:
                        l1_ttps_map[tid].technique_name = ttp.technique_name
                    if not l1_ttps_map[tid].description and ttp.description:
                        l1_ttps_map[tid].description = ttp.description

            if r.infrastructure.file_metadata and r.infrastructure.file_metadata.ttps:
                for ttp in r.infrastructure.file_metadata.ttps:
                    tid = ttp.technique_id.strip().upper()
                    if not tid:
                        continue
                    if tid not in l1_ttps_map:
                        l1_ttps_map[tid] = ttp.model_copy(deep=True)
                        if not l1_ttps_map[tid].technique_name and tid in MITRE_ATTACK_NAMES:
                            l1_ttps_map[tid].technique_name = MITRE_ATTACK_NAMES[tid]
                    else:
                        if p_name not in l1_ttps_map[tid].sources:
                            l1_ttps_map[tid].sources.append(p_name)
                        if not l1_ttps_map[tid].technique_name and ttp.technique_name:
                            l1_ttps_map[tid].technique_name = ttp.technique_name
                        if not l1_ttps_map[tid].description and ttp.description:
                            l1_ttps_map[tid].description = ttp.description

    sorted_l1_ttps = sorted(list(l1_ttps_map.values()), key=lambda t: t.technique_id)

    # Include Censys in Layer 1 provider status for supported IOC types without altering reputation scoring
    censys_res = next(
        (r for r in provider_results if r.provider_name.lower() == "censys" and r.status != ProviderStatus.UNSUPPORTED),
        None,
    )
    l1_provider_results = list(rep_results)
    if censys_res and censys_res not in l1_provider_results:
        l1_provider_results.append(censys_res)

    return Layer1ReputationResponse(
        root_ioc=root_ioc,
        root_type=root_type,
        overall_classification=overall_class,
        risk_score=risk_score,
        total_providers_queried=len(l1_provider_results),
        applicable_providers_count=len(evaluated_providers),
        providers_success=success_count + (1 if censys_res and censys_res.status == ProviderStatus.SUCCESS else 0),
        providers_failed=failed_count + (1 if censys_res and censys_res.status not in (ProviderStatus.SUCCESS, ProviderStatus.NOT_FOUND, ProviderStatus.UNSUPPORTED) else 0),
        providers_not_found=not_found_count + (1 if censys_res and censys_res.status == ProviderStatus.NOT_FOUND else 0),
        verdict_counts=verdict_counts,
        vt_engine_counts=vt_engine_counts,
        provider_results=l1_provider_results,
        ttps=sorted_l1_ttps,
    )


import re

MALWARE_CANONICAL_NAMES: Dict[str, str] = {
    # WannaCry & variants
    "wannacry": "WannaCry",
    "wannacrypt": "WannaCry",
    "wannacryptor": "WannaCry",
    "wcry": "WannaCry",
    "wncry": "WannaCry",
    "wanna": "WannaCry",
    "wannadecryptor": "WannaCry",
    "mssecsvc": "WannaCry",
    "edthreat": "WannaCry",
    # Major Ransomware
    "lockbit": "LockBit",
    "lockbit3": "LockBit",
    "lockbitblack": "LockBit",
    "conti": "Conti",
    "ryuk": "Ryuk",
    "blackcat": "BlackCat (ALPHV)",
    "alphv": "BlackCat (ALPHV)",
    "darkside": "DarkSide",
    "revil": "REvil (Sodinokibi)",
    "sodinokibi": "REvil (Sodinokibi)",
    "clop": "Clop",
    "blackbasta": "BlackBasta",
    "hive": "Hive",
    "babuk": "Babuk",
    "akira": "Akira",
    "play": "Play Ransomware",
    "playransomware": "Play Ransomware",
    "stop": "STOP / DJVU",
    "djvu": "STOP / DJVU",
    "stopdjvu": "STOP / DJVU",
    "cerber": "Cerber",
    "gandcrab": "GandCrab",
    "maze": "Maze",
    "netwalker": "NetWalker",
    "ragnar": "Ragnar Locker",
    "ragnarlocker": "Ragnar Locker",
    "phobos": "Phobos",
    "dharma": "Dharma",
    "medusa": "Medusa",
    "medusalocker": "MedusaLocker",
    "bianlian": "BianLian",
    "royal": "Royal Ransomware",
    "royalransomware": "Royal Ransomware",
    # C2 / Post-Exploitation
    "cobaltstrike": "Cobalt Strike",
    "sliver": "Sliver C2",
    "havoc": "Havoc C2",
    "bruteratel": "Brute Ratel",
    "mythic": "Mythic C2",
    # Stealers & Keyloggers
    "agenttesla": "Agent Tesla",
    "redline": "RedLine Stealer",
    "redlinestealer": "RedLine Stealer",
    "vidar": "Vidar Stealer",
    "raccoon": "Raccoon Stealer",
    "lumma": "Lumma Stealer",
    "lummastealer": "Lumma Stealer",
    "stealc": "Stealc",
    "metastealer": "MetaStealer",
    "formbook": "FormBook",
    "xloader": "XLoader",
    "lokibot": "LokiBot",
    "loki": "LokiBot",
    # RATs
    "remcos": "Remcos RAT",
    "remcosrat": "Remcos RAT",
    "asyncrat": "AsyncRAT",
    "njrat": "njRAT",
    "bladerat": "njRAT",
    "darkcomet": "DarkComet",
    "quasarrat": "Quasar RAT",
    "quasar": "Quasar RAT",
    "nanocore": "NanoCore RAT",
    "netwire": "Netwire RAT",
    "warzone": "Warzone RAT",
    "avemaria": "Warzone RAT (Ave Maria)",
    "avemariarat": "Warzone RAT (Ave Maria)",
    "glassrat": "GlassRAT",
    # Banking Trojans & Botnets
    "emotet": "Emotet",
    "geodo": "Emotet",
    "heodo": "Emotet",
    "qakbot": "QakBot",
    "qbot": "QakBot",
    "quakbot": "QakBot",
    "icedid": "IcedID",
    "bokbot": "IcedID",
    "danabot": "DanaBot",
    "dridex": "Dridex",
    "trickbot": "TrickBot",
    # Loaders & Droppers
    "bazarloader": "BazarLoader",
    "bazloader": "BazarLoader",
    "bazaloader": "BazarLoader",
    "smokeloader": "SmokeLoader",
    "guploader": "DBatLoader",
    "dbatloader": "DBatLoader",
    "amadey": "Amadey",
    # Miners
    "miner": "Crypto Miner",
    "cryptominer": "Crypto Miner",
    "cryptomining": "Crypto Mining",
    "xmrig": "XMRig Miner",
    "coinminer": "CoinMiner",
    # IoT / DDoS Botnets
    "mirai": "Mirai",
    "mozi": "Mozi",
    "gafgyt": "Gafgyt (BASHLITE)",
    "bashlite": "Gafgyt (BASHLITE)",
}

CVE_PATTERN = re.compile(r'^CVE-\d{4}-\d{4,8}$', re.IGNORECASE)


def is_cve_identifier(name: str) -> bool:
    if not name or not isinstance(name, str):
        return False
    return bool(CVE_PATTERN.match(name.strip()))


GENERIC_CLASSIFICATION_PATTERNS = [
    r'^(?:trojan\.)?generic(?:\.[a-z0-9]+)?$',
    r'^generic(?:\.[a-z0-9]+)?$',
    r'^trojan:win(?:32|64)/generic.*$',
    r'^generic\s+(?:malware|detection|classification|trojan|family|threat).*$',
    r'^(?:malware|trojan|virus|worm|backdoor|dropper|downloader|ransomware|infostealer|stealer|miner|botnet|payload|exploit)$',
    r'^(?:unknown|suspicious|malicious|sample|threat|unclassified)$',
    r'^heur(?:istic)?(?::|\.|\s).*$',
    r'^malware[\s_-]*(?:download|downloader|downloading|activity|delivery|traffic|beacon|sample|loader|dropper).*$',
    r'^trojan[\s_-]*(?:activity|downloader|dropper|download|generic).*$',
    r'^(?:botnet|c2)[\s_-]*(?:c2|activity|traffic|communication|server).*$',
    r'^(?:command[\s_-]*and[\s_-]*control|command[\s_-]*&[\s_-]*control)$',
    r'^(?:malicious|suspicious)[\s_-]*(?:activity|behavior|traffic|payload|download|domain|ip|url).*$',
    r'^(?:payload|payload[\s_-]*delivery|payload[\s_-]*download|exploit[\s_-]*kit|phishing|credential[\s_-]*harvesting).*$',
    r'^(?:mal|trojan|virus|worm|backdoor|exploit|adware|pua|pup)[/:\s_-]+(?:html|win32|win64|js|vbs|doc|pdf|script|gen|generic)[\w\s._-]*$',
    r'^.*[\s._/-]gen(?:eric)?(?:[\s._/-]?[a-z0-9]+)?$',
    r'^(?:win32|win64|msil|linux|osx|android|html|js|vbs)[:/._].*$',
    r'^(?:mal\s+html\s+gen.*)$',
    r'^(?:trojan\.win(?:32|64)\..*)$',
]


def is_generic_malware_classification(name: str) -> bool:
    if not name or not isinstance(name, str):
        return True
    s = name.strip()
    if is_cve_identifier(s):
        return True
    low = s.lower()
    norm = re.sub(r'[\s_-]+', ' ', low).strip()
    if norm in (
        "generic",
        "trojan generic",
        "trojan generickd",
        "generic detection",
        "generic malware classification",
        "generic malware",
        "generic threat",
        "unknown",
        "malicious",
        "suspicious",
        "malware",
        "malware download",
        "malware downloading",
        "malware delivery",
        "malware activity",
        "malware dropper",
        "malware loader",
        "payload",
        "payload download",
        "payload delivery",
        "malicious payload",
        "trojan",
        "trojan activity",
        "trojan downloader",
        "trojan dropper",
        "trojan download",
        "virus",
        "worm",
        "backdoor",
        "dropper",
        "downloader",
        "sample",
        "threat",
        "unclassified",
        "c2",
        "c2 activity",
        "c2 communication",
        "botnet c2",
        "command and control",
        "command & control",
        "phishing",
        "phishing campaign",
        "malicious activity",
        "suspicious activity",
        "malicious behavior",
        "suspicious behavior",
        "exploit",
        "exploit kit",
    ):
        return True
    for pat in GENERIC_CLASSIFICATION_PATTERNS:
        if re.match(pat, low) or re.match(pat, norm):
            return True
    return False

MALWARE_TYPES: Dict[str, str] = {
    "WannaCry": "ransomware",
    "LockBit": "ransomware",
    "Conti": "ransomware",
    "Ryuk": "ransomware",
    "BlackCat (ALPHV)": "ransomware",
    "DarkSide": "ransomware",
    "REvil (Sodinokibi)": "ransomware",
    "Clop": "ransomware",
    "BlackBasta": "ransomware",
    "Hive": "ransomware",
    "Babuk": "ransomware",
    "Akira": "ransomware",
    "Play Ransomware": "ransomware",
    "STOP / DJVU": "ransomware",
    "Cerber": "ransomware",
    "GandCrab": "ransomware",
    "Maze": "ransomware",
    "NetWalker": "ransomware",
    "Ragnar Locker": "ransomware",
    "Phobos": "ransomware",
    "Dharma": "ransomware",
    "Medusa": "ransomware",
    "MedusaLocker": "ransomware",
    "BianLian": "ransomware",
    "Royal Ransomware": "ransomware",
    "Agent Tesla": "infostealer",
    "RedLine Stealer": "infostealer",
    "Vidar Stealer": "infostealer",
    "Raccoon Stealer": "infostealer",
    "Lumma Stealer": "infostealer",
    "Stealc": "infostealer",
    "MetaStealer": "infostealer",
    "FormBook": "infostealer",
    "XLoader": "infostealer",
    "LokiBot": "infostealer",
    "Remcos RAT": "rat",
    "AsyncRAT": "rat",
    "njRAT": "rat",
    "DarkComet": "rat",
    "Quasar RAT": "rat",
    "NanoCore RAT": "rat",
    "Netwire RAT": "rat",
    "Warzone RAT": "rat",
    "Warzone RAT (Ave Maria)": "rat",
    "GlassRAT": "rat",
    "Cobalt Strike": "c2",
    "Sliver C2": "c2",
    "Havoc C2": "c2",
    "Brute Ratel": "c2",
    "Mythic C2": "c2",
    "Emotet": "botnet",
    "QakBot": "banking trojan",
    "TrickBot": "banking trojan",
    "Dridex": "banking trojan",
    "IcedID": "banking trojan",
    "DanaBot": "banking trojan",
    "BazarLoader": "loader",
    "SmokeLoader": "loader",
    "DBatLoader": "loader",
    "Amadey": "loader",
    "Mirai": "botnet",
    "Mozi": "botnet",
    "Gafgyt (BASHLITE)": "botnet",
    "XMRig Miner": "miner",
    "CoinMiner": "miner",
    "Crypto Miner": "miner",
}

THREAT_ACTOR_CANONICAL_NAMES: Dict[str, str] = {
    "apt29": "APT29 (Cozy Bear)",
    "cozybear": "APT29 (Cozy Bear)",
    "nobelium": "APT29 (Cozy Bear)",
    "thedukes": "APT29 (Cozy Bear)",
    "apt28": "APT28 (Fancy Bear)",
    "fancybear": "APT28 (Fancy Bear)",
    "strontium": "APT28 (Fancy Bear)",
    "lazarus": "Lazarus Group",
    "lazarusgroup": "Lazarus Group",
    "hiddencobra": "Lazarus Group",
    "ta505": "TA505",
    "hive0065": "TA505",
    "ta542": "TA542",
    "ta569": "TA569",
    "wizardspider": "Wizard Spider",
    "fin7": "FIN7",
    "carbanak": "FIN7 (Carbanak)",
    "sandworm": "Sandworm Team",
    "telebots": "Sandworm Team",
    "voodoobear": "Sandworm Team",
    "apt41": "APT41 (Double Dragon)",
    "barium": "APT41 (Double Dragon)",
    "wickedpanda": "APT41 (Double Dragon)",
    "mustangpanda": "Mustang Panda",
    "redapollo": "RedApollo (APT10)",
    "apt10": "RedApollo (APT10)",
    "silence": "Silence Group",
    "gamaredon": "Gamaredon",
    "kimsuky": "Kimsuky",
    "turla": "Turla",
}

KNOWN_MALWARE_PREFIXES = [
    r'^(?:trojan[-_.]ransom|trojan[-_.]downloader|trojan[-_.]dropper|trojan|ransomware|malware|backdoor|worm|dropper|downloader|infostealer|stealer|miner|botnet|virus|rootkit|exploit)\.',
    r'^(?:win32|win64|win|w32|w64|msil|osx|linux|android|elf)\.',
]

KNOWN_MALWARE_SUFFIXES = [
    r'[-_\s]+(?:ransomware|malware|trojan|stealer|infostealer|rat|botnet|miner|loader|backdoor|worm|dropper|downloader|keylogger|rootkit|wiper|beacon|payload)$',
    r'/(?:wcry|wannacry|wannacrypt)$',
]


def detect_malware_type(raw_name: str, canon_name: str = "") -> Optional[str]:
    if canon_name and canon_name in MALWARE_TYPES:
        return MALWARE_TYPES[canon_name]
    low = (raw_name or "").lower()
    if "ransomware" in low or "ransom" in low:
        return "ransomware"
    if "infostealer" in low or "stealer" in low or "keylogger" in low:
        return "infostealer"
    if "rat" in low.split() or " rat" in low or "rat " in low or "remote access trojan" in low:
        return "rat"
    if "botnet" in low or "ddos" in low:
        return "botnet"
    if "c2" in low or "beacon" in low or "command and control" in low:
        return "c2"
    if "miner" in low or "mining" in low or "cryptominer" in low:
        return "miner"
    if "loader" in low or "dropper" in low or "downloader" in low:
        return "loader"
    if "banking" in low:
        return "banking trojan"
    if "trojan" in low:
        return "trojan"
    if "backdoor" in low:
        return "backdoor"
    if "worm" in low:
        return "worm"
    if "wiper" in low:
        return "wiper"
    if "rootkit" in low:
        return "rootkit"
    return None


PROVIDER_DISPLAY_NAMES: Dict[str, str] = {
    "virustotal": "VirusTotal",
    "malwarebazaar": "MalwareBazaar",
    "hybrid_analysis": "Hybrid Analysis",
    "hybridanalysis": "Hybrid Analysis",
    "otx": "OTX",
    "threatfox": "ThreatFox",
    "urlhaus": "URLhaus",
    "pulsedive": "Pulsedive",
    "shodan": "Shodan",
    "censys": "Censys",
    "criminalip": "Criminal IP",
    "criminal_ip": "Criminal IP",
    "greynoise": "GreyNoise",
}


GENERIC_ACTOR_TERMS = {
    "china", "chinese", "russia", "russian", "iran", "iranian", "north korea", "dprk",
    "apt", "unknown", "generic", "sample", "threat", "malware", "trojan", "ransomware",
    "botnet", "infostealer", "stealer", "rat", "c2", "miner", "worm", "backdoor",
    "none", "n/a", "null", "undefined", "actor", "threat actor", "adversary",
}


def normalize_malware_name(name: str) -> str:
    if not name or not isinstance(name, str):
        return ""
    clean = name.strip()
    if is_cve_identifier(clean) or is_generic_malware_classification(clean):
        return ""
    s = clean
    for pat in KNOWN_MALWARE_PREFIXES:
        s = re.sub(pat, '', s, flags=re.IGNORECASE)
    stripped_suffix = s
    for pat in KNOWN_MALWARE_SUFFIXES:
        stripped_suffix = re.sub(pat, '', stripped_suffix, flags=re.IGNORECASE)
    # If stripping suffix reduces string to generic words, keep original
    if stripped_suffix.lower() not in ('unknown', 'generic', 'sample', 'suspicious', 'malicious', 'threat', ''):
        s = stripped_suffix

    key = re.sub(r'[^a-zA-Z0-9]', '', s).lower()
    if key in MALWARE_CANONICAL_NAMES:
        return MALWARE_CANONICAL_NAMES[key]

    orig_key = re.sub(r'[^a-zA-Z0-9]', '', clean).lower()
    if orig_key in MALWARE_CANONICAL_NAMES:
        return MALWARE_CANONICAL_NAMES[orig_key]

    for k, v in MALWARE_CANONICAL_NAMES.items():
        if len(k) >= 4 and (key.startswith(k) or key.endswith(k) or orig_key.startswith(k) or orig_key.endswith(k)):
            return v

    words = re.findall(r'[A-Z]?[a-z0-9]+|[A-Z]+(?=[A-Z][a-z]|\b)', s)
    if words and len(words) > 1 and "".join(words).lower() == key:
        return " ".join(w.capitalize() if not w.isupper() else w for w in words)
    return s.title() if s.islower() else s


def normalize_threat_actor_name(name: str) -> str:
    if not name or not isinstance(name, str):
        return ""
    clean = name.strip()
    if is_cve_identifier(clean) or is_generic_malware_classification(clean):
        return ""
    if clean.startswith("#"):
        return ""
    clean_low = clean.lower()
    if clean_low in GENERIC_ACTOR_TERMS or clean_low.replace(" ", "") in GENERIC_ACTOR_TERMS:
        return ""
    key = re.sub(r'[^a-zA-Z0-9]', '', clean).lower()
    if not key:
        return ""
    if key in THREAT_ACTOR_CANONICAL_NAMES:
        return THREAT_ACTOR_CANONICAL_NAMES[key]
    for k, v in THREAT_ACTOR_CANONICAL_NAMES.items():
        if len(k) >= 4 and key.startswith(k):
            return v
    return clean.title() if clean.islower() else clean


def _is_ip_str(val: str) -> bool:
    try:
        ipaddress.ip_address(str(val).strip())
        return True
    except (ValueError, AttributeError):
        return False


def is_valid_hostname_or_domain(val: str) -> bool:
    if not val or not isinstance(val, str):
        return False
    s = val.strip().lower()
    if not s or len(s) > 253:
        return False
    if _is_ip_str(s):
        return False
    if any(c in s for c in (':', '/', '\\', ' ', '\t', '\n', '\r', '@', '<', '>', '"', "'")):
        return False
    if not re.match(r'^[a-z0-9*._-]+$', s):
        return False
    if not any(c.isalpha() for c in s):
        return False
    if s in ('*', '.', '..', 'localhost', 'localhost.localdomain'):
        return False
    if s.endswith('.local') or s.endswith('.internal') or s.endswith('.lan') or s.endswith('.corp'):
        return False
    return True


AV_SIGNATURE_PATTERNS = [
    re.compile(r'^(?:mal|trojan|virus|worm|backdoor|exploit|adware|pua|pup|heur|heuristic)[/:\s_-]+(?:html|win32|win64|js|vbs|doc|pdf|script|gen|generic|trojan)[\w\s._-]*$', re.IGNORECASE),
    re.compile(r'^(?:heur|heuristic)[:/._\s].*$', re.IGNORECASE),
    re.compile(r'^.*[\s._/-]gen(?:eric)?(?:[\s._/-]?[a-z0-9]+)?$', re.IGNORECASE),
    re.compile(r'^(?:win32|win64|msil|linux|osx|android|html|js|vbs)[:/._].*$', re.IGNORECASE),
    re.compile(r'^(?:mal\s+html\s+gen.*)$', re.IGNORECASE),
    re.compile(r'^(?:trojan\.win(?:32|64)\..*)$', re.IGNORECASE),
]


def is_av_signature(name: str) -> bool:
    if not name or not isinstance(name, str):
        return False
    clean = name.strip()
    key = re.sub(r'[^a-zA-Z0-9]', '', clean).lower()
    if key in MALWARE_CANONICAL_NAMES:
        return False
    for pat in AV_SIGNATURE_PATTERNS:
        if pat.match(clean):
            return True
    return False


def compute_attribution_confidence(
    sources: List[str],
    has_ttps: bool = False,
    has_cves: bool = False,
    has_actor: bool = False,
    is_canonical_family: bool = False,
    is_classification: bool = False,
) -> float:
    src_count = len(set(sources))
    if is_classification:
        base = 50.0 + min(25.0, max(0, src_count - 1) * 10.0)
    elif is_canonical_family:
        if src_count >= 2:
            base = 82.0 + min(13.0, (src_count - 2) * 5.0)
        else:
            base = 65.0
    else:
        if src_count >= 2:
            base = 80.0 + min(15.0, (src_count - 2) * 5.0)
        else:
            base = 65.0

    if has_ttps:
        base += 4.0
    if has_cves:
        base += 4.0
    if has_actor:
        base += 4.0

    return min(98.0, round(base, 1))


def _has_meaningful_infra(inf: Optional[InfrastructureData]) -> bool:
    if not inf:
        return False
    if inf.open_ports or inf.services or inf.services_detail or inf.certificates or inf.certificates_detail or inf.vulnerabilities:
        return True
    if inf.asn or inf.org or inf.country or inf.city or inf.ptr:
        return True
    if inf.network and (inf.network.asn or inf.network.org or inf.network.ptr):
        return True
    if inf.geo and (inf.geo.country or inf.geo.city):
        return True
    if inf.dns and (inf.dns.hostnames or inf.dns.domains or inf.dns.records):
        return True
    if inf.whois and (inf.whois.registrar or inf.whois.creation_date):
        return True
    if inf.http and (inf.http.server or inf.http.title or inf.http.technologies):
        return True
    if inf.ip_scoring or inf.detection or inf.security:
        return True
    if inf.shodan_details or inf.censys_details:
        return True
    if inf.extra and len(inf.extra) > 0:
        return True
    return False


def build_layer2_infrastructure(
    root_ioc: str,
    root_type: IOCType,
    provider_results: List[ProviderResult],
) -> Layer2InfrastructureResponse:
    from app.schemas.provider import (
        NetworkInfo,
        GeoInfo,
        DnsInfo,
        DnsRecordItem,
        WhoisInfo,
        CertInfo,
        ServiceInfo,
        HttpInfo,
        TlsInfo,
        HostingInfo,
        VulnInfo,
        TemporalInfo,
        ShodanHostDetails,
        CensysHostDetails,
        ThreatAttribution,
        HistoricalWhoisRecord,
    )

    aggregated = InfrastructureData()
    provider_contribs: Dict[str, InfrastructureData] = {}

    # Separate collection maps for multi-provider merging and deduplication
    network_sources: set[str] = set()
    geo_sources: set[str] = set()
    dns_sources: set[str] = set()
    whois_sources: set[str] = set()
    http_sources: set[str] = set()
    tls_sources: set[str] = set()
    temporal_sources: set[str] = set()

    all_ports: set[int] = set()
    all_nameservers: set[str] = set()
    all_hostnames: set[str] = set()
    all_domains: set[str] = set()
    all_technologies: set[str] = set()
    merged_headers: Dict[str, str] = {}
    dns_records_merged: Dict[str, set[str]] = {}

    all_tls_versions: set[str] = set()
    all_tls_ciphers: set[str] = set()
    agg_jarm: Optional[str] = None
    agg_ja3s: Optional[str] = None

    agg_bgp_prefix: Optional[str] = None
    agg_isp: Optional[str] = None
    agg_continent: Optional[str] = None
    agg_http_status: Optional[int] = None

    agg_whois_registrar: Optional[str] = None
    agg_whois_creation: Optional[str] = None
    agg_whois_updated: Optional[str] = None
    agg_whois_expiration: Optional[str] = None
    agg_whois_status: List[str] = []
    agg_whois_registrant_org: Optional[str] = None
    agg_whois_registrant_country: Optional[str] = None
    agg_whois_registrar_url: Optional[str] = None
    agg_whois_registrar_whois_server: Optional[str] = None
    agg_whois_registry_domain_id: Optional[str] = None
    agg_whois_dnssec: Optional[str] = None

    services_by_key: Dict[Tuple[int, str], ServiceInfo] = {}
    certs_by_fp: Dict[str, CertInfo] = {}
    vulns_by_id: Dict[str, VulnInfo] = {}
    ttps_by_id: Dict[str, TTPTechnique] = {}
    threat_attributions_by_key: Dict[str, ThreatAttribution] = {}

    def _merge_tool_attribution(
        tool_raw: str,
        provider_name: str,
        confidence: Optional[float] = None,
        evidence: str = "",
        threat_tags: Optional[List[str]] = None,
        ttps: Optional[List[TTPTechnique]] = None,
        cves: Optional[List[str]] = None,
        relationship_type: Optional[str] = None,
    ):
        clean = tool_raw.strip()
        if not clean:
            return
        disp_name = PROVIDER_DISPLAY_NAMES.get(provider_name.lower(), provider_name)
        key = "tool:" + re.sub(r'[^a-zA-Z0-9]', '', clean).lower()
        if key not in threat_attributions_by_key:
            srcs = [disp_name]
            computed_conf = confidence if confidence is not None else compute_attribution_confidence(
                sources=srcs,
                has_ttps=bool(ttps),
                has_cves=bool(cves),
            )
            threat_attributions_by_key[key] = ThreatAttribution(
                canonical_name=clean,
                entity_type="tool",
                tool=clean,
                relationship_type=relationship_type or "associated_threat",
                threat_tags=list(set(threat_tags or [])),
                ttps=list(ttps or []),
                cves=list(set(cves or [])),
                sources=srcs,
                confidence=computed_conf,
                is_corroborated=False,
                evidence_summary=evidence or f"Tool association identified by {disp_name}",
            )
        else:
            existing = threat_attributions_by_key[key]
            if not any(s.lower() == disp_name.lower() for s in existing.sources):
                existing.sources.append(disp_name)
            if not existing.canonical_name:
                existing.canonical_name = clean
            if not existing.entity_type:
                existing.entity_type = "tool"
            if not existing.tool:
                existing.tool = clean
            if threat_tags:
                for t in threat_tags:
                    if t not in existing.threat_tags:
                        existing.threat_tags.append(t)
            if cves:
                for c in cves:
                    if c not in existing.cves:
                        existing.cves.append(c)
            if ttps:
                seen_techs = {t.technique_id for t in existing.ttps}
                for t in ttps:
                    if t.technique_id not in seen_techs:
                        existing.ttps.append(t)
                        seen_techs.add(t.technique_id)
            if evidence and evidence not in (existing.evidence_summary or ""):
                existing.evidence_summary = f"{existing.evidence_summary}; {evidence}"

            existing.confidence = compute_attribution_confidence(
                sources=existing.sources,
                has_ttps=bool(existing.ttps),
                has_cves=bool(existing.cves),
            )
            existing.is_corroborated = len(set(s.lower() for s in existing.sources)) >= 2

    def _merge_threat_association_attribution(
        assoc_raw: str,
        provider_name: str,
        confidence: Optional[float] = None,
        evidence: str = "",
        threat_tags: Optional[List[str]] = None,
        ttps: Optional[List[TTPTechnique]] = None,
        cves: Optional[List[str]] = None,
        relationship_type: Optional[str] = None,
    ):
        clean = assoc_raw.strip()
        if not clean:
            return
        disp_name = PROVIDER_DISPLAY_NAMES.get(provider_name.lower(), provider_name)
        key = "threat_association:" + re.sub(r'[^a-zA-Z0-9]', '', clean).lower()
        if key not in threat_attributions_by_key:
            srcs = [disp_name]
            computed_conf = confidence if confidence is not None else compute_attribution_confidence(
                sources=srcs,
                has_ttps=bool(ttps),
                has_cves=bool(cves),
            )
            threat_attributions_by_key[key] = ThreatAttribution(
                canonical_name=clean,
                entity_type="threat_association",
                threat_association=clean,
                relationship_type=relationship_type or "associated_threat",
                threat_tags=list(set(threat_tags or [])),
                ttps=list(ttps or []),
                cves=list(set(cves or [])),
                sources=srcs,
                confidence=computed_conf,
                is_corroborated=False,
                evidence_summary=evidence or f"Threat association identified by {disp_name}",
            )
        else:
            existing = threat_attributions_by_key[key]
            if not any(s.lower() == disp_name.lower() for s in existing.sources):
                existing.sources.append(disp_name)
            if not existing.canonical_name:
                existing.canonical_name = clean
            if not existing.entity_type:
                existing.entity_type = "threat_association"
            if not existing.threat_association:
                existing.threat_association = clean
            if threat_tags:
                for t in threat_tags:
                    if t not in existing.threat_tags:
                        existing.threat_tags.append(t)
            if cves:
                for c in cves:
                    if c not in existing.cves:
                        existing.cves.append(c)
            if ttps:
                seen_techs = {t.technique_id for t in existing.ttps}
                for t in ttps:
                    if t.technique_id not in seen_techs:
                        existing.ttps.append(t)
                        seen_techs.add(t.technique_id)
            if evidence and evidence not in (existing.evidence_summary or ""):
                existing.evidence_summary = f"{existing.evidence_summary}; {evidence}"

            existing.confidence = compute_attribution_confidence(
                sources=existing.sources,
                has_ttps=bool(existing.ttps),
                has_cves=bool(existing.cves),
            )
            existing.is_corroborated = len(set(s.lower() for s in existing.sources)) >= 2

    def _merge_classification_attribution(
        classification_raw: str,
        provider_name: str,
        verdict: Optional[str] = None,
        confidence: Optional[float] = None,
        evidence: str = "",
        threat_tags: Optional[List[str]] = None,
        ttps: Optional[List[TTPTechnique]] = None,
        provider_detection_name: Optional[str] = None,
    ):
        clean = classification_raw.strip()
        if not clean:
            return
        disp_name = PROVIDER_DISPLAY_NAMES.get(provider_name.lower(), provider_name)
        key = "classification:" + re.sub(r'[^a-zA-Z0-9]', '', clean).lower()
        if key not in threat_attributions_by_key:
            srcs = [disp_name]
            computed_conf = confidence if confidence is not None else compute_attribution_confidence(
                sources=srcs,
                has_ttps=bool(ttps),
                is_classification=True,
            )
            threat_attributions_by_key[key] = ThreatAttribution(
                canonical_name=clean,
                entity_type="provider_classification",
                detection_classification=clean,
                provider_detection_name=provider_detection_name or clean,
                verdict=verdict,
                threat_tags=list(set(threat_tags or [])),
                ttps=list(ttps or []),
                sources=srcs,
                confidence=computed_conf,
                is_corroborated=False,
                evidence_summary=evidence or f"{disp_name} provider classification '{clean}'",
            )
        else:
            existing = threat_attributions_by_key[key]
            if not any(s.lower() == disp_name.lower() for s in existing.sources):
                existing.sources.append(disp_name)
            if not existing.canonical_name:
                existing.canonical_name = clean
            if not existing.entity_type:
                existing.entity_type = "provider_classification"
            if provider_detection_name and not existing.provider_detection_name:
                existing.provider_detection_name = provider_detection_name
            existing.confidence = compute_attribution_confidence(
                sources=existing.sources,
                has_ttps=bool(existing.ttps or ttps),
                has_cves=bool(existing.cves),
                has_actor=bool(existing.threat_actor),
                is_classification=True,
            )
            existing.is_corroborated = len(set(s.lower() for s in existing.sources)) >= 2
            if verdict and not existing.verdict:
                existing.verdict = verdict
            if evidence and evidence not in (existing.evidence_summary or ""):
                existing.evidence_summary = f"{existing.evidence_summary}; {evidence}"
            if threat_tags:
                for t in threat_tags:
                    if t not in existing.threat_tags:
                        existing.threat_tags.append(t)
            if ttps:
                seen_techs = {t.technique_id for t in existing.ttps}
                for t in ttps:
                    if t.technique_id not in seen_techs:
                        existing.ttps.append(t)
                        seen_techs.add(t.technique_id)

    def _merge_cve_attribution(
        cve_raw: str,
        provider_name: str,
        verdict: Optional[str] = None,
        confidence: Optional[float] = None,
        evidence: str = "",
        threat_tags: Optional[List[str]] = None,
        ttps: Optional[List[TTPTechnique]] = None,
    ):
        cve_clean = cve_raw.strip().upper()
        if not is_cve_identifier(cve_clean):
            return
        disp_name = PROVIDER_DISPLAY_NAMES.get(provider_name.lower(), provider_name)
        key = "cve:" + cve_clean
        if key not in threat_attributions_by_key:
            srcs = [disp_name]
            computed_conf = confidence if confidence is not None else compute_attribution_confidence(
                sources=srcs,
                has_ttps=bool(ttps),
                has_cves=True,
            )
            threat_attributions_by_key[key] = ThreatAttribution(
                canonical_name=cve_clean,
                entity_type="vulnerability",
                cves=[cve_clean],
                verdict=verdict,
                threat_tags=list(set(threat_tags or [])),
                ttps=list(ttps or []),
                sources=srcs,
                confidence=computed_conf,
                is_corroborated=False,
                evidence_summary=evidence or f"{disp_name} vulnerability reference '{cve_clean}'",
            )
        else:
            existing = threat_attributions_by_key[key]
            if not any(s.lower() == disp_name.lower() for s in existing.sources):
                existing.sources.append(disp_name)
            if not existing.canonical_name:
                existing.canonical_name = cve_clean
            if not existing.entity_type:
                existing.entity_type = "vulnerability"
            existing.confidence = compute_attribution_confidence(
                sources=existing.sources,
                has_ttps=bool(existing.ttps or ttps),
                has_cves=True,
                has_actor=bool(existing.threat_actor),
            )
            existing.is_corroborated = len(set(s.lower() for s in existing.sources)) >= 2
            if verdict and not existing.verdict:
                existing.verdict = verdict
            if evidence and evidence not in (existing.evidence_summary or ""):
                existing.evidence_summary = f"{existing.evidence_summary}; {evidence}"
            if threat_tags:
                for t in threat_tags:
                    if t not in existing.threat_tags:
                        existing.threat_tags.append(t)
            if ttps:
                seen_techs = {t.technique_id for t in existing.ttps}
                for t in ttps:
                    if t.technique_id not in seen_techs:
                        existing.ttps.append(t)
                        seen_techs.add(t.technique_id)

    def _merge_malware_attribution(
        mf_raw: str,
        provider_name: str,
        confidence: Optional[float] = None,
        evidence: str = "",
        malware_type: Optional[str] = None,
        threat_tags: Optional[List[str]] = None,
        ttps: Optional[List[TTPTechnique]] = None,
        cves: Optional[List[str]] = None,
        campaign: Optional[str] = None,
        aliases: Optional[List[str]] = None,
        threat_actor: Optional[str] = None,
        threat_actor_aliases: Optional[List[str]] = None,
        verdict: Optional[str] = None,
        detection_classification: Optional[str] = None,
        provider_detection_name: Optional[str] = None,
    ):
        disp_name = PROVIDER_DISPLAY_NAMES.get(provider_name.lower(), provider_name)
        if is_cve_identifier(mf_raw):
            ev = evidence or f"{disp_name} — Falcon Sandbox VX family: \"{mf_raw.strip().upper()}\""
            if verdict and f"verdict: {verdict}" not in ev.lower():
                ev = f"{ev} (verdict: {verdict})"
            _merge_cve_attribution(
                cve_raw=mf_raw,
                provider_name=provider_name,
                verdict=verdict,
                confidence=confidence,
                evidence=ev,
                threat_tags=threat_tags,
                ttps=ttps,
            )
            return

        if is_generic_malware_classification(mf_raw) or is_av_signature(mf_raw):
            _merge_classification_attribution(
                classification_raw=mf_raw,
                provider_name=provider_name,
                verdict=verdict,
                confidence=confidence,
                evidence=evidence or f"{disp_name} provider detection '{mf_raw}'",
                threat_tags=threat_tags,
                ttps=ttps,
                provider_detection_name=provider_detection_name or mf_raw,
            )
            return

        canon_name = normalize_malware_name(mf_raw)
        if not canon_name or is_generic_malware_classification(canon_name) or is_cve_identifier(canon_name) or is_av_signature(canon_name):
            _merge_classification_attribution(
                classification_raw=mf_raw,
                provider_name=provider_name,
                verdict=verdict,
                confidence=confidence,
                evidence=evidence or f"{disp_name} provider detection '{mf_raw}'",
                threat_tags=threat_tags,
                ttps=ttps,
                provider_detection_name=provider_detection_name or mf_raw,
            )
            return

        det_type = malware_type or detect_malware_type(mf_raw, canon_name)
        key = "malware:" + re.sub(r'[^a-zA-Z0-9]', '', canon_name).lower()

        # Check if canon_name or mf_raw matches an existing attribution's family or aliases
        existing_key = None
        if key in threat_attributions_by_key:
            existing_key = key
        else:
            clean_canon = re.sub(r'[^a-zA-Z0-9]', '', canon_name).lower()
            clean_raw = re.sub(r'[^a-zA-Z0-9]', '', mf_raw).lower()
            for k, ex in threat_attributions_by_key.items():
                if ex.malware_family:
                    ex_canon = re.sub(r'[^a-zA-Z0-9]', '', ex.malware_family).lower()
                    ex_aliases = [re.sub(r'[^a-zA-Z0-9]', '', a).lower() for a in (ex.aliases or [])]
                    ex_names = [re.sub(r'[^a-zA-Z0-9]', '', n).lower() for n in (ex.malware_names or [])]
                    if clean_canon == ex_canon or clean_canon in ex_aliases or clean_canon in ex_names or clean_raw in ex_aliases or clean_raw in ex_names:
                        existing_key = k
                        break

        init_aliases = list(aliases or [])
        if mf_raw != canon_name and mf_raw not in init_aliases:
            init_aliases.append(mf_raw)

        det_name = provider_detection_name or (mf_raw if mf_raw != canon_name else None)

        if not existing_key:
            srcs = [disp_name]
            computed_conf = confidence if confidence is not None else compute_attribution_confidence(
                sources=srcs,
                has_ttps=bool(ttps),
                has_cves=bool(cves),
                has_actor=bool(threat_actor),
                is_canonical_family=True,
            )
            threat_attributions_by_key[key] = ThreatAttribution(
                canonical_name=canon_name,
                entity_type="malware_family",
                malware_family=canon_name,
                malware_names=[canon_name] if canon_name == mf_raw else [canon_name, mf_raw],
                malware_type=det_type,
                threat_actor=threat_actor,
                threat_actor_aliases=list(threat_actor_aliases or []),
                aliases=init_aliases,
                threat_tags=list(set(threat_tags or [])),
                ttps=list(ttps or []),
                cves=list(set(cves or [])),
                campaign=campaign,
                sources=srcs,
                confidence=computed_conf,
                is_corroborated=False,
                evidence_summary=evidence or f"Identified by {disp_name}",
                detection_classification=detection_classification,
                provider_detection_name=det_name,
                verdict=verdict,
            )
        else:
            existing = threat_attributions_by_key[existing_key]
            if not any(s.lower() == disp_name.lower() for s in existing.sources):
                existing.sources.append(disp_name)
            if not existing.canonical_name:
                existing.canonical_name = canon_name
            if not existing.entity_type:
                existing.entity_type = "malware_family"
            if det_name and not existing.provider_detection_name:
                existing.provider_detection_name = det_name
            if threat_actor and not existing.threat_actor:
                existing.threat_actor = threat_actor
            if threat_actor_aliases:
                for a in threat_actor_aliases:
                    if a not in existing.threat_actor_aliases:
                        existing.threat_actor_aliases.append(a)
            if detection_classification and not existing.detection_classification:
                existing.detection_classification = detection_classification
            if verdict and not existing.verdict:
                existing.verdict = verdict
            if mf_raw not in existing.malware_names:
                existing.malware_names.append(mf_raw)
            if mf_raw != existing.malware_family and mf_raw not in existing.aliases:
                existing.aliases.append(mf_raw)
            for a in init_aliases:
                if a != existing.malware_family and a not in existing.aliases:
                    existing.aliases.append(a)
            if not existing.malware_type and det_type:
                existing.malware_type = det_type
            if threat_tags:
                for tag in threat_tags:
                    if tag not in existing.threat_tags:
                        existing.threat_tags.append(tag)
            if cves:
                for c in cves:
                    if c not in existing.cves:
                        existing.cves.append(c)
            if ttps:
                seen_techs = {t.technique_id for t in existing.ttps}
                for t in ttps:
                    if t.technique_id not in seen_techs:
                        existing.ttps.append(t)
                        seen_techs.add(t.technique_id)
            if campaign and not existing.campaign:
                existing.campaign = campaign
            if evidence and evidence not in (existing.evidence_summary or ""):
                existing.evidence_summary = f"{existing.evidence_summary}; {evidence}"

            existing.confidence = compute_attribution_confidence(
                sources=existing.sources,
                has_ttps=bool(existing.ttps),
                has_cves=bool(existing.cves),
                has_actor=bool(existing.threat_actor),
                is_canonical_family=True,
            )
            existing.is_corroborated = len(set(s.lower() for s in existing.sources)) >= 2

    def _merge_actor_attribution(
        actor_raw: str,
        provider_name: str,
        confidence: Optional[float] = None,
        evidence: str = "",
        threat_tags: Optional[List[str]] = None,
        ttps: Optional[List[TTPTechnique]] = None,
        cves: Optional[List[str]] = None,
        campaign: Optional[str] = None,
        threat_actor_aliases: Optional[List[str]] = None,
    ):
        canon_name = normalize_threat_actor_name(actor_raw)
        if not canon_name:
            return
        disp_name = PROVIDER_DISPLAY_NAMES.get(provider_name.lower(), provider_name)
        key = "actor:" + re.sub(r'[^a-zA-Z0-9]', '', canon_name).lower()
        init_actor_aliases = list(threat_actor_aliases or [])
        if actor_raw != canon_name and actor_raw not in init_actor_aliases:
            init_actor_aliases.append(actor_raw)

        if key not in threat_attributions_by_key:
            srcs = [disp_name]
            computed_conf = confidence if confidence is not None else compute_attribution_confidence(
                sources=srcs,
                has_ttps=bool(ttps),
                has_cves=bool(cves),
                has_actor=True,
            )
            threat_attributions_by_key[key] = ThreatAttribution(
                canonical_name=canon_name,
                entity_type="threat_actor",
                threat_actor=canon_name,
                threat_actor_aliases=init_actor_aliases,
                aliases=[],  # NEVER put actor aliases into malware aliases
                threat_tags=list(set(threat_tags or [])),
                ttps=list(ttps or []),
                cves=list(set(cves or [])),
                campaign=campaign,
                sources=srcs,
                confidence=computed_conf,
                is_corroborated=False,
                evidence_summary=evidence or f"Identified by {disp_name}",
            )
        else:
            existing = threat_attributions_by_key[key]
            if not any(s.lower() == disp_name.lower() for s in existing.sources):
                existing.sources.append(disp_name)
            if not existing.canonical_name:
                existing.canonical_name = canon_name
            if not existing.entity_type:
                existing.entity_type = "threat_actor"
            for a in init_actor_aliases:
                if a not in existing.threat_actor_aliases and a != canon_name:
                    existing.threat_actor_aliases.append(a)
            if threat_tags:
                for tag in threat_tags:
                    if tag not in existing.threat_tags:
                        existing.threat_tags.append(tag)
            if cves:
                for c in cves:
                    if c not in existing.cves:
                        existing.cves.append(c)
            if ttps:
                seen_techs = {t.technique_id for t in existing.ttps}
                for t in ttps:
                    if t.technique_id not in seen_techs:
                        existing.ttps.append(t)
                        seen_techs.add(t.technique_id)
            if campaign and not existing.campaign:
                existing.campaign = campaign
            if evidence and evidence not in (existing.evidence_summary or ""):
                existing.evidence_summary = f"{existing.evidence_summary}; {evidence}"

            existing.confidence = compute_attribution_confidence(
                sources=existing.sources,
                has_ttps=bool(existing.ttps),
                has_cves=bool(existing.cves),
                has_actor=True,
            )
            existing.is_corroborated = len(set(s.lower() for s in existing.sources)) >= 2

    # Initial network model setup
    is_ip = root_type in (IOCType.IPV4, IOCType.IPV6)
    is_hash = root_type in (IOCType.MD5, IOCType.SHA1, IOCType.SHA256)

    agg_country: Optional[str] = None
    agg_country_code: Optional[str] = None
    agg_region: Optional[str] = None
    agg_city: Optional[str] = None
    agg_postal_code: Optional[str] = None
    agg_latitude: Optional[float] = None
    agg_longitude: Optional[float] = None
    agg_timezone: Optional[str] = None
    collected_geos: List[Tuple[str, GeoInfo]] = []

    # Cross-provider Threat Attribution Audit
    for res in provider_results:
        p_name = res.provider_name.lower()
        disp_p_name = PROVIDER_DISPLAY_NAMES.get(p_name, res.provider_name)
        if res.infrastructure:
            if _has_meaningful_infra(res.infrastructure):
                provider_contribs[res.provider_name] = res.infrastructure.model_copy(deep=True)
            for k, v in res.infrastructure.extra.items():
                if k not in aggregated.extra or not aggregated.extra[k]:
                    aggregated.extra[k] = v
                elif isinstance(v, dict) and isinstance(aggregated.extra.get(k), dict):
                    aggregated.extra[k].update(v)

        for mf in (res.malware_families or []):
            if mf:
                primary_actor = res.threat_actors[0] if (res.threat_actors and len(res.threat_actors) == 1) else None
                if is_cve_identifier(mf):
                    _merge_cve_attribution(mf, p_name, evidence=f"{disp_p_name} — vulnerability reference: \"{mf}\"")
                elif is_generic_malware_classification(mf) or is_av_signature(mf):
                    _merge_classification_attribution(mf, p_name, evidence=f"{disp_p_name} — provider classification: \"{mf}\"")
                else:
                    _merge_malware_attribution(mf, p_name, threat_actor=primary_actor, evidence=f"{disp_p_name} — malware family detection")
        for ta in (res.threat_actors or []):
            if ta:
                if not is_cve_identifier(ta) and not is_generic_malware_classification(ta):
                    _merge_actor_attribution(ta, p_name, evidence=f"{disp_p_name} — threat actor attribution")
        if res.infrastructure:
            for ta_obj in (res.infrastructure.threat_attributions or []):
                # Standalone Tool
                if ta_obj.entity_type == "tool" or (ta_obj.tool and not ta_obj.malware_family and not ta_obj.threat_actor):
                    tool_val = ta_obj.tool or ta_obj.canonical_name
                    if tool_val:
                        _merge_tool_attribution(
                            tool_raw=tool_val,
                            provider_name=p_name,
                            confidence=ta_obj.confidence,
                            evidence=ta_obj.evidence_summary or f"{disp_p_name} — tool association: \"{tool_val}\"",
                            threat_tags=ta_obj.threat_tags,
                            ttps=ta_obj.ttps,
                            cves=ta_obj.cves,
                            relationship_type=ta_obj.relationship_type,
                        )
                    continue

                # Standalone Threat Association
                if ta_obj.entity_type == "threat_association" or (ta_obj.threat_association and not ta_obj.malware_family and not ta_obj.threat_actor):
                    assoc_val = ta_obj.threat_association or ta_obj.canonical_name
                    if assoc_val:
                        _merge_threat_association_attribution(
                            assoc_raw=assoc_val,
                            provider_name=p_name,
                            confidence=ta_obj.confidence,
                            evidence=ta_obj.evidence_summary or f"{disp_p_name} — threat association: \"{assoc_val}\"",
                            threat_tags=ta_obj.threat_tags,
                            ttps=ta_obj.ttps,
                            cves=ta_obj.cves,
                            relationship_type=ta_obj.relationship_type,
                        )
                    continue

                # Standalone CVEs without malware family or threat actor
                if ta_obj.cves and not ta_obj.malware_family and not ta_obj.threat_actor and not ta_obj.detection_classification:
                    for cve_item in ta_obj.cves:
                        _merge_cve_attribution(
                            cve_raw=cve_item,
                            provider_name=p_name,
                            verdict=ta_obj.verdict,
                            confidence=ta_obj.confidence,
                            evidence=ta_obj.evidence_summary or f"{disp_p_name} — vulnerability reference: \"{cve_item}\"",
                            threat_tags=ta_obj.threat_tags,
                            ttps=ta_obj.ttps,
                        )

                # Malware family (with semantic validation)
                if ta_obj.malware_family:
                    if is_cve_identifier(ta_obj.malware_family):
                        _merge_cve_attribution(
                            cve_raw=ta_obj.malware_family,
                            provider_name=p_name,
                            verdict=ta_obj.verdict,
                            confidence=ta_obj.confidence,
                            evidence=ta_obj.evidence_summary or f"{disp_p_name} — Falcon Sandbox VX family: \"{ta_obj.malware_family.strip().upper()}\"",
                            threat_tags=ta_obj.threat_tags,
                            ttps=ta_obj.ttps,
                        )
                    elif is_generic_malware_classification(ta_obj.malware_family):
                        _merge_classification_attribution(
                            classification_raw=ta_obj.malware_family,
                            provider_name=p_name,
                            verdict=ta_obj.verdict,
                            confidence=ta_obj.confidence,
                            evidence=ta_obj.evidence_summary or f"{disp_p_name} provider classification '{ta_obj.malware_family}'",
                            threat_tags=ta_obj.threat_tags,
                            ttps=ta_obj.ttps,
                        )
                    else:
                        _merge_malware_attribution(
                            ta_obj.malware_family,
                            p_name,
                            confidence=ta_obj.confidence,
                            evidence=ta_obj.evidence_summary or f"{disp_p_name} — malware family detection",
                            malware_type=ta_obj.malware_type,
                            threat_tags=ta_obj.threat_tags,
                            ttps=ta_obj.ttps,
                            cves=ta_obj.cves,
                            campaign=ta_obj.campaign,
                            aliases=ta_obj.aliases,
                            threat_actor=ta_obj.threat_actor,
                            threat_actor_aliases=ta_obj.threat_actor_aliases,
                            verdict=ta_obj.verdict,
                            detection_classification=ta_obj.detection_classification,
                        )
                elif ta_obj.detection_classification:
                    _merge_classification_attribution(
                        classification_raw=ta_obj.detection_classification,
                        provider_name=p_name,
                        verdict=ta_obj.verdict,
                        confidence=ta_obj.confidence,
                        evidence=ta_obj.evidence_summary or f"{disp_p_name} provider classification '{ta_obj.detection_classification}'",
                        threat_tags=ta_obj.threat_tags,
                        ttps=ta_obj.ttps,
                    )

                if ta_obj.threat_actor and not ta_obj.malware_family:
                    _merge_actor_attribution(
                        ta_obj.threat_actor,
                        p_name,
                        confidence=ta_obj.confidence,
                        evidence=ta_obj.evidence_summary or f"{disp_p_name} — threat actor attribution",
                        threat_tags=ta_obj.threat_tags,
                        ttps=ta_obj.ttps,
                        cves=ta_obj.cves,
                        campaign=ta_obj.campaign,
                        threat_actor_aliases=ta_obj.threat_actor_aliases,
                    )

                if ta_obj.campaign and not ta_obj.malware_family and not ta_obj.threat_actor and not ta_obj.tool and not ta_obj.threat_association:
                    c_key = "campaign:" + re.sub(r'[^a-zA-Z0-9]', '', ta_obj.campaign).lower()
                    if c_key not in threat_attributions_by_key:
                        copy_ta = ta_obj.model_copy(deep=True)
                        copy_ta.canonical_name = copy_ta.canonical_name or ta_obj.campaign
                        copy_ta.entity_type = copy_ta.entity_type or "campaign"
                        threat_attributions_by_key[c_key] = copy_ta
                        if not any(s.lower() == disp_p_name.lower() for s in copy_ta.sources):
                            copy_ta.sources.append(disp_p_name)
                    else:
                        c_ex = threat_attributions_by_key[c_key]
                        if not any(s.lower() == disp_p_name.lower() for s in c_ex.sources):
                            c_ex.sources.append(disp_p_name)
                            c_ex.confidence = min(99.0, c_ex.confidence + 15.0)
                        c_ex.is_corroborated = len(set(s.lower() for s in c_ex.sources)) >= 2

            for pulse in (res.infrastructure.otx_pulses or []):
                pulse_cves = [t for t in (pulse.tags or []) if re.match(r'^CVE-\d{4}-\d+$', t, re.IGNORECASE)]
                pulse_ttps = [TTPTechnique(technique_id=tid, sources=["otx"]) for tid in (pulse.attack_ids or [])]
                p_families = [mf for mf in (pulse.malware_families or []) if mf and not is_cve_identifier(mf) and not is_generic_malware_classification(mf)]
                p_names = [mn for mn in (pulse.malware_names or []) if mn and not is_cve_identifier(mn) and not is_generic_malware_classification(mn)]

                # Explicit campaign only if specifically designated as a campaign by provider
                explicit_campaign = getattr(pulse, "campaign", None)

                # Merge explicit malware families individually — NEVER turn one into an alias of another!
                if p_families:
                    for fam in p_families:
                        _merge_malware_attribution(
                            fam,
                            "otx",
                            confidence=85.0 if pulse.adversary else 75.0,
                            evidence=f"OTX Pulse: \"{pulse.pulse_name}\"",
                            threat_tags=pulse.tags[:10],
                            ttps=pulse_ttps,
                            cves=pulse_cves,
                            campaign=explicit_campaign,
                            aliases=[],
                            threat_actor=pulse.adversary if pulse.adversary else None,
                        )
                elif p_names:
                    for name in p_names:
                        _merge_malware_attribution(
                            name,
                            "otx",
                            confidence=80.0 if pulse.adversary else 70.0,
                            evidence=f"OTX Pulse: \"{pulse.pulse_name}\"",
                            threat_tags=pulse.tags[:10],
                            ttps=pulse_ttps,
                            cves=pulse_cves,
                            campaign=explicit_campaign,
                            aliases=[],
                            threat_actor=pulse.adversary if pulse.adversary else None,
                        )
                elif pulse.adversary:
                    _merge_actor_attribution(
                        pulse.adversary,
                        "otx",
                        confidence=80.0,
                        evidence=f"OTX Pulse: \"{pulse.pulse_name}\" adversary",
                        threat_tags=pulse.tags[:10],
                        ttps=pulse_ttps,
                        cves=pulse_cves,
                        campaign=explicit_campaign,
                    )

    # 1. Ingest provider contributions
    for res in provider_results:
        if not res.infrastructure:
            continue

        infra = res.infrastructure
        if _has_meaningful_infra(infra):
            provider_contribs[res.provider_name] = infra
        p_name = res.provider_name.lower()

        # Ingest extra metadata (e.g. web-check, shodan, etc.)
        if infra.extra:
            for k, v in infra.extra.items():
                if k not in aggregated.extra:
                    aggregated.extra[k] = v
                elif isinstance(aggregated.extra[k], dict) and isinstance(v, dict):
                    aggregated.extra[k].update(v)

        # Collect and aggregate TTPs
        for ttp in (infra.ttps or []):
            tid = ttp.technique_id.strip().upper()
            if not tid:
                continue
            if tid not in ttps_by_id:
                ttps_by_id[tid] = ttp.model_copy(deep=True)
                if not ttps_by_id[tid].technique_name and tid in MITRE_ATTACK_NAMES:
                    ttps_by_id[tid].technique_name = MITRE_ATTACK_NAMES[tid]
            else:
                existing = ttps_by_id[tid]
                existing.sources = sorted(list(set(existing.sources + (ttp.sources or [p_name]))))
                if not existing.technique_name and ttp.technique_name:
                    existing.technique_name = ttp.technique_name
                if not existing.description and ttp.description:
                    existing.description = ttp.description
                if not existing.tactic and ttp.tactic:
                    existing.tactic = ttp.tactic
                if not existing.severity and ttp.severity:
                    existing.severity = ttp.severity

        if infra.file_metadata and infra.file_metadata.ttps:
            for ttp in infra.file_metadata.ttps:
                tid = ttp.technique_id.strip().upper()
                if not tid:
                    continue
                if tid not in ttps_by_id:
                    ttps_by_id[tid] = ttp.model_copy(deep=True)
                    if not ttps_by_id[tid].technique_name and tid in MITRE_ATTACK_NAMES:
                        ttps_by_id[tid].technique_name = MITRE_ATTACK_NAMES[tid]
                else:
                    existing = ttps_by_id[tid]
                    existing.sources = sorted(list(set(existing.sources + (ttp.sources or [p_name]))))
                    if not existing.technique_name and ttp.technique_name:
                        existing.technique_name = ttp.technique_name
                    if not existing.description and ttp.description:
                        existing.description = ttp.description
                    if not existing.tactic and ttp.tactic:
                        existing.tactic = ttp.tactic
                    if not existing.severity and ttp.severity:
                        existing.severity = ttp.severity

        # File metadata (Always relevant, especially for Hashes)
        if infra.file_type and not aggregated.file_type:
            aggregated.file_type = infra.file_type
        if infra.file_size and not aggregated.file_size:
            aggregated.file_size = infra.file_size
        if infra.file_metadata:
            if not aggregated.file_metadata:
                aggregated.file_metadata = infra.file_metadata.model_copy(deep=True)
            else:
                existing_fm = aggregated.file_metadata
                new_fm = infra.file_metadata
                existing_fm.sources = sorted(list(set(existing_fm.sources + (new_fm.sources or [p_name]))))
                for field_name in ["file_type", "magic", "file_size", "md5", "sha1", "sha256", "vhash", "authentihash", "imphash", "rich_pe_header_hash", "ssdeep", "tlsh", "detectiteasy", "magika", "pe_info", "compiler_info", "signature_info"]:
                    if not getattr(existing_fm, field_name) and getattr(new_fm, field_name):
                        setattr(existing_fm, field_name, getattr(new_fm, field_name))
                for fn in new_fm.file_names:
                    if fn not in existing_fm.file_names:
                        existing_fm.file_names.append(fn)
                for tr in new_fm.trid:
                    if tr not in existing_fm.trid:
                        existing_fm.trid.append(tr)
                for k, v in new_fm.timestamps.items():
                    if k not in existing_fm.timestamps:
                        existing_fm.timestamps[k] = v

        # Network/Host/Web infrastructure is strictly scoped to IP/Domain/URL IOCs, NEVER inherited by Hashes
        if not is_hash:
            # Merge scalar values if not already present
            if infra.asn and not aggregated.asn:
                aggregated.asn = infra.asn
            if infra.asn_name and not aggregated.asn_name:
                aggregated.asn_name = infra.asn_name
            if infra.org and not aggregated.org:
                aggregated.org = infra.org
            if infra.country and not aggregated.country:
                aggregated.country = infra.country
            if infra.region and not aggregated.region:
                aggregated.region = infra.region
            if infra.city and not aggregated.city:
                aggregated.city = infra.city
            if infra.cidr and not aggregated.cidr:
                aggregated.cidr = infra.cidr
            if infra.ptr and not aggregated.ptr:
                aggregated.ptr = infra.ptr
            if infra.registrar and not aggregated.registrar:
                aggregated.registrar = infra.registrar
            if infra.whois_creation and not aggregated.whois_creation:
                aggregated.whois_creation = infra.whois_creation
            if infra.whois_expiration and not aggregated.whois_expiration:
                aggregated.whois_expiration = infra.whois_expiration
            if infra.http_server and not aggregated.http_server:
                aggregated.http_server = infra.http_server
            if infra.http_title and not aggregated.http_title:
                aggregated.http_title = infra.http_title
            if infra.screenshot_url and not aggregated.screenshot_url:
                aggregated.screenshot_url = infra.screenshot_url

            # Collections
            for p in infra.open_ports:
                all_ports.add(p)
            for ns in infra.nameservers:
                all_nameservers.add(ns)
            for rec_type, values in infra.dns_records.items():
                if rec_type not in dns_records_merged:
                    dns_records_merged[rec_type] = set()
                for v in values:
                    dns_records_merged[rec_type].add(v)
            if infra.dns and infra.dns.records:
                for rec_item in infra.dns.records:
                    if rec_item.record_type and rec_item.value:
                        if rec_item.record_type not in dns_records_merged:
                            dns_records_merged[rec_item.record_type] = set()
                        dns_records_merged[rec_item.record_type].add(rec_item.value)

            # Structured Sub-models merging
            # Network
            if infra.network:
                if infra.network.asn or infra.network.org or infra.network.isp:
                    network_sources.update(infra.network.sources or [p_name])
                if not agg_bgp_prefix and infra.network.bgp_prefix:
                    agg_bgp_prefix = infra.network.bgp_prefix
                if not agg_isp and infra.network.isp:
                    agg_isp = infra.network.isp
            elif infra.asn or infra.org:
                network_sources.add(p_name)

            # Geo - Collect complete provider observation without field mixing
            prov_geo: Optional[GeoInfo] = None
            if infra.geo and (infra.geo.country or infra.geo.city or infra.geo.region or infra.geo.latitude is not None):
                prov_geo = infra.geo.model_copy(deep=True)
                if not prov_geo.sources:
                    prov_geo.sources = [p_name]
            elif infra.country or infra.city or infra.region:
                prov_geo = GeoInfo(
                    country=infra.country,
                    region=infra.region,
                    city=infra.city,
                    sources=[p_name],
                )
            if prov_geo:
                collected_geos.append((p_name, prov_geo))
                geo_sources.update(prov_geo.sources or [p_name])

            # DNS
            if infra.dns:
                for h in (infra.dns.hostnames or []):
                    if is_valid_hostname_or_domain(h):
                        all_hostnames.add(str(h).strip().lower().rstrip("."))
                for d in (infra.dns.domains or []):
                    if is_valid_hostname_or_domain(d):
                        all_domains.add(str(d).strip().lower().rstrip("."))
                dns_sources.update(infra.dns.sources or [p_name])

            # Whois
            if infra.whois:
                whois_sources.update(infra.whois.sources or [p_name])
                if not agg_whois_registrar and infra.whois.registrar:
                    agg_whois_registrar = infra.whois.registrar
                if not agg_whois_creation and infra.whois.creation_date:
                    agg_whois_creation = infra.whois.creation_date
                if not agg_whois_updated and infra.whois.updated_date:
                    agg_whois_updated = infra.whois.updated_date
                if not agg_whois_expiration and infra.whois.expiration_date:
                    agg_whois_expiration = infra.whois.expiration_date
                for s in (infra.whois.status or []):
                    if s not in agg_whois_status:
                        agg_whois_status.append(s)
                if not agg_whois_registrant_org and infra.whois.registrant_org:
                    agg_whois_registrant_org = infra.whois.registrant_org
                if not agg_whois_registrant_country and infra.whois.registrant_country:
                    agg_whois_registrant_country = infra.whois.registrant_country
                if not agg_whois_registrar_url and infra.whois.registrar_url:
                    agg_whois_registrar_url = infra.whois.registrar_url
                if not agg_whois_registrar_whois_server and infra.whois.registrar_whois_server:
                    agg_whois_registrar_whois_server = infra.whois.registrar_whois_server
                if not agg_whois_registry_domain_id and infra.whois.registry_domain_id:
                    agg_whois_registry_domain_id = infra.whois.registry_domain_id
                if not agg_whois_dnssec and infra.whois.dnssec:
                    agg_whois_dnssec = infra.whois.dnssec
            elif infra.registrar or infra.nameservers:
                whois_sources.add(p_name)

            # HTTP
            if infra.http:
                http_sources.update(infra.http.sources or [p_name])
                if infra.http.status_code is not None and agg_http_status is None:
                    agg_http_status = infra.http.status_code
                if infra.http.technologies:
                    all_technologies.update(infra.http.technologies)
                if infra.http.headers:
                    merged_headers.update(infra.http.headers)
            elif infra.http_server or infra.http_title or infra.screenshot_url:
                http_sources.add(p_name)

            # TLS
            if infra.tls:
                tls_sources.update(infra.tls.sources or [p_name])
                for v in (infra.tls.supported_versions or []):
                    all_tls_versions.add(v)
                for c in (infra.tls.ciphers or []):
                    all_tls_ciphers.add(c)
                if not agg_jarm and infra.tls.jarm:
                    agg_jarm = infra.tls.jarm
                if not agg_ja3s and getattr(infra.tls, 'ja3s', None):
                    agg_ja3s = infra.tls.ja3s
                elif not agg_ja3s and getattr(infra.tls, 'ja3', None):
                    agg_ja3s = infra.tls.ja3

            # Services Deduplication: Merge by (port, transport)
            for svc in infra.services_detail:
                key = (svc.port, svc.transport.lower())
                if key not in services_by_key:
                    services_by_key[key] = svc.model_copy(deep=True)
                else:
                    existing = services_by_key[key]
                    existing.sources = sorted(list(set(existing.sources + (svc.sources or [p_name]))))
                    if not existing.service_name and svc.service_name:
                        existing.service_name = svc.service_name
                    if not existing.product and svc.product:
                        existing.product = svc.product
                    if not existing.version and svc.version:
                        existing.version = svc.version
                    if not existing.vendor and svc.vendor:
                        existing.vendor = svc.vendor
                    if not existing.devicetype and svc.devicetype:
                        existing.devicetype = svc.devicetype
                    if existing.http_status is None and svc.http_status is not None:
                        existing.http_status = svc.http_status
                    if not existing.tls_version and svc.tls_version:
                        existing.tls_version = svc.tls_version
                    if not existing.cipher and svc.cipher:
                        existing.cipher = svc.cipher
                    if not existing.ja3s and svc.ja3s:
                        existing.ja3s = svc.ja3s
                    if not existing.jarm and svc.jarm:
                        existing.jarm = svc.jarm
                    for a in (svc.alpn or []):
                        if a not in existing.alpn:
                            existing.alpn.append(a)
                    if not existing.banner and svc.banner:
                        existing.banner = svc.banner
                    if not existing.http_title and svc.http_title:
                        existing.http_title = svc.http_title
                    if not existing.http_server and svc.http_server:
                        existing.http_server = svc.http_server
                    if not existing.scan_time and svc.scan_time:
                        existing.scan_time = svc.scan_time
                    for c in svc.cpe:
                        if c not in existing.cpe:
                            existing.cpe.append(c)
                    for v in svc.vulnerabilities:
                        if v not in existing.vulnerabilities:
                            existing.vulnerabilities.append(v)

            # Also merge legacy services if services_detail was not populated
            if not infra.services_detail and infra.services:
                for s in infra.services:
                    p = s.get("port")
                    if p:
                        key = (p, "tcp")
                        if key not in services_by_key:
                            services_by_key[key] = ServiceInfo(
                                port=p,
                                transport="tcp",
                                service_name=s.get("service_name"),
                                banner=s.get("banner"),
                                sources=[p_name],
                            )

            # Certificates Deduplication: Merge by fingerprint or serial
            for cert in infra.certificates_detail:
                fp_key = cert.fingerprint_sha256.lower() if cert.fingerprint_sha256 else (cert.serial_number or f"cert_{len(certs_by_fp)}")
                if fp_key not in certs_by_fp:
                    certs_by_fp[fp_key] = cert.model_copy(deep=True)
                else:
                    existing_cert = certs_by_fp[fp_key]
                    existing_cert.sources = sorted(list(set(existing_cert.sources + (cert.sources or [p_name]))))
                    for san in cert.sans:
                        if san not in existing_cert.sans:
                            existing_cert.sans.append(san)
                    if not existing_cert.subject_cn and cert.subject_cn:
                        existing_cert.subject_cn = cert.subject_cn
                    if not existing_cert.issuer_cn and cert.issuer_cn:
                        existing_cert.issuer_cn = cert.issuer_cn
                    if not existing_cert.subject_org and cert.subject_org:
                        existing_cert.subject_org = cert.subject_org
                    if not existing_cert.issuer_org and cert.issuer_org:
                        existing_cert.issuer_org = cert.issuer_org
                    if not existing_cert.valid_from and cert.valid_from:
                        existing_cert.valid_from = cert.valid_from
                    if not existing_cert.valid_to and cert.valid_to:
                        existing_cert.valid_to = cert.valid_to
                    if not existing_cert.serial_number and cert.serial_number:
                        existing_cert.serial_number = cert.serial_number
                    if not existing_cert.ja3s and cert.ja3s:
                        existing_cert.ja3s = cert.ja3s
                    if not existing_cert.jarm and cert.jarm:
                        existing_cert.jarm = cert.jarm
                    if not existing_cert.sig_alg and cert.sig_alg:
                        existing_cert.sig_alg = cert.sig_alg
                    for tv in cert.tls_versions:
                        if tv not in existing_cert.tls_versions:
                            existing_cert.tls_versions.append(tv)
                    for cp in cert.ciphers:
                        if cp not in existing_cert.ciphers:
                            existing_cert.ciphers.append(cp)

            # Also merge legacy certificates if certificates_detail was not populated
            if not infra.certificates_detail and infra.certificates:
                for c in infra.certificates:
                    fp = c.get("fingerprint")
                    if fp:
                        fp_key = fp.lower()
                        if fp_key not in certs_by_fp:
                            certs_by_fp[fp_key] = CertInfo(
                                fingerprint_sha256=fp,
                                sans=c.get("names", []),
                                sources=[p_name],
                            )

            # Vulnerabilities Deduplication: Merge by CVE ID
            for vuln in infra.vulnerabilities:
                cve_key = vuln.cve_id.upper()
                if cve_key not in vulns_by_id:
                    vulns_by_id[cve_key] = vuln.model_copy(deep=True)
                else:
                    existing_v = vulns_by_id[cve_key]
                    existing_v.sources = sorted(list(set(existing_v.sources + (vuln.sources or [p_name]))))
                    if existing_v.cvss is None and vuln.cvss is not None:
                        existing_v.cvss = vuln.cvss
                    if existing_v.cvss_v2 is None and vuln.cvss_v2 is not None:
                        existing_v.cvss_v2 = vuln.cvss_v2
                    if existing_v.cvss_v3 is None and vuln.cvss_v3 is not None:
                        existing_v.cvss_v3 = vuln.cvss_v3
                    if not existing_v.cwe_id and vuln.cwe_id:
                        existing_v.cwe_id = vuln.cwe_id
                    if not existing_v.severity and vuln.severity:
                        existing_v.severity = vuln.severity
                    if not existing_v.attack_vector and vuln.attack_vector:
                        existing_v.attack_vector = vuln.attack_vector
                    if not existing_v.affected_product and vuln.affected_product:
                        existing_v.affected_product = vuln.affected_product
                    if not existing_v.affected_vendor and vuln.affected_vendor:
                        existing_v.affected_vendor = vuln.affected_vendor
                    if not existing_v.port and vuln.port:
                        existing_v.port = vuln.port
                    if not existing_v.exploit and vuln.exploit:
                        existing_v.exploit = vuln.exploit
                    if not existing_v.exploit_details and vuln.exploit_details:
                        existing_v.exploit_details = vuln.exploit_details
                    if not existing_v.summary and vuln.summary:
                        existing_v.summary = vuln.summary
                    for r in vuln.references:
                        if r not in existing_v.references:
                            existing_v.references.append(r)
                    for c in (vuln.cpe or []):
                        if c not in existing_v.cpe:
                            existing_v.cpe.append(c)
                    for rp in (vuln.related_products or []):
                        if rp not in existing_v.related_products:
                            existing_v.related_products.append(rp)

            # IP Scoring Merging
            if infra.ip_scoring:
                if not aggregated.ip_scoring:
                    aggregated.ip_scoring = infra.ip_scoring.model_copy(deep=True)
                else:
                    ex_score = aggregated.ip_scoring
                    if not ex_score.inbound_score and infra.ip_scoring.inbound_score:
                        ex_score.inbound_score = infra.ip_scoring.inbound_score
                    if not ex_score.outbound_score and infra.ip_scoring.outbound_score:
                        ex_score.outbound_score = infra.ip_scoring.outbound_score
                    if ex_score.reputation_score is None and infra.ip_scoring.reputation_score is not None:
                        ex_score.reputation_score = infra.ip_scoring.reputation_score
                    if not ex_score.classification and infra.ip_scoring.classification:
                        ex_score.classification = infra.ip_scoring.classification
                    ex_score.critical_risk = ex_score.critical_risk or infra.ip_scoring.critical_risk
                    for ind in (infra.ip_scoring.abuse_indicators or []):
                        if ind not in ex_score.abuse_indicators:
                            ex_score.abuse_indicators.append(ind)
                    ex_score.sources = sorted(list(set(ex_score.sources + (infra.ip_scoring.sources or [p_name]))))

            # Detection Merging
            if infra.detection:
                if not aggregated.detection:
                    aggregated.detection = infra.detection.model_copy(deep=True)
                else:
                    ex_det = aggregated.detection
                    ex_det.is_vpn = ex_det.is_vpn or infra.detection.is_vpn
                    ex_det.is_tor = ex_det.is_tor or infra.detection.is_tor
                    ex_det.is_proxy = ex_det.is_proxy or infra.detection.is_proxy
                    ex_det.is_hosting = ex_det.is_hosting or infra.detection.is_hosting
                    ex_det.is_cloud = ex_det.is_cloud or infra.detection.is_cloud
                    ex_det.is_mobile = ex_det.is_mobile or infra.detection.is_mobile
                    ex_det.is_cdn = ex_det.is_cdn or infra.detection.is_cdn
                    ex_det.is_scanner = ex_det.is_scanner or infra.detection.is_scanner
                    ex_det.is_darkweb = ex_det.is_darkweb or infra.detection.is_darkweb
                    ex_det.is_snort = ex_det.is_snort or infra.detection.is_snort
                    ex_det.is_anonymous_vpn = ex_det.is_anonymous_vpn or infra.detection.is_anonymous_vpn
                    for vp in (infra.detection.vpn_providers or []):
                        if vp not in ex_det.vpn_providers:
                            ex_det.vpn_providers.append(vp)
                    for cat in (infra.detection.ip_categories or []):
                        if cat not in ex_det.ip_categories:
                            ex_det.ip_categories.append(cat)
                    for issue in (infra.detection.special_issues or []):
                        if issue not in ex_det.special_issues:
                            ex_det.special_issues.append(issue)
                    ex_det.sources = sorted(list(set(ex_det.sources + (infra.detection.sources or [p_name]))))

            # Security Indicators Merging
            if infra.security:
                if not aggregated.security:
                    aggregated.security = infra.security.model_copy(deep=True)
                else:
                    ex_sec = aggregated.security
                    ex_sec.abuse_record_count = max(ex_sec.abuse_record_count, infra.security.abuse_record_count)
                    ex_sec.user_search_count = max(ex_sec.user_search_count, infra.security.user_search_count)
                    ex_sec.honeypot_detected = ex_sec.honeypot_detected or infra.security.honeypot_detected
                    ex_sec.webcam_detected = ex_sec.webcam_detected or infra.security.webcam_detected
                    ex_sec.ids_alerts_count = max(ex_sec.ids_alerts_count, infra.security.ids_alerts_count)
                    ex_sec.invalid_ssl = ex_sec.invalid_ssl or infra.security.invalid_ssl
                    ex_sec.admin_page_detected = ex_sec.admin_page_detected or infra.security.admin_page_detected
                    for sig in (infra.security.ids_alert_signatures or []):
                        if sig not in ex_sec.ids_alert_signatures:
                            ex_sec.ids_alert_signatures.append(sig)
                    for pol in (infra.security.policy_violations or []):
                        if pol not in ex_sec.policy_violations:
                            ex_sec.policy_violations.append(pol)
                    ex_sec.sources = sorted(list(set(ex_sec.sources + (infra.security.sources or [p_name]))))

            # Temporal
            if infra.temporal:
                temporal_sources.update(infra.temporal.sources or [p_name])
                if not aggregated.temporal:
                    aggregated.temporal = infra.temporal.model_copy(deep=True)
                else:
                    if infra.temporal.first_seen and (not aggregated.temporal.first_seen or str(infra.temporal.first_seen) < str(aggregated.temporal.first_seen)):
                        aggregated.temporal.first_seen = infra.temporal.first_seen
                    if infra.temporal.last_seen and (not aggregated.temporal.last_seen or str(infra.temporal.last_seen) > str(aggregated.temporal.last_seen)):
                        aggregated.temporal.last_seen = infra.temporal.last_seen
                    if infra.temporal.last_scan and not aggregated.temporal.last_scan:
                        aggregated.temporal.last_scan = infra.temporal.last_scan

            # Shodan details
            if infra.shodan_details:
                if not aggregated.shodan_details:
                    aggregated.shodan_details = infra.shodan_details.model_copy(deep=True)
                else:
                    ex_sho = aggregated.shodan_details
                    if not ex_sho.os and infra.shodan_details.os:
                        ex_sho.os = infra.shodan_details.os
                    if not ex_sho.device_type and infra.shodan_details.device_type:
                        ex_sho.device_type = infra.shodan_details.device_type
                    ex_sho.total_ports = max(ex_sho.total_ports, infra.shodan_details.total_ports)
                    ex_sho.services_count = max(ex_sho.services_count, infra.shodan_details.services_count)
                    ex_sho.total_vulns = max(ex_sho.total_vulns, infra.shodan_details.total_vulns)
                    for t in (infra.shodan_details.tags or []):
                        if t not in ex_sho.tags:
                            ex_sho.tags.append(t)
                    for d in (infra.shodan_details.domains or []):
                        if d not in ex_sho.domains:
                            ex_sho.domains.append(d)
                    for h in (infra.shodan_details.hostnames or []):
                        if h not in ex_sho.hostnames:
                            ex_sho.hostnames.append(h)
                    if not ex_sho.last_update and infra.shodan_details.last_update:
                        ex_sho.last_update = infra.shodan_details.last_update
                    if not ex_sho.asn and infra.shodan_details.asn:
                        ex_sho.asn = infra.shodan_details.asn
                    if not ex_sho.isp and infra.shodan_details.isp:
                        ex_sho.isp = infra.shodan_details.isp
                    if not ex_sho.org and infra.shodan_details.org:
                        ex_sho.org = infra.shodan_details.org
                    if not ex_sho.city and infra.shodan_details.city:
                        ex_sho.city = infra.shodan_details.city
                    if not ex_sho.country and infra.shodan_details.country:
                        ex_sho.country = infra.shodan_details.country
                    if ex_sho.latitude is None and infra.shodan_details.latitude is not None:
                        ex_sho.latitude = infra.shodan_details.latitude
                    if ex_sho.longitude is None and infra.shodan_details.longitude is not None:
                        ex_sho.longitude = infra.shodan_details.longitude

            # Censys details
            if infra.censys_details:
                if not aggregated.censys_details:
                    aggregated.censys_details = infra.censys_details.model_copy(deep=True)
                else:
                    ex_cen = aggregated.censys_details
                    if not ex_cen.os and infra.censys_details.os:
                        ex_cen.os = infra.censys_details.os
                    ex_cen.service_count = max(ex_cen.service_count, infra.censys_details.service_count)
                    ex_cen.total_vulns = max(ex_cen.total_vulns, infra.censys_details.total_vulns)
                    for lbl in (infra.censys_details.host_labels or []):
                        if lbl not in ex_cen.host_labels:
                            ex_cen.host_labels.append(lbl)
                    for d in (infra.censys_details.dns_names or []):
                        if d not in ex_cen.dns_names:
                            ex_cen.dns_names.append(d)
                    if not ex_cen.bgp_prefix and infra.censys_details.bgp_prefix:
                        ex_cen.bgp_prefix = infra.censys_details.bgp_prefix
                    if not ex_cen.last_observed_at and infra.censys_details.last_observed_at:
                        ex_cen.last_observed_at = infra.censys_details.last_observed_at
                    if infra.censys_details.web_properties and not ex_cen.web_properties:
                        ex_cen.web_properties = infra.censys_details.web_properties

    # 2. IOC-Specific Live Authoritative Infrastructure Enrichment (STRICTLY for IP / Domain, NEVER for Hash)
    if is_ip and not is_hash:
        auth_ptr = None
        try:
            import socket
            ptr_name, _, _ = socket.gethostbyaddr(root_ioc)
            if ptr_name and ptr_name != root_ioc:
                auth_ptr = ptr_name
        except Exception:
            pass

        # Query DNS-over-HTTPS for authoritative PTR record
        if not auth_ptr:
            try:
                import httpx
                parts = root_ioc.split(".")
                if len(parts) == 4:
                    rev_name = f"{parts[3]}.{parts[2]}.{parts[1]}.{parts[0]}.in-addr.arpa"
                    doh_resp = httpx.get(f"https://dns.google/resolve?name={rev_name}&type=PTR", timeout=3.0)
                    if doh_resp.status_code == 200:
                        doh_data = doh_resp.json()
                        answers = doh_data.get("Answer", [])
                        if answers and answers[0].get("data"):
                            auth_ptr = answers[0]["data"].rstrip(".")
            except Exception:
                pass

        if auth_ptr:
            aggregated.ptr = auth_ptr
            all_hostnames.add(auth_ptr)
            dns_sources.add("dns")

        # If ASN or ASN name is missing from provider results, enrich via live public IP intelligence (ipinfo.io / RIR)
        if (not aggregated.asn or not aggregated.asn_name) and not collected_geos:
            try:
                import httpx
                resp = httpx.get(f"https://ipinfo.io/{root_ioc}/json", timeout=2.5)
                if resp.status_code == 200:
                    info = resp.json()
                    if not info.get("bogon"):
                        org_str = info.get("org", "")
                        if org_str and org_str.startswith("AS"):
                            parts = org_str.split(" ", 1)
                            if not aggregated.asn:
                                aggregated.asn = parts[0]
                            if not aggregated.asn_name and len(parts) > 1:
                                aggregated.asn_name = parts[1]
                        elif org_str and not aggregated.asn_name:
                            aggregated.asn_name = org_str
                        if not agg_country and info.get("country"):
                            agg_country = info.get("country")
                            aggregated.country = info.get("country")
                        if not agg_city and info.get("city"):
                            agg_city = info.get("city")
                            aggregated.city = info.get("city")
                        if not agg_region and info.get("region"):
                            agg_region = info.get("region")
                            aggregated.region = info.get("region")
                        if not aggregated.ptr and info.get("hostname"):
                            h_val = str(info["hostname"]).strip()
                            if is_valid_hostname_or_domain(h_val) and not _is_ip_str(h_val):
                                aggregated.ptr = h_val
                                all_hostnames.add(h_val)
                        ip_lat = None
                        ip_lon = None
                        if info.get("loc"):
                            try:
                                lat_s, lon_s = info["loc"].split(",", 1)
                                ip_lat = float(lat_s)
                                ip_lon = float(lon_s)
                            except Exception:
                                pass
                        if info.get("country") or info.get("city"):
                            collected_geos.append(("ipinfo", GeoInfo(
                                country=info.get("country"),
                                region=info.get("region"),
                                city=info.get("city"),
                                latitude=ip_lat,
                                longitude=ip_lon,
                                timezone=info.get("timezone"),
                                sources=["ipinfo"],
                            )))
                        network_sources.add("ipinfo")
                        geo_sources.add("ipinfo")
            except Exception:
                pass

    if root_type in (IOCType.DOMAIN, IOCType.URL) and not is_hash:
        target_domain = root_ioc
        if root_type == IOCType.URL:
            import urllib.parse
            try:
                parsed = urllib.parse.urlparse(root_ioc)
                target_domain = parsed.netloc or parsed.path.split("/")[0]
                if ":" in target_domain:
                    target_domain = target_domain.split(":")[0]
                if target_domain and is_valid_hostname_or_domain(target_domain) and not _is_ip_str(target_domain):
                    all_hostnames.add(target_domain)
                    all_domains.add(target_domain)
                    dns_sources.add("url_parsing")
            except Exception:
                target_domain = ""

        if target_domain and not dns_records_merged.get("A"):
            try:
                import socket
                _, _, ips = socket.gethostbyname_ex(target_domain)
                if ips:
                    dns_records_merged["A"] = set(ips)
                    dns_sources.add("dns")
            except Exception:
                pass

        if target_domain and (not aggregated.asn or not aggregated.asn_name or not collected_geos) and dns_records_merged.get("A"):
            try:
                first_ip = list(dns_records_merged["A"])[0]
                import httpx
                resp = httpx.get(f"https://ipinfo.io/{first_ip}/json", timeout=2.5)
                if resp.status_code == 200:
                    info = resp.json()
                    if not info.get("bogon"):
                        org_str = info.get("org", "")
                        if org_str and org_str.startswith("AS"):
                            parts = org_str.split(" ", 1)
                            if not aggregated.asn:
                                aggregated.asn = parts[0]
                            if not aggregated.asn_name and len(parts) > 1:
                                aggregated.asn_name = parts[1]
                        elif org_str and not aggregated.asn_name:
                            aggregated.asn_name = org_str
                        ip_lat = None
                        ip_lon = None
                        if info.get("loc"):
                            try:
                                lat_s, lon_s = info["loc"].split(",", 1)
                                ip_lat = float(lat_s)
                                ip_lon = float(lon_s)
                            except Exception:
                                pass
                        if info.get("country") or info.get("city"):
                            collected_geos.append(("ipinfo", GeoInfo(
                                country=info.get("country"),
                                region=info.get("region"),
                                city=info.get("city"),
                                latitude=ip_lat,
                                longitude=ip_lon,
                                timezone=info.get("timezone"),
                                sources=["ipinfo"],
                            )))
                        network_sources.add("ipinfo")
                        geo_sources.add("ipinfo")
            except Exception:
                pass

    # 3. Finalize Aggregated Structured Collections
    for p in all_ports:
        key = (p, "tcp")
        if key not in services_by_key:
            p_sources = [
                res.provider_name.lower()
                for res in provider_results
                if res.infrastructure and (
                    p in (res.infrastructure.open_ports or [])
                    or any(s.get("port") == p for s in (res.infrastructure.services or []))
                )
            ]
            services_by_key[key] = ServiceInfo(
                port=p,
                transport="tcp",
                service_name="open-port",
                sources=sorted(list(set(p_sources))) if p_sources else ["provider"],
            )

    # Synthesize any service-level vulnerabilities or provider extras into vulns_by_id
    for svc in services_by_key.values():
        for cve_raw in (svc.vulnerabilities or []):
            cve_clean = cve_raw.strip().upper()
            if is_cve_identifier(cve_clean) and cve_clean not in vulns_by_id:
                vulns_by_id[cve_clean] = VulnInfo(
                    cve_id=cve_clean,
                    port=svc.port,
                    affected_product=svc.product,
                    affected_vendor=svc.vendor,
                    sources=svc.sources or ["active_scanner"],
                )

    for res in provider_results:
        p_name = res.provider_name.lower()
        if res.infrastructure and res.infrastructure.extra:
            sho_vulns = res.infrastructure.extra.get("shodan", {}).get("vulns") or res.infrastructure.extra.get("vulns")
            if isinstance(sho_vulns, list):
                for cve_raw in sho_vulns:
                    if isinstance(cve_raw, str):
                        cve_clean = cve_raw.strip().upper()
                        if is_cve_identifier(cve_clean) and cve_clean not in vulns_by_id:
                            vulns_by_id[cve_clean] = VulnInfo(
                                cve_id=cve_clean,
                                sources=[p_name],
                            )
            cen_vulns = res.infrastructure.extra.get("censys", {}).get("vulns") or res.infrastructure.extra.get("censys_vulns")
            if isinstance(cen_vulns, list):
                for cve_raw in cen_vulns:
                    if isinstance(cve_raw, str):
                        cve_clean = cve_raw.strip().upper()
                        if is_cve_identifier(cve_clean) and cve_clean not in vulns_by_id:
                            vulns_by_id[cve_clean] = VulnInfo(
                                cve_id=cve_clean,
                                sources=[p_name],
                            )

    sorted_services = sorted(services_by_key.values(), key=lambda s: (s.port, s.transport))
    sorted_certs = list(certs_by_fp.values())
    sorted_vulns = sorted(vulns_by_id.values(), key=lambda v: (-(v.cvss or 0.0), v.cve_id))

    aggregated.open_ports = sorted(list(all_ports))
    aggregated.nameservers = sorted(list(all_nameservers))
    aggregated.dns_records = {k: sorted(list(v)) for k, v in dns_records_merged.items()}
    aggregated.services = [
        {
            "port": s.port,
            "transport": s.transport,
            "protocol": s.protocol,
            "service_name": s.service_name or s.product or "unknown",
            "banner": (s.banner or "")[:120],
            "sources": s.sources,
        }
        for s in sorted_services
    ]
    aggregated.certificates = [
        {"fingerprint": c.fingerprint_sha256, "names": c.sans if c.sans else ([c.subject_cn] if c.subject_cn else [])}
        for c in sorted_certs
    ]
    aggregated.services_detail = sorted_services
    aggregated.certificates_detail = sorted_certs
    aggregated.vulnerabilities = sorted_vulns

    if aggregated.security:
        aggregated.security.open_ports_count = len(aggregated.open_ports)
        aggregated.security.vulnerabilities_count = len(aggregated.vulnerabilities)

    # Finalize Network Model with Provenance
    if not is_hash and (is_ip or aggregated.asn or aggregated.org or aggregated.ptr or agg_bgp_prefix or agg_isp):
        aggregated.network = NetworkInfo(
            ip=root_ioc if is_ip else None,
            ip_version="IPv4" if root_type == IOCType.IPV4 else ("IPv6" if root_type == IOCType.IPV6 else None),
            asn=aggregated.asn,
            asn_name=aggregated.asn_name,
            cidr=aggregated.cidr,
            bgp_prefix=agg_bgp_prefix,
            isp=agg_isp,
            org=aggregated.org,
            ptr=aggregated.ptr,
            sources=sorted(list(network_sources)) if network_sources else (["authoritative"] if is_ip else []),
        )

    # Finalize Geo Model with Provenance & Alternative Observations (Strictly provider-consistent, zero field mixing)
    if not is_hash and collected_geos:
        provider_rank = {
            "censys": 10,
            "shodan": 9,
            "criminalip": 8,
            "ipinfo": 7,
            "ipqualityscore": 6,
            "virustotal": 5,
            "webcheck": 4,
            "abuseipdb": 3,
        }

        def _geo_score(item: Tuple[str, GeoInfo]) -> int:
            prov, g = item
            score = 0
            if g.latitude is not None and g.longitude is not None:
                score += 40
            if g.city:
                score += 30
            if g.region:
                score += 20
            if g.country or g.country_code:
                score += 10
            score += provider_rank.get(prov.lower(), 1)
            return score

        sorted_geos = sorted(collected_geos, key=_geo_score, reverse=True)
        primary_prov, best_geo = sorted_geos[0]

        # Use best_geo as authoritative self-consistent primary location
        aggregated.geo = best_geo.model_copy(deep=True)
        aggregated.country = best_geo.country
        aggregated.city = best_geo.city
        aggregated.region = best_geo.region

        # Collect distinct alternative observations to preserve provider contradictions (e.g. Anycast/Cloudflare)
        def _loc_key(g: GeoInfo) -> Tuple[Any, ...]:
            lat_r = round(g.latitude, 2) if g.latitude is not None else None
            lon_r = round(g.longitude, 2) if g.longitude is not None else None
            return (
                (g.country or "").strip().lower(),
                (g.region or "").strip().lower(),
                (g.city or "").strip().lower(),
                lat_r,
                lon_r,
            )

        seen_locations = {_loc_key(best_geo)}
        alt_geos: List[GeoInfo] = []

        for prov, g in sorted_geos[1:]:
            k = _loc_key(g)
            if k not in seen_locations:
                seen_locations.add(k)
                alt_g = g.model_copy(deep=True)
                if not alt_g.sources:
                    alt_g.sources = [prov]
                alt_geos.append(alt_g)
            else:
                if k == _loc_key(best_geo):
                    if prov not in (aggregated.geo.sources or []):
                        aggregated.geo.sources = sorted(list(set((aggregated.geo.sources or []) + [prov])))
                else:
                    for ex in alt_geos:
                        if _loc_key(ex) == k and prov not in (ex.sources or []):
                            ex.sources = sorted(list(set((ex.sources or []) + [prov])))

        aggregated.alternative_geolocations = alt_geos
    elif not is_hash and (agg_continent or agg_country or agg_city or agg_region or agg_latitude is not None or aggregated.country or aggregated.city or aggregated.region):
        aggregated.geo = GeoInfo(
            continent=agg_continent,
            country=agg_country or aggregated.country,
            country_code=agg_country_code,
            region=agg_region or aggregated.region,
            city=agg_city or aggregated.city,
            postal_code=agg_postal_code,
            latitude=agg_latitude,
            longitude=agg_longitude,
            timezone=agg_timezone,
            sources=sorted(list(geo_sources)) if geo_sources else ["authoritative"],
        )

    # Finalize DNS Model with Provenance
    dns_record_items = []
    for rtype, rvals in aggregated.dns_records.items():
        for rval in rvals:
            dns_record_items.append(DnsRecordItem(record_type=rtype, value=rval, sources=sorted(list(dns_sources))))

    if not is_hash and (all_hostnames or all_domains or dns_record_items):
        aggregated.dns = DnsInfo(
            hostnames=sorted(list(all_hostnames)),
            domains=sorted(list(all_domains)),
            records=dns_record_items,
            sources=sorted(list(dns_sources)) if dns_sources else ["dns"],
        )

    # Synchronize DNS MX records into Mail Security configuration to prevent MX contradictions
    mx_records = aggregated.dns_records.get("MX") or []
    if mx_records:
        webcheck_data = aggregated.extra.setdefault("webcheck", {})
        mail_cfg = webcheck_data.setdefault("mail-config", {})
        existing_mx = mail_cfg.get("mx") or []
        if not existing_mx:
            parsed_mx_list = []
            for rec in mx_records:
                parts = str(rec).strip().split()
                if len(parts) >= 2 and parts[0].isdigit():
                    parsed_mx_list.append({"exchange": parts[1].rstrip("."), "priority": int(parts[0])})
                elif len(parts) == 1:
                    parsed_mx_list.append({"exchange": parts[0].rstrip("."), "priority": 10})
                else:
                    parsed_mx_list.append({"exchange": str(rec).strip().rstrip("."), "priority": 10})
            mail_cfg["mx"] = parsed_mx_list

    # Finalize WHOIS Model with Provenance
    if not is_hash and (aggregated.registrar or aggregated.whois_creation or aggregated.whois_expiration or aggregated.nameservers or agg_whois_registrar or agg_whois_creation or agg_whois_expiration):
        aggregated.whois = WhoisInfo(
            registrar=agg_whois_registrar or aggregated.registrar,
            creation_date=agg_whois_creation or aggregated.whois_creation,
            updated_date=agg_whois_updated,
            expiration_date=agg_whois_expiration or aggregated.whois_expiration,
            nameservers=aggregated.nameservers,
            status=agg_whois_status,
            registrant_org=agg_whois_registrant_org,
            registrant_country=agg_whois_registrant_country,
            registrar_url=agg_whois_registrar_url,
            registrar_whois_server=agg_whois_registrar_whois_server,
            registry_domain_id=agg_whois_registry_domain_id,
            dnssec=agg_whois_dnssec,
            sources=sorted(list(whois_sources)) if whois_sources else ["rdap"],
        )

    # Finalize HTTP Model with Provenance
    if not is_hash and (aggregated.http_server or aggregated.http_title or aggregated.screenshot_url or all_technologies or merged_headers or agg_http_status is not None):
        aggregated.http = HttpInfo(
            server=aggregated.http_server,
            title=aggregated.http_title,
            status_code=agg_http_status,
            screenshot_url=aggregated.screenshot_url,
            technologies=sorted(list(all_technologies)),
            headers=merged_headers or {},
            sources=sorted(list(http_sources)) if http_sources else ["http"],
        )

    # Finalize TLS Model with Provenance
    if not is_hash and (all_tls_versions or all_tls_ciphers or agg_jarm or agg_ja3s):
        aggregated.tls = TlsInfo(
            supported_versions=sorted(list(all_tls_versions)),
            ciphers=sorted(list(all_tls_ciphers)),
            jarm=agg_jarm,
            ja3s=agg_ja3s,
            sources=sorted(list(tls_sources)) if tls_sources else ["tls"],
        )

    # Finalize Security Headers Analysis
    if not is_hash:
        sec_headers_candidates = [
            res.infrastructure.security_headers
            for res in provider_results
            if res.infrastructure and res.infrastructure.security_headers
        ]
        if sec_headers_candidates:
            aggregated.security_headers = sec_headers_candidates[0]
        elif aggregated.extra.get("webcheck") or merged_headers:
            wb_data = dict(aggregated.extra.get("webcheck") or {})
            if merged_headers and "headers" not in wb_data:
                wb_data["headers"] = merged_headers
            aggregated.security_headers = normalize_security_headers(
                wb_data,
                sources=["webcheck"] if aggregated.extra.get("webcheck") else ["http"],
            )

    # Finalize Temporal Model with Provenance
    if not aggregated.temporal and temporal_sources:
        aggregated.temporal = TemporalInfo(sources=sorted(list(temporal_sources)))
    elif aggregated.temporal and temporal_sources:
        aggregated.temporal.sources = sorted(list(set(aggregated.temporal.sources + list(temporal_sources))))

    # Finalize TTPs
    sorted_ttps = sorted(list(ttps_by_id.values()), key=lambda t: t.technique_id)
    aggregated.ttps = sorted_ttps
    if aggregated.file_metadata:
        aggregated.file_metadata.ttps = sorted_ttps

    # Finalize OTX Pulses
    all_pulses: List[PulseMetadata] = []
    seen_pulse_ids = set()
    for res in provider_results:
        if res.infrastructure and res.infrastructure.otx_pulses:
            for p in res.infrastructure.otx_pulses:
                if p.pulse_id not in seen_pulse_ids:
                    seen_pulse_ids.add(p.pulse_id)
                    all_pulses.append(p)
    aggregated.otx_pulses = all_pulses

    # Cross-link threat actor and malware family if they share the exact same campaign
    campaign_actors: Dict[str, str] = {}
    for k, a in list(threat_attributions_by_key.items()):
        if a.threat_actor and a.campaign and not a.malware_family:
            c_norm = re.sub(r'[^a-zA-Z0-9]', '', a.campaign).lower()
            if c_norm:
                campaign_actors[c_norm] = a.threat_actor

    for k, a in list(threat_attributions_by_key.items()):
        if a.malware_family and a.campaign and not a.threat_actor:
            c_norm = re.sub(r'[^a-zA-Z0-9]', '', a.campaign).lower()
            if c_norm in campaign_actors:
                a.threat_actor = campaign_actors[c_norm]

    # Remove standalone actor entry if its actor is represented in a malware family entry
    for k, a in list(threat_attributions_by_key.items()):
        if a.threat_actor and not a.malware_family:
            actor_norm = a.threat_actor.strip().lower()
            c_norm = re.sub(r'[^a-zA-Z0-9]', '', a.campaign).lower() if a.campaign else None
            # Look for a malware family entry that has this threat actor or shares the campaign
            matching_family = None
            for other in threat_attributions_by_key.values():
                if not other.malware_family:
                    continue
                other_actor_norm = other.threat_actor.strip().lower() if other.threat_actor else None
                other_c_norm = re.sub(r'[^a-zA-Z0-9]', '', other.campaign).lower() if other.campaign else None
                if (other_actor_norm and (other_actor_norm == actor_norm or actor_norm in other_actor_norm or other_actor_norm in actor_norm)) or (c_norm and other_c_norm and c_norm == other_c_norm):
                    matching_family = other
                    break

            if matching_family:
                if not matching_family.threat_actor:
                    matching_family.threat_actor = a.threat_actor
                for alias in (a.threat_actor_aliases or []):
                    if alias not in matching_family.threat_actor_aliases:
                        matching_family.threat_actor_aliases.append(alias)
                for s in a.sources:
                    if s not in matching_family.sources:
                        matching_family.sources.append(s)
                if a.evidence_summary and a.evidence_summary not in (matching_family.evidence_summary or ''):
                    matching_family.evidence_summary = f"{matching_family.evidence_summary}; {a.evidence_summary}" if matching_family.evidence_summary else a.evidence_summary
                if a.confidence > matching_family.confidence:
                    matching_family.confidence = a.confidence
                del threat_attributions_by_key[k]

    # Finalize Threat Attribution
    sorted_attributions = sorted(
        threat_attributions_by_key.values(),
        key=lambda a: (len(a.sources), a.confidence),
        reverse=True,
    )
    aggregated.threat_attributions = sorted_attributions
    if sorted_attributions:
        aggregated.threat_attribution = sorted_attributions[0]

    # Finalize Passive DNS Records
    all_pdns: List[PassiveDnsRecord] = []
    seen_pdns_keys = set()
    for res in provider_results:
        if res.infrastructure and res.infrastructure.passive_dns:
            for rec in res.infrastructure.passive_dns:
                key = (rec.query.lower(), rec.answer.lower(), rec.rrtype.upper())
                if key not in seen_pdns_keys:
                    seen_pdns_keys.add(key)
                    all_pdns.append(rec)
                else:
                    existing_rec = next((r for r in all_pdns if (r.query.lower(), r.answer.lower(), r.rrtype.upper()) == key), None)
                    if existing_rec:
                        for s in rec.sources:
                            if s not in existing_rec.sources:
                                existing_rec.sources.append(s)

    all_pdns.sort(key=lambda r: (r.last_seen_timestamp or 0, r.last_seen or ""), reverse=True)
    aggregated.passive_dns = all_pdns

    # Finalize Hierarchical MITRE ATT&CK Model
    ttp_hierarchy = build_ttp_hierarchy(sorted_ttps, sorted_attributions)
    aggregated.ttp_hierarchy = ttp_hierarchy

    # Finalize Historical WHOIS Records
    all_hw: List[HistoricalWhoisRecord] = []
    seen_hw_keys = set()
    for res in provider_results:
        if res.infrastructure and res.infrastructure.historical_whois:
            for hw in res.infrastructure.historical_whois:
                key = (hw.id or "", hw.first_seen or "", hw.registrar or "")
                if key not in seen_hw_keys:
                    seen_hw_keys.add(key)
                    all_hw.append(hw)
                else:
                    existing_hw = next((h for h in all_hw if (h.id or "", h.first_seen or "", h.registrar or "") == key), None)
                    if existing_hw:
                        for s in hw.sources:
                            if s not in existing_hw.sources:
                                existing_hw.sources.append(s)

    all_hw.sort(key=lambda r: (r.first_seen_timestamp or 0, r.first_seen or ""), reverse=True)
    aggregated.historical_whois = all_hw

    return Layer2InfrastructureResponse(
        root_ioc=root_ioc,
        root_type=root_type,
        aggregated_infrastructure=aggregated,
        provider_contributions=provider_contribs,
        ttps=sorted_ttps,
        otx_pulses=all_pulses,
        passive_dns=all_pdns,
        ttp_hierarchy=ttp_hierarchy,
        historical_whois=all_hw,
    )


def build_layer3_buckets(discovered_iocs: List[CanonicalIOCResponse]) -> Layer3DiscoveredIOCsResponse:
    """
    Groups discovered IOCs strictly into the 3 mandated Layer 3 buckets:
    1. Hashes (MD5, SHA1, SHA256)
    2. IPs (IPv4, IPv6)
    3. URLs & Domains (Domain, URL)
    """
    hashes: List[CanonicalIOCResponse] = []
    ips: List[CanonicalIOCResponse] = []
    urls_and_domains: List[CanonicalIOCResponse] = []

    for item in discovered_iocs:
        if item.ioc_type in (IOCType.MD5, IOCType.SHA1, IOCType.SHA256):
            hashes.append(item)
        elif item.ioc_type in (IOCType.IPV4, IOCType.IPV6):
            ips.append(item)
        elif item.ioc_type in (IOCType.DOMAIN, IOCType.URL):
            urls_and_domains.append(item)

    return Layer3DiscoveredIOCsResponse(
        hashes=hashes,
        ips=ips,
        urls_and_domains=urls_and_domains,
        total_count=len(discovered_iocs),
    )


def attach_infrastructure_iocs(
    root_canonical: str,
    root_type: IOCType,
    layer2: Layer2InfrastructureResponse,
    existing_iocs: List[CanonicalIOCResponse],
    existing_relationships: List[RelationshipResponse],
    current_depth: int = 1,
) -> Tuple[List[CanonicalIOCResponse], List[RelationshipResponse]]:
    """
    Extracts high-confidence dynamically resolved network infrastructure (PTR reverse DNS,
    DNS A / AAAA records) into canonical IOCs and relationships for Layer 3 and the Threat Graph.
    """
    import uuid

    iocs = list(existing_iocs)
    rels = list(existing_relationships)

    ioc_keys = {(i.canonical_value, i.ioc_type.value) for i in iocs}
    rel_dict: Dict[Tuple[str, str], RelationshipResponse] = {(r.source_value, r.target_value): r for r in rels}

    infra = layer2.aggregated_infrastructure
    if not infra or root_type in (IOCType.MD5, IOCType.SHA1, IOCType.SHA256):
        return iocs, rels

    # 0. URL -> Domain (hosted_on)
    if root_type == IOCType.URL:
        import urllib.parse
        try:
            parsed = urllib.parse.urlparse(root_canonical)
            url_host = parsed.netloc or parsed.path.split("/")[0]
            if ":" in url_host:
                url_host = url_host.split(":")[0]
            if url_host:
                norm_host = normalize_ioc(url_host, IOCType.DOMAIN)
                if norm_host.is_valid and norm_host.canonical_value:
                    host_val = norm_host.canonical_value
                    if (host_val, IOCType.DOMAIN.value) not in ioc_keys:
                        ioc_keys.add((host_val, IOCType.DOMAIN.value))
                        iocs.append(
                            CanonicalIOCResponse(
                                id=str(uuid.uuid4()),
                                canonical_value=host_val,
                                ioc_type=IOCType.DOMAIN,
                                is_root=False,
                                depth=current_depth,
                                confidence=95.0,
                                metadata={"source": "url_parsing", "description": f"Domain host for {root_canonical}"},
                                relationships=["hosted_on"],
                                providers=["dns"],
                            )
                        )
                    rel_key = (root_canonical, host_val)
                    if rel_key not in rel_dict:
                        new_rel = RelationshipResponse(
                            id=str(uuid.uuid4()),
                            source_value=root_canonical,
                            source_type=root_type.value,
                            target_value=host_val,
                            target_type=IOCType.DOMAIN.value,
                            relationship_type="hosted_on",
                            confidence=95.0,
                            providers=["dns"],
                            evidence_count=1,
                            evidence_summary=f"URL hosted on domain {host_val}",
                            depth=current_depth,
                        )
                        rels.append(new_rel)
                        rel_dict[rel_key] = new_rel
        except Exception:
            pass

    # 1. Reverse DNS (PTR) -> Domain
    if infra.ptr and is_valid_hostname_or_domain(infra.ptr) and not _is_ip_str(infra.ptr):
        norm_ptr = normalize_ioc(infra.ptr, IOCType.DOMAIN)
        if norm_ptr.is_valid and norm_ptr.canonical_value and norm_ptr.canonical_value != root_canonical:
            ptr_val = norm_ptr.canonical_value
            ptr_type = IOCType.DOMAIN
            if (ptr_val, ptr_type.value) not in ioc_keys:
                ioc_keys.add((ptr_val, ptr_type.value))
                iocs.append(
                    CanonicalIOCResponse(
                        id=str(uuid.uuid4()),
                        canonical_value=ptr_val,
                        ioc_type=ptr_type,
                        is_root=False,
                        depth=current_depth,
                        confidence=90.0,
                        metadata={"source": "reverse_dns_ptr", "description": f"Resolved PTR hostname for {root_canonical}"},
                        relationships=["resolves_to"],
                        providers=["dns"],
                    )
                )
            rel_key = (root_canonical, ptr_val)
            if rel_key in rel_dict:
                existing_rel = rel_dict[rel_key]
                if "resolves_to" not in existing_rel.relationship_type:
                    existing_rel.relationship_type = f"{existing_rel.relationship_type}, resolves_to"
                if "dns" not in existing_rel.providers:
                    existing_rel.providers.append("dns")
                    existing_rel.evidence_count = len(existing_rel.providers)
            else:
                new_rel = RelationshipResponse(
                    id=str(uuid.uuid4()),
                    source_value=root_canonical,
                    source_type=root_type.value,
                    target_value=ptr_val,
                    target_type=ptr_type.value,
                    relationship_type="resolves_to",
                    confidence=90.0,
                    providers=["dns"],
                    evidence_count=1,
                    evidence_summary=f"PTR record resolves {root_canonical} to {ptr_val}",
                    depth=current_depth,
                )
                rels.append(new_rel)
                rel_dict[rel_key] = new_rel

    # 2. DNS A records -> IPv4
    for ip_val in infra.dns_records.get("A", []):
        if not _is_ip_str(ip_val):
            continue
        norm_ip = normalize_ioc(ip_val, IOCType.IPV4)
        if norm_ip.is_valid and norm_ip.canonical_value and norm_ip.canonical_value != root_canonical:
            canon_ip = norm_ip.canonical_value
            if (canon_ip, IOCType.IPV4.value) not in ioc_keys:
                ioc_keys.add((canon_ip, IOCType.IPV4.value))
                iocs.append(
                    CanonicalIOCResponse(
                        id=str(uuid.uuid4()),
                        canonical_value=canon_ip,
                        ioc_type=IOCType.IPV4,
                        is_root=False,
                        depth=current_depth,
                        confidence=90.0,
                        metadata={"source": "dns_a_record", "description": f"DNS A record resolving {root_canonical}"},
                        relationships=["resolves_to"],
                        providers=["dns"],
                    )
                )
            rel_key = (root_canonical, canon_ip)
            if rel_key in rel_dict:
                existing_rel = rel_dict[rel_key]
                if "resolves_to" not in existing_rel.relationship_type:
                    existing_rel.relationship_type = f"{existing_rel.relationship_type}, resolves_to"
                if "dns" not in existing_rel.providers:
                    existing_rel.providers.append("dns")
                    existing_rel.evidence_count = len(existing_rel.providers)
            else:
                new_rel = RelationshipResponse(
                    id=str(uuid.uuid4()),
                    source_value=root_canonical,
                    source_type=root_type.value,
                    target_value=canon_ip,
                    target_type=IOCType.IPV4.value,
                    relationship_type="resolves_to",
                    confidence=90.0,
                    providers=["dns"],
                    evidence_count=1,
                    evidence_summary=f"DNS A record maps {root_canonical} to {canon_ip}",
                    depth=current_depth,
                )
                rels.append(new_rel)
                rel_dict[rel_key] = new_rel

    # 3. DNS AAAA records -> IPv6
    for ip_val in infra.dns_records.get("AAAA", []):
        if not _is_ip_str(ip_val):
            continue
        norm_ip6 = normalize_ioc(ip_val, IOCType.IPV6)
        if norm_ip6.is_valid and norm_ip6.canonical_value and norm_ip6.canonical_value != root_canonical:
            canon_ip6 = norm_ip6.canonical_value
            if (canon_ip6, IOCType.IPV6.value) not in ioc_keys:
                ioc_keys.add((canon_ip6, IOCType.IPV6.value))
                iocs.append(
                    CanonicalIOCResponse(
                        id=str(uuid.uuid4()),
                        canonical_value=canon_ip6,
                        ioc_type=IOCType.IPV6,
                        is_root=False,
                        depth=current_depth,
                        confidence=90.0,
                        metadata={"source": "dns_aaaa_record", "description": f"DNS AAAA record resolving {root_canonical}"},
                        relationships=["resolves_to"],
                        providers=["dns"],
                    )
                )
            rel_key = (root_canonical, canon_ip6)
            if rel_key in rel_dict:
                existing_rel = rel_dict[rel_key]
                if "resolves_to" not in existing_rel.relationship_type:
                    existing_rel.relationship_type = f"{existing_rel.relationship_type}, resolves_to"
                if "dns" not in existing_rel.providers:
                    existing_rel.providers.append("dns")
                    existing_rel.evidence_count = len(existing_rel.providers)
            else:
                new_rel = RelationshipResponse(
                    id=str(uuid.uuid4()),
                    source_value=root_canonical,
                    source_type=root_type.value,
                    target_value=canon_ip6,
                    target_type=IOCType.IPV6.value,
                    relationship_type="resolves_to",
                    confidence=90.0,
                    providers=["dns"],
                    evidence_count=1,
                    evidence_summary=f"DNS AAAA record maps {root_canonical} to {canon_ip6}",
                    depth=current_depth,
                )
                rels.append(new_rel)
                rel_dict[rel_key] = new_rel

    # 4. Nameservers -> Domain (dns_ns)
    for ns_val in (infra.nameservers or []):
        if not is_valid_hostname_or_domain(ns_val) or _is_ip_str(ns_val):
            continue
        norm_ns = normalize_ioc(ns_val, IOCType.DOMAIN)
        if norm_ns.is_valid and norm_ns.canonical_value and norm_ns.canonical_value != root_canonical:
            canon_ns = norm_ns.canonical_value
            if (canon_ns, IOCType.DOMAIN.value) not in ioc_keys:
                ioc_keys.add((canon_ns, IOCType.DOMAIN.value))
                iocs.append(
                    CanonicalIOCResponse(
                        id=str(uuid.uuid4()),
                        canonical_value=canon_ns,
                        ioc_type=IOCType.DOMAIN,
                        is_root=False,
                        depth=current_depth,
                        confidence=85.0,
                        metadata={"source": "authoritative_nameserver", "description": f"Authoritative nameserver for {root_canonical}"},
                        relationships=["dns_ns"],
                        providers=["dns"],
                    )
                )
            rel_key = (root_canonical, canon_ns)
            if rel_key in rel_dict:
                existing_rel = rel_dict[rel_key]
                if "dns_ns" not in existing_rel.relationship_type:
                    existing_rel.relationship_type = f"{existing_rel.relationship_type}, dns_ns"
                if "dns" not in existing_rel.providers:
                    existing_rel.providers.append("dns")
                    existing_rel.evidence_count = len(existing_rel.providers)
            else:
                new_rel = RelationshipResponse(
                    id=str(uuid.uuid4()),
                    source_value=root_canonical,
                    source_type=root_type.value,
                    target_value=canon_ns,
                    target_type=IOCType.DOMAIN.value,
                    relationship_type="dns_ns",
                    confidence=85.0,
                    providers=["dns"],
                    evidence_count=1,
                    evidence_summary=f"Authoritative nameserver for {root_canonical}",
                    depth=current_depth,
                )
                rels.append(new_rel)
                rel_dict[rel_key] = new_rel

    # 5. MX Records -> Domain (dns_mx)
    for mx_val in infra.dns_records.get("MX", []):
        clean_mx = mx_val.split()[-1] if " " in mx_val else mx_val
        if not is_valid_hostname_or_domain(clean_mx) or _is_ip_str(clean_mx):
            continue
        norm_mx = normalize_ioc(clean_mx, IOCType.DOMAIN)
        if norm_mx.is_valid and norm_mx.canonical_value and norm_mx.canonical_value != root_canonical:
            canon_mx = norm_mx.canonical_value
            if (canon_mx, IOCType.DOMAIN.value) not in ioc_keys:
                ioc_keys.add((canon_mx, IOCType.DOMAIN.value))
                iocs.append(
                    CanonicalIOCResponse(
                        id=str(uuid.uuid4()),
                        canonical_value=canon_mx,
                        ioc_type=IOCType.DOMAIN,
                        is_root=False,
                        depth=current_depth,
                        confidence=85.0,
                        metadata={"source": "dns_mx_record", "description": f"Mail exchange server for {root_canonical}"},
                        relationships=["dns_mx"],
                        providers=["dns"],
                    )
                )
            rel_key = (root_canonical, canon_mx)
            if rel_key in rel_dict:
                existing_rel = rel_dict[rel_key]
                if "dns_mx" not in existing_rel.relationship_type:
                    existing_rel.relationship_type = f"{existing_rel.relationship_type}, dns_mx"
                if "dns" not in existing_rel.providers:
                    existing_rel.providers.append("dns")
                    existing_rel.evidence_count = len(existing_rel.providers)
            else:
                new_rel = RelationshipResponse(
                    id=str(uuid.uuid4()),
                    source_value=root_canonical,
                    source_type=root_type.value,
                    target_value=canon_mx,
                    target_type=IOCType.DOMAIN.value,
                    relationship_type="dns_mx",
                    confidence=85.0,
                    providers=["dns"],
                    evidence_count=1,
                    evidence_summary=f"DNS MX mail server for {root_canonical}",
                    depth=current_depth,
                )
                rels.append(new_rel)
                rel_dict[rel_key] = new_rel

    # 6. Passive DNS Records -> Canonical IOCs & Relationships
    for pdns in (infra.passive_dns or []):
        prov_name = pdns.sources[0] if pdns.sources else "mnemonic Passive DNS"
        if root_type == IOCType.DOMAIN:
            target_val = None
            target_t = None
            rel_type = "resolves_to"

            if pdns.rrtype in ("A", "AAAA"):
                target_val = pdns.answer
                target_t = IOCType.IPV4 if "." in pdns.answer else IOCType.IPV6
            elif pdns.rrtype in ("CNAME", "PTR"):
                if is_valid_hostname_or_domain(pdns.answer) and not _is_ip_str(pdns.answer):
                    target_val = pdns.answer
                    target_t = IOCType.DOMAIN
            elif pdns.rrtype == "NS":
                if is_valid_hostname_or_domain(pdns.answer) and not _is_ip_str(pdns.answer):
                    target_val = pdns.answer
                    target_t = IOCType.DOMAIN
                    rel_type = "shares_nameserver"

            if target_val and target_t:
                norm_target = normalize_ioc(target_val, target_t)
                if norm_target.is_valid and norm_target.canonical_value and norm_target.canonical_value != root_canonical:
                    c_val = norm_target.canonical_value
                    c_type = norm_target.ioc_type
                    if (c_val, c_type.value) not in ioc_keys:
                        ioc_keys.add((c_val, c_type.value))
                        iocs.append(
                            CanonicalIOCResponse(
                                id=str(uuid.uuid4()),
                                canonical_value=c_val,
                                ioc_type=c_type,
                                is_root=False,
                                depth=current_depth,
                                confidence=85.0,
                                first_seen=pdns.first_seen,
                                last_seen=pdns.last_seen,
                                metadata={
                                    "source": "passive_dns",
                                    "rrtype": pdns.rrtype,
                                    "observations": pdns.observation_count,
                                },
                                relationships=[rel_type],
                                providers=[prov_name],
                            )
                        )
                    rel_key = (root_canonical, c_val)
                    if rel_key in rel_dict:
                        existing_rel = rel_dict[rel_key]
                        if rel_type not in existing_rel.relationship_type:
                            existing_rel.relationship_type = f"{existing_rel.relationship_type}, {rel_type}"
                        if prov_name not in existing_rel.providers:
                            existing_rel.providers.append(prov_name)
                            existing_rel.evidence_count = len(existing_rel.providers)
                    else:
                        new_rel = RelationshipResponse(
                            id=str(uuid.uuid4()),
                            source_value=root_canonical,
                            source_type=root_type.value,
                            target_value=c_val,
                            target_type=c_type.value,
                            relationship_type=rel_type,
                            confidence=85.0,
                            providers=[prov_name],
                            evidence_count=1,
                            evidence_summary=f"Passive DNS {pdns.rrtype} record {pdns.query} -> {pdns.answer}",
                            depth=current_depth,
                        )
                        rels.append(new_rel)
                        rel_dict[rel_key] = new_rel

        elif root_type in (IOCType.IPV4, IOCType.IPV6):
            if pdns.query and is_valid_hostname_or_domain(pdns.query) and not _is_ip_str(pdns.query):
                norm_q = normalize_ioc(pdns.query, IOCType.DOMAIN)
                if norm_q.is_valid and norm_q.canonical_value and norm_q.canonical_value != root_canonical:
                    c_domain = norm_q.canonical_value
                    c_type = IOCType.DOMAIN
                    if (c_domain, c_type.value) not in ioc_keys:
                        ioc_keys.add((c_domain, c_type.value))
                        iocs.append(
                            CanonicalIOCResponse(
                                id=str(uuid.uuid4()),
                                canonical_value=c_domain,
                                ioc_type=c_type,
                                is_root=False,
                                depth=current_depth,
                                confidence=85.0,
                                first_seen=pdns.first_seen,
                                last_seen=pdns.last_seen,
                                metadata={
                                    "source": "passive_dns",
                                    "rrtype": pdns.rrtype,
                                    "observations": pdns.observation_count,
                                },
                                relationships=["observed_with"],
                                providers=[prov_name],
                            )
                        )
                    rel_key = (root_canonical, c_domain)
                    if rel_key in rel_dict:
                        existing_rel = rel_dict[rel_key]
                        if "observed_with" not in existing_rel.relationship_type:
                            existing_rel.relationship_type = f"{existing_rel.relationship_type}, observed_with"
                        if prov_name not in existing_rel.providers:
                            existing_rel.providers.append(prov_name)
                            existing_rel.evidence_count = len(existing_rel.providers)
                    else:
                        new_rel = RelationshipResponse(
                            id=str(uuid.uuid4()),
                            source_value=root_canonical,
                            source_type=root_type.value,
                            target_value=c_domain,
                            target_type=c_type.value,
                            relationship_type="observed_with",
                            confidence=85.0,
                            providers=[prov_name],
                            evidence_count=1,
                            evidence_summary=f"Passive DNS historically resolved domain {c_domain} to {root_canonical}",
                            depth=current_depth,
                        )
                        rels.append(new_rel)
                        rel_dict[rel_key] = new_rel

    return iocs, rels

