"""
Canonical MITRE ATT&CK Enterprise Matrix Catalog & Normalization Engine.
Provides authoritative mapping for Tactics, Techniques, and Sub-techniques
according to the official MITRE ATT&CK framework.
"""

from typing import Optional, Dict, Tuple, List
from pydantic import BaseModel, Field


class MitreTactic(BaseModel):
    id: str
    name: str
    order: int


# 14 Enterprise Tactics in ATT&CK Matrix Order
MITRE_TACTICS: Dict[str, MitreTactic] = {
    "TA0043": MitreTactic(id="TA0043", name="Reconnaissance", order=1),
    "TA0042": MitreTactic(id="TA0042", name="Resource Development", order=2),
    "TA0001": MitreTactic(id="TA0001", name="Initial Access", order=3),
    "TA0002": MitreTactic(id="TA0002", name="Execution", order=4),
    "TA0003": MitreTactic(id="TA0003", name="Persistence", order=5),
    "TA0004": MitreTactic(id="TA0004", name="Privilege Escalation", order=6),
    "TA0005": MitreTactic(id="TA0005", name="Defense Evasion", order=7),
    "TA0006": MitreTactic(id="TA0006", name="Credential Access", order=8),
    "TA0007": MitreTactic(id="TA0007", name="Discovery", order=9),
    "TA0008": MitreTactic(id="TA0008", name="Lateral Movement", order=10),
    "TA0009": MitreTactic(id="TA0009", name="Collection", order=11),
    "TA0011": MitreTactic(id="TA0011", name="Command and Control", order=12),
    "TA0010": MitreTactic(id="TA0010", name="Exfiltration", order=13),
    "TA0040": MitreTactic(id="TA0040", name="Impact", order=14),
}

ENTERPRISE_TACTICS_ORDER: List[str] = list(MITRE_TACTICS.keys())

# Tactic Name to ID lookup
TACTIC_NAME_TO_ID: Dict[str, str] = {
    t.name.lower(): t.id for t in MITRE_TACTICS.values()
}
# Common aliases / variations
TACTIC_NAME_TO_ID.update({
    "command & control": "TA0011",
    "c2": "TA0011",
    "privilege-escalation": "TA0004",
    "defense-evasion": "TA0005",
    "credential-access": "TA0006",
    "lateral-movement": "TA0008",
    "initial-access": "TA0001",
    "resource-development": "TA0042",
})


class MitreTechniqueCatalogItem(BaseModel):
    id: str
    name: str
    primary_tactic_id: str
    primary_tactic_name: str
    parent_id: Optional[str] = None
    parent_name: Optional[str] = None
    is_subtechnique: bool = False


# Comprehensive Authoritative Enterprise Techniques and Sub-techniques Catalog
MITRE_CATALOG: Dict[str, MitreTechniqueCatalogItem] = {
    # --- Execution (TA0002) ---
    "T1059": MitreTechniqueCatalogItem(id="T1059", name="Command and Scripting Interpreter", primary_tactic_id="TA0002", primary_tactic_name="Execution"),
    "T1059.001": MitreTechniqueCatalogItem(id="T1059.001", name="PowerShell", primary_tactic_id="TA0002", primary_tactic_name="Execution", parent_id="T1059", parent_name="Command and Scripting Interpreter", is_subtechnique=True),
    "T1059.002": MitreTechniqueCatalogItem(id="T1059.002", name="AppleScript", primary_tactic_id="TA0002", primary_tactic_name="Execution", parent_id="T1059", parent_name="Command and Scripting Interpreter", is_subtechnique=True),
    "T1059.003": MitreTechniqueCatalogItem(id="T1059.003", name="Windows Command Shell", primary_tactic_id="TA0002", primary_tactic_name="Execution", parent_id="T1059", parent_name="Command and Scripting Interpreter", is_subtechnique=True),
    "T1059.004": MitreTechniqueCatalogItem(id="T1059.004", name="Unix Shell", primary_tactic_id="TA0002", primary_tactic_name="Execution", parent_id="T1059", parent_name="Command and Scripting Interpreter", is_subtechnique=True),
    "T1059.005": MitreTechniqueCatalogItem(id="T1059.005", name="Visual Basic", primary_tactic_id="TA0002", primary_tactic_name="Execution", parent_id="T1059", parent_name="Command and Scripting Interpreter", is_subtechnique=True),
    "T1059.006": MitreTechniqueCatalogItem(id="T1059.006", name="Python", primary_tactic_id="TA0002", primary_tactic_name="Execution", parent_id="T1059", parent_name="Command and Scripting Interpreter", is_subtechnique=True),
    "T1059.007": MitreTechniqueCatalogItem(id="T1059.007", name="JavaScript", primary_tactic_id="TA0002", primary_tactic_name="Execution", parent_id="T1059", parent_name="Command and Scripting Interpreter", is_subtechnique=True),
    "T1204": MitreTechniqueCatalogItem(id="T1204", name="User Execution", primary_tactic_id="TA0002", primary_tactic_name="Execution"),
    "T1204.001": MitreTechniqueCatalogItem(id="T1204.001", name="Malicious Link", primary_tactic_id="TA0002", primary_tactic_name="Execution", parent_id="T1204", parent_name="User Execution", is_subtechnique=True),
    "T1204.002": MitreTechniqueCatalogItem(id="T1204.002", name="Malicious File", primary_tactic_id="TA0002", primary_tactic_name="Execution", parent_id="T1204", parent_name="User Execution", is_subtechnique=True),
    "T1569": MitreTechniqueCatalogItem(id="T1569", name="System Services", primary_tactic_id="TA0002", primary_tactic_name="Execution"),
    "T1569.002": MitreTechniqueCatalogItem(id="T1569.002", name="Service Execution", primary_tactic_id="TA0002", primary_tactic_name="Execution", parent_id="T1569", parent_name="System Services", is_subtechnique=True),
    "T1053": MitreTechniqueCatalogItem(id="T1053", name="Scheduled Task/Job", primary_tactic_id="TA0002", primary_tactic_name="Execution"),
    "T1053.005": MitreTechniqueCatalogItem(id="T1053.005", name="Scheduled Task", primary_tactic_id="TA0002", primary_tactic_name="Execution", parent_id="T1053", parent_name="Scheduled Task/Job", is_subtechnique=True),
    "T1053.003": MitreTechniqueCatalogItem(id="T1053.003", name="Cron", primary_tactic_id="TA0002", primary_tactic_name="Execution", parent_id="T1053", parent_name="Scheduled Task/Job", is_subtechnique=True),
    "T1047": MitreTechniqueCatalogItem(id="T1047", name="Windows Management Instrumentation", primary_tactic_id="TA0002", primary_tactic_name="Execution"),
    "T1106": MitreTechniqueCatalogItem(id="T1106", name="Native API", primary_tactic_id="TA0002", primary_tactic_name="Execution"),

    # --- Initial Access (TA0001) ---
    "T1566": MitreTechniqueCatalogItem(id="T1566", name="Phishing", primary_tactic_id="TA0001", primary_tactic_name="Initial Access"),
    "T1566.001": MitreTechniqueCatalogItem(id="T1566.001", name="Spearphishing Attachment", primary_tactic_id="TA0001", primary_tactic_name="Initial Access", parent_id="T1566", parent_name="Phishing", is_subtechnique=True),
    "T1566.002": MitreTechniqueCatalogItem(id="T1566.002", name="Spearphishing Link", primary_tactic_id="TA0001", primary_tactic_name="Initial Access", parent_id="T1566", parent_name="Phishing", is_subtechnique=True),
    "T1190": MitreTechniqueCatalogItem(id="T1190", name="Exploit Public-Facing Application", primary_tactic_id="TA0001", primary_tactic_name="Initial Access"),
    "T1078": MitreTechniqueCatalogItem(id="T1078", name="Valid Accounts", primary_tactic_id="TA0001", primary_tactic_name="Initial Access"),
    "T1133": MitreTechniqueCatalogItem(id="T1133", name="External Remote Services", primary_tactic_id="TA0001", primary_tactic_name="Initial Access"),

    # --- Persistence (TA0003) ---
    "T1547": MitreTechniqueCatalogItem(id="T1547", name="Boot or Logon Autostart Execution", primary_tactic_id="TA0003", primary_tactic_name="Persistence"),
    "T1547.001": MitreTechniqueCatalogItem(id="T1547.001", name="Registry Run Keys / Startup Folder", primary_tactic_id="TA0003", primary_tactic_name="Persistence", parent_id="T1547", parent_name="Boot or Logon Autostart Execution", is_subtechnique=True),
    "T1543": MitreTechniqueCatalogItem(id="T1543", name="Create or Modify System Process", primary_tactic_id="TA0003", primary_tactic_name="Persistence"),
    "T1543.003": MitreTechniqueCatalogItem(id="T1543.003", name="Windows Service", primary_tactic_id="TA0003", primary_tactic_name="Persistence", parent_id="T1543", parent_name="Create or Modify System Process", is_subtechnique=True),
    "T1136": MitreTechniqueCatalogItem(id="T1136", name="Create Account", primary_tactic_id="TA0003", primary_tactic_name="Persistence"),
    "T1505": MitreTechniqueCatalogItem(id="T1505", name="Server Software Component", primary_tactic_id="TA0003", primary_tactic_name="Persistence"),
    "T1505.003": MitreTechniqueCatalogItem(id="T1505.003", name="Web Shell", primary_tactic_id="TA0003", primary_tactic_name="Persistence", parent_id="T1505", parent_name="Server Software Component", is_subtechnique=True),

    # --- Privilege Escalation (TA0004) ---
    "T1055": MitreTechniqueCatalogItem(id="T1055", name="Process Injection", primary_tactic_id="TA0004", primary_tactic_name="Privilege Escalation"),
    "T1055.001": MitreTechniqueCatalogItem(id="T1055.001", name="Dynamic-link Library Injection", primary_tactic_id="TA0004", primary_tactic_name="Privilege Escalation", parent_id="T1055", parent_name="Process Injection", is_subtechnique=True),
    "T1055.012": MitreTechniqueCatalogItem(id="T1055.012", name="Process Hollowing", primary_tactic_id="TA0004", primary_tactic_name="Privilege Escalation", parent_id="T1055", parent_name="Process Injection", is_subtechnique=True),
    "T1548": MitreTechniqueCatalogItem(id="T1548", name="Abuse Elevation Control Mechanism", primary_tactic_id="TA0004", primary_tactic_name="Privilege Escalation"),
    "T1548.002": MitreTechniqueCatalogItem(id="T1548.002", name="Bypass User Account Control", primary_tactic_id="TA0004", primary_tactic_name="Privilege Escalation", parent_id="T1548", parent_name="Abuse Elevation Control Mechanism", is_subtechnique=True),
    "T1068": MitreTechniqueCatalogItem(id="T1068", name="Exploitation for Privilege Escalation", primary_tactic_id="TA0004", primary_tactic_name="Privilege Escalation"),

    # --- Defense Evasion (TA0005) ---
    "T1027": MitreTechniqueCatalogItem(id="T1027", name="Obfuscated Files or Information", primary_tactic_id="TA0005", primary_tactic_name="Defense Evasion"),
    "T1027.001": MitreTechniqueCatalogItem(id="T1027.001", name="Binary Padding", primary_tactic_id="TA0005", primary_tactic_name="Defense Evasion", parent_id="T1027", parent_name="Obfuscated Files or Information", is_subtechnique=True),
    "T1027.002": MitreTechniqueCatalogItem(id="T1027.002", name="Software Packing", primary_tactic_id="TA0005", primary_tactic_name="Defense Evasion", parent_id="T1027", parent_name="Obfuscated Files or Information", is_subtechnique=True),
    "T1027.005": MitreTechniqueCatalogItem(id="T1027.005", name="Indicator Removal from Tools", primary_tactic_id="TA0005", primary_tactic_name="Defense Evasion", parent_id="T1027", parent_name="Obfuscated Files or Information", is_subtechnique=True),
    "T1140": MitreTechniqueCatalogItem(id="T1140", name="Deobfuscate/Decode Files or Information", primary_tactic_id="TA0005", primary_tactic_name="Defense Evasion"),
    "T1497": MitreTechniqueCatalogItem(id="T1497", name="Virtualization/Sandbox Evasion", primary_tactic_id="TA0005", primary_tactic_name="Defense Evasion"),
    "T1497.001": MitreTechniqueCatalogItem(id="T1497.001", name="System Checks", primary_tactic_id="TA0005", primary_tactic_name="Defense Evasion", parent_id="T1497", parent_name="Virtualization/Sandbox Evasion", is_subtechnique=True),
    "T1497.003": MitreTechniqueCatalogItem(id="T1497.003", name="Time Based Evasion", primary_tactic_id="TA0005", primary_tactic_name="Defense Evasion", parent_id="T1497", parent_name="Virtualization/Sandbox Evasion", is_subtechnique=True),
    "T1562": MitreTechniqueCatalogItem(id="T1562", name="Impair Defenses", primary_tactic_id="TA0005", primary_tactic_name="Defense Evasion"),
    "T1562.001": MitreTechniqueCatalogItem(id="T1562.001", name="Disable or Modify Tools", primary_tactic_id="TA0005", primary_tactic_name="Defense Evasion", parent_id="T1562", parent_name="Impair Defenses", is_subtechnique=True),
    "T1070": MitreTechniqueCatalogItem(id="T1070", name="Indicator Removal on Host", primary_tactic_id="TA0005", primary_tactic_name="Defense Evasion"),
    "T1070.004": MitreTechniqueCatalogItem(id="T1070.004", name="File Deletion", primary_tactic_id="TA0005", primary_tactic_name="Defense Evasion", parent_id="T1070", parent_name="Indicator Removal on Host", is_subtechnique=True),
    "T1036": MitreTechniqueCatalogItem(id="T1036", name="Masquerading", primary_tactic_id="TA0005", primary_tactic_name="Defense Evasion"),
    "T1036.005": MitreTechniqueCatalogItem(id="T1036.005", name="Match Legitimate Name or Location", primary_tactic_id="TA0005", primary_tactic_name="Defense Evasion", parent_id="T1036", parent_name="Masquerading", is_subtechnique=True),
    "T1112": MitreTechniqueCatalogItem(id="T1112", name="Modify Registry", primary_tactic_id="TA0005", primary_tactic_name="Defense Evasion"),
    "T1218": MitreTechniqueCatalogItem(id="T1218", name="System Binary Proxy Execution", primary_tactic_id="TA0005", primary_tactic_name="Defense Evasion"),
    "T1218.005": MitreTechniqueCatalogItem(id="T1218.005", name="Mshta", primary_tactic_id="TA0005", primary_tactic_name="Defense Evasion", parent_id="T1218", parent_name="System Binary Proxy Execution", is_subtechnique=True),
    "T1218.010": MitreTechniqueCatalogItem(id="T1218.010", name="Regsvr32", primary_tactic_id="TA0005", primary_tactic_name="Defense Evasion", parent_id="T1218", parent_name="System Binary Proxy Execution", is_subtechnique=True),
    "T1218.011": MitreTechniqueCatalogItem(id="T1218.011", name="Rundll32", primary_tactic_id="TA0005", primary_tactic_name="Defense Evasion", parent_id="T1218", parent_name="System Binary Proxy Execution", is_subtechnique=True),

    # --- Credential Access (TA0006) ---
    "T1003": MitreTechniqueCatalogItem(id="T1003", name="OS Credential Dumping", primary_tactic_id="TA0006", primary_tactic_name="Credential Access"),
    "T1003.001": MitreTechniqueCatalogItem(id="T1003.001", name="LSASS Memory", primary_tactic_id="TA0006", primary_tactic_name="Credential Access", parent_id="T1003", parent_name="OS Credential Dumping", is_subtechnique=True),
    "T1555": MitreTechniqueCatalogItem(id="T1555", name="Credentials from Password Stores", primary_tactic_id="TA0006", primary_tactic_name="Credential Access"),
    "T1555.003": MitreTechniqueCatalogItem(id="T1555.003", name="Credentials from Web Browsers", primary_tactic_id="TA0006", primary_tactic_name="Credential Access", parent_id="T1555", parent_name="Credentials from Password Stores", is_subtechnique=True),
    "T1056": MitreTechniqueCatalogItem(id="T1056", name="Input Capture", primary_tactic_id="TA0006", primary_tactic_name="Credential Access"),
    "T1056.001": MitreTechniqueCatalogItem(id="T1056.001", name="Keylogging", primary_tactic_id="TA0006", primary_tactic_name="Credential Access", parent_id="T1056", parent_name="Input Capture", is_subtechnique=True),
    "T1110": MitreTechniqueCatalogItem(id="T1110", name="Brute Force", primary_tactic_id="TA0006", primary_tactic_name="Credential Access"),

    # --- Discovery (TA0007) ---
    "T1082": MitreTechniqueCatalogItem(id="T1082", name="System Information Discovery", primary_tactic_id="TA0007", primary_tactic_name="Discovery"),
    "T1083": MitreTechniqueCatalogItem(id="T1083", name="File and Directory Discovery", primary_tactic_id="TA0007", primary_tactic_name="Discovery"),
    "T1057": MitreTechniqueCatalogItem(id="T1057", name="Process Discovery", primary_tactic_id="TA0007", primary_tactic_name="Discovery"),
    "T1012": MitreTechniqueCatalogItem(id="T1012", name="Query Registry", primary_tactic_id="TA0007", primary_tactic_name="Discovery"),
    "T1016": MitreTechniqueCatalogItem(id="T1016", name="System Network Configuration Discovery", primary_tactic_id="TA0007", primary_tactic_name="Discovery"),
    "T1049": MitreTechniqueCatalogItem(id="T1049", name="System Network Connections Discovery", primary_tactic_id="TA0007", primary_tactic_name="Discovery"),
    "T1033": MitreTechniqueCatalogItem(id="T1033", name="System Owner/User Discovery", primary_tactic_id="TA0007", primary_tactic_name="Discovery"),
    "T1087": MitreTechniqueCatalogItem(id="T1087", name="Account Discovery", primary_tactic_id="TA0007", primary_tactic_name="Discovery"),
    "T1046": MitreTechniqueCatalogItem(id="T1046", name="Network Service Discovery", primary_tactic_id="TA0007", primary_tactic_name="Discovery"),
    "T1124": MitreTechniqueCatalogItem(id="T1124", name="System Time Discovery", primary_tactic_id="TA0007", primary_tactic_name="Discovery"),

    # --- Lateral Movement (TA0008) ---
    "T1021": MitreTechniqueCatalogItem(id="T1021", name="Remote Services", primary_tactic_id="TA0008", primary_tactic_name="Lateral Movement"),
    "T1021.001": MitreTechniqueCatalogItem(id="T1021.001", name="Remote Desktop Protocol", primary_tactic_id="TA0008", primary_tactic_name="Lateral Movement", parent_id="T1021", parent_name="Remote Services", is_subtechnique=True),
    "T1021.002": MitreTechniqueCatalogItem(id="T1021.002", name="SMB/Windows Admin Shares", primary_tactic_id="TA0008", primary_tactic_name="Lateral Movement", parent_id="T1021", parent_name="Remote Services", is_subtechnique=True),
    "T1210": MitreTechniqueCatalogItem(id="T1210", name="Exploitation of Remote Services", primary_tactic_id="TA0008", primary_tactic_name="Lateral Movement"),

    # --- Collection (TA0009) ---
    "T1005": MitreTechniqueCatalogItem(id="T1005", name="Data from Local System", primary_tactic_id="TA0009", primary_tactic_name="Collection"),
    "T1074": MitreTechniqueCatalogItem(id="T1074", name="Data Staged", primary_tactic_id="TA0009", primary_tactic_name="Collection"),
    "T1113": MitreTechniqueCatalogItem(id="T1113", name="Screen Capture", primary_tactic_id="TA0009", primary_tactic_name="Collection"),
    "T1560": MitreTechniqueCatalogItem(id="T1560", name="Archive Collected Data", primary_tactic_id="TA0009", primary_tactic_name="Collection"),

    # --- Command and Control (TA0011) ---
    "T1071": MitreTechniqueCatalogItem(id="T1071", name="Application Layer Protocol", primary_tactic_id="TA0011", primary_tactic_name="Command and Control"),
    "T1071.001": MitreTechniqueCatalogItem(id="T1071.001", name="Web Protocols", primary_tactic_id="TA0011", primary_tactic_name="Command and Control", parent_id="T1071", parent_name="Application Layer Protocol", is_subtechnique=True),
    "T1071.002": MitreTechniqueCatalogItem(id="T1071.002", name="File Transfer Protocols", primary_tactic_id="TA0011", primary_tactic_name="Command and Control", parent_id="T1071", parent_name="Application Layer Protocol", is_subtechnique=True),
    "T1071.004": MitreTechniqueCatalogItem(id="T1071.004", name="DNS", primary_tactic_id="TA0011", primary_tactic_name="Command and Control", parent_id="T1071", parent_name="Application Layer Protocol", is_subtechnique=True),
    "T1105": MitreTechniqueCatalogItem(id="T1105", name="Ingress Tool Transfer", primary_tactic_id="TA0011", primary_tactic_name="Command and Control"),
    "T1573": MitreTechniqueCatalogItem(id="T1573", name="Encrypted Channel", primary_tactic_id="TA0011", primary_tactic_name="Command and Control"),
    "T1573.001": MitreTechniqueCatalogItem(id="T1573.001", name="Symmetric Cryptography", primary_tactic_id="TA0011", primary_tactic_name="Command and Control", parent_id="T1573", parent_name="Encrypted Channel", is_subtechnique=True),
    "T1573.002": MitreTechniqueCatalogItem(id="T1573.002", name="Asymmetric Cryptography", primary_tactic_id="TA0011", primary_tactic_name="Command and Control", parent_id="T1573", parent_name="Encrypted Channel", is_subtechnique=True),
    "T1090": MitreTechniqueCatalogItem(id="T1090", name="Proxy", primary_tactic_id="TA0011", primary_tactic_name="Command and Control"),
    "T1571": MitreTechniqueCatalogItem(id="T1571", name="Non-Standard Port", primary_tactic_id="TA0011", primary_tactic_name="Command and Control"),
    "T1572": MitreTechniqueCatalogItem(id="T1572", name="Protocol Tunneling", primary_tactic_id="TA0011", primary_tactic_name="Command and Control"),

    # --- Exfiltration (TA0010) ---
    "T1041": MitreTechniqueCatalogItem(id="T1041", name="Exfiltration Over C2 Channel", primary_tactic_id="TA0010", primary_tactic_name="Exfiltration"),
    "T1020": MitreTechniqueCatalogItem(id="T1020", name="Automated Exfiltration", primary_tactic_id="TA0010", primary_tactic_name="Exfiltration"),
    "T1048": MitreTechniqueCatalogItem(id="T1048", name="Exfiltration Over Alternative Protocol", primary_tactic_id="TA0010", primary_tactic_name="Exfiltration"),

    # --- Impact (TA0040) ---
    "T1486": MitreTechniqueCatalogItem(id="T1486", name="Data Encrypted for Impact", primary_tactic_id="TA0040", primary_tactic_name="Impact"),
    "T1489": MitreTechniqueCatalogItem(id="T1489", name="Service Stop", primary_tactic_id="TA0040", primary_tactic_name="Impact"),
    "T1490": MitreTechniqueCatalogItem(id="T1490", name="Inhibit System Recovery", primary_tactic_id="TA0040", primary_tactic_name="Impact"),
    "T1498": MitreTechniqueCatalogItem(id="T1498", name="Network Denial of Service", primary_tactic_id="TA0040", primary_tactic_name="Impact"),
    "T1499": MitreTechniqueCatalogItem(id="T1499", name="Endpoint Denial of Service", primary_tactic_id="TA0040", primary_tactic_name="Impact"),
}


def lookup_mitre_technique(raw_id: str) -> Optional[MitreTechniqueCatalogItem]:
    """Looks up a technique by ID (e.g. 'T1059.001', '1059.001', 'T1059')."""
    if not raw_id:
        return None
    tid = raw_id.strip().upper()
    if not tid.startswith("T") and any(c.isdigit() for c in tid):
        tid = f"T{tid}"

    if tid in MITRE_CATALOG:
        return MITRE_CATALOG[tid]

    # If it's a sub-technique not directly in catalog, try parent
    if "." in tid:
        parent_id = tid.split(".")[0]
        if parent_id in MITRE_CATALOG:
            parent = MITRE_CATALOG[parent_id]
            return MitreTechniqueCatalogItem(
                id=tid,
                name=f"Sub-technique of {parent.name}",
                primary_tactic_id=parent.primary_tactic_id,
                primary_tactic_name=parent.primary_tactic_name,
                parent_id=parent_id,
                parent_name=parent.name,
                is_subtechnique=True,
            )

    return None
