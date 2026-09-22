"""Offline deterministic concepts and phrase aliases; no external service is used."""

CONCEPTS = {
    "greeting": "Hello. I am Vigilant Sphere's offline security assistant. Ask about scans, findings, Wi-Fi audits, or cybersecurity concepts.",
    "help": "Ask about your latest scan, critical findings, open ports, risk score, Wi-Fi audit, MITRE ATT&CK, files, or passwords.",
    "cybersecurity_definition": "Cybersecurity is the practice of protecting systems, networks, applications, and data from unauthorized access or harm.",
    "malware_definition": "Malware is software designed to harm, disrupt, spy on, or gain unauthorized access to a system.",
    "virus_definition": "A virus is malware that attaches to legitimate content and spreads when that content runs.",
    "trojan_definition": "A trojan disguises itself as legitimate software while carrying an unwanted payload.",
    "ransomware_definition": "Ransomware blocks access to data or systems and demands payment; isolate affected systems and preserve evidence.",
    "phishing_definition": "Phishing uses deceptive messages or sites to steal credentials or persuade unsafe actions.",
    "spyware_definition": "Spyware secretly collects information or monitors activity without informed consent.",
    "botnet_definition": "A botnet is a group of compromised devices controlled by an operator.",
    "firewall_definition": "A firewall enforces network traffic rules between trusted and untrusted boundaries.",
    "antivirus_definition": "Antivirus detects known and suspicious malicious files or behavior; it is one control, not a guarantee.",
    "vpn_definition": "A VPN encrypts traffic between a device and a VPN endpoint; it does not make unsafe destinations trustworthy.",
    "encryption_definition": "Encryption transforms data so only holders of the correct key can read it.",
    "authentication_definition": "Authentication verifies an identity before granting access.",
    "mfa_definition": "Multi-factor authentication requires independent factors, reducing the impact of stolen passwords.",
    "password_security": "Use unique, long passwords or passphrases with a password manager and enable MFA. A breach check is separate from strength.",
    "zero_trust_definition": "Zero trust continuously verifies access rather than trusting a network location by default.",
    "soc_definition": "A Security Operations Center monitors, investigates, and responds to security events.",
    "dfir_definition": "Digital forensics and incident response preserves evidence, determines scope, and contains and recovers from incidents.",
    "tcp_definition": "TCP is a connection-oriented transport protocol designed for reliable ordered delivery.",
    "udp_definition": "UDP is a connectionless transport protocol with low overhead; applications handle reliability when needed.",
    "dns_definition": "DNS translates names to network records. DNS failures or records need context before being considered malicious.",
    "ip_address_definition": "An IP address identifies a network endpoint. Location or hosting alone does not prove maliciousness.",
    "mac_address_definition": "A MAC address is a link-layer interface identifier used on local networks.",
    "network_security": "Network security combines segmentation, secure configuration, monitoring, patching, and access control.",
    "smb_security": "SMB file sharing should be restricted to trusted networks, patched, and not exposed publicly.",
    "threat_definition": "A threat is a potential cause of harm; a finding is evidence that requires context and validation.",
    "critical_severity": "Critical findings require prompt validation and response because the scanner observed high-impact evidence.",
    "high_severity": "High findings need timely investigation; severity is not proof of compromise on its own.",
    "medium_severity": "Medium findings indicate a meaningful security weakness or suspicious observation that should be prioritized.",
    "low_severity": "Low findings are limited-risk observations or hardening opportunities.",
    "mitre_attack": "MITRE ATT&CK is a knowledge base describing adversary tactics and techniques used to map observed behavior.",
    "ioc_definition": "An indicator of compromise is an observable artifact such as a hash, IP, domain, or process detail that needs context.",
    "incident_definition": "An incident is a confirmed or suspected security event requiring coordinated investigation and response.",
    "file_scan": "File analysis is static and defensive: it hashes and inspects content without executing uploaded samples.",
    "suspicious_file": "A suspicious filename or heuristic is a lead for investigation, not a malware verdict.",
    "file_hash": "A file hash is a fixed digest used to identify a specific file; SHA-256 is preferred for modern integrity checks.",
    "sha256_definition": "SHA-256 is a cryptographic hash function used for integrity and indicator matching.",
    "file_entropy": "High file entropy can indicate compression or encryption; it is not by itself proof of malware.",
    "yara_definition": "YARA describes patterns used to classify files; a match needs analyst context.",
    "malware_analysis": "Vigilant Sphere performs local static analysis and optional attributed provider lookup; it does not execute malware.",
    "file_quarantine": "Quarantine isolates a suspicious file. Preserve evidence and follow approved response procedures.",
    "what_is_vigilant_sphere": "Vigilant Sphere is a defensive Security Intelligence and Threat Analysis Platform using local analysis and optional attributed intelligence.",
    "available_scanners": "Available scanners are shown in Scan Jobs. Capability states distinguish implemented, partial, unavailable, and not configured.",
    "how_to_scan": "Open Scan Center, choose a supported target or local scan, then review evidence, provider state, findings, and recommendations.",
    "scan_history": "Scan History contains your persisted scan results; it does not include password plaintext.",
    "security_report": "Reports summarize actual recorded evidence, risk, recommendations, and provider provenance.",
    "dashboard_help": "The dashboard summarizes your saved scan activity. Open a result to inspect the underlying evidence.",
    "mobile_security": "Mobile Security includes the local password assessment workflow; its plaintext input remains in the browser.",
    "phishing_scanner": "The phishing scanner assesses supplied URL indicators. It does not assert a site is safe merely because no heuristic matched.",
    "password_checker": "The Password Security Analyzer runs locally and uses HIBP range queries only after locally hashing the password.",
    "wifi_security": "Wi-Fi audit evaluates saved-profile authentication and encryption only; it cannot prove router firmware, AP authenticity, or absence of wireless attacks.",
    "wifi_encryption": "Wireless encryption protects traffic over the radio link. WPA3 or WPA2 with AES/CCMP are preferred over legacy protocols.",
    "wifi_open_network": "Open Wi-Fi profiles lack wireless authentication and are classified high risk by the local baseline.",
    "wifi_wpa": "WPA is an older protocol; migrate to WPA2-AES/CCMP or WPA3.",
    "wifi_wpa2": "WPA2 with AES/CCMP is generally a lower-risk saved-profile configuration; WPA2 with TKIP is weaker.",
    "wifi_wpa3": "WPA3 is a modern wireless authentication protocol, though it does not prove every aspect of network security.",
    "wifi_wep": "WEP is obsolete and broken. Replace it immediately with WPA2-AES/CCMP or WPA3.",
    "wifi_audit": "Run Wi-Fi Security from the sidebar to collect saved-profile authentication and encryption metadata without requesting keys.",
    "wifi_recommendation": "Remove WEP/open profiles where possible, replace WPA/TKIP, prefer WPA3 or WPA2-AES/CCMP, and keep router firmware current.",
}

ALIASES = {
    "greeting": ["hello", "hi", "hey"],
    "help": ["help", "what can you do"],
    "open_port": ["open port", "ports are open", "network ports"],
    "port_scan": ["port scan", "scan ports"],
    "active_connections": ["active connection", "connections"],
    "threat_finding": ["last scan find", "latest scan", "scan findings"],
    "risk_score": ["risk score", "risk level", "current risk"],
    "critical_severity": ["critical finding", "critical findings"],
    "high_severity": ["high finding", "high severity"],
    "medium_severity": ["medium finding", "medium severity"],
    "low_severity": ["low finding", "low severity"],
    "wifi_audit": [
        "wifi audit",
        "wi fi audit",
        "saved wifi",
        "saved wi fi",
        "weakest wifi",
        "wep network",
        "wifi networks",
    ],
}
for key in CONCEPTS:
    ALIASES.setdefault(key, [key.replace("_definition", "").replace("_", " ")])

ALIASES["wifi_wpa3"] = ["wpa3", "wifi wpa3"]
ALIASES["wifi_wpa2"] = ["wpa2", "wifi wpa2"]
ALIASES["wifi_wep"] = ["wep", "wifi wep"]
CONCEPTS["port_scan"] = (
    "A port scan checks whether services accept connections. An open port is an observation, not proof of compromise. Vigilant Sphere host scans are available to signed-in users and restricted to loopback; review intended services and firewall scope."
)
CONCEPTS["active_connections"] = (
    "Active connections are a momentary operating-system snapshot. They do not establish beaconing, lateral movement, or exfiltration without timing, process and traffic evidence."
)
CONCEPTS["owasp"] = (
    "OWASP-oriented review starts with access control, authentication, input handling, cryptography and configuration. Test authorization on every object, use parameterized database access, escape output, retain CSRF protection, restrict uploads and outbound requests, and avoid secrets in logs. A missing header alone does not prove an exploitable vulnerability."
)
ALIASES["owasp"] = [
    "owasp",
    "web security",
    "sql injection",
    "cross site scripting",
    "xss",
    "csrf",
]
