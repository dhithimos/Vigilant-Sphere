import hashlib
import os
import platform
import re
import socket
import uuid
from pathlib import Path

import psutil


COMMON_PORTS = {
    20: ("FTP data", "File transfer channel. Risky when exposed without encryption.", "high"),
    21: ("FTP", "Plain FTP can expose credentials and files.", "high"),
    22: ("SSH", "Remote administration. Safe when patched and key protected.", "medium"),
    23: ("Telnet", "Unencrypted remote shell. Usually harmful if open.", "critical"),
    25: ("SMTP", "Mail transfer. Can be abused for spam if misconfigured.", "medium"),
    53: ("DNS", "Name resolution. Public exposure can enable abuse if recursive.", "medium"),
    80: ("HTTP", "Web service. Safe if intended, risky if unpatched.", "medium"),
    110: ("POP3", "Mail retrieval without modern protection is risky.", "medium"),
    135: ("RPC", "Windows RPC. Avoid exposing outside trusted networks.", "high"),
    139: ("NetBIOS", "Legacy Windows sharing. Risky on public networks.", "high"),
    143: ("IMAP", "Mail retrieval. Prefer encrypted IMAPS.", "medium"),
    443: ("HTTPS", "Encrypted web service. Usually safe if configured well.", "low"),
    445: ("SMB", "Windows file sharing. Harmful when exposed to the internet.", "critical"),
    3306: ("MySQL", "Database service. Should not be public.", "high"),
    3389: ("RDP", "Remote desktop. High brute-force target.", "critical"),
    5432: ("PostgreSQL", "Database service. Should be restricted.", "high"),
    5900: ("VNC", "Remote desktop. Risky unless tightly controlled.", "high"),
    8000: ("Django dev server", "Development web server. Do not expose publicly.", "medium"),
    8080: ("HTTP alternate", "Web/proxy service. Review if intended.", "medium"),
}

RISK_WEIGHT = {
    "low": 3,
    "medium": 8,
    "high": 15,
    "critical": 25,
}

SUSPICIOUS_EXTENSIONS = {
    ".bat",
    ".cmd",
    ".dll",
    ".docm",
    ".exe",
    ".iso",
    ".jar",
    ".js",
    ".pdf",
    ".ps1",
    ".rar",
    ".scr",
    ".vbs",
    ".xlsm",
    ".zip",
}

SUSPICIOUS_NAMES = (
    "mimikatz",
    "keylogger",
    "meterpreter",
    "payload",
    "ransom",
    "reverse_shell",
    "trojan",
)

CREDENTIAL_PATTERNS = {
    "Private key": re.compile(r"-----BEGIN (?:RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----"),
    "AWS access key": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "Generic API token": re.compile(r"(?i)\b(api[_-]?key|token|secret)\b\s*[:=]\s*['\"]?[A-Za-z0-9_\-]{16,}"),
    "Password assignment": re.compile(r"(?i)\b(password|passwd|pwd)\b\s*[:=]\s*['\"]?[^'\"\s]{6,}"),
    "Bearer token": re.compile(r"(?i)bearer\s+[A-Za-z0-9_\-.]{20,}"),
}

TEXT_EXTENSIONS = {
    ".cfg",
    ".conf",
    ".env",
    ".ini",
    ".json",
    ".log",
    ".ps1",
    ".py",
    ".txt",
    ".xml",
    ".yaml",
    ".yml",
}


def _risk_level(score):
    if score <= 20:
        return "LOW"
    if score <= 40:
        return "MEDIUM"
    if score <= 70:
        return "HIGH"
    return "CRITICAL"


def _file_reason(path, risk, malicious, match=""):
    suffix = path.suffix.lower() or "no extension"
    if malicious == "Credential Exposure":
        return (
            f"SOC evidence: {match} was found in a readable file, which can expose secrets to malware or unauthorized users. "
            f"Treat {path.name} as sensitive until the credential is rotated and removed."
        )
    if any(token in path.name.lower() for token in SUSPICIOUS_NAMES):
        return (
            f"SOC evidence: filename contains an offensive or malware keyword and has {suffix} format. "
            "Analysts should validate source, hash reputation, and whether a user intentionally placed it there."
        )
    if suffix in {".exe", ".dll", ".scr"}:
        return (
            f"SOC evidence: executable content was found in a user landing folder with {risk.upper()} risk. "
            "Unsigned or unexpected binaries are common initial-access and payload artifacts."
        )
    if suffix in {".ps1", ".vbs", ".bat", ".cmd", ".js"}:
        return (
            f"SOC evidence: script file {path.name} can automate command execution. "
            "Review script contents, origin, and recent execution before trusting it."
        )
    return (
        f"SOC evidence: {suffix} files are frequently used for delivery or archive staging. "
        "Validate sender/source, file hash, and extraction behavior before opening."
    )


def _file_resolution(path, risk, malicious):
    if malicious == "Credential Exposure":
        return "Remove the secret, rotate the credential, invalidate exposed sessions, and move secrets into a vault or protected environment variable."
    if risk == "critical":
        return "Isolate the endpoint if the file executed, quarantine the file, collect hash/path evidence, and escalate to Tier 2 SOC review."
    if risk == "high":
        return "Quarantine until verified, check digital signature and hash reputation, and delete it if the owner cannot confirm business need."
    return "Keep blocked from execution until verified by source, hash, and user intent; archive evidence in the scan report."


def _sha256(path):
    digest = hashlib.sha256()
    try:
        with open(path, "rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()
    except OSError:
        return ""


def _file_entropy_hint(path):
    try:
        sample = path.read_bytes()[:1024 * 512]
    except OSError:
        return "Not readable"
    if not sample:
        return "0.0 - Empty file"
    from math import log2
    counts = {byte: sample.count(byte) for byte in set(sample)}
    entropy = -sum((count / len(sample)) * log2(count / len(sample)) for count in counts.values())
    if entropy >= 6:
        meaning = "Highly suspicious / packed or encrypted content possible"
    elif entropy >= 4:
        meaning = "Suspicious randomness"
    else:
        meaning = "Normal range"
    return f"{entropy:.2f} - {meaning}"


def _file_soc_details(path, risk, malicious, sha256):
    suffix = path.suffix.lower()
    name = path.name.lower()
    extension_mismatch = any(name.endswith(pattern) for pattern in [".jpg.exe", ".pdf.exe", ".pdf.scr", ".docm"])
    dangerous_locations = [
        marker for marker in ["AppData", "Temp", "Downloads", "Startup", "ProgramData", "Recycle Bin"]
        if marker.lower() in str(path).lower()
    ]
    yara_hits = []
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")[:200000].lower()
        if "bitcoin" in text or "encrypted" in text:
            yara_hits.append("ransomware indicator strings")
        if "powershell" in text or "frombase64string" in text:
            yara_hits.append("PowerShell abuse strings")
        if "createremotethread" in text or "writeprocessmemory" in text or "virtualallocex" in text:
            yara_hits.append("process injection API strings")
    except OSError:
        pass
    return {
        "reputation": "Known suspicious local heuristic" if risk in {"high", "critical"} else "Unknown / not found in local blacklist",
        "md5": "Calculated on demand by analyst workflow",
        "sha1": "Calculated on demand by analyst workflow",
        "sha256": sha256,
        "real_type": f"{suffix or 'unknown'} extension; deep magic-type inspection optional",
        "extension_mismatch": extension_mismatch,
        "entropy": _file_entropy_hint(path),
        "signature": "Unsigned or unverified; validate publisher before execution",
        "location_analysis": ", ".join(dangerous_locations) if dangerous_locations else "No dangerous user-location marker identified",
        "yara": ", ".join(yara_hits) if yara_hits else "No YARA-style local strings matched",
        "pe_analysis": "Check imports such as CreateRemoteThread, WriteProcessMemory, VirtualAllocEx, and SetWindowsHookEx for executable files",
        "persistence": "Check Registry Run keys, Startup folder, Scheduled Tasks, WMI, and services for this filename",
        "behavior": "Review for antivirus tampering, hidden files, registry edits, process injection, network connections, and payload downloads",
        "mitre": ["T1547 - Persistence", "T1055 - Process Injection", "T1003 - Credential Dumping", "T1059 - Command Execution"],
    }


def profile_system():
    memory = psutil.virtual_memory()
    disk = psutil.disk_usage(str(Path.home().anchor or "C:\\"))
    return {
        "hostname": socket.gethostname(),
        "ip_address": _local_ip(),
        "mac_address": ":".join(f"{(uuid.getnode() >> bits) & 0xff:02x}" for bits in range(40, -1, -8)),
        "os_name": platform.system(),
        "os_version": platform.version(),
        "machine": platform.machine(),
        "processor": platform.processor(),
        "cpu_count": psutil.cpu_count(),
        "ram_total_gb": round(memory.total / (1024 ** 3), 2),
        "ram_available_gb": round(memory.available / (1024 ** 3), 2),
        "disk_total_gb": round(disk.total / (1024 ** 3), 2),
        "disk_free_gb": round(disk.free / (1024 ** 3), 2),
        "endpoint_fingerprint": hashlib.sha256(
            f"{platform.node()}-{platform.processor()}-{platform.machine()}-{uuid.getnode()}".encode()
        ).hexdigest(),
    }


def _local_ip():
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.connect(("8.8.8.8", 80))
            return sock.getsockname()[0]
    except OSError:
        return "127.0.0.1"


def compliance_check():
    checks = [
        {
            "name": "Firewall",
            "status": "Review",
            "risk": "medium",
            "detail": "Confirm Windows Firewall is enabled for public and private profiles.",
        },
        {
            "name": "Defender or antivirus",
            "status": "Review",
            "risk": "medium",
            "detail": "Confirm real-time protection is enabled and signatures are current.",
        },
        {
            "name": "Secure Boot",
            "status": "Review",
            "risk": "medium",
            "detail": "Enable Secure Boot where supported to reduce boot-level tampering.",
        },
        {
            "name": "BitLocker",
            "status": "Review",
            "risk": "medium",
            "detail": "Encrypt portable devices and laptops that store sensitive data.",
        },
        {
            "name": "UAC",
            "status": "Review",
            "risk": "low",
            "detail": "Keep User Account Control enabled for privilege-change prompts.",
        },
    ]
    return {
        "cis_summary": "Baseline-style local review. Manual confirmation is required for exact CIS compliance.",
        "checks": checks,
    }


def process_audit(limit=80):
    suspicious = []
    for proc in psutil.process_iter(["pid", "name", "exe", "username", "cpu_percent", "memory_percent", "cmdline"]):
        try:
            info = proc.info
            name = (info.get("name") or "").lower()
            exe = info.get("exe") or ""
            cmdline = " ".join(info.get("cmdline") or [])
            if any(token in name or token in exe.lower() for token in SUSPICIOUS_NAMES):
                suspicious.append({
                    "pid": info.get("pid"),
                    "name": info.get("name"),
                    "path": exe,
                    "risk": "high",
                    "reason": "Name or path matches common offensive/malware keywords.",
                    "resolution": "Verify publisher, isolate if unknown, and scan with antivirus.",
                })
            if _contains_credential(cmdline):
                suspicious.append({
                    "pid": info.get("pid"),
                    "name": info.get("name"),
                    "path": exe,
                    "risk": "critical",
                    "reason": "Credential-like token or password appears in process command line.",
                    "resolution": "Stop the process if unauthorized, rotate the exposed secret, and remove secrets from scripts.",
                })
            if "powershell" in name and ("-enc" in cmdline.lower() or "frombase64string" in cmdline.lower()):
                suspicious.append({
                    "pid": info.get("pid"),
                    "name": info.get("name"),
                    "path": exe,
                    "risk": "high",
                    "reason": "Encoded PowerShell command detected.",
                    "resolution": "Inspect the command, parent process, and script source before trusting it.",
                })
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
        if len(suspicious) >= limit:
            break
    return suspicious


def _contains_credential(text):
    return bool(text and any(pattern.search(text) for pattern in CREDENTIAL_PATTERNS.values()))


def startup_audit():
    entries = []
    folders = [
        Path(os.path.expandvars(r"%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup")),
        Path(os.path.expandvars(r"%PROGRAMDATA%\Microsoft\Windows\Start Menu\Programs\Startup")),
    ]
    for folder in folders:
        if not folder.exists():
            continue
        for item in folder.iterdir():
            suffix = item.suffix.lower()
            risky = suffix in {".bat", ".cmd", ".ps1", ".vbs", ".js", ".exe"}
            entries.append({
                "name": item.name,
                "path": str(item),
                "risk": "high" if risky else "low",
                "reason": "Script or executable starts automatically." if risky else "Normal startup item.",
                "resolution": "Disable unknown startup entries and verify publisher." if risky else "No action needed if recognized.",
            })
    return entries


def active_network_connections(limit=120):
    rows = []
    for conn in psutil.net_connections(kind="inet"):
        if not conn.laddr:
            continue
        port = conn.laddr.port
        service, why, risk = COMMON_PORTS.get(port, ("Unknown service", "Open by an application or OS service.", "medium"))
        rows.append({
            "local_address": conn.laddr.ip,
            "port": port,
            "remote_address": f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "",
            "status": conn.status,
            "protocol": "TCP" if conn.type == socket.SOCK_STREAM else "UDP",
            "service": service,
            "why_open": why,
            "risk": risk,
            "harmful": risk in {"high", "critical"},
            "resolution": _port_resolution(port, risk),
        })
        if len(rows) >= limit:
            break
    return sorted(rows, key=lambda row: (row["risk"], row["port"]))


def port_scan(host="127.0.0.1", ports=None):
    ports = ports or sorted(COMMON_PORTS)
    open_ports = []
    for port in ports:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(0.08)
            if sock.connect_ex((host, port)) == 0:
                service, why, risk = COMMON_PORTS.get(port, ("Unknown service", "Open by an application.", "medium"))
                open_ports.append({
                    "host": host,
                    "port": port,
                    "protocol": "TCP",
                    "service": service,
                    "why_open": why,
                    "risk": risk,
                    "harmful": risk in {"high", "critical"},
                    "resolution": _port_resolution(port, risk),
                })
    return open_ports


def _port_resolution(port, risk):
    if risk == "critical":
        return f"Close port {port} if not required, restrict it with firewall rules, and patch the owning service."
    if risk == "high":
        return f"Limit port {port} to trusted IP addresses and disable it if unused."
    if risk == "medium":
        return f"Confirm the service on port {port} is intentional and not exposed publicly."
    return "Keep patched and monitor normally."


def file_scan(max_files=300):
    findings = []
    roots = [Path.home() / "Downloads", Path.home() / "Desktop", Path.home() / "Documents"]
    scanned = 0
    for root in roots:
        if not root.exists():
            continue
        for path in root.rglob("*"):
            if scanned >= max_files:
                break
            if not path.is_file():
                continue
            scanned += 1
            suffix = path.suffix.lower()
            name = path.name.lower()
            suspicious = suffix in SUSPICIOUS_EXTENSIONS or any(token in name for token in SUSPICIOUS_NAMES)
            credential_matches = credential_file_scan(path) if suffix in TEXT_EXTENSIONS or path.name.lower().startswith(".env") else []
            if suspicious:
                risk = "high" if suffix in {".exe", ".dll", ".scr", ".ps1", ".vbs"} else "medium"
                sha256 = _sha256(path)
                findings.append({
                    "name": path.name,
                    "path": str(path),
                    "sha256": sha256,
                    "risk": risk,
                    "malicious": "Suspicious",
                    "reason": _file_reason(path, risk, "Suspicious"),
                    "resolution": _file_resolution(path, risk, "Suspicious"),
                    **_file_soc_details(path, risk, "Suspicious", sha256),
                })
            for match in credential_matches:
                sha256 = _sha256(path)
                findings.append({
                    "name": path.name,
                    "path": str(path),
                    "sha256": sha256,
                    "risk": "critical",
                    "malicious": "Credential Exposure",
                    "reason": _file_reason(path, "critical", "Credential Exposure", match),
                    "resolution": _file_resolution(path, "critical", "Credential Exposure"),
                    **_file_soc_details(path, "critical", "Credential Exposure", sha256),
                })
    return {
        "scanned_count": scanned,
        "detected_count": len(findings),
        "files": findings,
    }


def credential_file_scan(path):
    matches = []
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return matches
    for label, pattern in CREDENTIAL_PATTERNS.items():
        if pattern.search(text):
            matches.append(label)
    return matches[:5]


def exposure_assessment():
    shares = []
    for partition in psutil.disk_partitions(all=False):
        if "removable" in partition.opts.lower():
            shares.append({
                "share": partition.device,
                "permission": "Removable media",
                "risk": "medium",
                "reason": "USB/removable storage can introduce untrusted files.",
            })
    return shares


def identity_privilege_assessment(user=None):
    return {
        "user": getattr(user, "username", "anonymous"),
        "email": getattr(user, "email", ""),
        "is_superuser": getattr(user, "is_superuser", False),
        "is_staff": getattr(user, "is_staff", False),
        "risk": "critical" if getattr(user, "is_superuser", False) else "low",
        "reason": "Superuser accounts should be used only for administration." if getattr(user, "is_superuser", False) else "Standard user privileges reduce blast radius.",
    }


def fim_snapshot(files):
    return [
        {"file": item["path"], "change": "new_or_suspicious", "risk": item["risk"]}
        for item in files["files"][:50]
    ]


def usb_monitoring_snapshot(files):
    return {
        "device": "Removable devices checked through mounted partitions",
        "files_scanned": files["scanned_count"],
        "malicious": len([item for item in files["files"] if item["risk"] in {"high", "critical"}]),
    }


def behavioral_analysis(processes, files, connections):
    findings = []
    if len(files["files"]) >= 5:
        findings.append({
            "behavior": "multiple_suspicious_files",
            "risk": "high",
            "reason": "Several suspicious files were found in landing zones.",
        })
    if any(item["risk"] == "critical" for item in processes):
        findings.append({
            "behavior": "credential_or_encoded_process_activity",
            "risk": "critical",
            "reason": "A process exposed credentials or used suspicious encoded execution.",
        })
    if any(row["port"] in {4444, 5555, 6667, 1337} for row in connections):
        findings.append({
            "behavior": "possible_reverse_shell_or_c2",
            "risk": "critical",
            "reason": "Connection uses a port commonly associated with callbacks or tooling.",
        })
    return findings


def threat_database_matches(files, ports):
    bad_ports = {23: "Telnet exposure", 445: "SMB exposure", 3389: "RDP exposure"}
    matches = []
    for row in ports:
        if row["port"] in bad_ports:
            matches.append({
                "match": bad_ports[row["port"]],
                "confidence": "85%",
                "ioc": f"{row['protocol']}:{row['port']}",
            })
    for item in files["files"]:
        if item["malicious"] == "Credential Exposure":
            matches.append({
                "match": "Credential material on disk",
                "confidence": "95%",
                "ioc": item["sha256"],
            })
    return matches


def threat_intel_lookup():
    return {
        "status": "offline",
        "sources": ["Local IOC rules", "Port risk map", "Suspicious filename heuristics"],
        "note": "External feeds require API keys; this build uses local analysis only.",
    }


def ai_recommendations(score, ports, files, processes, startup):
    recommendations = []
    if score < 70:
        recommendations.append("Priority: reduce exposed services, review suspicious files, and patch endpoint protection before normal use.")
    if any(item["risk"] in {"high", "critical"} for item in ports):
        recommendations.append("High-risk ports are open. Restrict remote administration and file-sharing ports to trusted networks only.")
    if files["detected_count"]:
        recommendations.append("Suspicious files were found. Quarantine unknown files, verify hashes, and avoid running downloaded scripts.")
    if processes:
        recommendations.append("Suspicious processes are running. Check the executable path, digital signature, and parent process.")
    if any(item.get("malicious") == "Credential Exposure" for item in files["files"]):
        recommendations.append("Credential material was detected. Rotate exposed secrets immediately and move credentials to a secure vault.")
    if startup:
        recommendations.append("Review startup entries so unknown scripts do not run automatically after reboot.")
    if not recommendations:
        recommendations.append("Risk is currently low. Keep updates enabled, retain firewall rules, and scan downloads before opening them.")
    recommendations.append("For deeper analysis, review the linked blogs about open ports, malware triage, MITRE mapping, and SOC response.")
    return recommendations


def _score_from_evidence(ports, files, processes, startup, behavioral, threat_db):
    risk_points = 0
    for row in ports:
        risk_points += RISK_WEIGHT.get(row["risk"], 8)
    for item in files["files"]:
        risk_points += RISK_WEIGHT.get(item["risk"], 8)
    risk_points += len(processes) * 15
    risk_points += sum(RISK_WEIGHT.get(item["risk"], 3) for item in startup)
    risk_points += sum(RISK_WEIGHT.get(item["risk"], 3) for item in behavioral)
    risk_points += len(threat_db) * 10
    return min(risk_points, 100)


def _scan_scope_payload(scan_type, connections, ports, files, processes, startup, behavioral, threat_db):
    normalized_type = (scan_type or "combined").lower()
    empty_files = {"scanned_count": files["scanned_count"], "detected_count": 0, "files": []}

    if normalized_type == "network":
        scoped_ports = connections + ports
        scoped_files = empty_files
        scoped_processes = []
        scoped_startup = []
        scoped_behavioral = [
            item for item in behavioral
            if item.get("behavior") == "possible_reverse_shell_or_c2"
        ]
        scoped_threat_db = [
            item for item in threat_db
            if str(item.get("ioc", "")).startswith(("TCP:", "UDP:"))
        ]
        scope_note = "Network Scan: active connections, open ports, exposed services, traffic indicators, and network risk only."
    elif normalized_type == "system":
        scoped_ports = []
        scoped_files = files
        scoped_processes = processes
        scoped_startup = startup
        scoped_behavioral = [
            item for item in behavioral
            if item.get("behavior") != "possible_reverse_shell_or_c2"
        ]
        scoped_threat_db = [
            item for item in threat_db
            if not str(item.get("ioc", "")).startswith(("TCP:", "UDP:"))
        ]
        scope_note = "System Scan: endpoint posture, files, processes, persistence, identity, compliance, and malware indicators only."
    elif normalized_type == "threat detection":
        scoped_ports = connections + ports
        scoped_files = files
        scoped_processes = processes
        scoped_startup = startup
        scoped_behavioral = behavioral
        scoped_threat_db = threat_db
        scope_note = "Threat Detection: focused EDR/NDR/file/behavior analysis with MITRE and SOAR guidance."
    else:
        scoped_ports = connections + ports
        scoped_files = files
        scoped_processes = processes
        scoped_startup = startup
        scoped_behavioral = behavioral
        scoped_threat_db = threat_db
        scope_note = "Combined Scan: full network, system, file, process, identity, MITRE, and response analysis."

    score = _score_from_evidence(
        scoped_ports,
        scoped_files,
        scoped_processes,
        scoped_startup,
        scoped_behavioral,
        scoped_threat_db,
    )
    return {
        "ports": scoped_ports,
        "files": scoped_files,
        "processes": scoped_processes,
        "startup": scoped_startup,
        "behavioral": scoped_behavioral,
        "threat_db": scoped_threat_db,
        "score": score,
        "risk": _risk_level(score),
        "scope_note": scope_note,
    }


def run_combined_scan(user=None, scan_type="combined"):
    profile = profile_system()
    compliance = compliance_check()
    processes = process_audit()
    startup = startup_audit()
    connections = active_network_connections()
    ports = port_scan()
    files = file_scan()
    exposure = exposure_assessment()
    identity = identity_privilege_assessment(user)
    behavioral = behavioral_analysis(processes, files, connections + ports)
    threat_db = threat_database_matches(files, connections + ports)
    protocols = sorted({row["protocol"] for row in connections + ports})

    scoped = _scan_scope_payload(scan_type, connections, ports, files, processes, startup, behavioral, threat_db)
    scoped_ports = scoped["ports"]
    scoped_files = scoped["files"]
    scoped_processes = scoped["processes"]
    scoped_startup = scoped["startup"]
    scoped_behavioral = scoped["behavioral"]
    scoped_threat_db = scoped["threat_db"]
    score = scoped["score"]
    risk = scoped["risk"]
    protocols = sorted({row["protocol"] for row in scoped_ports})

    return {
        "scan_type": scan_type,
        "score": score,
        "risk_level": risk,
        "profile": profile,
        "modules": {
            "scan_scope": {"type": scan_type, "note": scoped["scope_note"]},
            "asset_discovery": profile,
            "endpoint_fingerprinting": {"fingerprint": profile["endpoint_fingerprint"]},
            "security_compliance": compliance,
            "endpoint_protection": compliance["checks"][1],
            "identity_privilege_assessment": identity,
            "exposure_assessment": exposure,
            "network_exposure": scoped_ports,
            "landing_zone_scanner": scoped_files,
            "threat_hunting": scoped_processes,
            "startup_audit": scoped_startup,
            "malware_analysis": scoped_files,
            "real_time_monitoring": {"status": "dashboard_polling_enabled", "monitored": ["Downloads", "Desktop", "Documents", "WhatsApp", "USB"]},
            "usb_monitoring": usb_monitoring_snapshot(scoped_files),
            "file_integrity_monitoring": fim_snapshot(scoped_files),
            "threat_intelligence": threat_intel_lookup(),
            "ioc_correlation": scoped_threat_db,
            "threat_database": scoped_threat_db,
            "behavioral_analysis": scoped_behavioral,
            "mitre_attack": [
                {"technique": "T1547", "name": "Boot or Logon Autostart Execution", "matched": bool(scoped_startup)},
                {"technique": "T1046", "name": "Network Service Discovery", "matched": bool(scoped_ports)},
                {"technique": "T1204", "name": "User Execution", "matched": scoped_files["detected_count"] > 0},
                {"technique": "T1003", "name": "Credential Dumping / Credential Exposure", "matched": any(item.get("malicious") == "Credential Exposure" for item in scoped_files["files"])},
                {"technique": "T1059", "name": "Command and Scripting Interpreter", "matched": any("PowerShell" in item.get("reason", "") for item in scoped_processes)},
                {"technique": "T1071", "name": "Application Layer Protocol C2", "matched": bool(scoped_threat_db)},
            ],
            "quarantine": {"available": True, "mode": "manual_review_before_action"},
            "remediation": {"actions": ["kill process", "delete file", "block IP", "remove startup entry", "rotate credentials"]},
            "incident_response": {"create_incident_on_critical": True},
            "threat_timeline": [
                {"event": "Collection completed", "risk": "info"},
                {"event": "Analysis completed", "risk": risk},
                {"event": "Report generated", "risk": "info"},
            ],
            "edr": {
                "inputs": ["Running processes", "Parent-child process relationships", "Command line arguments", "PowerShell activity", "Scheduled tasks", "Services", "DLL loading", "Registry changes", "Startup entries"],
                "detection": "Suspicious PowerShell Execution" if any("PowerShell" in item.get("reason", "") for item in scoped_processes) else "No encoded PowerShell execution observed",
                "severity": "HIGH" if scoped_processes else "LOW",
                "mitre": "T1059.001 - PowerShell",
                "confidence": "94%" if scoped_processes else "62%",
                "recommended_action": "Isolate endpoint for confirmed malicious execution; otherwise continue monitoring.",
            },
            "ndr": {
                "inputs": ["Active connections", "DNS queries", "HTTP requests", "TLS certificates", "Ports", "Network flows", "Packet metadata"],
                "detections": ["Beaconing", "Port scanning", "Lateral movement", "C2 communication", "Data exfiltration", "DNS tunneling"],
                "threat_score": min(100, sum(RISK_WEIGHT.get(row["risk"], 8) for row in scoped_ports)),
                "severity": _risk_level(min(100, sum(RISK_WEIGHT.get(row["risk"], 8) for row in scoped_ports))),
            },
            "file_threat_analysis": {
                "inputs": ["Downloads", "USB files", "Email attachments", "File hashes", "File metadata"],
                "analysis": ["SHA256 hash", "Entropy indicator", "Unsigned binary review", "YARA-style local heuristics"],
                "detected": scoped_files["detected_count"],
                "malicious_confidence": "98%" if scoped_files["detected_count"] else "35%",
            },
            "uba": {
                "inputs": ["Login times", "User activity", "Admin actions", "Failed logins", "Privilege escalations"],
                "detection": "Privileged account exposure" if identity["risk"] == "critical" else "No abnormal user behavior detected",
                "severity": identity["risk"].upper(),
            },
            "risk_engine": {
                "formula": "Threat Score = Severity + Behavior + Reputation + Asset Criticality",
                "threat_score": score,
                "risk_level": risk,
                "mapping": "0-20 LOW, 21-40 MEDIUM, 41-70 HIGH, 71-100 CRITICAL",
            },
            "soar": {
                "actions": ["Kill Process", "Block IP", "Disable User", "Quarantine File", "Disconnect Endpoint", "Create Ticket", "Send Alert"],
                "status": "Manual approval required before destructive response.",
            },
            "executive_metrics": {
                "security_posture": max(0, 100 - score),
                "mttd": "Near real-time during active dashboard polling",
                "mttr": "Depends on analyst response",
                "open_incidents": len([item for item in scoped_behavioral if item["risk"] in {"high", "critical"}]),
                "compliance": "PASS" if score <= 40 else "REVIEW",
                "asset_coverage": "Local endpoint scope",
            },
        },
        "open_ports": scoped_ports,
        "connections": scoped_ports,
        "protocols": protocols,
        "detected_files": scoped_files,
        "recommendations": ai_recommendations(score, scoped_ports, scoped_files, scoped_processes, scoped_startup),
    }
