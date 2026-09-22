"""Distinct evidence contracts; shared storage and transport, not shared detection logic."""

from collections import Counter
import ipaddress
import math
import re
import unicodedata
from urllib.parse import urlsplit, urlunsplit, parse_qs, unquote
from django.core.files.uploadedfile import SimpleUploadedFile
from django.utils import timezone
from .ioc_correlation import (
    correlation_payload,
    normalize_indicator,
    persist_provider_results,
)
from myapp.scanners.target import (
    url_details,
    dns_scan,
    http_scan,
    classify_target,
)


def entropy(value):
    return (
        round(
            -sum(
                (n / len(value)) * math.log2(n / len(value))
                for n in Counter(value).values()
            ),
            3,
        )
        if value
        else 0
    )


def finding(title, evidence, points, recommendation, category, confidence="medium"):
    return dict(
        title=title,
        evidence=evidence,
        points=points,
        severity="HIGH"
        if points >= 35
        else "MEDIUM"
        if points >= 15
        else "LOW"
        if points
        else "INFO",
        confidence=confidence,
        description="Observed indicator requiring contextual review; not a confirmed compromise.",
        recommendation=recommendation,
        category=category,
        source="local " + category,
    )


def finish(scanner, target, details, findings, state="COMPLETED", sources=None):
    factors = [dict(title=f["title"], points=f.get("points", 0)) for f in findings]
    score = min(100, sum(x["points"] for x in factors))
    return dict(
        scanner=scanner,
        target=target,
        status=state,
        observed_at=timezone.now().isoformat(),
        risk_score=score,
        risk_factors=factors,
        verdict="Requires Review"
        if findings
        else "Insufficient Evidence"
        if state in {"UNAVAILABLE", "FAILED"}
        else "Not Observed",
        findings=findings,
        evidence=[x["evidence"] for x in findings],
        recommendations=list(dict.fromkeys(x["recommendation"] for x in findings)),
        sources=sources or [],
        assessment="Deterministic prioritization, not a probability or safety guarantee.",
        **details,
    )


def edit_distance(a, b):
    # Bounded domain labels, including adjacent transposition.
    a, b = a[:63], b[:63]
    matrix = [list(range(len(b) + 1))]
    for i, x in enumerate(a, 1):
        row = [i]
        for j, y in enumerate(b, 1):
            value = min(
                row[j - 1] + 1, matrix[i - 1][j] + 1, matrix[i - 1][j - 1] + (x != y)
            )
            if i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                value = min(value, matrix[i - 2][j - 2] + 1)
            row.append(value)
        matrix.append(row)
    return matrix[-1][-1]


def phishing_intelligence(raw):
    raw = raw.strip()
    parts = urlsplit(raw if "://" in raw else "https://" + raw)
    if (
        parts.scheme not in {"http", "https"}
        or not parts.hostname
        or parts.username is not None
        or any(c.isspace() or ord(c) < 32 for c in raw)
    ):
        raise ValueError("Enter an HTTP(S) URL without credentials or whitespace")
    host = parts.hostname.encode("idna").decode("ascii").lower().rstrip(".")
    authority = ("[" + host + "]" if ":" in host else host) + (
        " :".strip() + str(parts.port) if parts.port else ""
    )
    url = urlunsplit(
        (parts.scheme, authority, parts.path or "/", parts.query, parts.fragment)
    )
    parts = urlsplit(url)
    try:
        unicode_host = host.encode("ascii").decode("idna")
    except (UnicodeError, ValueError):
        unicode_host = host
    normalized = unicodedata.normalize("NFKC", unicode_host)
    scripts = sorted(
        {unicodedata.name(c, "").split(" ")[0] for c in normalized if c.isalpha()}
    )
    # A deliberately limited, documented confusable set; never advertised as complete Unicode detection.
    confusables = {
        "а": "a",
        "е": "e",
        "о": "o",
        "р": "p",
        "с": "c",
        "х": "x",
        "у": "y",
        "і": "i",
        "ӏ": "l",
        "ο": "o",
        "α": "a",
    }
    substitutions = [
        {"character": c, "resembles": confusables[c]}
        for c in sorted(set(normalized))
        if c in confusables
    ]
    brands = {
        "paypal": "paypal.com",
        "microsoft": "microsoft.com",
        "google": "google.com",
        "apple": "apple.com",
        "amazon": "amazon.com",
    }
    labels = normalized.split(".")
    similar = []
    impersonation = []
    findings = []
    for brand, official in brands.items():
        if host == official or host.endswith("." + official):
            continue
        for label in labels[:-1]:
            distance = edit_distance(label, brand)
            if 0 < distance <= 2 and len(label) >= 4:
                similar.append(
                    {
                        "label": label,
                        "reference": brand,
                        "edit_distance": distance,
                        "methods": "substitution/insertion/deletion/transposition",
                    }
                )
            if brand in label:
                impersonation.append(
                    {
                        "label": label,
                        "reference_domain": official,
                        "state": "Potential Indicator",
                    }
                )
    if similar:
        findings.append(
            finding(
                "Domain similarity indicator",
                similar[:10],
                12,
                "Verify the domain through an independently known channel.",
                "typosquatting",
            )
        )
    if impersonation:
        findings.append(
            finding(
                "Brand-like text outside reference domain",
                impersonation,
                10,
                "Do not infer ownership from brand-like text.",
                "brand similarity",
            )
        )
    if substitutions and len(scripts) > 1:
        findings.append(
            finding(
                "Mixed-script confusable hostname",
                substitutions,
                15,
                "Inspect the Unicode and ASCII hostname before providing credentials.",
                "homograph",
            )
        )
    try:
        lexical = url_details(url)
    except ValueError:
        lexical = {
            "scheme": parts.scheme,
            "hostname": host,
            "port": parts.port,
            "normalized_url": url,
            "length": len(url),
            "network_policy": "Nonstandard ports are analyzed lexically but never fetched",
        }
    lexical["suspicious_tld_indicator"] = host.rsplit(".", 1)[-1] in {
        "zip",
        "click",
        "top",
        "work",
    }
    lexical["suspicious_parameters"] = [
        key
        for key in parse_qs(parts.query)
        if key.lower()
        in {"password", "passwd", "token", "redirect", "returnurl", "continue"}
    ]
    lexical["note"] = (
        "TLD and parameter names are weak indicators, not proof of phishing"
    )
    if parts.port and parts.port not in {80, 443}:
        findings.append(
            finding(
                "Unusual web port",
                {"port": parts.port},
                5,
                "Confirm the intended service and port.",
                "URL structure",
                "low",
            )
        )
    components = {label: entropy(label) for label in labels if label}
    from myapp.scanners.target import module_result

    try:
        network = http_scan(url)
    except ValueError:
        network = [
            module_result(
                "http", url, "url", "blocked", errors=["Target blocked by fetch policy"]
            )
        ]
    try:
        dns = dns_scan(host)
    except Exception:
        dns = module_result(
            "dns", host, "domain", "unavailable", data={"state": "Source unavailable"}
        )
    for module in network:
        for item in module.get("findings", []):
            findings.append(
                dict(item, points=15 if item.get("severity") == "MEDIUM" else 5)
            )
    available = any(
        x.get("status") == "success" and x.get("module") == "http" for x in network
    )
    return finish(
        "phishing_intelligence",
        url,
        dict(
            url_analysis=dict(
                lexical,
                hostname=host,
                unicode_hostname=unicode_host,
                subdomain_depth=max(0, len(labels) - 2),
                path=parts.path,
                query_keys=list(parse_qs(parts.query))[:50],
                encoded_characters=bool(re.search(r"%[0-9a-fA-F]{2}", raw)),
                decoded_path=unquote(parts.path)[:2048],
            ),
            entropy_analysis={
                "components": components,
                "meaning": "Entropy alone is not maliciousness evidence",
            },
            typosquatting={"candidates": similar[:20]},
            homograph_analysis={
                "normalized": normalized,
                "scripts": scripts,
                "confusables": substitutions,
                "coverage": "Limited local confusable-character set",
            },
            brand_impersonation={
                "state": "Potential Indicator" if impersonation else "Not Observed",
                "evidence": impersonation,
            },
            dns_analysis=dns,
            mx_analysis=dns.get("data", {}).get("MX", {"state": "Source unavailable"}),
            http_analysis=network,
        ),
        findings,
        "COMPLETED" if available and dns["status"] == "success" else "PARTIAL",
        ["local URL heuristics", "bounded public HTTP", "DNS resolver"],
    )


def static_file_analysis(uploaded):
    from django.conf import settings
    from myapp.scanners.file_analysis import analyze_uploaded
    from myapp.scanners.binary_metadata import binary_metadata

    data = uploaded.read(settings.MAX_UPLOAD_SIZE + 1)
    if len(data) > settings.MAX_UPLOAD_SIZE:
        raise ValueError("Upload exceeds size limit")
    name = uploaded.name.replace("\\", "/").rsplit("/", 1)[-1][:180]
    modules = analyze_uploaded(SimpleUploadedFile(name, data))
    by_name = {x["module"]: x.get("data", {}) for x in modules}
    pe, elf = binary_metadata(data)
    metadata = by_name.get("file_metadata", {})
    extension = metadata.get("extension", "")
    expected = {
        ".exe": b"MZ",
        ".dll": b"MZ",
        ".pdf": b"%PDF-",
        ".png": b"\x89PNG\r\n\x1a\n",
        ".zip": b"PK",
    }
    mismatch = extension in expected and not data.startswith(expected[extension])
    metadata["type_mismatch"] = mismatch
    findings = []
    for module in modules:
        for item in module.get("findings", []):
            findings.append(
                dict(
                    item,
                    points=5
                    if "entropy" in item["title"].lower()
                    else 15
                    if item.get("severity") == "MEDIUM"
                    else 5,
                )
            )
    if mismatch:
        findings.append(
            finding(
                "Extension and signature mismatch",
                {"extension": extension, "signature": data[:16].hex()},
                8,
                "Verify the file origin and format without executing it.",
                "file signature",
            )
        )
    return finish(
        "static_file_analysis",
        name,
        dict(
            file_metadata=metadata,
            hashes=by_name.get("hashes", {}),
            entropy={
                "bits_per_byte": entropy(data),
                "interpretation": "Packing, compression or encryption can raise entropy; not a malware verdict",
            },
            pe_analysis=pe,
            elf_analysis=elf,
            strings=by_name.get("strings", {}),
            fuzzy_hash={"state": "Fuzzy hashing unavailable"},
            indicators=by_name.get("iocs", {}),
            static_modules=modules,
        ),
        findings,
        sources=["bounded in-memory static analysis"],
    )


def collect_process_snapshot():
    import psutil

    rows = []
    inaccessible = 0
    for process in psutil.process_iter(["pid", "ppid", "name", "exe", "cmdline"]):
        if len(rows) >= 500:
            break
        try:
            rows.append(process.info)
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            inaccessible += 1
    return rows, inaccessible


def threat_detection(processes=None):
    inaccessible = 0
    if processes is None:
        processes, inaccessible = collect_process_snapshot()
    by_pid = {x.get("pid"): x for x in processes}
    findings = []
    rules = []
    for process in processes[:500]:
        name = str(process.get("name", "")).lower()
        cmd = process.get("cmdline", [])
        cmd = " ".join(cmd) if isinstance(cmd, list) else str(cmd)
        parent = str(by_pid.get(process.get("ppid"), {}).get("name", "")).lower()
        evidence = {
            "pid": process.get("pid"),
            "process_name": name,
            "parent_name": parent,
            "ppid": process.get("ppid"),
        }
        matches = []
        if name in {"powershell.exe", "powershell", "pwsh", "pwsh.exe"} and re.search(
            r"(?i)(?:^|\s)-(?:enc|encodedcommand)\s+\S+", cmd
        ):
            matches.append(
                (
                    "VS-PS-ENC-001",
                    "Encoded PowerShell execution syntax",
                    30,
                    "T1059.001",
                    "Execution",
                )
            )
        if parent in {"winword.exe", "excel.exe", "outlook.exe"} and name in {
            "cmd.exe",
            "powershell.exe",
            "pwsh.exe",
            "wscript.exe",
        }:
            matches.append(
                (
                    "VS-OFFICE-CHILD-001",
                    "Office process spawned a command interpreter",
                    35,
                    "T1059.001"
                    if "powershell" in name or "pwsh" in name
                    else "T1059.003"
                    if name == "cmd.exe"
                    else "",
                    "Execution",
                )
            )
        path = str(process.get("exe") or "").lower().replace("\\", "/")
        if (
            name in {"svchost.exe", "lsass.exe", "services.exe"}
            and path
            and not re.search(r"/windows/(?:system32|syswow64)/", path)
        ):
            matches.append(
                (
                    "VS-PATH-001",
                    "System process name outside expected Windows directory",
                    20,
                    "T1036",
                    "Defense Evasion",
                )
            )
        for rule, title, points, technique, tactic in matches:
            ev = dict(evidence, rule_id=rule, matched_syntax=title)
            row = finding(
                title,
                ev,
                points,
                "Validate executable origin, signer and parent-child context. No automatic response is executed.",
                "behavioral rule",
            )
            from myapp.mitre_data import dataset, tactic_name_and_slug

            reference = next(
                (x for x in dataset()["techniques"] if x["id"] == technique), None
            )
            row.update(
                mitre_technique=technique if reference else "",
                mitre_tactic=", ".join(
                    tactic_name_and_slug(x)["name"] for x in reference["tactics"]
                )
                if reference
                else "",
            )
            findings.append(row)
            rules.append(
                dict(
                    rule_id=rule,
                    category="execution",
                    matched=True,
                    confidence=0.6,
                    evidence=ev,
                )
            )
    return finish(
        "threat_detection",
        "Local process snapshot",
        dict(
            behavioral_rules=rules,
            rule_engine="Internal deterministic rules; not YARA",
            process_summary={
                "observed": len(processes),
                "access_errors": inaccessible,
                "limit": 500,
            },
            persistence={
                "state": "Insufficient Evidence",
                "reason": "Snapshot does not establish persistence",
            },
            beaconing={
                "state": "Insufficient Evidence",
                "reason": "Timestamped connection sequences are required",
            },
            command_privacy="Raw command arguments are evaluated in memory and are not retained",
        ),
        findings,
        "COMPLETED" if processes else "UNAVAILABLE",
        ["local psutil process snapshot"],
    )


def threat_intelligence(raw):
    from myapp.threat_intel import provider_results

    kind, target = classify_target(raw)
    if kind not in {"ip", "domain", "url", "hash"}:
        raise ValueError("Enter an IP address, domain, URL or hash")
    if kind == "ip" and not ipaddress.ip_address(target).is_global:
        raise ValueError("External reputation lookup requires a public IP address")
    responses = provider_results(target, kind)
    persist_provider_results(responses, target, kind)
    findings = []
    for response in responses:
        if response.get("status") != "success":
            continue
        data = response.get("data", {})
        stats = data.get("detections", {})
        malicious = stats.get("malicious", 0)
        abuse = data.get("report", {}).get("abuseConfidenceScore", 0)
        if isinstance(malicious, int) and malicious > 0:
            findings.append(
                finding(
                    "Reported malicious reputation votes",
                    {
                        "source": response["provider"],
                        "votes": malicious,
                        "statistics": stats,
                    },
                    min(50, malicious * 5),
                    "Review the original source, timestamp and disagreement; reputation is not proof.",
                    "reputation",
                )
            )
        if isinstance(abuse, int) and abuse > 0:
            findings.append(
                finding(
                    "Reported abuse confidence",
                    {"source": response["provider"], "score": abuse},
                    round(abuse * 0.4),
                    "Validate the age and context of reported activity.",
                    "IP reputation",
                )
            )
    return finish(
        "threat_intelligence",
        target,
        dict(
            indicator_type=kind,
            reputation_sources=responses,
            attribution={
                "actor": "Unknown",
                "confidence": "Unknown",
                "source": "Not Available",
                "related_techniques": [],
                "references": [],
            },
        ),
        findings,
        "COMPLETED"
        if any(x.get("status") == "success" for x in responses)
        else "UNAVAILABLE",
        ["configured external reputation providers"],
    )


def detect_ioc(raw):
    value = raw.strip()
    if not value or len(value) > 1000:
        raise ValueError("Enter a bounded IOC value")
    if re.fullmatch(r"[a-fA-F0-9]{32}|[a-fA-F0-9]{64}", value):
        kind = "HASH"
    elif re.match(r"(?i)^(?:HKLM|HKCU|HKEY_[A-Z_]+)\\", value):
        kind = "REGISTRY"
        value = value.replace("/", "\\").casefold()
    elif re.match(r"^[A-Za-z]:[\\/]|^/", value):
        kind = "FILENAME"
        value = value.replace("\\", "/")
        value = value.casefold() if re.match(r"^[a-zA-Z]:", value) else value
    else:
        try:
            ipaddress.ip_address(value)
            kind = "IP"
        except ValueError:
            kind = "URL" if "://" in value else "DOMAIN"
    return normalize_indicator(kind, value)


def ioc_correlation(raw, user):
    from myapp.models import Finding

    indicator = detect_ioc(raw)
    payload = correlation_payload(indicator, user)
    owned = (
        Finding.objects.filter(job__requested_by=user)
        .select_related("asset")
        .prefetch_related("incidents")
        .order_by("-timestamp")[:1000]
    )
    related = []
    incidents = {}
    assets = {}
    mitre = []
    for row in owned:
        if not isinstance(row.ioc, dict) or indicator["value"] not in row.ioc.get(
            "indicator_values", []
        ):
            continue
        related.append({"id": row.pk, "title": row.title, "severity": row.severity})
        for incident in row.incidents.all():
            if incident.owner_id == user.pk:
                incidents[incident.pk] = {"id": incident.pk, "title": incident.title}
        if row.asset_id:
            assets[row.asset_id] = {"id": row.asset_id, "hostname": row.asset.hostname}
        if row.mitre_technique:
            mitre.append(
                {
                    "technique": row.mitre_technique,
                    "finding_id": row.pk,
                    "confidence": row.confidence,
                }
            )
        if len(related) >= 20:
            break
    findings = [
        finding(
            "Exact stored indicator match",
            {"value": x["value"], "source": x["source"], "confidence": x["confidence"]},
            min(30, round(x["confidence"] * 0.3)),
            "Validate the source and linked observations before escalating.",
            "IOC correlation",
        )
        for x in payload["matches"]
    ]
    return finish(
        "ioc_correlation",
        indicator["value"],
        dict(
            ioc=indicator["value"],
            ioc_type=indicator["ioc_type"],
            normalization=indicator,
            matches=payload["matches"],
            related_findings=related,
            related_incidents=list(incidents.values()),
            related_assets=list(assets.values()),
            mitre_relationships=mitre,
            threat_intelligence={
                "state": "Stored sources only; no new network request"
            },
            correlation=payload,
        ),
        findings,
        "UNAVAILABLE" if payload["status"] == "UNAVAILABLE" else "COMPLETED",
        ["reviewed local IOC store", "owned stored findings (latest 1000)"],
    )


def security_intelligence(user):
    from myapp.models import Finding, ScanJob

    rows = list(
        Finding.objects.filter(job__requested_by=user)
        .exclude(scanner="security_intel")
        .select_related("asset")
        .order_by("-risk_score", "-timestamp")[:100]
    )
    jobs = ScanJob.objects.filter(requested_by=user)
    assets = {}
    cves = set()
    evidence = []
    for row in rows:
        if row.asset_id:
            assets[row.asset_id] = {
                "id": row.asset_id,
                "hostname": row.asset.hostname,
                "operating_system": row.asset.operating_system,
            }
        # Only references already present in evidence, never invented version-to-CVE guesses.
        cves.update(re.findall(r"\bCVE-\d{4}-\d{4,7}\b", str(row.evidence)))
        evidence.append(
            {
                "finding_id": row.pk,
                "title": row.title,
                "severity": row.severity,
                "recorded_risk": row.risk_score,
                "confidence": row.confidence,
            }
        )
    findings = []
    if rows:
        highest = max(rows, key=lambda r: r.risk_score)
        findings = [
            finding(
                "Aggregate recorded exposure",
                {
                    "contributors": evidence,
                    "method": "Maximum recorded finding risk; avoids summing duplicated observations",
                },
                highest.risk_score,
                "Prioritize the linked finding and validate freshness of its evidence.",
                "aggregate security posture",
            )
        ]
    return finish(
        "security_intelligence",
        "Your stored security evidence",
        dict(
            asset_context=list(assets.values()),
            vulnerability_context={
                "cve_references": sorted(cves),
                "verification": "References in stored evidence, not verified vulnerabilities",
                "live_feed": "Source unavailable",
            },
            software_exposure={
                "state": "Insufficient Evidence",
                "reason": "No authoritative installed-version vulnerability feed configured",
            },
            security_posture={
                "stored_jobs": jobs.count(),
                "findings_considered": len(rows),
                "aggregation_limit": 100,
            },
            threat_landscape={
                "classification": "Recorded local exposure" if rows else "Unknown",
                "attribution": "Unknown",
            },
            contextual_evidence=evidence,
        ),
        findings,
        "COMPLETED" if rows else "UNAVAILABLE",
        ["owned persisted findings and asset relations"],
    )
