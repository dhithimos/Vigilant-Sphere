"""Offline-first scanner contract and persistence pipeline.



This module deliberately separates collection from detection.  It never executes

files, visits URLs, scans remote hosts without an explicit authorization token,

or performs remediation.

"""

from __future__ import annotations


import hashlib

import importlib.util


import uuid

from dataclasses import dataclass


from typing import Any


from django.utils import timezone


from . import scan_engine

from django.db import transaction
from .models import Finding, FindingEvidence, ScanJob

from .scanners.wifi import collect as collect_wifi


SEVERITY_POINTS = {"INFO": 0, "LOW": 10, "MEDIUM": 25, "HIGH": 50, "CRITICAL": 75}

MITRE = {
    "encoded_powershell": ("T1059.001", "Execution"),
    "credential_exposure": ("T1552.001", "Credential Access"),
}


def redact(value: Any) -> Any:
    """Retain enough evidence for triage while never persisting secret values."""

    if isinstance(value, dict):
        sensitive = (
            "password",
            "token",
            "secret",
            "api_key",
            "apikey",
            "credential",
            "session",
            "key_content",
            "smtp",
        )

        return {
            str(k): "[REDACTED]"
            if any(marker in str(k).lower() for marker in sensitive)
            else redact(v)
            for k, v in value.items()
        }

    if isinstance(value, list):
        return [redact(v) for v in value]

    if isinstance(value, str) and (
        "token" in value.lower()
        or "password" in value.lower()
        or "akia" in value.lower()
    ):
        return (
            value[:4] + "****************" + value[-4:]
            if len(value) > 8
            else "[REDACTED]"
        )

    return value


@dataclass(frozen=True)
class ScannerHealth:
    status: str

    detail: str


class BaseScanner:
    scanner_id = "base"

    name = "Base scanner"

    category = "core"

    supported_platforms = ("Windows", "Linux", "Darwin")

    dependencies: tuple[str, ...] = ()

    permissions = "standard user"

    status = "PARTIAL"

    def health_check(self) -> ScannerHealth:

        missing = [d for d in self.dependencies if importlib.util.find_spec(d) is None]

        return (
            ScannerHealth(
                "NOT INSTALLED",
                f"Optional dependencies unavailable: {', '.join(missing)}",
            )
            if missing
            else ScannerHealth("AVAILABLE", self.status)
        )

    def scan(self, context: dict[str, Any]) -> list[dict[str, Any]]:

        return []


class SystemScanner(BaseScanner):
    scanner_id, name, category, status = (
        "system",
        "System Scanner",
        "endpoint",
        "IMPLEMENTED",
    )

    def scan(self, context):

        profile = scan_engine.profile_system()

        return [
            {
                "type": "system_inventory",
                "title": "Local endpoint inventory collected",
                "severity": "INFO",
                "confidence": 0.98,
                "evidence": profile,
                "recommendation": "Use the inventory as a baseline; unavailable OS controls remain UNKNOWN.",
            }
        ]


class ProcessScanner(BaseScanner):
    scanner_id, name, category, status = (
        "processes",
        "Process Scanner",
        "endpoint",
        "IMPLEMENTED",
    )

    def scan(self, context):

        output = []

        for item in scan_engine.process_audit(limit=80):
            reason = item.get("reason", "")

            key = (
                "encoded_powershell"
                if "Encoded PowerShell" in reason
                else "credential_exposure"
                if "Credential" in reason
                else ""
            )

            output.append(
                {
                    "type": key or "suspicious_process",
                    "title": f"Suspicious process: {item.get('name', 'unknown')}",
                    "severity": item.get("risk", "medium").upper(),
                    "confidence": 0.82 if key else 0.55,
                    "evidence": item,
                    "recommendation": item.get(
                        "resolution", "Investigate process context."
                    ),
                }
            )

        return output


class PersistenceScanner(BaseScanner):
    scanner_id, name, category, status = (
        "persistence",
        "Persistence Scanner",
        "endpoint",
        "PARTIAL",
    )

    def scan(self, context):

        output = []

        for item in scan_engine.startup_audit():
            output.append(
                {
                    "type": "startup_script",
                    "title": f"Startup entry: {item['name']}",
                    "severity": item["risk"].upper(),
                    "confidence": 0.65,
                    "evidence": item,
                    "recommendation": item["resolution"],
                }
            )

        return output


class FileScanner(BaseScanner):
    scanner_id, name, category, status = (
        "files",
        "File Security Scanner",
        "endpoint",
        "PARTIAL",
    )

    def scan(self, context):

        output = []

        for item in scan_engine.file_scan(max_files=300)["files"]:
            kind = (
                "credential_exposure"
                if item.get("malicious") == "Credential Exposure"
                else "suspicious_file"
            )

            output.append(
                {
                    "type": kind,
                    "title": f"{item.get('malicious', 'Suspicious')} file: {item['name']}",
                    "severity": item["risk"].upper(),
                    "confidence": 0.9 if kind == "credential_exposure" else 0.6,
                    "evidence": item,
                    "recommendation": item["resolution"],
                    "ioc": {"sha256": item.get("sha256", "")},
                }
            )

        return output


class NetworkConfigScanner(BaseScanner):
    scanner_id, name, category, status = (
        "network_config",
        "Network Configuration Scanner",
        "network",
        "IMPLEMENTED",
    )

    def scan(self, context):

        profile = scan_engine.profile_system()

        return [
            {
                "type": "network_configuration",
                "title": "Local network configuration collected",
                "severity": "INFO",
                "confidence": 0.95,
                "evidence": {
                    "ip_address": profile.get("ip_address"),
                    "mac_address": profile.get("mac_address"),
                },
                "recommendation": "Establish a reviewed baseline before treating configuration changes as suspicious.",
            }
        ]


class PortScanner(BaseScanner):
    scanner_id, name, category, status = (
        "ports",
        "Local Port Scanner",
        "network",
        "IMPLEMENTED",
    )

    def scan(self, context):

        # The only default target is loopback.  Remote targets must be authorized in a future agent workflow.

        return [
            {
                "type": "open_local_port",
                "title": f"Local service exposed on TCP/{x['port']}",
                "severity": x["risk"].upper(),
                "confidence": 0.75,
                "evidence": x,
                "recommendation": x["resolution"],
            }
            for x in scan_engine.port_scan("127.0.0.1")
        ]


class ConnectionScanner(BaseScanner):
    scanner_id, name, category, status = (
        "connections",
        "Active Connection Scanner",
        "network",
        "IMPLEMENTED",
    )

    def scan(self, context):

        return [
            {
                "type": "active_connection",
                "title": f"Active {x['protocol']} connection on {x['port']}",
                "severity": x["risk"].upper(),
                "confidence": 0.45,
                "evidence": x,
                "recommendation": x["resolution"],
            }
            for x in scan_engine.active_network_connections(limit=120)
            if x["risk"] in {"high", "critical"}
        ]


class WiFiSecurityScanner(BaseScanner):
    scanner_id, name, category, status = (
        "wifi",
        "Wi-Fi Security Audit",
        "user_safety",
        "IMPLEMENTED",
    )

    def scan(self, context):

        from .wifi_audit_service import authorize, finding_type_for

        authorize(context["job"].requested_by)
        state, rows, detail = collect_wifi()

        if state != "AVAILABLE":
            raise RuntimeError("Wi-Fi collection unavailable: " + state)

        return [
            {
                "type": finding_type_for(row),
                "title": f"Wi-Fi profile: {row['profile_name']}",
                "severity": row["risk_level"]
                if row["risk_level"] != "UNKNOWN"
                else "INFO",
                "confidence": 0.9,
                "evidence": row,
                "recommendation": row["recommendation"],
            }
            for row in rows
        ]


class CapabilityScanner(BaseScanner):
    """An intentional capability record, never a fake detection."""

    def scan(self, context):

        return []


SCANNER_CATALOG = {
    "combined": ("Combined Security Scan", "core", "IMPLEMENTED"),
    "system": ("System Scanner", "endpoint", "IMPLEMENTED"),
    "processes": ("Process Scanner", "endpoint", "IMPLEMENTED"),
    "persistence": ("Persistence Scanner", "endpoint", "PARTIAL"),
    "files": ("File Security Scanner", "endpoint", "PARTIAL"),
    "secrets": ("Secret Scanner", "endpoint", "PARTIAL"),
    "privilege": ("Privilege Scanner", "endpoint", "PARTIAL"),
    "compliance": ("Compliance Scanner", "endpoint", "PARTIAL"),
    "vulnerabilities": ("Vulnerability Scanner", "endpoint", "NOT_IMPLEMENTED"),
    "hardening": ("Hardening Scanner", "endpoint", "PARTIAL"),
    "network_config": ("Network Configuration Scanner", "network", "IMPLEMENTED"),
    "ports": ("Local Port Scanner", "network", "IMPLEMENTED"),
    "connections": ("Active Connection Scanner", "network", "IMPLEMENTED"),
    "dns": ("DNS Scanner", "network", "IMPLEMENTED_TARGET"),
    "hosts": ("Hosts File Scanner", "network", "NOT_IMPLEMENTED"),
    "network_behavior": ("Network Behaviour Scanner", "network", "NOT_IMPLEMENTED"),
    "scope": (
        "Authorized External Asset Scanner",
        "network",
        "BLOCKED_BY_AUTHORIZATION",
    ),
    "urls": ("URL Scanner", "user_safety", "PARTIAL"),
    "phishing": ("Phishing Analyzer", "user_safety", "IMPLEMENTED_TARGET"),
    "passwords": ("Password Analyzer", "user_safety", "IMPLEMENTED_CLIENT_SIDE"),
    "wifi": ("Wi-Fi Security Audit", "user_safety", "IMPLEMENTED"),
    "privacy": ("Privacy Scanner", "user_safety", "NOT_IMPLEMENTED"),
    "browser": ("Browser Security Scanner", "user_safety", "NOT_IMPLEMENTED"),
    "fim": ("File Integrity Monitoring", "monitoring", "NOT_IMPLEMENTED"),
    "process_monitor": ("Process Monitoring", "monitoring", "NOT_IMPLEMENTED"),
    "persistence_monitor": ("Persistence Monitoring", "monitoring", "NOT_IMPLEMENTED"),
    "login_monitor": ("Login Monitoring", "monitoring", "NOT_IMPLEMENTED"),
    "usb_monitor": ("USB Monitoring", "monitoring", "NOT_IMPLEMENTED"),
    "dns_monitor": ("DNS Monitoring", "monitoring", "NOT_IMPLEMENTED"),
    "config_drift": ("Configuration Drift Monitoring", "monitoring", "NOT_IMPLEMENTED"),
    "ioc": ("IOC Engine", "soc", "PARTIAL"),
    "threat_intelligence": ("Threat Intelligence", "soc", "LOCAL_ONLY"),
    "threat_hunting": ("Threat Hunting", "soc", "PARTIAL"),
    "mitre_correlation_risk": (
        "MITRE / Correlation / Risk Engine",
        "soc",
        "IMPLEMENTED",
    ),
}


class ScannerRegistry:
    def __init__(self):

        self.scanners = {
            x.scanner_id: x
            for x in (
                SystemScanner(),
                ProcessScanner(),
                PersistenceScanner(),
                FileScanner(),
                NetworkConfigScanner(),
                PortScanner(),
                ConnectionScanner(),
                WiFiSecurityScanner(),
            )
        }

        for key, (name, category, status) in SCANNER_CATALOG.items():
            self.scanners.setdefault(
                key,
                type(
                    "CatalogScanner",
                    (CapabilityScanner,),
                    {
                        "scanner_id": key,
                        "name": name,
                        "category": category,
                        "status": status,
                    },
                )(),
            )

    def for_profile(self, profile):

        profiles = {
            "combined": [
                "system",
                "processes",
                "persistence",
                "files",
                "network_config",
                "ports",
                "connections",
            ],
            "system": ["system", "processes", "persistence", "files"],
            "network": ["network_config", "ports", "connections"],
            "wifi": ["wifi"],
        }

        return [self.scanners[x] for x in profiles.get(profile, profiles["combined"])]


def normalize(scanner: BaseScanner, raw: dict, job: ScanJob) -> dict:

    severity = str(raw.get("severity", "INFO")).upper()

    confidence = max(0.0, min(1.0, float(raw.get("confidence", 0.5))))

    evidence = redact(raw.get("evidence", {}))

    seed = f"{job.asset_id}:{scanner.scanner_id}:{raw.get('type')}:{raw.get('title')}"

    mitre_technique, mitre_tactic = MITRE.get(raw.get("type"), ("", ""))

    from .analysis.ioc_correlation import correlation_block

    fingerprint = hashlib.sha256(seed.encode()).hexdigest()
    cache = getattr(job, "_ioc_cache", {})
    if fingerprint not in cache:
        try:
            with transaction.atomic():
                prior = Finding.objects.filter(job=job, fingerprint=fingerprint).first()
                cache[fingerprint] = (
                    prior.ioc if prior else correlation_block(raw, job.requested_by)
                )
        except Exception:
            cache[fingerprint] = {
                "status": "UNAVAILABLE",
                "checked": [],
                "matches": [],
                "indicator_values": [],
                "related_findings": [],
                "note": "IOC check unavailable",
            }
        job._ioc_cache = cache
    correlated = cache[fingerprint]
    return {
        "finding_id": uuid.uuid4().hex,
        "fingerprint": hashlib.sha256(seed.encode()).hexdigest(),
        "scanner": scanner.scanner_id,
        "finding_type": raw.get("type", "observation"),
        "title": raw.get("title", "Security observation"),
        "description": raw.get("description", raw.get("title", "Security observation")),
        "severity": severity,
        "confidence": confidence,
        "risk_score": min(
            100, round(SEVERITY_POINTS.get(severity, 0) * (0.5 + confidence / 2))
        ),
        "evidence": evidence,
        "observations": raw.get("observations", []),
        "recommendation": raw.get(
            "recommendation", "Review the evidence and validate local context."
        ),
        "remediation": raw.get(
            "remediation", "Human approval is required for any response."
        ),
        "mitre_technique": mitre_technique,
        "mitre_tactic": mitre_tactic,
        "ioc": correlated,
        "requires_approval": True,
    }


def execute_job(job_id: int) -> None:

    claimed = ScanJob.objects.filter(pk=job_id, status="QUEUED").update(
        status="RUNNING"
    )
    if not claimed:
        return
    job = ScanJob.objects.get(pk=job_id)

    if job.scan_type == "wifi":
        from .wifi_audit_service import run_audit

        try:
            run_audit(job.requested_by, job=job)
        except PermissionError:
            job.status = "FAILED"
            job.error = "Wi-Fi collection not authorized"
            job.completed_at = timezone.now()
            job.save()
        return
    registry = ScannerRegistry()

    selected = registry.for_profile(job.scan_type)

    job.status, job.started_at, job.scanner_count = (
        "RUNNING",
        timezone.now(),
        len(selected),
    )

    job.save(update_fields=["status", "started_at", "scanner_count"])

    failed = 0

    stored = []

    for index, scanner in enumerate(selected, 1):
        try:
            for raw in scanner.scan({"job": job, "asset": job.asset}):
                item = normalize(scanner, raw, job)

                # Deduplicate only within a recent time window; historical evidence remains available.

                prior = Finding.objects.filter(
                    job=job, fingerprint=item["fingerprint"]
                ).first()

                if prior:
                    continue

                finding = Finding.objects.create(job=job, asset=job.asset, **item)

                FindingEvidence.objects.create(
                    finding=finding,
                    source=scanner.scanner_id,
                    content=item["evidence"],
                    content_hash=hashlib.sha256(
                        repr(item["evidence"]).encode()
                    ).hexdigest(),
                )

                from .alerts import get_or_create_deduped_alert

                get_or_create_deduped_alert(finding)

                stored.append(finding)

        except Exception as exc:  # individual scanner failure must not fail the job
            failed += 1

            job.error = (job.error + f"\n{scanner.scanner_id}: {type(exc).__name__}")[
                :4000
            ]

        job.completed_scanner_count, job.failed_scanner_count, job.progress = (
            index - failed,
            failed,
            round(index * 100 / len(selected)),
        )

        job.save(
            update_fields=[
                "completed_scanner_count",
                "failed_scanner_count",
                "progress",
                "error",
            ]
        )

    score = min(100, sum(x.risk_score for x in stored))

    job.finding_count, job.risk_score, job.status, job.completed_at, job.progress = (
        len(stored),
        score,
        ("FAILED" if failed == len(selected) else "PARTIAL" if failed else "COMPLETED"),
        timezone.now(),
        100,
    )

    job.save(
        update_fields=[
            "finding_count",
            "risk_score",
            "status",
            "completed_at",
            "progress",
        ]
    )
