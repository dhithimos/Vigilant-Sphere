"""Separate scanner workflows with shared authenticated persistence and reporting."""

import uuid
from django import forms
from django.db import transaction
from django.contrib.auth.decorators import login_required
from django.shortcuts import redirect
from django.utils import timezone
from .presentation import render
from .models import TargetScan, ScanJob
from .analysis import domain_scanners as scanners
from .analysis.investigation import _limit
from .analysis.persistence import persist_findings
from .scanners.target import module_result

SCANNERS = {
    "phishing_intelligence": (
        "Phishing & Scam Intelligence",
        "URL structure, domain similarity and bounded public web evidence",
        scanners.phishing_intelligence,
        "phishing",
    ),
    "static_file_analysis": (
        "Static File Analysis",
        "Metadata, hashes, PE/ELF structure and static indicators; uploaded bytes are never executed",
        scanners.static_file_analysis,
        "file",
    ),
    "security_intelligence": (
        "Security Intelligence & Threat Analysis",
        "Aggregate owned asset and finding context; no fabricated CVE lookup",
        scanners.security_intelligence,
        "security_intel",
    ),
    "threat_detection": (
        "Threat Detection",
        "Internal behavioral rules over a bounded local process snapshot",
        scanners.threat_detection,
        "behavior",
    ),
    "threat_intelligence": (
        "Threat Intelligence",
        "Type-specific external reputation evidence from configured providers",
        scanners.threat_intelligence,
        "reputation",
    ),
    "ioc_correlation": (
        "IOC Correlation",
        "Normalized exact matches and relationships in your stored evidence",
        scanners.ioc_correlation,
        "ioc",
    ),
}


@login_required
def scanner_page(request, kind):
    title, method, engine, record_type = SCANNERS[kind]

    class InputForm(forms.Form):
        target = forms.CharField(
            max_length=2048,
            label={
                "phishing_intelligence": "URL or domain",
                "threat_intelligence": "Public IP, domain, URL or file hash",
                "ioc_correlation": "IOC: IP, domain, URL, hash, path or registry key",
            }.get(kind, "Target"),
            required=kind
            not in {
                "static_file_analysis",
                "security_intelligence",
                "threat_detection",
            },
        )
        sample = forms.FileField(
            required=kind == "static_file_analysis", label="File for static analysis"
        )

    form = InputForm(request.POST or None, request.FILES or None)
    if kind == "static_file_analysis":
        form.fields.pop("target")
    else:
        form.fields.pop("sample")
    if kind in {"security_intelligence", "threat_detection"}:
        form.fields.pop("target")
    if request.method == "POST":
        # Preserve historical field names accepted by the dedicated file/phishing routes.
        data = request.POST.copy()
        files = request.FILES.copy()
        if "url_to_scan" in data:
            data["target"] = data["url_to_scan"]
        if "file_to_scan" in files:
            files["sample"] = files["file_to_scan"]
        form = InputForm(data, files)
        for field in list(form.fields):
            if (
                field == "sample"
                and kind != "static_file_analysis"
                or field == "target"
                and kind
                in {"static_file_analysis", "security_intelligence", "threat_detection"}
            ):
                form.fields.pop(field)
        if form.is_valid():
            if not _limit(request.user):
                form.add_error(None, "Scan rate limit reached. Try again later.")
            else:
                from .context import can_inspect_host

                if kind == "threat_detection" and not can_inspect_host(request.user):
                    return render(request, "myapp/scanner_access.html", status=403)
                job = ScanJob.objects.create(
                    scan_id=str(uuid.uuid4()),
                    requested_by=request.user,
                    scan_type=record_type,
                    status="RUNNING",
                    started_at=timezone.now(),
                )
                try:
                    if kind == "ioc_correlation":
                        contract = engine(form.cleaned_data["target"], request.user)
                    elif kind == "security_intelligence":
                        contract = engine(request.user)
                    elif kind == "threat_detection":
                        contract = engine()
                    else:
                        contract = engine(
                            form.cleaned_data["sample"]
                            if kind == "static_file_analysis"
                            else form.cleaned_data["target"]
                        )
                    with transaction.atomic():
                        record = TargetScan.objects.create(
                            job=job,
                            scan_id=job.scan_id,
                            user=request.user,
                            target=contract["target"],
                            target_type=record_type,
                            status=contract["status"],
                            risk_score=contract["risk_score"],
                            risk_level="HIGH"
                            if contract["risk_score"] >= 60
                            else "MEDIUM"
                            if contract["risk_score"] >= 30
                            else "LOW"
                            if contract["risk_score"]
                            else "UNKNOWN",
                            confidence="medium" if contract["findings"] else "low",
                            results=[
                                module_result(
                                    kind,
                                    contract["target"],
                                    record_type,
                                    "unavailable"
                                    if contract["status"] == "UNAVAILABLE"
                                    else "success",
                                    data=contract,
                                )
                            ],
                            findings=contract["findings"],
                            provider_results=contract.get("reputation_sources", []),
                            started_at=job.started_at,
                            completed_at=timezone.now(),
                        )
                        persist_findings(record)
                    from .views import audit_security_event

                    audit_security_event(
                        request,
                        "Dedicated scan completed",
                        details={
                            "scanner": kind,
                            "job_id": job.pk,
                            "status": contract["status"],
                        },
                    )
                    return redirect("domain_result", scan_id=record.scan_id)
                except Exception as exc:
                    job.status = "FAILED"
                    job.error = type(exc).__name__
                    job.completed_at = timezone.now()
                    job.save()
                    form.add_error(
                        None,
                        str(exc)
                        if isinstance(exc, ValueError)
                        else "Scan could not complete; the failed job was retained.",
                    )
    return render(
        request,
        "myapp/domain_scanner.html",
        {
            "title": title,
            "method": method,
            "kind": kind,
            "form": form,
            "recent": TargetScan.objects.filter(
                user=request.user, target_type=record_type
            ).order_by("-created_at")[:10],
        },
    )


@login_required
def scanner_result(request, scan_id):
    from django.shortcuts import get_object_or_404

    record = get_object_or_404(TargetScan, scan_id=scan_id, user=request.user)
    contract = record.results[0].get("data", {}) if record.results else {}
    identity = contract.get("scanner")
    if identity not in SCANNERS:
        return redirect("target_scan_detail", scan_id=record.scan_id)
    labels = {
        "phishing_intelligence": [
            ("URL analysis", "url_analysis"),
            ("Entropy", "entropy_analysis"),
            ("Typosquatting", "typosquatting"),
            ("Homographs", "homograph_analysis"),
            ("Brand similarity", "brand_impersonation"),
            ("DNS", "dns_analysis"),
            ("MX", "mx_analysis"),
            ("HTTP evidence", "http_analysis"),
        ],
        "static_file_analysis": [
            ("File metadata", "file_metadata"),
            ("Hashes", "hashes"),
            ("Entropy", "entropy"),
            ("PE structure", "pe_analysis"),
            ("ELF structure", "elf_analysis"),
            ("Strings", "strings"),
            ("Fuzzy hash", "fuzzy_hash"),
            ("Indicators", "indicators"),
            ("Detailed static modules and optional tool status", "static_modules"),
        ],
        "security_intelligence": [
            ("Assets", "asset_context"),
            ("Vulnerabilities", "vulnerability_context"),
            ("Software exposure", "software_exposure"),
            ("Posture", "security_posture"),
            ("Recorded context", "contextual_evidence"),
        ],
        "threat_detection": [
            ("Behavioral rules", "behavioral_rules"),
            ("Snapshot", "process_summary"),
            ("Persistence", "persistence"),
            ("Beaconing", "beaconing"),
            ("Rule engine", "rule_engine"),
        ],
        "threat_intelligence": [
            ("IOC type", "indicator_type"),
            ("Reputation sources", "reputation_sources"),
            ("Threat actor attribution", "attribution"),
        ],
        "ioc_correlation": [
            ("Normalization", "normalization"),
            ("Matches", "matches"),
            ("Related findings", "related_findings"),
            ("Related incidents", "related_incidents"),
            ("Assets", "related_assets"),
            ("MITRE relationships", "mitre_relationships"),
            ("Check status", "correlation"),
        ],
    }
    return render(
        request,
        "myapp/domain_result.html",
        {
            "scan": record,
            "contract": contract,
            "title": SCANNERS[identity][0],
            "sections": [(label, contract.get(key)) for label, key in labels[identity]],
        },
    )
