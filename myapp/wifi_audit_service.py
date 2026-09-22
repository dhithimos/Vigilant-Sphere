"""One authorized Wi-Fi audit path for web, pipeline and scheduled commands."""

import getpass
import hashlib
import json
import uuid
from django.db import transaction
from django.utils import timezone
from django.db.models import OuterRef, Subquery
from .context import can_inspect_host
from .models import (
    ScanJob,
    WiFiAudit,
    Finding,
    FindingEvidence,
    TrustedWifiProfile,
    FeatureFlag,
)
from .scanners.wifi import collect, collect_current_connection, MISSING


def compare_risk(previous, current):
    return (
        "NEW"
        if previous is None
        else "DEGRADED"
        if current > previous
        else "IMPROVED"
        if current < previous
        else "UNCHANGED"
    )


def authorize(user):
    if not can_inspect_host(user):
        raise PermissionError("Host inspection unavailable for this account")
    flag, _ = FeatureFlag.objects.get_or_create(
        key="WIFI_SECURITY_AUDIT", defaults={"enabled": True}
    )
    if not flag.enabled:
        raise PermissionError("Wi-Fi feature is disabled")


def finding_type_for(row):
    if row.get("collection_status") != "AVAILABLE":
        return "wifi_collection"
    return (
        "wifi_weak_encryption"
        if row.get("risk_level") in {"MEDIUM", "HIGH", "CRITICAL"}
        else "wifi_profile"
    )


def annotate_rows(rows):
    groups = {}
    for row in rows:
        label = row.get("ssid")
        key = (
            ("SSID", label)
            if label and label != MISSING
            else ("Profile name", row["profile_name"])
        )
        groups.setdefault(key, set()).add(row["security_level"])
        row["duplicate_group"] = key
    for row in rows:
        levels = groups[row["duplicate_group"]]
        row["duplicate_ssid_conflict"] = len(levels) > 1
        row["conflicting_levels"] = sorted(levels)
    return rows


def run_audit(user, request=None, job=None):
    authorize(user)
    state, rows, detail = collect()
    current = collect_current_connection()
    job = persist_audit(user, state, rows, detail, current=current, job=job)
    from .views import audit_security_event

    if request is not None:
        audit_security_event(
            request,
            "Wi-Fi audit collected",
            details={
                "status": state,
                "os_account": getpass.getuser(),
                "job_id": job.pk,
            },
        )
    else:
        # Same logging helper with a request-shaped local command context.
        from django.test import RequestFactory

        command_request = RequestFactory().get("/management/run_wifi_audit/")
        command_request.user = user
        audit_security_event(
            command_request,
            "Scheduled Wi-Fi audit",
            details={
                "status": state,
                "os_account": getpass.getuser(),
                "job_id": job.pk,
            },
        )
    return job, state, current


@transaction.atomic
def persist_audit(user, state, rows, detail, current=None, job=None):
    from .security_pipeline import normalize, ScannerRegistry
    from .alerts import get_or_create_deduped_alert

    available = state == "AVAILABLE"
    partial = available and any(r.get("collection_status") != "AVAILABLE" for r in rows)
    status = "PARTIAL" if partial else "COMPLETED" if available else "UNAVAILABLE"
    if job is None:
        job = ScanJob.objects.create(
            scan_id=str(uuid.uuid4()), requested_by=user, scan_type="wifi"
        )
    job.status = status
    job.started_at = job.started_at or timezone.now()
    job.completed_at = timezone.now()
    job.progress = 100
    job.scanner_count = 1
    job.completed_scanner_count = int(available and not partial)
    job.failed_scanner_count = int(not available or partial)
    job.error = "" if status == "COMPLETED" else detail
    current = current or {}
    rows = annotate_rows(rows)
    names = {r["profile_name"] for r in rows}
    prior = {}
    from django.db.models import Window, F
    from django.db.models.functions import RowNumber

    for audit in (
        WiFiAudit.objects.filter(user=user, profile_name__in=names)
        .annotate(
            rank=Window(
                expression=RowNumber(),
                partition_by=[F("profile_name")],
                order_by=F("pk").desc(),
            )
        )
        .filter(rank=1)
    ):
        prior.setdefault(audit.profile_name, audit)
    trusts = {
        x.profile_name: x
        for x in TrustedWifiProfile.objects.filter(user=user, profile_name__in=names)
    }
    scanner = ScannerRegistry().scanners["wifi"]
    scores = []
    duplicates = set()

    def save_finding(raw):
        finding = Finding.objects.create(job=job, **normalize(scanner, raw, job))
        FindingEvidence.objects.create(
            finding=finding,
            source="wifi",
            content=finding.evidence,
            content_hash=hashlib.sha256(
                json.dumps(finding.evidence, sort_keys=True).encode()
            ).hexdigest(),
        )
        scores.append(finding.risk_score)
        transaction.on_commit(
            lambda finding=finding: get_or_create_deduped_alert(
                finding, f"wifi:{user.pk}:{raw['evidence']['profile_name']}"
            )
        )
        return finding

    for row in rows if available else []:
        name = row["profile_name"]
        previous = prior.get(name)
        trust = trusts.get(name)
        matched = current.get("profile_name") == name or (
            row.get("ssid") not in {None, MISSING, ""}
            and current.get("ssid") == row["ssid"]
        )
        bssid = current.get("bssid") if matched else None
        if bssid == MISSING:
            bssid = None
        if matched:
            row["gateway"] = current.get("gateway", MISSING)
            row["dns_servers"] = [
                x.strip().split(" ")[0] for x in current.get("dns", "").split(",")
            ]
        audit = WiFiAudit.objects.create(
            user=user,
            profile_name=name,
            authentication=row["authentication"],
            encryption=row["encryption"],
            security_level=row["security_level"],
            risk_level=row["risk_level"],
            risk_score=row["risk_score"],
            risk_reason=row["reason"],
            recommendation=row["recommendation"],
            collection_status=row["collection_status"],
            score_breakdown=row.get("score_breakdown", []),
            bssid=bssid,
        )
        suppressed = (
            trust
            and compare_risk(trust.risk_score_at_trust, row["risk_score"]) != "DEGRADED"
        )
        if suppressed:
            continue
        raw = {
            "type": finding_type_for(row),
            "title": "Wi-Fi profile: " + name,
            "severity": row["risk_level"]
            if row["risk_level"] in {"HIGH", "CRITICAL", "MEDIUM"}
            else "INFO",
            "confidence": 0.9,
            "evidence": row,
            "recommendation": row["recommendation"],
        }
        finding = save_finding(raw)
        audit.finding = finding
        audit.save(update_fields=["finding"])
        if (
            previous
            and previous.bssid
            and bssid
            and previous.bssid.lower() != bssid.lower()
        ):
            save_finding(
                dict(
                    raw,
                    type="wifi_bssid_changed",
                    severity="INFO",
                    title=f"Access point identifier changed for {name}",
                    evidence=dict(
                        row, previous_bssid=previous.bssid, current_bssid=bssid
                    ),
                    recommendation="The recorded BSSID differs. Multiple access points and mesh systems legitimately share an SSID.",
                )
            )
        key = row["duplicate_group"]
        if row["duplicate_ssid_conflict"] and key not in duplicates:
            duplicates.add(key)
            save_finding(
                dict(
                    raw,
                    type="wifi_duplicate_ssid",
                    severity="INFO",
                    title=f"{key[0]} {key[1]} appears with differing security levels",
                    recommendation="Review the recorded configurations; this is not evidence of an attack.",
                )
            )
    job.finding_count = len(scores)
    job.risk_score = min(100, sum(scores))
    job.save()
    # Reuse the existing investigation JSON/CSV/PDF export paths for Wi-Fi jobs.
    from .models import TargetScan
    from .scanners.target import module_result

    from .scanners.wifi_report import executive_report
    executive=executive_report(state,rows,current)
    TargetScan.objects.update_or_create(
        job=job,
        defaults={
            "scan_id": job.scan_id,
            "user": user,
            "target": "Local saved Wi-Fi profiles",
            "target_type": "wifi",
            "status": job.status,
            "risk_score": job.risk_score,
            "risk_level": "UNKNOWN",
            "confidence": "medium" if available else "low",
            "results": [
                module_result(
                    "wifi",
                    "local",
                    "wifi",
                    "success" if available else "unavailable",
                    data={
                        "profiles": rows,
                        "executive_report":executive,
                        "disclaimer": "Informational mapping; not a compliance certification.",
                    },
                )
            ],
            "findings": [
                {
                    "title": f.title,
                    "severity": f.severity,
                    "confidence": f.confidence,
                    "evidence": f.evidence,
                    "recommendation": f.recommendation,
                }
                for f in job.findings.all()
            ],
            "started_at": job.started_at,
            "completed_at": job.completed_at,
        },
    )
    return job


def history_queryset(user):
    earlier = WiFiAudit.objects.filter(
        user=user, profile_name=OuterRef("profile_name"), pk__lt=OuterRef("pk")
    ).order_by("-pk")
    return (
        WiFiAudit.objects.filter(user=user)
        .select_related("finding__job__investigation", "finding__alert__email_delivery")
        .annotate(previous_score=Subquery(earlier.values("risk_score")[:1]))
        .order_by("-created_at", "-pk")
    )
