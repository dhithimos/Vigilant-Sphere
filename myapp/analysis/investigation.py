"""Orchestrates independent passive checks and derives an explainable risk score."""

from __future__ import annotations


import uuid

from datetime import timedelta


from django.conf import settings

from django.utils import timezone


from myapp.models import TargetScan, ScanJob

from myapp.scanners.file_analysis import analyze_uploaded

from myapp.scanners.target import (
    classify_target,
    dns_scan,
    http_scan,
    module_result,
    rdap_scan,
    tls_scan,
)

from myapp.threat_intel import provider_results


POINTS = {"INFO": 0, "LOW": 8, "MEDIUM": 20, "HIGH": 40, "CRITICAL": 65}


def _level(score):

    return (
        "CRITICAL"
        if score >= 80
        else "HIGH"
        if score >= 60
        else "MEDIUM"
        if score >= 30
        else "LOW"
        if score
        else "UNKNOWN"
    )


def _risk(results, providers):

    findings = [finding for result in results for finding in result.get("findings", [])]

    factors = [
        {
            "source": x.get("source", "local"),
            "title": x.get("title"),
            "points": POINTS.get(x.get("severity", "INFO").upper(), 0),
        }
        for x in findings
    ]

    for row in providers:
        detections = row.get("data", {}).get("detections", {})

        malicious = int(detections.get("malicious", 0) or 0)

        if malicious:
            points = min(50, malicious * 10)

            factors.append(
                {
                    "source": row["provider"],
                    "title": f"Provider reported {malicious} malicious detections",
                    "points": points,
                }
            )

        abuse = row.get("data", {}).get("report", {}).get("abuseConfidenceScore")

        if isinstance(abuse, int) and abuse:
            factors.append(
                {
                    "source": row["provider"],
                    "title": f"Provider reported abuse confidence {abuse}",
                    "points": round(abuse * 0.3),
                }
            )

    score = min(100, sum(item["points"] for item in factors))

    confidence = "medium" if factors else "low"

    return score, _level(score), confidence, findings, factors


def _limit(user):

    since = timezone.now() - timedelta(hours=1)

    return (
        TargetScan.objects.filter(user=user, created_at__gte=since).count()
        < settings.TARGET_SCAN_LIMIT_PER_HOUR
    )


def _run_target_scan(user, raw_target="", uploaded=None, job=None):

    if not _limit(user):
        raise ValueError("Target scan rate limit reached. Try again later.")

    started = timezone.now()

    if uploaded:
        if uploaded.size > settings.MAX_UPLOAD_SIZE:
            raise ValueError("The uploaded file exceeds the configured size limit.")

        target_type, target = "file", uploaded.name

        results = analyze_uploaded(uploaded)

        hashes = next((x["data"] for x in results if x["module"] == "hashes"), {})

        providers = provider_results(hashes.get("sha256", ""), "hash") if hashes else []

    else:
        target_type, target = classify_target(raw_target)

        results, providers = [], []

        if target_type == "url":
            results.extend(http_scan(target))

            host = (
                __import__("urllib.parse", fromlist=["urlsplit"])
                .urlsplit(target)
                .hostname
            )

            results.extend(
                [
                    dns_scan(host, "url"),
                    tls_scan(host, target_type="url"),
                    rdap_scan(host),
                ]
            )

            providers = provider_results(target, "url")

        elif target_type == "domain":
            results.extend([dns_scan(target), tls_scan(target), rdap_scan(target)])

            providers = provider_results(target, "domain")

        elif target_type == "ip":
            # Direct IP lookups remain non-invasive; no port probing is performed.

            try:
                reverse = __import__("socket").gethostbyaddr(target)[0]

            except Exception:
                reverse = None

            results.append(
                module_result(
                    "ip",
                    target,
                    "ip",
                    data={
                        "reverse_dns": reverse,
                        "network_policy": "No port scan performed.",
                    },
                )
            )

            providers = provider_results(target, "ip")

        elif target_type == "hash":
            providers = provider_results(target, "hash")

        elif target_type == "email":
            providers = provider_results(target, "email")

    from .ioc_correlation import persist_provider_results
    persist_provider_results(providers, target, target_type)
    score, level, confidence, findings, factors = _risk(results, providers)

    record = TargetScan.objects.create(
        job=job,
        scan_id=job.scan_id if job else str(uuid.uuid4()),
        user=user,
        target=target,
        target_type=target_type,
        status=(
            "PARTIAL"
            if any(x["status"] in {"error", "blocked", "unavailable"} for x in results)
            and any(x["status"] == "success" for x in results)
            else "FAILED"
            if results and not any(x["status"] == "success" for x in results)
            else "UNAVAILABLE"
            if not results
            and not any(
                x.get("status") in {"success", "found", "not_found"} for x in providers
            )
            else "COMPLETED"
        ),
        risk_score=score,
        risk_level=level,
        confidence=confidence,
        results=results,
        provider_results=providers,
        findings=findings,
        started_at=started,
        completed_at=timezone.now(),
    )

    record.results.append(
        module_result(
            "risk_explanation",
            target,
            target_type,
            data={
                "score": score,
                "factors": factors,
                "formula": "Sum factor points, capped at 100",
                "meaning": "Prioritization heuristic; not a probability or safety verdict.",
            },
        )
    )
    record.save(update_fields=["results"])
    from .persistence import persist_findings

    persist_findings(record)

    return record, factors


def run_target_scan(user, raw_target="", uploaded=None):
    """Record a running job before collection and retain failures for inspection."""
    if not _limit(user):
        raise ValueError("Target scan rate limit reached. Try again later.")
    kind = "file" if uploaded else classify_target(raw_target)[0]
    job = ScanJob.objects.create(
        scan_id=str(uuid.uuid4()), requested_by=user, scan_type=kind, status="QUEUED"
    )
    claimed = ScanJob.objects.filter(pk=job.pk, status="QUEUED").update(
        status="RUNNING", started_at=timezone.now()
    )
    if not claimed:
        raise ValueError("The queued job was cancelled before collection started.")
    try:
        return _run_target_scan(user, raw_target, uploaded, job=job)
    except Exception as exc:
        ScanJob.objects.filter(pk=job.pk).update(
            status="FAILED",
            completed_at=timezone.now(),
            error=type(exc).__name__,
            progress=100,
        )
        raise
