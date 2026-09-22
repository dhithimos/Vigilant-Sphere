"""Persist normalized findings alongside immutable investigation observations."""

import hashlib
import json
import uuid
from django.db import transaction
from myapp.models import ScanJob, Finding, FindingEvidence


@transaction.atomic
def persist_findings(record):
    values = dict(
        scan_id=record.scan_id,
        requested_by=record.user,
        scan_type=record.target_type,
        status=record.status,
        progress=100,
        started_at=record.started_at,
        completed_at=record.completed_at,
        finding_count=len(record.findings),
        risk_score=record.risk_score,
        scanner_count=len(record.results),
        completed_scanner_count=sum(x["status"] == "success" for x in record.results),
        failed_scanner_count=sum(
            x["status"] in {"error", "blocked", "unavailable"} for x in record.results
        ),
    )
    if record.job_id:
        job = record.job
        for key, value in values.items():
            setattr(job, key, value)
        job.save(update_fields=list(values))
    else:
        job = ScanJob.objects.create(**values)
    from myapp.mitre_data import dataset

    technique_ids = {x["id"] for x in dataset()["techniques"]}
    from .ioc_correlation import correlation_block
    for row in record.findings:
        evidence = row.get("evidence", {})
        finding = Finding.objects.create(
            job=job,
            finding_id=uuid.uuid4().hex,
            fingerprint=hashlib.sha256(
                json.dumps(row, sort_keys=True).encode()
            ).hexdigest(),
            scanner={"file": "files", "url": "urls"}.get(
                record.target_type, record.target_type
            ),
            finding_type=row.get("category", "observation"),
            title=row["title"],
            description=row.get("description", ""),
            severity=row.get("severity", "INFO"),
            risk_score=row.get("points", {
                "INFO": 0,
                "LOW": 8,
                "MEDIUM": 20,
                "HIGH": 40,
                "CRITICAL": 65,
            }.get(row.get("severity", "INFO"), 0)),
            confidence={"high": 0.9, "medium": 0.6, "low": 0.3}.get(
                row.get("confidence"), 0.3
            ),
            evidence=evidence,
            ioc=correlation_block(dict(row,results=record.results),record.user),
            recommendation=row.get("recommendation", ""),
            mitre_technique=row.get("mitre_technique", "")
            if row.get("mitre_technique") in technique_ids
            else "",
            mitre_tactic=row.get("mitre_tactic", ""),
        )
        FindingEvidence.objects.create(
            finding=finding,
            source=row.get("source", "local"),
            content=evidence,
            content_hash=hashlib.sha256(
                json.dumps(evidence, sort_keys=True).encode()
            ).hexdigest(),
        )
    record.job = job
    record.save(update_fields=["job"])
