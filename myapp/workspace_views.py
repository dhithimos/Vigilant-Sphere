from .presentation import render, display_text

"""Authorized lifecycle views for investigations, incidents and publishing."""

import csv
import json
import uuid
from django import forms
from django.contrib.auth.decorators import login_required
from django.db.models import Q
from django.http import HttpResponse
from django.shortcuts import get_object_or_404, redirect
from django.utils import timezone
from .models import Incident, Finding, TargetScan, CMSBlogPost, ScanJob


class IncidentForm(forms.ModelForm):
    class Meta:
        model = Incident
        fields = [
            "title",
            "description",
            "severity",
            "target",
            "status",
            "assigned_responder",
            "findings",
            "scan_jobs",
        ]
        widgets = {"description": forms.Textarea(attrs={"rows": 4})}

    def __init__(self, *args, user, **kwargs):
        super().__init__(*args, **kwargs)
        from django.contrib.auth import get_user_model
        self.fields["assigned_responder"].queryset = get_user_model().objects.filter(is_active=True)
        self.fields["assigned_responder"].required=False
        self.fields["findings"].queryset = Finding.objects.filter(
            job__requested_by=user
        )
        self.fields["findings"].required = False
        self.fields["scan_jobs"].queryset = ScanJob.objects.filter(requested_by=user)
        self.fields["scan_jobs"].required = False
        self.fields["scan_jobs"].label_from_instance = lambda job: (
            f"{job.scan_id[:8]} | {job.scan_type} | {job.status} | {job.created_at:%Y-%m-%d %H:%M}"
        )
        self.fields[
            "findings"
        ].help_text = "Select real findings or a related scan job below. Run a scan first if both lists are empty."
        self.fields["severity"] = forms.ChoiceField(
            choices=[
                (x, x.title()) for x in ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
            ]
        )

    def clean(self):
        data = super().clean()
        if not data.get("findings") and not data.get("scan_jobs"):
            raise forms.ValidationError(
                "Select at least one of your findings or scan jobs. Run a scan first if none exist; incidents require recorded evidence."
            )
        return data


@login_required
def incident_list(request):
    return render(
        request,
        "myapp/workspace_list.html",
        {
            "title": "Incidents",
            "incidents": Incident.objects.filter(Q(owner=request.user)|Q(assigned_responder=request.user), archived=False),
            "create_incident": True,
        },
    )


@login_required
def incident_edit(request, pk=None):
    obj = get_object_or_404(Incident, pk=pk, owner=request.user) if pk else None
    initial = {}
    if not obj and request.GET.get("finding"):
        finding = get_object_or_404(
            Finding, pk=request.GET["finding"], job__requested_by=request.user
        )
        initial = {
            "title": finding.title,
            "description": finding.description,
            "severity": finding.severity,
            "findings": [finding.pk],
            "scan_jobs": [finding.job_id],
        }
    form = IncidentForm(
        request.POST or None, instance=obj, user=request.user, initial=initial
    )
    if request.method == "POST" and form.is_valid():
        obj = form.save(commit=False)
        obj.owner = request.user
        if not obj.incident_id:
            obj.incident_id = "VS-" + uuid.uuid4().hex[:12]
        obj.notes = (obj.notes if isinstance(obj.notes, list) else []) + [
            {
                "at": timezone.now().isoformat(),
                "actor": request.user.username,
                "event": "Saved incident",
                "status": obj.status,
            }
        ]
        obj.save()
        form.save_m2m()
        return redirect("incident_detail", pk=obj.pk)
    return render(
        request,
        "myapp/editor.html",
        {
            "title": "Edit incident" if obj else "Create incident from findings",
            "form": form,
            "incident_editor": True,
        },
    )


@login_required
def incident_detail(request, pk):
    from .incident_response import authorized_incident, default_playbook
    obj = authorized_incident(request.user,pk)
    if not obj.playbook:obj.playbook=default_playbook()
    if request.method == "POST":
        if request.POST.get("action") == "archive" and obj.owner_id != request.user.pk:
            return HttpResponse(status=403)
        if request.POST.get("action") == "archive":
            obj.archived = True
        note = request.POST.get("note", "").strip()[:4000]
        if not note and request.POST.get("action") != "archive":
            return HttpResponse("Enter a note or choose Archive.", status=400)
        obj.notes = (obj.notes if isinstance(obj.notes, list) else []) + [
            {
                "at": timezone.now().isoformat(),
                "actor": request.user.username,
                "event": note or "Archived incident",
            }
        ]
        obj.save()
        return redirect("incident_detail", pk=pk)
    return render(
        request,
        "myapp/incident_detail.html",
        {
            "incident": obj,
            "phases": Incident.PHASES,
            "artifacts":obj.artifacts.defer("data").select_related("uploaded_by"),
            "findings": obj.findings.select_related("job"),
            "related_jobs": obj.scan_jobs.filter(requested_by=request.user),
            "mitre_techniques": obj.findings.filter(job__requested_by=request.user)
            .exclude(mitre_technique="")
            .values_list("mitre_technique", "mitre_tactic")
            .distinct(),
        },
    )


@login_required
def finding_detail(request, pk):
    obj = get_object_or_404(Finding, pk=pk, job__requested_by=request.user)
    choices = ["OPEN", "ACKNOWLEDGED", "RESOLVED", "FALSE_POSITIVE", "ACCEPTED_RISK"]
    if request.method == "POST":
        status = request.POST.get("status")
        if status not in choices:
            return HttpResponse("Invalid status", status=400)
        obj.status = status
        obj.save(update_fields=["status", "updated_at"])
        return redirect("finding_detail", pk=pk)
    from .alerts import delivery_label

    related = (
        Finding.objects.filter(
            job__requested_by=request.user,
            pk__in=(obj.ioc or {}).get("related_findings", []),
        )
        if isinstance(obj.ioc, dict)
        else []
    )
    return render(
        request,
        "myapp/finding_detail.html",
        {
            "finding": obj,
            "choices": choices,
            "delivery_status": delivery_label(obj),
            "related_ioc_findings": related,
        },
    )


@login_required
def history(request):
    from .models import ScanResult

    return render(
        request,
        "myapp/workspace_list.html",
        {
            "title": "Investigation history and reports",
            "legacy_scans": ScanResult.objects.filter(user=request.user).order_by(
                "-created_at"
            )[:100],
            "scans": TargetScan.objects.filter(user=request.user).order_by(
                "-created_at"
            )[:200],
        },
    )


@login_required
def compare(request):
    scans = TargetScan.objects.filter(user=request.user).order_by("-created_at")
    selected = []
    if request.GET.get("left") and request.GET.get("right"):
        for key in ["left", "right"]:
            selected.append(get_object_or_404(scans, scan_id=request.GET[key]))
    delta = None
    if selected:
        a, b = selected
        old = {x["title"] for x in a.findings}
        new = {x["title"] for x in b.findings}
        delta = {
            "risk_change": b.risk_score - a.risk_score,
            "added": sorted(new - old),
            "removed": sorted(old - new),
            "note": "Different collection conditions can change findings; removal does not prove remediation.",
        }
    return render(
        request,
        "myapp/compare.html",
        {"scans": scans[:200], "selected": selected, "delta": delta},
    )


@login_required
def csv_report(request, scan_id):
    scan = get_object_or_404(TargetScan, scan_id=scan_id, user=request.user)
    response = HttpResponse(content_type="text/csv")
    response["Content-Disposition"] = 'attachment; filename="investigation.csv"'
    writer = csv.writer(response)

    def safe(value):
        text = display_text(value)
        return (
            "'" + text
            if text.lstrip().startswith(("=", "+", "-", "@", "\t", "\r"))
            else text
        )

    writer.writerow(
        [
            "scan_id",
            "target",
            "timestamp",
            "status",
            "severity",
            "title",
            "evidence",
            "confidence",
            "recommendation",
        ]
    )
    for row in scan.findings or [{}]:
        writer.writerow(
            [
                safe(x)
                for x in [
                    scan.scan_id,
                    scan.target,
                    scan.created_at,
                    scan.status,
                    row.get("severity", ""),
                    row.get("title", "No findings recorded; not a safety verdict"),
                    json.dumps(row.get("evidence", {})),
                    row.get("confidence", ""),
                    row.get("recommendation", ""),
                ]
            ]
        )
    for row in scan.provider_results:
        writer.writerow(
            [
                scan.scan_id,
                "",
                "",
                "Capability status",
                "",
                row.get("provider"),
                row.get("status"),
                "",
                "",
            ]
        )
    return response


class PostForm(forms.ModelForm):
    class Meta:
        model = CMSBlogPost
        fields = [
            "title",
            "slug",
            "category",
            "tags",
            "excerpt",
            "content",
            "status",
            "published_at",
        ]
        widgets = {
            "published_at": forms.DateTimeInput(attrs={"type": "datetime-local"}),
            "content": forms.Textarea(attrs={"rows": 12}),
        }

    def clean(self):
        data = super().clean()
        if data.get("status") == "SCHEDULED" and not data.get("published_at"):
            self.add_error("published_at", "Scheduled posts need a publication date.")
        return data


def public_queryset():
    return CMSBlogPost.objects.filter(
        Q(status="PUBLISHED") | Q(status="SCHEDULED"), published_at__lte=timezone.now()
    )


def public_posts(request):
    from django.core.paginator import Paginator

    rows = public_queryset().order_by("-published_at")
    if request.GET.get("category"):
        rows = rows.filter(category=request.GET["category"])
    return render(
        request,
        "myapp/public_blog.html",
        {"posts": Paginator(rows, 10).get_page(request.GET.get("page"))},
    )


def post_detail(request, slug):
    rows = (
        CMSBlogPost.objects.all()
        if request.user.is_authenticated
        else public_queryset()
    )
    return render(
        request, "myapp/post_detail.html", {"post": get_object_or_404(rows, slug=slug)}
    )


@login_required
def post_edit(request, pk=None):
    obj = get_object_or_404(CMSBlogPost, pk=pk) if pk else None
    if obj and request.method == "POST" and request.POST.get("action") == "delete":
        obj.delete()
        return redirect("cms_blog")
    form = PostForm(request.POST or None, instance=obj)
    if request.method == "POST" and form.is_valid():
        obj = form.save(commit=False)
        obj.author = obj.author or request.user
        if obj.status == "PUBLISHED" and not obj.published_at:
            obj.published_at = timezone.now()
        obj.save()
        return redirect("cms_blog")
    return render(
        request,
        "myapp/editor.html",
        {"title": "Edit post" if obj else "Create post", "form": form},
    )


@login_required
def post_list(request):
    return render(
        request,
        "myapp/workspace_list.html",
        {
            "title": "CMS posts",
            "posts": CMSBlogPost.objects.order_by("-updated_at"),
            "create_post": True,
        },
    )


@login_required
def static_analysis(request, kind):
    from .scanners.web_analysis import analyze_html, javascript
    from .scanners.target import dns_scan, tls_scan, classify_target, http_scan

    result = None
    if request.method == "POST":
        value = request.POST.get("input", "")[: 1024 * 1024]
        if kind in {"html", "javascript"}:
            result = analyze_html(value) if kind == "html" else javascript(value)
        else:
            try:
                category, target = classify_target(value)
                if kind == "dns":
                    result = dns_scan(target, category)
                elif kind == "tls":
                    result = tls_scan(
                        __import__("urllib.parse", fromlist=["urlsplit"])
                        .urlsplit(target)
                        .hostname
                        if category == "url"
                        else target
                    )
                else:
                    result = http_scan(target)
            except ValueError as exc:
                result = {"state": "Blocked", "detail": str(exc)}
    return render(
        request,
        "myapp/static_analysis.html",
        {
            "title": kind.upper() + " analysis",
            "result": json.dumps(result, indent=2) if result is not None else None,
            "kind": kind,
        },
    )


@login_required
def mitre(request, technique=None, tactic=None):
    from .mitre_data import dataset, children_of, tactic_name_and_slug

    import copy

    data = dataset()
    rows = copy.deepcopy(data["techniques"])
    owned = (
        Finding.objects.filter(job__requested_by=request.user)
        .exclude(mitre_technique="")
        .order_by("-timestamp")
    )
    from django.db.models import Count, Window, F
    from django.db.models.functions import RowNumber

    counts = dict(
        owned.values("mitre_technique")
        .annotate(n=Count("pk"))
        .values_list("mitre_technique", "n")
    )
    by_technique = {}
    samples = owned.annotate(
        rank=Window(
            expression=RowNumber(),
            partition_by=[F("mitre_technique")],
            order_by=[F("timestamp").desc(), F("pk").desc()],
        )
    ).filter(rank__lte=10)
    for finding in samples:
        by_technique.setdefault(finding.mitre_technique, []).append(finding)
    tactics = {x["slug"]: x for x in data["tactics"]}
    coverage = [
        {
            "name": value["name"],
            "slug": key,
            "total": sum(key in x["tactics"] for x in rows),
            "mapped": sum(
                key in x["tactics"] and x["id"] in by_technique for x in rows
            ),
        }
        for key, value in tactics.items()
    ]
    for row in rows:
        row["finding_count"] = counts.get(row["id"], 0)
        row["related_findings"] = by_technique.get(row["id"], [])
        row["state"] = "Mapped" if row["related_findings"] else "No Evidence"
        row["tactic_names"] = [
            tactics[x]["name"] if x in tactics else x for x in row["tactics"]
        ]
        row["children"] = children_of(row["id"])
        row["tactic_links"] = [tactic_name_and_slug(slug) for slug in row["tactics"]]
    if technique:
        rows = [x for x in rows if x["id"] == technique]
        if not rows:
            return HttpResponse("Technique not in the bundled dataset", status=404)
    if tactic:
        if tactic not in tactics:
            return HttpResponse("Tactic not in the bundled dataset", status=404)
        rows = [x for x in rows if tactic in x["tactics"]]
    query = request.GET.get("q", "").strip()[:200].lower()
    if query:
        rows = [
            row
            for row in rows
            if query
            in (row["id"] + " " + row["name"] + " " + row["description"]).lower()
        ]
    if request.GET.get("format") in {"json", "csv"}:
        import json, csv, io

        exported = [
            {
                "id": r["id"],
                "name": r["name"],
                "state": r["state"],
                "finding_count": r["finding_count"],
                "tactics": r["tactics"],
                "reference": r["reference"],
            }
            for r in rows
        ]
        from django.db.models import Prefetch

        selected_ids = {r["id"] for r in rows}
        mapping_rows = list(
            owned.filter(mitre_technique__in=selected_ids).prefetch_related(
                Prefetch(
                    "incidents", queryset=Incident.objects.filter(owner=request.user)
                )
            )[:10001]
        )
        truncated = len(mapping_rows) > 10000
        details = {}
        for finding in mapping_rows[:10000]:
            details.setdefault(finding.mitre_technique, []).append(
                {
                    "id": finding.pk,
                    "title": finding.title,
                    "confidence": finding.confidence,
                    "incidents": [
                        {"id": i.pk, "title": i.title} for i in finding.incidents.all()
                    ],
                }
            )
        for row in exported:
            row["findings"] = details.get(row["id"], [])
        if request.GET["format"] == "json":
            response = HttpResponse(
                json.dumps(
                    {
                        "provenance": data["provenance"],
                        "techniques": exported,
                        "findings_truncated": truncated,
                    }
                ),
                content_type="application/json",
            )
        else:
            stream = io.StringIO()
            writer = csv.writer(stream)
            writer.writerow(
                [
                    "id",
                    "name",
                    "state",
                    "finding_count",
                    "tactics",
                    "reference",
                    "findings_and_incidents_json",
                    "findings_truncated",
                ]
            )

            def cell(value):
                text = str(value)
                return (
                    "'" + text
                    if text.lstrip().startswith(("=", "+", "-", "@", "\t", "\r"))
                    else text
                )

            for row in exported:
                writer.writerow(
                    [
                        cell(x)
                        for x in [
                            row["id"],
                            row["name"],
                            row["state"],
                            row["finding_count"],
                            "; ".join(row["tactics"]),
                            row["reference"],
                            json.dumps(row["findings"]),
                            truncated,
                        ]
                    ]
                )
            response = HttpResponse(stream.getvalue(), content_type="text/csv")
        response["Content-Disposition"] = (
            'attachment; filename="mitre-coverage.' + request.GET["format"] + '"'
        )
        return response
    return render(
        request,
        "myapp/mitre_catalog.html",
        {
            "techniques": rows,
            "tactics": data["tactics"],
            "coverage": coverage,
            "meta": data["provenance"],
            "detail_view":bool(technique),
            "matrix":[{"tactic":t,"techniques":[r for r in rows if t["slug"] in r["tactics"]]} for t in data["tactics"]],
        },
    )


@login_required
def cancel_job(request, job_id):
    from .models import ScanJob

    if request.method != "POST":
        return HttpResponse(status=405)
    job = get_object_or_404(ScanJob, id=job_id, requested_by=request.user)
    changed = ScanJob.objects.filter(pk=job.pk, status="QUEUED").update(
        status="CANCELLED", completed_at=timezone.now()
    )
    if not changed:
        return HttpResponse(
            "Only queued jobs can be cancelled. Running synchronous scans finish within their configured limits.",
            status=409,
        )
    return redirect("scan_job_detail", job_id=job.pk)


@login_required
def trust_wifi(request, audit_id):
    from .wifi_audit_service import authorize
    from .models import WiFiAudit, TrustedWifiProfile
    from .views import audit_security_event, require_feature

    if request.method != "POST":
        return HttpResponse(status=405)
    disabled = require_feature("WIFI_SECURITY_AUDIT")
    if disabled:
        return disabled
    try:
        authorize(request.user)
    except PermissionError:
        return HttpResponse(status=403)
    audit = get_object_or_404(WiFiAudit, pk=audit_id, user=request.user)
    if request.POST.get("action") == "untrust":
        TrustedWifiProfile.objects.filter(
            user=request.user, profile_name=audit.profile_name
        ).delete()
    else:
        TrustedWifiProfile.objects.update_or_create(
            user=request.user,
            profile_name=audit.profile_name,
            defaults={
                "security_level_at_trust": audit.security_level,
                "risk_score_at_trust": audit.risk_score,
            },
        )
    audit_security_event(
        request, "Wi-Fi trust preference changed", details={"audit_id": audit.pk}
    )
    return redirect("wifi_security")
