"""Authorized response tracking and private, download-only evidence artifacts."""

import hashlib
import json
from PIL import Image
from pathlib import PurePosixPath
from django.contrib.auth.decorators import login_required
from django.db import transaction
from django.db.models import Q
from django.http import HttpResponse
from django.shortcuts import get_object_or_404, redirect
from django.utils import timezone
from django.views.decorators.http import require_POST
from .models import Incident, IncidentArtifact


def authorized_incident(user, pk):
    return get_object_or_404(
        Incident.objects.filter(Q(owner=user) | Q(assigned_responder=user)), pk=pk
    )


def default_playbook():
    return [
        {"phase": phase, "action": action, "status": "Pending"}
        for phase, action in [
            ("TRIAGE", "Validate evidence, scope and affected assets"),
            ("CONTAINMENT", "Document and authorize a proportionate containment plan"),
            ("ERADICATION", "Remove confirmed causes using an approved change process"),
            ("RECOVERY", "Validate restored service and monitor for recurrence"),
            ("REVIEW", "Record lessons, remaining risks and follow-up owners"),
        ]
    ]


def timeline(incident, user, event):
    incident.notes = (incident.notes if isinstance(incident.notes, list) else []) + [
        dict(
            at=timezone.now().isoformat(),
            actor=user.username,
            event=event,
            phase=incident.phase,
        )
    ]


@login_required
@require_POST
@transaction.atomic
def update_response(request, pk):
    incident = authorized_incident(request.user, pk)
    incident = Incident.objects.select_for_update().get(pk=incident.pk)
    note = request.POST.get("note", "").strip()
    if not note or len(note) > 4000:
        return HttpResponse("A note of 1–4000 characters is required.", status=400)
    if "step" in request.POST:
        if not incident.playbook:
            incident.playbook = default_playbook()
        try:
            index = int(request.POST["step"])
        except ValueError:
            return HttpResponse(status=400)
        if not 0 <= index < len(incident.playbook):
            return HttpResponse(status=400)
        incident.playbook[index].update(
            status="Reviewed",
            responder=request.user.username,
            at=timezone.now().isoformat(),
        )
        timeline(incident, request.user, "Playbook step reviewed: " + note)
    else:
        phase = request.POST.get("phase")
        if phase not in dict(Incident.PHASES):
            return HttpResponse("Invalid phase", status=400)
        incident.phase = phase
        timeline(incident, request.user, "Response phase updated: " + note)
    incident.save()
    return redirect("incident_detail", pk=pk)


def validate_artifact(uploaded):
    name = PurePosixPath(uploaded.name.replace("\\", "/")).name
    if not name or len(name) > 180 or any(ord(c) < 32 for c in name):
        raise ValueError("Invalid filename")
    data = uploaded.read(2 * 1024 * 1024 + 1)
    if not data or len(data) > 2 * 1024 * 1024:
        raise ValueError("File must be between 1 byte and 2 MB")
    ext = PurePosixPath(name).suffix.lower()
    types = {
        ".txt": "text/plain",
        ".csv": "text/csv",
        ".json": "application/json",
        ".pdf": "application/pdf",
        ".png": "image/png",
        ".jpg": "image/jpeg",
        ".jpeg": "image/jpeg",
    }
    if ext not in types:
        raise ValueError("Unsupported attachment type")
    if ext in {".txt", ".csv", ".json"}:
        text = data.decode("utf-8")
        if "\0" in text:
            raise ValueError("Binary content in text attachment")
        if ext == ".json":
            json.loads(text)
    if ext == ".pdf" and not data.startswith(b"%PDF-"):
        raise ValueError("PDF signature not found")
    if ext in {".png", ".jpg", ".jpeg"}:
        from PIL import Image
        from io import BytesIO

        with Image.open(BytesIO(data)) as image:
            if image.width * image.height > 16_000_000:
                raise ValueError("Image dimensions exceed limit")
            if image.format != ("PNG" if ext == ".png" else "JPEG"):
                raise ValueError("Image type mismatch")
            image.verify()
    return name, data, types[ext]


@login_required
@require_POST
@transaction.atomic
def upload_artifact(request, pk):
    incident = authorized_incident(request.user, pk)
    uploaded = request.FILES.get("artifact")
    if not uploaded:
        return HttpResponse("Choose an attachment", status=400)
    try:
        name, data, mime = validate_artifact(uploaded)
    except (ValueError, UnicodeError, OSError, Image.DecompressionBombError):
        return HttpResponse("Invalid, oversized or unsupported attachment", status=400)
    if incident.artifacts.count() >= 50:
        return HttpResponse("Attachment limit reached", status=400)
    artifact = IncidentArtifact.objects.create(
        incident=incident,
        uploaded_by=request.user,
        name=name,
        data=data,
        content_type=mime,
        size=len(data),
        sha256=hashlib.sha256(data).hexdigest(),
    )
    timeline(
        incident,
        request.user,
        f"Evidence attachment #{artifact.pk} saved; SHA-256 {artifact.sha256}",
    )
    incident.save(update_fields=["notes", "updated_at"])
    return redirect("incident_detail", pk=pk)


@login_required
def download_artifact(request, pk):
    artifact = get_object_or_404(
        IncidentArtifact.objects.filter(
            Q(incident__owner=request.user)
            | Q(incident__assigned_responder=request.user)
        ),
        pk=pk,
    )
    response = HttpResponse(
        bytes(artifact.data), content_type="application/octet-stream"
    )
    # A fixed generated filename prevents header injection and browser inline rendering.
    extension = PurePosixPath(artifact.name).suffix.lower()
    response["Content-Disposition"] = (
        f'attachment; filename="evidence-{artifact.pk}{extension}"'
    )
    response["X-Content-Type-Options"] = "nosniff"
    response["Cache-Control"] = "no-store"
    return response
