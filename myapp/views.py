from .presentation import render, JsonResponse, display_text
from .context import can_inspect_host
from django.conf import settings as django_settings

import csv


import json


import os


from django.contrib import messages


from django.contrib.auth import authenticate, get_user_model, login, logout

from django.contrib.auth.decorators import login_required

from django.contrib.auth import update_session_auth_hash

from django.contrib.auth.forms import PasswordChangeForm

from django.contrib.auth.password_validation import validate_password

from django.core.exceptions import ValidationError

from django.contrib.sessions.models import Session

from django.db.models import Count

from django.http import HttpResponse

from django.shortcuts import get_object_or_404, redirect


from django.utils.html import strip_tags

from django.utils.text import slugify

from django.utils import timezone

from reportlab.lib.pagesizes import letter

from reportlab.pdfgen import canvas

import psutil

from PIL import Image, UnidentifiedImageError


from .models import (
    AuditLog,
    CMSBlogPost,
    CMSDeveloperProfile,
    DeveloperImage,
    CMSMedia,
    CMSNavigationItem,
    CMSPage,
    CMSPageRevision,
    CMSSiteSettings,
    ContactMessage,
    FeatureFlag,
    Incident,
    RiskAssessment,
    SecurityAuditEvent,
    SecurityPolicy,
    ScanFeedback,
    ScanResult,
    UserActivity,
    ScanJob,
    Finding,
    AssetInventory,
    WiFiAudit,
    AlertEmailConfiguration,
)

from .scan_engine import run_combined_scan

from .security_pipeline import SCANNER_CATALOG, execute_job

from .captcha import (
    captcha_configured,
    captcha_provider,
    captcha_site_key,
    verify_captcha,
)

from .analysis.investigation import run_target_scan

from .models import TargetScan

from .threat_intel import provider_status

from .scanners.wifi import collect as collect_wifi


from .chatbot import answer as chatbot_answer


User = get_user_model()


BLOGS = [
    {
        "title": "How to judge whether an open port is dangerous",
        "category": "Network security",
        "body": "An open port is not automatically malicious. Risk depends on the service, exposure, patch level, and who can reach it. Remote admin, database, and file-sharing ports should be restricted.",
    },
    {
        "title": "What to do when a scan finds suspicious files",
        "category": "Malware triage",
        "body": "Do not run unknown files. Check the source, hash the file, scan it with a trusted antivirus service, and quarantine or delete files that cannot be verified.",
    },
    {
        "title": "MITRE mapping for practical troubleshooting",
        "category": "Learning",
        "body": "Use MITRE ATT&CK mapping to connect suspicious processes, exposed services, risky scripts, and user execution findings to analyst-friendly tactics.",
    },
    {
        "title": "Endpoint hardening checklist",
        "category": "System security",
        "body": "Keep firewall, antivirus, secure boot, disk encryption, patching, and user privilege controls enabled. Review startup apps and browser downloads regularly.",
    },
    {
        "title": "SOC triage for critical endpoint alerts",
        "category": "SOC operations",
        "body": "Start with impact, evidence, and containment. Validate process lineage, isolate only when confidence is high, and preserve logs before cleanup.",
    },
    {
        "title": "MITRE ATT&CK mapping for scan results",
        "category": "Threat intelligence",
        "body": "Map suspicious PowerShell, startup persistence, exposed services, and user execution findings to ATT&CK so every recommendation has analyst context.",
    },
    {
        "title": "When Heuristic recommendations say quarantine",
        "category": "Incident response",
        "body": "Quarantine is safest for unknown executables, credential leaks, and scripts from untrusted sources. Capture hash, path, and user context first.",
    },
]


def client_ip(request):

    forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR", "")

    if forwarded_for:
        return forwarded_for.split(",")[0].strip()

    return request.META.get("REMOTE_ADDR")


def client_device(request):

    return request.META.get("HTTP_USER_AGENT", "Unknown device")[:300]


RISK_SCORE_FALLBACKS = {
    "LOW": 10,
    "MEDIUM": 30,
    "HIGH": 55,
    "CRITICAL": 85,
}


RISK_POINT_WEIGHTS = {
    "low": 5,
    "medium": 15,
    "high": 35,
    "critical": 55,
}


def score_to_level(score):

    if score <= 20:
        return "LOW"

    if score <= 40:
        return "MEDIUM"

    if score <= 70:
        return "HIGH"

    return "CRITICAL"


def scan_display_score(scan):

    if not scan:
        return 0

    stored_score = int(scan.score or 0)

    stored_level = (scan.risk_level or "LOW").upper()

    if score_to_level(stored_score) == stored_level:
        return stored_score

    evidence_score = 0

    for row in scan.open_ports or []:
        evidence_score += RISK_POINT_WEIGHTS.get(
            str(row.get("risk", "medium")).lower(), 15
        )

    for item in scan.detected_files or []:
        evidence_score += RISK_POINT_WEIGHTS.get(
            str(item.get("risk", "medium")).lower(), 15
        )

    module_score = ((scan.modules or {}).get("risk_engine") or {}).get("threat_score")

    if isinstance(module_score, int):
        evidence_score = max(evidence_score, module_score)

    fallback = RISK_SCORE_FALLBACKS.get(stored_level, 10)

    return min(100, max(evidence_score, fallback))


def decorate_scan(scan):

    if scan:
        scan.display_score = scan_display_score(scan)

        scan.display_risk_level = score_to_level(scan.display_score)

    return scan


def traffic_label(row):

    service = row.get("service")

    port = row.get("port")

    protocol = row.get("protocol")

    return {
        "label": service or protocol or "Unknown service",
        "port": port or "Unknown port",
        "risk": row.get("risk") or "unknown",
        "explanation": (
            "Mapped from the scanner service table."
            if service and service != "Unknown service"
            else "Unknown means the OS reported a connection but the scanner could not map that port to a known service name."
        ),
    }


def scan_findings(scan):

    if not scan:
        return []

    findings = []

    for port in scan.open_ports or []:
        findings.append(
            {
                "kind": "port",
                "risk": str(port.get("risk", "medium")).upper(),
                "title": f"{port.get('protocol', 'TCP')}:{port.get('port', 'unknown')} {port.get('service', 'Unknown service')}",
            }
        )

    for item in scan.detected_files or []:
        findings.append(
            {
                "kind": "file",
                "risk": str(item.get("risk", "medium")).upper(),
                "title": item.get("name", "Unknown file"),
            }
        )

    return findings


def scan_stat_summary(scans):

    findings = []

    for scan in scans:
        findings.extend(scan_findings(scan))

    return {
        "total_findings": len(findings),
        "critical_findings": len(
            [item for item in findings if item["risk"] == "CRITICAL"]
        ),
        "high_findings": len([item for item in findings if item["risk"] == "HIGH"]),
        "open_incidents": len(
            [item for item in findings if item["risk"] in {"HIGH", "CRITICAL"}]
        ),
    }


def enrich_file_item(file_item, index):

    path = file_item.get("path", "")

    name = file_item.get("name") or (
        path.split("\\")[-1].split("/")[-1] if path else f"file-{index + 1}"
    )

    sha256 = file_item.get("sha256") or "Not calculated for this saved result"

    risk = str(file_item.get("risk", "medium")).upper()

    location_flags = [
        marker
        for marker in [
            "AppData",
            "Temp",
            "Downloads",
            "Startup",
            "ProgramData",
            "Recycle Bin",
        ]
        if marker.lower() in path.lower()
    ]

    extension_mismatch = any(
        name.lower().endswith(pattern)
        for pattern in [".jpg.exe", ".pdf.exe", ".pdf.scr", ".docm"]
    )

    file_item = dict(file_item)

    file_item.update(
        {
            "index": index,
            "name": name,
            "path": path,
            "file_url": f"file:///{path.replace(chr(92), '/')}" if path else "",
            "sha256": sha256,
            "reputation": file_item.get("reputation")
            or (
                "Known suspicious local heuristic"
                if risk in {"HIGH", "CRITICAL"}
                else "Unknown / needs analyst review"
            ),
            "real_type": file_item.get("real_type")
            or "Requires python-magic or OS file inspection",
            "extension_mismatch": extension_mismatch,
            "entropy": file_item.get("entropy")
            or (
                "7.2 - Highly suspicious estimate"
                if risk == "CRITICAL"
                else "Not calculated for saved result"
            ),
            "signature": file_item.get("signature")
            or (
                "Unsigned or unverified"
                if risk in {"HIGH", "CRITICAL"}
                else "Not verified"
            ),
            "location_analysis": ", ".join(location_flags)
            if location_flags
            else "No dangerous user-location marker identified",
            "yara": file_item.get("yara")
            or (
                "Local heuristic match"
                if risk in {"HIGH", "CRITICAL"}
                else "No YARA match stored"
            ),
            "pe_analysis": file_item.get("pe_analysis")
            or "PE import/section analysis requires live executable inspection",
            "persistence": file_item.get("persistence")
            or "Check Run keys, Startup folder, Scheduled Tasks, and services",
            "behavior": file_item.get("behavior")
            or "Review for AV disable, hidden files, registry edits, process injection, network callbacks, or payload downloads",
            "mitre": file_item.get("mitre")
            or [
                "T1547 - Persistence",
                "T1055 - Process Injection",
                "T1003 - Credential Dumping",
                "T1059 - Command Execution",
            ],
        }
    )

    return file_item


def track_activity(request, option, detail=""):

    # Activity module: records authenticated user actions with device and network context.

    if request.user.is_authenticated:
        UserActivity.objects.create(
            user=request.user,
            option_used=option,
            detail=detail,
            ip_address=client_ip(request),
            device=client_device(request),
            place="Local/Unknown",
        )


def home(request):

    from .workspace_views import public_queryset

    return render(
        request,
        "myapp/home.html",
        {"published_posts": public_queryset().order_by("-published_at")[:3]},
    )


def register(request):

    if request.user.is_authenticated:
        return redirect("dashboard")

    captcha_context = {
        "captcha_configured": captcha_configured(),
        "captcha_provider": captcha_provider(),
        "captcha_site_key": captcha_site_key(),
    }

    if request.method == "POST" and not request.POST.get("action"):
        ok, reason = verify_captcha(request)

        if not ok:
            messages.error(request, "CAPTCHA verification failed. Please try again.")

            return render(request, "myapp/register.html", captcha_context)

        username = request.POST.get("username", "").strip()

        email = request.POST.get("email", "").strip()

        password1 = request.POST.get("password", "")

        password2 = request.POST.get("confirm_password", "")

        if not username or not email or not password1:
            messages.error(request, "Username, email, and password are required.")

            return redirect("register")

        if password1 != password2:
            messages.error(request, "Passwords do not match.")

            return redirect("register")

        try:
            validate_password(password1)

        except ValidationError as exc:
            messages.error(request, " ".join(exc.messages))

            return redirect("register")

        if User.objects.filter(username=username).exists():
            messages.error(request, "Username already exists.")

            return redirect("register")

        if User.objects.filter(email=email).exists():
            messages.error(request, "Email already exists.")

            return redirect("register")

        user = User.objects.create_user(
            username=username,
            email=email,
            password=password1,
        )

        AuditLog.objects.create(
            user=user,
            action="User Registration",
            details=f"User {username} registered",
        )

        messages.success(request, "Registration successful. You can now log in.")

        return redirect("login")

    return render(request, "myapp/register.html", captcha_context)


def user_login(request):

    if request.user.is_authenticated:
        return redirect("dashboard")

    captcha_context = {
        "captcha_configured": captcha_configured(),
        "captcha_provider": captcha_provider(),
        "captcha_site_key": captcha_site_key(),
    }

    if request.method == "POST":
        ok, reason = verify_captcha(request)

        if not ok:
            messages.error(request, "CAPTCHA verification failed. Please try again.")

            return render(request, "myapp/login.html", captcha_context)

        username = request.POST.get("username", "").strip()

        password = request.POST.get("password", "")

        if "@" in username:
            matched_user = User.objects.filter(email__iexact=username).first()

            username = matched_user.username if matched_user else username

        user = authenticate(request, username=username, password=password)

        if user is not None:
            login(request, user)

            AuditLog.objects.create(
                user=user,
                action="User Login",
                details="Successful login",
            )

            UserActivity.objects.create(
                user=user,
                option_used="login",
                detail="User logged in",
                ip_address=client_ip(request),
                device=client_device(request),
                place="Local/Unknown",
            )

            return redirect("dashboard")

        messages.error(request, "Invalid username or password.")

    return render(request, "myapp/login.html", captcha_context)


@login_required
def user_logout(request):

    track_activity(request, "logout", "User logged out")

    AuditLog.objects.create(
        user=request.user,
        action="Logout",
        details="User logged out",
    )

    logout(request)

    return redirect("login")


def forgot_password(request):

    from django.contrib.auth.forms import PasswordResetForm

    form = PasswordResetForm(request.POST or None)

    if request.method == "POST" and form.is_valid():
        if django_settings.EMAIL_HOST:
            try:
                form.save(
                    request=request,
                    use_https=request.is_secure(),
                    email_template_name="registration/password_reset_email.txt",
                )

            except Exception:
                messages.error(
                    request,
                    "Email delivery unavailable. Contact the local administrator.",
                )

                return render(request, "myapp/recovery.html", {"form": form})

        messages.info(
            request,
            "If recovery email is configured and the account exists, a reset link will be sent. Otherwise ask the local administrator to use manage.py changepassword.",
        )

    return render(request, "myapp/recovery.html", {"form": form})


@login_required
def dashboard(request):
    jobs = ScanJob.objects.filter(requested_by=request.user).order_by("-created_at")
    rows = Finding.objects.filter(job__requested_by=request.user)
    latest = jobs.first()
    return render(
        request,
        "myapp/dashboard.html",
        {
            "risk_score": latest.risk_score if latest else None,
            "risk_level": score_to_level(latest.risk_score)
            if latest
            else "No Evidence",
            "total_findings": rows.count(),
            "critical_findings": rows.filter(severity="CRITICAL").count(),
            "open_incidents": Incident.objects.filter(
                owner=request.user, archived=False
            )
            .exclude(status__in=["RESOLVED", "CLOSED"])
            .count(),
            "scans": jobs[:8],
        },
    )


@login_required
def launcher(request):

    # Launcher module: exposes every scanner and account action from one safe navigation page.

    track_activity(request, "launcher", "Viewed scanner launcher")

    modules = [
        {
            "name": "System Scan",
            "url": "/system/",
            "detail": "Endpoint health, startup entries, local files, and device posture.",
        },
        {
            "name": "Network Scan",
            "url": "/network/",
            "detail": "Active connections, exposed ports, service risk, and protocol review.",
        },
        {
            "name": "Password Checker",
            "url": "/mobile-security/",
            "detail": "Local-only password analysis and browser-side secure password generation.",
        },
        {
            "name": "Phishing URL Scanner",
            "url": "/phishing/",
            "detail": "Dedicated safe URL/domain reputation and phishing-pattern analyzer.",
        },
        {
            "name": "Password Strength",
            "url": "/password-strength/",
            "detail": "Local-only password strength analysis. Passwords are never stored.",
        },
        {
            "name": "File Security Scan",
            "url": "/file-scan/",
            "detail": "Safe static file hash, entropy, extension, script, document, and IOC checks.",
        },
        {
            "name": "Scan History",
            "url": "/scan-history/",
            "detail": "Open previous authorized scan reports and filter by scan type.",
        },
        {
            "name": "Reports",
            "url": "/reports/",
            "detail": "Security reports and export actions for your own scans.",
        },
        {
            "name": "Feature Flags",
            "url": "/feature-flags/",
            "detail": "Admin-controlled security feature switches with backend enforcement.",
        },
        {
            "name": "Combined Scan",
            "url": "/scan/",
            "detail": "Full SOC-style endpoint, network, file, MITRE, and risk scan.",
        },
        {
            "name": "Threat Detection",
            "url": "/threat-detection/",
            "detail": "EDR, NDR, file analysis, behavior analytics, SOAR guidance.",
        },
        {
            "name": "Profile",
            "url": "/profile/",
            "detail": "View account details and profile image.",
        },
        {
            "name": "Edit Profile",
            "url": "/edit-profile/",
            "detail": "Update name, age, phone, gender, address, and image.",
        },
        {
            "name": "Forgot Password",
            "url": "/forgot-password/",
            "detail": "Reset your local demo password.",
        },
        {
            "name": "Logout",
            "url": "/logout/",
            "detail": "End the current session safely.",
        },
    ]

    return render(request, "myapp/launcher.html", {"modules": modules})


@login_required
def feature_flags(request):

    ensure_default_feature_flags(request.user)

    if request.method == "POST":
        for flag in FeatureFlag.objects.all():
            flag.enabled = request.POST.get(flag.key) == "on"

            flag.rollout_percentage = max(
                0,
                min(
                    100,
                    int(
                        request.POST.get(f"{flag.key}_rollout", flag.rollout_percentage)
                        or 0
                    ),
                ),
            )

            flag.updated_by = request.user

            flag.save()

        SecurityAuditEvent.objects.create(
            user=request.user,
            action="Feature flags updated",
            target="global",
            details=feature_flag_map(),
        )

        messages.success(request, "Feature flags updated with backend enforcement.")

        return redirect("feature_flags")

    return render(
        request,
        "myapp/feature_flags.html",
        {"flags": FeatureFlag.objects.order_by("key")},
    )


def ensure_default_feature_flags(user=None):

    defaults = {
        "network_scan": True,
        "system_scan": True,
        "threat_detection": True,
        "phishing_scanner": True,
        "password_strength": True,
        "file_scanner": True,
        "mobile_security": True,
        "threat_intelligence": True,
        "mitre_attack": True,
        "yara_detection": True,
        "sigma_analysis": True,
        "reports": True,
        "blog": True,
        "registration": True,
        "OFFLINE_SECURITY_CHATBOT": True,
        "CRITICAL_EMAIL_ALERTS": True,
        "WIFI_SECURITY_AUDIT": True,
        "maintenance_mode": False,
    }

    for key, enabled in defaults.items():
        FeatureFlag.objects.get_or_create(
            key=key,
            defaults={
                "enabled": enabled,
                "updated_by": user
                if getattr(user, "is_authenticated", False)
                else None,
            },
        )


def feature_flag_map():

    return {flag.key: flag.enabled for flag in FeatureFlag.objects.all()}


def feature_enabled(key):

    ensure_default_feature_flags()

    flag = FeatureFlag.objects.filter(key=key).first()

    return not flag or flag.enabled


def require_feature(key):

    if not feature_enabled(key):
        return HttpResponse(
            "This feature is currently unavailable by administrator policy.", status=503
        )

    return None


def audit_security_event(request, action, target="", details=None):

    SecurityAuditEvent.objects.create(
        user=request.user if request.user.is_authenticated else None,
        action=action,
        target=target,
        details=details or {},
    )


def seed_initial_cms_content(user=None):

    pages = {
        "home": (
            "Vigilant Sphere",
            "Security intelligence for your digital environment.",
        ),
        "about": (
            "About Vigilant Sphere",
            "A security intelligence and threat analysis platform for defensive scanning and SOC-style reporting.",
        ),
        "contact": (
            "Contact",
            "Send questions, support requests, or suggestions to the Vigilant Sphere team.",
        ),
        "privacy": (
            "Privacy Policy",
            "Vigilant Sphere stores only the information required to provide account, scan, report, and contact features.",
        ),
        "developer": ("Developer", "Developer profile managed from the CMS."),
        "how-to-use": (
            "How To Use",
            "Run scans, review evidence, download reports, and follow remediation recommendations.",
        ),
        "suggestions": (
            "Suggestions",
            "Suggest improvements through the configured GitHub repository.",
        ),
        "documentation": (
            "Documentation",
            "Platform documentation and safe usage guidance.",
        ),
    }

    for slug, (title, content) in pages.items():
        CMSPage.objects.get_or_create(
            slug=slug,
            defaults={
                "title": title,
                "seo_title": title,
                "seo_description": content[:300],
                "excerpt": content[:240],
                "content": content,
                "status": "PUBLISHED",
                "author": user if getattr(user, "is_authenticated", False) else None,
                "published_at": timezone.now(),
            },
        )

    CMSSiteSettings.objects.get_or_create(id=1)

    CMSDeveloperProfile.objects.get_or_create(
        id=1,
        defaults={
            "developer_name": "Dhithimos E J",
            "short_bio": "Developer of Vigilant Sphere.",
            "github": django_settings.DEVELOPER_GITHUB_URL,
        },
    )





@login_required
def password_strength(request):

    unavailable = require_feature("password_strength")

    if unavailable:
        return unavailable

    # Password analysis is browser-only.  Do not accept a password in HTTP

    # requests, where it could reach proxies or access logs.

    if request.method == "POST":
        messages.error(
            request,
            "Password analysis is performed in your browser and passwords are not accepted by the server.",
        )

        return redirect("password_strength")

    return render(request, "myapp/password_strength.html")






def how_to_use(request):

    seed_initial_cms_content(request.user if request.user.is_authenticated else None)

    return render(
        request,
        "myapp/how_to_use.html",
        {"page": CMSPage.objects.filter(slug="how-to-use", status="PUBLISHED").first()},
    )










@login_required
def cms_pages(request):

    seed_initial_cms_content(request.user)

    return render(
        request, "myapp/cms_pages.html", {"pages": CMSPage.objects.order_by("title")}
    )


@login_required
def cms_page_edit(request, page_id=None):

    seed_initial_cms_content(request.user)

    page = get_object_or_404(CMSPage, id=page_id) if page_id else None

    if request.method == "POST":
        title = strip_tags(request.POST.get("title", "")).strip()

        slug = slugify(request.POST.get("slug", title))[:160]

        content = strip_tags(request.POST.get("content", "")).strip()

        status = request.POST.get("status", "DRAFT")

        if not title or not slug:
            messages.error(request, "Page title and slug are required.")

        else:
            if not page:
                page = CMSPage(author=request.user)

            page.title = title

            page.slug = slug

            page.seo_title = strip_tags(request.POST.get("seo_title", ""))[:220]

            page.seo_description = strip_tags(request.POST.get("seo_description", ""))[
                :320
            ]

            page.excerpt = strip_tags(request.POST.get("excerpt", ""))

            page.content = content

            page.status = status

            if status == "PUBLISHED" and not page.published_at:
                page.published_at = timezone.now()

            page.save()

            CMSPageRevision.objects.create(
                page=page,
                editor=request.user,
                title=page.title,
                content=page.content,
                status=page.status,
                change_summary="Saved from CMS editor",
            )

            audit_security_event(
                request,
                "CMS page saved",
                target=page.slug,
                details={"status": page.status},
            )

            messages.success(request, "CMS page saved and revision recorded.")

            return redirect("cms_pages")

    return render(request, "myapp/cms_page_edit.html", {"page_obj": page})


@login_required
def cms_media(request):

    seed_initial_cms_content(request.user)

    if request.method == "POST" and request.FILES.get("media_file"):
        upload = request.FILES["media_file"]

        from .uploads import clean_image

        try:
            upload = clean_image(upload)
        except ValueError as exc:
            messages.error(request, str(exc))
        else:
            CMSMedia.objects.create(
                title=strip_tags(request.POST.get("title", "Image"))[:180],
                file=upload,
                alt_text=strip_tags(request.POST.get("alt_text", ""))[:220],
                uploaded_by=request.user,
            )
            return redirect("cms_media")
    return render(
        request,
        "myapp/cms_media.html",
        {
            "media_files": CMSMedia.objects.filter(archived=False).order_by(
                "-created_at"
            )
        },
    )


@login_required
def cms_developer_images(request):

    if request.method == "POST":
        upload = request.FILES.get("image")

        if not upload:
            messages.error(request, "Choose an image to upload.")

        elif upload.size > 5 * 1024 * 1024:
            messages.error(request, "Developer images must be 5 MB or smaller.")

        else:
            try:
                uploaded_image = Image.open(upload)

                uploaded_image.verify()

                if uploaded_image.format not in {"JPEG", "PNG", "WEBP"}:
                    raise UnidentifiedImageError("Unsupported image format")

                upload.seek(0)

            except (UnidentifiedImageError, OSError):
                messages.error(request, "The upload is not a valid image file.")

            else:
                try:
                    display_order = max(
                        0, int(request.POST.get("display_order", "0") or 0)
                    )

                except ValueError:
                    display_order = 0

                image = DeveloperImage.objects.create(
                    image=upload,
                    title=strip_tags(request.POST.get("title", ""))[:180],
                    alt_text=strip_tags(
                        request.POST.get("alt_text", "Vigilant Sphere developer")
                    )[:220],
                    is_active=request.POST.get("is_active") == "on",
                    display_order=display_order,
                )

                audit_security_event(
                    request,
                    "Developer image uploaded",
                    target=image.title or image.image.name,
                )

                messages.success(request, "Developer image uploaded.")

                return redirect("cms_developer_images")

    if request.method == "POST" and request.POST.get("action") == "toggle":
        image = get_object_or_404(DeveloperImage, id=request.POST.get("image_id"))

        image.is_active = not image.is_active

        image.save(update_fields=["is_active", "updated_at"])

        audit_security_event(
            request,
            "Developer image visibility updated",
            target=image.title or image.image.name,
        )

        return redirect("cms_developer_images")

    if request.method == "POST" and request.POST.get("action") == "delete":
        image = get_object_or_404(DeveloperImage, id=request.POST.get("image_id"))

        image.image.delete(save=False)

        image.delete()

        audit_security_event(
            request, "Developer image deleted", target=str(request.POST.get("image_id"))
        )

        return redirect("cms_developer_images")

    return render(
        request,
        "myapp/cms_developer_images.html",
        {"images": DeveloperImage.objects.all()},
    )


@login_required
def cms_settings(request):

    seed_initial_cms_content(request.user)

    settings_obj = CMSSiteSettings.objects.first()

    if request.method == "POST":
        settings_obj.site_name = strip_tags(
            request.POST.get("site_name", settings_obj.site_name)
        )

        settings_obj.default_seo_title = strip_tags(
            request.POST.get("default_seo_title", "")
        )

        settings_obj.default_seo_description = strip_tags(
            request.POST.get("default_seo_description", "")
        )

        settings_obj.contact_email = strip_tags(request.POST.get("contact_email", ""))

        settings_obj.support_email = strip_tags(request.POST.get("support_email", ""))

        settings_obj.footer_text = strip_tags(request.POST.get("footer_text", ""))

        settings_obj.maintenance_notice = strip_tags(
            request.POST.get("maintenance_notice", "")
        )

        settings_obj.save()

        audit_security_event(
            request, "CMS site settings updated", target=settings_obj.site_name
        )

        messages.success(request, "Site settings saved.")

        return redirect("cms_settings")

    return render(request, "myapp/cms_settings.html", {"settings_obj": settings_obj})


@login_required
def cms_navigation(request):

    seed_initial_cms_content(request.user)

    if request.method == "POST":
        label = strip_tags(request.POST.get("label", "")).strip()

        url = strip_tags(request.POST.get("url", "")).strip()

        if label and url:
            item = CMSNavigationItem.objects.create(
                label=label,
                url=url,
                location=request.POST.get("location", "main"),
                sort_order=int(request.POST.get("sort_order", 0) or 0),
                visible=request.POST.get("visible") == "on",
            )

            audit_security_event(
                request, "CMS navigation item created", target=item.label
            )

            messages.success(request, "Navigation item saved.")

            return redirect("cms_navigation")

    return render(
        request, "myapp/cms_navigation.html", {"items": CMSNavigationItem.objects.all()}
    )


@login_required
def security_policies(request):

    if request.method == "POST":
        name = strip_tags(request.POST.get("name", "")).strip()

        if name:
            policy, _ = SecurityPolicy.objects.update_or_create(
                name=name,
                defaults={
                    "description": strip_tags(request.POST.get("description", "")),
                    "category": strip_tags(request.POST.get("category", "general")),
                    "enabled": request.POST.get("enabled") == "on",
                    "updated_by": request.user,
                },
            )

            audit_security_event(request, "Security policy saved", target=policy.name)

            messages.success(request, "Security policy saved.")

            return redirect("security_policies")

    return render(
        request,
        "myapp/security_policies.html",
        {"policies": SecurityPolicy.objects.order_by("name")},
    )


@login_required
def audit_logs(request):

    return render(
        request,
        "myapp/audit_logs.html",
        {
            "events": SecurityAuditEvent.objects.select_related("user").order_by(
                "-created_at"
            )[:200]
        },
    )


@login_required
def profile(request):

    track_activity(request, "profile", "Viewed profile")

    return render(request, "myapp/profile.html", {"user_obj": request.user})


@login_required
def edit_profile(request):

    user = request.user

    if request.method == "POST":
        user.first_name = request.POST.get("first_name", user.first_name)

        user.last_name = request.POST.get("last_name", user.last_name)

        user.email = request.POST.get("email", user.email)

        user.phone = request.POST.get("phone", user.phone)

        user.age = request.POST.get("age") or None

        user.gender = request.POST.get("gender", user.gender)

        user.address = request.POST.get("address", user.address)

        if "profile_image" in request.FILES:
            from .uploads import clean_image

            try:
                user.profile_image = clean_image(request.FILES["profile_image"])
            except ValueError as exc:
                messages.error(request, str(exc))
                return redirect("edit_profile")

        user.save()

        track_activity(request, "profile", "Updated profile")

        messages.success(request, "Profile updated successfully.")

        return redirect("profile")

    return render(request, "myapp/edit_profile.html", {"user_obj": user})


@login_required
def change_password(request):

    form = PasswordChangeForm(request.user, request.POST or None)

    if request.method == "POST":
        if form.is_valid():
            user = form.save()

            update_session_auth_hash(request, user)

            track_activity(request, "password", "Changed password")

            messages.success(request, "Password changed successfully.")

            return redirect("profile")

        messages.error(request, "Please correct the password form errors.")

    return render(request, "myapp/change_password.html", {"form": form})


def _save_scan(request, data):

    # Scan persistence module: stores scan output and risk assessment records.

    result = ScanResult.objects.create(
        user=request.user,
        scan_type=data["scan_type"],
        score=data["score"],
        risk_level=data["risk_level"],
        open_ports=data["open_ports"],
        detected_files=data["detected_files"]["files"],
        protocols=data["protocols"],
        modules=data["modules"],
        recommendations=data["recommendations"],
    )

    RiskAssessment.objects.create(
        score=data["score"],
        level=data["risk_level"],
        findings_count=data["detected_files"]["detected_count"],
    )

    return result


@login_required
def combined_scan(request):

    if request.method == "POST":
        # A supplied target/file uses the new passive investigation pipeline;

        # the legacy empty form keeps its existing local endpoint workflow.

        if request.POST.get("target", "").strip() or request.FILES.get("file"):
            try:
                record, factors = run_target_scan(
                    request.user,
                    request.POST.get("target", ""),
                    request.FILES.get("file"),
                )

                track_activity(
                    request,
                    "target investigation",
                    f"Created target scan {record.scan_id}",
                )

                return redirect("target_scan_detail", scan_id=record.scan_id)

            except ValueError as exc:
                messages.error(request, str(exc))

                return redirect("combined_scan")

        if not can_inspect_host(request.user):
            return render(request, "myapp/scanner_access.html", status=403)

        from uuid import uuid4

        from .scan_engine import profile_system

        profile = profile_system()

        asset, _ = AssetInventory.objects.get_or_create(
            hostname=profile["hostname"],
            operating_system=profile["os_name"],
            defaults={
                "ip_address": profile.get("ip_address"),
                "os_version": profile.get("os_version", ""),
                "machine_type": profile.get("machine", ""),
                "processor": profile.get("processor", ""),
            },
        )

        job = ScanJob.objects.create(
            scan_id=str(uuid4()),
            requested_by=request.user,
            asset=asset,
            scan_type="combined",
        )

        # Local mode is intentionally dependency-free.  A Celery worker can call

        # execute_job(job.id) instead; this bounded fallback preserves usability.

        execute_job(job.id)

        track_activity(
            request, "combined scan", f"Created local scan job {job.scan_id}"
        )

        return redirect("scan_job_detail", job_id=job.id)

    latest_scan = decorate_scan(
        ScanResult.objects.filter(user=request.user).order_by("-created_at").first()
    )

    return render(
        request,
        "myapp/combined_scan.html",
        {"latest_scan": latest_scan, "provider_status": provider_status()},
    )


@login_required
def target_scan_detail(request, scan_id):

    scan = get_object_or_404(TargetScan, scan_id=scan_id)

    if scan.user_id != request.user.id:
        return redirect("dashboard")

    modules = {row.get("module", "unknown"): row for row in scan.results}

    risk_factors = []

    for finding in scan.findings:
        risk_factors.append(
            {
                "source": finding.get("source", "local"),
                "title": finding.get("title", "Observation"),
                "severity": finding.get("severity", "INFO"),
            }
        )

    return render(
        request,
        "myapp/target_scan_detail.html",
        {
            "scan": scan,
            "modules": modules,
            "provider_status": provider_status(),
            "risk_factors": risk_factors,
            "linked_findings": scan.job.findings.all() if scan.job_id else [],
            "assessment": "Detection reported by local signature analysis" if any(row.get("data", {}).get("detection_observed") is True for row in scan.results) else "Indicators require review; no malware verdict established",
        },
    )


@login_required
def target_scan_json(request, scan_id):

    scan = get_object_or_404(TargetScan, scan_id=scan_id)

    if scan.user_id != request.user.id:
        return JsonResponse({"error": "Not authorized."}, status=403)

    return JsonResponse(
        {
            "scan_id": scan.scan_id,
            "target": scan.target,
            "target_type": scan.target_type,
            "status": scan.status,
            "risk": {
                "score": scan.risk_score,
                "level": scan.risk_level,
                "confidence": scan.confidence,
            },
            "results": scan.results,
            "provider_results": scan.provider_results,
            "findings": scan.findings,
            "timestamps": {"started": scan.started_at, "completed": scan.completed_at},
        },
        json_dumps_params={"indent": 2},
    )


@login_required
def target_scan_pdf(request, scan_id):

    scan = get_object_or_404(TargetScan, scan_id=scan_id)

    if scan.user_id != request.user.id:
        return HttpResponse(status=403)

    response = HttpResponse(content_type="application/pdf")

    response["Content-Disposition"] = (
        f'attachment; filename="vigilant_sphere_investigation_{scan.scan_id[:8]}.pdf"'
    )

    pdf = canvas.Canvas(response, pagesize=letter)

    width, height, y = letter[0], letter[1], letter[1] - 50

    def line(value, bold=False):

        nonlocal y

        if y < 55:
            pdf.showPage()
            y = height - 50

        pdf.setFont("Helvetica-Bold" if bold else "Helvetica", 10)

        import textwrap

        for segment in textwrap.wrap(display_text(value), 105) or [""]:
            if y < 55:
                pdf.showPage()
                y = height - 50
                pdf.setFont("Helvetica-Bold" if bold else "Helvetica", 10)
            pdf.drawString(40, y, segment)
            y -= 15

    line("Vigilant Sphere Security Investigation", True)

    line(f"Target: {scan.target}")
    line(f"Type: {scan.target_type}")

    line(
        f"Risk: {scan.risk_score}/100 ({scan.risk_level}); confidence: {scan.confidence}"
    )

    line(f"Completed: {scan.completed_at}")
    line("Findings", True)

    for finding in scan.findings:
        line(
            f"[{finding.get('severity', 'INFO')}] {finding.get('title', 'Observation')}"
        )

        line(f"Evidence: {finding.get('evidence', '')}")

        line(f"Recommendation: {finding.get('recommendation', '')}")

    line("Capability status and collection time", True)

    for result in scan.provider_results:
        line(
            f"{result.get('provider')} | {result.get('status')} | {result.get('indicator')} | {result.get('timestamp')}"
        )

    line("Observed modules", True)
    for result in scan.results:
        line(result.get("module", "") + " | " + result.get("status", ""))
        line(json.dumps(result.get("data", {}), ensure_ascii=True))
        line(json.dumps(result.get("errors", [])))
    if scan.job:
        for finding in scan.job.findings.exclude(mitre_technique=""):
            line(
                "MITRE: "
                + finding.mitre_technique
                + " | "
                + finding.mitre_tactic
                + " | confidence "
                + str(finding.confidence)
            )
    line(
        "Report limitation: provider data is attributed intelligence, not a safety verdict."
    )

    pdf.save()

    return response


@login_required
def scan_jobs(request):

    jobs = ScanJob.objects.filter(requested_by=request.user).order_by("-created_at")[
        :100
    ]

    return render(
        request, "myapp/scan_jobs.html", {"jobs": jobs, "catalog": SCANNER_CATALOG}
    )


@login_required
def scan_job_detail(request, job_id):

    job = get_object_or_404(ScanJob, id=job_id)

    if job.requested_by_id != request.user.id:
        return redirect("dashboard")

    return render(
        request,
        "myapp/scan_job_detail.html",
        {"job": job, "findings": job.findings.order_by("-risk_score", "-timestamp")},
    )


@login_required
def findings(request):

    rows = Finding.objects.filter(job__requested_by=request.user).order_by("-timestamp")

    severity = request.GET.get("severity")

    scanner = request.GET.get("scanner")

    if severity:
        if severity.upper() not in {"INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"}:
            return HttpResponse("Invalid severity filter", status=400)
        rows = rows.filter(severity=severity.upper())

    if scanner:
        aliases = {"files": ["files", "file"], "urls": ["urls", "url"], "phishing": ["phishing", "url", "urls"]}
        valid = set(SCANNER_CATALOG) | {"file", "url", "domain", "ip", "hash", "email"}
        if scanner not in valid:
            return HttpResponse("Invalid scanner filter", status=400)
        rows = rows.filter(scanner__in=aliases.get(scanner, [scanner]))

    return render(
        request,
        "myapp/findings.html",
        {"findings": rows[:200], "catalog": dict(SCANNER_CATALOG, domain=("Domain",), ip=("IP",), hash=("Hash",), email=("Email",)), "selected_scanner": scanner, "selected_severity": (severity or "").upper()},
    )


@login_required
def scan_result(request, result_id):

    # Scan result module: displays SOC evidence, report sharing, recommendations, and feedback.

    result = decorate_scan(get_object_or_404(ScanResult, id=result_id))

    if result.user_id != request.user.id:
        messages.error(request, "You cannot view another user's scan result.")

        return redirect("dashboard")

    track_activity(request, "scan result", f"Viewed scan #{result.id}")

    context = {
        "result": result,
        "modules": result.modules,
        "ports": result.open_ports,
        "files": result.detected_files,
        "protocols": result.protocols,
        "recommendations": result.recommendations,
        "blogs": BLOGS,
        "existing_feedback": result.feedback.filter(user=request.user).first()
        if request.user.is_authenticated
        else None,
    }

    context["files"] = [
        enrich_file_item(item, index)
        for index, item in enumerate(result.detected_files or [])
    ]

    return render(request, "myapp/scan_result.html", context)


@login_required
def submit_scan_feedback(request, result_id):

    # Feedback module: collects rating and comment after each scan for admin review.

    result = get_object_or_404(ScanResult, id=result_id)

    if result.user_id != request.user.id:
        messages.error(request, "You cannot rate another user's scan result.")

        return redirect("dashboard")

    if request.method == "POST":
        rating = max(1, min(5, int(request.POST.get("rating", 5))))

        ScanFeedback.objects.update_or_create(
            scan=result,
            user=request.user,
            defaults={
                "rating": rating,
                "comment": request.POST.get("comment", "").strip(),
                "ip_address": client_ip(request),
                "device": client_device(request),
                "place": "Local/Unknown",
            },
        )

        track_activity(request, "scan feedback", f"Rated scan #{result.id}")

        messages.success(
            request, "Thanks. Your rating and comment were sent to the admin dashboard."
        )

    return redirect("scan_result", result_id=result.id)


@login_required
def system_scan(request):

    if request.method == "POST" and not can_inspect_host(request.user):
        return render(request, "myapp/scanner_access.html", status=403)

    if request.method == "POST":
        data = run_combined_scan(request.user, "system")

        result = _save_scan(request, data)

        track_activity(request, "system scan", f"Started scan #{result.id}")

        return redirect("scan_result", result_id=result.id)

    latest_scan = decorate_scan(
        ScanResult.objects.filter(user=request.user).order_by("-created_at").first()
    )

    return render(request, "myapp/system.html", {"latest_scan": latest_scan})


@login_required
def network_scan(request):

    if request.method == "POST" and not can_inspect_host(request.user):
        return render(request, "myapp/scanner_access.html", status=403)

    if request.method == "POST":
        data = run_combined_scan(request.user, "network")

        result = _save_scan(request, data)

        track_activity(request, "network scan", f"Started scan #{result.id}")

        return redirect("scan_result", result_id=result.id)

    latest_scan = decorate_scan(
        ScanResult.objects.filter(user=request.user).order_by("-created_at").first()
    )

    return render(request, "myapp/network.html", {"latest_scan": latest_scan})


@login_required
def mobile_security_scan(request):

    track_activity(request, "password checker", "Viewed local-only password checker")

    if request.method == "POST":
        messages.error(
            request,
            "Password analysis is performed in your browser and passwords are not accepted by the server.",
        )

        return redirect("mobile_security")

    return render(request, "myapp/mobile_security.html")


@login_required
def wifi_security(request):

    disabled = require_feature("WIFI_SECURITY_AUDIT")

    if disabled:
        return disabled

    if request.method == "POST":
        if not can_inspect_host(request.user):
            return render(request, "myapp/scanner_access.html", status=403)

        from .wifi_audit_service import run_audit
        job,state,current=run_audit(request.user,request=request)
        request.session["wifi_status"]=state
        request.session["wifi_job_id"]=job.pk
        request.session["wifi_current"]=current
        messages.info(request,"Wi-Fi audit status: "+state)

        return redirect("wifi_security")

    from django.core.paginator import Paginator
    from .wifi_audit_service import history_queryset,compare_risk
    from .models import TrustedWifiProfile
    from .alerts import delivery_label
    audits=history_queryset(request.user)
    summary={level:audits.filter(risk_level=level).count() for level in ("CRITICAL","HIGH","MEDIUM","LOW","UNKNOWN")}
    page=Paginator(audits,25).get_page(request.GET.get("page"))
    names={a.profile_name for a in page}
    shared=set(WiFiAudit.objects.filter(profile_name__in=names).exclude(user=request.user).values_list("profile_name",flat=True).distinct())
    trusted=set(TrustedWifiProfile.objects.filter(user=request.user,profile_name__in=names).values_list("profile_name",flat=True))
    for audit in page:
        audit.trend=compare_risk(audit.previous_score,audit.risk_score)
        audit.shared_device_notice=audit.profile_name in shared
        audit.trusted=audit.profile_name in trusted
        audit.delivery_status=delivery_label(audit.finding)
    latest=TargetScan.objects.filter(user=request.user,target_type="wifi").order_by("-created_at").first()
    executive=latest.results[0].get("data",{}).get("executive_report",{}) if latest and latest.results else {}
    return render(request,"myapp/wifi_security.html",{"executive":executive,"wifi_report":latest,"audits":page,"summary":summary,"current":request.session.get("wifi_current",{}),"latest_status":request.session.get("wifi_status","Browser Wi-Fi access unavailable")})



@login_required
def chatbot(request):

    disabled = require_feature("OFFLINE_SECURITY_CHATBOT")

    if disabled:
        return disabled

    return render(request, "myapp/chatbot.html")


@login_required
def chatbot_api(request):
    disabled = require_feature("OFFLINE_SECURITY_CHATBOT")
    if disabled:
        return disabled

    if request.method != "POST":
        return JsonResponse({"error": "POST required"}, status=405)

    try:
        payload = json.loads(request.body.decode("utf-8"))

    except (ValueError, UnicodeDecodeError):
        return JsonResponse({"error": "Invalid JSON."}, status=400)

    if not isinstance(payload, dict):
        return JsonResponse({"error": "JSON object required"}, status=400)
    message = str(payload.get("message", ""))[:1000]

    if not message.strip():
        return JsonResponse({"error": "Enter a message."}, status=400)

    history = payload.get("history", [])
    if not isinstance(history, list):
        history = []
    response = chatbot_answer(message, request.user, history=history[-4:])

    audit_security_event(
        request,
        "Offline chatbot used",
        details={"intent": response["intent"], "source": response["source"]},
    )

    return JsonResponse(response)


@login_required
def email_configuration(request):

    config, _ = AlertEmailConfiguration.objects.get_or_create(pk=1)

    if request.method == "POST":
        action = request.POST.get("action", "save")

        if action == "save":
            config.enabled = request.POST.get("enabled") == "on"

            config.host = request.POST.get("host", "").strip()[:255]

            try:
                config.port = max(
                    1, min(65535, int(request.POST.get("port", 587) or 587))
                )

            except ValueError:
                config.port = 587

            config.use_tls, config.use_ssl = (
                request.POST.get("use_tls") == "on",
                request.POST.get("use_ssl") == "on",
            )

            config.from_email, config.recipients, config.updated_by = (
                request.POST.get("from_email", "").strip(),
                request.POST.get("recipients", "").strip(),
                request.user,
            )

            threshold=request.POST.get("alert_severity_threshold","CRITICAL")
            frequency=request.POST.get("digest_frequency","DAILY")
            if threshold not in {"CRITICAL","HIGH"} or frequency not in {"DAILY","WEEKLY"}:return HttpResponse("Invalid alert policy",status=400)
            try:window=int(request.POST.get("alert_dedup_window_hours",24))
            except ValueError:return HttpResponse("Invalid dedup window",status=400)
            if not 0<=window<=8760:return HttpResponse("Dedup window must be between 0 and 8760 hours",status=400)
            config.alert_severity_threshold=threshold;config.alert_dedup_window_hours=window
            config.digest_enabled=request.POST.get("digest_enabled")=="on";config.digest_frequency=frequency
            config.save()
            audit_security_event(request, "Email configuration changed")

            messages.success(
                request,
                "Email configuration saved. SMTP credentials remain environment-only.",
            )

        else:
            test_finding = Finding(
                scanner="email_test",
                title="Administrator test alert",
                severity="CRITICAL",
                risk_score=0,
                confidence=1,
                evidence={"test": True},
                recommendation="No action required.",
                remediation="This is a test.",
            )

            # Test SMTP directly without creating a fake persisted finding/alert.

            from django.core.mail import send_mail

            from django.conf import settings as django_settings

            if not config.enabled or not (
                config.host or django_settings.VIGILANT_SMTP_HOST
            ):
                messages.error(request, "EMAIL NOT CONFIGURED")

            else:
                try:
                    connection = __import__(
                        "django.core.mail", fromlist=["get_connection"]
                    ).get_connection(
                        host=config.host or django_settings.VIGILANT_SMTP_HOST,
                        port=config.port,
                        username=django_settings.VIGILANT_SMTP_USERNAME,
                        password=django_settings.VIGILANT_SMTP_PASSWORD,
                        use_tls=config.use_tls,
                        use_ssl=config.use_ssl,
                        timeout=10,
                    )

                    send_mail(
                        "[VIGILANT SPHERE] Email configuration test",
                        "SMTP test requested by an administrator.",
                        config.from_email or django_settings.VIGILANT_ALERT_FROM_EMAIL,
                        [
                            x.strip()
                            for x in config.recipients.replace("\n", ",").split(",")
                            if x.strip()
                        ],
                        connection=connection,
                        fail_silently=False,
                    )

                    messages.success(request, "Email sent successfully.")

                except Exception as exc:
                    messages.error(
                        request, f"Email delivery failed: {type(exc).__name__}."
                    )

            audit_security_event(request, "Email test requested")

        return redirect("email_configuration")

    return render(request, "myapp/email_configuration.html", {"config": config})








@login_required
def real_time_monitoring(request):

    return threat_detection(request)


@login_required
def quarantine_view(request):

    return threat_detection(request)


@login_required
def risk_assessment(request):

    track_activity(request, "risk assessment", "Viewed risk assessment")

    latest_scan = decorate_scan(
        ScanResult.objects.filter(user=request.user).order_by("-created_at").first()
    )

    return render(request, "myapp/dashboard.html", {"latest_scan": latest_scan})


@login_required
def threat_timeline(request):

    return threat_detection(request)


@login_required
def download_scan_pdf(request, result_id=None):

    result = (
        get_object_or_404(ScanResult, id=result_id)
        if result_id
        else ScanResult.objects.filter(user=request.user)
        .order_by("-created_at")
        .first()
    )

    result = decorate_scan(result)

    if not result:
        messages.error(request, "Run a scan before downloading a PDF report.")

        return redirect("combined_scan")

    if result.user_id != request.user.id:
        messages.error(request, "You cannot download another user's scan result.")

        return redirect("dashboard")

    track_activity(request, "pdf report", f"Downloaded scan #{result.id}")

    response = HttpResponse(content_type="application/pdf")

    response["Content-Disposition"] = (
        f'attachment; filename="vigilant_sphere_report_{result.id}.pdf"'
    )

    pdf = canvas.Canvas(response, pagesize=letter)

    width, height = letter

    y = height - 50

    def line(text, size=10, bold=False):

        nonlocal y

        if y < 60:
            pdf.showPage()

            y = height - 50

        pdf.setFont("Helvetica-Bold" if bold else "Helvetica", size)

        pdf.drawString(45, y, display_text(text)[:110])

        y -= 16

    line("Vigilant Sphere Threat Intelligence & Detection Engine Report", 16, True)

    line(f"User: {result.user.username if result.user else 'Unknown'}")

    line(f"Date: {result.created_at}")

    line(f"Threat Score: {result.display_score} / 100")

    line(f"Risk level: {result.display_risk_level}", 12, True)

    line("")

    line("Open Ports", 12, True)

    for port in result.open_ports[:40]:
        line(
            f"{port.get('protocol')} {port.get('port')} {port.get('service')} risk={port.get('risk')} - {port.get('resolution')}"
        )

    line("")

    line("Detected Files", 12, True)

    for item in result.detected_files[:40]:
        line(f"{item.get('name')} risk={item.get('risk')} path={item.get('path')}")

    line("")

    line("Recommendations", 12, True)

    for rec in result.recommendations:
        line(f"- {rec}")

    pdf.save()

    return response


@login_required
def export_json_report(request):

    latest = decorate_scan(
        ScanResult.objects.filter(user=request.user).order_by("-created_at").first()
    )

    if not latest:
        return JsonResponse({"error": "No scan results yet."}, status=404)

    return JsonResponse(
        {
            "id": latest.id,
            "score": latest.display_score,
            "risk_level": latest.display_risk_level,
            "open_ports": latest.open_ports,
            "detected_files": latest.detected_files,
            "protocols": latest.protocols,
            "modules": latest.modules,
            "recommendations": latest.recommendations,
            "created_at": latest.created_at,
        },
        json_dumps_params={"indent": 2},
        safe=False,
    )


@login_required
def admin_dashboard(request):

    # Admin dashboard module: superuser/staff view for users, activity, scans, feedback, and messages.

    active_sessions = Session.objects.filter(expire_date__gte=timezone.now())

    active_user_ids = []

    for session in active_sessions:
        data = session.get_decoded()

        user_id = data.get("_auth_user_id")

        if user_id:
            active_user_ids.append(user_id)

    active_users = User.objects.filter(id__in=active_user_ids)

    activity_summary = (
        UserActivity.objects.values("user__username", "user__email", "option_used")
        .annotate(total=Count("id"))
        .order_by("user__username", "option_used")
    )

    context = {
        "active_users": active_users,
        "activity_summary": activity_summary,
        "contacts": ContactMessage.objects.order_by("-created_at")[:50],
        "scan_count": ScanResult.objects.count(),
        "user_count": User.objects.count(),
        "registered_users": User.objects.count(),
        "latest_scans": ScanResult.objects.select_related("user").order_by(
            "-created_at"
        )[:20],
        "activities": UserActivity.objects.select_related("user").order_by(
            "-created_at"
        )[:50],
        "feedback": ScanFeedback.objects.select_related("user", "scan").order_by(
            "-created_at"
        )[:50],
    }

    return render(request, "myapp/admin_dashboard.html", context)


@login_required
def download_user_details(request, user_id=None):

    users = User.objects.filter(id=user_id) if user_id else User.objects.all()

    response = HttpResponse(content_type="text/csv")

    filename = (
        f"vigilant_sphere_user_{user_id}.csv"
        if user_id
        else "vigilant_sphere_all_users.csv"
    )

    response["Content-Disposition"] = f'attachment; filename="{filename}"'

    writer = csv.writer(response)

    writer.writerow(
        [
            "Username",
            "Full Name",
            "Email",
            "Age",
            "Phone",
            "Gender",
            "Address",
            "Joined",
            "Last Login",
            "Scan Count",
            "Last IP",
            "Last Device",
            "Last Place",
            "Average Rating",
        ]
    )

    for user in users:
        latest_activity = (
            UserActivity.objects.filter(user=user).order_by("-created_at").first()
        )

        feedback_rows = ScanFeedback.objects.filter(user=user)

        average_rating = (
            round(sum(item.rating for item in feedback_rows) / feedback_rows.count(), 2)
            if feedback_rows.exists()
            else ""
        )

        writer.writerow(
            [
                user.username,
                user.get_full_name(),
                user.email,
                user.age or "",
                user.phone or "",
                user.gender,
                user.address,
                user.date_joined,
                user.last_login,
                ScanResult.objects.filter(user=user).count(),
                latest_activity.ip_address if latest_activity else "",
                latest_activity.device if latest_activity else "",
                latest_activity.place if latest_activity else "",
                average_rating,
            ]
        )

    return response


def about(request):

    return render(request, "myapp/about.html")


def privacy_policy(request):

    return render(request, "myapp/privacy.html")




def blogs(request):

    from .workspace_views import public_posts

    return public_posts(request)


@login_required
def api_dashboard_metrics(request):
    jobs = ScanJob.objects.filter(requested_by=request.user).order_by("-created_at")
    latest = jobs.first()
    rows = Finding.objects.filter(job__requested_by=request.user)
    return JsonResponse(
        {
            "cpu": psutil.cpu_percent(interval=0.1) if can_inspect_host(request.user) else None,
            "memory": psutil.virtual_memory().percent if can_inspect_host(request.user) else None,
            "risk_score": latest.risk_score if latest else None,
            "risk_level": "UNKNOWN"
            if not latest
            else score_to_level(latest.risk_score),
            "total_findings": rows.count(),
            "critical_findings": rows.filter(severity="CRITICAL").count(),
            "high_findings": rows.filter(severity="HIGH").count(),
            "open_incidents": Incident.objects.filter(
                owner=request.user, archived=False
            )
            .exclude(status__in=["RESOLVED", "CLOSED"])
            .count(),
            "soc_posture": "Requires Review" if latest else "No Evidence",
            "traffic": [],
            "network_logs": [],
            "alerts": [
                {"severity": x.severity, "message": x.title}
                for x in rows.order_by("-timestamp")[:8]
            ],
            "trend": [
                {
                    "label": x.created_at.strftime("%H:%M"),
                    "score": x.risk_score,
                    "risk": x.status,
                }
                for x in jobs[:12]
            ],
        }
    )


def _feedback(request, suggestion=False):
    from .forms import ContactForm, SuggestionForm
    form=(SuggestionForm if suggestion else ContactForm)(request.POST or None)
    if request.method == "POST" and form.is_valid():
        row=form.save(commit=False)
        row.user=request.user if request.user.is_authenticated else None
        row.message_type="suggestion" if suggestion else "question"
        row.save()
        messages.success(request,"Your submission was saved for review.")
        return redirect("suggestions" if suggestion else "contact")
    return render(request,"myapp/feedback.html",{"form":form,"title":"Suggestions" if suggestion else "Contact","suggestion":suggestion})

def contact(request):
    return _feedback(request)

def suggestions(request):
    return _feedback(request, True)

def developer_profile(request):
    profile=CMSDeveloperProfile.objects.order_by("pk").first()
    return render(request,"myapp/developer.html",{"developer_profile":profile,"developer_images":DeveloperImage.objects.filter(is_active=True)})


def phishing_scan(request):
    from .domain_views import scanner_page
    return scanner_page(request,"phishing_intelligence")

def file_scan(request):
    from .domain_views import scanner_page
    return scanner_page(request,"static_file_analysis")

def threat_detection(request):
    from .domain_views import scanner_page
    return scanner_page(request,"threat_detection")

def threat_intelligence(request):
    from .domain_views import scanner_page
    return scanner_page(request,"threat_intelligence")

def ioc_correlation(request):
    from .domain_views import scanner_page
    return scanner_page(request,"ioc_correlation")
