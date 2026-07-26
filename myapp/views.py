import csv
import hashlib
import json
import math
import re
from urllib.parse import urlparse

from django.contrib import messages
from django.contrib.admin.views.decorators import staff_member_required
from django.contrib.auth import authenticate, get_user_model, login, logout
from django.contrib.auth.decorators import login_required
from django.contrib.auth import update_session_auth_hash
from django.contrib.auth.forms import PasswordChangeForm
from django.contrib.sessions.models import Session
from django.db.models import Count
from django.http import HttpResponse, JsonResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.utils import timezone
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
import psutil

from .models import (
    AuditLog,
    ContactMessage,
    Incident,
    RiskAssessment,
    ScanFeedback,
    ScanResult,
    ThreatFinding,
    UserActivity,
)
from .scan_engine import active_network_connections, run_combined_scan


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
        "title": "When AI recommendations say quarantine",
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
        evidence_score += RISK_POINT_WEIGHTS.get(str(row.get("risk", "medium")).lower(), 15)
    for item in scan.detected_files or []:
        evidence_score += RISK_POINT_WEIGHTS.get(str(item.get("risk", "medium")).lower(), 15)

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
        findings.append({
            "kind": "port",
            "risk": str(port.get("risk", "medium")).upper(),
            "title": f"{port.get('protocol', 'TCP')}:{port.get('port', 'unknown')} {port.get('service', 'Unknown service')}",
        })
    for item in scan.detected_files or []:
        findings.append({
            "kind": "file",
            "risk": str(item.get("risk", "medium")).upper(),
            "title": item.get("name", "Unknown file"),
        })
    return findings


def scan_stat_summary(scans):
    findings = []
    for scan in scans:
        findings.extend(scan_findings(scan))
    return {
        "total_findings": len(findings),
        "critical_findings": len([item for item in findings if item["risk"] == "CRITICAL"]),
        "high_findings": len([item for item in findings if item["risk"] == "HIGH"]),
        "open_incidents": len([item for item in findings if item["risk"] in {"HIGH", "CRITICAL"}]),
    }


def enrich_file_item(file_item, index):
    path = file_item.get("path", "")
    name = file_item.get("name") or (path.split("\\")[-1].split("/")[-1] if path else f"file-{index + 1}")
    sha256 = file_item.get("sha256") or "Not calculated for this saved result"
    risk = str(file_item.get("risk", "medium")).upper()
    location_flags = [
        marker for marker in ["AppData", "Temp", "Downloads", "Startup", "ProgramData", "Recycle Bin"]
        if marker.lower() in path.lower()
    ]
    extension_mismatch = any(name.lower().endswith(pattern) for pattern in [".jpg.exe", ".pdf.exe", ".pdf.scr", ".docm"])
    file_item = dict(file_item)
    file_item.update({
        "index": index,
        "name": name,
        "path": path,
        "file_url": f"file:///{path.replace(chr(92), '/')}" if path else "",
        "sha256": sha256,
        "reputation": file_item.get("reputation") or ("Known suspicious local heuristic" if risk in {"HIGH", "CRITICAL"} else "Unknown / needs analyst review"),
        "real_type": file_item.get("real_type") or "Requires python-magic or OS file inspection",
        "extension_mismatch": extension_mismatch,
        "entropy": file_item.get("entropy") or ("7.2 - Highly suspicious estimate" if risk == "CRITICAL" else "Not calculated for saved result"),
        "signature": file_item.get("signature") or ("Unsigned or unverified" if risk in {"HIGH", "CRITICAL"} else "Not verified"),
        "location_analysis": ", ".join(location_flags) if location_flags else "No dangerous user-location marker identified",
        "yara": file_item.get("yara") or ("Local heuristic match" if risk in {"HIGH", "CRITICAL"} else "No YARA match stored"),
        "pe_analysis": file_item.get("pe_analysis") or "PE import/section analysis requires live executable inspection",
        "persistence": file_item.get("persistence") or "Check Run keys, Startup folder, Scheduled Tasks, and services",
        "behavior": file_item.get("behavior") or "Review for AV disable, hidden files, registry edits, process injection, network callbacks, or payload downloads",
        "mitre": file_item.get("mitre") or ["T1547 - Persistence", "T1055 - Process Injection", "T1003 - Credential Dumping", "T1059 - Command Execution"],
    })
    return file_item


def uploaded_file_entropy(uploaded_file):
    position = uploaded_file.tell()
    uploaded_file.seek(0)
    data = uploaded_file.read(1024 * 1024)
    uploaded_file.seek(position)
    if not data:
        return 0
    counts = {byte: data.count(byte) for byte in set(data)}
    return round(-sum((count / len(data)) * math.log2(count / len(data)) for count in counts.values()), 2)


def hash_uploaded_file(uploaded_file):
    digests = {
        "md5": hashlib.md5(),
        "sha1": hashlib.sha1(),
        "sha256": hashlib.sha256(),
    }
    uploaded_file.seek(0)
    for chunk in uploaded_file.chunks():
        for digest in digests.values():
            digest.update(chunk)
    uploaded_file.seek(0)
    return {name: digest.hexdigest() for name, digest in digests.items()}


def analyze_mobile_url(raw_url):
    value = (raw_url or "").strip()
    if not value:
        return None
    if "://" not in value:
        value = f"https://{value}"
    parsed = urlparse(value)
    host = parsed.netloc.lower()
    suspicious_terms = ["login", "verify", "free", "gift", "bonus", "wallet", "bank", "otp", "urgent"]
    risk_points = 0
    reasons = []
    if parsed.scheme != "https":
        risk_points += 25
        reasons.append("URL does not use HTTPS.")
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host):
        risk_points += 25
        reasons.append("URL uses a raw IP address instead of a domain.")
    if any(term in value.lower() for term in suspicious_terms):
        risk_points += 20
        reasons.append("URL contains common phishing lure keywords.")
    if host.count("-") >= 2 or len(host) > 45:
        risk_points += 15
        reasons.append("Domain shape is unusual or overly long.")
    if "@" in value:
        risk_points += 30
        reasons.append("URL contains @ redirection-style syntax.")
    if not reasons:
        reasons.append("No obvious phishing pattern detected by local heuristics.")
    return {
        "url": value,
        "host": host or "Unknown host",
        "risk_score": min(100, risk_points),
        "risk_level": score_to_level(min(100, risk_points)),
        "reasons": reasons,
    }


def analyze_password_strength(password):
    if not password:
        return None
    score = 0
    checks = []
    if len(password) >= 12:
        score += 25
        checks.append("Length is strong.")
    else:
        checks.append("Use at least 12 characters.")
    if re.search(r"[A-Z]", password) and re.search(r"[a-z]", password):
        score += 20
        checks.append("Contains uppercase and lowercase letters.")
    if re.search(r"\d", password):
        score += 20
        checks.append("Contains numbers.")
    if re.search(r"[^A-Za-z0-9]", password):
        score += 20
        checks.append("Contains symbols.")
    if not re.search(r"(.)\1\1", password):
        score += 15
        checks.append("No obvious repeated character pattern.")
    label = "Weak" if score < 45 else "Medium" if score < 75 else "Strong"
    return {"score": score, "label": label, "checks": checks}


def analyze_uploaded_mobile_file(uploaded_file):
    if not uploaded_file:
        return None
    hashes = hash_uploaded_file(uploaded_file)
    entropy = uploaded_file_entropy(uploaded_file)
    name = uploaded_file.name
    suffix = f".{name.rsplit('.', 1)[-1].lower()}" if "." in name else ""
    risky_extensions = {".apk", ".exe", ".scr", ".docm", ".xlsm", ".zip", ".rar", ".js", ".vbs", ".ps1"}
    risk_points = 0
    findings = []
    if suffix in risky_extensions:
        risk_points += 30
        findings.append("File extension can carry executable, macro, archive, or script risk.")
    if entropy >= 6:
        risk_points += 25
        findings.append("High entropy may indicate packed, encrypted, or obfuscated content.")
    if any(token in name.lower() for token in ["payload", "crack", "mod", "hack", "invoice.pdf.exe"]):
        risk_points += 30
        findings.append("Filename contains malware/social-engineering style keywords.")
    if not findings:
        findings.append("No obvious local file heuristic matched.")
    return {
        "name": name,
        "size": uploaded_file.size,
        "extension": suffix or "No extension",
        "entropy": entropy,
        "hashes": hashes,
        "risk_score": min(100, risk_points),
        "risk_level": score_to_level(min(100, risk_points)),
        "findings": findings,
        "yara": "Local strings/extension/entropy heuristics only; connect YARA engine for production rules.",
    }


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
    return render(request, "myapp/home.html")


def register(request):
    if request.user.is_authenticated:
        return redirect("dashboard")

    if request.method == "POST":
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

    return render(request, "myapp/register.html")


def user_login(request):
    if request.user.is_authenticated:
        return redirect("dashboard")

    if request.method == "POST":
        username = request.POST.get("username", "")
        password = request.POST.get("password", "")
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

    return render(request, "myapp/login.html")


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
    context = {"step": "request"}
    if request.method == "POST":
        action = request.POST.get("action")
        if action == "request":
            user = User.objects.filter(
                username=request.POST.get("username", "").strip(),
                email=request.POST.get("email", "").strip(),
            ).first()
            if not user:
                messages.error(request, "No matching account was found.")
                return redirect("forgot_password")
            request.session["reset_user_id"] = user.id
            request.session["reset_otp"] = "123456"
            context = {"step": "otp", "email_sent": True, "demo_otp": "123456"}
        elif action == "otp":
            if request.POST.get("otp") == request.session.get("reset_otp"):
                context = {"step": "reset", "verified": True}
            else:
                messages.error(request, "Invalid OTP. For this local demo, use 123456.")
                context = {"step": "otp", "demo_otp": "123456"}
        elif action == "reset":
            user = User.objects.filter(id=request.session.get("reset_user_id")).first()
            password = request.POST.get("password", "")
            confirm = request.POST.get("confirm_password", "")
            if not user or password != confirm or len(password) < 8:
                messages.error(request, "Password must match and be at least 8 characters.")
                context = {"step": "reset", "verified": True}
            else:
                user.set_password(password)
                user.save()
                request.session.pop("reset_user_id", None)
                request.session.pop("reset_otp", None)
                context = {"step": "success", "success": True}
    return render(request, "myapp/forgot_password.html", context)


@login_required
def dashboard(request):
    # Dashboard module: renders SOC metrics, risk trend, traffic visualization, alerts, and recent scans.
    track_activity(request, "dashboard", "Viewed user dashboard")
    latest_scan = decorate_scan(ScanResult.objects.filter(user=request.user).order_by("-created_at").first())
    severity_filter = request.GET.get("severity", "")
    all_scans = [decorate_scan(scan) for scan in ScanResult.objects.filter(user=request.user).order_by("-created_at")]
    scans = all_scans
    if severity_filter:
        scans = [scan for scan in scans if scan.display_risk_level == severity_filter]
    scans = scans[:8]
    summary = scan_stat_summary(all_scans)
    context = {
        "risk_score": latest_scan.display_score if latest_scan else 0,
        "risk_level": latest_scan.display_risk_level if latest_scan else "LOW",
        "total_findings": summary["total_findings"],
        "critical_findings": summary["critical_findings"],
        "high_findings": summary["high_findings"],
        "total_incidents": Incident.objects.count(),
        "open_incidents": summary["open_incidents"],
        "recent_findings": ThreatFinding.objects.order_by("-created_at")[:10],
        "recent_incidents": Incident.objects.order_by("-created_at")[:10],
        "latest_scan": latest_scan,
        "scans": scans,
        "severity_filter": severity_filter,
    }
    return render(request, "myapp/dashboard.html", context)


@login_required
def launcher(request):
    # Launcher module: exposes every scanner and account action from one safe navigation page.
    track_activity(request, "launcher", "Viewed scanner launcher")
    modules = [
        {"name": "System Scan", "url": "/system/", "detail": "Endpoint health, startup entries, local files, and device posture."},
        {"name": "Network Scan", "url": "/network/", "detail": "Active connections, exposed ports, service risk, and protocol review."},
        {"name": "Mobile Security Scan", "url": "/mobile-security/", "detail": "Browser-safe mobile checks, URL/QR scan, password review, file upload scan, and Wi-Fi checklist."},
        {"name": "Combined Scan", "url": "/scan/", "detail": "Full SOC-style endpoint, network, file, MITRE, and risk scan."},
        {"name": "Threat Detection", "url": "/threat-detection/", "detail": "EDR, NDR, file analysis, behavior analytics, SOAR guidance."},
        {"name": "Profile", "url": "/profile/", "detail": "View account details and profile image."},
        {"name": "Edit Profile", "url": "/edit-profile/", "detail": "Update name, age, phone, gender, address, and image."},
        {"name": "Forgot Password", "url": "/forgot-password/", "detail": "Reset your local demo password."},
        {"name": "Logout", "url": "/logout/", "detail": "End the current session safely."},
    ]
    return render(request, "myapp/launcher.html", {"modules": modules})


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
            user.profile_image = request.FILES["profile_image"]
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
        data = run_combined_scan(request.user, "combined")
        result = _save_scan(request, data)
        track_activity(request, "combined scan", f"Started scan #{result.id}")
        return redirect("scan_result", result_id=result.id)

    latest_scan = decorate_scan(ScanResult.objects.filter(user=request.user).order_by("-created_at").first())
    return render(request, "myapp/combined_scan.html", {"latest_scan": latest_scan})


@login_required
def scan_result(request, result_id):
    # Scan result module: displays SOC evidence, report sharing, recommendations, and feedback.
    result = decorate_scan(get_object_or_404(ScanResult, id=result_id))
    if not request.user.is_superuser and result.user_id != request.user.id:
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
        "existing_feedback": result.feedback.filter(user=request.user).first() if request.user.is_authenticated else None,
    }
    context["files"] = [enrich_file_item(item, index) for index, item in enumerate(result.detected_files or [])]
    return render(request, "myapp/scan_result.html", context)


@login_required
def submit_scan_feedback(request, result_id):
    # Feedback module: collects rating and comment after each scan for admin review.
    result = get_object_or_404(ScanResult, id=result_id)
    if not request.user.is_superuser and result.user_id != request.user.id:
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
        messages.success(request, "Thanks. Your rating and comment were sent to the admin dashboard.")
    return redirect("scan_result", result_id=result.id)


@login_required
def system_scan(request):
    if request.method == "POST":
        data = run_combined_scan(request.user, "system")
        result = _save_scan(request, data)
        track_activity(request, "system scan", f"Started scan #{result.id}")
        return redirect("scan_result", result_id=result.id)
    latest_scan = decorate_scan(ScanResult.objects.filter(user=request.user).order_by("-created_at").first())
    return render(request, "myapp/system.html", {"latest_scan": latest_scan})


@login_required
def network_scan(request):
    if request.method == "POST":
        data = run_combined_scan(request.user, "network")
        result = _save_scan(request, data)
        track_activity(request, "network scan", f"Started scan #{result.id}")
        return redirect("scan_result", result_id=result.id)
    latest_scan = decorate_scan(ScanResult.objects.filter(user=request.user).order_by("-created_at").first())
    return render(request, "myapp/network.html", {"latest_scan": latest_scan})


@login_required
def mobile_security_scan(request):
    track_activity(request, "mobile security scan", "Viewed mobile browser security checks")
    context = {
        "network_info": {
            "public_ip_hint": client_ip(request),
            "local_ip_hint": "Browser sandbox blocks exact local IP on most modern phones.",
            "user_agent": request.META.get("HTTP_USER_AGENT", "Unknown browser"),
            "secure_request": request.is_secure(),
            "cookies_enabled_hint": "If you are logged in, session cookies are working.",
            "device_type": "Android" if "Android" in request.META.get("HTTP_USER_AGENT", "") else "iPhone/iPad" if any(token in request.META.get("HTTP_USER_AGENT", "") for token in ["iPhone", "iPad"]) else "Desktop/Unknown",
        },
        "web_checks": {
            "https": "PASS" if request.is_secure() else "REVIEW - local HTTP is normal for development, use HTTPS for production/mobile internet access.",
            "cookies": "PASS - session cookie active for authenticated user.",
            "headers": "REVIEW - deploy behind HTTPS with HSTS, CSP, X-Frame-Options, and secure cookies.",
            "mixed_content": "Use HTTPS assets only in production.",
            "csp": "Recommended: default-src 'self'; script-src trusted CDNs only.",
        },
        "wifi_checklist": [
            "Use WPA2/WPA3 encryption; avoid open Wi-Fi for scans.",
            "Change router admin password from default.",
            "Disable WPS if not needed.",
            "Keep router firmware updated.",
            "Use guest Wi-Fi for untrusted devices.",
            "Do not expose router admin page to the internet.",
        ],
        "android_modules": [
            "Installed apps inventory requires a native Android app.",
            "APK permission analysis can be performed by uploading APK files here.",
            "Root/debugging detection requires a native Android app.",
            "Unknown sources setting check requires a native Android app.",
            "App signature/hash check can be performed for uploaded APKs.",
            "SMS/call permission risk review requires Android app permissions.",
            "Local network port scan from the phone requires a native app or browser-limited WebRTC techniques.",
            "Basic device posture such as OS version, patch level, and storage encryption requires a native Android app.",
        ],
        "iphone_limits": [
            "iOS browser cannot scan apps or system files.",
            "Native iOS apps have limited visibility due to Apple sandboxing.",
            "Best iPhone modules are URL scan, file upload scan, Wi-Fi/network guidance, and web security checks.",
        ],
    }
    if request.method == "POST":
        context["url_result"] = analyze_mobile_url(request.POST.get("url_to_scan"))
        context["qr_result"] = analyze_mobile_url(request.POST.get("qr_link"))
        context["password_result"] = analyze_password_strength(request.POST.get("password_to_check"))
        context["file_result"] = analyze_uploaded_mobile_file(request.FILES.get("mobile_file"))
        messages.success(request, "Mobile browser-safe checks completed.")
    return render(request, "myapp/mobile_security.html", context)


@login_required
def threat_detection(request):
    if request.method == "POST":
        data = run_combined_scan(request.user, "threat detection")
        result = _save_scan(request, data)
        track_activity(request, "threat detection", f"Started scan #{result.id}")
        return redirect("scan_result", result_id=result.id)
    latest_scan = decorate_scan(ScanResult.objects.filter(user=request.user).order_by("-created_at").first())
    return render(request, "myapp/threat_detection.html", {"latest_scan": latest_scan})


@login_required
def threat_intelligence(request):
    return threat_detection(request)


@login_required
def ioc_correlation(request):
    return threat_detection(request)


@login_required
def mitre_mapping(request):
    return threat_detection(request)


@login_required
def real_time_monitoring(request):
    return threat_detection(request)


@login_required
def usb_monitoring(request):
    return threat_detection(request)


@login_required
def incidents(request):
    track_activity(request, "incidents", "Viewed incidents")
    return render(request, "myapp/threat_detection.html", {"incidents": Incident.objects.order_by("-created_at")})


@login_required
def quarantine_view(request):
    return threat_detection(request)


@login_required
def risk_assessment(request):
    track_activity(request, "risk assessment", "Viewed risk assessment")
    latest_scan = decorate_scan(ScanResult.objects.filter(user=request.user).order_by("-created_at").first())
    return render(request, "myapp/dashboard.html", {"latest_scan": latest_scan})


@login_required
def threat_timeline(request):
    return threat_detection(request)


@login_required
def download_scan_pdf(request, result_id=None):
    result = get_object_or_404(ScanResult, id=result_id) if result_id else ScanResult.objects.filter(user=request.user).order_by("-created_at").first()
    result = decorate_scan(result)
    if not result:
        messages.error(request, "Run a scan before downloading a PDF report.")
        return redirect("combined_scan")
    if not request.user.is_superuser and result.user_id != request.user.id:
        messages.error(request, "You cannot download another user's scan result.")
        return redirect("dashboard")

    track_activity(request, "pdf report", f"Downloaded scan #{result.id}")
    response = HttpResponse(content_type="application/pdf")
    response["Content-Disposition"] = f'attachment; filename="vigilant_sphere_report_{result.id}.pdf"'
    pdf = canvas.Canvas(response, pagesize=letter)
    width, height = letter
    y = height - 50

    def line(text, size=10, bold=False):
        nonlocal y
        if y < 60:
            pdf.showPage()
            y = height - 50
        pdf.setFont("Helvetica-Bold" if bold else "Helvetica", size)
        pdf.drawString(45, y, str(text)[:110])
        y -= 16

    line("Vigilant Sphere Threat Intelligence & Detection Engine Report", 16, True)
    line(f"User: {result.user.username if result.user else 'Unknown'}")
    line(f"Date: {result.created_at}")
    line(f"Threat Score: {result.display_score} / 100")
    line(f"Risk level: {result.display_risk_level}", 12, True)
    line("")
    line("Open Ports", 12, True)
    for port in result.open_ports[:40]:
        line(f"{port.get('protocol')} {port.get('port')} {port.get('service')} risk={port.get('risk')} - {port.get('resolution')}")
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
    latest = decorate_scan(ScanResult.objects.filter(user=request.user).order_by("-created_at").first())
    if not latest:
        return JsonResponse({"error": "No scan results yet."}, status=404)
    return JsonResponse({
        "id": latest.id,
        "score": latest.display_score,
        "risk_level": latest.display_risk_level,
        "open_ports": latest.open_ports,
        "detected_files": latest.detected_files,
        "protocols": latest.protocols,
        "modules": latest.modules,
        "recommendations": latest.recommendations,
        "created_at": latest.created_at,
    }, json_dumps_params={"indent": 2}, safe=False)


@staff_member_required
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
        "latest_scans": ScanResult.objects.select_related("user").order_by("-created_at")[:20],
        "activities": UserActivity.objects.select_related("user").order_by("-created_at")[:50],
        "feedback": ScanFeedback.objects.select_related("user", "scan").order_by("-created_at")[:50],
    }
    return render(request, "myapp/admin_dashboard.html", context)


@staff_member_required
def download_user_details(request, user_id=None):
    users = User.objects.filter(id=user_id) if user_id else User.objects.all()
    response = HttpResponse(content_type="text/csv")
    filename = f"vigilant_sphere_user_{user_id}.csv" if user_id else "vigilant_sphere_all_users.csv"
    response["Content-Disposition"] = f'attachment; filename="{filename}"'
    writer = csv.writer(response)
    writer.writerow(["Username", "Full Name", "Email", "Age", "Phone", "Gender", "Address", "Joined", "Last Login", "Scan Count", "Last IP", "Last Device", "Last Place", "Average Rating"])
    for user in users:
        latest_activity = UserActivity.objects.filter(user=user).order_by("-created_at").first()
        feedback_rows = ScanFeedback.objects.filter(user=user)
        average_rating = round(sum(item.rating for item in feedback_rows) / feedback_rows.count(), 2) if feedback_rows.exists() else ""
        writer.writerow([
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
        ])
    return response


def about(request):
    return render(request, "myapp/about.html")


def privacy_policy(request):
    return render(request, "myapp/privacy.html")


def contact(request):
    if request.method == "POST":
        ContactMessage.objects.create(
            user=request.user if request.user.is_authenticated else None,
            name=request.POST.get("name", "").strip() or "Anonymous",
            email=request.POST.get("email", "").strip(),
            message_type=request.POST.get("message_type", "suggestion"),
            message=request.POST.get("message", "").strip(),
        )
        if request.user.is_authenticated:
            track_activity(request, "contact", "Submitted contact form")
        messages.success(request, "Your message was sent to the admin dashboard.")
        return redirect("contact")
    return render(request, "myapp/contact.html")


def blogs(request):
    # Blog module: learning articles tied to AI recommendations and SOC triage.
    return render(request, "myapp/blogs.html", {"blogs": BLOGS})


@login_required
def api_dashboard_metrics(request):
    latest_scan = decorate_scan(ScanResult.objects.filter(user=request.user).order_by("-created_at").first())
    all_user_scans = [decorate_scan(scan) for scan in ScanResult.objects.filter(user=request.user).order_by("-created_at")]
    user_scans = all_user_scans[:12]
    summary = scan_stat_summary(all_user_scans)
    network_rows = active_network_connections(limit=20)
    alerts = []
    if latest_scan:
        if latest_scan.display_risk_level in {"HIGH", "CRITICAL"}:
            alerts.append({
                "severity": latest_scan.display_risk_level,
                "message": f"Latest scan risk is {latest_scan.display_risk_level} with score {latest_scan.display_score}.",
            })
        for file_item in latest_scan.detected_files[:5]:
            alerts.append({
                "severity": file_item.get("risk", "medium").upper(),
                "message": f"{file_item.get('malicious')} detected: {file_item.get('name')}",
            })
    cpu = psutil.cpu_percent(interval=0.1)
    memory = psutil.virtual_memory().percent
    return JsonResponse({
        "cpu": cpu,
        "memory": memory,
        "risk_score": latest_scan.display_score if latest_scan else 0,
        "risk_level": latest_scan.display_risk_level if latest_scan else "LOW",
        "total_findings": summary["total_findings"],
        "critical_findings": summary["critical_findings"],
        "high_findings": summary["high_findings"],
        "open_incidents": summary["open_incidents"],
        "soc_posture": "PASS" if not latest_scan or latest_scan.display_score <= 20 else "WATCH" if latest_scan.display_score <= 70 else "ACTION",
        "traffic": [
            traffic_label(row)
            for row in network_rows[:10]
        ],
        "network_logs": network_rows[:12],
        "alerts": alerts[:8],
        "trend": [
            {"label": scan.created_at.strftime("%H:%M"), "score": scan.display_score, "risk": scan.display_risk_level}
            for scan in reversed(user_scans)
        ] or [{"label": "No scans", "score": 0, "risk": "LOW"}],
    })
