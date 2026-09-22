from django.db import models
from django.contrib.auth.models import AbstractUser
from django.core.validators import FileExtensionValidator


# ==========================================================
# CUSTOM USER
# ==========================================================


class CustomUser(AbstractUser):
    age = models.PositiveIntegerField(blank=True, null=True)

    phone = models.CharField(max_length=20, blank=True, null=True)

    gender = models.CharField(max_length=40, blank=True)

    address = models.TextField(blank=True)

    profile_image = models.ImageField(upload_to="profiles/", blank=True, null=True)

    is_analyst = models.BooleanField(default=False)

    created_at = models.DateTimeField(auto_now_add=True)

    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.username


# ==========================================================
# ASSET INVENTORY
# ==========================================================


class AssetInventory(models.Model):
    hostname = models.CharField(max_length=255)

    ip_address = models.GenericIPAddressField(null=True, blank=True)

    operating_system = models.CharField(max_length=255)

    os_version = models.CharField(max_length=255, blank=True)

    machine_type = models.CharField(max_length=255, blank=True)

    processor = models.CharField(max_length=500, blank=True)

    risk_level = models.CharField(max_length=50, default="LOW")

    discovered_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.hostname


# ==========================================================
# ENDPOINT FINGERPRINT
# ==========================================================


class EndpointFingerprint(models.Model):
    asset = models.ForeignKey(
        AssetInventory, on_delete=models.CASCADE, related_name="fingerprints"
    )

    fingerprint_hash = models.CharField(max_length=128, unique=True)

    cpu_count = models.IntegerField(default=0)

    ram_gb = models.FloatField(default=0)

    disk_count = models.IntegerField(default=0)

    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.fingerprint_hash


# ==========================================================
# COMPLIANCE CHECK
# ==========================================================


class ComplianceCheck(models.Model):
    asset = models.ForeignKey(AssetInventory, on_delete=models.CASCADE)

    compliance_score = models.IntegerField(default=0)

    firewall_enabled = models.BooleanField(default=False)

    defender_enabled = models.BooleanField(default=False)

    secure_boot_enabled = models.BooleanField(default=False)

    bitlocker_enabled = models.BooleanField(default=False)

    uac_enabled = models.BooleanField(default=False)

    failed_controls = models.JSONField(default=list)

    checked_at = models.DateTimeField(auto_now_add=True)


# ==========================================================
# THREAT FINDINGS
# ==========================================================


class ThreatFinding(models.Model):
    SEVERITY_CHOICES = [
        ("LOW", "LOW"),
        ("MEDIUM", "MEDIUM"),
        ("HIGH", "HIGH"),
        ("CRITICAL", "CRITICAL"),
    ]

    STATUS_CHOICES = [
        ("OPEN", "OPEN"),
        ("INVESTIGATING", "INVESTIGATING"),
        ("RESOLVED", "RESOLVED"),
        ("CLOSED", "CLOSED"),
    ]

    title = models.CharField(max_length=500)

    description = models.TextField()

    severity = models.CharField(max_length=20, choices=SEVERITY_CHOICES, default="LOW")

    status = models.CharField(max_length=30, choices=STATUS_CHOICES, default="OPEN")

    evidence = models.JSONField(default=dict)

    created_at = models.DateTimeField(auto_now_add=True)

    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.title


# ==========================================================
# INCIDENT MANAGEMENT
# ==========================================================


class Incident(models.Model):
    PHASES = [("TRIAGE", "Triage"), ("CONTAINMENT", "Containment"), ("ERADICATION", "Eradication"), ("RECOVERY", "Recovery"), ("REVIEW", "Post-Incident Review")]
    phase = models.CharField(max_length=20, choices=PHASES, default="TRIAGE")
    assigned_responder = models.ForeignKey(CustomUser, null=True, blank=True, on_delete=models.SET_NULL, related_name="assigned_incidents")
    playbook = models.JSONField(default=list, blank=True)

    scan_jobs = models.ManyToManyField("ScanJob", blank=True, related_name="incidents")
    owner = models.ForeignKey(
        CustomUser,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="incidents",
    )
    findings = models.ManyToManyField("Finding", blank=True, related_name="incidents")
    target = models.CharField(max_length=2048, blank=True)
    notes = models.JSONField(default=list, blank=True)
    archived = models.BooleanField(default=False)

    STATUS_CHOICES = [
        ("OPEN", "OPEN"),
        ("INVESTIGATING", "INVESTIGATING"),
        ("CONTAINED", "CONTAINED"),
        ("RESOLVED", "RESOLVED"),
        ("CLOSED", "CLOSED"),
    ]

    incident_id = models.CharField(max_length=50, unique=True)

    title = models.CharField(max_length=500)

    description = models.TextField()

    severity = models.CharField(max_length=20)

    status = models.CharField(max_length=30, choices=STATUS_CHOICES, default="OPEN")

    created_at = models.DateTimeField(auto_now_add=True)

    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.incident_id


# ==========================================================
# THREAT INTELLIGENCE
# ==========================================================


class ThreatIntel(models.Model):
    indicator = models.CharField(max_length=500)

    indicator_type = models.CharField(max_length=50)

    source = models.CharField(max_length=200)

    classification = models.CharField(max_length=200, blank=True)

    confidence = models.IntegerField(default=0)

    checked_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.indicator


# ==========================================================
# IOC DATABASE
# ==========================================================


class IOC(models.Model):
    IOC_TYPES = [
        ("IP", "IP"),
        ("DOMAIN", "DOMAIN"),
        ("URL", "URL"),
        ("HASH", "HASH"),
    ]

    ioc_type = models.CharField(max_length=20, choices=IOC_TYPES)

    value = models.CharField(max_length=1000, unique=True)

    source = models.CharField(max_length=200)

    malicious = models.BooleanField(default=False)

    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.value


# ==========================================================
# MITRE ATT&CK TECHNIQUES
# ==========================================================


class MitreTechnique(models.Model):
    technique_id = models.CharField(max_length=20, unique=True)

    technique_name = models.CharField(max_length=300)

    tactic = models.CharField(max_length=200)

    description = models.TextField()

    def __str__(self):
        return self.technique_id


# ==========================================================
# MITRE MAPPING
# ==========================================================


class MitreMapping(models.Model):
    finding = models.ForeignKey(ThreatFinding, on_delete=models.CASCADE)

    technique = models.ForeignKey(MitreTechnique, on_delete=models.CASCADE)

    confidence = models.IntegerField(default=50)

    mapped_at = models.DateTimeField(auto_now_add=True)


# ==========================================================
# THREAT TIMELINE
# ==========================================================


class ThreatTimeline(models.Model):
    event = models.TextField()

    severity = models.CharField(max_length=30, default="INFO")

    timestamp = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.event[:100]


# ==========================================================
# QUARANTINE ENGINE
# ==========================================================


class QuarantineItem(models.Model):
    file_name = models.CharField(max_length=500)

    original_path = models.TextField()

    quarantine_path = models.TextField()

    sha256 = models.CharField(max_length=128)

    quarantined_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.file_name


# ==========================================================
# RISK SCORING
# ==========================================================


class RiskAssessment(models.Model):
    score = models.IntegerField(default=0)

    level = models.CharField(max_length=50)

    findings_count = models.IntegerField(default=0)

    calculated_at = models.DateTimeField(auto_now_add=True)


# ==========================================================
# FILE MONITOR EVENTS
# ==========================================================


class FileMonitorEvent(models.Model):
    EVENT_TYPES = [
        ("CREATED", "CREATED"),
        ("MODIFIED", "MODIFIED"),
        ("DELETED", "DELETED"),
    ]

    file_path = models.TextField()

    event_type = models.CharField(max_length=20, choices=EVENT_TYPES)

    sha256 = models.CharField(max_length=128, blank=True)

    created_at = models.DateTimeField(auto_now_add=True)


# ==========================================================
# COMBINED SCAN RESULTS
# ==========================================================


class ScanResult(models.Model):
    scan_type = models.CharField(max_length=80, default="combined")

    user = models.ForeignKey(
        CustomUser, on_delete=models.SET_NULL, null=True, blank=True
    )

    score = models.IntegerField(default=0)

    risk_level = models.CharField(max_length=40, default="LOW")

    open_ports = models.JSONField(default=list)

    detected_files = models.JSONField(default=list)

    protocols = models.JSONField(default=list)

    modules = models.JSONField(default=dict)

    recommendations = models.JSONField(default=list)

    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.scan_type} - {self.risk_level} - {self.created_at}"


# ==========================================================
# USER ACTIVITY
# ==========================================================


class UserActivity(models.Model):
    user = models.ForeignKey(
        CustomUser, on_delete=models.SET_NULL, null=True, blank=True
    )

    option_used = models.CharField(max_length=120)

    detail = models.TextField(blank=True)

    ip_address = models.GenericIPAddressField(null=True, blank=True)

    device = models.CharField(max_length=300, blank=True)

    place = models.CharField(max_length=150, blank=True, default="Local/Unknown")

    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        username = self.user.username if self.user else "Anonymous"
        return f"{username} used {self.option_used}"


# ==========================================================
# SCAN FEEDBACK / RATING
# ==========================================================


class ScanFeedback(models.Model):
    user = models.ForeignKey(
        CustomUser, on_delete=models.SET_NULL, null=True, blank=True
    )

    scan = models.ForeignKey(
        ScanResult, on_delete=models.CASCADE, related_name="feedback"
    )

    rating = models.PositiveSmallIntegerField(default=5)

    comment = models.TextField(blank=True)

    ip_address = models.GenericIPAddressField(null=True, blank=True)

    device = models.CharField(max_length=300, blank=True)

    place = models.CharField(max_length=150, blank=True, default="Local/Unknown")

    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        username = self.user.username if self.user else "Anonymous"
        return f"{username} rated scan {self.scan_id}: {self.rating}/5"


# ==========================================================
# CONTACT / FEEDBACK
# ==========================================================


class ContactMessage(models.Model):
    subject = models.CharField(max_length=200, blank=True)
    category = models.CharField(max_length=80, blank=True)

    MESSAGE_TYPES = [
        ("suggestion", "Suggestion"),
        ("complaint", "Complaint"),
        ("question", "Question"),
    ]

    user = models.ForeignKey(
        CustomUser, on_delete=models.SET_NULL, null=True, blank=True
    )

    name = models.CharField(max_length=150)

    email = models.EmailField()

    message_type = models.CharField(
        max_length=30, choices=MESSAGE_TYPES, default="suggestion"
    )

    message = models.TextField()

    is_resolved = models.BooleanField(default=False)

    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.message_type}: {self.email}"


# ==========================================================
# AUDIT LOG
# ==========================================================


class AuditLog(models.Model):
    user = models.ForeignKey(
        CustomUser, on_delete=models.SET_NULL, null=True, blank=True
    )

    action = models.CharField(max_length=300)

    details = models.TextField(blank=True)

    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.action


class FeatureFlag(models.Model):
    key = models.CharField(max_length=120, unique=True)
    enabled = models.BooleanField(default=True)
    scope = models.CharField(max_length=80, default="global")
    environment = models.CharField(max_length=80, default="development")
    rollout_percentage = models.PositiveSmallIntegerField(default=100)
    updated_by = models.ForeignKey(
        CustomUser, on_delete=models.SET_NULL, null=True, blank=True
    )
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.key}: {'enabled' if self.enabled else 'disabled'}"


class SecurityAuditEvent(models.Model):
    user = models.ForeignKey(
        CustomUser, on_delete=models.SET_NULL, null=True, blank=True
    )
    action = models.CharField(max_length=240)
    target = models.CharField(max_length=240, blank=True)
    details = models.JSONField(default=dict)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.action


class FalsePositiveReview(models.Model):
    STATUS_CHOICES = [
        ("TRUE_POSITIVE", "True Positive"),
        ("FALSE_POSITIVE", "False Positive"),
        ("NEEDS_REVIEW", "Needs Review"),
    ]
    scan = models.ForeignKey(
        ScanResult, on_delete=models.CASCADE, related_name="false_positive_reviews"
    )
    analyst = models.ForeignKey(
        CustomUser, on_delete=models.SET_NULL, null=True, blank=True
    )
    finding_title = models.CharField(max_length=500)
    status = models.CharField(
        max_length=40, choices=STATUS_CHOICES, default="NEEDS_REVIEW"
    )
    reason = models.TextField(blank=True)
    previous_score = models.IntegerField(default=0)
    updated_score = models.IntegerField(default=0)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.status}: {self.finding_title}"


class SecurityPolicy(models.Model):
    name = models.CharField(max_length=180, unique=True)
    description = models.TextField(blank=True)
    category = models.CharField(max_length=80, default="general")
    enabled = models.BooleanField(default=True)
    configuration = models.JSONField(default=dict)
    updated_by = models.ForeignKey(
        CustomUser, on_delete=models.SET_NULL, null=True, blank=True
    )
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.name




class CMSPage(models.Model):
    STATUS_CHOICES = [
        ("DRAFT", "Draft"),
        ("PUBLISHED", "Published"),
        ("SCHEDULED", "Scheduled"),
        ("ARCHIVED", "Archived"),
    ]
    title = models.CharField(max_length=220)
    slug = models.SlugField(max_length=160, unique=True)
    seo_title = models.CharField(max_length=220, blank=True)
    seo_description = models.CharField(max_length=320, blank=True)
    seo_keywords = models.CharField(max_length=320, blank=True)
    excerpt = models.TextField(blank=True)
    content = models.TextField(blank=True)
    status = models.CharField(max_length=30, choices=STATUS_CHOICES, default="DRAFT")
    show_in_navigation = models.BooleanField(default=True)
    show_in_footer = models.BooleanField(default=False)
    search_visible = models.BooleanField(default=True)
    author = models.ForeignKey(
        CustomUser,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="cms_pages",
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    published_at = models.DateTimeField(null=True, blank=True)

    def __str__(self):
        return self.title


class CMSPageRevision(models.Model):
    page = models.ForeignKey(
        CMSPage, on_delete=models.CASCADE, related_name="revisions"
    )
    editor = models.ForeignKey(
        CustomUser, on_delete=models.SET_NULL, null=True, blank=True
    )
    title = models.CharField(max_length=220)
    content = models.TextField(blank=True)
    status = models.CharField(max_length=30, default="DRAFT")
    change_summary = models.CharField(max_length=260, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.page.title} revision {self.id}"


class CMSBlock(models.Model):
    page = models.ForeignKey(CMSPage, on_delete=models.CASCADE, related_name="blocks")
    block_type = models.CharField(max_length=60, default="text")
    title = models.CharField(max_length=220, blank=True)
    body = models.TextField(blank=True)
    sort_order = models.PositiveIntegerField(default=0)
    visible = models.BooleanField(default=True)

    class Meta:
        ordering = ["sort_order", "id"]

    def __str__(self):
        return f"{self.block_type}: {self.title}"


class CMSMedia(models.Model):
    title = models.CharField(max_length=180)
    file = models.FileField(upload_to="cms_media/")
    alt_text = models.CharField(max_length=220, blank=True)
    caption = models.CharField(max_length=260, blank=True)
    uploaded_by = models.ForeignKey(
        CustomUser, on_delete=models.SET_NULL, null=True, blank=True
    )
    archived = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.title


class CMSBlogPost(models.Model):
    STATUS_CHOICES = CMSPage.STATUS_CHOICES
    title = models.CharField(max_length=220)
    slug = models.SlugField(max_length=160, unique=True)
    category = models.CharField(max_length=80, default="Security")
    tags = models.CharField(max_length=240, blank=True)
    excerpt = models.TextField(blank=True)
    content = models.TextField(blank=True)
    reading_time = models.PositiveIntegerField(default=3)
    status = models.CharField(max_length=30, choices=STATUS_CHOICES, default="DRAFT")
    author = models.ForeignKey(
        CustomUser,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="cms_blog_posts",
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    published_at = models.DateTimeField(null=True, blank=True)

    def __str__(self):
        return self.title


class CMSNavigationItem(models.Model):
    label = models.CharField(max_length=120)
    url = models.CharField(max_length=260)
    location = models.CharField(max_length=60, default="main")
    sort_order = models.PositiveIntegerField(default=0)
    visible = models.BooleanField(default=True)

    class Meta:
        ordering = ["location", "sort_order", "id"]

    def __str__(self):
        return self.label


class CMSSiteSettings(models.Model):
    site_name = models.CharField(max_length=180, default="Vigilant Sphere")
    default_seo_title = models.CharField(max_length=220, blank=True)
    default_seo_description = models.CharField(max_length=320, blank=True)
    contact_email = models.EmailField(blank=True)
    support_email = models.EmailField(blank=True)
    footer_text = models.CharField(
        max_length=260, default="Vigilant Sphere Security Intelligence Platform"
    )
    maintenance_notice = models.CharField(max_length=260, blank=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.site_name


class CMSAnnouncement(models.Model):
    TYPES = [
        ("INFO", "Information"),
        ("WARNING", "Warning"),
        ("SUCCESS", "Success"),
        ("CRITICAL", "Critical"),
    ]
    message = models.CharField(max_length=260)
    announcement_type = models.CharField(max_length=30, choices=TYPES, default="INFO")
    enabled = models.BooleanField(default=True)
    cta_label = models.CharField(max_length=80, blank=True)
    cta_url = models.CharField(max_length=260, blank=True)
    start_at = models.DateTimeField(null=True, blank=True)
    end_at = models.DateTimeField(null=True, blank=True)

    def __str__(self):
        return self.message[:80]


class CMSDeveloperProfile(models.Model):
    developer_name = models.CharField(max_length=180, default="Dhithimos E J")
    short_bio = models.CharField(max_length=320, blank=True)
    full_bio = models.TextField(blank=True)
    skills = models.TextField(blank=True)
    technologies = models.TextField(blank=True)
    projects = models.TextField(blank=True)
    achievements = models.TextField(blank=True)
    education = models.TextField(blank=True)
    experience = models.TextField(blank=True)
    github = models.URLField(blank=True)
    linkedin = models.URLField(blank=True)
    email = models.EmailField(blank=True)
    website = models.URLField(blank=True)
    profile_image = models.ForeignKey(
        CMSMedia, on_delete=models.SET_NULL, null=True, blank=True
    )
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.developer_name


class DeveloperImage(models.Model):
    """Staff-managed public images for the developer profile."""

    image = models.ImageField(
        upload_to="developer/",
        validators=[FileExtensionValidator(["jpg", "jpeg", "png", "webp"])],
    )
    title = models.CharField(max_length=180, blank=True)
    alt_text = models.CharField(max_length=220, default="Vigilant Sphere developer")
    is_active = models.BooleanField(default=True)
    display_order = models.PositiveIntegerField(default=0)
    uploaded_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["display_order", "id"]

    def __str__(self):
        return self.title or self.alt_text


# ==========================================================
# UNIFIED LOCAL SECURITY PIPELINE
# ==========================================================


class ScanJob(models.Model):
    """A durable request for a local, bounded security assessment."""

    scan_id = models.CharField(max_length=36, unique=True)
    requested_by = models.ForeignKey(
        CustomUser,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="security_scan_jobs",
    )
    asset = models.ForeignKey(
        AssetInventory,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="scan_jobs",
    )
    scan_type = models.CharField(max_length=80, default="combined")
    selected_scanners = models.JSONField(default=list)
    status = models.CharField(max_length=16, default="QUEUED", db_index=True)
    progress = models.PositiveSmallIntegerField(default=0)
    scanner_count = models.PositiveSmallIntegerField(default=0)
    completed_scanner_count = models.PositiveSmallIntegerField(default=0)
    failed_scanner_count = models.PositiveSmallIntegerField(default=0)
    finding_count = models.PositiveIntegerField(default=0)
    risk_score = models.PositiveSmallIntegerField(default=0)
    error = models.TextField(blank=True)
    started_at = models.DateTimeField(null=True, blank=True)
    completed_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        indexes = [models.Index(fields=["status", "created_at"])]


class Finding(models.Model):
    """Normalized scanner output. Evidence is redacted before it reaches this model."""

    updated_at = models.DateTimeField(auto_now=True)
    finding_id = models.CharField(max_length=64, unique=True)
    fingerprint = models.CharField(max_length=64, db_index=True)
    job = models.ForeignKey(ScanJob, on_delete=models.CASCADE, related_name="findings")
    asset = models.ForeignKey(
        AssetInventory,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="findings",
    )
    scanner = models.CharField(max_length=80, db_index=True)
    finding_type = models.CharField(max_length=100)
    title = models.CharField(max_length=500)
    description = models.TextField()
    severity = models.CharField(max_length=10, db_index=True)
    confidence = models.FloatField(default=0.0)
    risk_score = models.PositiveSmallIntegerField(default=0)
    status = models.CharField(max_length=20, default="OPEN", db_index=True)
    evidence = models.JSONField(default=dict)
    observations = models.JSONField(default=list)
    recommendation = models.TextField(blank=True)
    remediation = models.TextField(blank=True)
    mitre_technique = models.CharField(max_length=32, blank=True)
    mitre_tactic = models.CharField(max_length=100, blank=True)
    ioc = models.JSONField(default=dict)
    requires_approval = models.BooleanField(default=True)
    timestamp = models.DateTimeField(auto_now_add=True, db_index=True)

    class Meta:
        indexes = [
            models.Index(fields=["severity", "status", "timestamp"]),
            models.Index(fields=["scanner", "timestamp"]),
        ]


class SecurityAlert(models.Model):
    dedup_key = models.CharField(max_length=600, blank=True, db_index=True)
    last_notified_at = models.DateTimeField(null=True, blank=True)
    finding = models.OneToOneField(
        Finding, on_delete=models.CASCADE, related_name="alert"
    )
    status = models.CharField(max_length=20, default="OPEN", db_index=True)
    created_at = models.DateTimeField(auto_now_add=True)


class FindingEvidence(models.Model):
    finding = models.ForeignKey(
        Finding, on_delete=models.CASCADE, related_name="evidence_records"
    )
    source = models.CharField(max_length=120)
    content = models.JSONField(default=dict)
    content_hash = models.CharField(max_length=64, db_index=True)
    created_at = models.DateTimeField(auto_now_add=True)


class ResponseApproval(models.Model):
    finding = models.ForeignKey(
        Finding, on_delete=models.CASCADE, related_name="approvals"
    )
    requested_by = models.ForeignKey(
        CustomUser,
        null=True,
        on_delete=models.SET_NULL,
        related_name="response_requests",
    )
    approved_by = models.ForeignKey(
        CustomUser,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="response_approvals",
    )
    action = models.CharField(max_length=80)
    dry_run = models.BooleanField(default=True)
    status = models.CharField(max_length=20, default="PENDING")
    result = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)


class TargetScan(models.Model):
    """A target-centric investigation. Passwords and their hashes are never targets."""

    job = models.OneToOneField(
        ScanJob,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="investigation",
    )
    scan_id = models.CharField(max_length=36, unique=True)
    user = models.ForeignKey(
        CustomUser, null=True, on_delete=models.SET_NULL, related_name="target_scans"
    )
    target = models.CharField(max_length=2048)
    target_type = models.CharField(max_length=20, db_index=True)
    status = models.CharField(max_length=24, default="COMPLETED", db_index=True)
    risk_score = models.PositiveSmallIntegerField(default=0)
    risk_level = models.CharField(max_length=16, default="UNKNOWN")
    confidence = models.CharField(max_length=16, default="low")
    results = models.JSONField(default=list)
    provider_results = models.JSONField(default=list)
    findings = models.JSONField(default=list)
    started_at = models.DateTimeField()
    completed_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        indexes = [
            models.Index(fields=["user", "created_at"]),
            models.Index(fields=["target_type", "created_at"]),
        ]


class WiFiAudit(models.Model):
    finding = models.ForeignKey("Finding", null=True, blank=True, on_delete=models.SET_NULL, related_name="wifi_audits")
    score_breakdown = models.JSONField(default=list, blank=True)
    bssid = models.CharField(max_length=32, null=True, blank=True)
    """Saved Wi-Fi security metadata only; credentials/key content are never fields."""

    user = models.ForeignKey(
        CustomUser, null=True, on_delete=models.SET_NULL, related_name="wifi_audits"
    )
    profile_name = models.CharField(max_length=512)
    authentication = models.CharField(max_length=120, blank=True)
    encryption = models.CharField(max_length=120, blank=True)
    security_level = models.CharField(max_length=32, default="UNKNOWN")
    risk_level = models.CharField(max_length=16, default="UNKNOWN")
    risk_score = models.PositiveSmallIntegerField(default=0)
    risk_reason = models.TextField(blank=True)
    recommendation = models.TextField(blank=True)
    collection_status = models.CharField(max_length=32, default="AVAILABLE")
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        indexes = [
            models.Index(fields=["user", "created_at"]),
            models.Index(fields=["risk_level", "created_at"]),
        ]


class TrustedWifiProfile(models.Model):
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE)
    profile_name = models.CharField(max_length=512)
    security_level_at_trust = models.CharField(max_length=32)
    risk_score_at_trust = models.PositiveSmallIntegerField()
    trusted_at = models.DateTimeField(auto_now=True)

    class Meta:
        constraints = [models.UniqueConstraint(fields=["user", "profile_name"], name="unique_trusted_wifi_user_profile")]


class AlertEmailConfiguration(models.Model):
    alert_severity_threshold = models.CharField(max_length=8, choices=[("CRITICAL", "Critical"), ("HIGH", "High")], default="CRITICAL")
    alert_dedup_window_hours = models.PositiveIntegerField(default=24)
    digest_enabled = models.BooleanField(default=False)
    digest_frequency = models.CharField(max_length=8, choices=[("DAILY", "Daily"), ("WEEKLY", "Weekly")], default="DAILY")
    last_digest_sent_at = models.DateTimeField(null=True, blank=True)

    """Operational settings; SMTP username/password stay in environment variables."""

    enabled = models.BooleanField(default=False)
    host = models.CharField(max_length=255, blank=True)
    port = models.PositiveIntegerField(default=587)
    use_tls = models.BooleanField(default=True)
    use_ssl = models.BooleanField(default=False)
    from_email = models.EmailField(blank=True)
    recipients = models.TextField(
        blank=True, help_text="One email address per line or comma-separated."
    )
    updated_by = models.ForeignKey(
        CustomUser, null=True, blank=True, on_delete=models.SET_NULL
    )
    updated_at = models.DateTimeField(auto_now=True)


class SecurityAlertDelivery(models.Model):
    STATUS = [
        ("PENDING", "Pending"),
        ("SENT", "Sent"),
        ("FAILED", "Failed"),
        ("NOT_CONFIGURED", "Not configured"),
    ]
    alert = models.OneToOneField(
        SecurityAlert, on_delete=models.CASCADE, related_name="email_delivery"
    )
    status = models.CharField(max_length=32, choices=STATUS, default="PENDING")
    recipient_count = models.PositiveIntegerField(default=0)
    delivery_attempts = models.PositiveSmallIntegerField(default=0)
    error = models.CharField(max_length=500, blank=True)
    sent_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)


# Register legacy models so existing migration state and tables are preserved.
from .advanced_models import (  # noqa: F401 -- register legacy migration models
    AttackPatternDetection,
    BehavioralThreat,
    ComplianceFramework,
    DomainReputation,
    FileIntegrityEvent,
    FileReputation,
    ForensicSnapshot,
    IndicatorOfCompromise,
    IPReputation,
    MalwareSignature,
    ProcessAnalysis,
    RealTimeAlert,
    RemediationAction,
    RiskMetric,
    ThreatHuntingRule,
    ThreatIntelFeed,
    ThreatIntelMatch,
)


class IncidentArtifact(models.Model):
    """Private bounded attachment; never exposed through MEDIA_URL or executed."""
    incident = models.ForeignKey(Incident, on_delete=models.CASCADE, related_name="artifacts")
    uploaded_by = models.ForeignKey(CustomUser, null=True, on_delete=models.SET_NULL)
    name = models.CharField(max_length=180)
    content_type = models.CharField(max_length=80)
    data = models.BinaryField(editable=False)
    sha256 = models.CharField(max_length=64)
    size = models.PositiveIntegerField()
    created_at = models.DateTimeField(auto_now_add=True)
