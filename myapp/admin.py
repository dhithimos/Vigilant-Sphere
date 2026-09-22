from .local_admin import local_admin_site, LocalPermissions, LocalModelAdmin
from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from django import forms

from .models import (
    AssetInventory,
    AuditLog,
    CMSAnnouncement,
    CMSBlogPost,
    CMSBlock,
    CMSDeveloperProfile,
    DeveloperImage,
    CMSMedia,
    CMSNavigationItem,
    CMSPage,
    CMSPageRevision,
    CMSSiteSettings,
    ComplianceCheck,
    ContactMessage,
    CustomUser,
    EndpointFingerprint,
    FeatureFlag,
    FalsePositiveReview,
    FileMonitorEvent,
    Incident,
    IOC,
    MitreMapping,
    MitreTechnique,
    QuarantineItem,
    RiskAssessment,
    ScanFeedback,
    ScanResult,
    ThreatFinding,
    ThreatIntel,
    ThreatTimeline,
    SecurityAuditEvent,
    SecurityPolicy,
    UserActivity,
    WiFiAudit,
    AlertEmailConfiguration,
    SecurityAlertDelivery,
)


@admin.register(CustomUser, site=local_admin_site)
class CustomUserAdmin(LocalPermissions, UserAdmin):
    fieldsets = UserAdmin.fieldsets + (
        (
            "Vigilant Sphere profile",
            {
                "fields": (
                    "age",
                    "phone",
                    "gender",
                    "address",
                    "profile_image",
                    "is_analyst",
                )
            },
        ),
    )


@admin.register(ScanResult, site=local_admin_site)
class ScanResultAdmin(LocalModelAdmin):
    list_display = ("scan_type", "user", "score", "risk_level", "created_at")
    list_filter = ("scan_type", "risk_level", "created_at")
    search_fields = ("user__username", "user__email")


@admin.register(UserActivity, site=local_admin_site)
class UserActivityAdmin(LocalModelAdmin):
    list_display = ("user", "option_used", "ip_address", "place", "created_at")
    list_filter = ("option_used", "created_at")
    search_fields = ("user__username", "user__email", "detail", "ip_address", "device")


@admin.register(ScanFeedback, site=local_admin_site)
class ScanFeedbackAdmin(LocalModelAdmin):
    list_display = ("user", "scan", "rating", "ip_address", "place", "created_at")
    list_filter = ("rating", "created_at")
    search_fields = ("user__username", "user__email", "comment", "device")


@admin.register(ContactMessage, site=local_admin_site)
class ContactMessageAdmin(LocalModelAdmin):
    list_display = ("name", "email", "message_type", "is_resolved", "created_at")
    list_filter = ("message_type", "is_resolved", "created_at")
    search_fields = ("name", "email", "message")


local_admin_site.register(AssetInventory, LocalModelAdmin)
local_admin_site.register(AuditLog, LocalModelAdmin)
local_admin_site.register(CMSAnnouncement, LocalModelAdmin)
local_admin_site.register(CMSBlogPost, LocalModelAdmin)
local_admin_site.register(CMSBlock, LocalModelAdmin)
local_admin_site.register(CMSDeveloperProfile, LocalModelAdmin)


@admin.register(DeveloperImage, site=local_admin_site)
class DeveloperImageAdmin(LocalModelAdmin):
    class DeveloperImageForm(forms.ModelForm):
        class Meta:
            model = DeveloperImage
            fields = "__all__"

        def clean_image(self):
            image = self.cleaned_data["image"]
            if image.size > 5 * 1024 * 1024:
                raise forms.ValidationError("Developer images must be 5 MB or smaller.")
            return image

    form = DeveloperImageForm
    list_display = ("title", "is_active", "display_order", "updated_at")
    list_editable = ("is_active", "display_order")
    list_filter = ("is_active",)
    search_fields = ("title", "alt_text")


local_admin_site.register(CMSMedia, LocalModelAdmin)
local_admin_site.register(CMSNavigationItem, LocalModelAdmin)
local_admin_site.register(CMSPage, LocalModelAdmin)
local_admin_site.register(CMSPageRevision, LocalModelAdmin)
local_admin_site.register(CMSSiteSettings, LocalModelAdmin)
local_admin_site.register(ComplianceCheck, LocalModelAdmin)
local_admin_site.register(EndpointFingerprint, LocalModelAdmin)
local_admin_site.register(FeatureFlag, LocalModelAdmin)
local_admin_site.register(FalsePositiveReview, LocalModelAdmin)
local_admin_site.register(FileMonitorEvent, LocalModelAdmin)
local_admin_site.register(Incident, LocalModelAdmin)
local_admin_site.register(IOC, LocalModelAdmin)
local_admin_site.register(MitreMapping, LocalModelAdmin)
local_admin_site.register(MitreTechnique, LocalModelAdmin)
local_admin_site.register(QuarantineItem, LocalModelAdmin)
local_admin_site.register(RiskAssessment, LocalModelAdmin)
local_admin_site.register(ThreatFinding, LocalModelAdmin)
local_admin_site.register(ThreatIntel, LocalModelAdmin)
local_admin_site.register(ThreatTimeline, LocalModelAdmin)
local_admin_site.register(SecurityAuditEvent, LocalModelAdmin)
local_admin_site.register(SecurityPolicy, LocalModelAdmin)
local_admin_site.register(WiFiAudit, LocalModelAdmin)
local_admin_site.register(AlertEmailConfiguration, LocalModelAdmin)
local_admin_site.register(SecurityAlertDelivery, LocalModelAdmin)


from .models import ScanJob, Finding, FindingEvidence, TargetScan

for model in (ScanJob, Finding, FindingEvidence, TargetScan):
    if not local_admin_site.is_registered(model):
        local_admin_site.register(model, LocalModelAdmin)

from .models import IndicatorOfCompromise, TrustedWifiProfile
from .analysis.ioc_correlation import normalize_indicator

class IndicatorForm(forms.ModelForm):
    class Meta:
        model=IndicatorOfCompromise
        fields="__all__"
    def clean(self):
        data=super().clean()
        if not str(data.get("source", "")).strip():self.add_error("source", "Source is required")
        if data.get("ioc_type") and data.get("value"):
            try:data.update(normalize_indicator(data["ioc_type"],data["value"]))
            except ValueError as exc:self.add_error("value", str(exc))
        if data.get("confidence") is not None and not 0<=data["confidence"]<=100:self.add_error("confidence", "Use 0–100")
        return data

@admin.register(IndicatorOfCompromise,site=local_admin_site)
class IndicatorOfCompromiseAdmin(LocalModelAdmin):
    form=IndicatorForm
    list_display=("ioc_type","value","source","confidence","is_active","last_seen","matches_found")
    list_filter=("ioc_type","source","is_active")
    search_fields=("value","threat_name")
    readonly_fields=("matches_found","discovered_at","last_seen")
    list_editable=("is_active",)

local_admin_site.register(TrustedWifiProfile, LocalModelAdmin)


