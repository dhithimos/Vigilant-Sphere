from django.urls import path

from . import views, workspace_views as workspace
from django.contrib.auth import views as auth_views


urlpatterns = [
    path(
        "reset/<uidb64>/<token>/",
        auth_views.PasswordResetConfirmView.as_view(
            template_name="myapp/recovery.html", success_url="/login/"
        ),
        name="password_reset_confirm",
    ),
    path("incidents/new/", workspace.incident_edit, name="incident_new"),
    path("incidents/<int:pk>/", workspace.incident_detail, name="incident_detail"),
    path("incidents/<int:pk>/edit/", workspace.incident_edit, name="incident_edit"),
    path("findings/<int:pk>/", workspace.finding_detail, name="finding_detail"),
    path("compare/", workspace.compare, name="scan_compare"),
    path(
        "investigations/<str:scan_id>/csv/",
        workspace.csv_report,
        name="target_scan_csv",
    ),
    path("blog/<slug:slug>/", workspace.post_detail, name="post_detail"),
    path("admin-dashboard/cms/blog/new/", workspace.post_edit, name="post_new"),
    path("admin-dashboard/cms/blog/<int:pk>/", workspace.post_edit, name="post_edit"),
    path("mitre/technique/<str:technique>/", workspace.mitre, name="technique_detail"),
    path("mitre/tactic/<slug:tactic>/", workspace.mitre, name="tactic_detail"),
    # Public pages
    path("", views.home, name="home"),
    path("about/", views.about, name="about"),
    path("contact/", views.contact, name="contact"),
    path("privacy/", views.privacy_policy, name="privacy"),
    path("blogs/", views.blogs, name="blogs"),
    path("blog/", views.blogs, name="blog"),
    # Authentication pages
    path("login/", views.user_login, name="login"),
    path("logout/", views.user_logout, name="logout"),
    path("register/", views.register, name="register"),
    path("forgot-password/", views.forgot_password, name="forgot_password"),
    path("change-password/", views.change_password, name="change_password"),
    # User dashboard and profile pages
    path("dashboard/", views.dashboard, name="dashboard"),
    path("security-admin/", views.admin_dashboard, name="admin_dashboard"),
    path("profile/", views.profile, name="profile"),
    path("edit-profile/", views.edit_profile, name="edit_profile"),
    path("launcher/", views.launcher, name="launcher"),
    # Scan pages and report exports
    path("scan/", views.combined_scan, name="combined_scan"),
    path(
        "investigations/<str:scan_id>/",
        views.target_scan_detail,
        name="target_scan_detail",
    ),
    path(
        "investigations/<str:scan_id>/json/",
        views.target_scan_json,
        name="target_scan_json",
    ),
    path(
        "investigations/<str:scan_id>/pdf/",
        views.target_scan_pdf,
        name="target_scan_pdf",
    ),
    path("scan-jobs/", views.scan_jobs, name="scan_jobs"),
    path("scan-jobs/<int:job_id>/", views.scan_job_detail, name="scan_job_detail"),
    path("findings/", views.findings, name="findings"),
    path("scan/<int:result_id>/", views.scan_result, name="scan_result"),
    path("scan/<int:result_id>/pdf/", views.download_scan_pdf, name="scan_pdf"),
    path(
        "scan/<int:result_id>/feedback/",
        views.submit_scan_feedback,
        name="scan_feedback",
    ),
    # Separate scanner modules
    path("system/", views.system_scan, name="system_scan"),
    path("network/", views.network_scan, name="network_scan"),
    path("mobile-security/", views.mobile_security_scan, name="mobile_security"),
    path("phishing/", views.phishing_scan, name="phishing_scan"),
    path("password-strength/", views.password_strength, name="password_strength"),
    path("password-checker/", views.mobile_security_scan, name="password_checker"),
    path("wifi-security/", views.wifi_security, name="wifi_security"),
    path("chatbot/", views.chatbot, name="chatbot"),
    path("api/chatbot/", views.chatbot_api, name="chatbot_api"),
    path("email-configuration/", views.email_configuration, name="email_configuration"),
    path("file-scan/", views.file_scan, name="file_scan"),
    path("feature-flags/", views.feature_flags, name="feature_flags"),
    path("threat-detection/", views.threat_detection, name="threat_detection"),
    path("threat-intelligence/", views.threat_intelligence, name="threat_intelligence"),
    path("ioc-correlation/", views.ioc_correlation, name="ioc_correlation"),
    path("mitre-mapping/", workspace.mitre, name="mitre_mapping"),
    path("fim/", views.real_time_monitoring, name="real_time_monitoring"),
    path("incidents/", workspace.incident_list, name="incidents"),
    path("quarantine/", views.quarantine_view, name="quarantine"),
    path("risk-assessment/", views.risk_assessment, name="risk_assessment"),
    path("timeline/", views.threat_timeline, name="threat_timeline"),
    path("scan-history/", workspace.history, name="scan_history"),
    path("reports/", workspace.history, name="reports"),
    path("developer/", views.developer_profile, name="developer"),
    path("how-to-use/", views.how_to_use, name="how_to_use"),
    path("documentation/", views.how_to_use, name="documentation"),
    path("suggestions/", views.suggestions, name="suggestions"),
    # API and admin CSV exports
    path("report/pdf/", views.download_scan_pdf, name="download_scan_pdf"),
    path("report/json/", views.export_json_report, name="export_json_report"),
    path(
        "api/dashboard-metrics/",
        views.api_dashboard_metrics,
        name="api_dashboard_metrics",
    ),
    path("admin-dashboard/", views.admin_dashboard, name="admin_dashboard_alias"),
    path("admin-dashboard/cms/pages/", views.cms_pages, name="cms_pages"),
    path("admin-dashboard/cms/pages/new/", views.cms_page_edit, name="cms_page_new"),
    path(
        "admin-dashboard/cms/pages/<int:page_id>/",
        views.cms_page_edit,
        name="cms_page_edit",
    ),
    path("admin-dashboard/cms/media/", views.cms_media, name="cms_media"),
    path(
        "admin-dashboard/cms/developer-images/",
        views.cms_developer_images,
        name="cms_developer_images",
    ),
    path("admin-dashboard/cms/blog/", workspace.post_list, name="cms_blog"),
    path(
        "admin-dashboard/cms/navigation/", views.cms_navigation, name="cms_navigation"
    ),
    path("admin-dashboard/cms/settings/", views.cms_settings, name="cms_settings"),
    path(
        "admin-dashboard/security-policies/",
        views.security_policies,
        name="security_policies",
    ),
    path("admin-dashboard/audit-logs/", views.audit_logs, name="audit_logs"),
    path(
        "security-admin/users/download/",
        views.download_user_details,
        name="download_all_users",
    ),
    path(
        "security-admin/users/<int:user_id>/download/",
        views.download_user_details,
        name="download_user_details",
    ),
]

urlpatterns += [
    path("dns/", workspace.static_analysis, {"kind": "dns"}, name="dns_analysis")
]

urlpatterns += [
    path("tls/", workspace.static_analysis, {"kind": "tls"}, name="tls_analysis")
]

urlpatterns += [
    path("http/", workspace.static_analysis, {"kind": "http"}, name="http_analysis")
]

urlpatterns += [
    path("html/", workspace.static_analysis, {"kind": "html"}, name="html_analysis")
]

urlpatterns += [
    path(
        "javascript/",
        workspace.static_analysis,
        {"kind": "javascript"},
        name="javascript_analysis",
    )
]

urlpatterns += [
    path("scan-jobs/<int:job_id>/cancel/", workspace.cancel_job, name="cancel_job")
]

urlpatterns += [path("wifi-security/<int:audit_id>/trust/", workspace.trust_wifi, name="trust_wifi")]

from . import domain_views, incident_response
urlpatterns += [
    path("security-intelligence/", domain_views.scanner_page, {"kind":"security_intelligence"}, name="security_intelligence"),
    path("analysis/<str:scan_id>/", domain_views.scanner_result, name="domain_result"),
    path("incidents/<int:pk>/response/", incident_response.update_response, name="incident_response"),
    path("incidents/<int:pk>/evidence/", incident_response.upload_artifact, name="incident_evidence_upload"),
    path("incident-evidence/<int:pk>/download/", incident_response.download_artifact, name="incident_evidence_download"),
]
