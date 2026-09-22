"""Regression coverage for evidence correctness, authorization and offline operation."""

import io
import json
import zipfile
from unittest.mock import patch, MagicMock
from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import TestCase, SimpleTestCase, override_settings
from django.urls import reverse
from django.utils import timezone
from .models import CMSBlogPost, Incident
from .analysis.investigation import run_target_scan
from .scanners.target import http_scan, safe_host, normalize_url
from .scanners.file_analysis import analyze_uploaded
from .scanners.web_analysis import analyze_html, javascript
from .uploads import clean_image


@override_settings(VT_API_KEY="", ABUSEIPDB_API_KEY="", OTX_API_KEY="", HIBP_API_KEY="")
class WorkflowTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.user = get_user_model().objects.create_user(
            "analyst2", "analyst@example.test", "Long-Test-Pass-928!"
        )
        cls.other = get_user_model().objects.create_user(
            "other2", "other@example.test", "Long-Test-Pass-928!"
        )
        cls.staff = get_user_model().objects.create_user(
            "staff2", "staff@example.test", "Long-Test-Pass-928!", is_staff=True
        )

    def setUp(self):
        self.client.force_login(self.user)

    def scan(self):
        # Fixture entropy establishes an actual indicator without malware claims.
        return run_target_scan(
            self.user, uploaded=SimpleUploadedFile("entropy.bin", bytes(range(256)) * 8)
        )[0]

    def test_file_persistence_reports_and_isolation(self):
        scan = self.scan()
        self.assertEqual(scan.status, "COMPLETED")
        self.assertTrue(scan.job.findings.exists())
        for name in [
            "target_scan_detail",
            "target_scan_json",
            "target_scan_pdf",
            "target_scan_csv",
        ]:
            response = self.client.get(reverse(name, args=[scan.scan_id]))
            self.assertEqual(response.status_code, 200, name)
        self.client.force_login(self.other)
        for name in ["target_scan_json", "target_scan_pdf", "target_scan_csv"]:
            self.assertIn(
                self.client.get(reverse(name, args=[scan.scan_id])).status_code,
                [403, 404],
            )
        self.assertFalse(any(x["status"] == "success" for x in scan.provider_results))

    def test_incident_finding_lifecycle(self):
        scan = self.scan()
        finding = scan.job.findings.first()
        response = self.client.post(
            reverse("incident_new"),
            {
                "title": "Review sample",
                "description": "Entropy observation",
                "severity": "LOW",
                "status": "OPEN",
                "target": "entropy.bin",
                "findings": [finding.pk],
            },
        )
        self.assertEqual(response.status_code, 302)
        incident = Incident.objects.get(owner=self.user)
        self.assertIn(finding, incident.findings.all())
        self.client.post(
            reverse("finding_detail", args=[finding.pk]), {"status": "ACKNOWLEDGED"}
        )
        finding.refresh_from_db()
        self.assertEqual(finding.status, "ACKNOWLEDGED")
        self.client.post(
            reverse("incident_detail", args=[incident.pk]), {"note": "Reviewed source"}
        )
        incident.refresh_from_db()
        self.assertEqual(incident.notes[-1]["event"], "Reviewed source")
        self.client.force_login(self.other)
        self.assertEqual(
            self.client.get(reverse("incident_detail", args=[incident.pk])).status_code,
            404,
        )
        self.assertEqual(
            self.client.post(
                reverse("finding_detail", args=[finding.pk]), {"status": "RESOLVED"}
            ).status_code,
            404,
        )

    def test_unowned_findings_cannot_be_attached(self):
        finding = self.scan().job.findings.first()
        self.client.force_login(self.other)
        self.client.post(
            reverse("incident_new"),
            {
                "title": "Bad link",
                "description": "Test",
                "severity": "LOW",
                "status": "OPEN",
                "findings": [finding.pk],
            },
        )
        self.assertFalse(Incident.objects.filter(owner=self.other).exists())

    def test_cms_publish_schedule_draft_and_xss(self):
        self.assertEqual(self.client.get(reverse("post_new")).status_code, 200)
        response = self.client.post(
            reverse("post_new"),
            {
                "title": "Published evidence",
                "slug": "published-evidence",
                "category": "Security",
                "tags": "local",
                "excerpt": "Real post",
                "content": "<script>alert(1)</script>",
                "status": "PUBLISHED",
            },
        )
        self.assertEqual(response.status_code, 302)
        post = CMSBlogPost.objects.get(slug="published-evidence")
        self.assertIsNotNone(post.published_at)
        self.client.logout()
        self.assertContains(self.client.get(reverse("blogs")), "Published evidence")
        self.assertContains(self.client.get(reverse("home")), "Published evidence")
        detail = self.client.get(reverse("post_detail", args=[post.slug]))
        self.assertContains(detail, "&lt;script&gt;")
        self.assertNotContains(detail, "<script>alert(1)</script>")
        post.status = "DRAFT"
        post.save()
        self.assertEqual(
            self.client.get(reverse("post_detail", args=[post.slug])).status_code, 404
        )
        post.status = "SCHEDULED"
        post.published_at = timezone.now() + __import__("datetime").timedelta(days=1)
        post.save()
        self.assertNotContains(self.client.get(reverse("blogs")), "Published evidence")

    def test_recovery_does_not_accept_demo_otp(self):
        self.client.logout()
        self.client.post(
            reverse("forgot_password"),
            {
                "action": "request",
                "username": self.user.username,
                "email": self.user.email,
            },
        )
        self.client.post(
            reverse("forgot_password"),
            {
                "action": "reset",
                "password": "Changed-Pass-983!",
                "confirm_password": "Changed-Pass-983!",
            },
        )
        self.user.refresh_from_db()
        self.assertTrue(self.user.check_password("Long-Test-Pass-928!"))

    def test_authentication_and_csrf(self):
        self.client.logout()
        self.assertTrue(
            self.client.login(username="analyst2", password="Long-Test-Pass-928!")
        )
        from django.test import Client

        c = Client(enforce_csrf_checks=True)
        c.force_login(self.user)
        self.assertEqual(
            c.post(
                reverse("chatbot_api"),
                data='{"message":"What is phishing?"}',
                content_type="application/json",
            ).status_code,
            403,
        )

    def test_host_inspection_requires_login_not_staff(self):
        from .context import can_inspect_host
        self.assertFalse(self.user.is_staff)
        self.assertTrue(can_inspect_host(self.user))
        for name in ["system_scan", "network_scan", "wifi_security"]:
            self.assertEqual(self.client.get(reverse(name)).status_code, 200)
        self.client.logout()
        for name in ["system_scan", "network_scan", "threat_detection", "wifi_security", "combined_scan"]:
            self.assertEqual(self.client.post(reverse(name)).status_code, 302)

    def test_system_network_posts_allow_regular_users(self):
        from unittest.mock import patch, Mock
        for name, mode in [("system_scan", "system"), ("network_scan", "network")]:
            with patch("myapp.views.run_combined_scan", return_value={}) as scanner, patch("myapp.views._save_scan", return_value=Mock(id=123)), patch("myapp.views.track_activity"):
                response = self.client.post(reverse(name))
                self.assertEqual(response.status_code, 302)
                scanner.assert_called_once_with(self.user, mode)

    def test_shared_management_without_staff(self):
        from .local_admin import local_admin_site
        from django.test import RequestFactory
        request = RequestFactory().get("/admin/")
        request.user = self.user
        self.assertFalse(self.user.is_staff)
        for model, manager in local_admin_site._registry.items():
            self.assertTrue(manager.has_view_permission(request))
            self.assertTrue(manager.has_add_permission(request))
            self.assertTrue(manager.has_change_permission(request))
            self.assertTrue(manager.has_delete_permission(request))
        for path in ["/admin/", "/admin/myapp/customuser/", "/admin/myapp/cmsblogpost/add/"]:
            self.assertEqual(self.client.get(path).status_code, 200, path)
        self.client.logout()
        self.assertEqual(self.client.get("/admin/").status_code, 302)

    def test_get_pages_and_footer(self):
        for name in [
            "dashboard",
            "file_scan",
            "phishing_scan",
            "password_strength",
            "mobile_security",
            "wifi_security",
            "mitre_mapping",
            "findings",
            "incidents",
            "scan_jobs",
            "reports",
            "scan_history",
            "scan_compare",
            "chatbot",
            "developer",
            "dns_analysis",
            "tls_analysis",
            "http_analysis",
            "html_analysis",
            "javascript_analysis",
        ]:
            r = self.client.get(reverse(name))
            self.assertEqual(r.status_code, 200, name)
            self.assertContains(r, 'aria-label="Footer"')

    @patch("myapp.analysis.investigation.rdap_scan", return_value={"module": "registration", "status": "unavailable", "data": {}, "findings": []})
    def test_failure_never_becomes_completed(self, registration):
        with (
            patch(
                "myapp.analysis.investigation.http_scan",
                return_value=[
                    {
                        "module": "http",
                        "status": "unavailable",
                        "data": {},
                        "findings": [],
                    }
                ],
            ),
            patch(
                "myapp.analysis.investigation.dns_scan",
                return_value={
                    "module": "dns",
                    "status": "unavailable",
                    "data": {},
                    "findings": [],
                },
            ),
            patch(
                "myapp.analysis.investigation.tls_scan",
                return_value={
                    "module": "tls",
                    "status": "unavailable",
                    "data": {},
                    "findings": [],
                },
            ),
        ):
            scan, _ = run_target_scan(self.user, "https://example.com")
            self.assertEqual(scan.status, "FAILED")
            self.assertEqual(scan.risk_level, "UNKNOWN")

    def test_chatbot_invalid_json_and_local_answer(self):
        self.assertEqual(
            self.client.post(
                reverse("chatbot_api"), data="[]", content_type="application/json"
            ).status_code,
            400,
        )
        r = self.client.post(
            reverse("chatbot_api"),
            data=json.dumps({"message": "What is WPA3?"}),
            content_type="application/json",
        )
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()["source"], "local_knowledge")

    def test_compare_uses_stored_records(self):
        a = self.scan()
        b = self.scan()
        r = self.client.get(
            reverse("scan_compare"), {"left": a.scan_id, "right": b.scan_id}
        )
        self.assertEqual(r.status_code, 200)
        self.assertContains(r, "risk_change")

    def test_wifi_unavailable_status_persists(self):
        self.client.force_login(self.staff)
        with patch(
            "myapp.wifi_audit_service.collect",
            return_value=("UNSUPPORTED OS", [], "Unavailable"),
        ):
            self.client.post(reverse("wifi_security"))
        self.assertContains(self.client.get(reverse("wifi_security")), "UNSUPPORTED OS")


class AnalysisSecurityTests(SimpleTestCase):
    def test_private_and_mixed_dns_blocked(self):
        for host in ["127.0.0.1", "::1", "169.254.169.254", "10.0.0.1", "localhost"]:
            with self.assertRaises(ValueError):
                safe_host(host)
        with patch(
            "socket.getaddrinfo",
            return_value=[
                (2, 1, 6, "", ("8.8.8.8", 0)),
                (2, 1, 6, "", ("127.0.0.1", 0)),
            ],
        ):
            with self.assertRaises(ValueError):
                safe_host("mixed.example")

    def test_credentials_and_ports_blocked(self):
        for url in [
            "http://user:secret@example.com/",
            "http://example.com:8080/",
            "file:///etc/passwd",
        ]:
            with self.assertRaises(ValueError):
                normalize_url(url)

    def test_socket_uses_validated_ip(self):
        from .scanners.transport import fetch

        connection = MagicMock()
        response = connection.getresponse.return_value
        response.status = 200
        response.getheaders.return_value = [("Content-Type", "text/html")]
        response.read1.side_effect = [b"<p>ok</p>", b""]
        with (
            patch("myapp.scanners.target.safe_host", return_value=["93.184.216.34"]),
            patch(
                "myapp.scanners.transport.http.client.HTTPConnection",
                return_value=connection,
            ),
            patch("myapp.scanners.transport.socket.create_connection") as connect,
        ):
            fetch("http://example.com/")
            self.assertEqual(connect.call_args.args[0], ("93.184.216.34", 80))

    def test_redirect_revalidated(self):
        from .scanners.transport import fetch

        conn = MagicMock()
        conn.getresponse.return_value.status = 302
        conn.getresponse.return_value.getheaders.return_value = [
            ("Location", "http://127.0.0.1/")
        ]
        with (
            patch(
                "myapp.scanners.target.safe_host",
                side_effect=[["8.8.8.8"], ValueError("Blocked")],
            ),
            patch(
                "myapp.scanners.transport.http.client.HTTPConnection", return_value=conn
            ),
            patch("myapp.scanners.transport.socket.create_connection") as connect,
        ):
            with self.assertRaises(ValueError):
                fetch("http://example.com/")
            self.assertEqual(connect.call_count, 1)

    def test_unavailable_http_has_no_header_findings(self):
        with patch("myapp.scanners.transport.fetch", side_effect=OSError()):
            rows = http_scan("https://example.com")
            self.assertFalse(rows[0]["findings"])
            self.assertEqual(next(x for x in rows if x["module"] == "http")["status"], "unavailable")

    def test_cookie_values_not_persisted(self):
        fixture = {
            "url": "https://example.com/",
            "status": 200,
            "headers": {"content-type": "text/html", "set-cookie": "session=SECRET"},
            "cookies": ["session=SECRET; Secure; HttpOnly; SameSite=Lax"],
            "body": b'<form><input type="password"></form>',
            "truncated": False,
            "redirects": [],
            "serving_ips": ["8.8.8.8"],
        }
        with patch("myapp.scanners.transport.fetch", return_value=fixture):
            self.assertNotIn("SECRET", json.dumps(http_scan("https://example.com/")))

    def test_static_html_javascript(self):
        observed = analyze_html(
            '<form action="http://other.example"><input type="password"></form><script>eval(atob("abc"))</script>'
        )
        self.assertEqual(observed["password_fields"], 1)
        self.assertTrue(observed["javascript_indicators"])
        self.assertEqual(javascript("const answer=42;"), [])

    def test_archive_is_not_extracted_and_hashes_correct(self):
        b = io.BytesIO()
        with zipfile.ZipFile(b, "w") as z:
            z.writestr("../escape.txt", "fixture")
        raw = b.getvalue()
        rows = analyze_uploaded(SimpleUploadedFile("sample.zip", raw))
        h = next(x["data"] for x in rows if x["module"] == "hashes")
        self.assertEqual(h["sha256"], __import__("hashlib").sha256(raw).hexdigest())
        archive = next(x for x in rows if x["module"] == "archive")
        self.assertIn("../escape.txt", archive["data"]["suspicious_members"])

    def test_upload_limit_and_active_image_rejected(self):
        with override_settings(MAX_UPLOAD_SIZE=4):
            with self.assertRaises(ValueError):
                analyze_uploaded(SimpleUploadedFile("x.bin", b"12345"))
        with self.assertRaises(ValueError):
            clean_image(SimpleUploadedFile("x.svg", b'<svg onload="alert(1)"></svg>'))

    def test_mitre_dataset_ids_and_parent(self):
        from .mitre_data import dataset

        rows = {x["id"]: x for x in dataset()["techniques"]}
        self.assertEqual(rows["T1059.001"]["name"], "PowerShell")
        self.assertIn("execution", rows["T1059.001"]["tactics"])
        self.assertIn(rows["T1059.001"]["parent"], rows)

    def test_password_source_privacy(self):
        source = (
            settings.BASE_DIR / "myapp/static/myapp/password-analyzer.js"
        ).read_text(encoding="utf-8")
        for forbidden in [
            "localStorage",
            "sessionStorage",
            "sendBeacon",
            "XMLHttpRequest",
            "console.log",
        ]:
            self.assertNotIn(forbidden, source)
        self.assertIn("crypto.getRandomValues", source)
        self.assertIn("hash.slice(0,5)", source)
        self.assertIn("breachOptIn", source)
        html = (settings.BASE_DIR / "templates/myapp/mobile_security.html").read_text(
            encoding="utf-8"
        )
        self.assertNotIn('name="password', html)


class NetworkCapabilityTests(SimpleTestCase):
    def test_dns_observations_and_timeout(self):
        from .scanners.target import dns_scan
        import dns.exception

        resolver = MagicMock()
        resolver.resolve.return_value = ["203.0.113.1"]
        with patch("dns.resolver.Resolver", return_value=resolver):
            result = dns_scan("example.test")
            self.assertEqual(result["data"]["MX"]["state"], "Observed")
            self.assertEqual(len(result["data"]), 7)
        resolver.resolve.side_effect = dns.exception.Timeout()
        with patch("dns.resolver.Resolver", return_value=resolver):
            result = dns_scan("example.test")
            self.assertEqual(result["status"], "unavailable")
            self.assertEqual(result["findings"], [])

    def test_tls_transport_failure_not_invalid_certificate(self):
        from .scanners.target import tls_scan

        with (
            patch("myapp.scanners.target.safe_host", return_value=["8.8.8.8"]),
            patch(
                "myapp.scanners.target.socket.create_connection",
                side_effect=TimeoutError(),
            ),
        ):
            result = tls_scan("example.test")
            self.assertEqual(result["status"], "error")
            self.assertNotIn("invalid", str(result).lower())

    def test_wifi_unknown_encryption_not_inferred(self):
        from .scanners.wifi import classify

        self.assertEqual(classify("WPA2-Personal", "")["risk_level"], "UNKNOWN")


class JobLifecycleTests(TestCase):
    def test_cancel_and_no_reexecution(self):
        from .models import ScanJob
        from .security_pipeline import execute_job

        user = get_user_model().objects.create_user(
            "cancel-test", password="Test-Password-738!"
        )
        job = ScanJob.objects.create(
            scan_id="cancel-fixture", requested_by=user, status="QUEUED"
        )
        self.client.force_login(user)
        self.assertEqual(
            self.client.post(reverse("cancel_job", args=[job.pk])).status_code, 302
        )
        with patch("myapp.security_pipeline.ScannerRegistry") as registry:
            execute_job(job.pk)
            registry.assert_not_called()
        job.refresh_from_db()
        self.assertEqual(job.status, "CANCELLED")
