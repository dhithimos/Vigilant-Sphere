"""Regression tests for the ten requested workflows; all evidence below is fixture data."""

import base64
import json
import re
import uuid
import zlib
from unittest.mock import patch
from django.contrib.auth import get_user_model
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import TestCase, SimpleTestCase, override_settings
from django.urls import reverse
from .models import Incident, ScanJob, FeatureFlag
from .analysis.investigation import run_target_scan
from .scanners.target import rdap_scan, http_scan
from .scanners.wifi import classify
from .presentation import display, display_text


@override_settings(VT_API_KEY="", ABUSEIPDB_API_KEY="", OTX_API_KEY="", HIBP_API_KEY="")
class RequestedWorkflowTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.user = get_user_model().objects.create_user(
            "fix-user", password="Long-fixture-pass-128!"
        )
        cls.other = get_user_model().objects.create_user(
            "fix-other", password="Long-fixture-pass-129!"
        )

    def setUp(self):
        self.client.force_login(self.user)

    def job(self, user=None):
        return ScanJob.objects.create(
            scan_id=str(uuid.uuid4()), requested_by=user or self.user
        )

    def scan(self):
        return run_target_scan(
            self.user,
            uploaded=SimpleUploadedFile(
                "fixture.ps1", b"powershell.exe -EncodedCommand QUJDREVGR0g="
            ),
        )[0]

    def incident_data(self):
        return {
            "title": "Fixture review",
            "description": "Review recorded evidence",
            "severity": "LOW",
            "status": "OPEN",
        }

    def test_incident_accepts_owned_job_without_findings(self):
        job = self.job()
        data = self.incident_data() | {"scan_jobs": [job.pk]}
        self.assertEqual(
            self.client.post(reverse("incident_new"), data).status_code, 302
        )
        incident = Incident.objects.get(owner=self.user)
        self.assertTrue(incident.incident_id.startswith("VS-"))
        self.assertEqual(list(incident.scan_jobs.all()), [job])
        self.assertEqual(
            self.client.post(
                reverse("incident_detail", args=[incident.pk]), {}
            ).status_code,
            400,
        )
        self.client.post(
            reverse("incident_detail", args=[incident.pk]), {"action": "archive"}
        )
        incident.refresh_from_db()
        self.assertTrue(incident.archived)
        self.assertEqual(incident.notes[-1]["event"], "Archived incident")
        self.assertNotContains(self.client.get(reverse("incidents")), "Fixture review")

    def test_incident_rejects_empty_evidence_and_foreign_job(self):
        for data in [
            self.incident_data(),
            self.incident_data() | {"scan_jobs": [self.job(self.other).pk]},
        ]:
            self.assertEqual(
                self.client.post(reverse("incident_new"), data).status_code, 200
            )
        self.assertFalse(Incident.objects.filter(owner=self.user).exists())

    def test_finding_escalation_and_filters(self):
        scan = self.scan()
        finding = scan.job.findings.get()
        self.assertEqual(finding.mitre_technique, "T1059.001")
        response = self.client.get(reverse("incident_new"), {"finding": finding.pk})
        self.assertContains(response, "Potential encoded PowerShell command")
        self.assertContains(
            self.client.get(
                reverse("findings"), {"scanner": "files", "severity": "medium"}
            ),
            finding.title,
        )
        self.assertEqual(
            self.client.get(reverse("findings"), {"scanner": "invalid"}).status_code,
            400,
        )
        self.client.force_login(self.other)
        self.assertEqual(
            self.client.get(
                reverse("incident_new"), {"finding": finding.pk}
            ).status_code,
            404,
        )

    def test_job_visible_during_collection_and_failure_retained(self):
        def fail(upload):
            self.assertTrue(
                ScanJob.objects.filter(
                    requested_by=self.user, status="RUNNING", completed_at=None
                ).exists()
            )
            raise ValueError("fixture failure")

        with patch("myapp.analysis.investigation.analyze_uploaded", side_effect=fail):
            with self.assertRaises(ValueError):
                self.scan()
        job = ScanJob.objects.get(requested_by=self.user)
        self.assertEqual(job.status, "FAILED")
        self.assertIsNotNone(job.completed_at)

    def test_job_cancellation_owner_and_post_only(self):
        job = self.job()
        route = reverse("cancel_job", args=[job.pk])
        self.assertEqual(self.client.get(route).status_code, 405)
        self.client.force_login(self.other)
        self.assertEqual(self.client.post(route).status_code, 404)
        self.client.force_login(self.user)
        self.assertEqual(self.client.post(route).status_code, 302)
        self.assertEqual(self.client.post(route).status_code, 409)

    def test_pipeline_partial_state_and_success_counter(self):
        from .security_pipeline import BaseScanner, execute_job

        class GoodScanner(BaseScanner):
            scanner_id = "fixture-good"

        class FailedScanner(BaseScanner):
            scanner_id = "fixture-failed"

            def scan(self, context):
                raise OSError("Fixture unavailable")

        job = self.job()
        with patch(
            "myapp.security_pipeline.ScannerRegistry.for_profile",
            return_value=[GoodScanner(), FailedScanner()],
        ):
            execute_job(job.pk)
        job.refresh_from_db()
        self.assertEqual(job.status, "PARTIAL")
        self.assertEqual(job.completed_scanner_count, 1)
        self.assertEqual(job.failed_scanner_count, 1)
        self.assertIsNotNone(job.completed_at)

    def test_wifi_default_flag_and_partial_collection(self):
        from .views import ensure_default_feature_flags
        from .wifi_records import persist_audit

        ensure_default_feature_flags()
        self.assertTrue(FeatureFlag.objects.get(key="WIFI_SECURITY_AUDIT").enabled)
        row = dict(
            profile_name="Fixture unavailable profile",
            authentication="",
            encryption="",
            collection_status="COLLECTION ERROR",
            **classify("", ""),
        )
        job = persist_audit(self.user, "AVAILABLE", [row], "Fixture")
        self.assertEqual(job.status, "PARTIAL")
        self.assertEqual(job.findings.get().severity, "INFO")

    def test_feature_flags_enforced_on_api_and_wifi(self):
        for key, route in [
            ("WIFI_SECURITY_AUDIT", "wifi_security"),
            ("OFFLINE_SECURITY_CHATBOT", "chatbot_api"),
        ]:
            FeatureFlag.objects.update_or_create(key=key, defaults={"enabled": False})
            self.assertEqual(
                self.client.post(
                    reverse(route),
                    data=json.dumps({"message": "hello"}),
                    content_type="application/json",
                ).status_code,
                503,
            )

    def test_wifi_profiles_and_unavailable_jobs(self):
        row = dict(
            profile_name="Fixture wireless",
            authentication="WPA2-Personal",
            encryption="CCMP",
            collection_status="AVAILABLE",
            **classify("WPA2-Personal", "CCMP"),
        )
        with patch(
            "myapp.wifi_audit_service.collect", return_value=("AVAILABLE", [row], "Fixture")
        ):
            self.client.post(reverse("wifi_security"))
        job = ScanJob.objects.get(requested_by=self.user, scan_type="wifi")
        self.assertEqual(job.status, "COMPLETED")
        self.assertEqual(job.findings.count(), 1)
        with patch(
            "myapp.wifi_audit_service.collect",
            return_value=("UNSUPPORTED OS", [], "Not available on this platform"),
        ):
            self.client.post(reverse("wifi_security"))
        latest = ScanJob.objects.order_by("-pk").first()
        self.assertEqual(latest.status, "UNAVAILABLE")
        self.assertEqual(latest.findings.count(), 0)

    def test_mitre_detail_has_evidence_without_cross_account_leak(self):
        scan = self.scan()
        response = self.client.get(reverse("technique_detail", args=["T1059.001"]))
        self.assertContains(response, "Platforms")
        self.assertContains(response, "Potential encoded PowerShell command")
        self.client.force_login(self.other)
        response = self.client.get(reverse("technique_detail", args=["T1059.001"]))
        self.assertNotContains(response, scan.job.findings.get().title)
        self.assertContains(response, "No Evidence")

    def test_display_scrubs_exports_but_keeps_database(self):
        scan = self.scan()
        vendors = (
            "VirusTotal AbuseIPDB AlienVault OTX HIBP Have I Been Pwned YARA ClamAV"
        )
        scan.provider_results = [
            {
                "provider": "VirusTotal",
                "status": "unavailable",
                "data": {"provider_attribution": vendors},
                "errors": [vendors],
            }
        ]
        scan.findings[0]["description"] = vendors
        scan.save()
        for name in [
            "target_scan_detail",
            "target_scan_json",
            "target_scan_csv",
            "target_scan_pdf",
        ]:
            response = self.client.get(reverse(name, args=[scan.scan_id]))
            self.assertEqual(response.status_code, 200, name)
            payload = response.content
            if name.endswith("pdf"):
                streams = re.findall(rb"stream\r?\n(.*?)endstream", payload, re.S)
                payload = b" ".join(
                    zlib.decompress(base64.a85decode(x.strip(), adobe=True))
                    for x in streams
                )
            text = payload.decode("utf-8", errors="replace")
            for name in [
                "virustotal",
                "abuseipdb",
                "alienvault",
                "hibp",
                "have i been pwned",
                "yara",
                "clamav",
            ]:
                self.assertNotIn(name, text.lower())
        scan.refresh_from_db()
        self.assertEqual(scan.provider_results[0]["provider"], "VirusTotal")

    def test_footer_image_removed_developer_page_retained(self):
        response = self.client.get(reverse("developer"))
        html = response.content.decode()
        footer = re.search(r"<footer\b[^>]*>(.*?)</footer>", html, re.S).group(1)
        self.assertNotIn("<img", footer)
        self.assertContains(response, "Dhithimos")
        self.assertIn("<img", html)

    def test_profile_pages_preserve_lazy_user_fields(self):
        for path in ["/profile/", "/edit-profile/"]:
            self.assertEqual(self.client.get(path).status_code, 200)

    def test_local_chat_rich_answer_and_no_data(self):
        from .chatbot.engine import answer

        result = answer(
            "How should I investigate a suspicious attachment and a fake login link?",
            self.user,
        )
        self.assertGreater(len(result["response"].split()), 180)
        self.assertIn("### Example", result["response"])
        self.assertFalse(result["live_data"])
        self.assertIn(
            "NO DATA", answer("What did my latest scan find?", self.user)["response"]
        )


class RequestedAnalysisTests(SimpleTestCase):
    def test_registration_date_derived_only_from_events(self):
        document = {
            "events": [
                {"eventAction": "registration", "eventDate": "2020-01-01T00:00:00Z"}
            ]
        }
        with patch(
            "myapp.scanners.transport.fetch",
            return_value={
                "status": 200,
                "truncated": False,
                "body": json.dumps(document).encode(),
            },
        ):
            result = rdap_scan("example.test")
        self.assertEqual(result["data"]["registration_date"], "2020-01-01T00:00:00Z")
        self.assertGreater(result["data"]["age_days"], 0)
        with patch("myapp.scanners.transport.fetch", side_effect=OSError):
            self.assertEqual(rdap_scan("example.test")["status"], "unavailable")

    def test_blocked_page_retains_lexical_evidence_without_header_claim(self):
        with patch("myapp.scanners.transport.fetch", side_effect=ValueError("Blocked")):
            rows = http_scan("http://127.0.0.1/login")
        self.assertEqual(rows[-1]["status"], "blocked")
        self.assertTrue(rows[0]["findings"])
        self.assertFalse(any(row["module"] == "headers" for row in rows))

    def test_display_preserves_numbers_and_opaque_tokens(self):
        original = {"provider": "VirusTotal", "detections": 3, "status": "Rate Limited"}
        result = display(original)
        self.assertEqual(result["provider"], "Reputation Check")
        self.assertEqual(result["detections"], 3)
        self.assertEqual(original["provider"], "VirusTotal")
        self.assertEqual(display_text("abcOTX123"), "abcOTX123")
