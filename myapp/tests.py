from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse

from .models import DeveloperImage
from .models import AssetInventory, Finding, ScanJob
from .security_pipeline import SCANNER_CATALOG, ScannerRegistry, normalize, redact


class NavigationAndDeveloperTests(TestCase):
    def setUp(self):
        self.user = get_user_model().objects.create_user(
            "analyst", "analyst@example.test", "A-strong-password-123"
        )

    def test_authenticated_security_pages_resolve(self):
        self.client.force_login(self.user)
        for name in (
            "dashboard",
            "combined_scan",
            "threat_intelligence",
            "mitre_mapping",
            "mobile_security",
        ):
            response = self.client.get(reverse(name))
            self.assertEqual(response.status_code, 200, name)

    def test_developer_images_and_signed_in_management(self):
        self.assertEqual(self.client.get(reverse("developer")).status_code, 200)
        self.client.force_login(self.user)
        response = self.client.get("/admin/myapp/developerimage/")
        self.assertEqual(response.status_code, 200)
        # Migration 0007 intentionally seeds the supplied developer image.
        self.assertEqual(DeveloperImage.objects.count(), 1)


class SecurityPipelineTests(TestCase):
    def setUp(self):
        self.user = get_user_model().objects.create_user(
            "operator", "operator@example.test", "A-strong-password-123"
        )
        self.asset = AssetInventory.objects.create(
            hostname="test-host", operating_system="TestOS"
        )
        self.job = ScanJob.objects.create(
            scan_id="00000000-0000-0000-0000-000000000001",
            requested_by=self.user,
            asset=self.asset,
        )

    def test_catalog_has_all_34_declared_modules(self):
        self.assertEqual(len(SCANNER_CATALOG), 34)
        self.assertIn("mitre_correlation_risk", SCANNER_CATALOG)

    def test_normalizer_keeps_confidence_separate_and_maps_supported_mitre(self):
        scanner = ScannerRegistry().scanners["processes"]
        row = normalize(
            scanner,
            {
                "type": "encoded_powershell",
                "title": "Encoded PowerShell",
                "severity": "HIGH",
                "confidence": 0.72,
                "evidence": {"command": "powershell -enc ..."},
            },
            self.job,
        )
        finding = Finding.objects.create(job=self.job, asset=self.asset, **row)
        self.assertEqual(finding.severity, "HIGH")
        self.assertEqual(finding.confidence, 0.72)
        self.assertEqual(finding.mitre_technique, "T1059.001")
        self.assertLessEqual(finding.risk_score, 100)

    def test_redaction_does_not_preserve_token_values(self):
        self.assertNotIn(
            "very-secret-token-value",
            str(redact({"secret": "very-secret-token-value"})),
        )
