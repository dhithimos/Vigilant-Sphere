from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings
from .alerts import send_critical_alert
from .models import (
    AlertEmailConfiguration,
    AssetInventory,
    Finding,
    ScanJob,
    SecurityAlert,
)


class CriticalAlertTests(TestCase):
    def setUp(self):
        user = get_user_model().objects.create_user(
            "alert-user", "alert@example.test", "Test-password-123"
        )
        asset = AssetInventory.objects.create(
            hostname="alert-host", operating_system="test"
        )
        job = ScanJob.objects.create(
            scan_id="20000000-0000-0000-0000-000000000001",
            requested_by=user,
            asset=asset,
        )
        finding = Finding.objects.create(
            finding_id="critical-alert",
            fingerprint="b" * 64,
            job=job,
            asset=asset,
            scanner="test",
            finding_type="test",
            title="<unsafe>",
            description="test",
            severity="CRITICAL",
            confidence=0.9,
            risk_score=95,
            evidence={"password": "do-not-send"},
            recommendation="Investigate",
        )
        self.alert = SecurityAlert.objects.create(finding=finding)

    def test_not_configured_is_recorded_without_send(self):
        delivery = send_critical_alert(self.alert)
        self.assertEqual(delivery.status, "NOT_CONFIGURED")

    @override_settings(EMAIL_BACKEND="django.core.mail.backends.locmem.EmailBackend")
    def test_delivery_is_sent_once_when_configured(self):
        AlertEmailConfiguration.objects.create(
            enabled=True,
            host="smtp.test",
            port=25,
            use_tls=False,
            from_email="alerts@example.test",
            recipients="soc@example.test",
        )
        first = send_critical_alert(self.alert)
        second = send_critical_alert(self.alert)
        self.assertEqual(first.status, "SENT")
        self.assertEqual(second.delivery_attempts, 1)
