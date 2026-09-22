from django.contrib.auth import get_user_model
from django.test import TestCase
from .chatbot.intents import CONCEPTS
from .chatbot.engine import answer
from .models import AssetInventory, Finding, ScanJob
from .scanners.wifi import classify, parse_profile_security, parse_profiles


class WiFiClassifierTests(TestCase):
    def test_baseline_classifications(self):
        self.assertEqual(classify("WEP", "WEP")["risk_level"], "CRITICAL")
        self.assertEqual(classify("WPA-Personal", "TKIP")["risk_level"], "HIGH")
        self.assertEqual(classify("WPA2-Personal", "TKIP")["risk_level"], "MEDIUM")
        self.assertEqual(classify("WPA2-Personal", "CCMP")["risk_level"], "LOW")
        self.assertEqual(classify("WPA3-Personal", "CCMP")["risk_level"], "LOW")
        self.assertEqual(classify("Open", "None")["risk_level"], "HIGH")
        self.assertEqual(classify("", "")["risk_level"], "UNKNOWN")

    def test_parser_never_extracts_key_content(self):
        self.assertEqual(
            parse_profiles("    All User Profile     : HomeWiFi\n"), ["HomeWiFi"]
        )
        auth, enc = parse_profile_security(
            "Authentication : WPA2-Personal\nEncryption : CCMP\nKey Content : secret\n"
        )
        self.assertEqual((auth, enc), ("WPA2-Personal", "CCMP"))
        self.assertNotIn("secret", auth + enc)


class ChatbotTests(TestCase):
    def setUp(self):
        self.user = get_user_model().objects.create_user(
            "bot-user", "bot@example.test", "Test-password-123"
        )

    def test_more_than_fifty_offline_intents(self):
        self.assertGreaterEqual(len(CONCEPTS), 50)

    def test_unknown_is_safe(self):
        self.assertEqual(
            answer("execute powershell now", self.user)["intent"], "unknown"
        )

    def test_live_critical_count_is_user_scoped(self):
        asset = AssetInventory.objects.create(
            hostname="bot-host", operating_system="test"
        )
        job = ScanJob.objects.create(
            scan_id="10000000-0000-0000-0000-000000000001",
            requested_by=self.user,
            asset=asset,
            status="COMPLETED",
        )
        Finding.objects.create(
            finding_id="bot-finding",
            fingerprint="a" * 64,
            job=job,
            asset=asset,
            scanner="test",
            finding_type="test",
            title="Actual critical",
            description="Actual",
            severity="CRITICAL",
            confidence=0.9,
            risk_score=90,
        )
        self.assertIn(
            "1 CRITICAL", answer("how many critical findings", self.user)["response"]
        )

    def test_wifi_no_data(self):
        self.assertIn(
            "NO DATA", answer("what did wifi audit find", self.user)["response"]
        )
