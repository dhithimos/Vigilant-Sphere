import io
import uuid
from unittest.mock import patch
from subprocess import CompletedProcess
from django.contrib.auth import get_user_model
from django.core.management import call_command
from django.test import TestCase, SimpleTestCase, override_settings
from django.urls import reverse
from .models import (
    Finding,
    ScanJob,
    TrustedWifiProfile,
    WiFiAudit,
    IndicatorOfCompromise,
    AlertEmailConfiguration,
    SecurityAlert,
    FeatureFlag,
)
from .scanners.wifi import (
    classify,
    collect_windows,
    collect_linux,
    collect_macos,
    collect_current_connection,
)
from .wifi_audit_service import persist_audit
from .analysis.ioc_correlation import upsert_indicator, correlation_payload


class PassiveParserTests(SimpleTestCase):
    def test_open_wep_and_score_sum(self):
        row = classify("Open", "WEP", True)
        self.assertEqual(row["security_level"], "WEP")
        self.assertEqual(row["risk_score"], 100)
        self.assertEqual(sum(x["points"] for x in row["score_breakdown"]), 100)

    @patch("myapp.scanners.wifi._run")
    def test_windows_cipher_and_no_secret_arguments(self, run):
        run.side_effect = [
            CompletedProcess([], 0, "All User Profile : Fixture\n", ""),
            CompletedProcess(
                [],
                0,
                'Authentication : WPA2-Personal\nCipher : CCMP\nConnection mode : Connect automatically\nSSID name : "Fixture"',
                "",
            ),
        ]
        state, rows, _ = collect_windows()
        self.assertEqual(state, "AVAILABLE")
        self.assertEqual(rows[0]["security_level"], "WPA2")
        self.assertNotIn("key=clear", str(run.call_args_list))

    @patch("myapp.scanners.wifi._run")
    def test_linux_saved_metadata(self, run):
        run.side_effect = [
            CompletedProcess(
                [],
                0,
                "11111111-1111-1111-1111-111111111111:Office\\:west:802-11-wireless",
                "",
            ),
            CompletedProcess([], 0, "wpa-psk\nrsn\nccmp\nyes\nOffice", ""),
        ]
        state, rows, _ = collect_linux()
        self.assertEqual(state, "AVAILABLE")
        self.assertEqual(rows[0]["profile_name"], "Office:west")
        self.assertEqual(rows[0]["security_level"], "WPA2")
        self.assertNotIn("--show-secrets", str(run.call_args_list))

    @patch("myapp.scanners.wifi._run")
    def test_macos_missing_security_is_unknown(self, run):
        run.side_effect = [
            CompletedProcess([], 0, "Hardware Port: Wi-Fi\nDevice: en0\n", ""),
            CompletedProcess([], 0, "Preferred networks on en0:\n    Fixture\n", ""),
        ]
        state, rows, _ = collect_macos()
        self.assertEqual(rows[0]["risk_level"], "UNKNOWN")

    @patch("myapp.scanners.wifi.platform.system", return_value="Windows")
    @patch("myapp.scanners.wifi._run")
    def test_gateway_query_is_wifi_scoped(self, run, system):
        run.side_effect = [
            CompletedProcess(
                [], 0, "Name : Wi-Fi\nState : connected\nSSID : Fixture\n", ""
            ),
            CompletedProcess([], 0, "Default Gateway : 192.168.1.1", ""),
        ]
        result = collect_current_connection()
        self.assertEqual(result["gateway"], "192.168.1.1")
        self.assertIn("name=Wi-Fi", run.call_args.args[0])


class ConsolidatedWorkflowTests(TestCase):
    def setUp(self):
        self.user = get_user_model().objects.create_user(
            "ordinary", password="Fixture-password-193!"
        )
        self.other = get_user_model().objects.create_user(
            "other", password="Fixture-password-193!"
        )
        self.client.force_login(self.user)

    def finding(self, severity="HIGH"):
        job = ScanJob.objects.create(scan_id=str(uuid.uuid4()), requested_by=self.user)
        return Finding.objects.create(
            job=job,
            finding_id=uuid.uuid4().hex,
            fingerprint=uuid.uuid4().hex,
            title="Fixture evidence",
            severity=severity,
            confidence=0.9,
            evidence={"observed": True},
        )

    def row(self, auth="WPA2", enc="CCMP"):
        return dict(
            profile_name="Fixture",
            authentication=auth,
            encryption=enc,
            collection_status="AVAILABLE",
            **classify(auth, enc),
        )

    def test_wifi_history_trust_and_degradation(self):
        job = persist_audit(self.user, "AVAILABLE", [self.row()], "Fixture")
        audit = WiFiAudit.objects.get(user=self.user)
        self.assertEqual(self.client.get(reverse("wifi_security")).status_code, 200)
        self.assertEqual(
            self.client.post(reverse("trust_wifi", args=[audit.pk])).status_code, 302
        )
        self.assertTrue(TrustedWifiProfile.objects.filter(user=self.user).exists())
        same = persist_audit(self.user, "AVAILABLE", [self.row()], "Fixture")
        self.assertEqual(same.findings.count(), 0)
        worse = persist_audit(
            self.user, "AVAILABLE", [self.row("WEP", "WEP")], "Fixture"
        )
        self.assertEqual(worse.findings.count(), 1)
        self.assertContains(self.client.get(reverse("wifi_security")), "DEGRADED")
        self.client.force_login(self.other)
        self.assertEqual(
            self.client.post(reverse("trust_wifi", args=[audit.pk])).status_code, 404
        )

    def test_launcher_flag_and_access(self):
        self.assertContains(self.client.get(reverse("dashboard")), "assistant-launcher")
        FeatureFlag.objects.update_or_create(
            key="OFFLINE_SECURITY_CHATBOT", defaults={"enabled": False}
        )
        self.assertNotContains(
            self.client.get(reverse("dashboard")), "assistant-launcher"
        )
        self.assertEqual(self.client.get(reverse("developer")).status_code, 200)

    def test_ioc_retirement_and_check_status(self):
        row = dict(ioc_type="HASH", value="a" * 64, source="fixture", confidence=80)
        obj, created = upsert_indicator(row)
        self.assertTrue(created)
        result = correlation_payload({"sha256": "a" * 64}, self.user)
        self.assertEqual(result["status"], "MATCHED")
        obj.is_active = False
        obj.save()
        upsert_indicator(row)
        obj.refresh_from_db()
        self.assertFalse(obj.is_active)
        self.assertEqual(
            correlation_payload({"sha256": "a" * 64}, self.user)["status"],
            "NOT_OBSERVED",
        )

    def test_management_commands_dry_run(self):
        output = io.StringIO()
        for command in ["sync_local_iocs", "expire_stale_iocs", "send_alert_digest"]:
            call_command(command, dry_run=True, stdout=output)
        self.assertEqual(IndicatorOfCompromise.objects.count(), 0)

    def test_mitre_exports_are_scoped(self):
        finding = self.finding()
        finding.mitre_technique = "T1059.001"
        finding.save()
        response = self.client.get("/mitre/technique/T1059.001/?format=json")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["techniques"][0]["finding_count"], 1)
        self.client.force_login(self.other)
        self.assertEqual(
            self.client.get("/mitre/technique/T1059.001/?format=json").json()[
                "techniques"
            ][0]["finding_count"],
            0,
        )

    @override_settings(EMAIL_BACKEND="django.core.mail.backends.locmem.EmailBackend")
    def test_threshold_dedup_and_digest(self):
        from .alerts import get_or_create_deduped_alert, send_digest

        config = AlertEmailConfiguration.objects.create(
            pk=1,
            enabled=True,
            host="fixture",
            from_email="a@example.test",
            recipients="b@example.test",
            use_tls=False,
            digest_enabled=True,
        )
        self.assertIsNone(get_or_create_deduped_alert(self.finding("HIGH"), "fixture"))
        config.alert_severity_threshold = "HIGH"
        config.save()
        first = get_or_create_deduped_alert(self.finding("HIGH"), "fixture")
        second = get_or_create_deduped_alert(self.finding("HIGH"), "fixture")
        self.assertEqual(first.pk, second.pk)
        critical = get_or_create_deduped_alert(self.finding("CRITICAL"), "fixture")
        self.assertNotEqual(critical.pk, first.pk)
        self.assertIn("Would summarize", send_digest(dry_run=True))
        config.refresh_from_db()
        self.assertIsNone(config.last_digest_sent_at)
        self.assertIn("Digest sent", send_digest())
        self.assertEqual(send_digest(), "Digest not due")

    def test_normalize_ioc_is_idempotent_for_job(self):
        from .security_pipeline import normalize, ScannerRegistry

        obj, _ = upsert_indicator(
            dict(ioc_type="HASH", value="b" * 64, source="fixture", confidence=70)
        )
        job = self.finding().job
        raw = {
            "type": "fixture",
            "title": "IOC fixture",
            "evidence": {"sha256": "b" * 64},
        }
        first = normalize(ScannerRegistry().scanners["wifi"], raw, job)
        second = normalize(ScannerRegistry().scanners["wifi"], raw, job)
        self.assertEqual(first["ioc"]["status"], "MATCHED")
        self.assertEqual(first["ioc"], second["ioc"])
        obj.refresh_from_db()
        self.assertEqual(obj.matches_found, 1)

    def test_provider_evidence_and_disabled_guards(self):
        from .analysis.ioc_correlation import persist_provider_results

        for state in ["not_configured", "unavailable", "rate_limited", "error"]:
            persist_provider_results(
                [
                    {
                        "status": state,
                        "provider": "Fixture",
                        "data": {"detections": {"malicious": 8}},
                    }
                ],
                "c" * 64,
                "hash",
            )
        self.assertEqual(IndicatorOfCompromise.objects.count(), 0)
        response = [
            {
                "status": "success",
                "provider": "Fixture",
                "data": {"detections": {"malicious": 8, "undetected": 2}},
            }
        ]
        persist_provider_results(response, "c" * 64, "hash")
        self.assertEqual(IndicatorOfCompromise.objects.get().confidence, 80)
        persist_provider_results(response, "127.0.0.1", "ip")
        persist_provider_results(response, "private@example.test", "email")
        self.assertEqual(IndicatorOfCompromise.objects.count(), 1)

    def test_import_export_roundtrip_and_strict_validation(self):
        import json, tempfile
        from pathlib import Path
        from django.core.management.base import CommandError

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "set.json"
            upsert_indicator(
                dict(
                    ioc_type="DOMAIN",
                    value="example.test",
                    source="fixture",
                    confidence=55,
                )
            )
            call_command("export_iocs", str(path), stdout=io.StringIO())
            exported = json.loads(path.read_text())
            call_command("import_iocs", str(path), strict=True, stdout=io.StringIO())
            self.assertEqual(IndicatorOfCompromise.objects.count(), 1)
            self.assertEqual(exported[0]["confidence"], 55)
            path.write_text(
                json.dumps([{"ioc_type": "INVALID", "value": "x", "source": ""}])
            )
            with self.assertRaises(CommandError):
                call_command(
                    "import_iocs",
                    str(path),
                    strict=True,
                    stdout=io.StringIO(),
                    stderr=io.StringIO(),
                )

    def test_duplicate_and_bssid_findings_are_observations(self):
        initial = dict(self.row(), ssid="Fixture")
        persist_audit(
            self.user,
            "AVAILABLE",
            [initial],
            "Fixture",
            current={"ssid": "Fixture", "bssid": "00:11:22:33:44:55"},
        )
        second = dict(
            self.row("WEP", "WEP"), profile_name="Fixture alternate", ssid="Fixture"
        )
        job = persist_audit(
            self.user,
            "AVAILABLE",
            [dict(self.row(), ssid="Fixture"), second],
            "Fixture",
            current={"ssid": "Fixture", "bssid": "00:11:22:33:44:66"},
        )
        self.assertEqual(
            job.findings.filter(finding_type="wifi_bssid_changed").count(), 1
        )
        self.assertEqual(
            job.findings.filter(finding_type="wifi_duplicate_ssid").count(), 1
        )
        self.assertFalse(job.findings.exclude(mitre_technique="").exists())

    def test_launcher_three_pages_and_anonymous(self):
        for name in ["dashboard", "developer", "wifi_security"]:
            self.assertContains(self.client.get(reverse(name)), "assistant-launcher")
        self.assertNotContains(
            self.client.get(reverse("chatbot")), "assistant-launcher"
        )
        self.client.logout()
        self.assertNotContains(
            self.client.get(reverse("developer")), "assistant-launcher"
        )
