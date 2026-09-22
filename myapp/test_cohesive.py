"""Regression coverage for distinct scanners and authorized response workflows."""

import hashlib
import json
import struct
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import Client, TestCase
from django.urls import reverse, NoReverseMatch

from .analysis import domain_scanners as scanners
from .forms import ContactForm, SuggestionForm
from .incident_response import validate_artifact
from .models import Incident, IncidentArtifact, ContactMessage
from .scanners.binary_metadata import binary_metadata
from .scanners.wifi_report import executive_report


class CohesiveTests(TestCase):
    def test_pe_and_elf_header_evidence(self):
        pe = bytearray(128)
        pe[:2] = b'MZ'
        struct.pack_into('<I', pe, 60, 64)
        pe[64:68] = b'PE\0\0'
        struct.pack_into('<HHIIIHH', pe, 68, 0x8664, 0, 0, 0, 0, 40, 2)
        struct.pack_into('<H', pe, 88, 0x20B)
        struct.pack_into('<I', pe, 104, 4096)
        pe_result, _ = binary_metadata(bytes(pe))
        self.assertEqual(pe_result['state'], 'Observed')
        self.assertEqual(pe_result['architecture'], 'x86-64')
        self.assertEqual(pe_result['entry_point_rva'], 4096)
        elf = b'\x7fELF\x02\x01\x01' + bytes(9)
        elf += struct.pack('<HHIQQQIHHHHHH', 2, 62, 1, 4096, 0, 0, 0, 64, 56, 0, 64, 0, 0)
        _, elf_result = binary_metadata(elf)
        self.assertEqual(elf_result['state'], 'Observed')

    def test_file_workflow_persists_and_renders_contract(self):
        from .models import TargetScan

        response = self.client.post(reverse('file_scan'), {'sample': SimpleUploadedFile('fixture.txt', b'ordinary fixture content')})
        self.assertEqual(response.status_code, 302)
        record = TargetScan.objects.get(user=self.owner)
        self.assertEqual(record.results[0]['data']['scanner'], 'static_file_analysis')
        self.assertEqual(record.job.status, 'COMPLETED')
        self.assertContains(self.client.get(response.url), hashlib.sha256(b'ordinary fixture content').hexdigest())
        for format_name in ['json', 'csv', 'pdf']:
            self.assertEqual(self.client.get(f'/investigations/{record.scan_id}/{format_name}/').status_code, 200)

    def setUp(self):
        self.owner = get_user_model().objects.create_user(username="owner")
        self.responder = get_user_model().objects.create_user(username="responder")
        self.outsider = get_user_model().objects.create_user(username="outsider")
        self.client.force_login(self.owner)

    def test_empty_scanners_have_distinct_contracts(self):
        behavior = scanners.threat_detection([])
        aggregate = scanners.security_intelligence(self.owner)
        correlation = scanners.ioc_correlation("example.test", self.owner)
        wifi = executive_report("UNAVAILABLE", [], {"status": "Unavailable"})
        self.assertEqual(
            len({x["scanner"] for x in [behavior, aggregate, correlation, wifi]}), 4
        )
        self.assertIn("behavioral_rules", behavior)
        self.assertIn("asset_context", aggregate)
        self.assertIn("normalization", correlation)
        self.assertEqual(wifi["access_points"], [])
        self.assertIsNone(wifi["audit_summary"]["risk_score"])
        for result in [behavior, aggregate, correlation]:
            self.assertEqual(result["findings"], [])
            self.assertEqual(result["risk_score"], 0)

    def test_behavior_requires_execution_context_and_redacts_arguments(self):
        benign = scanners.threat_detection(
            [{"pid": 1, "name": "notes.txt", "cmdline": ["powershell -enc SECRET"]}]
        )
        self.assertEqual(benign["findings"], [])
        observed = scanners.threat_detection(
            [
                {
                    "pid": 2,
                    "name": "powershell.exe",
                    "cmdline": ["powershell.exe", "-enc", "SECRET"],
                }
            ]
        )
        self.assertEqual(observed["findings"][0]["mitre_technique"], "T1059.001")
        self.assertNotIn("SECRET", json.dumps(observed))
        self.assertEqual(observed["risk_score"], 30)

    @patch(
        "myapp.analysis.domain_scanners.dns_scan",
        return_value={"status": "unavailable", "data": {}},
    )
    @patch("myapp.analysis.domain_scanners.http_scan", return_value=[])
    def test_phishing_has_lexical_contract_without_fabricated_network(self, http, dns):
        result = scanners.phishing_intelligence("https://paypa1.example.test/login")
        self.assertEqual(result["scanner"], "phishing_intelligence")
        self.assertIn("homograph_analysis", result)
        self.assertIn("typosquatting", result)
        self.assertEqual(result["status"], "PARTIAL")
        self.assertEqual(result["dns_analysis"]["status"], "unavailable")

    def test_static_file_hash_and_nonexecution(self):
        sample = b"ordinary static content\n"
        with patch(
            "subprocess.Popen", side_effect=AssertionError("Unexpected execution")
        ):
            result = scanners.static_file_analysis(
                SimpleUploadedFile("sample.txt", sample)
            )
        self.assertEqual(result["scanner"], "static_file_analysis")
        self.assertIn(hashlib.sha256(sample).hexdigest(), json.dumps(result["hashes"]))
        self.assertIn("pe_analysis", result)
        self.assertIn("elf_analysis", result)
        self.assertEqual(result["fuzzy_hash"]["state"], "Fuzzy hashing unavailable")

    def test_truncated_executable_metadata_is_bounded(self):
        for sample in [b"MZ", b"\x7fELF", b"MZ" + b"\xff" * 64]:
            result = binary_metadata(sample)
            self.assertEqual(len(result), 2)

    @patch("myapp.threat_intel.provider_results", return_value=[])
    def test_reputation_unavailable_is_not_clean(self, providers):
        result = scanners.threat_intelligence("8.8.8.8")
        self.assertEqual(result["scanner"], "threat_intelligence")
        self.assertEqual(result["status"], "UNAVAILABLE")
        self.assertEqual(result["attribution"]["actor"], "Unknown")
        self.assertEqual(result["findings"], [])

    def test_ioc_types_are_normalized(self):
        for value in [
            "2001:4860:4860::8888",
            "A" * 64,
            "EXAMPLE.test",
            r"C:\Temp\Sample.txt",
            r"HKLM\Software\Example",
        ]:
            result = scanners.detect_ioc(value)
            self.assertIn("value", result)
            self.assertIn("ioc_type", result)
        self.assertEqual(scanners.detect_ioc("A" * 64)["value"], "a" * 64)

    def test_artifact_validation(self):
        for name, data in [
            ("code.exe", b"MZ"),
            ("fake.pdf", b"not pdf"),
            ("a.json", b"{"),
            ("big.txt", b"a" * (2 * 1024 * 1024 + 1)),
        ]:
            with self.assertRaises((ValueError, UnicodeError)):
                validate_artifact(SimpleUploadedFile(name, data))
        name, data, mime = validate_artifact(
            SimpleUploadedFile("note.txt", b"evidence note")
        )
        self.assertEqual((name, mime), ("note.txt", "text/plain"))

    def test_incident_responder_and_private_download(self):
        incident = Incident.objects.create(
            owner=self.owner,
            title="Actual test observation",
            assigned_responder=self.responder,
        )
        upload_url = reverse("incident_evidence_upload", args=[incident.pk])
        self.assertEqual(
            self.client.post(
                upload_url,
                {"artifact": SimpleUploadedFile("note.txt", b"observed fixture")},
            ).status_code,
            302,
        )
        artifact = IncidentArtifact.objects.get(incident=incident)
        url = reverse("incident_evidence_download", args=[artifact.pk])
        self.client.force_login(self.responder)
        self.assertEqual(
            self.client.post(
                reverse("incident_response", args=[incident.pk]),
                {"phase": "CONTAINMENT", "note": "Review approved plan"},
            ).status_code,
            302,
        )
        response = self.client.get(url)
        self.assertEqual(response.content, b"observed fixture")
        self.assertEqual(response["Content-Type"], "application/octet-stream")
        incident.refresh_from_db()
        self.assertEqual(incident.phase, "CONTAINMENT")
        self.client.force_login(self.outsider)
        self.assertEqual(self.client.get(url).status_code, 404)
        self.assertEqual(
            self.client.post(
                upload_url, {"artifact": SimpleUploadedFile("note.txt", b"x")}
            ).status_code,
            404,
        )

    def test_feedback_validation_and_storage(self):
        self.assertFalse(
            ContactForm(
                {
                    "name": "Tester",
                    "email": "bad",
                    "subject": "Test",
                    "message": "Long enough message",
                }
            ).is_valid()
        )
        self.assertFalse(
            SuggestionForm({"category": "other", "message": "short"}).is_valid()
        )
        response = self.client.post(
            reverse("contact"),
            {
                "name": "Tester",
                "email": "test@example.test",
                "subject": "Review",
                "message": "A bounded test message",
            },
        )
        self.assertEqual(response.status_code, 302)
        self.assertEqual(ContactMessage.objects.get().subject, "Review")
        self.assertEqual(
            Client(enforce_csrf_checks=True).post(reverse("contact"), {}).status_code,
            403,
        )

    def test_removed_routes_and_shared_theme(self):
        for name in ["applications", "cms_dashboard"]:
            with self.assertRaises(NoReverseMatch):
                reverse(name)
        for name in [
            "contact",
            "suggestions",
            "developer",
            "about",
            "privacy",
            "security_intelligence",
        ]:
            response = self.client.get(reverse(name))
            self.assertEqual(response.status_code, 200, name)
            self.assertContains(response, "theme-init.js")
            self.assertContains(response, "app.js")
