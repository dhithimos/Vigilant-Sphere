from django.test import SimpleTestCase

from .scanners.target import classify_target, normalize_url, safe_host


class TargetClassificationTests(SimpleTestCase):
    def test_detects_supported_target_types(self):
        self.assertEqual(classify_target("Example.COM")[0], "domain")
        self.assertEqual(classify_target("https://example.com/a?b=c")[0], "url")
        self.assertEqual(classify_target("8.8.8.8")[0], "ip")
        self.assertEqual(classify_target("a" * 64)[0], "hash")
        self.assertEqual(classify_target("analyst@example.com")[0], "email")

    def test_normalizes_url_and_rejects_bad_target(self):
        self.assertEqual(normalize_url("HTTPS://Example.COM"), "https://example.com/")
        with self.assertRaises(ValueError):
            classify_target("not a target")

    def test_private_literals_are_blocked_before_http(self):
        with self.assertRaises(ValueError):
            safe_host("127.0.0.1")
        with self.assertRaises(ValueError):
            safe_host("::1")
