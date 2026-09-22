"""Shared frontend integration, including error rendering without database access."""
from django.test import TestCase, RequestFactory, override_settings, Client
from django.template.loader import render_to_string
from django.views.defaults import server_error


class GlobalThemeTests(TestCase):
    def test_csrf_failure_uses_themed_error(self):
        response = Client(enforce_csrf_checks=True).post('/contact/', {})
        self.assertContains(response, 'Access unavailable', status_code=403)
        self.assertContains(response, 'css/components.css', status_code=403)

    def test_server_error_is_themed_without_database(self):
        request = RequestFactory().get('/unavailable/')
        with self.assertNumQueries(0):
            response = server_error(request)
        self.assertEqual(response.status_code, 500)
        self.assertContains(response, 'css/components.css', status_code=500)
        self.assertContains(response, 'data-theme-select', status_code=500)

    @override_settings(DEBUG=False)
    def test_missing_page_uses_shared_shell(self):
        response = self.client.get('/missing-theme-test-page/')
        self.assertContains(response, 'Page not found', status_code=404)
        self.assertContains(response, 'css/theme.css', status_code=404)
        self.assertContains(response, 'css/components.css', status_code=404)

    def test_error_templates_escape_exception_context(self):
        for code in [400, 401, 403, 404, 429, 500, 503]:
            rendered = render_to_string(f'{code}.html', {'exception': '<script>alert(1)</script>'})
            self.assertNotIn('<script>alert(1)</script>', rendered)
            self.assertIn('main-content', rendered)
