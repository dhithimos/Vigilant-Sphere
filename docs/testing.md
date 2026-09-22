# Verification and exact commands

Environment: Windows, Python 3.12, Django 5.2.17, SQLite. No provider credentials configured. Run from the extracted project root:

```powershell
python manage.py migrate
python manage.py check
python manage.py makemigrations --check --dry-run
python manage.py test myapp --noinput
```

62 tests cover authentication/CSRF, the removed reset bypass, dashboard/footer/developer routes, account isolation, incident/finding lifecycle, upload size/signatures, real hash fixtures, archive traversal metadata, URL normalization/private/mixed-address blocking, pinned socket targets and redirects, unavailable HTTP/DNS/TLS, HTML/JavaScript observations, cookie redaction, source-level password privacy, Wi-Fi classification/capability state, official MITRE parent/tactic records, JSON/CSV/PDF responses, comparison, CMS publication/scheduling/escaping, chatbot and queued cancellation. Tests use synthetic fixtures and mocked network responses; they do not assert invented provider detections.

Browser checks on localhost: sign-in, dashboard No Evidence, local password analysis with HIBP off, secure generation, and assistant response. Responsive measurements on the password page: viewport/content widths 390/375, 768/753, 1440/1425 (no horizontal overflow). The developer photo and shared footer rendered. These are selected browser checks, not exhaustive device testing. HIBP was not contacted.

Manual acceptance procedure: register/login; upload a harmless ZIP/text/PDF; open persisted details/job/findings; export each format; create an incident from a real indicator, add a note and archive; compare two uploads; publish a user-created post and inspect homepage/blog/detail logged out; exercise focused analyzers against authorized public targets or pasted static code; inspect Wi-Fi limitation; browse ATT&CK parent/tactic links; use the assistant; inspect disabled provider states. Never upload production credentials as test data.

Optional local developer checks: `python -m ruff check . --select F821,E9,F401`; `python -m pip_audit -r requirements.txt`. These developer tools are not runtime dependencies.

See `verification.json` for recorded command results and `dependency-audit.json` for the final advisory response. The supplied Django 5.2.14 had 17 reported advisories; it was upgraded to 5.2.17, after which the dependency audit reported no known vulnerabilities.

The Tasks 1–10 suite is `python manage.py test myapp.test_requested_fixes --noinput`. It includes empty-account incidents, owned job links, escalation, blank notes, running/failed/partial jobs, queued cancellation, scanner filters, Wi-Fi states/default flags, feature-disabled chatbot API, local answer grounding, MITRE account isolation, decoded PDF/CSV/JSON/HTML display labels, footer scope, and lazy-user profile rendering. New registration lookups and local engines are tested with fixtures/mocks; live registry responses and installed optional engines were not certified. Changed browser scripts passed Node syntax checks; interactive browser rendering was not revalidated for this revision.
