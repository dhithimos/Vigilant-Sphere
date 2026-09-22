> Historical initial-project audit. The current Tasks 1–10 update, exact change locations and verification supersede overlapping statements below: see `docs/TASKS_1_10_CHANGELOG.md` and `docs/verification.json`.

# Audit and implementation report

## Part 1 — Project status

**Existing project modified.** Input ZIP contained 129 files. This report supersedes the old supplied audit claims. Source architecture and migration history were retained; no replacement project was created. Tests prove the documented scenarios, not every advanced specification item.

## Part 2 — Cleanup summary

Removed the supplied populated `db.sqlite3`, three logs, four duplicate CMS uploads, and the personal static profile upload. Runtime databases/logs/caches created during verification are excluded again before packaging. Removed unreferenced templates after route consolidation: templates/myapp/advanced_unavailable.html, templates/myapp/blogs.html, templates/myapp/cms_blog.html, templates/myapp/dashboard_advanced.html, templates/myapp/incidents.html, templates/myapp/mitre_mapping.html, templates/myapp/reports.html, templates/myapp/scan_history.html. The obsolete demo reset template was removed. Duplicate inline analyzers and superseded CMS/incident/history/report views were removed after callers were redirected. Five mandatory existing dependencies were retained because imports require them; dnspython was added. No mandatory dependency was falsely described as removed. Unused imports were cleaned.

One intentional image duplicate remains: the supplied developer photo in `media/developer/dhithimos-es.jpg` supports historical migration 0007, while `static/images/developer.jpg` is the source-controlled public UI asset. Empty Python package initializers are required, not redundant implementations.

## Part 3 — Actual final tree

See `docs/final-tree.txt`, generated from the final ZIP entries.

## Part 4 — Initial audit results

Existing: one Django app, auth, host collectors, target/file analyzers, provider adapters, templates, Wi-Fi parser, local assistant, legacy/normalized models and 12 migrations. Working or partially working: model-backed auth, browser password generator, static hashing, provider-disabled behavior and Wi-Fi parsing. Broken: insecure reset, public CMS query, global incidents, sliced Wi-Fi summary query, stale model registration, and unconditional scan completion. Missing: incident editing/relations, finding lifecycle, comparison, CSV, comprehensive catalog and focused analyzers. Unsafe/misleading: rebinding-sensitive transport, host inspection available to all users, arbitrary upload types, fabricated confidence/telemetry descriptions. `docs/initial-inventory.json` inventories every original path, size, hash, imports, symbols and references. `docs/file-audit.json` records per-file actions and final symbol line numbers. Automated references are conservative; lack of a match was not used to delete schema models.

## Part 5 — Fixes implemented

Incident CRUD-with-archive, notes/timeline and owned finding relations; one-time job claims and queued cancellation; finding lifecycle; persistent file/phishing pipelines; bounded file metadata and optional engine adapters; pinned URL transport; DNS records; verified TLS connection; actual HTTP headers/cookies; HTML and JavaScript static pages; browser-local passwords and opt-in HIBP; Wi-Fi capability messages; official ATT&CK catalog; owned JSON/CSV/PDF/history/comparison; CMS public publishing; local assistant conversation UI; shared footer/developer image and optional social links; secure recovery and available to signed-in users host inspection. Partial features are itemized in `docs/limitations.md`.

## Part 6 — Security audit

| Severity | Actual file / current line / function | Original problem and impact | Implemented fix |
|---|---|---|---|
| Critical | `myapp/views.py:560` `forgot_password` | Fixed demo OTP and reset action did not require verified ownership. Unauthenticated account takeover using known username/email. | Replaced with Django signed single-use reset tokens, SMTP delivery and explicit unavailable/local administrator recovery. |
| High | `myapp/scanners/transport.py:11` `fetch` | URL validation resolved DNS separately from the socket connection; redirects could repeat resolution. DNS rebinding/SSRF into internal services. | Public-address allow policy, pinned socket addresses, hostname-verified TLS, safe ports, credential rejection, redirect revalidation, bounded bytes and read deadline. |
| High | `myapp/workspace_views.py:79` `incident_detail` | Incident list was global and models lacked ownership/relations. Cross-account incident exposure; incomplete evidence workflow. | Added incident owner, owned detail/edit/relationship queries, timeline and archive lifecycle. |
| High | `myapp/views.py:1494` `combined_scan` | Any logged-in user could launch host inspection. Remote users could collect sensitive server filesystem/process information. | Signed-in host/Wi-Fi inspection; ordinary users retain isolated uploaded/target scans. |
| High | `myapp/uploads.py:9` `clean_image` | Profile and CMS uploads trusted filename/extension; SVG/PDF could be publicly served. Stored active content and unsafe upload handling. | Public image uploads validate dimensions/format/size and re-encode to randomized JPEG names; SVG/PDF removed from the CMS image view. |
| High | `myapp/analysis/investigation.py:107` `run_target_scan` | Investigations were persisted as COMPLETED unconditionally. Failed/unavailable checks looked successful. | Status derived from actual module outcomes; normalized owned job/finding persistence. |
| Medium | `myapp/security_pipeline.py:513` `execute_job` | Finding deduplication used global fingerprints/time windows. One user scan could suppress another user’s evidence. | Deduplicate only within the current job; claim queued jobs once and retain history. |
| Medium | `myapp/scan_engine.py:239` `_file_soc_details` | Generic MITRE lists, YARA-style strings and fixed confidence labels implied detections. Misleading SOC/malware findings. | Removed unsupported maps and fake engine claims; exact local IOC matching uses an empty-by-default reviewed dataset. |
| Medium | `myapp/threat_intel/providers.py:35` `_request` | Default redirect handling could forward provider authorization headers. Possible API key disclosure across redirects. | Provider requests disable redirects and environment proxy inheritance. |
| Medium | `myapp/workspace_views.py:162` `csv_report` | New CSV reports could embed formula-leading user content. Spreadsheet formula interpretation. | Prefix formula-leading cells and export owned evidence only. |
| Medium | `myapp/middleware.py:8` `AuthenticationThrottle` | No local authentication throttling. Unlimited local brute-force submissions. | Bounded IP/path attempts with 15-minute cache window; shared limiter needed for multi-worker deployment. |
| High | `requirements.txt:1` `dependency pin` | Supplied Django 5.2.14 dependency had 17 advisories in pip-audit. Version-specific framework risks. | Updated to 5.2.17 and pinned audited dependencies; follow-up advisory query returned no known vulnerabilities. |

Line references describe the final implementation location. Original snippets are not copied when they could disclose sensitive content. The complete replacement code is in the delivered files. No vulnerability-free or production certification claim is made.

## Part 7 — Restructuring

Old root: `Vigilant-Sphere-production-features/` with source, DB, logs and uploads mixed together. New root: `Vigilant-Sphere/` with existing `scanner/`, `myapp/`, `templates/`, `static/` retained and new `data/` plus clearer scanner/analysis modules. Added transport, web/file details, optional tools, persistence, ownership lifecycle views, image validation, throttle, context processor and tests. Imported legacy advanced models to preserve schema state. Existing URL names now point to the appropriate consolidated view. No original app was relocated or renamed. Runtime folders are created at launch and excluded from ZIP.

## Part 8 — MITRE

Official Enterprise ATT&CK 19.2; 697 active technique/sub-technique entries, 15 tactics, parents, descriptions, references, source version and mitigation relationships. Data retrieved 2026-09-20, source hash in `data/attack.json`, upstream license included. UI marks only account-specific mapped findings; all other entries have No Evidence. Mapping rules cover actual encoded PowerShell process evidence and credential-file pattern indicators, with confidence and evidence in findings/incidents/reports. Not all ATT&CK techniques have local detection rules.

## Part 9 — CMS fix

The previous `views.blogs` rendered a static `BLOGS` list and never queried CMSBlogPost, so saving a published database post did not affect the public blog. It now calls the same due-publication queryset used by homepage and detail. Model forms implement editing, slug uniqueness, timestamps, draft/published/scheduled/archived transitions, category/tags and staff preview. Public output is escaped; unauthorized edits are denied.

## Part 10 — Chatbot

Local Security Assistant, not fake AI. Memory-only conversation sidebar/new/clear/history, user/assistant messages, loading, copy and keyboard send behavior. Local concepts, ATT&CK lookup and user-scoped stored observations. No external LLM or optional AI adapter; no persisted chat transcript.

## Part 11 — Wi-Fi

Windows saved profiles through bounded netsh commands; no key collection or active attacks. Signed-in because this is the server adapter. Unsupported platforms, missing tooling and collection failures are visible. WPA2 authentication without reported cipher does not imply AES. No claim of live network enumeration, WPS detection or Linux/macOS collection.

## Part 12 — Requirements

Runtime: Django, Pillow, psutil, reportlab, python-dotenv and dnspython; exact versions in requirements/constraints. Optional: yara-python with reviewed rules and ClamAV with signatures. Providers: VT, AbuseIPDB, OTX and HIBP. Development tools Ruff/pip-audit are not runtime dependencies.

## Part 13 — Environment

Exact `.env.example`:

```dotenv
# Copy to .env for local settings. Never distribute your populated .env.
VIGILANT_DEBUG=true
VIGILANT_SECRET_KEY=
VIGILANT_ALLOWED_HOSTS=127.0.0.1,localhost
VIGILANT_MAX_UPLOAD_SIZE=26214400
VIGILANT_TARGET_HTTP_TIMEOUT=10
VIGILANT_TARGET_HTTP_MAX_BYTES=1048576
VIGILANT_TARGET_REDIRECT_LIMIT=5
VIGILANT_TARGET_SCAN_LIMIT_PER_HOUR=30
VT_API_KEY=
ABUSEIPDB_API_KEY=
OTX_API_KEY=
HIBP_API_KEY=
HIBP_EMAIL_CHECK_ENABLED=true
HIBP_EMAIL_TIMEOUT=10
DEVELOPER_GITHUB_URL=
DEVELOPER_LINKEDIN_URL=
VIGILANT_SPHERE_GITHUB_URL=
VIGILANT_SMTP_HOST=
VIGILANT_SMTP_PORT=587
VIGILANT_SMTP_USERNAME=
VIGILANT_SMTP_PASSWORD=
VIGILANT_SMTP_USE_TLS=true
VIGILANT_SMTP_USE_SSL=false
VIGILANT_ALERT_FROM_EMAIL=
VIGILANT_ALERT_RECIPIENTS=
CAPTCHA_PROVIDER=turnstile
CAPTCHA_SITE_KEY=
CAPTCHA_SECRET_KEY=
```

## Part 14 — Installation

Use the Windows commands in README. Create a fresh virtual environment, install requirements, copy `.env.example`, migrate, check, create your own administrator and bind runserver to localhost. No database, account, password or secret is delivered.

## Part 15 — Tests and acceptance

43 regression tests passed on Django 5.2.17 with provider keys empty. A further route/template/static audit checked 70 parameter-free routes and found no server errors or missing template/static references. Selected browser workflows and three viewport sizes were checked. Dependency audit returned no known vulnerabilities. `docs/testing.md` contains exact commands; `docs/acceptance.md` distinguishes tested, partial and untested capabilities. Fresh ZIP extraction validation is recorded in `docs/verification.json`.

## Honest delivery boundary

This is a runnable, improved local platform, not a claim that every advanced master-prompt item is complete. Deep PDF/Office/PE analysis, LLM integration, full radio assessment, running-job interruption, normalized category/tag taxonomies and exhaustive browser/network/OS validation remain limited. See the explicit limitations document.
