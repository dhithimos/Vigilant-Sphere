# Global unified theme revision

See [theme implementation and validation](docs/THEME_UNIFICATION.md), [every changed file](docs/theme-changed-files.json), and [exact test output](docs/theme-verification.json). This theme update preserves backend code and adds no migrations or dependencies. Earlier reports describe earlier revisions.

# Latest cohesive revision

Existing project modified from `Vigilant-Sphere-completed-file.zip`. Read [implementation, upgrade notes and limitations](docs/COHESIVE_IMPLEMENTATION.md), [exact verification](docs/cohesive-verification.json), [file changes](docs/cohesive-changed-files.json), and [actual packaged tree](docs/final-tree.txt). Earlier reports in docs describe previous revisions.

# Vigilant Sphere

Existing project modified from `Vigilant-Sphere-production-features.zip`. The original `scanner` configuration and `myapp` Django application, URL names and migration history are preserved.

Core Vigilant Sphere functionality: **FREE**.

Optional third-party integrations: Provider accounts/API keys may be required and provider-specific limits may apply. No API key, paid service, Redis, Celery, commercial database, cloud account or LLM is required.

## Windows installation

Use Python 3.10 or newer (tested with Python 3.12 on Windows). Extract the ZIP, open PowerShell in `Vigilant-Sphere`, then:

```powershell
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
Copy-Item .env.example .env
python manage.py migrate
python manage.py check
python manage.py createsuperuser
python manage.py runserver 127.0.0.1:8000
```

Open http://127.0.0.1:8000/. Register an ordinary account or sign in using your newly created administrator. There are no packaged accounts or passwords. Existing migrations are included; do not run makemigrations just to install. `setup.ps1 -CreateSuperuser` automates dependency installation, migrations and checks.

If activation is blocked, invoke `.\.venv\Scripts\python.exe` directly. If `py` is absent, install Python or use the full path to an available Python executable.

## Architecture

- `scanner/`: Django settings, root URLs, WSGI and ASGI.
- `myapp/models.py`, `advanced_models.py`, `migrations/`: existing schema, retained legacy models and additive lifecycle migration 0013.
- `myapp/scanners/`: pinned-IP HTTP transport, DNS/TLS, HTML/JavaScript, uploaded-file metadata, optional engines and Windows Wi-Fi profiles.
- `myapp/analysis/`: investigation orchestration and normalized finding persistence.
- `myapp/security_pipeline.py`: privileged synchronous host scanner jobs and evidence normalization.
- `myapp/workspace_views.py`: incident/finding lifecycle, public CMS queries, editing, reports, comparison and ATT&CK catalog.
- `myapp/threat_intel/`: optional provider adapters; `myapp/chatbot/`: deterministic local assistant.
- `templates/`, `static/`: shared interface and browser-local password tools.
- `data/`: licensed official ATT&CK 19.2 snapshot and empty operator-maintained IOC dataset.
- `media/`: supplied developer image compatibility asset; new uploads are runtime data.

See `docs/final-tree.txt` for the exact packaged tree and `AUDIT_AND_IMPLEMENTATION.md` for the audit.

## Scanners and investigations

Use File Scanner, Phishing or Scan Center. File analysis hashes bytes, measures entropy, inspects signatures, extracts bounded strings/IOC candidates, lists ZIP/OOXML members, and identifies PDF markers and PE/ELF headers. No uploaded sample is executed. Archive contents are not extracted. Stored evidence may contain sensitive sample metadata: protect the local SQLite database and exported reports.

URLs use public HTTP(S) ports only, validate all resolved destinations, connect to a pinned address, verify TLS hostnames, bound response bytes/time/redirects, and revalidate every redirect. HTML and JavaScript analysis are static. Security-header absence is reported only after receiving a response. Cookies are represented by names/attributes; their values are discarded. DNS supports A/AAAA/MX/NS/TXT/CNAME/PTR. DNS resolution failures are not security findings. TLS failures do not automatically imply invalid certificates.

The separate `/dns/`, `/tls/`, `/http/`, `/html/`, `/javascript/` pages provide focused checks. Paste HTML/JavaScript for offline analysis. These focused pages show transient results; use Scan Center to persist a complete URL investigation. Network-dependent operations require internet and report errors/unavailability when it is absent.

Scores sum disclosed severity-based weights and are capped at 100. They are prioritization heuristics, not calibrated probabilities. No finding or zero score does not establish safety.

## Findings, incidents and history

Persistent investigations create an owned ScanJob and normalized Findings. Open a finding to acknowledge, resolve, accept risk or mark a false positive. Create incidents from your findings, edit status/severity/description/target, add timeline notes and archive them. Ownership is enforced on detail, editing, exports and relationships. Legacy scans remain linked in history. Compare actual stored investigations and regenerate JSON, CSV and PDF reports. Queued jobs can be cancelled; running synchronous jobs cannot be interrupted through the UI.

Host filesystem/process/port and Wi-Fi inspections are available to all signed-in users and inspect the **Django server**, not the browser device. Do not run the server as an administrator unless a reviewed operational need requires it.

## MITRE ATT&CK

Bundled official Enterprise ATT&CK **19.2**, 697 active techniques/sub-techniques and 15 tactics, retrieved 2026-09-20. `data/attack.json` records upstream source, SHA-256, individual versions, descriptions, parents and mitigations. `data/MITRE-LICENSE.txt` retains the upstream license. Catalog/matrix pages show No Evidence unless your findings contain a mapping. Mapping does not establish malicious intent. The local process rule maps observed encoded PowerShell to T1059.001 / Execution; credential-pattern observations can map to T1552.001 / Credential Access. Generic file presence, open ports and startup presence no longer produce unsupported technique mappings.

## CMS

Signed-in users can create/edit/preview/publish/unpublish/archive/delete posts at `/admin-dashboard/cms/blog/`. Category and tags retain the existing text-field schema and are editable per post. Scheduled posts become public when their publication timestamp is due. Public blog, category filter, homepage and detail use the same database publication predicate. Duplicate slugs return form errors. Content is escaped and rendered as plain text paragraphs, not executable HTML. Django admin provides additional model management.

## Local Security Assistant

No LLM is connected. The assistant answers from local concepts, official ATT&CK data and account-scoped recorded findings. It supports separate conversations, history during the page session, new/clear chat, loading state, copy, Enter-to-send and Shift+Enter. Conversation content is not persisted by the chatbot; reloading clears it. Questions are sent only to the local Django service. Do not paste credentials. Unrecognized questions receive an honest fallback, not a fabricated answer. No optional AI provider has been configured or implemented.

## Password privacy

Analyzer and generator use browser JavaScript. Inputs have no submission name and submission is intercepted. No plaintext, complete hash, password history, cookies, analytics or browser-storage persistence is used. Generation uses `crypto.getRandomValues()` with rejection sampling. Entropy and crack-time estimates are theoretical and cannot predict targeted guessing. Optional HIBP lookup is off by default; explicit opt-in sends only the first five SHA-1 characters directly to HIBP, compares suffixes locally, omits credentials/referrer and uses a timeout. HIBP email is a separate optional server provider.

## Wi-Fi

Ordinary browsers cannot enumerate Wi-Fi networks. Signed-in users can inspect Windows saved profile authentication/encryption using `netsh wlan show profiles` and `netsh wlan show profile`. No `key=clear`, password collection, cracking, packet injection or deauthentication. English Windows output is supported; localization, permissions, WLAN service and unavailable tools can limit collection. Linux/macOS metadata collectors are also available where supported OS tools report fields; these platform paths are fixture-tested. WPS, channel, signal, gateway and DNS are shown only when reported. No active neighboring radio survey, congestion measurement or handshake capture is implemented.

## Optional tools/providers

- `yara-python`: optional, install reviewed `.yar` rules under runtime `yara_rules/`; matching is bounded and static.
- ClamAV `clamscan`: optional local executable with separately maintained signatures; temporary samples are removed after scanning.
- Nmap/OpenSSL are not required; active network scanning and executable OpenSSL integration are not implemented.
- VirusTotal: hash/domain/IP lookups; automatic URL submission is unsupported.
- AbuseIPDB: IP reputation; OTX: supported indicators; HIBP: optional email breach lookup.
- Empty provider keys produce Not Configured/Unsupported, never a clean verdict. Live provider calls were not tested without accounts.

## Environment and local operation

`.env.example` contains only configuration placeholders. For persistent sessions, generate a local key with `python -c "import secrets; print(secrets.token_urlsafe(64))"` and set `VIGILANT_SECRET_KEY` in your private `.env`. With an empty key in debug mode, an ephemeral random key is used, so restarting signs users out. Hostnames default to localhost and 127.0.0.1.

Set the three developer/project URL variables to your actual URLs; no social account is invented. Replace `static/images/developer.jpg` to update the source developer photo. The media copy is retained because migration 0007 references it.

Email reset uses Django signed single-use tokens and configured SMTP. If SMTP is absent, use `python manage.py changepassword USERNAME` locally. Authentication has local-process throttling; production multi-worker deployment needs a shared cache/rate limiter. HTTP local debug mode is for localhost. Public deployment requires a private persistent secret, DEBUG=false, explicit allowed hosts, HTTPS, static/media serving and operational review; Django runserver is not a production server.

## Testing

```powershell
python manage.py check
python manage.py makemigrations --check --dry-run
python manage.py test myapp --noinput
```

See `docs/testing.md` and `docs/acceptance.md`. Network tests use deterministic mocked responses and do not contact arbitrary hosts. API keys can remain empty. First dependency installation needs internet or a prebuilt wheel cache; runtime offline features do not.

## Troubleshooting

- No such table: run migrate from the extracted project root.
- Invalid host: use localhost/127.0.0.1 or explicitly configure the intended hostname.
- Missing styles: use runserver locally; deploy static assets with collectstatic for a proper web server.
- Wi-Fi unavailable: inspect the capability message; web browsers have no adapter permission API.
- Provider unavailable: check optional key/limits and network; local scans still work.
- Failed URL scan: private targets and unusual ports are intentionally blocked; no bypass flag is provided.
- No posts: ensure status Published (or due Scheduled) and a publication date, using the CMS editor.

This is a local defensive application with documented partial analyzers, not an EDR/SIEM, malware sandbox or certification of production security. See `docs/limitations.md` before deployment.

## Local access model

All active signed-in accounts can use every scanner, CMS, settings, and `/admin/` management page without staff, analyst, or superuser flags. Management is shared, including user and global record editing. Use this access model with trusted local users only. Personal scan/finding/incident pages retain ownership checks; anonymous users cannot manage records. Existing role fields are retained for database compatibility and do not unlock features.


## Workflow update (Tasks 1–10)

Apply `python manage.py migrate` after updating. Migration `0014_incident_scan_jobs` adds optional incident-to-job links. Incidents require at least one real owned finding or scan job; an empty account must run a scan first. Findings provide an escalation link. Synchronous scans now record RUNNING jobs before collection and retain failures.

Wi-Fi produces one job per attempt, including unavailable and partially collected attempts. Collection remains limited to Windows saved-profile metadata. Feature flags apply to both pages and the chatbot API.

URL investigations include lexical indicators and a bounded public registration lookup. Registration dates are shown only when actually returned; subdomains may have no registration record. Screenshot capture and target JavaScript execution remain unavailable. File details include potential command-pattern findings and evidence-specific technique mappings.

The local assistant retrieves authored topic guidance and account-owned records. It is not an LLM and cannot reliably answer arbitrary questions beyond its knowledge. Conversations remain in page memory; short recent context is sent only to the local server on follow-up. A safe Markdown subset supports headings, emphasis, and text without rendering model-supplied HTML.

User-facing pages and reports use generic capability labels. Internal provider records, optional API settings, and request/parsing implementations remain unchanged. Direct optional service requests (including browser breach comparison) still expose their real destinations to browser network tools; this is display labeling, not network anonymity. Original evidence remains in the database; exports are labelled presentation copies.

See `docs/TASKS_1_10_CHANGELOG.md` for exact file/function locations, reasons, migration and verification details.
