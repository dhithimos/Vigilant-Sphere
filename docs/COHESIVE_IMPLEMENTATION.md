# Cohesive platform implementation and verification

Existing project modified from `Vigilant-Sphere-completed-file.zip`.
This report supersedes earlier revision reports retained in docs as historical provenance.

## Audit and structure

The original scanner settings package, myapp application, root templates/static directories, existing authentication, database relationships and migration history were retained. No replacement project or extra application hierarchy was introduced. Inventory and baseline checks preceded edits; the baseline had 78 passing tests. Existing Wi-Fi code already avoided simulated APs. The principal defects were overlapping scanner entry points, absent suggestion persistence, insufficient contact validation, absent global theme, and incomplete incident response tracking.

Exact created/modified/deleted files and Python function/class line ranges are in `cohesive-changed-files.json`. The complete packaged tree is `final-tree.txt`. No source files were moved. Six unreferenced legacy scanner/contact/suggestion templates were removed after reference searches, plus the Applications and CMS Command Center templates. Dependencies were retained because their runtime uses remain; no new mandatory dependency was added. Runtime databases, uploads, caches, logs, secrets, virtual environments and old ZIPs are excluded, not treated as source.

## Scanners

- Phishing: dedicated URL, Unicode/IDN, limited confusable-character, edit-distance brand/domain similarity, entropy, DNS/MX and safe HTTP evidence sections. Similarity is a potential indicator, not proof of impersonation. Network failure remains unavailable/partial. Ports outside the fetch allowlist can be examined lexically but are not fetched.
- File: bounded in-memory static processing, hashes including SHA-256, magic/type mismatch, entropy, strings, IOCs, existing archive/PDF/Office/optional-tool modules, and bounded PE/ELF parsing. PE imports list library names, not imported function names. No uploaded content is executed. Fuzzy hashing is explicitly unavailable.
- Security Intelligence: aggregate owned persisted asset/finding context, maximum recorded finding risk to avoid summing duplicate observations, and literal CVE references already present in evidence. No authoritative installed-software vulnerability feed is configured. Aggregate findings are excluded from later aggregation.
- Threat Detection: internal deterministic rules over actual process snapshots for encoded PowerShell, Office-child command interpreters and suspicious Windows system-process paths. Raw command arguments are evaluated in memory and not retained. Persistence and beaconing require evidence beyond the snapshot and remain insufficient evidence. Internal rules are not advertised as YARA.
- Threat Intelligence: distinct type-specific configured-provider reputation pipeline, public-IP validation, honest unavailable states and Unknown attribution without a supporting source.
- IOC: normalized hash/IP/domain/URL/path/registry exact matching against the reviewed local store and owned finding/incident/asset/MITRE relationships. No extra outbound requests.
- Wi-Fi: saved-profile configuration posture is distinct from actual current-connection observations. Executive sections show only collected signal/channel/security/frequency/BSSID data. No neighboring radio survey, congestion measurement, OUI feed, PMKID capture or handshake analysis is claimed. Duplicate saved configurations are potential indicators only.

Each domain has its own result contract and named detailed sections; low-level transport, persistence and reports are shared. Scores expose actual contributing factors and do not establish safety when zero. JSON/CSV/PDF retain actual records and provider states.

## Incidents and database

Migration `0016_incidentartifact_delete_applicationrelease_and_more` adds response phase, assigned responder and playbook to Incident, adds private IncidentArtifact records, adds subject/category to ContactMessage, and removes ApplicationRelease. Existing legacy incident status remains compatible. Phases are Triage, Containment, Eradication, Recovery and Post-Incident Review. Playbooks track authorized work; no remediation command is executed. Notes record actor/time/actions. Owners can assign active users and archive; assigned responders can update response and access attached incident evidence. Other personal-record access remains scoped.

Artifacts allow only bounded text/CSV/JSON/PDF/PNG/JPEG content, validate content/signatures, retain SHA-256, and are downloaded as attachment/octet-stream with nosniff and no-store. They are stored privately in SQLite, outside public media. Attachment creation is only through the validated incident workflow. Back up an existing database before upgrading: migration 0016 intentionally removes the obsolete application-release table and its rows. Historic migrations are preserved.

## MITRE

The existing bundled official-data-derived Enterprise ATT&CK 19.2 dataset is retained: 697 techniques/sub-techniques and 15 tactics, with provenance, source hash and license in data. No IDs were invented or refreshed during this revision. The responsive collapsible matrix groups actual techniques by tactics and links descriptions, sub-techniques, sources and evidence. Only stored supported mappings count as observed. Coverage is not equated with confirmed detection; unobserved rows do not imply measured defensive gaps. Behavioral mappings require the rule's process context and a valid bundled technique ID. Wi-Fi configuration weaknesses are not mapped to attacks without attack evidence.

## UI, CMS, developer and feedback

A single theme-init script applies manual preference or OS preference before stylesheet paint. app.js controls the global toggle, theme persistence, accessible mobile drawer, Escape/outside/close/link behavior and table wrappers. Central semantic CSS supplies light/dark surfaces, focus states, responsive grids/forms/tables, reduced motion and admin tokens. Password inputs remain browser-local; only a theme preference is added to localStorage. The local knowledge assistant, existing conversations, CMS blog publishing and existing account workflows are retained.

Applications and the CMS Command Center landing page/routes/navigation are removed. CMS blog editing and necessary static pages remain. Contact and Suggestions now use bounded server-validated ModelForms with CSRF and database storage. Developer information uses the existing admin-editable CMSDeveloperProfile and supplied images/fallback; no qualifications or social URLs were invented. Footer removes the five technical analyzer labels while retaining actual useful routes. About/privacy copy describes implemented capabilities and actual data handling.

## Security changes

- File: myapp/incident_response.py, validate_artifact/upload_artifact/download_artifact. New evidence uploads enforce size/type/content checks and owner/responder authorization; generated download filenames prevent header injection and avoid inline rendering.
- File: myapp/domain_views.py, scanner_page. Forms validate bounded input, rate limits remain, and scan/result persistence is transactional. Engine failure retains a failed job instead of a completed result.
- File: myapp/analysis/domain_scanners.py. Uses existing SSRF-protected public transport with redirects/DNS/IP validation, response bounds and timeouts; raw process command lines are not persisted. Nonstandard ports are lexical-only.
- File: myapp/forms.py and views._feedback. Contact/suggestion fields validate email, category and length server-side; CSRF is retained and stored text is escaped in templates.
- File: myapp/scanners/binary_metadata.py. Bounded header/section/program/symbol tables and strict slice checks avoid unbounded parsing or executing supplied binaries.

The explicitly requested no-staff local access model is preserved: active signed-in users can inspect the server host and use shared local management. This is a trusted-local-user model; ordinary signed-in administration is intentionally broad. Login, CSRF and ownership/responder checks on personal workflows remain. No external security certification or penetration-test completeness is claimed.

## Actual verification

See `cohesive-verification.json` for exact command output and `cohesive-reference-verification.json` for route statuses. Tests cover previous features plus distinct schemas, real static hashes, bounded/truncated and minimal valid PE/ELF headers, behavioral evidence/privacy, unavailable reputation, IOC normalization, empty Wi-Fi honesty, contact validation/CSRF, private artifact access, incident phase changes, removed routes, file persistence and report generation.

Browser QA used a disposable ordinary account and SQLite database, never packaged. Login and dashboard live CPU evidence worked. Manual light/dark switching persisted through reload; Escape and navigation-link selection closed the mobile drawer. Dashboard overflow checks passed at 360x800, 390x844, 768x1024, 1024x768, 1366x768 and 1920x1080. Phishing, MITRE, Wi-Fi and Contact each passed DOM overflow checks at those six sizes. Thirteen major scanner/information pages passed 390px checks in light mode; representative pages passed dark mode. No browser console errors were observed during those checks. Screenshots were sampled; every screen/state and accessibility contrast combination was not exhaustively visually tested.

Optional live provider accounts, SMTP delivery, Linux/macOS host collectors, installed ClamAV/YARA and actual wireless hardware behavior were not newly live-tested. Optional tools and network failures retain explicit capability states. OS theme fallback and reduced motion were source-verified; automated OS preference switching and every modal/chart state were not simulated. The application is a local evidence-assessment tool, not an EDR agent, sandbox, wireless attack tool or guaranteed malware detector.

## Run and test on Windows

```powershell
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
Copy-Item .env.example .env
python manage.py check
python manage.py migrate
python manage.py makemigrations --check
python manage.py test
python manage.py runserver 127.0.0.1:8000
```

Register a local account. Existing data upgrades must use the provided migrations. The exact environment template is `.env.example`; optional API keys may remain empty. Mandatory dependencies are Django, Pillow, psutil, ReportLab, python-dotenv and dnspython with provided constraints. Optional local tools include YARA/ClamAV and platform Wi-Fi commands. Optional reputation providers remain account/key dependent with their own limits. Core functionality is free; no cloud, paid feed, external LLM, Celery or Redis is mandatory.
