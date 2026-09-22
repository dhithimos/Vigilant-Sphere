# Tasks 1–10 changelog

Existing Vigilant Sphere project modified in place. Login, personal-record ownership checks, and feature flags remain enforced. The previous user-requested trusted-local access model is retained; staff status is not required.

## Changes and reasons

1. **Incidents** — The form required findings even on accounts with only scan jobs. Added optional owned scan-job relationships and validation requiring at least one real finding or job. Empty accounts receive a scan-first explanation. Escalation preselects owned findings. Empty note POSTs return 400 instead of creating a false archive event; JSON notes tolerate legacy non-list values. List filtering and archive behavior remain owner-scoped.
2. **Scan jobs** — Target investigations previously created jobs only after collection. They now create and claim a job before collection, preserve terminal failures, and finalize the same job. The host pipeline success counter no longer includes failed scanners. Unavailable Wi-Fi collection cannot report Completed. Job detail refreshes while queued/running. Existing 100-row newest-first listing, risk/timestamp detail ordering, POST-only owner-checked queued cancellation and one-time execution claims are retained. Running synchronous jobs are not interruptible.
3. **Findings** — Investigation scanner IDs did not match catalog IDs. New uploads use `files`, URLs use `urls`; filters include historical aliases, normalize severity, validate scanner choices and preserve the existing 200-row limit/order. Detail displays risk, job and escalation. Existing status updates and ownership are preserved. Wi-Fi observations now consistently link to a job and evidence row.
4. **Phishing** — Added local keyword, internationalized/mixed-script and approximate hostname-spelling indicators with severity, confidence and evidence. These are potential indicators, not phishing verdicts. Lexical evidence survives a failed fetch without claiming absent HTTP headers. Bounded SSRF-safe public registration lookup reports returned registration events/age or Unavailable; it does not guess parent-domain ownership. Existing redirect, TLS, HTTP, form and JavaScript observations are retained. Screenshots and target JavaScript execution remain explicitly unavailable.
5. **File details** — Existing hashes, signatures, entropy, strings/IOCs and archive/PE/ELF/document/script data remain visible. Added a syntax-specific encoded-command indicator and validated T1059.001 link; it explicitly does not claim execution. Detail now surfaces assessment and linked normalized findings/MITRE. Optional-engine identities are generic display labels. No optional engine request/parsing code changed.
6. **Chatbot** — Added local topic retrieval over authored multi-paragraph guidance, examples, practical steps and recent conversation context. Existing account-owned live-record queries retain NO DATA behavior. The assistant identifies itself as local knowledge, not an LLM; unsupported questions receive an honest boundary. Safe Markdown headings/emphasis use DOM text nodes, with existing history, new-chat, loading and copy controls. The API now enforces the same offline-assistant flag as the page. No external LLM dependency or request was added.
7. **Wi-Fi** — Kept the enabled-by-default flag and management toggle. One job records each attempt, including unavailable attempts; partial profile collection is Partial. Every observed profile has a linked finding/evidence record. Existing Windows saved-profile limitations and no-key collection remain. The UI links to the job and feature flags and distinguishes stored history from live radio data.
8. **MITRE** — Enriched the existing curated official ATT&CK 19.2 dataset from the already-downloaded upstream STIX bundle with platforms, source-provided data sources and detection-strategy descriptions. Tactics use names; techniques list children, mitigations and owned finding links/counts. Coverage meters count mapped techniques versus total per tactic, not attacks. Per-request copies prevent account-specific state from mutating the cached dataset. Missing source guidance stays explicitly unavailable.
9. **Display identity** — Shared render/JSON presentation helpers copy and label data without changing records; final textual-response handling covers HTML/admin/CSV/JSON and PDF text is labelled before drawing. Known identities become capability names; unknown structured provider/attribution values become External intelligence. Original integration code, API names and `.env.example` are unchanged. The password opt-in element and its JavaScript selector were renamed together; the breach request still sends only a hash prefix. Actual remote destinations remain inspectable in browser network tools. Presentation masking is not network anonymity.
10. **Footer** — Removed only the footer image element. Developer name/link, configured social/repository links and footer navigation remain. The dedicated developer and image-management templates, model fields and image files remain intact.

## Migration and verification

New migration: `myapp/migrations/0014_incident_scan_jobs.py`. It adds the incident–job many-to-many table; existing rows are preserved. Run `python manage.py migrate` after updating.

Validation: 62 Django tests passed; Django system check passed; no migration drift; 70 parameter-free routes checked with no server/template/static errors; changed rendered inline JavaScript and password script passed Node syntax checks. Tests use explicit synthetic fixtures/mocked network responses, not manufactured live scan evidence. Protected integration files and environment template were compared with the input ZIP. Final clean-extraction validation is recorded in `docs/verification.json`.

Not newly validated live: registry/network availability, installed optional local engines, real Wi-Fi adapter output, SMTP delivery, and interactive browser layouts. The local assistant is bounded authored retrieval; it cannot answer arbitrary questions as an LLM would. No new mandatory dependency was introduced.

## Exact changed locations

Paths below are relative to the project root. Line ranges refer to the final files. For Python, changed symbols are listed; template/data rows list every changed output range. CREATE means a new file; PATCH means an existing file was modified. The reasons above apply to each task's files. Presentation-only imports are noted separately from changed functions.

| FILE | ACTION | FUNCTION / LINE |
|---|---|---|
| `data/attack.json` | PATCH | Dataset technique metadata (platforms, data_sources, detection_guidance) |
| `myapp/analysis/investigation.py` | PATCH | `_run_target_scan` lines 107–233; `run_target_scan` lines 236–258 |
| `myapp/analysis/persistence.py` | PATCH | `persist_findings` lines 11–79 |
| `myapp/chatbot/engine.py` | PATCH | `_record_answer` lines 26–158; `answer` lines 173–247 |
| `myapp/chatbot/intents.py` | PATCH | Module imports/configuration |
| `myapp/chatbot/knowledge.py` | CREATE | Module imports/configuration |
| `myapp/migrations/0014_incident_scan_jobs.py` | CREATE | `Migration` lines 6–18 |
| `myapp/models.py` | PATCH | `Incident` lines 150–187 |
| `myapp/presentation.py` | CREATE | `display_text` lines 31–32; `display` lines 35–79; `render` lines 82–85; `JsonResponse` lines 88–90; `CapabilityDisplayMiddleware` lines 93–114 |
| `myapp/scanners/file_details.py` | PATCH | `details` lines 10–136 |
| `myapp/scanners/phishing_indicators.py` | CREATE | `lexical` lines 9–66 |
| `myapp/scanners/target.py` | PATCH | `http_scan` lines 176–312; `rdap_scan` lines 389–451 |
| `myapp/scanners/web_analysis.py` | PATCH | `javascript` lines 21–34 |
| `myapp/security_pipeline.py` | PATCH | `WiFiSecurityScanner` lines 327–356; `execute_job` lines 504–604 |
| `myapp/static/myapp/password-analyzer.js` | PATCH | Lines 23–23 |
| `myapp/test_regressions.py` | PATCH | `WorkflowTests` lines 22–319; `AnalysisSecurityTests` lines 322–459 |
| `myapp/test_requested_fixes.py` | CREATE | `RequestedWorkflowTests` lines 21–296; `RequestedAnalysisTests` lines 299–333 |
| `myapp/views.py` | PATCH | `target_scan_detail` lines 1552–1583; `target_scan_pdf` lines 1615–1701; `findings` lines 1732–1756; `wifi_security` lines 1891–1948; `chatbot_api` lines 1963–1995; `download_scan_pdf` lines 2173–2259 |
| `myapp/wifi_records.py` | CREATE | `persist_audit` lines 13–81 |
| `myapp/workspace_views.py` | PATCH | `IncidentForm` lines 17–57; `incident_edit` lines 74–115; `incident_detail` lines 119–144; `csv_report` lines 208–266; `mitre` lines 397–452 |
| `README.md` | PATCH | Lines 121–135 |
| `scanner/settings.py` | PATCH | Module imports/configuration |
| `templates/base.html` | PATCH | Lines 55–55 |
| `templates/myapp/chatbot.html` | PATCH | Lines 6–6 |
| `templates/myapp/combined_scan.html` | PATCH | Lines 280–280 |
| `templates/myapp/editor.html` | PATCH | Lines 3–3 |
| `templates/myapp/file_scan.html` | PATCH | Lines 3–3, 361–361 |
| `templates/myapp/finding_detail.html` | PATCH | Lines 2–2, 4–6 |
| `templates/myapp/findings.html` | PATCH | Lines 244–248, 251–251 |
| `templates/myapp/incident_detail.html` | PATCH | Lines 2–2, 4–6 |
| `templates/myapp/mitre_catalog.html` | PATCH | Lines 3–3 |
| `templates/myapp/mobile_security.html` | PATCH | Lines 415–415 |
| `templates/myapp/phishing.html` | PATCH | Lines 3–3 |
| `templates/myapp/scan_job_detail.html` | PATCH | Lines 295–295 |
| `templates/myapp/scan_result.html` | PATCH | Lines 513–513 |
| `templates/myapp/target_scan_detail.html` | PATCH | Lines 364–364, 372–372, 381–381, 391–391, 411–411, 442–442 |
| `templates/myapp/threat_detection.html` | PATCH | Lines 300–300, 302–302 |
| `templates/myapp/threat_intelligence.html` | PATCH | Lines 222–222, 224–224 |
| `templates/myapp/wifi_security.html` | PATCH | Lines 304–304 |

Documentation updates: README installation/limitations; docs/testing.md test scope; this changelog; regenerated file-audit, final-tree, reference-verification and verification records. Original audit is retained as historical context.
