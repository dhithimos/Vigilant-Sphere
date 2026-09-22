# Acceptance checklist

Checked means implemented and verified at the scope stated, not certification of all possible inputs.

- [x] Django starts; SQLite migrations run
- [x] Authentication and CSRF regression tests
- [x] Dashboard uses owned evidence and no-scan state
- [x] Scan jobs, queued cancellation and no reexecution
- [x] Finding status lifecycle and ownership
- [x] Incident creation/edit/notes/archive and owned finding relationships
- [x] File hashing, entropy, bounded metadata and archive inspection
- [x] Detailed file result modules rendered
- [x] URL transport and SSRF defenses tested with controlled fixtures
- [x] Phishing-related form/header observations (partial analyzer)
- [x] DNS A/AAAA/MX/NS/TXT/CNAME/PTR fixture/error handling
- [x] TLS verified-connection implementation and failure handling
- [x] HTTP headers/cookie redaction and failure states
- [x] HTML and JavaScript static observations
- [x] Password analyzer browser-local by default; generator uses secure randomness
- [x] HIBP only 5-character prefix in source; explicit opt-in
- [x] Wi-Fi real Windows collector or honest capability status
- [x] Official MITRE technique/tactic/sub-technique data and evidence UI
- [x] JSON/CSV/PDF report response tests
- [x] History and actual-record comparison
- [x] CMS creation/publication/scheduling, homepage and public detail
- [x] Local chatbot response and conversation UI
- [x] Shared footer and configurable developer image/page
- [x] API keys empty; no mandatory paid service
- [x] Runtime personal data, logs and caches excluded from ZIP
- [x] Existing app/migrations preserved; unused templates and duplicate analyzers removed
- [x] Undefined-name/import checks and template/static reference audit

- [ ] Live HIBP/provider/SMTP end-to-end integration (not exercised without accounts)
- [ ] YARA/ClamAV execution against installed engines/signatures (not installed here)
- [ ] Exhaustive DNS/TLS/HTTP tests against internet targets (fixtures used)
- [ ] Live wireless adapter measurements and other OS collectors
- [ ] Full PDF/Office/PE/ELF semantic analysis (bounded metadata only)
- [ ] Full ATT&CK detection coverage and confirmed intrusion attribution
- [ ] Persistent chatbot transcripts or an LLM provider
- [ ] Independent production penetration test or every-browser/device QA

Final packaging/extraction results are in verification.json. GitHub/LinkedIn/project links render only when configured; no URLs were invented.
