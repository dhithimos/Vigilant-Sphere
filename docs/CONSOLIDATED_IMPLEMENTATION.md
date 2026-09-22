# Consolidated implementation — 2026-09-21

Existing project modified: `vigilant-spherecomplete.zip` → `vigilant-spherecomplete/Vigilant-Sphere`. This report supersedes earlier revision verification claims. Original audit documents are retained as historical provenance.

## Task traceability

### P1-T1–T4
FILE: `myapp/scanners/wifi.py` · ACTION: MODIFY · LOCATION: classify L11–83; _run L86–96; fields L99–105; parse_profiles L108–109; parse_profile_entries L112–122; parse_profile_security L125–129; parse_profile_connection_mode L132–140; split_terse L143–159; band L162–177; _row L180–188; _failure L191–198; collect_windows L201–245; linux_security L248–260; collect_linux L263–308; mac_interface L311–319; collect_macos L322–342; collect L345–358; collect_current_connection L361–508
Cross-platform passive collectors, scoped gateway/DNS metadata, auto-connect scoring, honest WPS/unknown states; never read key properties.

### P1-T5–T8; P2-T5–T10
FILE: `myapp/wifi_audit_service.py` · ACTION: CREATE · LOCATION: compare_risk L22–31; authorize L34–41; finding_type_for L44–51; annotate_rows L54–69; run_audit L72–104; persist_audit L108–295; history_queryset L298–307
Shared audit transaction, job/finding/report persistence, duplicate/BSSID observations, trust suppression, score trends and bounded history. Weak encryption is not attack evidence; no wireless ATT&CK mapping added.

### P1-T7–T8; P2-T2
FILE: `templates/myapp/wifi_security.html` · ACTION: MODIFY · LOCATION: L1–5
Paginated history, evidence, trust POSTs, current metadata, alert delivery and existing job/report links.

### P2-T1–T4
FILE: `myapp/alerts.py` · ACTION: MODIFY · LOCATION: _config L16–48; _safe L51–52; send_alert L55–114; send_critical_alert L117–119; get_or_create_deduped_alert L123–156; delivery_label L159–170; send_digest L174–239
Configurable HIGH/CRITICAL threshold, successful-send deduplication, escalation bypass, env-only SMTP credentials, additive digest with timestamp checkpoint.

### P2-T1–T2; P2-T7; P6-C1
FILE: `myapp/views.py` · ACTION: MODIFY · LOCATION: client_ip L145–152; client_device L155–157; score_to_level L176–187; scan_display_score L190–221; decorate_scan L224–231; traffic_label L234–251; scan_findings L254–279; scan_stat_summary L282–298; enrich_file_item L301–386; track_activity L389–401; home L404–412; register L415–486; user_login L489–541; user_logout L545–557; forgot_password L560–588; dashboard L592–613; launcher L617–706; feature_flags L710–748; ensure_default_feature_flags L751–783; feature_flag_map L786–788; feature_enabled L791–797; require_feature L800–807; audit_security_event L810–817; seed_initial_cms_content L820–904; phishing_scan L908–921; password_strength L925–944; file_scan L948–961; developer_profile L964–965; how_to_use L968–976; suggestions L979–992; applications L996–1007; download_application L1011–1036; cms_dashboard L1040–1055; cms_pages L1059–1065; cms_page_edit L1069–1132; cms_media L1136–1165; cms_developer_images L1169–1255; cms_settings L1259–1298; cms_navigation L1302–1330; security_policies L1334–1360; audit_logs L1364–1374; profile L1378–1382; edit_profile L1386–1422; change_password L1426–1444; _save_scan L1447–1469; combined_scan L1473–1548; target_scan_detail L1552–1583; target_scan_json L1587–1611; target_scan_pdf L1615–1701; scan_jobs L1705–1713; scan_job_detail L1717–1728; findings L1732–1756; scan_result L1760–1791; submit_scan_feedback L1795–1827; system_scan L1831–1849; network_scan L1853–1871; mobile_security_scan L1875–1887; wifi_security L1891–1926; chatbot L1931–1938; chatbot_api L1942–1974; email_configuration L1978–2086; threat_detection L2090–2108; threat_intelligence L2112–2120; ioc_correlation L2124–2126; real_time_monitoring L2130–2132; quarantine_view L2136–2138; risk_assessment L2142–2150; threat_timeline L2154–2156; download_scan_pdf L2160–2246; export_json_report L2250–2273; admin_dashboard L2277–2319; download_user_details L2323–2390; about L2393–2395; privacy_policy L2398–2400; contact L2403–2421; blogs L2424–2428; api_dashboard_metrics L2432–2468
Normal signed-in access, alert form validation, user-scoped history, shared-host notice and active developer images.

### P2-T8
FILE: `myapp/management/commands/run_wifi_audit.py` · ACTION: CREATE · LOCATION: Command L7–28
One shared passive audit path, required application attribution username and OS-account context.

### P2-T4
FILE: `myapp/management/commands/send_alert_digest.py` · ACTION: CREATE · LOCATION: Command L5–18
External scheduler entry point; dry-run and force options.

### P3-T1
FILE: `myapp/context.py` · ACTION: MODIFY · LOCATION: site_context L5–28; can_inspect_host L31–33
Authenticated, feature-gated launcher hidden on chat page.

### P3-T1
FILE: `templates/base.html` · ACTION: MODIFY · LOCATION: L1–67
Single local SVG link to existing assistant page; no duplicated chat runtime.

### P3-T2–T4
FILE: `myapp/chatbot/engine.py` · ACTION: MODIFY · LOCATION: _normalize L32–33; _find L36–49; _record_answer L52–221; answer L236–310
Local record answers with bounded owned findings, full ATT&CK descriptions, service context, risk contributors and NO DATA states.

### P3-T3
FILE: `templates/myapp/chatbot.html` · ACTION: MODIFY · LOCATION: L1–7
Safe DOM text-node formatting, lists, headings, emphasis and only relative-path links; no unescaped HTML.

### P4-T1–T4
FILE: `myapp/analysis/ioc_correlation.py` · ACTION: CREATE · LOCATION: _load L22–31; load_local_iocs L34–41; normalize_indicator L44–85; local_entries L88–106; upsert_indicator L110–137; clean_indicators L140–148; correlate_indicators L151–197; extract_indicators L200–247; correlation_payload L250–289; persist_provider_results L292–355
Shared cached reviewed-set loader, exact normalized matching, counters, retirement preservation, bounded owned related findings, qualified existing provider results.

### P4-T1
FILE: `myapp/security_pipeline.py` · ACTION: MODIFY · LOCATION: redact L48–85; ScannerHealth L89–92; BaseScanner L95–125; SystemScanner L128–149; ProcessScanner L152–188; PersistenceScanner L191–215; FileScanner L218–249; NetworkConfigScanner L252–276; PortScanner L279–301; ConnectionScanner L304–325; WiFiSecurityScanner L328–358; CapabilityScanner L361–366; ScannerRegistry L415–464; normalize L467–525; execute_job L528–635
Per-job cached correlation; repeated normalization does not increment counters twice; errors remain unavailable.

### P4-T2
FILE: `myapp/scan_engine.py` · ACTION: MODIFY · LOCATION: _risk_level L131–142; _file_reason L145–176; _file_resolution L179–190; _sha256 L193–205; _file_entropy_hint L208–236; _file_soc_details L239–257; profile_system L260–284; _local_ip L287–296; compliance_check L299–337; process_audit L340–400; _contains_credential L403–407; startup_audit L410–450; active_network_connections L453–487; port_scan L490–518; _port_resolution L521–532; file_scan L535–622; credential_file_scan L625–639; exposure_assessment L642–657; identity_privilege_assessment L660–671; fim_snapshot L674–679; behavioral_analysis L682–713; threat_database_matches L716–719; threat_intel_lookup L722–767; ai_recommendations L770–813; _score_from_evidence L816–834; _scan_scope_payload L837–944; run_combined_scan L947–1092
Shared hash correlation retains legacy output shape.

### P4-T2
FILE: `myapp/scanners/file_analysis.py` · ACTION: MODIFY · LOCATION: _entropy L26–32; analyze_uploaded L35–201
File module uses shared local IOC correlation.

### P4-T3
FILE: `myapp/analysis/investigation.py` · ACTION: MODIFY · LOCATION: _level L35–47; _risk L50–94; _limit L97–104; _run_target_scan L107–235; run_target_scan L238–260
Persist qualified results from requests already performed; no additional outbound calls.

### P4-T4
FILE: `myapp/analysis/persistence.py` · ACTION: MODIFY · LOCATION: persist_findings L11–81
Store correlation on findings from target investigations.

### P4-T5
FILE: `templates/myapp/finding_detail.html` · ACTION: MODIFY · LOCATION: L1–7
Visible match/miss/unavailable evidence, owned related links and delivery status.

### P4-T5
FILE: `templates/myapp/target_scan_detail.html` · ACTION: MODIFY · LOCATION: L1–447
IOC section links actual persisted findings.

### P4-T6
FILE: `myapp/admin.py` · ACTION: MODIFY · LOCATION: CustomUserAdmin L48–63; ScanResultAdmin L67–70; UserActivityAdmin L74–77; ScanFeedbackAdmin L81–84; ContactMessageAdmin L88–91; DeveloperImageAdmin L104–120; IndicatorForm L158–169; IndicatorOfCompromiseAdmin L172–178
IOC filters, search, source/value validation and retirement controls in existing signed-in local admin.

### P4-T3
FILE: `myapp/management/commands/sync_local_iocs.py` · ACTION: CREATE · LOCATION: Command L5–19
Explicit reviewed-set ingestion; no startup feed.

### P4-T7
FILE: `myapp/management/commands/import_iocs.py` · ACTION: CREATE · LOCATION: Command L7–80
Bounded JSON/CSV import, strict validation, dry-run and explicit reactivation.

### P4-T7
FILE: `myapp/management/commands/export_iocs.py` · ACTION: CREATE · LOCATION: Command L6–28
Active IOC exchange using existing source metadata; JSON preferred for exact round trip.

### P4-T8
FILE: `myapp/management/commands/expire_stale_iocs.py` · ACTION: CREATE · LOCATION: Command L9–34
Single deactivation update, source exemptions, no deletion.

### P5-A1–A2
FILE: `myapp/mitre_data.py` · ACTION: MODIFY · LOCATION: dataset L7–10; indexes L14–21; children_of L24–26; tactic_name_and_slug L29–31
Cached immutable helper indexes with copied child rows and unknown-slug fallback.

### P5-A3–A8; P2-T9
FILE: `myapp/workspace_views.py` · ACTION: MODIFY · LOCATION: IncidentForm L17–57; incident_list L61–70; incident_edit L74–115; incident_detail L119–148; finding_detail L152–181; history L185–200; compare L204–225; csv_report L229–287; PostForm L290–312; public_queryset L315–318; public_posts L321–331; post_detail L334–342; post_edit L346–363; post_list L367–376; static_analysis L380–414; mitre L418–589; cancel_job L593–607; trust_wifi L611–642
Owned exact-ID counts, window-bounded finding samples, filtered mapping JSON/CSV, incident rollup and ownership-checked trust mutation.

### P5-A1–A9
FILE: `templates/myapp/mitre_catalog.html` · ACTION: MODIFY · LOCATION: L1–4
Children, tactic links, counts, coverage, search, modified date, exports and source-backed detection fallback.

### P5-A5
FILE: `templates/myapp/incident_detail.html` · ACTION: MODIFY · LOCATION: L1–7
Derived ATT&CK section without duplicated model data.

### P5-B1–B3
FILE: `templates/myapp/dashboard.html` · ACTION: MODIFY · LOCATION: L1–478
Pinned local Chart.js, retained text fallback, no null chart samples; server CPU interval is 0.1 seconds.

### P6-C1–C7
FILE: `templates/myapp/developer.html` · ACTION: MODIFY · LOCATION: L1–1
Extend existing route/template with local supplied image fallback and configured links; no invented biography.

### P3-T1; P6-C2/C6
FILE: `static/css/theme.css` · ACTION: MODIFY · LOCATION: L1–17
Scoped developer styles, launcher focus and reduced-motion rules, responsive safe-area spacing.

### P1/P2 migrations
FILE: `myapp/migrations/0015_alertemailconfiguration_alert_dedup_window_hours_and_more.py` · ACTION: CREATE · LOCATION: Migration L8–79
Additive schema for trust, score breakdown, finding relation, BSSID and alert policy; no migration deletions.

## Decisions and fact corrections

- C1: the supplied project already had Wi-Fi persistence in `wifi_records.py`, including informational observations. It is now a compatibility import of the shared service; not a second implementation.
- Launcher: plain link (C21). Service: `wifi_audit_service.py`. Scheduling is external; no Celery/Redis or in-app scheduler.
- Digest checkpoint uses the configuration timestamp, with equal-timestamp boundary handling. Digests are additional to immediate notifications.
- IOC upsert key is type/value/source. No uniqueness migration: legacy duplicates remain valid; concurrent first inserts can race. Transactions lock existing rows. Local reviewed indicators expire unless excluded explicitly.
- Provider request/parsing and `.env.example` remain unchanged. VirusTotal minimum malicious detections: 3; AbuseIPDB minimum score: 80; OTX minimum pulses: 3. OTX has no calibrated confidence field: stored confidence 0 explicitly means not supplied, not a measured risk probability. HIBP/email results and non-global IPs are never persisted as provider IOCs.
- ATT&CK counts are exact-ID, no parent roll-up. Coverage includes sub-techniques. Search intersects the current route filter. Export includes at most 10,000 newest owned findings with truncation metadata; counts remain complete. No suggested mappings are mixed into observed mappings.
- Wi-Fi ATT&CK verification table: no entries added. OPEN/WEP, auto-connect, duplicate SSIDs and BSSID changes do not establish T1557 or T1040 behavior. Bundled ATT&CK version and provenance are unchanged in `data/attack.json`.
- CPU: locally vendored Chart.js 4.5.1 plus MIT license; `cpu_percent(interval=0.1)`. Active signed-in users retain host access. Removed misleading staff fallback; no staff gate introduced.
- Existing `/developer/` route and `developer.html` were extended. The consolidated text describes a separate HTML mockup but does not contain its full biography. Existing supplied name/image and factual project copy retained; no qualifications invented.
- Safe DOM creation replaces the requested escaped-innerHTML approach: it supports structure without parsing untrusted markup.
- Linux `none` key management cannot prove WEP without more configuration evidence, so it remains UNKNOWN; OWE is distinct from unencrypted OPEN. Enterprise configuration remains unassessed. Windows English field parsing and OS permissions limit available metadata.

## Security and privacy

No uploaded file execution, wireless attacks, wireless keys, secret Wi-Fi properties, external LLM or new mandatory Python dependency added. Login, feature flags and per-user finding/incident ownership remain. SMTP username/password are read only from environment settings. Digest and alert HTML escape/redact evidence. CSV MITRE export neutralizes formula-leading text. IOC CSV is an exact exchange format; use JSON for untrusted sets rather than opening CSV in a spreadsheet.

## Not live-verified / limitations

Linux/macOS collectors are fixture-tested only. This Windows host listed 17 saved profiles but returned no usable security fields and no current-connection metadata; these remain unknown, with incomplete profile collection marked partial. No live SMTP email or paid/provider request was made. Installed YARA/ClamAV paths were not retested. The browser webview failed to attach, so chart animation, visual layout and mobile overlap were not visually verified. Django template rendering, static references and JavaScript syntax are checked separately. Developer-image files missing from user-managed storage use the static fallback only when no active database image is selected; an active broken media path needs operator replacement.

## New files and exact symbol ledger

See `consolidated-changed-files.json` for every changed/new file and function/class line range. No app, model or migration was removed. Runtime databases, uploaded media, caches and generated logs are preserved locally and excluded from delivery; existing supplied static developer image remains. Mandatory requirements and provider parsing were preserved.

## Source references

[Chart.js official API documentation](https://www.chartjs.org/docs/latest/api/) and [NetworkManager nmcli documentation](https://networkmanager.pages.freedesktop.org/NetworkManager/NetworkManager/nmcli.html) informed the pinned local chart integration and cached `--rescan no` Wi-Fi collection. Chart.js license is bundled beside the library.
