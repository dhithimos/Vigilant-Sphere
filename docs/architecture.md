# Architecture

The original one-app architecture is retained. New code is grouped by responsibility without changing app labels or existing migration identifiers. `scanner/urls.py` includes `myapp/urls.py`. Existing routes remain available; incident, CMS, MITRE, report and history routes now call `workspace_views.py`. Uploaded-file and phishing forms converge on `analysis/investigation.py`, then `analysis/persistence.py` creates ScanJob -> Finding -> FindingEvidence. Incidents relate to Findings, which already retain job and mapping evidence.

`advanced_models.py` was previously absent from model registration even though migration 0004 created its tables. It is now explicitly registered from models.py; no legacy tables are dropped. Migration 0013 is additive: finding update timestamp, incident owner/findings/notes/target/archive flag, and TargetScan.job.

Outbound web checks use `scanners/transport.py`; static parsers use `web_analysis.py`; file metadata and optional tools are separate modules. Frontend forms retain CSRF protection, autoescaping and owner filtering. No JavaScript package manager or build pipeline is needed. Shared theme CSS includes offline layout fallbacks and the base footer uses real URL names.
