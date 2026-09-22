# Scheduling external jobs

Core functionality is free. No in-app scheduler, Redis, Celery or cloud service is required. Optional third-party integrations may require accounts/API keys and have provider-specific limits.

From the extracted project on Windows:

```powershell
py -3 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
Copy-Item .env.example .env
.\.venv\Scripts\python.exe manage.py migrate
.\.venv\Scripts\python.exe manage.py check
.\.venv\Scripts\python.exe manage.py test myapp
.\.venv\Scripts\python.exe manage.py runserver 127.0.0.1:8000
```

Register through the local application. Ordinary active signed-in users can use System, Network, Wi-Fi and the existing local administration interface. Do not expose this intentionally shared local administration model to untrusted users.

Example installation at `C:\Vigilant-Sphere`; substitute your actual absolute installation path and existing attribution username. These are examples, not jobs automatically installed by this delivery:

```powershell
schtasks /Create /TN "Vigilant WiFi" /SC DAILY /ST 09:00 /TR "C:\Vigilant-Sphere\.venv\Scripts\python.exe C:\Vigilant-Sphere\manage.py run_wifi_audit --username operator"
schtasks /Create /TN "Vigilant Digest" /SC DAILY /ST 09:15 /TR "C:\Vigilant-Sphere\.venv\Scripts\python.exe C:\Vigilant-Sphere\manage.py send_alert_digest"
schtasks /Create /TN "Vigilant IOC expiry" /SC DAILY /ST 09:30 /TR "C:\Vigilant-Sphere\.venv\Scripts\python.exe C:\Vigilant-Sphere\manage.py expire_stale_iocs"
```

For paths with spaces, use Task Scheduler's separate Program and Arguments fields. Program is the virtualenv Python absolute path; arguments start with the quoted absolute manage.py path. Set Start in to the project directory. Configure the task account deliberately: the OS account controls visible saved Wi-Fi profiles, while `--username` controls the application owner. Service accounts often cannot see interactive-user profiles. No passwords belong in task arguments. Feature flags and active-account checks apply to scheduled audits too.

Linux cron examples (installation `/opt/Vigilant-Sphere`):

```cron
0 9 * * * cd /opt/Vigilant-Sphere && .venv/bin/python manage.py run_wifi_audit --username operator
15 9 * * * cd /opt/Vigilant-Sphere && .venv/bin/python manage.py send_alert_digest
30 9 * * * cd /opt/Vigilant-Sphere && .venv/bin/python manage.py expire_stale_iocs
```

Enable SMTP/digest through Email Alerts. SMTP credentials come only from environment variables `VIGILANT_SMTP_USERNAME` / `VIGILANT_SMTP_PASSWORD`. Digest delivery is additional to immediate alerts. `send_alert_digest --dry-run` does not send; `--force` bypasses the frequency check, not the enabled/configured checks.

Reviewed IOC operations:

```powershell
.\.venv\Scripts\python.exe manage.py sync_local_iocs --dry-run
.\.venv\Scripts\python.exe manage.py sync_local_iocs
.\.venv\Scripts\python.exe manage.py import_iocs reviewed.json --strict --dry-run
.\.venv\Scripts\python.exe manage.py import_iocs reviewed.json --strict
.\.venv\Scripts\python.exe manage.py export_iocs exported.json --format json
.\.venv\Scripts\python.exe manage.py expire_stale_iocs --dry-run
.\.venv\Scripts\python.exe manage.py expire_stale_iocs --exclude-source local_reviewed
```

`data/local_iocs.json` supports strings or objects such as `{"value":"example.test","confidence":50,"threat_name":"Operator review"}` in the existing domains/ips/sha256 arrays. No feed is auto-ingested. Retired records stay retired unless `--reactivate` is explicitly passed. Expiry defaults to 90 days, based on last_seen or discovered_at. Configure `IOC_EXPIRY_DAYS`, `IOC_MIN_DETECTIONS` (3), `IOC_MIN_ABUSE_SCORE` (80), `IOC_MIN_OTX_PULSES` (3) through the process environment; `.env.example` is unchanged as requested. Prefer JSON for exact safe exchange. Import limits: 10 MB and 10,000 rows. A local match is not a malware verdict; absence is not a safety claim.
