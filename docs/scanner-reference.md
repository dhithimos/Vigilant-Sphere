# Scanner routes

| Feature | Actual route | Persistence / scope |
|---|---|---|
| File | /file-scan/ | TargetScan, ScanJob, Finding evidence; bounded in-memory static inspection |
| URL/investigation | /scan/ | Public URL/domain/IP/hash/email; optional providers |
| Phishing | /phishing/ | Shared URL evidence pipeline, not a phishing verdict |
| DNS / TLS / HTTP | /dns/, /tls/, /http/ | Focused transient public-network checks |
| HTML / JavaScript | /html/, /javascript/ | Pasted source, local static analysis |
| Password | /password-strength/, /mobile-security/ | Browser-local; opt-in HIBP prefix only |
| Wi-Fi | /wifi-security/ | Signed-in Windows saved-profile metadata or capability status |
| Host | /system/, /network/, /threat-detection/ | Signed-in local server snapshots |
| Jobs / findings / incidents | /scan-jobs/, /findings/, /incidents/ | Owned durable records and lifecycle controls |
| MITRE | /mitre-mapping/ | ATT&CK 19.2 catalog and account mappings |
| History / reports / comparison | /scan-history/, /reports/, /compare/ | Stored investigations and legacy records |
| CMS | /admin-dashboard/cms/blog/ | Signed-in editorial workflow |
| Public blog | /blogs/, /blog/<slug>/ | Database publication predicate |
| Assistant | /chatbot/, /api/chatbot/ | Local concepts, catalog and owned findings |

JSON/PDF/CSV investigation exports are under `/investigations/<scan_id>/json/`, `/pdf/`, `/csv/`. Signed-in users can use Django admin for operational models. No paid service is mandatory.
