└── sigma_rules/
```

## Main URLs

```text
/                         Home
/register/                Register
/login/                   Login
/dashboard/               SOC dashboard
/launcher/                Module launcher
/system/                  System scan
/network/                 Network scan
/scan/                    Combined scan
/threat-detection/        Threat detection
/mobile-security/         Mobile browser-safe scan
/profile/                 User profile
/edit-profile/            Edit profile
/forgot-password/         Forgot password
/security-admin/          Admin dashboard
/admin/                   Django admin panel
```

## Scan Types

### System Scan

Checks endpoint-focused security items:

- endpoint posture
- files and suspicious downloads
- processes
- startup entries
- persistence indicators
- identity/admin account posture
- compliance hints
- malware/IOC evidence
- MITRE ATT&CK mapping

### Network Scan

Checks network-focused exposure:

- active connections
- open ports
- exposed services
- attack surface
- RDP/SMB exposure
- brute-force exposure
- DNS/ARP/DHCP security guidance
- network risk scoring

### Combined Scan

Runs both system and network analysis together.

### Mobile Security Scan

Browser-safe checks:

- public IP hint
- user-agent/device details
- HTTPS/cookie/header guidance
- phishing URL scanner
- QR/link scanner
- password strength checker
- uploaded file scan with hashes and entropy
- Wi‑Fi safety checklist
- Android/iPhone limitations

## GitHub Upload Notes

Before pushing to GitHub, do not commit local runtime/cache files. Recommended `.gitignore`:

```gitignore
__pycache__/
*.py[cod]
*.sqlite3
db.sqlite3
logs/
media/
reports/
quarantine/
*.zip
.env
venv/
.venv/
staticfiles/
```

If these files were already committed, remove them from Git tracking:

```bash
git rm -r --cached __pycache__ myapp/__pycache__ scanner/__pycache__ myapp/migrations/__pycache__
git rm --cached db.sqlite3 logs/aegis.log
git add .gitignore
git commit -m "Clean ignored runtime files"
```

Push:

```bash
git remote set-url origin https://github.com/dhithimos/Vigilant-Sphere.git
git branch -M main
git push -u origin main
```

## Development Server Warning

Django may show:

```text
WARNING: This is a development server. Do not use it in a production setting.
```

This is normal for local testing. For production, deploy with a production WSGI/ASGI server such as Gunicorn, uWSGI, Daphne, or Uvicorn behind Nginx/Apache.

## Security Disclaimer

Vigilant Sphere is intended for educational, local auditing, and defensive security use. Do not scan systems, networks, files, or accounts without permission. Some detections are heuristic and should be validated by a security analyst before taking destructive actions.

## License

Add your preferred license before public release.
