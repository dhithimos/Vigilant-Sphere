




# Vigilant Sphere

**Vigilant Sphere Threat Intelligence & Detection Engine** is a Django-based cybersecurity scanner and SOC-style dashboard. It includes system scanning, network scanning, threat detection, mobile browser-safe checks, scan reports, user profiles, admin monitoring, and security recommendations.

## Author

**Dhithimos E J**  
GitHub: [dhithimos](https://github.com/dhithimos)  
Repository: [dhithimos/Vigilant-Sphere](https://github.com/dhithimos/Vigilant-Sphere)

## Features

- **Dashboard:** SOC-style risk score, live alerts, threat trend, traffic visualization, CPU/memory status, findings, incidents, and scan history.
- **System Scan:** endpoint posture, suspicious files, processes, startup/persistence checks, compliance guidance, malware/IOC hints, and MITRE mapping.
- **Network Scan:** active connections, open ports, exposed services, attack surface analysis, SMB/RDP exposure, DNS/ARP/DHCP guidance, and network risk scoring.
- **Threat Detection:** EDR, NDR, file threat analysis, user behavior analytics, threat intelligence, SOAR recommendations, and executive metrics.
- **Mobile Security Scan:** browser-safe mobile checks, URL/QR phishing scanner, password strength checker, uploaded file hash/entropy scan, Wi‑Fi checklist, Android/iPhone limitations.
- **Reports:** PDF report download, print option, Gmail/WhatsApp/Discord sharing helpers.
- **User Management:** registration, login, profile, edit profile, forgot-password flow, image upload.
- **Admin Dashboard:** user activity, active/logged-in users, scan usage, feedback/rating, contact messages, device/IP/time details, CSV export.

## Requirements

- Python **3.10+**
- Django **5.2+**
- psutil
- reportlab
- SQLite, included with Python
- Modern browser: Chrome, Edge, Firefox, or Safari

Optional but recommended:

- Git
- GitHub account
- Virtual environment

## Installation

Clone the repository:

```bash
git clone https://github.com/dhithimos/Vigilant-Sphere.git
cd Vigilant-Sphere
```

Create and activate a virtual environment:

```bash
python -m venv venv
```

Windows PowerShell:

```powershell
.\venv\Scripts\Activate.ps1
```

Command Prompt:

```cmd
venv\Scripts\activate
```

Linux/macOS:

```bash
source venv/bin/activate
```

Install dependencies:

```bash
pip install django psutil reportlab
```

Apply migrations:

```bash
python manage.py migrate
```

Create an admin user:

```bash
python manage.py createsuperuser
```

Run the development server:

```bash
python manage.py runserver
```

Open:

```text
http://127.0.0.1:8000/
```

## Run On Mobile Browser

Start Django on all network interfaces:

```bash
python manage.py runserver 0.0.0.0:8000
```

Find your computer IP address, then open this from your phone:

```text
http://YOUR_PC_IP:8000/
```

Example:

```text
http://192.168.1.10:8000/
```

Note: mobile browser scans are browser-safe only. Android/iPhone system-level scans require a native mobile app because browsers cannot access installed apps, SMS/call permissions, root/debugging status, or full device storage.

## Project Structure

```text
Vigilant-Sphere/
├── manage.py
├── scanner/
│   ├── settings.py
│   ├── urls.py
│   ├── asgi.py
│   └── wsgi.py
├── myapp/
│   ├── models.py
│   ├── views.py
│   ├── urls.py
│   ├── scan_engine.py
│   ├── advanced_models.py
│   ├── advanced_views.py
│   └── migrations/
├── templates/
│   ├── base.html
│   └── myapp/
├── static/
├── media/
├── reports/
├── logs/
├── quarantine/
├── threat_database/
├── ioc_data/
├── yara_rules/
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



