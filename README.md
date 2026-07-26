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

Add your preferred license before public release.






























# 🛡️ Vigilant Sphere - Threat Intelligence & Detection Engine

![Python](https://img.shields.io/badge/Python-3.10+-blue.svg)
![Django](https://img.shields.io/badge/Django-5.2+-green.svg)
![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey.svg)
![License](https://img.shields.io/badge/License-MIT-yellow.svg)
![Status](https://img.shields.io/badge/Status-Active-success.svg)
![Security](https://img.shields.io/badge/Cybersecurity-SOC-red.svg)

---

# Vigilant Sphere

**Vigilant Sphere Threat Intelligence & Detection Engine** is a modern Django-based cybersecurity platform designed for learning, defensive security, SOC (Security Operations Center) simulations, and security assessments.

It combines endpoint security, network analysis, threat detection, browser-safe mobile security checks, PDF reporting, and an administrative monitoring dashboard into one web application.

The project is intended for cybersecurity students, SOC analysts, security researchers, penetration testers, and anyone learning defensive security.

---

# Author

**Dhithimos E J**

GitHub:
https://github.com/dhithimos

Repository:
https://github.com/dhithimos/Vigilant-Sphere

---

# Features

## SOC Dashboard

- Live Security Dashboard
- Risk Score
- Threat Level
- Incident Summary
- Security Findings
- Scan History
- Active Alerts
- CPU Usage
- Memory Usage
- Threat Trend Graph
- Traffic Visualization
- Executive Metrics

---

## System Security Scan

Performs endpoint posture assessment.

Checks include:

- Running Processes
- Suspicious Files
- Download Folder Inspection
- Startup Programs
- Persistence Indicators
- Administrator Account Status
- Windows Security Recommendations
- IOC Detection
- Malware Indicators
- MITRE ATT&CK Mapping
- Compliance Guidance
- Security Score

---

## Network Security Scan

Analyzes the local network.

Checks include:

- Active Connections
- Listening Ports
- Exposed Services
- Attack Surface
- SMB Exposure
- RDP Exposure
- DNS Security
- DHCP Guidance
- ARP Security
- Network Risk Score
- Brute-force Exposure Suggestions

---

## Threat Detection

Includes SOC-inspired detection modules.

Features:

- Endpoint Detection & Response (EDR)
- Network Detection & Response (NDR)
- File Threat Analysis
- User Behavior Analytics
- Threat Intelligence
- IOC Matching
- SOAR Recommendations
- Executive Summary

---

## Mobile Security Scanner

Browser-safe mobile security checks.

Includes:

- Device Information
- User Agent Analysis
- Browser Security
- HTTPS Validation
- Cookie Security
- Security Headers
- Public IP Detection
- Password Strength Checker
- URL Phishing Detection
- QR Link Scanner
- Uploaded File Hash Analysis
- File Entropy Detection
- Wi-Fi Safety Checklist

### Browser Limitations

Because this project runs inside a browser, it **cannot** access:

- Installed Applications
- SMS
- Call Logs
- Root Status
- Android Debug Bridge
- Full Device Storage
- Background Processes

A native Android/iOS application would be required for those capabilities.

---

## Reports

Generate professional reports.

Supports:

- PDF Export
- Print
- Gmail Share
- WhatsApp Share
- Discord Share

---

## User Management

- User Registration
- Login
- Logout
- Forgot Password
- User Profile
- Edit Profile
- Profile Image Upload

---

## Security Administration

Administrator Dashboard includes:

- User Activity
- Login History
- Device Information
- IP Address
- Browser Details
- Active Users
- Scan Usage
- Contact Messages
- Feedback
- Ratings
- CSV Export

---

# Technology Stack

Backend

- Python
- Django 5.2+

Frontend

- HTML
- CSS
- JavaScript

Database

- SQLite

Libraries

- psutil
- reportlab

Other

- Git
- GitHub

---

# Requirements

- Python 3.10+
- Django 5.2+
- psutil
- reportlab

Optional

- Git
- GitHub Account
- Virtual Environment

---

# Installation

Clone Repository

```bash
git clone https://github.com/dhithimos/Vigilant-Sphere.git

cd Vigilant-Sphere
```

---

Create Virtual Environment

```bash
python -m venv venv
```

Windows PowerShell

```powershell
.\venv\Scripts\Activate.ps1
```

Command Prompt

```cmd
venv\Scripts\activate
```

Linux/macOS

```bash
source venv/bin/activate
```

---

Install Dependencies

```bash
pip install django psutil reportlab
```

---

Run Database Migration

```bash
python manage.py migrate
```

---

Create Admin User

```bash
python manage.py createsuperuser
```

---

Start Development Server

```bash
python manage.py runserver
```

Open

```
http://127.0.0.1:8000/
```

---

# Mobile Browser Access

Run

```bash
python manage.py runserver 0.0.0.0:8000
```

Find your computer IP.

Example

```
192.168.1.10
```

Open on your phone

```
http://192.168.1.10:8000/
```

---

# Project Structure

```
Vigilant-Sphere
│
├── manage.py
│
├── scanner
│   ├── settings.py
│   ├── urls.py
│   ├── asgi.py
│   └── wsgi.py
│
├── myapp
│   ├── models.py
│   ├── views.py
│   ├── urls.py
│   ├── scan_engine.py
│   ├── advanced_models.py
│   ├── advanced_views.py
│   └── migrations
│
├── templates
├── static
├── media
├── logs
├── reports
├── quarantine
├── threat_database
├── yara_rules
├── sigma_rules
└── ioc_data
```

---

# Main URLs

| URL | Description |
|------|-------------|
| / | Home |
| /register | Register |
| /login | Login |
| /dashboard | SOC Dashboard |
| /launcher | Launcher |
| /system | System Scan |
| /network | Network Scan |
| /scan | Combined Scan |
| /threat-detection | Threat Detection |
| /mobile-security | Mobile Security |
| /profile | User Profile |
| /edit-profile | Edit Profile |
| /forgot-password | Forgot Password |
| /security-admin | Security Admin |
| /admin | Django Admin |

---

# Scan Types

## System Scan

- Endpoint Security
- Processes
- Startup Entries
- Malware Indicators
- Persistence
- IOC Detection
- MITRE ATT&CK

---

## Network Scan

- Ports
- Services
- Connections
- Attack Surface
- DNS
- DHCP
- ARP
- SMB
- RDP

---

## Combined Scan

Runs both System Scan and Network Scan together.

---

## Mobile Security Scan

Browser-safe scanning including:

- URL Scanner
- QR Scanner
- Password Strength
- File Hash Analysis
- Wi-Fi Security

---

# Recommended .gitignore

```
__pycache__/
*.py[cod]
*.sqlite3
db.sqlite3
logs/
reports/
media/
quarantine/
.env
venv/
.venv/
staticfiles/
*.zip
```

---

# Remove Cached Files

```bash
git rm -r --cached __pycache__

git rm --cached db.sqlite3

git add .gitignore

git commit -m "Removed runtime files"

git push
```

---

# Development Server Warning

```
WARNING:
This is a development server.
Do not use it in a production deployment.
```

For production deployment use:

- Gunicorn
- Uvicorn
- Daphne
- uWSGI

behind

- Nginx
- Apache

---

# Security Disclaimer

Vigilant Sphere is provided **for educational purposes, defensive security research, cybersecurity training, and authorized security assessments only**.

Users are responsible for ensuring they have explicit authorization before scanning systems, networks, applications, or accounts.

The developers are **not responsible** for any misuse, unauthorized access, illegal activities, data loss, or damages resulting from the use of this software.

Some detections are heuristic-based and should always be reviewed by a qualified security analyst before taking remediation actions.

---

# Contributing

Contributions are welcome.

1. Fork the repository

2. Create a feature branch

```
git checkout -b feature-name
```

3. Commit changes

```
git commit -m "Added feature"
```

4. Push

```
git push origin feature-name
```

5. Open a Pull Request

---

# Reporting Issues

If you encounter:

- Bugs
- Security Issues
- False Positives
- Feature Requests
- Documentation Errors

Please create an Issue on GitHub:

https://github.com/dhithimos/Vigilant-Sphere/issues

Please include:

- Operating System
- Python Version
- Django Version
- Browser
- Error Message
- Steps to Reproduce

---

# Contact Author

For questions, support, or collaboration:

**Author:** Dhithimos E J

GitHub

https://github.com/dhithimos

Repository

https://github.com/dhithimos/Vigilant-Sphere

Issue Tracker

https://github.com/dhithimos/Vigilant-Sphere/issues

If you discover a **security vulnerability**, please **do not disclose it publicly**. Instead, report it responsibly by opening a private discussion (if enabled) or contacting the author through GitHub.

---

# Future Roadmap

Planned improvements include:

- AI Threat Detection
- Live Threat Intelligence Feed
- VirusTotal Integration
- YARA Rule Engine
- Sigma Rule Detection
- Real-Time Monitoring
- Email Alerts
- SOAR Automation
- Cloud Security Module
- Windows Event Log Analysis
- Linux Log Analysis
- Active Directory Security Checks
- MITRE ATT&CK Heatmap
- SIEM Dashboard
- Docker Deployment
- REST API
- Dark Mode
- Multi-language Support

---

# License

This project is licensed under the **MIT License**.

Copyright (c) 2026 Dhithimos E J

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

---

⭐ If you found this project useful, please consider giving it a star on GitHub!
