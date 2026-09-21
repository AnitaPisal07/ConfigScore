<div align="center">

# 🛡️ ConfigScore

### Website Security Scanner & Configuration Auditor

[![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=flat&logo=python&logoColor=white)](https://python.org)
[![Flask](https://img.shields.io/badge/Flask-3.0+-000000?style=flat&logo=flask&logoColor=white)](https://flask.palletsprojects.com)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

**ConfigScore** is an automated, passive website security assessment tool that evaluates HTTP security headers, TLS configurations, cookie protections, and DNS policies — generating a scored audit report with actionable remediation guidance.

[Features](#-features) · [Screenshots](#-screenshots) · [Installation](#-installation) · [Usage](#-usage) · [Security Checks](#-security-checks) · [Tech Stack](#-tech-stack)

</div>

---

## 📌 About

ConfigScore performs **defensive, non-intrusive** security audits on websites. It sends standard HTTP/HTTPS requests and inspects the server's response headers, TLS certificate chain, cookie attributes, and DNS records — without sending any exploitation payloads.

The tool is designed for:
- **Web developers** who want to verify their server's security configuration
- **Computer Science students** learning about web security concepts
- **System administrators** performing quick compliance checks

> ⚠️ **Ethical Use Only** — Only scan websites you own or have explicit authorization to test.

---

## ✨ Features

| Feature | Description |
|---------|-------------|
| 🔍 **20-Point Security Scan** | Evaluates 20 essential security controls against OWASP, RFC, and NIST standards |
| 📊 **Risk Scoring (0–100)** | Weighted deduction algorithm with clear risk levels (Low / Medium / High / Critical) |
| 📄 **PDF Audit Reports** | Downloadable professional PDF report generated with ReportLab |
| 📚 **20 Deep-Dive Topic Pages** | Each security check links to a dedicated learning page with attack scenarios, fix examples, and references |
| 🔒 **Passive & Safe** | No exploit payloads, no intrusive probes — only standard HTTP, TLS, and DNS queries |
| 🧭 **Redirect Chain Tracking** | Follows and visualizes the full HTTP redirect path |
| 🛡️ **SSRF Protection** | Built-in safeguards prevent scanning of internal/private IP ranges |
| 🎨 **Modern UI** | Clean, responsive interface with a purple-themed design |

---

## 🖼️ Screenshots

> _Add screenshots of your running application here before pushing to GitHub._
>
> Example:
> ```
> ![Home Page](screenshots/home.png)
> ![Scan Result](screenshots/result.png)
> ```

---

## 🔐 Security Checks

ConfigScore evaluates the following **20 security controls**:

| # | Check | Category | Risk if Missing |
|---|-------|----------|-----------------|
| 1 | **HTTPS** | Transport & Encryption | Critical |
| 2 | **HSTS** (Strict-Transport-Security) | Transport & Encryption | High |
| 3 | **Content-Security-Policy** | Header Security | High |
| 4 | **X-Frame-Options** | Header Security | Medium |
| 5 | **X-Content-Type-Options** | Header Security | Medium |
| 6 | **X-XSS-Protection** | Header Security | Low |
| 7 | **Referrer-Policy** | Header Security | Medium |
| 8 | **Permissions-Policy** | Header Security | Medium |
| 9 | **Secure Cookies** | Cookie Security | High |
| 10 | **HttpOnly Cookies** | Cookie Security | High |
| 11 | **SameSite Cookies** | Cookie Security | Medium |
| 12 | **TLS Version** | Transport & Encryption | Critical |
| 13 | **Certificate Validity** | Transport & Encryption | Critical |
| 14 | **Certificate Chain** | Transport & Encryption | High |
| 15 | **DNS CAA Records** | DNS Security | Medium |
| 16 | **DNSSEC** | DNS Security | Medium |
| 17 | **Server Header Leakage** | Information Disclosure | Low |
| 18 | **X-Powered-By Leakage** | Information Disclosure | Low |
| 19 | **HTTP to HTTPS Redirect** | Transport & Encryption | High |
| 20 | **Mixed Content** | Transport & Encryption | Medium |

Each check returns a status: **PASS**, **WARNING**, **MISSING**, or **REVIEW**.

---

## 🚀 Installation

### Prerequisites
- **Python 3.10+**
- **pip** (Python package manager)

### Steps

```bash
# 1. Clone the repository
git clone https://github.com/YOUR_USERNAME/ConfigScore.git
cd ConfigScore

# 2. Create a virtual environment
python -m venv .venv

# 3. Activate the virtual environment
# Windows (PowerShell):
.\.venv\Scripts\Activate.ps1
# Windows (CMD):
.\.venv\Scripts\activate.bat
# macOS/Linux:
source .venv/bin/activate

# 4. Install dependencies
pip install -r requirements.txt
```

---

## 💻 Usage

### Start the Development Server

```bash
# Option 1: Run directly
python app.py

# Option 2: Use Flask CLI
flask run --port 5050
```

The app will start at **http://127.0.0.1:5050/**

### Run a Scan
1. Open the app in your browser
2. Navigate to the **Scanner** page
3. Enter the website URL you want to scan
4. Click **Start Scan**
5. View the detailed results with score, findings, and fixes
6. Download the **PDF report** if needed

---

## 🏗️ Project Structure

```
ConfigScore/
├── app.py                  # Flask application entry point & routes
├── requirements.txt        # Python dependencies
├── run.py                  # Alternative runner script
├── run.bat                 # Windows batch launcher
│
├── scanner/                # Core scanning engine
│   ├── __init__.py
│   ├── engine.py           # URL validation, SSRF defense, TLS probing, score calculation
│   ├── checks.py           # 20 passive security checks implementation
│   └── report.py           # PDF report generation (ReportLab)
│
├── data/
│   └── topics.json         # Knowledge base for 20 security topics (deep-dive content)
│
├── templates/              # Jinja2 HTML templates
│   ├── base.html           # Base layout (navbar, footer, flash messages)
│   ├── index.html           # Homepage with hero section & feature pillars
│   ├── scanner.html        # Scan input form
│   ├── result.html         # Scan result dashboard
│   ├── cyber_security.html # Security topics hub (20 topics grouped by category)
│   ├── topic.html          # Individual topic deep-dive page
│   ├── insights.html       # Security insights & methodology
│   ├── about.html          # About page & ethical guidelines
│   └── 404.html            # Custom error page
│
├── static/
│   ├── css/style.css       # Custom CSS (purple & white theme)
│   ├── js/script.js        # Client-side JavaScript
│   └── img/                # Images and illustrations
│
├── test_scanner.py         # Unit tests for scanner engine
└── test_flask_routes.py    # Unit tests for Flask routes
```

---

## 🧪 Running Tests

```bash
# Run scanner tests
python -m pytest test_scanner.py -v

# Run route tests
python -m pytest test_flask_routes.py -v

# Run all tests
python -m pytest -v
```

---

## 🛠️ Tech Stack

| Layer | Technology |
|-------|-----------|
| **Backend** | Python 3, Flask 3 |
| **Frontend** | HTML5, CSS3 (Custom Theme), Jinja2 Templates |
| **Scanner** | `requests`, `ssl`, `socket`, `dnspython` |
| **PDF Reports** | ReportLab |
| **Fonts** | Inter, JetBrains Mono (Google Fonts) |

---

## 📋 Dependencies

```
Flask>=3.0.0
requests>=2.31.0
reportlab>=4.0.0
dnspython>=2.6.0
urllib3>=2.0.0
```

---

## 🤝 Contributing

Contributions are welcome! Feel free to:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/new-check`)
3. Commit your changes (`git commit -m 'Add new security check'`)
4. Push to the branch (`git push origin feature/new-check`)
5. Open a Pull Request

---

## 📄 License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.

---

## ⚠️ Disclaimer

ConfigScore is an **educational and defensive** security tool. It performs only passive HTTP, TLS, and DNS configuration queries. **Do not** use this tool to scan websites without proper authorization. The developers assume no liability for misuse.

---

<div align="center">

**Built with ❤️ using Python & Flask**

</div>
