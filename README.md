# ConfigScore – Website Security Scanner

ConfigScore is a student-built web application for checking common website security configurations.

It performs passive security checks on HTTP/HTTPS responses, TLS settings, cookies, and DNS records. The scanner then gives a security score, shows individual findings, and provides practical suggestions for fixing missing configurations.

> **Ethical use:** Only scan websites that you own or have explicit permission to test.

## About the Project

ConfigScore was developed as a **Third Year B.Sc. Computer Science project** to understand how common web security configurations can be checked programmatically.

The project focuses on:

- Checking common website security configurations
- Showing a simple security score and risk level
- Explaining individual security findings
- Providing practical remediation examples
- Learning about HTTP security headers, TLS, cookies, and DNS security
- Generating a PDF report of scan results

The scanner is designed to be **passive and non-intrusive**. It does not send exploitation payloads.

## Main Features

- 20-point website security scan
- Security score from 0–100
- Risk level for scan results
- HTTP security header checks
- TLS and certificate checks
- Cookie security checks
- DNS security checks
- Server information leakage checks
- HTTP-to-HTTPS redirect tracking
- SSRF protection for internal/private addresses
- Individual security findings
- Practical remediation guidance
- Security topic / Deep Dive pages
- PDF security reports
- Responsive web interface

## Security Checks

ConfigScore currently checks these 20 areas:

| # | Security Check | Category |
|---|---|---|
| 1 | HTTPS | Transport & Encryption |
| 2 | HSTS | Transport & Encryption |
| 3 | Content Security Policy (CSP) | Header Security |
| 4 | X-Frame-Options | Header Security |
| 5 | X-Content-Type-Options | Header Security |
| 6 | X-XSS-Protection | Header Security |
| 7 | Referrer-Policy | Header Security |
| 8 | Permissions-Policy | Header Security |
| 9 | Secure Cookies | Cookie Security |
| 10 | HttpOnly Cookies | Cookie Security |
| 11 | SameSite Cookies | Cookie Security |
| 12 | TLS Version | Transport & Encryption |
| 13 | Certificate Validity | Transport & Encryption |
| 14 | Certificate Chain | Transport & Encryption |
| 15 | DNS CAA Records | DNS Security |
| 16 | DNSSEC | DNS Security |
| 17 | Server Header Leakage | Information Disclosure |
| 18 | X-Powered-By Leakage | Information Disclosure |
| 19 | HTTP to HTTPS Redirect | Transport & Encryption |
| 20 | Mixed Content | Transport & Encryption |

Each check can return one of these statuses:

- **PASS** – The configuration was detected and passed the check.
- **WARNING** – The configuration needs attention.
- **MISSING** – The expected security configuration was not found.
- **REVIEW** – The result needs manual review.

## How the Scanner Works

The basic flow is:

```text
Enter Website URL
       ↓
Validate URL
       ↓
Perform Passive Checks
       ↓
HTTP / HTTPS / TLS / Cookie / DNS Analysis
       ↓
Calculate Security Score
       ↓
Show Findings & Recommendations
       ↓
Generate PDF Report
```

## Deep Dive Topics

The project includes dedicated pages for the security topics checked by the scanner.

Each topic explains the relevant security configuration, why it matters, the problem that can occur when it is missing, and possible ways to fix it.

Where appropriate, configuration examples are provided for technologies such as:

- Nginx
- Apache
- Flask
- Express.js

## Technology Stack

| Part | Technology |
|---|---|
| Backend | Python, Flask |
| Frontend | HTML5, CSS3, Jinja2 |
| Scanner | Requests, SSL, Socket, dnspython |
| PDF Reports | ReportLab |
| Testing | Python test scripts |

## Project Structure

```text
ConfigScore/
│
├── app.py
├── requirements.txt
├── run.py
├── run.bat
│
├── scanner/
│   ├── __init__.py
│   ├── engine.py
│   ├── checks.py
│   └── report.py
│
├── data/
│   └── topics.json
│
├── templates/
│   ├── base.html
│   ├── index.html
│   ├── scanner.html
│   ├── result.html
│   ├── cyber_security.html
│   ├── topic.html
│   ├── insights.html
│   ├── about.html
│   └── 404.html
│
├── static/
│   ├── css/
│   │   └── style.css
│   ├── js/
│   │   └── script.js
│   └── img/
│
├── test_scanner.py
└── test_flask_routes.py
```

## Installation

### Requirements

- Python 3.10 or newer
- pip

### 1. Clone the repository

```bash
git clone https://github.com/YOUR_USERNAME/ConfigScore.git
cd ConfigScore
```

### 2. Create a virtual environment

**Windows:**

```bash
python -m venv .venv
.\.venv\Scripts\activate
```

**macOS / Linux:**

```bash
python3 -m venv .venv
source .venv/bin/activate
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

## Running the Project

You can start the application with:

```bash
python app.py
```

Or:

```bash
python run.py
```

The development server runs locally and can be opened in a browser.

## Running a Scan

1. Open ConfigScore.
2. Go to the **Scanner** page.
3. Enter a website URL that you are authorized to test.
4. Start the scan.
5. Review the security score and risk level.
6. Read the individual findings.
7. Check the recommended fixes.
8. Download the PDF report if required.

## Testing

The project includes tests for scanner functionality and Flask routes.

Run the scanner tests:

```bash
python test_scanner.py
```

Run the Flask route tests:

```bash
python test_flask_routes.py
```

## Security and Ethical Use

ConfigScore is intended for **defensive and educational purposes**.

The scanner uses passive HTTP, HTTPS, TLS, cookie, and DNS checks. It should only be used on websites for which you have permission to perform security configuration checks.

The project also includes protection against requests to internal and private network addresses.

## Limitations

ConfigScore is a configuration auditing tool, not a complete penetration-testing system.

A passing score does not mean that a website is completely secure. The scanner focuses on the security configurations implemented by the project and cannot identify every possible vulnerability in a web application.

Some results may also require manual review.

## Project Purpose

This project was created as part of a **B.Sc. Computer Science academic project** to learn and demonstrate:

- Web development with Flask
- Website security concepts
- HTTP security headers
- TLS and certificates
- Cookie security
- DNS security
- Security scoring
- PDF report generation
- Basic security testing

## License

This project is licensed under the MIT License. See the `LICENSE` file for details.

---

**ConfigScore – Website Security Scanner**

A student project for learning and demonstrating website security configuration auditing.
