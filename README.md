# ConfigScore: Website Security Scanner 

A full-stack, non-intrusive web security posture scanner and configuration auditor designed for **Third Year (TY) Computer Science** project submission.

---

## 📌 Project Overview
Web application security often fails not because of complex zero-day bugs, but due to **misconfigured HTTP response headers, weak SSL/TLS certificates, unhardened cookies, and server information disclosure**.

**ConfigScore** performs passive, RFC-compliant security audits on any website URL, calculates an overall security health score (**0 to 100**) with letter grades (**A+ to F**), and generates **ready-to-use copy-paste configuration code** for Nginx, Apache, Node.js (Express), Python (FastAPI), and Next.js.

---

## 🚀 Key Features

1. **🛡️ HTTP Security Header Auditing:**
   - **Content-Security-Policy (CSP):** Mitigates Cross-Site Scripting (XSS) and code injection (CWE-79).
   - **Strict-Transport-Security (HSTS):** Defends against Man-in-the-Middle (MITM) and SSL-stripping attacks (CWE-319).
   - **X-Frame-Options (XFO):** Defends against UI Redressing & Clickjacking attacks (CWE-1021).
   - **X-Content-Type-Options:** Prevents MIME-type confusion / sniffing exploits (CWE-430).
   - **Referrer-Policy:** Protects against sensitive query token / PII leakage (CWE-200).
   - **Permissions-Policy:** Restricts browser access to camera, microphone, and geolocation APIs.

2. **🔒 SSL / TLS Handshake & Certificate Verification:**
   - Live socket negotiation over port 443.
   - Certificate issuer and expiration tracking (warns on $< 30$ days validity).
   - Checks TLS protocol versions (TLS 1.2, TLS 1.3 vs. deprecated TLS 1.0/1.1/SSLv3).

3. **🍪 Cookie Hygiene & Session Security:**
   - Audits `Set-Cookie` directives for `HttpOnly` (stops cookie theft via XSS).
   - Checks `Secure` flag (enforces HTTPS-only cookie transmission).
   - Audits `SameSite` (`Lax` / `Strict`) to prevent Cross-Site Request Forgery (CSRF).

4. **🕵️ Server Hardening & Information Disclosure:**
   - Flags version disclosures in the `Server` header (e.g., `Apache/2.4.41`).
   - Flags framework fingerprinting via `X-Powered-By` (e.g., `Express`, `PHP/7.4`).

5. **🛠️ Automated Remediation Engine ("The Solver"):**
   - For every failed test, generates one-click copyable config code for **Nginx**, **Apache**, **Express.js (Helmet)**, and **FastAPI / Flask**.

6. **📈 Scan History & Printable PDF Report:**
   - SQLite persistent database storing past audits.
   - Built-in printable / PDF format for college report submissions.

---

## 🏗️ System Architecture

```
User Browser (Modern Cyber Dashboard)
       │  POST /api/scan {"url": "..."}
       ▼
FastAPI Application Server (Backend)
       │
       ├──► Header Auditor (CSP, HSTS, XFO, etc.)
       ├──► TLS Auditor (Direct socket & SSL handshake)
       ├──► Cookie Auditor (HttpOnly, Secure, SameSite)
       ├──► Server Leak Auditor (Banner grabbing)
       └──► DNS & SPF Auditor (SPF, DMARC records)
       │
       ▼
Scoring & Grade Engine (Weighted 0-100 & A+ to F)
       │
       ▼
Remediation Generator (Nginx / Apache / Express / Python)
       │
       ▼
SQLite Database (configscore.db) & JSON Response
```

---

## 📂 Project Directory Structure

```
configscore/
│
├── backend/
│   ├── scanner/
│   │   ├── header_audit.py     # HTTP security headers checks
│   │   ├── tls_audit.py        # SSL cert & TLS protocol handshake
│   │   ├── cookie_audit.py     # Set-Cookie flags inspection
│   │   ├── server_leak.py      # Banner grabbing & version disclosure
│   │   └── dns_audit.py        # SPF & DMARC DNS records
│   ├── scoring/
│   │   └── engine.py           # Score calculation (0-100) and letter grades
│   ├── remediation/
│   │   └── fixer.py            # Code snippet generator for all servers
│   ├── database.py             # SQLite database manager
│   ├── main.py                 # FastAPI REST API & static file server
│   └── requirements.txt        # Python backend dependencies
│
├── frontend/
│   └── index.html              # Modern dark-mode cyber dashboard
│
├── run.py                      # One-click cross-platform launcher
├── run.bat                     # Windows 1-click batch launcher
└── README.md                   # Complete documentation & Viva guide
```

---

## ⚡ How to Run the Project

### Method 1: Double-Click (Windows)
Double-click `run.bat` in this folder. It will automatically check Python, install required packages, start the server, and open your browser to `http://localhost:8000`.

### Method 2: Terminal / Command Prompt
```bash
# Navigate to project folder
cd C:\Users\Anita\.gemini\antigravity\scratch\configscore

# Run launcher
python run.py
```

Once running:
- **Web Dashboard:** `http://localhost:8000`
- **Interactive API Docs (Swagger UI):** `http://localhost:8000/docs`

---

## 🎓 Viva Voce & Presentation Q&A Guide

**Q1: Is this tool a penetration testing / offensive hacking tool?**
> *Answer:* No, ConfigScore is a **passive, non-intrusive security configuration auditor**. It operates purely by analyzing publicly returned HTTP headers, SSL certificates, and DNS records. It sends standard RFC-compliant requests without exploiting vulnerabilities or attempting unauthorized access.

**Q2: How does your tool mitigate Clickjacking?**
> *Answer:* It verifies the presence of the `X-Frame-Options` header (`DENY` or `SAMEORIGIN`) and the CSP `frame-ancestors` directive. These tell the web browser never to render the webpage inside an invisible `<iframe>` on a third-party attacker's website.

**Q3: Why is `HttpOnly` important for cookies?**
> *Answer:* If a website suffers from a Cross-Site Scripting (XSS) vulnerability, an attacker can execute `document.cookie` to steal session tokens. The `HttpOnly` flag instructs the browser to block JavaScript from accessing the cookie, effectively preventing session hijacking.

**Q4: How is the ConfigScore calculated?**
> *Answer:* The algorithm starts at a base score of 100 points and applies weighted deductions based on vulnerability severity:
> - Critical issues (Missing HSTS, Missing CSP): $-15$ points
> - High issues (Missing XFO, Insecure Cookies): $-10$ points
> - Medium issues (Version disclosure, Missing SameSite): $-6$ points
> - Low issues (Missing Referrer-Policy, Permissions-Policy): $-3$ points
> The final score maps to academic letter grades from **A+** (95+) down to **F** ($< 35$).
