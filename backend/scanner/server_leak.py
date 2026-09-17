import re
from typing import Dict, Any, List

LEAK_HEADERS = ["server", "x-powered-by", "x-aspnet-version", "x-generator", "x-runtime"]

def audit_server_leakage(headers: Dict[str, str]) -> List[Dict[str, Any]]:
    findings = []
    normalized_headers = {k.lower(): v for k, v in headers.items()}
    
    server_val = normalized_headers.get("server")
    powered_by = normalized_headers.get("x-powered-by")
    aspnet = normalized_headers.get("x-aspnet-version")

    # 1. Inspect Server header
    if server_val:
        # Check if version numbers are revealed, e.g., Apache/2.4.41 or nginx/1.18.0
        has_version = bool(re.search(r"\d+\.\d+", server_val))
        if has_version:
            findings.append({
                "id": "server-version-leak",
                "title": "Detailed Server Version Leaked",
                "category": "Server Hygiene",
                "severity": "MEDIUM",
                "status": "WARNING",
                "value": server_val,
                "description": f"The Server header discloses exact software versions ('{server_val}'). Attackers can use this to search for unpatched CVEs.",
                "recommendation": "Configure your server to omit version banners (e.g., 'ServerTokens Prod' in Apache or 'server_tokens off;' in Nginx).",
                "cwe": "CWE-200"
            })
        else:
            findings.append({
                "id": "server-generic",
                "title": "Server Header Masked / Generic",
                "category": "Server Hygiene",
                "severity": "LOW",
                "status": "PASS",
                "value": server_val,
                "description": f"Server banner ('{server_val}') does not disclose exact minor version numbers.",
                "recommendation": "Good practice. Optionally strip the Server header entirely.",
                "cwe": "CWE-200"
            })
    else:
        findings.append({
            "id": "server-hidden",
            "title": "Server Banner Stripped",
            "category": "Server Hygiene",
            "severity": "LOW",
            "status": "PASS",
            "value": "Hidden",
            "description": "The server does not send a Server identification header, preventing basic reconnaissance.",
            "recommendation": "Excellent server hardening.",
            "cwe": "CWE-200"
        })

    # 2. Inspect X-Powered-By
    if powered_by:
        findings.append({
            "id": "x-powered-by-leak",
            "title": "Technology Fingerprinted (X-Powered-By)",
            "category": "Server Hygiene",
            "severity": "MEDIUM",
            "status": "WARNING",
            "value": powered_by,
            "description": f"The application reveals its underlying framework ('{powered_by}').",
            "recommendation": "Disable X-Powered-By (e.g., 'app.disable(\"x-powered-by\")' in Express or 'expose_php = Off' in php.ini).",
            "cwe": "CWE-200"
        })
    else:
        findings.append({
            "id": "x-powered-by-hidden",
            "title": "Framework Signature Masked",
            "category": "Server Hygiene",
            "severity": "LOW",
            "status": "PASS",
            "value": "Hidden",
            "description": "No X-Powered-By header found.",
            "recommendation": "Good configuration.",
            "cwe": "CWE-200"
        })

    return findings
