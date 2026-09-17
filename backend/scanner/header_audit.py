from typing import Dict, Any, List

HEADER_DEFINITIONS = {
    "content-security-policy": {
        "name": "Content-Security-Policy",
        "category": "Headers",
        "severity": "CRITICAL",
        "description": "Prevents Cross-Site Scripting (XSS), Clickjacking, and other code injection attacks by restricting where scripts, images, and styles can be loaded from.",
        "recommended": "default-src 'self'; script-src 'self' https:; object-src 'none';",
        "cwe": "CWE-79"
    },
    "strict-transport-security": {
        "name": "Strict-Transport-Security",
        "category": "Headers",
        "severity": "CRITICAL",
        "description": "Enforces secure HTTPS connections, preventing Man-in-the-Middle (MITM) attacks and SSL-stripping downgrade attempts.",
        "recommended": "max-age=31536000; includeSubDomains; preload",
        "cwe": "CWE-319"
    },
    "x-frame-options": {
        "name": "X-Frame-Options",
        "category": "Headers",
        "severity": "HIGH",
        "description": "Protects against Clickjacking attacks by forbidding browsers from rendering the webpage inside an iframe or frame.",
        "recommended": "DENY or SAMEORIGIN",
        "cwe": "CWE-1021"
    },
    "x-content-type-options": {
        "name": "X-Content-Type-Options",
        "category": "Headers",
        "severity": "MEDIUM",
        "description": "Prevents MIME-type sniffing attacks, stopping browsers from executing non-executable files (like images) as JavaScript.",
        "recommended": "nosniff",
        "cwe": "CWE-430"
    },
    "referrer-policy": {
        "name": "Referrer-Policy",
        "category": "Headers",
        "severity": "LOW",
        "description": "Controls how much referrer information (like sensitive URLs or query tokens) is sent to external sites when navigating away.",
        "recommended": "strict-origin-when-cross-origin",
        "cwe": "CWE-200"
    },
    "permissions-policy": {
        "name": "Permissions-Policy",
        "category": "Headers",
        "severity": "LOW",
        "description": "Restricts browser features and hardware APIs such as camera, microphone, geolocation, and payment gateways.",
        "recommended": "camera=(), microphone=(), geolocation=()",
        "cwe": "CWE-250"
    },
    "cross-origin-opener-policy": {
        "name": "Cross-Origin-Opener-Policy",
        "category": "Headers",
        "severity": "LOW",
        "description": "Isolates the browsing context to defend against Spectre-style cross-origin timing attacks.",
        "recommended": "same-origin",
        "cwe": "CWE-346"
    }
}

def audit_headers(headers: Dict[str, str]) -> List[Dict[str, Any]]:
    findings = []
    # normalize header keys to lowercase
    normalized_headers = {k.lower(): v for k, v in headers.items()}

    for header_key, meta in HEADER_DEFINITIONS.items():
        val = normalized_headers.get(header_key)
        
        if val is None:
            findings.append({
                "id": f"header-{header_key}",
                "title": f"Missing {meta['name']}",
                "category": meta["category"],
                "severity": meta["severity"],
                "status": "FAIL",
                "value": None,
                "description": meta["description"],
                "recommendation": f"Configure '{meta['name']}' header: {meta['recommended']}",
                "cwe": meta["cwe"]
            })
        else:
            # Analyze quality of present header
            status = "PASS"
            msg = f"Configured properly: {val}"
            
            if header_key == "strict-transport-security":
                if "max-age" not in val.lower():
                    status = "WARNING"
                    msg = "HSTS header present but missing 'max-age' directive."
                elif "includesubdomains" not in val.lower():
                    status = "PASS"
                    msg = f"HSTS is active ({val}), but consider adding 'includeSubDomains'."

            elif header_key == "x-frame-options":
                val_upper = val.strip().upper()
                if val_upper not in ["DENY", "SAMEORIGIN"]:
                    status = "WARNING"
                    msg = f"Value '{val}' may not be supported across all modern browsers. Recommend 'DENY' or 'SAMEORIGIN'."

            elif header_key == "x-content-type-options":
                if val.strip().lower() != "nosniff":
                    status = "WARNING"
                    msg = f"Invalid value '{val}'. Must be strictly 'nosniff'."

            findings.append({
                "id": f"header-{header_key}",
                "title": f"{meta['name']} Detected",
                "category": meta["category"],
                "severity": meta["severity"],
                "status": status,
                "value": val,
                "description": meta["description"],
                "recommendation": msg,
                "cwe": meta["cwe"]
            })

    return findings
