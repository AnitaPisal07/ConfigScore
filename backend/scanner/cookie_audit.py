from typing import Dict, Any, List
from http.cookies import SimpleCookie

def audit_cookies(cookie_headers: List[str]) -> List[Dict[str, Any]]:
    findings = []
    
    if not cookie_headers:
        findings.append({
            "id": "cookie-none",
            "title": "No Direct Cookies Set",
            "category": "Cookies",
            "severity": "LOW",
            "status": "PASS",
            "value": "None",
            "description": "The server response does not set any cookies on the initial request.",
            "recommendation": "When setting session or authentication cookies, always enforce Secure, HttpOnly, and SameSite flags.",
            "cwe": "CWE-614"
        })
        return findings

    for raw_cookie in cookie_headers:
        cookie_obj = SimpleCookie()
        try:
            cookie_obj.load(raw_cookie)
        except Exception:
            continue

        for name, morsel in cookie_obj.items():
            cookie_str_lower = raw_cookie.lower()
            is_secure = "secure" in cookie_str_lower or bool(morsel.get("secure"))
            is_httponly = "httponly" in cookie_str_lower or bool(morsel.get("httponly"))
            samesite = morsel.get("samesite", "")
            if not samesite:
                # manual regex check if SimpleCookie didn't capture SameSite
                for part in cookie_str_lower.split(";"):
                    if "samesite" in part:
                        samesite = part.split("=")[-1].strip().capitalize()

            # 1. Check HttpOnly
            if not is_httponly:
                findings.append({
                    "id": f"cookie-{name}-httponly",
                    "title": f"Cookie '{name}' Missing HttpOnly",
                    "category": "Cookies",
                    "severity": "HIGH",
                    "status": "FAIL",
                    "value": f"Cookie: {name}",
                    "description": f"The cookie '{name}' lacks the HttpOnly attribute, allowing JavaScript (via XSS) to read or exfiltrate session data.",
                    "recommendation": f"Add the 'HttpOnly' directive to Set-Cookie: {name}=...; HttpOnly",
                    "cwe": "CWE-1004"
                })
            else:
                findings.append({
                    "id": f"cookie-{name}-httponly",
                    "title": f"Cookie '{name}' HttpOnly Protected",
                    "category": "Cookies",
                    "severity": "HIGH",
                    "status": "PASS",
                    "value": f"Cookie: {name} (HttpOnly)",
                    "description": "HttpOnly prevents client-side scripts from reading this cookie.",
                    "recommendation": "Good configuration.",
                    "cwe": "CWE-1004"
                })

            # 2. Check Secure Flag
            if not is_secure:
                findings.append({
                    "id": f"cookie-{name}-secure",
                    "title": f"Cookie '{name}' Missing Secure Flag",
                    "category": "Cookies",
                    "severity": "HIGH",
                    "status": "FAIL",
                    "value": f"Cookie: {name}",
                    "description": f"The cookie '{name}' can be transmitted in cleartext over unencrypted HTTP connections.",
                    "recommendation": f"Add the 'Secure' directive: Set-Cookie: {name}=...; Secure",
                    "cwe": "CWE-614"
                })
            else:
                findings.append({
                    "id": f"cookie-{name}-secure",
                    "title": f"Cookie '{name}' Enforces Secure Flag",
                    "category": "Cookies",
                    "severity": "HIGH",
                    "status": "PASS",
                    "value": f"Cookie: {name} (Secure)",
                    "description": "The cookie will only be transmitted across encrypted HTTPS connections.",
                    "recommendation": "Good configuration.",
                    "cwe": "CWE-614"
                })

            # 3. Check SameSite
            if not samesite or samesite.lower() == "none":
                findings.append({
                    "id": f"cookie-{name}-samesite",
                    "title": f"Cookie '{name}' Missing / Weak SameSite",
                    "category": "Cookies",
                    "severity": "MEDIUM",
                    "status": "WARNING",
                    "value": f"SameSite={samesite or 'Missing'}",
                    "description": f"Lacks strict cross-origin protection. Makes the application susceptible to Cross-Site Request Forgery (CSRF).",
                    "recommendation": f"Set SameSite to 'Lax' or 'Strict': Set-Cookie: {name}=...; SameSite=Lax",
                    "cwe": "CWE-1275"
                })
            else:
                findings.append({
                    "id": f"cookie-{name}-samesite",
                    "title": f"Cookie '{name}' SameSite Active ({samesite})",
                    "category": "Cookies",
                    "severity": "MEDIUM",
                    "status": "PASS",
                    "value": f"SameSite={samesite}",
                    "description": "Protects against unauthorized cross-site transmission during forged requests.",
                    "recommendation": "Good configuration.",
                    "cwe": "CWE-1275"
                })

    return findings
