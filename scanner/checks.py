"""
ConfigScore Security Checks
Implements 20 passive, defensive security configuration checks.
Each check returns a structured dictionary:
{
    "id": str,
    "title": str,
    "slug": str,
    "status": "PASS" | "WARNING" | "MISSING" | "REVIEW",
    "risk": "Low" | "Medium" | "High" | "Critical",
    "points_deducted": int,
    "observation": str,
    "technical_details": dict
}
"""

import re
from datetime import datetime, timezone


def check_https(scan_data):
    """Check 1: Evaluates if the website is accessible via HTTPS."""
    final_url = scan_data.get("final_url", "")
    is_https = final_url.startswith("https://")
    
    if is_https:
        return {
            "id": "https",
            "title": "HTTPS",
            "slug": "https",
            "status": "PASS",
            "risk": "Low",
            "points_deducted": 0,
            "observation": f"The website successfully established an encrypted HTTPS session ({final_url}).",
            "technical_details": {"final_url": final_url, "scheme": "https"}
        }
    else:
        return {
            "id": "https",
            "title": "HTTPS",
            "slug": "https",
            "status": "MISSING",
            "risk": "Critical",
            "points_deducted": 15,
            "observation": "The website is serving content over unencrypted HTTP. Transport encryption is not enforced.",
            "technical_details": {"final_url": final_url, "scheme": "http"}
        }


def check_ssl_tls(scan_data):
    """Check 2: Evaluates the TLS protocol version and negotiated cipher."""
    tls_info = scan_data.get("tls_info", {})
    protocol = tls_info.get("version", "")
    cipher = tls_info.get("cipher", "")

    if not protocol:
        return {
            "id": "ssl-tls",
            "title": "SSL/TLS Protocol Configuration",
            "slug": "ssl-tls",
            "status": "REVIEW",
            "risk": "High",
            "points_deducted": 0,
            "observation": "Could not inspect TLS handshake parameters directly. Verify that TLS 1.2 or 1.3 is configured.",
            "technical_details": {"tls_info": tls_info}
        }

    if "TLSv1.3" in protocol:
        return {
            "id": "ssl-tls",
            "title": "SSL/TLS Protocol Configuration",
            "slug": "ssl-tls",
            "status": "PASS",
            "risk": "Low",
            "points_deducted": 0,
            "observation": f"Server negotiated modern {protocol} using cipher suite {cipher}.",
            "technical_details": {"version": protocol, "cipher": cipher}
        }
    elif "TLSv1.2" in protocol:
        return {
            "id": "ssl-tls",
            "title": "SSL/TLS Protocol Configuration",
            "slug": "ssl-tls",
            "status": "PASS",
            "risk": "Low",
            "points_deducted": 0,
            "observation": f"Server negotiated secure {protocol}. Upgrading to TLS 1.3 is recommended for lower latency and modern ciphers.",
            "technical_details": {"version": protocol, "cipher": cipher}
        }
    elif any(old in protocol for old in ["TLSv1.0", "TLSv1.1", "SSLv3", "SSLv2"]):
        return {
            "id": "ssl-tls",
            "title": "SSL/TLS Protocol Configuration",
            "slug": "ssl-tls",
            "status": "MISSING",
            "risk": "Critical",
            "points_deducted": 10,
            "observation": f"Server accepted obsolete/insecure protocol version ({protocol}).",
            "technical_details": {"version": protocol, "cipher": cipher}
        }
    else:
        return {
            "id": "ssl-tls",
            "title": "SSL/TLS Protocol Configuration",
            "slug": "ssl-tls",
            "status": "REVIEW",
            "risk": "Medium",
            "points_deducted": 0,
            "observation": f"Negotiated protocol: {protocol}. Review cipher configuration against current industry standards.",
            "technical_details": {"version": protocol, "cipher": cipher}
        }


def check_hsts(scan_data):
    """Check 3: Evaluates the HTTP Strict Transport Security (HSTS) header."""
    headers = scan_data.get("headers", {})
    hsts = headers.get("strict-transport-security")

    if not hsts:
        return {
            "id": "hsts",
            "title": "HTTP Strict Transport Security (HSTS)",
            "slug": "hsts",
            "status": "MISSING",
            "risk": "High",
            "points_deducted": 8,
            "observation": "Strict-Transport-Security header is missing. Users could be vulnerable to SSL-stripping on initial visits.",
            "technical_details": {"header_present": False}
        }

    max_age_match = re.search(r"max-age=(\d+)", hsts, re.IGNORECASE)
    max_age = int(max_age_match.group(1)) if max_age_match else 0
    has_subdomains = "includesubdomains" in hsts.lower()
    has_preload = "preload" in hsts.lower()

    if max_age >= 15552000:  # >= 180 days
        obs = f"HSTS is active with max-age={max_age}s (~{max_age // 86400} days)."
        if has_subdomains:
            obs += " includeSubDomains is enabled."
        if has_preload:
            obs += " Preload flag is included."
        return {
            "id": "hsts",
            "title": "HTTP Strict Transport Security (HSTS)",
            "slug": "hsts",
            "status": "PASS",
            "risk": "Low",
            "points_deducted": 0,
            "observation": obs,
            "technical_details": {"raw": hsts, "max_age": max_age, "includeSubDomains": has_subdomains, "preload": has_preload}
        }
    else:
        return {
            "id": "hsts",
            "title": "HTTP Strict Transport Security (HSTS)",
            "slug": "hsts",
            "status": "WARNING",
            "risk": "Medium",
            "points_deducted": 4,
            "observation": f"HSTS max-age is set to {max_age}s ({max_age // 86400} days). Recommended duration is at least 15,552,000s (6 months) or 31,536,000s (1 year).",
            "technical_details": {"raw": hsts, "max_age": max_age, "includeSubDomains": has_subdomains, "preload": has_preload}
        }


def check_csp(scan_data):
    """Check 4: Evaluates Content Security Policy (CSP)."""
    headers = scan_data.get("headers", {})
    csp = headers.get("content-security-policy")
    csp_report = headers.get("content-security-policy-report-only")

    if not csp and not csp_report:
        return {
            "id": "csp",
            "title": "Content Security Policy (CSP)",
            "slug": "csp",
            "status": "MISSING",
            "risk": "Critical",
            "points_deducted": 10,
            "observation": "Content-Security-Policy header is missing. Browsers will execute any client-side scripts encountered without source origin restrictions.",
            "technical_details": {"header_present": False}
        }

    policy_to_check = csp if csp else csp_report
    directives = [d.strip() for d in policy_to_check.split(";") if d.strip()]
    has_unsafe_inline = "'unsafe-inline'" in policy_to_check.lower()
    has_unsafe_eval = "'unsafe-eval'" in policy_to_check.lower()
    has_wildcard = " *" in policy_to_check or "*;" in policy_to_check

    if csp_report and not csp:
        return {
            "id": "csp",
            "title": "Content Security Policy (CSP)",
            "slug": "csp",
            "status": "WARNING",
            "risk": "Medium",
            "points_deducted": 4,
            "observation": "CSP is present in Report-Only mode. Violations are reported but malicious resources are not actively blocked.",
            "technical_details": {"raw": policy_to_check, "report_only": True}
        }

    if has_unsafe_inline or has_unsafe_eval or has_wildcard:
        flaws = []
        if has_unsafe_inline:
            flaws.append("'unsafe-inline'")
        if has_unsafe_eval:
            flaws.append("'unsafe-eval'")
        if has_wildcard:
            flaws.append("wildcard origins (*)")
        return {
            "id": "csp",
            "title": "Content Security Policy (CSP)",
            "slug": "csp",
            "status": "WARNING",
            "risk": "Medium",
            "points_deducted": 5,
            "observation": f"CSP is deployed but contains permissive directives: {', '.join(flaws)}, which weaken defense against XSS.",
            "technical_details": {"raw": csp, "directives_count": len(directives), "weaknesses": flaws}
        }

    return {
        "id": "csp",
        "title": "Content Security Policy (CSP)",
        "slug": "csp",
        "status": "PASS",
        "risk": "Low",
        "points_deducted": 0,
        "observation": f"Content-Security-Policy is active with {len(directives)} directives and without unsafe wildcards.",
        "technical_details": {"raw": csp, "directives_count": len(directives)}
    }


def check_x_content_type_options(scan_data):
    """Check 5: Evaluates X-Content-Type-Options."""
    headers = scan_data.get("headers", {})
    xcto = headers.get("x-content-type-options")

    if not xcto:
        return {
            "id": "x-content-type-options",
            "title": "X-Content-Type-Options",
            "slug": "x-content-type-options",
            "status": "MISSING",
            "risk": "Medium",
            "points_deducted": 5,
            "observation": "X-Content-Type-Options header is absent. Browsers may sniff responses away from the declared MIME type.",
            "technical_details": {"header_present": False}
        }

    if xcto.strip().lower() == "nosniff":
        return {
            "id": "x-content-type-options",
            "title": "X-Content-Type-Options",
            "slug": "x-content-type-options",
            "status": "PASS",
            "risk": "Low",
            "points_deducted": 0,
            "observation": "X-Content-Type-Options is correctly configured with 'nosniff'.",
            "technical_details": {"raw": xcto}
        }
    else:
        return {
            "id": "x-content-type-options",
            "title": "X-Content-Type-Options",
            "slug": "x-content-type-options",
            "status": "WARNING",
            "risk": "Medium",
            "points_deducted": 2,
            "observation": f"X-Content-Type-Options is set to unexpected value '{xcto}'. Expected 'nosniff'.",
            "technical_details": {"raw": xcto}
        }


def check_x_frame_options(scan_data):
    """Check 6: Evaluates X-Frame-Options or CSP frame-ancestors."""
    headers = scan_data.get("headers", {})
    xfo = headers.get("x-frame-options")
    csp = headers.get("content-security-policy", "")
    has_frame_ancestors = "frame-ancestors" in csp.lower()

    if has_frame_ancestors:
        fa_match = re.search(r"frame-ancestors\s+([^;]+)", csp, re.IGNORECASE)
        fa_val = fa_match.group(1).strip() if fa_match else "configured"
        return {
            "id": "x-frame-options",
            "title": "X-Frame-Options (Clickjacking Protection)",
            "slug": "x-frame-options",
            "status": "PASS",
            "risk": "Low",
            "points_deducted": 0,
            "observation": f"Clickjacking protection is enforced via CSP frame-ancestors ({fa_val}).",
            "technical_details": {"mechanism": "CSP frame-ancestors", "policy": fa_val}
        }

    if not xfo:
        return {
            "id": "x-frame-options",
            "title": "X-Frame-Options (Clickjacking Protection)",
            "slug": "x-frame-options",
            "status": "MISSING",
            "risk": "High",
            "points_deducted": 8,
            "observation": "Neither X-Frame-Options nor CSP frame-ancestors is present. The site may be framed in a clickjacking attack.",
            "technical_details": {"header_present": False}
        }

    val = xfo.strip().upper()
    if val in ["DENY", "SAMEORIGIN"]:
        return {
            "id": "x-frame-options",
            "title": "X-Frame-Options (Clickjacking Protection)",
            "slug": "x-frame-options",
            "status": "PASS",
            "risk": "Low",
            "points_deducted": 0,
            "observation": f"X-Frame-Options is properly configured with '{val}'.",
            "technical_details": {"raw": xfo}
        }
    elif "ALLOW-FROM" in val:
        return {
            "id": "x-frame-options",
            "title": "X-Frame-Options (Clickjacking Protection)",
            "slug": "x-frame-options",
            "status": "WARNING",
            "risk": "Medium",
            "points_deducted": 4,
            "observation": "X-Frame-Options uses deprecated 'ALLOW-FROM'. Modern browsers ignore this; use CSP frame-ancestors instead.",
            "technical_details": {"raw": xfo}
        }
    else:
        return {
            "id": "x-frame-options",
            "title": "X-Frame-Options (Clickjacking Protection)",
            "slug": "x-frame-options",
            "status": "WARNING",
            "risk": "Medium",
            "points_deducted": 4,
            "observation": f"X-Frame-Options contains non-standard directive '{xfo}'.",
            "technical_details": {"raw": xfo}
        }


def check_referrer_policy(scan_data):
    """Check 7: Evaluates Referrer-Policy header."""
    headers = scan_data.get("headers", {})
    rp = headers.get("referrer-policy")

    if not rp:
        return {
            "id": "referrer-policy",
            "title": "Referrer-Policy",
            "slug": "referrer-policy",
            "status": "MISSING",
            "risk": "Medium",
            "points_deducted": 5,
            "observation": "Referrer-Policy header is missing. Default browser policy is applied which may leak URLs with query parameters.",
            "technical_details": {"header_present": False}
        }

    rp_clean = rp.strip().lower()
    secure_policies = ["strict-origin-when-cross-origin", "no-referrer", "same-origin", "strict-origin"]
    insecure_policies = ["unsafe-url", "no-referrer-when-downgrade"]

    if any(sp in rp_clean for sp in secure_policies):
        return {
            "id": "referrer-policy",
            "title": "Referrer-Policy",
            "slug": "referrer-policy",
            "status": "PASS",
            "risk": "Low",
            "points_deducted": 0,
            "observation": f"Referrer-Policy is securely configured as '{rp}'.",
            "technical_details": {"raw": rp}
        }
    elif any(ip in rp_clean for ip in insecure_policies):
        return {
            "id": "referrer-policy",
            "title": "Referrer-Policy",
            "slug": "referrer-policy",
            "status": "WARNING",
            "risk": "Medium",
            "points_deducted": 4,
            "observation": f"Referrer-Policy is set to '{rp}', which leaks complete request URLs (including query strings) to third parties.",
            "technical_details": {"raw": rp}
        }
    else:
        return {
            "id": "referrer-policy",
            "title": "Referrer-Policy",
            "slug": "referrer-policy",
            "status": "REVIEW",
            "risk": "Low",
            "points_deducted": 0,
            "observation": f"Referrer-Policy has custom value '{rp}'. Verify privacy alignment.",
            "technical_details": {"raw": rp}
        }


def check_permissions_policy(scan_data):
    """Check 8: Evaluates Permissions-Policy or Feature-Policy."""
    headers = scan_data.get("headers", {})
    pp = headers.get("permissions-policy")
    fp = headers.get("feature-policy")

    if pp:
        return {
            "id": "permissions-policy",
            "title": "Permissions-Policy",
            "slug": "permissions-policy",
            "status": "PASS",
            "risk": "Low",
            "points_deducted": 0,
            "observation": f"Permissions-Policy is declared, controlling browser hardware APIs and delegations.",
            "technical_details": {"raw": pp}
        }
    elif fp:
        return {
            "id": "permissions-policy",
            "title": "Permissions-Policy",
            "slug": "permissions-policy",
            "status": "WARNING",
            "risk": "Low",
            "points_deducted": 1,
            "observation": "Legacy Feature-Policy header detected. Migrate to the modern structured Permissions-Policy specification.",
            "technical_details": {"legacy_raw": fp}
        }
    else:
        return {
            "id": "permissions-policy",
            "title": "Permissions-Policy",
            "slug": "permissions-policy",
            "status": "MISSING",
            "risk": "Low",
            "points_deducted": 2,
            "observation": "Permissions-Policy header is missing. Unrestricted hardware access (camera, microphone, geolocation) can be requested by embedded frames.",
            "technical_details": {"header_present": False}
        }


def check_secure_cookies(scan_data):
    """Check 9: Evaluates the Secure flag on cookies."""
    cookies = scan_data.get("cookies", [])

    if not cookies:
        return {
            "id": "secure-cookies",
            "title": "Secure Cookie Flag",
            "slug": "secure-cookies",
            "status": "REVIEW",
            "risk": "Low",
            "points_deducted": 0,
            "observation": "No Set-Cookie headers were observed in the landing page response. Review authenticated session endpoints manually.",
            "technical_details": {"cookies_count": 0}
        }

    insecure_cookies = [c["name"] for c in cookies if not c.get("secure")]

    if not insecure_cookies:
        return {
            "id": "secure-cookies",
            "title": "Secure Cookie Flag",
            "slug": "secure-cookies",
            "status": "PASS",
            "risk": "Low",
            "points_deducted": 0,
            "observation": f"All {len(cookies)} detected cookie(s) enforce the 'Secure' transport flag.",
            "technical_details": {"cookies_count": len(cookies)}
        }
    else:
        return {
            "id": "secure-cookies",
            "title": "Secure Cookie Flag",
            "slug": "secure-cookies",
            "status": "MISSING",
            "risk": "High",
            "points_deducted": 8,
            "observation": f"{len(insecure_cookies)} cookie(s) lack the 'Secure' attribute: {', '.join(insecure_cookies[:3])}. They may be leaked over plaintext HTTP.",
            "technical_details": {"insecure_cookies": insecure_cookies}
        }


def check_httponly_cookies(scan_data):
    """Check 10: Evaluates the HttpOnly flag on cookies."""
    cookies = scan_data.get("cookies", [])

    if not cookies:
        return {
            "id": "httponly-cookies",
            "title": "HttpOnly Cookie Flag",
            "slug": "httponly-cookies",
            "status": "REVIEW",
            "risk": "Low",
            "points_deducted": 0,
            "observation": "No Set-Cookie headers were returned during initial inspection. Verify authenticated session cookies manually.",
            "technical_details": {"cookies_count": 0}
        }

    non_httponly = [c["name"] for c in cookies if not c.get("httponly")]

    if not non_httponly:
        return {
            "id": "httponly-cookies",
            "title": "HttpOnly Cookie Flag",
            "slug": "httponly-cookies",
            "status": "PASS",
            "risk": "Low",
            "points_deducted": 0,
            "observation": f"All {len(cookies)} detected cookie(s) include the 'HttpOnly' protection flag.",
            "technical_details": {"cookies_count": len(cookies)}
        }
    else:
        return {
            "id": "httponly-cookies",
            "title": "HttpOnly Cookie Flag",
            "slug": "httponly-cookies",
            "status": "WARNING",
            "risk": "High",
            "points_deducted": 6,
            "observation": f"{len(non_httponly)} cookie(s) lack the 'HttpOnly' flag: {', '.join(non_httponly[:3])}. Accessible via JavaScript document.cookie in case of XSS.",
            "technical_details": {"non_httponly_cookies": non_httponly}
        }


def check_samesite_cookies(scan_data):
    """Check 11: Evaluates the SameSite attribute on cookies."""
    cookies = scan_data.get("cookies", [])

    if not cookies:
        return {
            "id": "samesite-cookies",
            "title": "SameSite Cookie Attribute",
            "slug": "samesite-cookies",
            "status": "REVIEW",
            "risk": "Low",
            "points_deducted": 0,
            "observation": "No Set-Cookie headers observed. Verify CSRF protections on state-changing endpoints.",
            "technical_details": {"cookies_count": 0}
        }

    missing_samesite = [c["name"] for c in cookies if not c.get("samesite")]
    samesite_none = [c["name"] for c in cookies if c.get("samesite") == "none"]

    if not missing_samesite and not samesite_none:
        return {
            "id": "samesite-cookies",
            "title": "SameSite Cookie Attribute",
            "slug": "samesite-cookies",
            "status": "PASS",
            "risk": "Low",
            "points_deducted": 0,
            "observation": f"All {len(cookies)} cookie(s) declare SameSite (Lax or Strict) to mitigate CSRF.",
            "technical_details": {"cookies_count": len(cookies)}
        }
    elif samesite_none:
        return {
            "id": "samesite-cookies",
            "title": "SameSite Cookie Attribute",
            "slug": "samesite-cookies",
            "status": "WARNING",
            "risk": "Medium",
            "points_deducted": 4,
            "observation": f"Cookie(s) configured with SameSite=None: {', '.join(samesite_none[:3])}. Transmitted on cross-origin requests.",
            "technical_details": {"samesite_none": samesite_none}
        }
    else:
        return {
            "id": "samesite-cookies",
            "title": "SameSite Cookie Attribute",
            "slug": "samesite-cookies",
            "status": "WARNING",
            "risk": "Medium",
            "points_deducted": 4,
            "observation": f"Cookie(s) omit explicit SameSite attribute: {', '.join(missing_samesite[:3])}. Relying on browser-dependent default behaviors.",
            "technical_details": {"missing_samesite": missing_samesite}
        }


def check_cors(scan_data):
    """Check 12: Evaluates CORS configuration."""
    headers = scan_data.get("headers", {})
    acao = headers.get("access-control-allow-origin")
    acac = headers.get("access-control-allow-credentials", "").lower()

    if not acao:
        return {
            "id": "cors-configuration",
            "title": "CORS Configuration",
            "slug": "cors-configuration",
            "status": "PASS",
            "risk": "Low",
            "points_deducted": 0,
            "observation": "No open CORS headers returned. Standard Same-Origin Policy (SOP) is strictly enforced.",
            "technical_details": {"header_present": False}
        }

    if acao == "*":
        if acac == "true":
            return {
                "id": "cors-configuration",
                "title": "CORS Configuration",
                "slug": "cors-configuration",
                "status": "MISSING",
                "risk": "High",
                "points_deducted": 8,
                "observation": "Critical CORS misconfiguration: Wildcard '*' origin with Allow-Credentials: true.",
                "technical_details": {"acao": acao, "acac": acac}
            }
        else:
            return {
                "id": "cors-configuration",
                "title": "CORS Configuration",
                "slug": "cors-configuration",
                "status": "WARNING",
                "risk": "Medium",
                "points_deducted": 4,
                "observation": "Access-Control-Allow-Origin is set to '*'. Appropriate for public CDN assets, but hazardous if returning authenticated user data.",
                "technical_details": {"acao": acao}
            }
    else:
        return {
            "id": "cors-configuration",
            "title": "CORS Configuration",
            "slug": "cors-configuration",
            "status": "PASS",
            "risk": "Low",
            "points_deducted": 0,
            "observation": f"CORS is restricted to explicit origin: {acao}.",
            "technical_details": {"acao": acao}
        }


def check_server_disclosure(scan_data):
    """Check 13: Evaluates Server and X-Powered-By information disclosure."""
    headers = scan_data.get("headers", {})
    server = headers.get("server", "")
    x_powered_by = headers.get("x-powered-by", "")

    leaks = []
    has_version = bool(re.search(r"(\d+\.[\d\.]+)", server))

    if x_powered_by:
        leaks.append(f"X-Powered-By: {x_powered_by}")
    if has_version:
        leaks.append(f"Server version: {server}")

    if leaks:
        return {
            "id": "server-disclosure",
            "title": "Server Information Disclosure",
            "slug": "server-disclosure",
            "status": "WARNING",
            "risk": "Low",
            "points_deducted": 3,
            "observation": f"Backend technology details exposed: {'; '.join(leaks)}. This facilitates targeted CVE scanning.",
            "technical_details": {"server": server, "x_powered_by": x_powered_by}
        }
    elif server:
        return {
            "id": "server-disclosure",
            "title": "Server Information Disclosure",
            "slug": "server-disclosure",
            "status": "PASS",
            "risk": "Low",
            "points_deducted": 0,
            "observation": f"Server token is generic or masked ('{server}'). No exact version numbers leaked.",
            "technical_details": {"server": server}
        }
    else:
        return {
            "id": "server-disclosure",
            "title": "Server Information Disclosure",
            "slug": "server-disclosure",
            "status": "PASS",
            "risk": "Low",
            "points_deducted": 0,
            "observation": "No Server or X-Powered-By banner headers detected. Fingerprinting minimized.",
            "technical_details": {"server": None, "x_powered_by": None}
        }


def check_cache_control(scan_data):
    """Check 14: Evaluates Cache-Control header."""
    headers = scan_data.get("headers", {})
    cc = headers.get("cache-control")

    if not cc:
        return {
            "id": "cache-control",
            "title": "Cache-Control Security",
            "slug": "cache-control",
            "status": "MISSING",
            "risk": "Low",
            "points_deducted": 2,
            "observation": "Cache-Control header is missing on the inspected response.",
            "technical_details": {"header_present": False}
        }

    cc_clean = cc.lower()
    if "no-store" in cc_clean:
        return {
            "id": "cache-control",
            "title": "Cache-Control Security",
            "slug": "cache-control",
            "status": "PASS",
            "risk": "Low",
            "points_deducted": 0,
            "observation": f"Response prohibits caching ('no-store'), preventing data retention on shared devices.",
            "technical_details": {"raw": cc}
        }
    elif "public" in cc_clean:
        return {
            "id": "cache-control",
            "title": "Cache-Control Security",
            "slug": "cache-control",
            "status": "REVIEW",
            "risk": "Low",
            "points_deducted": 0,
            "observation": f"Response contains 'public' caching directives ('{cc}'). Normal for landing pages; ensure private routes declare 'no-store'.",
            "technical_details": {"raw": cc}
        }
    else:
        return {
            "id": "cache-control",
            "title": "Cache-Control Security",
            "slug": "cache-control",
            "status": "PASS",
            "risk": "Low",
            "points_deducted": 0,
            "observation": f"Cache-Control directive specified: '{cc}'.",
            "technical_details": {"raw": cc}
        }


def check_dns_security(scan_data):
    """Check 15: Evaluates DNS CAA records."""
    dns_info = scan_data.get("dns_info", {})
    caa_records = dns_info.get("caa", [])
    spf_records = dns_info.get("spf", [])

    if caa_records:
        return {
            "id": "dns-security",
            "title": "DNS Security & CAA Records",
            "slug": "dns-security",
            "status": "PASS",
            "risk": "Low",
            "points_deducted": 0,
            "observation": f"DNS CAA record(s) found: {', '.join(caa_records[:3])}. Unauthorized CAs are forbidden from issuing certificates.",
            "technical_details": {"caa_records": caa_records, "spf_records": spf_records}
        }
    else:
        return {
            "id": "dns-security",
            "title": "DNS Security & CAA Records",
            "slug": "dns-security",
            "status": "WARNING",
            "risk": "Medium",
            "points_deducted": 4,
            "observation": "No DNS CAA (Certification Authority Authorization) records found. Any public CA worldwide may issue certificates for this domain.",
            "technical_details": {"caa_records": [], "spf_records": spf_records}
        }


def check_cert_validity(scan_data):
    """Check 16: Evaluates certificate validity and trust chain."""
    tls_info = scan_data.get("tls_info", {})
    valid = tls_info.get("cert_valid")
    error = tls_info.get("cert_error")
    issuer = tls_info.get("issuer", {})
    subject = tls_info.get("subject", {})

    if valid:
        issuer_org = issuer.get("organizationName") or issuer.get("commonName") or "Trusted CA"
        return {
            "id": "cert-validity",
            "title": "Certificate Validity & Trust Chain",
            "slug": "cert-validity",
            "status": "PASS",
            "risk": "Low",
            "points_deducted": 0,
            "observation": f"SSL/TLS certificate is valid and issued by {issuer_org}.",
            "technical_details": {"issuer": issuer, "subject": subject}
        }
    elif error:
        return {
            "id": "cert-validity",
            "title": "Certificate Validity & Trust Chain",
            "slug": "cert-validity",
            "status": "MISSING",
            "risk": "Critical",
            "points_deducted": 15,
            "observation": f"Certificate validation error: {error}. Browsers will display severe security warnings.",
            "technical_details": {"error": error}
        }
    else:
        return {
            "id": "cert-validity",
            "title": "Certificate Validity & Trust Chain",
            "slug": "cert-validity",
            "status": "REVIEW",
            "risk": "Medium",
            "points_deducted": 0,
            "observation": "Certificate details could not be parsed automatically. Review TLS configuration.",
            "technical_details": {}
        }


def check_cert_expiry(scan_data):
    """Check 17: Evaluates certificate remaining lifetime."""
    tls_info = scan_data.get("tls_info", {})
    days_left = tls_info.get("days_left")

    if days_left is None:
        return {
            "id": "cert-expiry",
            "title": "Certificate Expiry & Renewal Horizon",
            "slug": "cert-expiry",
            "status": "REVIEW",
            "risk": "Medium",
            "points_deducted": 0,
            "observation": "Certificate expiration timestamp unavailable.",
            "technical_details": {}
        }

    if days_left <= 0:
        return {
            "id": "cert-expiry",
            "title": "Certificate Expiry & Renewal Horizon",
            "slug": "cert-expiry",
            "status": "MISSING",
            "risk": "Critical",
            "points_deducted": 15,
            "observation": f"Certificate has EXPIRED ({abs(days_left)} days ago). Immediate replacement is necessary.",
            "technical_details": {"days_left": days_left}
        }
    elif days_left < 30:
        return {
            "id": "cert-expiry",
            "title": "Certificate Expiry & Renewal Horizon",
            "slug": "cert-expiry",
            "status": "WARNING",
            "risk": "High",
            "points_deducted": 6,
            "observation": f"Certificate will expire in {days_left} days. Automated renewal should be initiated immediately.",
            "technical_details": {"days_left": days_left}
        }
    else:
        return {
            "id": "cert-expiry",
            "title": "Certificate Expiry & Renewal Horizon",
            "slug": "cert-expiry",
            "status": "PASS",
            "risk": "Low",
            "points_deducted": 0,
            "observation": f"Certificate is valid for {days_left} more days.",
            "technical_details": {"days_left": days_left}
        }


def check_mixed_content(scan_data):
    """Check 18: Checks for mixed content risks."""
    final_url = scan_data.get("final_url", "")
    is_https = final_url.startswith("https://")
    csp = scan_data.get("headers", {}).get("content-security-policy", "").lower()
    body_text = scan_data.get("body_sample", "")

    if not is_https:
        return {
            "id": "mixed-content",
            "title": "Mixed Content Prevention",
            "slug": "mixed-content",
            "status": "REVIEW",
            "risk": "Medium",
            "points_deducted": 0,
            "observation": "Target is serving over HTTP; mixed content analysis applies only to HTTPS origins.",
            "technical_details": {}
        }

    has_upgrade = "upgrade-insecure-requests" in csp

    # Scan body snippet for plaintext http sub-resources
    insecure_refs = re.findall(r'(?:src|href)=["\'](http://[^"\']+\.(?:js|css|png|jpg|jpeg|gif|svg|ico|woff|woff2))["\']', body_text, re.IGNORECASE)

    if insecure_refs:
        return {
            "id": "mixed-content",
            "title": "Mixed Content Prevention",
            "slug": "mixed-content",
            "status": "MISSING",
            "risk": "High",
            "points_deducted": 8,
            "observation": f"Insecure HTTP sub-resource links detected on HTTPS page ({len(insecure_refs)} instance(s) found in initial HTML).",
            "technical_details": {"insecure_resources": insecure_refs[:5]}
        }
    elif has_upgrade:
        return {
            "id": "mixed-content",
            "title": "Mixed Content Prevention",
            "slug": "mixed-content",
            "status": "PASS",
            "risk": "Low",
            "points_deducted": 0,
            "observation": "HTTPS is enforced and CSP 'upgrade-insecure-requests' directive automatically upgrades HTTP sub-resources.",
            "technical_details": {"upgrade_insecure_requests": True}
        }
    else:
        return {
            "id": "mixed-content",
            "title": "Mixed Content Prevention",
            "slug": "mixed-content",
            "status": "REVIEW",
            "risk": "Low",
            "points_deducted": 0,
            "observation": "No plaintext resource references found in landing page markup. Adding 'upgrade-insecure-requests' to CSP is recommended for defense-in-depth.",
            "technical_details": {"upgrade_insecure_requests": False}
        }


def check_redirect_security(scan_data):
    """Check 19: Evaluates HTTP to HTTPS redirection and redirect chain."""
    redirect_chain = scan_data.get("redirect_chain", [])

    if not redirect_chain or len(redirect_chain) == 0:
        return {
            "id": "redirect-security",
            "title": "Redirect Security & HTTP Redirection",
            "slug": "redirect-security",
            "status": "REVIEW",
            "risk": "Low",
            "points_deducted": 0,
            "observation": "Direct connection on target URL without initial redirection observed.",
            "technical_details": {"redirect_chain": []}
        }

    # Analyze hops
    has_insecure_hop_after_https = False
    reached_https = False
    initial_redirect_code = None

    for hop in redirect_chain:
        url = hop.get("url", "")
        code = hop.get("status_code")

        if url.startswith("https://"):
            reached_https = True
        elif reached_https and url.startswith("http://"):
            has_insecure_hop_after_https = True

        if initial_redirect_code is None and code in [301, 302, 307, 308]:
            initial_redirect_code = code

    final_url = scan_data.get("final_url", "")
    final_is_https = final_url.startswith("https://")

    if has_insecure_hop_after_https:
        return {
            "id": "redirect-security",
            "title": "Redirect Security & HTTP Redirection",
            "slug": "redirect-security",
            "status": "MISSING",
            "risk": "High",
            "points_deducted": 8,
            "observation": "Insecure redirect downgrade detected in hop chain: connection transitioned from HTTPS back to HTTP.",
            "technical_details": {"chain": redirect_chain}
        }

    if final_is_https and initial_redirect_code in [301, 308]:
        return {
            "id": "redirect-security",
            "title": "Redirect Security & HTTP Redirection",
            "slug": "redirect-security",
            "status": "PASS",
            "risk": "Low",
            "points_deducted": 0,
            "observation": f"Clean permanent redirection ({initial_redirect_code}) to HTTPS confirmed across {len(redirect_chain)} hop(s).",
            "technical_details": {"chain": redirect_chain}
        }
    elif final_is_https and initial_redirect_code in [302, 307]:
        return {
            "id": "redirect-security",
            "title": "Redirect Security & HTTP Redirection",
            "slug": "redirect-security",
            "status": "WARNING",
            "risk": "Low",
            "points_deducted": 2,
            "observation": f"Temporary redirect ({initial_redirect_code}) used instead of permanent (301/308) redirect to HTTPS.",
            "technical_details": {"chain": redirect_chain}
        }
    elif not final_is_https:
        return {
            "id": "redirect-security",
            "title": "Redirect Security & HTTP Redirection",
            "slug": "redirect-security",
            "status": "MISSING",
            "risk": "High",
            "points_deducted": 8,
            "observation": "Target does not redirect HTTP traffic to secure HTTPS.",
            "technical_details": {"chain": redirect_chain}
        }
    else:
        return {
            "id": "redirect-security",
            "title": "Redirect Security & HTTP Redirection",
            "slug": "redirect-security",
            "status": "PASS",
            "risk": "Low",
            "points_deducted": 0,
            "observation": "Redirect flow verified successfully.",
            "technical_details": {"chain": redirect_chain}
        }


def check_security_headers_overall(scan_data):
    """Check 20: Evaluates holistic defense-in-depth header posture."""
    headers = scan_data.get("headers", {})
    key_headers = [
        ("Strict-Transport-Security", "strict-transport-security"),
        ("Content-Security-Policy", "content-security-policy"),
        ("X-Content-Type-Options", "x-content-type-options"),
        ("X-Frame-Options", "x-frame-options"),
        ("Referrer-Policy", "referrer-policy"),
        ("Permissions-Policy", "permissions-policy")
    ]

    present = [display for display, key in key_headers if key in headers]
    missing = [display for display, key in key_headers if key not in headers]

    count = len(present)

    if count >= 5:
        return {
            "id": "security-headers-overall",
            "title": "Security Headers Overall Configuration",
            "slug": "security-headers-overall",
            "status": "PASS",
            "risk": "Low",
            "points_deducted": 0,
            "observation": f"Strong defense-in-depth: {count} of 6 core security headers are active ({', '.join(present)}).",
            "technical_details": {"present": present, "missing": missing, "count": count}
        }
    elif count >= 3:
        return {
            "id": "security-headers-overall",
            "title": "Security Headers Overall Configuration",
            "slug": "security-headers-overall",
            "status": "WARNING",
            "risk": "Medium",
            "points_deducted": 4,
            "observation": f"Moderate coverage: {count} of 6 headers active. Still missing: {', '.join(missing)}.",
            "technical_details": {"present": present, "missing": missing, "count": count}
        }
    else:
        return {
            "id": "security-headers-overall",
            "title": "Security Headers Overall Configuration",
            "slug": "security-headers-overall",
            "status": "MISSING",
            "risk": "High",
            "points_deducted": 8,
            "observation": f"Inadequate header protection: Only {count} of 6 core security headers configured. Missing: {', '.join(missing)}.",
            "technical_details": {"present": present, "missing": missing, "count": count}
        }


# Registry of all 20 checks in sequential order
ALL_CHECKS = [
    check_https,
    check_ssl_tls,
    check_hsts,
    check_csp,
    check_x_content_type_options,
    check_x_frame_options,
    check_referrer_policy,
    check_permissions_policy,
    check_secure_cookies,
    check_httponly_cookies,
    check_samesite_cookies,
    check_cors,
    check_server_disclosure,
    check_cache_control,
    check_dns_security,
    check_cert_validity,
    check_cert_expiry,
    check_mixed_content,
    check_redirect_security,
    check_security_headers_overall
]


def run_all_checks(scan_data):
    """Executes all 20 passive security checks against raw scan data."""
    results = []
    for check_fn in ALL_CHECKS:
        try:
            res = check_fn(scan_data)
            results.append(res)
        except Exception as e:
            # Safe fallback so a single check error never crashes the scan
            results.append({
                "id": check_fn.__name__.replace("check_", "").replace("_", "-"),
                "title": check_fn.__name__.replace("check_", "").replace("_", " ").title(),
                "slug": check_fn.__name__.replace("check_", "").replace("_", "-"),
                "status": "REVIEW",
                "risk": "Low",
                "points_deducted": 0,
                "observation": f"Check could not be evaluated due to an unexpected parsing condition: {str(e)}",
                "technical_details": {"error": str(e)}
            })
    return results
