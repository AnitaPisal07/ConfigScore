import time
import socket
from urllib.parse import urlparse
from typing import Dict, Any, List

from scanner.header_audit import audit_headers
from scanner.tls_audit import audit_tls
from scanner.cookie_audit import audit_cookies
from scanner.server_leak import audit_server_leakage
from scanner.dns_audit import audit_dns
from scoring.engine import calculate_score
from remediation.fixer import generate_remediations
from database import save_scan

def normalize_url(raw_url: str) -> Dict[str, str]:
    raw_url = raw_url.strip()
    if not raw_url.startswith("http://") and not raw_url.startswith("https://"):
        raw_url = "https://" + raw_url

    parsed = urlparse(raw_url)
    domain = parsed.hostname or raw_url
    scheme = parsed.scheme or "https"
    path = parsed.path if parsed.path else "/"
    port = parsed.port or (443 if scheme == "https" else 80)
    
    return {
        "full_url": f"{scheme}://{domain}{path}",
        "domain": domain,
        "scheme": scheme,
        "port": port
    }

async def run_security_scan(target_input: str) -> Dict[str, Any]:
    start_time = time.time()
    url_info = normalize_url(target_input)
    domain = url_info["domain"]
    full_url = url_info["full_url"]

    # 1. Resolve IP Address
    ip_address = "Unknown"
    try:
        ip_address = socket.gethostbyname(domain)
    except Exception:
        pass

    # 2. Fetch HTTP Headers via HTTPX or urllib
    response_headers = {}
    cookie_headers = []
    redirect_history = []
    status_code = 0
    
    try:
        import httpx
        async with httpx.AsyncClient(timeout=10.0, follow_redirects=True, verify=False) as client:
            resp = await client.get(full_url)
            status_code = resp.status_code
            response_headers = dict(resp.headers)
            cookie_headers = resp.headers.get_list("set-cookie") if hasattr(resp.headers, "get_list") else []
            redirect_history = [str(r.url) for r in resp.history]
    except ImportError:
        # Fallback to urllib standard library
        import urllib.request
        import ssl
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        req = urllib.request.Request(full_url, headers={"User-Agent": "ConfigScore-SecurityScanner/1.0"})
        try:
            with urllib.request.urlopen(req, timeout=10.0, context=ctx) as resp:
                status_code = resp.status
                response_headers = dict(resp.headers)
                cookie_headers = resp.headers.get_all("Set-Cookie", [])
        except Exception as err:
            response_headers = {}

    # 3. Execute Specialized Audits
    header_findings = audit_headers(response_headers)
    tls_findings = audit_tls(domain, port=url_info["port"])
    cookie_findings = audit_cookies(cookie_headers)
    server_findings = audit_server_leakage(response_headers)
    dns_findings = audit_dns(domain)

    all_findings: List[Dict[str, Any]] = (
        header_findings +
        tls_findings +
        cookie_findings +
        server_findings +
        dns_findings
    )

    # 4. Compute Score & Remediation
    score_data = calculate_score(all_findings)
    remediations = generate_remediations(all_findings)

    duration_ms = int((time.time() - start_time) * 1000)

    # 5. Save to Database
    scan_id = save_scan(
        target_url=full_url,
        domain=domain,
        score=score_data["score"],
        grade=score_data["grade"],
        status_counts=score_data["status_counts"],
        duration_ms=duration_ms,
        findings=all_findings,
        remediations=remediations
    )

    return {
        "scan_id": scan_id,
        "target_url": full_url,
        "domain": domain,
        "ip_address": ip_address,
        "status_code": status_code,
        "duration_ms": duration_ms,
        "score": score_data["score"],
        "grade": score_data["grade"],
        "grade_label": score_data["grade_label"],
        "grade_color": score_data["grade_color"],
        "status_counts": score_data["status_counts"],
        "category_stats": score_data["category_stats"],
        "findings": all_findings,
        "remediations": remediations,
        "raw_headers": response_headers
    }
