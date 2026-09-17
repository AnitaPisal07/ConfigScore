"""
ConfigScore Scanner Engine
Handles URL validation, SSRF defense, network inspection, TLS probing,
passive DNS checks, check execution, and score calculation.
"""

import ipaddress
import json
import os
import re
import socket
import ssl
import time
import urllib.parse
from datetime import datetime, timezone
import requests
import urllib3

from .checks import run_all_checks

# Suppress insecure request warnings during passive inspection
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Load topic remediation data
TOPICS_PATH = os.path.join(os.path.dirname(__file__), "..", "data", "topics.json")
TOPICS_MAP = {}
if os.path.exists(TOPICS_PATH):
    try:
        with open(TOPICS_PATH, "r", encoding="utf-8") as f:
            topics_list = json.load(f)
            TOPICS_MAP = {t["id"]: t for t in topics_list}
    except Exception as e:
        print(f"Warning: Could not load topics.json: {e}")


def is_private_or_restricted_ip(ip_str):
    """
    Validates whether an IP address is private, loopback, link-local,
    reserved, or belongs to cloud metadata (SSRF defense).
    """
    try:
        ip = ipaddress.ip_address(ip_str)
        return (
            ip.is_private or
            ip.is_loopback or
            ip.is_link_local or
            ip.is_reserved or
            ip.is_multicast or
            ip.is_unspecified or
            str(ip) == "169.254.169.254" or  # Cloud metadata service
            str(ip).startswith("0.")
        )
    except ValueError:
        return True


def validate_and_normalize_url(raw_url):
    """
    Normalizes and validates user-submitted URL.
    Blocks non-HTTP schemes and internal/private hostnames.
    """
    if not raw_url:
        raise ValueError("Please provide a website URL to scan.")

    cleaned = raw_url.strip()
    if not re.match(r"^[a-zA-Z]+://", cleaned):
        cleaned = "https://" + cleaned

    parsed = urllib.parse.urlparse(cleaned)

    if parsed.scheme not in ["http", "https"]:
        raise ValueError("Only HTTP and HTTPS URLs are supported.")

    hostname = parsed.hostname
    if not hostname:
        raise ValueError("Invalid URL: Missing hostname.")

    # Block obvious local names
    hostname_lower = hostname.lower()
    blocked_hostnames = ["localhost", "127.0.0.1", "::1", "0.0.0.0"]
    if hostname_lower in blocked_hostnames or hostname_lower.endswith((".local", ".internal", ".lan", ".home")):
        raise ValueError(f"Scanning internal or local host '{hostname}' is not permitted.")

    # Resolve IP and verify SSRF protection
    try:
        addr_info = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
        resolved_ips = list(set([item[4][0] for item in addr_info]))
    except socket.gaierror:
        raise ValueError(f"Unable to resolve domain '{hostname}'. Please check the domain name and your internet connection.")

    for ip in resolved_ips:
        if is_private_or_restricted_ip(ip):
            raise ValueError(f"Target '{hostname}' resolves to restricted IP ({ip}). Scanning private/internal addresses is blocked for security.")

    return parsed.geturl(), hostname, resolved_ips[0]


def inspect_tls(hostname, port=443):
    """
    Connects to the server over TLS/SSL to retrieve protocol version,
    cipher suite, certificate chain, and validity dates.
    """
    tls_data = {
        "version": None,
        "cipher": None,
        "cert_valid": False,
        "cert_error": None,
        "days_left": None,
        "issuer": {},
        "subject": {},
        "san": []
    }

    context = ssl.create_default_context()
    # Allow inspection even if certificate is self-signed/expired to report accurate findings
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    try:
        with socket.create_connection((hostname, port), timeout=6) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                tls_data["version"] = ssock.version()
                cipher_tuple = ssock.cipher()
                if cipher_tuple:
                    tls_data["cipher"] = cipher_tuple[0]

                # Fetch peer certificate
                cert = ssock.getpeercert(binary_form=False)
                if not cert:
                    # Binary certificate fallback for unverified contexts
                    der_cert = ssock.getpeercert(binary_form=True)
                    if der_cert:
                        # Re-verify with default context to check actual validity
                        verify_ctx = ssl.create_default_context()
                        try:
                            with socket.create_connection((hostname, port), timeout=5) as v_sock:
                                with verify_ctx.wrap_socket(v_sock, server_hostname=hostname) as v_ssock:
                                    cert = v_ssock.getpeercert()
                                    tls_data["cert_valid"] = True
                        except ssl.SSLCertVerificationError as ve:
                            tls_data["cert_valid"] = False
                            tls_data["cert_error"] = ve.verify_message
                        except Exception as e:
                            tls_data["cert_valid"] = False
                            tls_data["cert_error"] = str(e)
                else:
                    tls_data["cert_valid"] = True

                if cert:
                    # Parse dates
                    not_after_str = cert.get("notAfter")
                    if not_after_str:
                        expiry_dt = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                        now_dt = datetime.now(timezone.utc)
                        tls_data["days_left"] = (expiry_dt - now_dt).days
                        tls_data["expiry_date"] = expiry_dt.strftime("%Y-%m-%d %H:%M:%S UTC")

                    # Parse issuer and subject
                    for item in cert.get("issuer", []):
                        for k, v in item:
                            tls_data["issuer"][k] = v

                    for item in cert.get("subject", []):
                        for k, v in item:
                            tls_data["subject"][k] = v

                    # Subject Alternative Names
                    sans = [v for k, v in cert.get("subjectAltName", []) if k == "DNS"]
                    tls_data["san"] = sans

    except Exception as e:
        tls_data["cert_error"] = str(e)

    return tls_data


def inspect_dns(hostname):
    """
    Performs passive DNS queries to detect CAA and SPF records.
    """
    dns_data = {"caa": [], "spf": []}
    
    try:
        import dns.resolver
        resolver = dns.resolver.Resolver()
        resolver.timeout = 3
        resolver.lifetime = 3

        # Query CAA records
        try:
            caa_answers = resolver.resolve(hostname, "CAA")
            for rdata in caa_answers:
                dns_data["caa"].append(f"{rdata.flags} {rdata.tag.decode()} \"{rdata.value.decode()}\"")
        except Exception:
            pass

        # Query TXT records (for SPF/DMARC passive info)
        try:
            txt_answers = resolver.resolve(hostname, "TXT")
            for rdata in txt_answers:
                txt_str = "".join([s.decode() for s in rdata.strings])
                if txt_str.startswith("v=spf1"):
                    dns_data["spf"].append(txt_str)
        except Exception:
            pass

    except ImportError:
        pass
    except Exception:
        pass

    return dns_data


def parse_cookie_headers(headers_raw):
    """
    Extracts and parses Set-Cookie directives into structured cookie objects.
    """
    cookies = []
    # In requests headers, Set-Cookie may be combined or handled by raw response
    for key, val in headers_raw.items():
        if key.lower() == "set-cookie":
            parts = [p.strip() for p in val.split(";")]
            if not parts or not parts[0]:
                continue
            
            name_val = parts[0].split("=", 1)
            c_name = name_val[0].strip()
            c_val = name_val[1].strip() if len(name_val) > 1 else ""

            cookie_dict = {
                "name": c_name,
                "value": c_val,
                "secure": False,
                "httponly": False,
                "samesite": None
            }

            for p in parts[1:]:
                p_lower = p.lower()
                if p_lower == "secure":
                    cookie_dict["secure"] = True
                elif p_lower == "httponly":
                    cookie_dict["httponly"] = True
                elif p_lower.startswith("samesite="):
                    cookie_dict["samesite"] = p.split("=", 1)[1].strip().lower()

            cookies.append(cookie_dict)
    return cookies


def scan_website(target_url):
    """
    Main entry point for scanning a website.
    Coordinates URL validation, HTTP requests, TLS checks, DNS checks,
    executes checks, and computes the security score.
    """
    start_time = time.time()
    scan_timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    
    # Step 1: Validate URL & check SSRF
    clean_url, hostname, resolved_ip = validate_and_normalize_url(target_url)

    # Step 2: Establish HTTP session and perform passive request
    session = requests.Session()
    headers_req = {
        "User-Agent": "ConfigScore/1.0 (Defensive Security Scanner; BSc Final Year Project)",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5"
    }

    redirect_chain = []
    response = None
    fetch_error = None

    try:
        # First test initial connection (start with http to check redirect if user entered apex domain)
        initial_test_url = clean_url
        # If user entered https://, also check if http:// redirects cleanly
        parsed_clean = urllib.parse.urlparse(clean_url)
        http_probe_url = f"http://{parsed_clean.netloc}{parsed_clean.path or '/'}"

        # Probe HTTP to see redirect behavior
        try:
            http_resp = session.get(http_probe_url, headers=headers_req, timeout=5, allow_redirects=False, verify=False)
            if http_resp.is_redirect:
                redirect_chain.append({
                    "url": http_probe_url,
                    "status_code": http_resp.status_code,
                    "location": http_resp.headers.get("Location", "")
                })
        except Exception:
            pass

        # Perform main request following redirects
        response = session.get(clean_url, headers=headers_req, timeout=(5, 7), allow_redirects=True, verify=False)
        
        # Collect full redirect history
        for hist_resp in response.history:
            redirect_chain.append({
                "url": hist_resp.url,
                "status_code": hist_resp.status_code,
                "location": hist_resp.headers.get("Location", "")
            })

        # Final landing URL
        final_url = response.url
        status_code = response.status_code
        resp_headers = {k.lower(): v for k, v in response.headers.items()}
        body_sample = response.text[:100000] if response.text else ""

    except requests.exceptions.SSLError as se:
        fetch_error = f"SSL/TLS Handshake Error: {str(se)}"
        final_url = clean_url
        status_code = None
        resp_headers = {}
        body_sample = ""
    except requests.exceptions.ConnectTimeout:
        raise ConnectionError(f"Connection timed out while connecting to {hostname}. The server may be offline or blocking scanner requests.")
    except requests.exceptions.ConnectionError as ce:
        raise ConnectionError(f"Could not connect to {hostname}. Verify the domain exists and is currently reachable.")
    except Exception as e:
        raise RuntimeError(f"An unexpected error occurred while scanning {clean_url}: {str(e)}")

    # Step 3: Inspect TLS details directly
    tls_info = inspect_tls(hostname, 443)

    # Step 4: Inspect DNS details
    dns_info = inspect_dns(hostname)

    # Step 5: Extract parsed cookies
    cookies = parse_cookie_headers(resp_headers)

    # Step 6: Assemble raw scan data object
    scan_data = {
        "target_url": clean_url,
        "final_url": final_url,
        "hostname": hostname,
        "resolved_ip": resolved_ip,
        "status_code": status_code,
        "headers": resp_headers,
        "cookies": cookies,
        "redirect_chain": redirect_chain,
        "tls_info": tls_info,
        "dns_info": dns_info,
        "body_sample": body_sample,
        "fetch_error": fetch_error
    }

    # Step 7: Run all 20 passive security checks
    checks_results = run_all_checks(scan_data)

    # Step 8: Calculate overall score and risk level
    base_score = 100
    total_deductions = sum(c.get("points_deducted", 0) for c in checks_results)
    final_score = max(0, min(100, base_score - total_deductions))

    # Tally statistics
    passed_count = sum(1 for c in checks_results if c["status"] == "PASS")
    missing_count = sum(1 for c in checks_results if c["status"] == "MISSING")
    warning_count = sum(1 for c in checks_results if c["status"] == "WARNING")
    review_count = sum(1 for c in checks_results if c["status"] == "REVIEW")

    # Risk level determination
    if final_score >= 90:
        risk_level = "Low Risk"
        risk_color = "success"
    elif final_score >= 70:
        risk_level = "Medium Risk"
        risk_color = "warning"
    elif final_score >= 40:
        risk_level = "High Risk"
        risk_color = "orange"
    else:
        risk_level = "Critical Risk"
        risk_color = "danger"

    # Attach topic metadata and remediation guides to each check result
    enriched_checks = []
    for c in checks_results:
        cid = c["id"]
        topic_meta = TOPICS_MAP.get(cid, {})
        c_copy = dict(c)
        c_copy["category"] = topic_meta.get("category", "General")
        c_copy["importance"] = topic_meta.get("importance", "Medium")
        c_copy["what_is_it"] = topic_meta.get("what_is_it", "")
        c_copy["why_it_matters"] = topic_meta.get("why_it_matters", "")
        c_copy["actual_problem"] = topic_meta.get("actual_problem", "")
        c_copy["security_impact"] = topic_meta.get("security_impact", "")
        c_copy["how_to_fix"] = topic_meta.get("how_to_fix", {})
        c_copy["example"] = topic_meta.get("example", {})
        c_copy["common_mistakes"] = topic_meta.get("common_mistakes", [])
        c_copy["references"] = topic_meta.get("references", [])
        enriched_checks.append(c_copy)

    elapsed_time = round(time.time() - start_time, 2)
    scan_id = f"scan_{int(time.time())}_{hostname.replace('.', '_')}"

    return {
        "scan_id": scan_id,
        "target_url": clean_url,
        "final_url": final_url,
        "hostname": hostname,
        "resolved_ip": resolved_ip,
        "status_code": status_code,
        "timestamp": scan_timestamp,
        "elapsed_seconds": elapsed_time,
        "score": final_score,
        "risk_level": risk_level,
        "risk_color": risk_color,
        "stats": {
            "total": len(enriched_checks),
            "passed": passed_count,
            "missing": missing_count,
            "warning": warning_count,
            "review": review_count
        },
        "redirect_chain": redirect_chain,
        "tls_info": tls_info,
        "dns_info": dns_info,
        "checks": enriched_checks,
        "server_banner": resp_headers.get("server", "Not disclosed")
    }
