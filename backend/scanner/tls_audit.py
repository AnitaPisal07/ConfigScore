import socket
import ssl
from datetime import datetime
from typing import Dict, Any, List, Optional
from urllib.parse import urlparse

def audit_tls(domain: str, port: int = 443, timeout: float = 5.0) -> List[Dict[str, Any]]:
    findings = []
    
    # 1. Establish TLS connection and inspect certificate
    context = ssl.create_default_context()
    try:
        with socket.create_connection((domain, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()
                protocol_version = ssock.version()
                
                # Check Protocol Version
                if protocol_version in ["TLSv1.3", "TLSv1.2"]:
                    findings.append({
                        "id": "tls-protocol",
                        "title": f"Modern Protocol: {protocol_version}",
                        "category": "SSL/TLS",
                        "severity": "HIGH",
                        "status": "PASS",
                        "value": f"{protocol_version} (Cipher: {cipher[0]} {cipher[2]} bits)",
                        "description": "The server negotiates a modern, cryptographically secure TLS protocol version.",
                        "recommendation": "Maintain TLS 1.2+ and avoid falling back to deprecated protocols.",
                        "cwe": "CWE-326"
                    })
                else:
                    findings.append({
                        "id": "tls-protocol",
                        "title": f"Insecure / Legacy TLS Version: {protocol_version}",
                        "category": "SSL/TLS",
                        "severity": "CRITICAL",
                        "status": "FAIL",
                        "value": protocol_version,
                        "description": "Legacy protocols (SSLv3, TLS 1.0, TLS 1.1) are vulnerable to known cryptographic attacks (POODLE, BEAST, SWEET32).",
                        "recommendation": "Disable TLS 1.0/1.1 and enable TLS 1.2 and TLS 1.3 only.",
                        "cwe": "CWE-326"
                    })

                # Check Expiration & Validity
                if cert and "notAfter" in cert:
                    # e.g., 'May 20 12:00:00 2027 GMT'
                    expiry_str = cert["notAfter"]
                    expiry_date = datetime.strptime(expiry_str, "%b %d %H:%M:%S %Y %Z")
                    now = datetime.utcnow()
                    days_remaining = (expiry_date - now).days

                    issuer_dict = dict(x[0] for x in cert.get("issuer", []))
                    issuer_org = issuer_dict.get("organizationName", issuer_dict.get("commonName", "Unknown CA"))

                    if days_remaining < 0:
                        findings.append({
                            "id": "tls-expiry",
                            "title": "SSL Certificate Expired",
                            "category": "SSL/TLS",
                            "severity": "CRITICAL",
                            "status": "FAIL",
                            "value": f"Expired {abs(days_remaining)} days ago ({expiry_str})",
                            "description": "The TLS certificate is expired. Browsers will block visitors with an insecure connection warning.",
                            "recommendation": "Renew the SSL/TLS certificate immediately with a trusted certificate authority.",
                            "cwe": "CWE-295"
                        })
                    elif days_remaining < 30:
                        findings.append({
                            "id": "tls-expiry",
                            "title": "Certificate Expiring Soon",
                            "category": "SSL/TLS",
                            "severity": "HIGH",
                            "status": "WARNING",
                            "value": f"{days_remaining} days remaining (Expires: {expiry_str})",
                            "description": "The certificate has less than 30 days of validity remaining. Prompt renewal prevents downtime.",
                            "recommendation": "Trigger automated certificate renewal (e.g., Certbot / Let's Encrypt).",
                            "cwe": "CWE-295"
                        })
                    else:
                        findings.append({
                            "id": "tls-expiry",
                            "title": "SSL Certificate Valid",
                            "category": "SSL/TLS",
                            "severity": "HIGH",
                            "status": "PASS",
                            "value": f"Valid for {days_remaining} days (Issuer: {issuer_org})",
                            "description": f"Issued by {issuer_org}. Valid until {expiry_str}.",
                            "recommendation": "No action needed. Certificate trust is established.",
                            "cwe": "CWE-295"
                        })
    except ssl.SSLCertVerificationError as e:
        findings.append({
            "id": "tls-error",
            "title": "Certificate Verification Failed",
            "category": "SSL/TLS",
            "severity": "CRITICAL",
            "status": "FAIL",
            "value": str(e),
            "description": "The SSL certificate is self-signed, untrusted, or has a mismatched hostname.",
            "recommendation": "Install a valid certificate issued by a globally recognized Certificate Authority.",
            "cwe": "CWE-295"
        })
    except Exception as e:
        findings.append({
            "id": "tls-conn-failed",
            "title": "TLS Connection Failed",
            "category": "SSL/TLS",
            "severity": "CRITICAL",
            "status": "FAIL",
            "value": str(e),
            "description": "Could not establish a secure TLS handshake on port 443.",
            "recommendation": "Ensure port 443 is open and configured with an active TLS listener.",
            "cwe": "CWE-319"
        })

    return findings
