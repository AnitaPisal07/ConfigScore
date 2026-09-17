from typing import Dict, Any, List

def audit_dns(domain: str) -> List[Dict[str, Any]]:
    findings = []
    
    # Try using dnspython if installed
    try:
        import dns.resolver
        resolver = dns.resolver.Resolver()
        resolver.timeout = 3.0
        resolver.lifetime = 3.0

        # 1. Check SPF record (TXT record on domain)
        has_spf = False
        spf_value = None
        try:
            answers = resolver.resolve(domain, "TXT")
            for rdata in answers:
                txt_str = "".join([b.decode("utf-8", errors="ignore") for b in rdata.strings])
                if txt_str.startswith("v=spf1"):
                    has_spf = True
                    spf_value = txt_str
                    break
        except Exception:
            pass

        if has_spf:
            findings.append({
                "id": "dns-spf",
                "title": "SPF Record Configured",
                "category": "DNS & Email",
                "severity": "HIGH",
                "status": "PASS",
                "value": spf_value[:60] + ("..." if len(spf_value) > 60 else ""),
                "description": "Sender Policy Framework (SPF) designates authorized mail servers, preventing scammers from spoofing emails from your domain.",
                "recommendation": "Maintain SPF record accuracy as mail sending services change.",
                "cwe": "CWE-290"
            })
        else:
            findings.append({
                "id": "dns-spf",
                "title": "Missing SPF Record",
                "category": "DNS & Email",
                "severity": "HIGH",
                "status": "FAIL",
                "value": "None found",
                "description": "No SPF TXT record detected. Anyone can forge emails appearing to originate from this domain.",
                "recommendation": "Add a TXT DNS record: 'v=spf1 include:_spf.google.com ~all' (configured for your mail provider).",
                "cwe": "CWE-290"
            })

        # 2. Check DMARC record (_dmarc.domain)
        has_dmarc = False
        dmarc_val = None
        try:
            dmarc_host = f"_dmarc.{domain}"
            answers = resolver.resolve(dmarc_host, "TXT")
            for rdata in answers:
                txt_str = "".join([b.decode("utf-8", errors="ignore") for b in rdata.strings])
                if txt_str.startswith("v=DMARC1"):
                    has_dmarc = True
                    dmarc_val = txt_str
                    break
        except Exception:
            pass

        if has_dmarc:
            findings.append({
                "id": "dns-dmarc",
                "title": "DMARC Policy Enforced",
                "category": "DNS & Email",
                "severity": "HIGH",
                "status": "PASS",
                "value": dmarc_val[:60] + ("..." if len(dmarc_val) > 60 else ""),
                "description": "Domain-based Message Authentication (DMARC) specifies how receivers handle unauthenticated emails (reject/quarantine).",
                "recommendation": "Good configuration. Monitor DMARC aggregate reports.",
                "cwe": "CWE-290"
            })
        else:
            findings.append({
                "id": "dns-dmarc",
                "title": "Missing DMARC Record",
                "category": "DNS & Email",
                "severity": "MEDIUM",
                "status": "WARNING",
                "value": "None found at _dmarc." + domain,
                "description": "DMARC record missing. Receivers have no explicit instructions for handling spoofed phishing emails.",
                "recommendation": "Add TXT record at _dmarc." + domain + ": 'v=DMARC1; p=quarantine; rua=mailto:dmarc@" + domain + "'",
                "cwe": "CWE-290"
            })

    except ImportError:
        # Fallback if dnspython is not installed
        findings.append({
            "id": "dns-skipped",
            "title": "DNS Resolver Dependency Optional",
            "category": "DNS & Email",
            "severity": "LOW",
            "status": "PASS",
            "value": "dnspython not active",
            "description": "Install dnspython ('pip install dnspython') to enable live SPF/DMARC resolution.",
            "recommendation": "Install dnspython for automated SPF/DMARC checks.",
            "cwe": "CWE-200"
        })
    except Exception as e:
        findings.append({
            "id": "dns-error",
            "title": "DNS Lookup Failed",
            "category": "DNS & Email",
            "severity": "LOW",
            "status": "WARNING",
            "value": str(e),
            "description": "Could not complete DNS TXT resolution.",
            "recommendation": "Verify your local network has outbound DNS access on port 53.",
            "cwe": "CWE-200"
        })

    return findings
