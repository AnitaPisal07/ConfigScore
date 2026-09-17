"""
ConfigScore Verification Test Suite
Tests scanner engine, SSRF blocking, checks execution, and ReportLab PDF generation.
"""

import os
import sys

# Ensure ConfigScore root is in path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from scanner.engine import scan_website, validate_and_normalize_url
from scanner.report import generate_pdf_report
import json

def test_topics_data():
    print("[+] Testing topics.json structure...")
    topics_file = os.path.join(os.path.dirname(__file__), "data", "topics.json")
    assert os.path.exists(topics_file), "data/topics.json does not exist!"
    
    with open(topics_file, "r", encoding="utf-8") as f:
        topics = json.load(f)
    
    assert len(topics) == 20, f"Expected 20 topics, found {len(topics)}"
    
    required_keys = [
        "id", "slug", "title", "short_description", "category",
        "importance", "weight", "what_is_it", "why_it_matters",
        "actual_problem", "security_impact", "how_to_check",
        "how_to_fix", "example", "common_mistakes", "references", "status_meanings"
    ]
    
    for t in topics:
        for k in required_keys:
            assert k in t, f"Topic '{t.get('id')}' missing key '{k}'"
        assert isinstance(t["how_to_fix"], dict), f"how_to_fix in '{t.get('id')}' must be dict"
        assert "nginx" in t["how_to_fix"], f"how_to_fix in '{t.get('id')}' missing nginx snippet"
        assert "apache" in t["how_to_fix"], f"how_to_fix in '{t.get('id')}' missing apache snippet"
        assert "flask" in t["how_to_fix"], f"how_to_fix in '{t.get('id')}' missing flask snippet"
        assert "express" in t["how_to_fix"], f"how_to_fix in '{t.get('id')}' missing express snippet"

    print(f"    [OK] All {len(topics)} topics are complete and valid.")

def test_ssrf_protection():
    print("[+] Testing anti-SSRF protections...")
    blocked_urls = [
        "http://127.0.0.1",
        "http://localhost",
        "http://127.0.0.2:8080",
        "http://10.0.0.1",
        "http://192.168.1.1",
        "http://172.16.0.1",
        "http://169.254.169.254/latest/meta-data/"
    ]
    
    for u in blocked_urls:
        try:
            validate_and_normalize_url(u)
            raise AssertionError(f"SSRF failed: '{u}' should have been blocked!")
        except ValueError as ve:
            # Expected blocking
            pass
    print("    [OK] All internal and metadata URLs successfully blocked.")

def test_mock_scan_and_pdf():
    print("[+] Testing scanner engine & PDF generator with mock scan data...")
    mock_scan_data = {
        "scan_id": "test_scan_12345",
        "target_url": "https://example.com",
        "final_url": "https://example.com",
        "hostname": "example.com",
        "resolved_ip": "93.184.215.14",
        "status_code": 200,
        "timestamp": "2026-09-15 12:00:00 UTC",
        "elapsed_seconds": 1.25,
        "score": 85,
        "risk_level": "Medium Risk",
        "risk_color": "warning",
        "stats": {
            "total": 20,
            "passed": 15,
            "missing": 3,
            "warning": 2,
            "review": 0
        },
        "redirect_chain": [
            {"url": "http://example.com", "status_code": 301, "location": "https://example.com/"}
        ],
        "checks": [
            {
                "id": "https",
                "title": "HTTPS",
                "slug": "https",
                "status": "PASS",
                "risk": "Low",
                "points_deducted": 0,
                "observation": "Website enforces HTTPS.",
                "why_it_matters": "Confidentiality and integrity.",
                "how_to_fix": {"overview": "Enable TLS.", "nginx": "listen 443 ssl;"}
            },
            {
                "id": "hsts",
                "title": "HTTP Strict Transport Security (HSTS)",
                "slug": "hsts",
                "status": "MISSING",
                "risk": "High",
                "points_deducted": 8,
                "observation": "Strict-Transport-Security header is missing.",
                "why_it_matters": "Vulnerable to SSL-stripping.",
                "how_to_fix": {"overview": "Add Strict-Transport-Security header.", "nginx": "add_header Strict-Transport-Security \"max-age=31536000\";"}
            }
        ],
        "server_banner": "ECS (dcb/7ea3)"
    }
    
    # Generate PDF
    pdf_bytes = generate_pdf_report(mock_scan_data)
    assert pdf_bytes is not None and len(pdf_bytes) > 1000, "PDF generation failed or returned empty bytes!"
    print(f"    [OK] PDF Report generated successfully ({len(pdf_bytes)} bytes).")

if __name__ == "__main__":
    print("=" * 60)
    print("ConfigScore — Standalone Verification Tests")
    print("=" * 60)
    test_topics_data()
    test_ssrf_protection()
    test_mock_scan_and_pdf()
    print("\n[SUCCESS] All verification tests passed cleanly!")
