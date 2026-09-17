"""
Flask Routes Verification Test
Ensures all templates render correctly with no Jinja errors.
"""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app import app

def test_routes():
    client = app.test_client()
    
    endpoints = [
        ("/", 200, "Know how secure your"),
        ("/scanner", 200, "Website Security Scanner"),
        ("/cyber-security", 200, "Cyber Security Knowledge Hub"),
        ("/topic/https", 200, "HTTPS (Hypertext Transfer Protocol Secure)"),
        ("/topic/hsts", 200, "HTTP Strict Transport Security (HSTS)"),
        ("/topic/csp", 200, "Content Security Policy (CSP)"),
        ("/topic/x-frame-options", 200, "X-Frame-Options (Clickjacking Protection)"),
        ("/topic/secure-cookies", 200, "Secure Cookie Flag"),
        ("/insights", 200, "Security Insights & Best Practices"),
        ("/about", 200, "About ConfigScore"),
        ("/topic/nonexistent-slug-xyz", 404, "404")
    ]
    
    for path, expected_status, text_snippet in endpoints:
        resp = client.get(path)
        assert resp.status_code == expected_status, f"Route {path} returned {resp.status_code}, expected {expected_status}"
        assert text_snippet in resp.get_data(as_text=True), f"Snippet '{text_snippet}' not found in {path}"
        print(f"[OK] Route {path} -> HTTP {resp.status_code}")

if __name__ == "__main__":
    print("Testing Flask endpoints and template rendering...")
    test_routes()
    print("\n[SUCCESS] All Flask routes rendered successfully!")
