import pytest
from backend.app.scanner.checks import SecurityChecks

def test_check_missing_security_headers():
    headers = {"Content-Type": "text/html"}
    findings = SecurityChecks.check_security_headers("https://example.com", headers)
    titles = [f.title for f in findings]
    assert "Missing X-Frame-Options Header" in titles
    assert "Missing or Invalid X-Content-Type-Options Header" in titles
    assert "Missing Referrer-Policy Header" in titles

def test_check_csp_missing_and_weak():
    headers_none = {}
    finding = SecurityChecks.check_csp("https://example.com", headers_none)
    assert finding is not None
    assert finding.severity == "medium"
    assert "Missing Content Security Policy" in finding.title

    headers_weak = {"Content-Security-Policy": "default-src 'self' 'unsafe-inline'"}
    finding_weak = SecurityChecks.check_csp("https://example.com", headers_weak)
    assert finding_weak is not None
    assert "Weak Content Security Policy" in finding_weak.title

def test_check_hsts_missing():
    finding = SecurityChecks.check_hsts("https://example.com", {})
    assert finding is not None
    assert "Strict Transport Security" in finding.title

def test_check_cookie_flags():
    cookies = ["session_id=abc123456"]
    findings = SecurityChecks.check_cookies("https://example.com", cookies)
    titles = [f.title for f in findings]
    assert any("Missing Secure Flag" in t for t in titles)
    assert any("Missing HttpOnly Flag" in t for t in titles)
    assert any("Missing SameSite" in t for t in titles)

def test_check_info_disclosure():
    headers = {
        "Server": "Apache/2.4.41 (Ubuntu)",
        "X-Powered-By": "PHP/7.4.3"
    }
    findings = SecurityChecks.check_info_disclosure("https://example.com", headers)
    assert len(findings) == 2
