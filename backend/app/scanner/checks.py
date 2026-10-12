from typing import List, Dict, Any, Optional
from urllib.parse import urlparse

class SecurityCheckItem:
    def __init__(
        self,
        title: str,
        severity: str,
        category: str,
        affected_url: str,
        description: str,
        evidence: str,
        impact: str,
        remediation: str,
        manual_verification: str,
        verification_status: str = "New"
    ):
        self.title = title
        self.severity = severity
        self.category = category
        self.affected_url = affected_url
        self.description = description
        self.evidence = evidence
        self.impact = impact
        self.remediation = remediation
        self.manual_verification = manual_verification
        self.verification_status = verification_status

class SecurityChecks:
    @staticmethod
    def check_security_headers(target_url: str, headers: Dict[str, str]) -> List[SecurityCheckItem]:
        findings = []
        low_headers = {k.lower(): v for k, v in headers.items()}

        # X-Frame-Options
        if "x-frame-options" not in low_headers and "frame-ancestors" not in low_headers.get("content-security-policy", ""):
            findings.append(SecurityCheckItem(
                title="Missing X-Frame-Options Header",
                severity="low",
                category="Security Headers",
                affected_url=target_url,
                description="The response lacks an X-Frame-Options header and frame-ancestors CSP directive.",
                evidence=f"Headers present: {', '.join(low_headers.keys())}",
                impact="May allow clickjacking attacks if malicious websites embed the page in opaque iframes.",
                remediation="Add 'X-Frame-Options: SAMEORIGIN' or 'X-Frame-Options: DENY'.",
                manual_verification="Test rendering target in local <iframe> element."
            ))

        # X-Content-Type-Options
        if low_headers.get("x-content-type-options", "").lower() != "nosniff":
            findings.append(SecurityCheckItem(
                title="Missing or Invalid X-Content-Type-Options Header",
                severity="low",
                category="Security Headers",
                affected_url=target_url,
                description="The server does not enforce 'X-Content-Type-Options: nosniff'.",
                evidence=f"Observed: {low_headers.get('x-content-type-options', 'Absent')}",
                impact="Browsers may perform MIME sniffing, treating non-executable uploads as scripts.",
                remediation="Configure 'X-Content-Type-Options: nosniff' on all HTTP responses.",
                manual_verification="Verify headers using curl -sI <url> | grep -i x-content-type-options."
            ))

        # Referrer-Policy
        if "referrer-policy" not in low_headers:
            findings.append(SecurityCheckItem(
                title="Missing Referrer-Policy Header",
                severity="informational",
                category="Security Headers",
                affected_url=target_url,
                description="No Referrer-Policy specified. Browsers may send complete URLs across origins.",
                evidence="Header Referrer-Policy is missing.",
                impact="Query parameters or paths may leak to external third-party referrers.",
                remediation="Set 'Referrer-Policy: strict-origin-when-cross-origin'.",
                manual_verification="Inspect Referer header on outbound hyperlinks."
            ))

        return findings

    @staticmethod
    def check_csp(target_url: str, headers: Dict[str, str]) -> Optional[SecurityCheckItem]:
        low_headers = {k.lower(): v for k, v in headers.items()}
        csp = low_headers.get("content-security-policy")

        if not csp:
            return SecurityCheckItem(
                title="Missing Content Security Policy (CSP)",
                severity="medium",
                category="Content Security",
                affected_url=target_url,
                description="No Content-Security-Policy header was detected. CSP provides essential browser-enforced mitigation against cross-site scripting (XSS).",
                evidence="Content-Security-Policy header absent in HTTP response.",
                impact="Increases risk of untrusted script execution if injection vulnerabilities exist.",
                remediation="Implement a Content Security Policy (e.g. default-src 'self'; script-src 'self').",
                manual_verification="Evaluate policy in Google CSP Evaluator."
            )

        if "'unsafe-inline'" in csp or "'unsafe-eval'" in csp:
            return SecurityCheckItem(
                title="Weak Content Security Policy Directives",
                severity="low",
                category="Content Security",
                affected_url=target_url,
                description="The CSP uses permissive directives ('unsafe-inline' or 'unsafe-eval').",
                evidence=f"CSP: {csp[:200]}...",
                impact="Weak directives significantly reduce CSP's protective capability against XSS.",
                remediation="Replace 'unsafe-inline' with cryptographic nonces or hashes.",
                manual_verification="Check CSP warnings in browser console."
            )

        return None

    @staticmethod
    def check_hsts(target_url: str, headers: Dict[str, str]) -> Optional[SecurityCheckItem]:
        low_headers = {k.lower(): v for k, v in headers.items()}
        is_https = target_url.lower().startswith("https://")
        hsts = low_headers.get("strict-transport-security")

        if is_https and not hsts:
            return SecurityCheckItem(
                title="Missing HTTP Strict Transport Security (HSTS)",
                severity="medium",
                category="Transport Layer Security",
                affected_url=target_url,
                description="The HTTPS service does not instruct browsers to require secure connections exclusively.",
                evidence="Strict-Transport-Security header not returned.",
                impact="Permits SSL-stripping and network downgrade attacks.",
                remediation="Set 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload'.",
                manual_verification="Query headers with curl -sI <url> | grep -i strict-transport-security."
            )
        return None

    @staticmethod
    def check_cookies(target_url: str, cookies_list: List[str]) -> List[SecurityCheckItem]:
        findings = []
        is_https = target_url.lower().startswith("https://")

        for cookie in cookies_list:
            lower = cookie.lower()
            name = cookie.split("=")[0].strip()

            if is_https and "secure" not in lower:
                findings.append(SecurityCheckItem(
                    title=f"Cookie '{name}' Missing Secure Flag",
                    severity="medium",
                    category="Session Management",
                    affected_url=target_url,
                    description=f"The cookie '{name}' was set over HTTPS without the Secure flag.",
                    evidence=f"Set-Cookie: {cookie}",
                    impact="Browser may transmit this cookie in unencrypted HTTP requests.",
                    remediation="Append '; Secure' attribute to all cookies served over HTTPS.",
                    manual_verification="Inspect cookie attributes in browser DevTools Application tab."
                ))

            if "httponly" not in lower and not name.startswith(("_ga", "theme")):
                findings.append(SecurityCheckItem(
                    title=f"Cookie '{name}' Missing HttpOnly Flag",
                    severity="low",
                    category="Session Management",
                    affected_url=target_url,
                    description=f"The cookie '{name}' lacks the HttpOnly directive.",
                    evidence=f"Set-Cookie: {cookie}",
                    impact="Client-side JavaScript can read this cookie, risking exfiltration via XSS.",
                    remediation="Add '; HttpOnly' to session tokens.",
                    manual_verification="Check document.cookie access in console."
                ))

            if "samesite" not in lower:
                findings.append(SecurityCheckItem(
                    title=f"Cookie '{name}' Missing SameSite Attribute",
                    severity="low",
                    category="Session Management",
                    affected_url=target_url,
                    description=f"Cookie '{name}' does not configure SameSite.",
                    evidence=f"Set-Cookie: {cookie}",
                    impact="May allow cross-site requests to transmit cookies, contributing to CSRF.",
                    remediation="Set '; SameSite=Lax' or '; SameSite=Strict'.",
                    manual_verification="Review SameSite policy in network panel."
                ))

        return findings

    @staticmethod
    def check_info_disclosure(target_url: str, headers: Dict[str, str]) -> List[SecurityCheckItem]:
        findings = []
        low_headers = {k.lower(): v for k, v in headers.items()}

        server = low_headers.get("server")
        if server and any(c.isdigit() for c in server):
            findings.append(SecurityCheckItem(
                title=f"Detailed Server Version Disclosure ({server})",
                severity="low",
                category="Information Disclosure",
                affected_url=target_url,
                description="The Server response header discloses software and version numbers.",
                evidence=f"Server: {server}",
                impact="Enables precise target fingerprinting and search for known CVEs.",
                remediation="Configure web server to suppress banner version info.",
                manual_verification="Inspect curl -sI <url> | grep -i server."
            ))

        powered_by = low_headers.get("x-powered-by")
        if powered_by:
            findings.append(SecurityCheckItem(
                title=f"Technology Banner Disclosure ({powered_by})",
                severity="informational",
                category="Information Disclosure",
                affected_url=target_url,
                description="X-Powered-By header discloses underlying backend framework.",
                evidence=f"X-Powered-By: {powered_by}",
                impact="Reveals technology stack details to observers.",
                remediation="Disable X-Powered-By header in application settings.",
                manual_verification="Verify absence of X-Powered-By header."
            ))

        return findings
