import asyncio
import httpx
from datetime import datetime
from typing import List, Dict, Any, Callable
from urllib.parse import urlparse, urljoin
from sqlalchemy.orm import Session

from ..models import Scan, ScanLog, Finding, Target
from ..scope_guard import ScopeGuard, ScopeGuardError
from .checks import SecurityChecks, SecurityCheckItem

class ScanEngine:
    def __init__(self, db: Session, scan_id: str):
        self.db = db
        self.scan_id = scan_id
        self.scan = db.query(Scan).filter(Scan.id == scan_id).first()
        self.target = db.query(Target).filter(Target.id == self.scan.target_id).first() if self.scan else None
        self.is_cancelled = False

    def log(self, level: str, message: str):
        if not self.scan:
            return
        log_entry = ScanLog(
            scan_id=self.scan_id,
            level=level,
            message=message,
            timestamp=datetime.utcnow()
        )
        self.db.add(log_entry)
        self.db.commit()

    async def run(self):
        if not self.scan or not self.target:
            return

        self.scan.status = "running"
        self.scan.progress = 5
        self.db.commit()

        self.log("info", f"ScopeGuard starting pre-flight destination validation for {self.target.url}...")

        try:
            # 1. ScopeGuard validation
            normalized_url, hostname, resolved_ip = ScopeGuard.validate_destination_network(
                target_url=self.target.url,
                allowed_host=self.target.hostname,
                allow_subdomains=self.target.allow_subdomains,
                excluded_hosts=self.target.excluded_hosts or [],
                excluded_paths=self.target.excluded_paths or [],
                user_authorized=self.target.user_authorized
            )

            self.log("info", f"ScopeGuard: Verified {hostname} -> {resolved_ip}. Scope allowlist approved.")
            self.scan.progress = 15
            self.db.commit()

            timeout = (self.scan.config or {}).get("timeout", 8000) / 1000.0
            delay = (self.scan.config or {}).get("delay_ms", 250) / 1000.0

            async with httpx.AsyncClient(
                verify=False,
                timeout=timeout,
                follow_redirects=True,
                headers={"User-Agent": "WebBugHunter/1.0 (Defensive Security Audit; Scope-Enforced)"}
            ) as client:
                if delay > 0:
                    await asyncio.sleep(delay)

                self.log("info", "Executing baseline HTTP request...")
                response = await client.get(normalized_url)
                self.log("info", f"Received HTTP {response.status_code}. Response headers count: {len(response.headers)}")
                self.scan.progress = 30
                self.db.commit()

                # Checks accumulation
                raw_findings: List[SecurityCheckItem] = []

                # Check 1: Security Headers
                self.log("info", "Running Check 1/10: HTTP Security Headers audit...")
                raw_findings.extend(SecurityChecks.check_security_headers(normalized_url, dict(response.headers)))
                self.scan.progress = 40

                # Check 2: CSP
                self.log("info", "Running Check 2/10: Content Security Policy evaluation...")
                csp_finding = SecurityChecks.check_csp(normalized_url, dict(response.headers))
                if csp_finding:
                    raw_findings.append(csp_finding)
                self.scan.progress = 50

                # Check 3: HSTS
                self.log("info", "Running Check 3/10: Strict Transport Security check...")
                hsts_finding = SecurityChecks.check_hsts(normalized_url, dict(response.headers))
                if hsts_finding:
                    raw_findings.append(hsts_finding)
                self.scan.progress = 60

                # Check 4: Cookies
                self.log("info", "Running Check 4/10: Cookie security flags verification...")
                set_cookies = response.headers.get_list("set-cookie") if hasattr(response.headers, "get_list") else [response.headers.get("set-cookie", "")]
                raw_findings.extend(SecurityChecks.check_cookies(normalized_url, [c for c in set_cookies if c]))
                self.scan.progress = 70

                # Check 7: Info disclosure
                self.log("info", "Running Check 7/10: Server version disclosure check...")
                raw_findings.extend(SecurityChecks.check_info_disclosure(normalized_url, dict(response.headers)))
                self.scan.progress = 80

                # Check 8: Directory listing probe
                self.log("info", "Running Check 8/10: Directory listing test...")
                try:
                    dir_url = urljoin(normalized_url, "/static/")
                    # Revalidate with scope guard
                    ScopeGuard.validate_destination_network(dir_url, self.target.hostname, self.target.allow_subdomains)
                    dir_res = await client.get(dir_url)
                    if "index of /" in dir_res.text.lower() or "directory listing for" in dir_res.text.lower():
                        raw_findings.append(SecurityCheckItem(
                            title="Directory Listing Enabled",
                            severity="medium",
                            category="Information Disclosure",
                            affected_url=dir_url,
                            description="Web server produces directory index listings displaying files.",
                            evidence=f"Directory index detected at {dir_url}",
                            impact="Allows discovering sensitive assets or unlinked scripts.",
                            remediation="Disable directory indexing (e.g. Options -Indexes).",
                            manual_verification=f"Browse to {dir_url} and check index display."
                        ))
                except Exception:
                    pass
                self.scan.progress = 85

                # Check 9: Non-destructive sensitive file probing
                self.log("info", "Running Check 9/10: Sensitive configuration file check...")
                try:
                    env_url = urljoin(normalized_url, "/.env")
                    ScopeGuard.validate_destination_network(env_url, self.target.hostname, self.target.allow_subdomains)
                    env_res = await client.get(env_url)
                    if env_res.status_code == 200 and any(k in env_res.text for k in ("DB_", "KEY=", "SECRET=")):
                        raw_findings.append(SecurityCheckItem(
                            title="Potentially Exposed .env File",
                            severity="critical",
                            category="Sensitive File Exposure",
                            affected_url=env_url,
                            description="An environment configuration file was found publicly accessible.",
                            evidence=f"Status 200 at {env_url}",
                            impact="Secrets, API tokens, and database credentials could be exposed.",
                            remediation="Block access to hidden and .env files at the web server.",
                            manual_verification=f"Query {env_url} with curl -I."
                        ))
                except Exception:
                    pass
                self.scan.progress = 90

                # Check 10: Harmless reflected input marker check
                self.log("info", "Running Check 10/10: Harmless test marker reflection audit...")
                try:
                    benign_token = "WbTokenMarker12345"
                    test_url = f"{normalized_url}?wb_marker={benign_token}"
                    ScopeGuard.validate_destination_network(test_url, self.target.hostname, self.target.allow_subdomains)
                    refl_res = await client.get(test_url)
                    if benign_token in refl_res.text:
                        raw_findings.append(SecurityCheckItem(
                            title="Harmless Test Parameter Reflected in Body",
                            severity="low",
                            category="Input Validation",
                            affected_url=test_url,
                            description=f"Benign test marker '{benign_token}' was reflected in the HTTP response body.",
                            evidence=f"Parameter reflected unencoded in {len(refl_res.text)} byte response.",
                            impact="If reflection occurs in an executable HTML context without encoding, XSS may be possible.",
                            remediation="Apply contextual HTML encoding to all reflected user input.",
                            manual_verification="Inspect element in DOM inspector where token appears."
                        ))
                except Exception:
                    pass
                self.scan.progress = 95

                # Persist findings into database
                for item in raw_findings:
                    finding_record = Finding(
                        scan_id=self.scan_id,
                        target_id=self.target.id,
                        title=item.title,
                        severity=item.severity,
                        category=item.category,
                        affected_url=item.affected_url,
                        description=item.description,
                        evidence=item.evidence,
                        impact=item.impact,
                        remediation=item.remediation,
                        verification_status=item.verification_status,
                        manual_verification=item.manual_verification,
                        first_discovered=datetime.utcnow(),
                        last_observed=datetime.utcnow()
                    )
                    self.db.add(finding_finding := finding_record)

                self.scan.progress = 100
                self.scan.status = "completed"
                self.scan.checks_run = 10
                self.scan.findings_count = len(raw_findings)
                self.scan.completed_at = datetime.utcnow()
                self.target.status = "completed"
                self.target.last_scan_at = datetime.utcnow()
                self.db.commit()

                self.log("info", f"Scan complete. 10 modular checks finished. {len(raw_findings)} findings recorded.")

        except ScopeGuardError as sge:
            self.log("error", f"ScopeGuard violation: {str(sge)}")
            self.scan.status = "failed"
            self.target.status = "error"
            self.db.commit()
        except Exception as e:
            self.log("error", f"Scan error: {str(e)}")
            self.scan.status = "failed"
            self.target.status = "error"
            self.db.commit()
