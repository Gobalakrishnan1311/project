import io
import csv
import json
from datetime import datetime
from typing import List, Dict, Any
from .models import Scan, Finding, Project, Target

class ReportGenerator:
    @staticmethod
    def generate_json(scan: Scan, project: Project, target: Target, findings: List[Finding]) -> str:
        report_data = {
            "report_title": "WebBug Hunter — Website Security Audit Report",
            "generated_at": datetime.utcnow().isoformat(),
            "project": {
                "id": project.id,
                "name": project.name,
                "description": project.description
            },
            "target": {
                "id": target.id,
                "url": target.url,
                "hostname": target.hostname,
                "authorization_confirmation": target.owner_confirmation
            },
            "scan": {
                "scan_id": scan.id,
                "started_at": scan.started_at.isoformat() if scan.started_at else None,
                "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
                "checks_run": scan.checks_run,
                "total_findings": len(findings),
                "severity_counts": {
                    "critical": len([f for f in findings if f.severity == "critical"]),
                    "high": len([f for f in findings if f.severity == "high"]),
                    "medium": len([f for f in findings if f.severity == "medium"]),
                    "low": len([f for f in findings if f.severity == "low"]),
                    "informational": len([f for f in findings if f.severity == "informational"]),
                }
            },
            "findings": [
                {
                    "id": f.id,
                    "title": f.title,
                    "severity": f.severity,
                    "category": f.category,
                    "affected_url": f.affected_url,
                    "description": f.description,
                    "evidence": f.evidence,
                    "impact": f.impact,
                    "remediation": f.remediation,
                    "verification_status": f.verification_status,
                    "manual_verification": f.manual_verification
                }
                for f in findings
            ],
            "disclaimer": "Defensive security audit conducted under explicit authorization. Prohibited attacks were blocked by ScopeGuard."
        }
        return json.dumps(report_data, indent=2)

    @staticmethod
    def generate_csv(findings: List[Finding]) -> str:
        output = io.StringIO()
        writer = csv.writer(output, quoting=csv.QUOTE_ALL)
        writer.writerow([
            "Finding ID", "Title", "Severity", "Category",
            "Affected URL", "Verification Status", "Description",
            "Evidence", "Impact", "Remediation"
        ])
        for f in findings:
            writer.writerow([
                f.id, f.title, f.severity, f.category,
                f.affected_url, f.verification_status, f.description,
                f.evidence, f.impact, f.remediation
            ])
        return output.getvalue()

    @staticmethod
    def generate_html(scan: Scan, project: Project, target: Target, findings: List[Finding]) -> str:
        def badge_color(sev: str) -> str:
            colors = {
                "critical": "#ef4444",
                "high": "#f97316",
                "medium": "#eab308",
                "low": "#3b82f6",
                "informational": "#6b7280"
            }
            return colors.get(sev, "#6b7280")

        findings_html = "".join([
            f"""
            <div style="border: 1px solid #334155; border-radius: 6px; padding: 16px; margin-bottom: 16px; background: #0f172a;">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
                    <span style="font-size: 16px; font-weight: 600; color: #f8fafc;">{f.title}</span>
                    <span style="background: {badge_color(f.severity)}; color: white; padding: 3px 8px; border-radius: 4px; font-size: 11px; font-weight: bold; text-transform: uppercase;">{f.severity}</span>
                </div>
                <div style="color: #94a3b8; font-size: 12px; margin-bottom: 8px;">Category: {f.category} · Status: {f.verification_status}</div>
                <div style="color: #cbd5e1; font-size: 13px; margin-bottom: 8px;"><strong>Affected URL:</strong> {f.affected_url}</div>
                <div style="color: #cbd5e1; font-size: 13px; margin-bottom: 8px;">{f.description}</div>
                <div style="background: #020617; border: 1px solid #1e293b; padding: 8px; border-radius: 4px; font-family: monospace; font-size: 11px; color: #cbd5e1; margin-bottom: 8px;">{f.evidence}</div>
                <div style="color: #38bdf8; font-size: 12px;"><strong>Remediation:</strong> {f.remediation}</div>
            </div>
            """
            for f in findings
        ])

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Security Audit Report - {target.hostname}</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #030712; color: #f1f5f9; padding: 40px; }}
        .box {{ max-width: 900px; margin: 0 auto; background: #111827; border: 1px solid #1f2937; border-radius: 8px; padding: 32px; }}
        h1 {{ color: #38bdf8; font-size: 22px; border-bottom: 1px solid #374151; padding-bottom: 16px; }}
    </style>
</head>
<body>
    <div class="box">
        <h1>WebBug Hunter — Website Security Audit Report</h1>
        <p><strong>Target:</strong> {target.url} | <strong>Project:</strong> {project.name}</p>
        <p><strong>Scope Authorization:</strong> {target.owner_confirmation}</p>
        <p><strong>Total Checks:</strong> {scan.checks_run} | <strong>Findings Identified:</strong> {len(findings)}</p>
        <hr style="border: 0; border-top: 1px solid #374151; margin: 24px 0;">
        <h2>Vulnerability Findings ({len(findings)})</h2>
        {findings_html if findings else '<p style="color: #9ca3af;">No vulnerabilities identified.</p>'}
    </div>
</body>
</html>"""
