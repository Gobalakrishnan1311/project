import { ScopeGuard, TargetScopeConfig } from './scope_guard.ts';
import { SecurityAuditor, Finding, safeFetch } from './scanner.ts';
import dns from 'dns/promises';
import { URL } from 'url';

export interface Project {
  id: string;
  name: string;
  description: string;
  created_at: string;
}

export interface Target {
  id: string;
  project_id: string;
  url: string;
  hostname: string;
  scheme: string;
  user_authorized: boolean;
  owner_confirmation: string;
  allow_subdomains: boolean;
  excluded_hosts: string[];
  excluded_paths: string[];
  request_timeout: number;
  max_requests: number;
  created_at: string;
  last_scan_at?: string;
  status: 'ready' | 'scanning' | 'completed' | 'error';
}

export interface Scan {
  id: string;
  target_id: string;
  target_url: string;
  target_hostname: string;
  project_id: string;
  status: 'pending' | 'running' | 'completed' | 'cancelled' | 'failed';
  progress: number;
  started_at: string;
  completed_at?: string;
  checks_run: number;
  findings_count: number;
  config: {
    timeout: number;
    max_requests: number;
    concurrency: number;
    delay_ms: number;
  };
}

export interface ScanLog {
  id: string;
  scan_id: string;
  timestamp: string;
  level: 'info' | 'warn' | 'error';
  message: string;
}

// In-Memory Database with Demo Seed Data
class DatabaseStore {
  public projects: Map<string, Project> = new Map();
  public targets: Map<string, Target> = new Map();
  public scans: Map<string, Scan> = new Map();
  public logs: ScanLog[] = [];
  public findings: Map<string, Finding> = new Map();
  public activeCancellations: Set<string> = new Set();

  constructor() {
    this.seedDemoData();
  }

  public seedDemoData() {
    // 1. Demo Project
    const projId = 'proj-demo-1';
    this.projects.set(projId, {
      id: projId,
      name: 'Authorized Pentest Q4 - Bug Bounty Scope',
      description: 'Scope-restricted website security audit for authorized testing endpoints.',
      created_at: new Date(Date.now() - 86400000 * 3).toISOString()
    });

    // 2. Demo Target
    const targetId = 'target-demo-1';
    this.targets.set(targetId, {
      id: targetId,
      project_id: projId,
      url: 'https://example.com',
      hostname: 'example.com',
      scheme: 'https',
      user_authorized: true,
      owner_confirmation: 'Authorized Bug Bounty Scope Agreement ID #BB-2026-9941',
      allow_subdomains: true,
      excluded_hosts: ['internal.example.com', 'payment-gateway.example.com'],
      excluded_paths: ['/logout', '/delete-account'],
      request_timeout: 8000,
      max_requests: 50,
      created_at: new Date(Date.now() - 86400000 * 2).toISOString(),
      last_scan_at: new Date(Date.now() - 3600000 * 4).toISOString(),
      status: 'completed'
    });

    // 3. Demo Completed Scan
    const scanId = 'scan-demo-101';
    this.scans.set(scanId, {
      id: scanId,
      target_id: targetId,
      target_url: 'https://example.com',
      target_hostname: 'example.com',
      project_id: projId,
      status: 'completed',
      progress: 100,
      started_at: new Date(Date.now() - 3600000 * 4).toISOString(),
      completed_at: new Date(Date.now() - 3600000 * 4 + 18400).toISOString(),
      checks_run: 10,
      findings_count: 5,
      config: {
        timeout: 8000,
        max_requests: 50,
        concurrency: 2,
        delay_ms: 250
      }
    });

    // 4. Demo Logs
    this.logs.push(
      { id: 'log-1', scan_id: scanId, timestamp: new Date(Date.now() - 3600000 * 4).toISOString(), level: 'info', message: 'ScopeGuard initialized. Target authorization verified (ID: #BB-2026-9941).' },
      { id: 'log-2', scan_id: scanId, timestamp: new Date(Date.now() - 3600000 * 4 + 1000).toISOString(), level: 'info', message: 'DNS Resolution: 93.184.215.14. Destination verified as public IP (Non-SSRF compliant).' },
      { id: 'log-3', scan_id: scanId, timestamp: new Date(Date.now() - 3600000 * 4 + 2500).toISOString(), level: 'info', message: 'Executing Security Check 1/10: HTTP Security Headers analysis.' },
      { id: 'log-4', scan_id: scanId, timestamp: new Date(Date.now() - 3600000 * 4 + 4000).toISOString(), level: 'warn', message: 'Security Header finding: X-Frame-Options and X-Content-Type-Options missing.' },
      { id: 'log-5', scan_id: scanId, timestamp: new Date(Date.now() - 3600000 * 4 + 8000).toISOString(), level: 'info', message: 'Executing Security Check 2/10: Content Security Policy evaluation.' },
      { id: 'log-6', scan_id: scanId, timestamp: new Date(Date.now() - 3600000 * 4 + 11000).toISOString(), level: 'info', message: 'Executing Security Check 5/10: TLS Certificate validity inspection.' },
      { id: 'log-7', scan_id: scanId, timestamp: new Date(Date.now() - 3600000 * 4 + 14000).toISOString(), level: 'info', message: 'Executing Security Check 7/10: Technology disclosure identification.' },
      { id: 'log-8', scan_id: scanId, timestamp: new Date(Date.now() - 3600000 * 4 + 18400).toISOString(), level: 'info', message: 'Scan complete. 10 modular checks finished. 5 findings recorded in SQLite store.' }
    );

    // 5. Demo Findings
    const sampleFindings: Finding[] = [
      {
        id: 'find-demo-1',
        scan_id: scanId,
        target_id: targetId,
        title: 'Missing Content Security Policy (CSP)',
        severity: 'medium',
        category: 'Content Security',
        affected_url: 'https://example.com/',
        description: 'No Content-Security-Policy header was observed on the root document. Without a Content Security Policy, modern browser XSS execution and untrusted data injection mitigations are disabled.',
        evidence: 'Response headers missing "Content-Security-Policy".',
        impact: 'Permits execution of injected scripts if HTML sanitization flaws exist elsewhere.',
        remediation: 'Implement a strict CSP policy: default-src \'self\'; script-src \'self\'; object-src \'none\';',
        verification_status: 'New',
        first_discovered: new Date(Date.now() - 3600000 * 4).toISOString(),
        last_observed: new Date(Date.now() - 3600000 * 4).toISOString(),
        manual_verification: 'Execute `curl -I https://example.com` and review response headers.'
      },
      {
        id: 'find-demo-2',
        scan_id: scanId,
        target_id: targetId,
        title: 'Missing HTTP Strict Transport Security (HSTS)',
        severity: 'medium',
        category: 'Transport Layer Security',
        affected_url: 'https://example.com/',
        description: 'The server answers over HTTPS but omits the Strict-Transport-Security header.',
        evidence: 'Header "Strict-Transport-Security" not returned.',
        impact: 'First-time visitors may be susceptible to SSL-stripping man-in-the-middle downgrade attacks.',
        remediation: 'Send "Strict-Transport-Security: max-age=31536000; includeSubDomains".',
        verification_status: 'Confirmed',
        first_discovered: new Date(Date.now() - 3600000 * 4).toISOString(),
        last_observed: new Date(Date.now() - 3600000 * 4).toISOString(),
        manual_verification: 'Verify that HSTS header is missing in curl response.'
      },
      {
        id: 'find-demo-3',
        scan_id: scanId,
        target_id: targetId,
        title: 'Missing X-Frame-Options Clickjacking Header',
        severity: 'low',
        category: 'Security Headers',
        affected_url: 'https://example.com/',
        description: 'Neither X-Frame-Options nor CSP frame-ancestors is present.',
        evidence: 'X-Frame-Options header missing.',
        impact: 'Third-party sites can embed this page in transparent frames for clickjacking UI deception.',
        remediation: 'Add "X-Frame-Options: SAMEORIGIN" or CSP "frame-ancestors \'self\'".',
        verification_status: 'Needs Review',
        first_discovered: new Date(Date.now() - 3600000 * 4).toISOString(),
        last_observed: new Date(Date.now() - 3600000 * 4).toISOString(),
        manual_verification: 'Embed page into a local iframe to confirm behavior.'
      },
      {
        id: 'find-demo-4',
        scan_id: scanId,
        target_id: targetId,
        title: 'Missing X-Content-Type-Options Header',
        severity: 'low',
        category: 'Security Headers',
        affected_url: 'https://example.com/',
        description: 'Server lacks "X-Content-Type-Options: nosniff" protection.',
        evidence: 'X-Content-Type-Options header not present in response.',
        impact: 'Browsers may attempt MIME sniffing on untrusted resources.',
        remediation: 'Configure web server to return "X-Content-Type-Options: nosniff".',
        verification_status: 'Confirmed',
        first_discovered: new Date(Date.now() - 3600000 * 4).toISOString(),
        last_observed: new Date(Date.now() - 3600000 * 4).toISOString(),
        manual_verification: 'Check response headers on static files.'
      },
      {
        id: 'find-demo-5',
        scan_id: scanId,
        target_id: targetId,
        title: 'Missing Referrer-Policy Header',
        severity: 'informational',
        category: 'Security Headers',
        affected_url: 'https://example.com/',
        description: 'No explicit Referrer-Policy is specified. The browser may send full referrer URLs across origins.',
        evidence: 'Referrer-Policy header missing.',
        impact: 'Query parameters or path information might leak to third-party assets.',
        remediation: 'Set "Referrer-Policy: strict-origin-when-cross-origin".',
        verification_status: 'Accepted Risk',
        first_discovered: new Date(Date.now() - 3600000 * 4).toISOString(),
        last_observed: new Date(Date.now() - 3600000 * 4).toISOString(),
        manual_verification: 'Inspect outbound request referrers in browser.'
      }
    ];

    for (const f of sampleFindings) {
      this.findings.set(f.id, f);
    }
  }
}

export const db = new DatabaseStore();

export async function runScanAsync(scanId: string) {
  const scan = db.scans.get(scanId);
  if (!scan) return;

  const target = db.targets.get(scan.target_id);
  if (!target) {
    scan.status = 'failed';
    return;
  }

  scan.status = 'running';
  scan.progress = 5;

  const log = (level: 'info' | 'warn' | 'error', message: string) => {
    db.logs.push({
      id: `log-${Date.now()}-${Math.random().toString(36).substring(2, 6)}`,
      scan_id: scanId,
      timestamp: new Date().toISOString(),
      level,
      message
    });
  };

  const isCancelled = () => db.activeCancellations.has(scanId);

  const scopeConfig: TargetScopeConfig = {
    targetId: target.id,
    allowedHost: target.hostname,
    allowSubdomains: target.allow_subdomains,
    excludedHosts: target.excluded_hosts,
    excludedPaths: target.excluded_paths,
    userAuthorized: target.user_authorized,
    ownerConfirmation: target.owner_confirmation
  };

  try {
    log('info', `ScopeGuard verification initiated for target: ${target.url}`);
    
    // Step 1: Pre-flight Scope check
    const scopeCheck = await ScopeGuard.validateDestination(target.url, scopeConfig);
    if (!scopeCheck.allowed) {
      log('error', `ScopeGuard rejected target: ${scopeCheck.reason}`);
      scan.status = 'failed';
      target.status = 'error';
      return;
    }

    log('info', `Scope verified. Target resolves to ${scopeCheck.resolvedIp}. ScopeGuard allowlist confirmed.`);
    scan.progress = 15;

    if (isCancelled()) {
      scan.status = 'cancelled';
      log('warn', 'Scan cancelled by user request.');
      return;
    }

    // Delay if configured
    if (scan.config.delay_ms > 0) {
      await new Promise(r => setTimeout(r, scan.config.delay_ms));
    }

    // Step 2: Fetch baseline HTTP response
    log('info', 'Performing baseline HTTP request and header analysis...');
    const httpRes = await safeFetch(target.url, {
      timeoutMs: scan.config.timeout,
      scopeConfig
    });

    log('info', `Baseline HTTP status: ${httpRes.statusCode} (${httpRes.durationMs}ms). TLS Peer: ${httpRes.tlsInfo?.issuer || 'N/A'}`);
    scan.progress = 30;

    const newFindings: Finding[] = [];

    // Check 1: Security Headers
    if (isCancelled()) return;
    log('info', 'Running Check 1/10: HTTP Security Headers analysis...');
    const headerResults = SecurityAuditor.auditSecurityHeaders(target.url, httpRes.headers);
    for (const r of headerResults) {
      if (!r.passed && r.finding) {
        newFindings.push({
          id: `find-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`,
          scan_id: scanId,
          target_id: target.id,
          first_discovered: new Date().toISOString(),
          last_observed: new Date().toISOString(),
          ...r.finding
        });
      }
    }
    scan.progress = 40;

    // Check 2: CSP
    if (isCancelled()) return;
    log('info', 'Running Check 2/10: Content Security Policy evaluation...');
    const cspRes = SecurityAuditor.auditCSP(target.url, httpRes.headers);
    if (!cspRes.passed && cspRes.finding) {
      newFindings.push({
        id: `find-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`,
        scan_id: scanId,
        target_id: target.id,
        first_discovered: new Date().toISOString(),
        last_observed: new Date().toISOString(),
        ...cspRes.finding
      });
    }
    scan.progress = 50;

    // Check 3: HSTS
    if (isCancelled()) return;
    log('info', 'Running Check 3/10: Strict-Transport-Security enforcement...');
    const hstsRes = SecurityAuditor.auditHSTS(target.url, httpRes.headers);
    if (!hstsRes.passed && hstsRes.finding) {
      newFindings.push({
        id: `find-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`,
        scan_id: scanId,
        target_id: target.id,
        first_discovered: new Date().toISOString(),
        last_observed: new Date().toISOString(),
        ...hstsRes.finding
      });
    }
    scan.progress = 60;

    // Check 4: Cookies
    if (isCancelled()) return;
    log('info', 'Running Check 4/10: Cookie security attributes audit...');
    const cookieResults = SecurityAuditor.auditCookies(target.url, httpRes.headers);
    for (const r of cookieResults) {
      if (!r.passed && r.finding) {
        newFindings.push({
          id: `find-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`,
          scan_id: scanId,
          target_id: target.id,
          first_discovered: new Date().toISOString(),
          last_observed: new Date().toISOString(),
          ...r.finding
        });
      }
    }

    // Check 5: TLS
    if (isCancelled()) return;
    log('info', 'Running Check 5/10: TLS certificate posture and expiry...');
    const tlsRes = SecurityAuditor.auditTLS(target.url, httpRes.tlsInfo);
    if (!tlsRes.passed && tlsRes.finding) {
      newFindings.push({
        id: `find-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`,
        scan_id: scanId,
        target_id: target.id,
        first_discovered: new Date().toISOString(),
        last_observed: new Date().toISOString(),
        ...tlsRes.finding
      });
    }
    scan.progress = 70;

    // Check 6: CORS
    if (isCancelled()) return;
    log('info', 'Running Check 6/10: Cross-Origin Resource Sharing policy audit...');
    const corsRes = SecurityAuditor.auditCORS(target.url, httpRes.headers);
    if (!corsRes.passed && corsRes.finding) {
      newFindings.push({
        id: `find-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`,
        scan_id: scanId,
        target_id: target.id,
        first_discovered: new Date().toISOString(),
        last_observed: new Date().toISOString(),
        ...corsRes.finding
      });
    }

    // Check 7: Info disclosure
    if (isCancelled()) return;
    log('info', 'Running Check 7/10: Technology & server banner disclosure check...');
    const infoResults = SecurityAuditor.auditInfoDisclosure(target.url, httpRes.headers);
    for (const r of infoResults) {
      if (!r.passed && r.finding) {
        newFindings.push({
          id: `find-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`,
          scan_id: scanId,
          target_id: target.id,
          first_discovered: new Date().toISOString(),
          last_observed: new Date().toISOString(),
          ...r.finding
        });
      }
    }
    scan.progress = 80;

    // Check 8: Directory listing
    if (isCancelled()) return;
    log('info', 'Running Check 8/10: Public directory listing exposure verification...');
    const dirRes = await SecurityAuditor.auditDirectoryListing(target.url, scopeConfig);
    if (!dirRes.passed && dirRes.finding) {
      newFindings.push({
        id: `find-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`,
        scan_id: scanId,
        target_id: target.id,
        first_discovered: new Date().toISOString(),
        last_observed: new Date().toISOString(),
        ...dirRes.finding
      });
    }

    // Check 9: Exposed files
    if (isCancelled()) return;
    log('info', 'Running Check 9/10: Non-destructive sensitive config & diagnostic probing...');
    const fileResults = await SecurityAuditor.auditExposedFiles(target.url, scopeConfig);
    for (const r of fileResults) {
      if (!r.passed && r.finding) {
        newFindings.push({
          id: `find-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`,
          scan_id: scanId,
          target_id: target.id,
          first_discovered: new Date().toISOString(),
          last_observed: new Date().toISOString(),
          ...r.finding
        });
      }
    }
    scan.progress = 90;

    // Check 10: Reflected harmless token
    if (isCancelled()) return;
    log('info', 'Running Check 10/10: Harmless benign token reflection audit...');
    const reflRes = await SecurityAuditor.auditReflectedMarker(target.url, scopeConfig);
    if (!reflRes.passed && reflRes.finding) {
      newFindings.push({
        id: `find-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`,
        scan_id: scanId,
        target_id: target.id,
        first_discovered: new Date().toISOString(),
        last_observed: new Date().toISOString(),
        ...reflRes.finding
      });
    }

    // Save findings
    for (const f of newFindings) {
      db.findings.set(f.id, f);
    }

    scan.progress = 100;
    scan.status = 'completed';
    scan.completed_at = new Date().toISOString();
    scan.checks_run = 10;
    scan.findings_count = newFindings.length;
    target.status = 'completed';
    target.last_scan_at = scan.completed_at;

    log('info', `Scan completed successfully. Checks performed: 10. Findings recorded: ${newFindings.length}.`);
  } catch (err: any) {
    if (isCancelled()) {
      scan.status = 'cancelled';
      log('warn', 'Scan process stopped due to user cancellation.');
    } else {
      scan.status = 'failed';
      target.status = 'error';
      log('error', `Scan failed: ${err?.message || 'Unknown network error'}`);
    }
  } finally {
    db.activeCancellations.delete(scanId);
  }
}
