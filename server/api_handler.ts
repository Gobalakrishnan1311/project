import { db, runScanAsync, Project, Target, Scan } from './store.ts';
import { ScopeGuard } from './scope_guard.ts';
import { safeFetch } from './scanner.ts';
import dns from 'dns/promises';
import { URL } from 'url';
import path from 'path';
import fs from 'fs';
import { createRequire } from 'module';

const require = createRequire(import.meta.url);
const archiver = require('archiver');

export async function handleApi(req: any, res: any) {
  const urlObj = new URL(req.url, 'http://localhost');
  const pathname = urlObj.pathname;
  const method = req.method.toUpperCase();

  // Helper JSON responders
  const json = (data: any, status = 200) => {
    res.statusCode = status;
    res.setHeader('Content-Type', 'application/json');
    res.end(JSON.stringify(data));
  };

  const errorJson = (message: string, status = 400) => {
    res.statusCode = status;
    res.setHeader('Content-Type', 'application/json');
    res.end(JSON.stringify({ error: message, success: false }));
  };

  // Helper body parser
  const getBody = async (): Promise<any> => {
    return new Promise((resolve) => {
      let body = '';
      req.on('data', (chunk: any) => {
        body += chunk;
      });
      req.on('end', () => {
        try {
          resolve(body ? JSON.parse(body) : {});
        } catch {
          resolve({});
        }
      });
    });
  };

  try {
    // 1. Health check
    if (pathname === '/api/health' && method === 'GET') {
      return json({
        status: 'healthy',
        service: 'WebBug Hunter',
        version: '1.0.0',
        mode: 'defensive_authorized_audit',
        scope_guard: 'active',
        timestamp: new Date().toISOString()
      });
    }

    // 2. Dashboard summary
    if (pathname === '/api/dashboard' && method === 'GET') {
      const allFindings = Array.from(db.findings.values());
      const allScans = Array.from(db.scans.values());
      const allTargets = Array.from(db.targets.values());

      const severityCounts = {
        critical: allFindings.filter(f => f.severity === 'critical').length,
        high: allFindings.filter(f => f.severity === 'high').length,
        medium: allFindings.filter(f => f.severity === 'medium').length,
        low: allFindings.filter(f => f.severity === 'low').length,
        informational: allFindings.filter(f => f.severity === 'informational').length
      };

      const completedScans = allScans.filter(s => s.status === 'completed').length;

      // Sort recent scans by started_at desc
      const recentScans = [...allScans]
        .sort((a, b) => new Date(b.started_at).getTime() - new Date(a.started_at).getTime())
        .slice(0, 5);

      // Sort recent findings by first_discovered desc
      const latestFindings = [...allFindings]
        .sort((a, b) => new Date(b.first_discovered).getTime() - new Date(a.first_discovered).getTime())
        .slice(0, 6);

      return json({
        metrics: {
          totalTargets: allTargets.length,
          totalScans: allScans.length,
          completedScans,
          totalFindings: allFindings.length,
          severityCounts
        },
        recentScans,
        latestFindings
      });
    }

    // 3. Projects
    if (pathname === '/api/projects') {
      if (method === 'GET') {
        return json(Array.from(db.projects.values()));
      }
      if (method === 'POST') {
        const body = await getBody();
        if (!body.name?.trim()) return errorJson('Project name is required');
        const proj: Project = {
          id: `proj-${Date.now()}`,
          name: body.name.trim(),
          description: body.description?.trim() || '',
          created_at: new Date().toISOString()
        };
        db.projects.set(proj.id, proj);
        return json(proj, 201);
      }
    }

    // 4. Targets
    if (pathname === '/api/targets') {
      if (method === 'GET') {
        return json(Array.from(db.targets.values()));
      }
      if (method === 'POST') {
        const body = await getBody();
        const rawUrl = body.url;
        if (!rawUrl) return errorJson('Target URL or domain is required');

        // Mandatory scope validation
        const norm = ScopeGuard.normalizeTargetInput(rawUrl);
        if (!norm.valid || !norm.normalizedUrl || !norm.hostname) {
          return errorJson(norm.error || 'Invalid target destination URL');
        }

        if (!body.user_authorized) {
          return errorJson('Authorization confirmation is required. You must explicitly certify authorization to test this target.', 403);
        }

        const parsed = new URL(norm.normalizedUrl);
        const target: Target = {
          id: `target-${Date.now()}`,
          project_id: body.project_id || Array.from(db.projects.values())[0]?.id || 'default-proj',
          url: norm.normalizedUrl,
          hostname: norm.hostname,
          scheme: parsed.protocol.replace(':', ''),
          user_authorized: true,
          owner_confirmation: body.owner_confirmation?.trim() || 'Owner Authorization Confirmed in ScopeGuard',
          allow_subdomains: Boolean(body.allow_subdomains),
          excluded_hosts: Array.isArray(body.excluded_hosts) ? body.excluded_hosts : [],
          excluded_paths: Array.isArray(body.excluded_paths) ? body.excluded_paths : [],
          request_timeout: Number(body.request_timeout) || 8000,
          max_requests: Number(body.max_requests) || 50,
          created_at: new Date().toISOString(),
          status: 'ready'
        };

        db.targets.set(target.id, target);
        return json(target, 201);
      }
    }

    // Specific target
    if (pathname.startsWith('/api/targets/')) {
      const targetId = pathname.replace('/api/targets/', '');
      const target = db.targets.get(targetId);
      if (!target) return errorJson('Target not found', 404);

      if (method === 'GET') {
        const scans = Array.from(db.scans.values()).filter(s => s.target_id === targetId);
        const findings = Array.from(db.findings.values()).filter(f => f.target_id === targetId);
        return json({ ...target, scans, findings });
      }

      if (method === 'DELETE') {
        db.targets.delete(targetId);
        return json({ success: true, message: 'Target removed successfully' });
      }
    }

    // 5. Scans
    if (pathname === '/api/scans') {
      if (method === 'GET') {
        return json(Array.from(db.scans.values()));
      }
      if (method === 'POST') {
        const body = await getBody();
        const targetId = body.target_id;
        const target = db.targets.get(targetId);
        if (!target) return errorJson('Invalid target ID');

        if (!target.user_authorized) {
          return errorJson('Target has not been authorized for testing. ScopeGuard blocks execution.', 403);
        }

        const scanId = `scan-${Date.now()}`;
        const newScan: Scan = {
          id: scanId,
          target_id: target.id,
          target_url: target.url,
          target_hostname: target.hostname,
          project_id: target.project_id,
          status: 'pending',
          progress: 0,
          started_at: new Date().toISOString(),
          checks_run: 0,
          findings_count: 0,
          config: {
            timeout: Number(body.timeout) || target.request_timeout || 8000,
            max_requests: Number(body.max_requests) || target.max_requests || 50,
            concurrency: Number(body.concurrency) || 2,
            delay_ms: Number(body.delay_ms) || 200
          }
        };

        db.scans.set(scanId, newScan);
        target.status = 'scanning';

        // Trigger asynchronous scan
        runScanAsync(scanId).catch(err => {
          console.error('Scan execution error:', err);
        });

        return json(newScan, 201);
      }
    }

    // Specific scan
    if (pathname.startsWith('/api/scans/')) {
      const parts = pathname.split('/');
      const scanId = parts[3];

      if (parts[4] === 'cancel' && method === 'POST') {
        const scan = db.scans.get(scanId);
        if (!scan) return errorJson('Scan not found', 404);
        db.activeCancellations.add(scanId);
        scan.status = 'cancelled';
        return json({ success: true, message: 'Scan cancellation requested' });
      }

      if (method === 'GET') {
        const scan = db.scans.get(scanId);
        if (!scan) return errorJson('Scan not found', 404);
        const logs = db.logs.filter(l => l.scan_id === scanId);
        const findings = Array.from(db.findings.values()).filter(f => f.scan_id === scanId);
        return json({ ...scan, logs, findings });
      }
    }

    // 6. Findings
    if (pathname === '/api/findings') {
      if (method === 'GET') {
        const targetId = urlObj.searchParams.get('target_id');
        const severity = urlObj.searchParams.get('severity');
        const status = urlObj.searchParams.get('status');
        let list = Array.from(db.findings.values());

        if (targetId) list = list.filter(f => f.target_id === targetId);
        if (severity) list = list.filter(f => f.severity === severity);
        if (status) list = list.filter(f => f.verification_status === status);

        return json(list);
      }
    }

    if (pathname.startsWith('/api/findings/')) {
      const findingId = pathname.replace('/api/findings/', '');
      const finding = db.findings.get(findingId);
      if (!finding) return errorJson('Finding not found', 404);

      if (method === 'PATCH') {
        const body = await getBody();
        if (body.verification_status) finding.verification_status = body.verification_status;
        if (body.severity) finding.severity = body.severity;
        if (body.notes) finding.manual_verification = `${finding.manual_verification}\nNote: ${body.notes}`;
        finding.last_observed = new Date().toISOString();
        db.findings.set(findingId, finding);
        return json(finding);
      }

      if (method === 'DELETE') {
        db.findings.delete(findingId);
        return json({ success: true, message: 'Finding deleted successfully' });
      }
    }

    // 7. Reconnaissance: DNS Lookup
    if (pathname === '/api/recon/dns' && method === 'POST') {
      const body = await getBody();
      const rawHost = body.hostname || body.url;
      if (!rawHost) return errorJson('Hostname or URL required');

      const norm = ScopeGuard.normalizeTargetInput(rawHost);
      if (!norm.valid || !norm.hostname) return errorJson(norm.error || 'Invalid host');

      const hostname = norm.hostname;

      // Scope check for SSRF
      const scopeCheck = await ScopeGuard.validateDestination(`https://${hostname}`);
      if (!scopeCheck.allowed) {
        return errorJson(`ScopeGuard blocked DNS probe: ${scopeCheck.reason}`, 403);
      }

      const records: any = {
        hostname,
        a: [],
        aaaa: [],
        mx: [],
        ns: [],
        txt: [],
        cname: []
      };

      try {
        records.a = await dns.resolve4(hostname).catch(() => []);
      } catch {}
      try {
        records.aaaa = await dns.resolve6(hostname).catch(() => []);
      } catch {}
      try {
        records.mx = await dns.resolveMx(hostname).catch(() => []);
      } catch {}
      try {
        records.ns = await dns.resolveNs(hostname).catch(() => []);
      } catch {}
      try {
        records.txt = (await dns.resolveTxt(hostname).catch(() => [])).flat();
      } catch {}
      try {
        records.cname = await dns.resolveCname(hostname).catch(() => []);
      } catch {}

      return json({ success: true, hostname, records });
    }

    // 8. Reconnaissance: HTTP metadata, robots.txt, sitemap.xml, tech detection
    if (pathname === '/api/recon/http' && method === 'POST') {
      const body = await getBody();
      const rawUrl = body.url;
      if (!rawUrl) return errorJson('URL is required');

      const norm = ScopeGuard.normalizeTargetInput(rawUrl);
      if (!norm.valid || !norm.normalizedUrl) return errorJson(norm.error || 'Invalid URL');

      const targetUrl = norm.normalizedUrl;
      const parsed = new URL(targetUrl);

      // Perform safe fetch
      const mainRes = await safeFetch(targetUrl, { timeoutMs: 8000 });

      // Robots.txt check
      let robotsContent: string | null = null;
      try {
        const robotsRes = await safeFetch(`${parsed.origin}/robots.txt`, { timeoutMs: 4000 });
        if (robotsRes.statusCode === 200) robotsContent = robotsRes.body.substring(0, 4000);
      } catch {}

      // Sitemap.xml check
      let sitemapFound = false;
      let sitemapPreview = '';
      try {
        const smRes = await safeFetch(`${parsed.origin}/sitemap.xml`, { timeoutMs: 4000 });
        if (smRes.statusCode === 200 && smRes.body.includes('<?xml')) {
          sitemapFound = true;
          sitemapPreview = smRes.body.substring(0, 800);
        }
      } catch {}

      // Passive tech detection from headers & body
      const technologies: string[] = [];
      const headers = mainRes.headers;
      if (headers['server']) technologies.push(`Server: ${headers['server']}`);
      if (headers['x-powered-by']) technologies.push(`Backend: ${headers['x-powered-by']}`);
      if (headers['cf-ray']) technologies.push('CDN: Cloudflare');
      if (headers['x-amz-cf-id']) technologies.push('CDN: AWS CloudFront');
      if (headers['x-fastly-request-id']) technologies.push('CDN: Fastly');
      if (headers['x-github-request-id']) technologies.push('Hosting: GitHub Pages');
      if (mainRes.body.includes('wp-content') || mainRes.body.includes('wp-includes')) technologies.push('CMS: WordPress');
      if (mainRes.body.includes('__NEXT_DATA__')) technologies.push('Framework: Next.js');
      if (mainRes.body.includes('data-reactroot') || mainRes.body.includes('react')) technologies.push('Framework: React');
      if (mainRes.body.includes('ng-version')) technologies.push('Framework: Angular');
      if (mainRes.body.includes('data-v-')) technologies.push('Framework: Vue.js');

      return json({
        url: targetUrl,
        statusCode: mainRes.statusCode,
        responseTimeMs: mainRes.durationMs,
        headers: mainRes.headers,
        contentType: headers['content-type'] || 'unknown',
        tlsInfo: mainRes.tlsInfo,
        robotsTxt: robotsContent,
        sitemap: { found: sitemapFound, preview: sitemapPreview },
        technologies
      });
    }

    // 9. HTTP Inspector (GET/HEAD with ScopeGuard verification)
    if (pathname === '/api/inspector/request' && method === 'POST') {
      const body = await getBody();
      const rawUrl = body.url;
      const httpMethod = (body.method || 'GET').toUpperCase();
      if (!['GET', 'HEAD'].includes(httpMethod)) {
        return errorJson('Only GET and HEAD requests are permitted in inspector mode.', 405);
      }

      const norm = ScopeGuard.normalizeTargetInput(rawUrl);
      if (!norm.valid || !norm.normalizedUrl) return errorJson(norm.error || 'Invalid URL');

      // Verify ScopeGuard
      const scopeCheck = await ScopeGuard.validateDestination(norm.normalizedUrl);
      if (!scopeCheck.allowed) {
        return errorJson(`ScopeGuard blocked inspection: ${scopeCheck.reason}`, 403);
      }

      const resInspect = await safeFetch(norm.normalizedUrl, {
        method: httpMethod,
        headers: body.headers || {},
        timeoutMs: Number(body.timeout) || 8000
      });

      return json({
        status: resInspect.statusCode,
        durationMs: resInspect.durationMs,
        headers: resInspect.headers,
        body: httpMethod === 'HEAD' ? '' : resInspect.body.substring(0, 100000), // max 100kb body preview
        truncated: resInspect.body.length > 100000,
        tlsInfo: resInspect.tlsInfo,
        cookies: resInspect.headers['set-cookie'] || null
      });
    }

    // 10. Reports: HTML, JSON, CSV
    if (pathname.startsWith('/api/reports/')) {
      const parts = pathname.split('/');
      const scanId = parts[3];
      const format = parts[4]; // 'html' | 'json' | 'csv'

      const scan = db.scans.get(scanId);
      if (!scan) return errorJson('Scan not found', 404);

      const target = db.targets.get(scan.target_id);
      const project = db.projects.get(scan.project_id);
      const findings = Array.from(db.findings.values()).filter(f => f.scan_id === scanId);

      // JSON report
      if (format === 'json') {
        res.setHeader('Content-Type', 'application/json');
        res.setHeader('Content-Disposition', `attachment; filename="webbug-hunter-report-${scanId}.json"`);
        return res.end(JSON.stringify({
          report_title: 'WebBug Hunter Security Audit Report',
          generated_at: new Date().toISOString(),
          project: project || { name: 'Bug Bounty Testing' },
          target: {
            url: scan.target_url,
            hostname: scan.target_hostname,
            authorization: target?.owner_confirmation || 'Authorized'
          },
          scan_summary: {
            scan_id: scan.id,
            started_at: scan.started_at,
            completed_at: scan.completed_at,
            checks_performed: scan.checks_run,
            total_findings: findings.length,
            severity_breakdown: {
              critical: findings.filter(f => f.severity === 'critical').length,
              high: findings.filter(f => f.severity === 'high').length,
              medium: findings.filter(f => f.severity === 'medium').length,
              low: findings.filter(f => f.severity === 'low').length,
              informational: findings.filter(f => f.severity === 'informational').length
            }
          },
          findings,
          disclaimer: 'This assessment was conducted using safe, non-destructive security checks under explicit authorization.'
        }, null, 2));
      }

      // CSV report
      if (format === 'csv') {
        res.setHeader('Content-Type', 'text/csv; charset=utf-8');
        res.setHeader('Content-Disposition', `attachment; filename="webbug-hunter-findings-${scanId}.csv"`);
        const escapeCsv = (val: string) => `"${(val || '').replace(/"/g, '""')}"`;

        const csvHeaders = ['Finding ID', 'Title', 'Severity', 'Category', 'Affected URL', 'Verification Status', 'Description', 'Evidence', 'Remediation'];
        const csvRows = findings.map(f => [
          escapeCsv(f.id),
          escapeCsv(f.title),
          escapeCsv(f.severity),
          escapeCsv(f.category),
          escapeCsv(f.affected_url),
          escapeCsv(f.verification_status),
          escapeCsv(f.description),
          escapeCsv(f.evidence),
          escapeCsv(f.remediation)
        ].join(','));

        return res.end([csvHeaders.join(','), ...csvRows].join('\n'));
      }

      // HTML report
      if (format === 'html') {
        res.setHeader('Content-Type', 'text/html; charset=utf-8');
        const severityBadgeColor = (sev: string) => {
          switch (sev) {
            case 'critical': return '#ef4444';
            case 'high': return '#f97316';
            case 'medium': return '#eab308';
            case 'low': return '#3b82f6';
            default: return '#6b7280';
          }
        };

        const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Security Audit Report - ${scan.target_hostname}</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #0f172a; color: #f8fafc; margin: 0; padding: 40px; }
    .container { max-width: 900px; margin: 0 auto; background: #1e293b; border-radius: 8px; border: 1px solid #334155; padding: 32px; }
    h1 { margin-top: 0; color: #38bdf8; font-size: 24px; border-bottom: 1px solid #334155; padding-bottom: 16px; }
    .meta-grid { display: grid; grid-template-columns: repeat(2, 1fr); gap: 16px; margin-bottom: 24px; background: #0f172a; padding: 16px; border-radius: 6px; }
    .meta-item { font-size: 14px; }
    .meta-label { color: #94a3b8; font-weight: 500; }
    .meta-value { color: #f1f5f9; font-weight: 600; }
    .summary-box { display: flex; gap: 12px; margin-bottom: 32px; }
    .stat { flex: 1; background: #0f172a; border: 1px solid #334155; border-radius: 6px; padding: 12px; text-align: center; }
    .stat-num { font-size: 24px; font-weight: 700; color: #f8fafc; }
    .stat-label { font-size: 12px; color: #94a3b8; text-transform: uppercase; }
    .finding-card { border: 1px solid #334155; border-radius: 6px; margin-bottom: 16px; background: #0f172a; padding: 16px; }
    .finding-title { font-size: 16px; font-weight: 600; display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px; }
    .badge { font-size: 11px; font-weight: 700; text-transform: uppercase; padding: 4px 8px; border-radius: 4px; color: #fff; }
    .field { margin-top: 8px; font-size: 13px; line-height: 1.5; }
    .field-label { color: #38bdf8; font-weight: 600; }
    .evidence { background: #020617; border: 1px solid #1e293b; padding: 8px; border-radius: 4px; font-family: monospace; font-size: 12px; color: #cbd5e1; word-break: break-all; margin-top: 4px; }
    .footer { margin-top: 40px; font-size: 12px; color: #64748b; text-align: center; border-top: 1px solid #334155; padding-top: 16px; }
  </style>
</head>
<body>
  <div class="container">
    <h1>WebBug Hunter — Website Security Audit Report</h1>
    
    <div class="meta-grid">
      <div class="meta-item"><span class="meta-label">Target URL:</span> <span class="meta-value">${scan.target_url}</span></div>
      <div class="meta-item"><span class="meta-label">Project:</span> <span class="meta-value">${project?.name || 'Authorized Testing'}</span></div>
      <div class="meta-item"><span class="meta-label">Scan Date:</span> <span class="meta-value">${new Date(scan.started_at).toLocaleString()}</span></div>
      <div class="meta-item"><span class="meta-label">Authorization:</span> <span class="meta-value">${target?.owner_confirmation || 'Explicit User Authorization'}</span></div>
    </div>

    <div class="summary-box">
      <div class="stat"><div class="stat-num">${scan.checks_run}</div><div class="stat-label">Checks Performed</div></div>
      <div class="stat"><div class="stat-num">${findings.length}</div><div class="stat-label">Total Findings</div></div>
      <div class="stat"><div class="stat-num" style="color: #ef4444">${findings.filter(f => f.severity === 'critical' || f.severity === 'high').length}</div><div class="stat-label">Critical / High</div></div>
      <div class="stat"><div class="stat-num" style="color: #eab308">${findings.filter(f => f.severity === 'medium').length}</div><div class="stat-label">Medium</div></div>
      <div class="stat"><div class="stat-num" style="color: #3b82f6">${findings.filter(f => f.severity === 'low' || f.severity === 'informational').length}</div><div class="stat-label">Low / Info</div></div>
    </div>

    <h2>Vulnerability Findings (${findings.length})</h2>
    ${findings.length === 0 ? '<p style="color: #94a3b8;">No security findings identified for this target.</p>' : ''}
    ${findings.map(f => `
      <div class="finding-card">
        <div class="finding-title">
          <span>${f.title}</span>
          <span class="badge" style="background: ${severityBadgeColor(f.severity)}">${f.severity}</span>
        </div>
        <div class="field"><span class="field-label">Category:</span> ${f.category} · <span class="field-label">Status:</span> ${f.verification_status}</div>
        <div class="field"><span class="field-label">Affected Endpoint:</span> ${f.affected_url}</div>
        <div class="field"><span class="field-label">Description:</span> ${f.description}</div>
        <div class="field"><span class="field-label">Impact:</span> ${f.impact}</div>
        <div class="field">
          <span class="field-label">Observed Evidence:</span>
          <div class="evidence">${f.evidence}</div>
        </div>
        <div class="field"><span class="field-label">Remediation Advice:</span> ${f.remediation}</div>
        <div class="field"><span class="field-label">Manual Verification Guidance:</span> ${f.manual_verification}</div>
      </div>
    `).join('')}

    <div class="footer">
      Generated automatically by WebBug Hunter. Strict ScopeGuard was active throughout the audit.
    </div>
  </div>
</body>
</html>`;
        return res.end(html);
      }
    }

    // 11. Demo Seed trigger
    if (pathname === '/api/demo/seed' && method === 'POST') {
      db.seedDemoData();
      return json({ success: true, message: 'Sample demo dataset loaded successfully' });
    }

    // 12. Full Project Source Code Download (.ZIP)
    if (pathname === '/api/download/source' && (method === 'GET' || method === 'HEAD')) {
      const zipPath = '/tmp/webbug-hunter-source.zip';
      try {
        const { execSync } = require('child_process');
        execSync('python3 scripts/create_zip.py /tmp/webbug-hunter-source.zip', { cwd: process.cwd() });
      } catch (e) {
        console.error('Failed to regenerate zip:', e);
      }

      if (!fs.existsSync(zipPath)) {
        return errorJson('Failed to package source code archive', 500);
      }

      const stat = fs.statSync(zipPath);
      res.statusCode = 200;
      res.setHeader('Content-Type', 'application/zip');
      res.setHeader('Content-Length', stat.size);
      res.setHeader('Content-Disposition', 'attachment; filename="webbug-hunter-source.zip"');

      if (method === 'HEAD') {
        return res.end();
      }

      const stream = fs.createReadStream(zipPath);
      return stream.pipe(res);
    }

    return errorJson('API Route not found', 404);
  } catch (err: any) {
    console.error('API Error:', err);
    return errorJson(err?.message || 'Internal server error', 500);
  }
}
