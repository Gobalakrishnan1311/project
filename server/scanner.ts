import { ScopeGuard, TargetScopeConfig } from './scope_guard.ts';
import https from 'https';
import http from 'http';
import tls from 'tls';
import { URL } from 'url';

export interface Finding {
  id: string;
  scan_id: string;
  target_id: string;
  title: string;
  severity: 'informational' | 'low' | 'medium' | 'high' | 'critical';
  category: string;
  affected_url: string;
  description: string;
  evidence: string;
  impact: string;
  remediation: string;
  verification_status: 'New' | 'Needs Review' | 'Confirmed' | 'False Positive' | 'Fixed' | 'Accepted Risk';
  first_discovered: string;
  last_observed: string;
  manual_verification: string;
}

export interface ScanResult {
  scan_id: string;
  target_url: string;
  status: 'completed' | 'failed' | 'cancelled';
  checks_run: number;
  findings_count: number;
  findings: Finding[];
  logs: Array<{ timestamp: string; level: 'info' | 'warn' | 'error'; message: string }>;
  duration_ms: number;
}

export interface SecurityCheckResult {
  name: string;
  passed: boolean;
  finding?: Omit<Finding, 'id' | 'scan_id' | 'target_id' | 'first_discovered' | 'last_observed'>;
  log?: string;
}

// Safe HTTP request dispatcher enforcing ScopeGuard on every attempt
export async function safeFetch(
  url: string,
  options: {
    method?: string;
    headers?: Record<string, string>;
    timeoutMs?: number;
    scopeConfig?: TargetScopeConfig;
  } = {}
): Promise<{
  statusCode: number;
  headers: Record<string, string>;
  body: string;
  durationMs: number;
  finalUrl: string;
  tlsInfo?: {
    authorized: boolean;
    validTo?: string;
    issuer?: string;
    subject?: string;
  };
}> {
  const timeoutMs = options.timeoutMs || 8000;
  const start = Date.now();

  // Validate via ScopeGuard before connecting
  const scopeCheck = await ScopeGuard.validateDestination(url, options.scopeConfig);
  if (!scopeCheck.allowed) {
    throw new Error(`ScopeGuard blocked request: ${scopeCheck.reason}`);
  }

  const parsed = new URL(url);
  const isHttps = parsed.protocol === 'https:';

  return new Promise((resolve, reject) => {
    let timer: NodeJS.Timeout;

    const reqOptions: http.RequestOptions = {
      method: options.method || 'GET',
      hostname: parsed.hostname,
      port: parsed.port || (isHttps ? 443 : 80),
      path: parsed.pathname + parsed.search,
      headers: {
        'User-Agent': 'WebBugHunter/1.0 (Defensive Security Audit; Scope-Enforced)',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        ...(options.headers || {})
      },
      timeout: timeoutMs
    };

    const protocolModule = isHttps ? https : http;
    let tlsDetails: any = undefined;

    const req = protocolModule.request(reqOptions, (res) => {
      clearTimeout(timer);
      const headers: Record<string, string> = {};
      for (const [k, v] of Object.entries(res.headers)) {
        if (typeof v === 'string') headers[k.toLowerCase()] = v;
        else if (Array.isArray(v)) headers[k.toLowerCase()] = v.join(', ');
      }

      // Check TLS certificate if HTTPS
      if (isHttps && (res.socket as tls.TLSSocket).getPeerCertificate) {
        try {
          const tlsSocket = res.socket as tls.TLSSocket;
          const cert = tlsSocket.getPeerCertificate();
          if (cert && Object.keys(cert).length > 0) {
            tlsDetails = {
              authorized: tlsSocket.authorized,
              validTo: cert.valid_to,
              issuer: cert.issuer?.O || cert.issuer?.CN || 'Unknown Issuer',
              subject: cert.subject?.CN || parsed.hostname
            };
          }
        } catch {
          // ignore tls cert parse errors
        }
      }

      let body = '';
      res.setEncoding('utf8');

      res.on('data', (chunk) => {
        // Enforce max 2MB preview to prevent buffer exhaustion
        if (body.length < 2 * 1024 * 1024) {
          body += chunk;
        }
      });

      res.on('end', () => {
        resolve({
          statusCode: res.statusCode || 0,
          headers,
          body,
          durationMs: Date.now() - start,
          finalUrl: url,
          tlsInfo: tlsDetails
        });
      });
    });

    timer = setTimeout(() => {
      req.destroy();
      reject(new Error(`Request timed out after ${timeoutMs}ms`));
    }, timeoutMs);

    req.on('error', (err) => {
      clearTimeout(timer);
      reject(err);
    });

    req.end();
  });
}

/**
 * 10 Modular Security Checks
 */
export class SecurityAuditor {
  // Check 1: Missing or Weak HTTP Security Headers
  public static auditSecurityHeaders(targetUrl: string, headers: Record<string, string>): SecurityCheckResult[] {
    const results: SecurityCheckResult[] = [];

    // X-Frame-Options
    if (!headers['x-frame-options']) {
      results.push({
        name: 'Header: X-Frame-Options Missing',
        passed: false,
        finding: {
          title: 'Missing X-Frame-Options Header',
          severity: 'low',
          category: 'Security Headers',
          affected_url: targetUrl,
          description: 'The response does not include an X-Frame-Options header, nor a frame-ancestors directive in CSP. This may permit unauthorized clickjacking if sensitive actions can be framed.',
          evidence: `Response headers inspected: ${Object.keys(headers).join(', ')}`,
          impact: 'Adversaries could frame this web application inside an opaque iframe to deceive users into triggering uncoordinated clicks.',
          remediation: 'Implement "X-Frame-Options: DENY" or "X-Frame-Options: SAMEORIGIN", or use CSP "frame-ancestors \'self\'".',
          verification_status: 'New',
          manual_verification: 'Open a local HTML test file with <iframe src="' + targetUrl + '"></iframe> and check if the browser prevents rendering.'
        }
      });
    }

    // X-Content-Type-Options
    if (!headers['x-content-type-options'] || headers['x-content-type-options'].toLowerCase() !== 'nosniff') {
      results.push({
        name: 'Header: X-Content-Type-Options Missing or Misconfigured',
        passed: false,
        finding: {
          title: 'Missing or Invalid X-Content-Type-Options Header',
          severity: 'low',
          category: 'Security Headers',
          affected_url: targetUrl,
          description: 'The response lacks "X-Content-Type-Options: nosniff". Browsers may attempt MIME sniffing on uploaded or dynamic content.',
          evidence: headers['x-content-type-options'] ? `Observed: ${headers['x-content-type-options']}` : 'Header absent in response.',
          impact: 'MIME confusion attacks could allow script execution if user-supplied assets are interpreted as text/html or javascript.',
          remediation: 'Add "X-Content-Type-Options: nosniff" to all HTTP responses.',
          verification_status: 'New',
          manual_verification: 'Verify that server sends "X-Content-Type-Options: nosniff" across all static and dynamic endpoints.'
        }
      });
    }

    // Referrer-Policy
    if (!headers['referrer-policy']) {
      results.push({
        name: 'Header: Referrer-Policy Missing',
        passed: false,
        finding: {
          title: 'Missing Referrer-Policy Header',
          severity: 'informational',
          category: 'Security Headers',
          affected_url: targetUrl,
          description: 'No explicit Referrer-Policy is specified. The browser may default to leaking path or query parameters in the Referer header to external destinations.',
          evidence: 'Header "Referrer-Policy" was not found in response.',
          impact: 'Sensitive URL parameters (tokens, session IDs, internal IDs) could leak to third-party domains in outbound links.',
          remediation: 'Set "Referrer-Policy: strict-origin-when-cross-origin" or "no-referrer".',
          verification_status: 'New',
          manual_verification: 'Check outbound link headers in browser DevTools Network tab.'
        }
      });
    }

    // Permissions-Policy
    if (!headers['permissions-policy'] && !headers['feature-policy']) {
      results.push({
        name: 'Header: Permissions-Policy Missing',
        passed: false,
        finding: {
          title: 'Missing Permissions-Policy Header',
          severity: 'informational',
          category: 'Security Headers',
          affected_url: targetUrl,
          description: 'No Permissions-Policy header is defined to restrict browser hardware and feature capabilities (camera, microphone, geolocation, usb).',
          evidence: 'Neither "Permissions-Policy" nor legacy "Feature-Policy" observed.',
          impact: 'Embedded third-party frames or cross-origin scripts might request access to device APIs without strict site-level constraints.',
          remediation: 'Define a Permissions-Policy header, for example: "camera=(), microphone=(), geolocation=()".',
          verification_status: 'New',
          manual_verification: 'Inspect site permissions in browser page info modal.'
        }
      });
    }

    return results;
  }

  // Check 2: Content Security Policy (CSP)
  public static auditCSP(targetUrl: string, headers: Record<string, string>): SecurityCheckResult {
    const csp = headers['content-security-policy'];
    if (!csp) {
      return {
        name: 'CSP: Missing Content Security Policy',
        passed: false,
        finding: {
          title: 'Missing Content Security Policy (CSP)',
          severity: 'medium',
          category: 'Content Security',
          affected_url: targetUrl,
          description: 'No Content-Security-Policy header was observed. CSP is a primary defense-in-depth barrier against cross-site scripting (XSS) and unauthorized resource loading.',
          evidence: 'Header "Content-Security-Policy" is missing in HTTP response.',
          impact: 'Without CSP, the browser has no origin enforcement restrictions for script sources, object tags, or data exfiltration endpoints.',
          remediation: 'Implement a strict CSP such as: default-src \'self\'; script-src \'self\' \'nonce-...\'; style-src \'self\' \'unsafe-inline\'; object-src \'none\';',
          verification_status: 'New',
          manual_verification: 'Review page source scripts and formulate a baseline CSP starting in Report-Only mode.'
        }
      };
    }

    // Check for unsafe directives in existing CSP
    if (csp.includes("'unsafe-inline'") || csp.includes("'unsafe-eval'") || csp.includes('*')) {
      return {
        name: 'CSP: Weak Directives Detected',
        passed: false,
        finding: {
          title: 'Weak Content Security Policy Directives',
          severity: 'low',
          category: 'Content Security',
          affected_url: targetUrl,
          description: 'A Content Security Policy exists but includes permissive directives such as \'unsafe-inline\', \'unsafe-eval\', or wildcard hosts (*).',
          evidence: `CSP Value: ${csp.substring(0, 300)}...`,
          impact: 'Permissive CSP directives undermine XSS mitigation effectiveness.',
          remediation: 'Migrate to nonce-based or hash-based script execution and eliminate \'unsafe-inline\' and \'unsafe-eval\'.',
          verification_status: 'New',
          manual_verification: 'Run CSP Evaluator (csp-evaluator.withgoogle.com) on the policy string.'
        }
      };
    }

    return { name: 'CSP: Strict Policy Enforced', passed: true };
  }

  // Check 3: Strict-Transport-Security (HSTS)
  public static auditHSTS(targetUrl: string, headers: Record<string, string>): SecurityCheckResult {
    const isHttps = targetUrl.startsWith('https://');
    const hsts = headers['strict-transport-security'];

    if (!isHttps) {
      return {
        name: 'HSTS: Inapplicable (Target served over Plain HTTP)',
        passed: false,
        finding: {
          title: 'Website Not Served Over HTTPS',
          severity: 'high',
          category: 'Transport Layer Security',
          affected_url: targetUrl,
          description: 'Target was requested over unencrypted HTTP protocol without mandatory TLS encryption.',
          evidence: `Scheme: http://, Target: ${targetUrl}`,
          impact: 'All plaintext traffic is vulnerable to eavesdropping and on-path manipulation.',
          remediation: 'Enforce HTTPS everywhere and redirect all HTTP traffic to HTTPS.',
          verification_status: 'Confirmed',
          manual_verification: 'Test automatic redirect from port 80 to 443 with curl -I.'
        }
      };
    }

    if (!hsts) {
      return {
        name: 'HSTS: Missing Strict-Transport-Security',
        passed: false,
        finding: {
          title: 'Missing HTTP Strict Transport Security (HSTS)',
          severity: 'medium',
          category: 'Transport Layer Security',
          affected_url: targetUrl,
          description: 'The HTTPS response does not include a Strict-Transport-Security header. Browsers may allow initial unencrypted connection downgrade attempts.',
          evidence: 'Header "Strict-Transport-Security" not present in response.',
          impact: 'First-time visitors can be subjected to SSL-stripping attacks on untrusted wireless networks.',
          remediation: 'Configure "Strict-Transport-Security: max-age=31536000; includeSubDomains; preload".',
          verification_status: 'New',
          manual_verification: 'Verify HSTS header with curl -sI https://... | grep -i strict-transport-security.'
        }
      };
    }

    return { name: 'HSTS: Strict Transport Security Present', passed: true };
  }

  // Check 4: Cookie Flags (Secure, HttpOnly, SameSite)
  public static auditCookies(targetUrl: string, headers: Record<string, string>): SecurityCheckResult[] {
    const rawCookies = headers['set-cookie'];
    if (!rawCookies) return [];

    const results: SecurityCheckResult[] = [];
    const cookiesList = rawCookies.split(/,(?=\s*[a-zA-Z0-9_\-]+=)/);

    for (const cookie of cookiesList) {
      const cookieTrimmed = cookie.trim();
      const cookieName = cookieTrimmed.split('=')[0];
      const lower = cookieTrimmed.toLowerCase();

      const isSecure = lower.includes('secure');
      const isHttpOnly = lower.includes('httponly');
      const hasSameSite = lower.includes('samesite');

      if (!isSecure && targetUrl.startsWith('https://')) {
        results.push({
          name: `Cookie '${cookieName}': Missing Secure Flag`,
          passed: false,
          finding: {
            title: `Cookie "${cookieName}" Missing Secure Flag`,
            severity: 'medium',
            category: 'Session Management',
            affected_url: targetUrl,
            description: `The cookie "${cookieName}" was issued over HTTPS without the "Secure" directive.`,
            evidence: `Set-Cookie: ${cookieTrimmed}`,
            impact: 'The browser could transmit this cookie in unencrypted HTTP requests if a user visits an http:// link.',
            remediation: 'Append the "; Secure" flag to all cookies set over HTTPS.',
            verification_status: 'New',
            manual_verification: 'Inspect cookie attributes in browser Storage/Application tab.'
          }
        });
      }

      if (!isHttpOnly && !cookieName.startsWith('_ga') && !cookieName.startsWith('theme')) {
        results.push({
          name: `Cookie '${cookieName}': Missing HttpOnly Flag`,
          passed: false,
          finding: {
            title: `Cookie "${cookieName}" Missing HttpOnly Flag`,
            severity: 'low',
            category: 'Session Management',
            affected_url: targetUrl,
            description: `The cookie "${cookieName}" lacks the HttpOnly attribute. Client-side JavaScript can read this cookie.`,
            evidence: `Set-Cookie: ${cookieTrimmed}`,
            impact: 'If a cross-site scripting flaw exists anywhere on the site, malicious scripts could read and steal this cookie value.',
            remediation: 'Add "; HttpOnly" flag to all session and sensitive authentication tokens.',
            verification_status: 'New',
            manual_verification: 'Type `document.cookie` in browser console to verify whether the cookie is accessible.'
          }
        });
      }

      if (!hasSameSite) {
        results.push({
          name: `Cookie '${cookieName}': Missing SameSite Attribute`,
          passed: false,
          finding: {
            title: `Cookie "${cookieName}" Missing SameSite Attribute`,
            severity: 'low',
            category: 'Session Management',
            affected_url: targetUrl,
            description: `The cookie does not specify a SameSite directive (Lax or Strict).`,
            evidence: `Set-Cookie: ${cookieTrimmed}`,
            impact: 'May expose session or state cookies to Cross-Site Request Forgery (CSRF) in cross-site browsing contexts.',
            remediation: 'Add "; SameSite=Lax" or "; SameSite=Strict" to all Set-Cookie headers.',
            verification_status: 'New',
            manual_verification: 'Verify SameSite attribute in response headers.'
          }
        });
      }
    }

    return results;
  }

  // Check 5: TLS / HTTPS Configuration
  public static auditTLS(targetUrl: string, tlsInfo?: any): SecurityCheckResult {
    if (!targetUrl.startsWith('https://')) {
      return { name: 'TLS: Plain HTTP target', passed: false };
    }

    if (!tlsInfo) {
      return {
        name: 'TLS: Certificate Data Unavailable',
        passed: false,
        finding: {
          title: 'TLS Certificate Could Not Be Verified',
          severity: 'low',
          category: 'Transport Layer Security',
          affected_url: targetUrl,
          description: 'Could not extract TLS certificate metadata during the connection handshake.',
          evidence: 'No peer certificate returned from socket.',
          impact: 'Unable to verify authenticity of endpoint certificate.',
          remediation: 'Inspect SSL/TLS certificate installation and web server cipher configuration.',
          verification_status: 'Needs Review',
          manual_verification: 'Use openssl s_client -connect <host>:443 -servername <host> to inspect certificate chain.'
        }
      };
    }

    // Check expiration date
    if (tlsInfo.validTo) {
      const expiry = new Date(tlsInfo.validTo).getTime();
      const now = Date.now();
      const daysRemaining = Math.floor((expiry - now) / (1000 * 60 * 60 * 24));

      if (daysRemaining < 0) {
        return {
          name: 'TLS: Expired Certificate',
          passed: false,
          finding: {
            title: 'TLS Certificate Expired',
            severity: 'high',
            category: 'Transport Layer Security',
            affected_url: targetUrl,
            description: `The SSL/TLS certificate for this target expired on ${tlsInfo.validTo}.`,
            evidence: `Certificate valid_to: ${tlsInfo.validTo}, Issuer: ${tlsInfo.issuer}`,
            impact: 'Visitors will receive severe browser security warning screens preventing site access.',
            remediation: 'Renew and deploy a valid SSL/TLS certificate immediately.',
            verification_status: 'Confirmed',
            manual_verification: 'Check certificate date in browser address bar lock icon.'
          }
        };
      } else if (daysRemaining <= 14) {
        return {
          name: 'TLS: Certificate Expiring Soon',
          passed: false,
          finding: {
            title: `TLS Certificate Expiring Soon (${daysRemaining} Days)`,
            severity: 'low',
            category: 'Transport Layer Security',
            affected_url: targetUrl,
            description: `The SSL certificate expires in ${daysRemaining} days (${tlsInfo.validTo}).`,
            evidence: `Issuer: ${tlsInfo.issuer}, Expiry: ${tlsInfo.validTo}`,
            impact: 'If renewal automation fails, the site will trigger browser blocking warnings.',
            remediation: 'Ensure automated renewal (e.g. Certbot / Let\'s Encrypt) is operating properly.',
            verification_status: 'New',
            manual_verification: 'Check ACME / certbot logs on web server.'
          }
        };
      }
    }

    return { name: 'TLS: Certificate Valid', passed: true };
  }

  // Check 6: Unsafe CORS Configuration
  public static auditCORS(targetUrl: string, headers: Record<string, string>): SecurityCheckResult {
    const acao = headers['access-control-allow-origin'];
    const acac = headers['access-control-allow-credentials'];

    if (acao === '*' && acac === 'true') {
      return {
        name: 'CORS: Wildcard Origin With Credentials Flag',
        passed: false,
        finding: {
          title: 'Unsafe CORS: Wildcard Origin with Credentials',
          severity: 'high',
          category: 'Access Control',
          affected_url: targetUrl,
          description: 'The server combines Access-Control-Allow-Origin: * with Access-Control-Allow-Credentials: true. While modern browsers reject this combination, it indicates a flawed CORS configuration.',
          evidence: `ACAO: ${acao}, ACAC: ${acac}`,
          impact: 'May allow unauthorized cross-origin requests or indicate misconfigured authentication boundaries.',
          remediation: 'Explicitly specify trusted origins in Access-Control-Allow-Origin rather than wildcards when credentials are used.',
          verification_status: 'Needs Review',
          manual_verification: 'Send request with Origin: https://evil.attacker.example and inspect response headers.'
        }
      };
    }

    if (acao === 'null') {
      return {
        name: 'CORS: Null Origin Permitted',
        passed: false,
        finding: {
          title: 'Insecure CORS "null" Origin Allowed',
          severity: 'medium',
          category: 'Access Control',
          affected_url: targetUrl,
          description: 'The server permits the "null" origin in Access-Control-Allow-Origin. Sandboxed iframes and local file protocols generate a "null" origin.',
          evidence: `Access-Control-Allow-Origin: ${acao}`,
          impact: 'Attacker sandboxed iframes could trigger cross-origin API requests and read authenticated responses.',
          remediation: 'Do not allow "null" in Access-Control-Allow-Origin.',
          verification_status: 'New',
          manual_verification: 'Test with curl -H "Origin: null" and observe ACAO header.'
        }
      };
    }

    return { name: 'CORS: Safe or Not Specified', passed: true };
  }

  // Check 7: Server Version or Tech Disclosure
  public static auditInfoDisclosure(targetUrl: string, headers: Record<string, string>): SecurityCheckResult[] {
    const results: SecurityCheckResult[] = [];
    const server = headers['server'];
    const poweredBy = headers['x-powered-by'];
    const aspNet = headers['x-aspnet-version'];

    if (server && /\d+\.\d+/.test(server)) {
      results.push({
        name: 'Disclosure: Server Version Banner',
        passed: false,
        finding: {
          title: `Server Version Disclosure (${server})`,
          severity: 'low',
          category: 'Information Disclosure',
          affected_url: targetUrl,
          description: `The "Server" header reveals precise software and version numbers: "${server}".`,
          evidence: `Server: ${server}`,
          impact: 'Assists attackers in fingerprinting known CVEs and vulnerabilities specific to this software release.',
          remediation: 'Configure the web server (e.g. "ServerTokens Prod" in Apache or "server_tokens off" in Nginx) to suppress detailed version numbers.',
          verification_status: 'New',
          manual_verification: 'Verify server header reduction in production responses.'
        }
      });
    }

    if (poweredBy) {
      results.push({
        name: 'Disclosure: X-Powered-By Header Present',
        passed: false,
        finding: {
          title: `Technology Fingerprint Disclosure (${poweredBy})`,
          severity: 'informational',
          category: 'Information Disclosure',
          affected_url: targetUrl,
          description: `The "X-Powered-By" header discloses underlying framework: "${poweredBy}".`,
          evidence: `X-Powered-By: ${poweredBy}`,
          impact: 'Provides architectural details to external observers that simplify reconnaissance.',
          remediation: 'Disable X-Powered-By header in application framework settings (e.g. app.disable(\'x-powered-by\') in Express, expose_php = Off in php.ini).',
          verification_status: 'New',
          manual_verification: 'Check curl -I output for absence of X-Powered-By.'
        }
      });
    }

    if (aspNet) {
      results.push({
        name: 'Disclosure: X-AspNet-Version Header Present',
        passed: false,
        finding: {
          title: `ASP.NET Version Disclosure (${aspNet})`,
          severity: 'low',
          category: 'Information Disclosure',
          affected_url: targetUrl,
          description: `The "X-AspNet-Version" header discloses the exact runtime framework version.`,
          evidence: `X-AspNet-Version: ${aspNet}`,
          impact: 'Aids attackers in pinpointing targeted exploits for this specific ASP.NET version.',
          remediation: 'Set <httpRuntime enableVersionHeader="false" /> in web.config.',
          verification_status: 'New',
          manual_verification: 'Verify web.config disables version headers.'
        }
      });
    }

    return results;
  }

  // Check 8: Directory Listing Check
  public static async auditDirectoryListing(targetUrl: string, scopeConfig?: TargetScopeConfig): Promise<SecurityCheckResult> {
    try {
      const parsed = new URL(targetUrl);
      const testPath = new URL('/static/', parsed.origin).toString();
      const res = await safeFetch(testPath, { timeoutMs: 5000, scopeConfig });

      const bodyLower = res.body.toLowerCase();
      if (
        bodyLower.includes('index of /') ||
        bodyLower.includes('directory listing for') ||
        bodyLower.includes('<title>index of')
      ) {
        return {
          name: 'Directory Listing Exposed',
          passed: false,
          finding: {
            title: 'Directory Listing Enabled',
            severity: 'medium',
            category: 'Information Disclosure',
            affected_url: testPath,
            description: 'The web server generates directory index listings showing file contents and directories.',
            evidence: `Response contains directory index keywords at ${testPath}`,
            impact: 'Internal files, backup archives, logs, or unlinked scripts may be discovered and downloaded.',
            remediation: 'Disable automatic directory listing (e.g. Options -Indexes in Apache, autoindex off; in Nginx).',
            verification_status: 'Confirmed',
            manual_verification: 'Navigate to directory URLs and verify 403 or 404 is returned instead of index.'
          }
        };
      }
    } catch {
      // safe fallback if network or scope restricts
    }
    return { name: 'Directory Listing: Disabled or Inaccessible', passed: true };
  }

  // Check 9: Exposed Sensitive / Config Files (Passive / Non-destructive Probing)
  public static async auditExposedFiles(targetUrl: string, scopeConfig?: TargetScopeConfig): Promise<SecurityCheckResult[]> {
    const results: SecurityCheckResult[] = [];
    const parsed = new URL(targetUrl);

    // List of standard benign probes for exposure
    const probes = [
      {
        path: '/.env',
        title: 'Potentially Exposed .env Environment File',
        severity: 'critical' as const,
        indicator: (body: string, status: number) => status === 200 && (body.includes('DB_') || body.includes('KEY=') || body.includes('SECRET=') || body.includes('PASSWORD='))
      },
      {
        path: '/.git/HEAD',
        title: 'Exposed .git Repository Metadata',
        severity: 'high' as const,
        indicator: (body: string, status: number) => status === 200 && body.startsWith('ref: refs/')
      },
      {
        path: '/robots.txt',
        title: 'robots.txt Disclosing Sensitive Disallow Paths',
        severity: 'informational' as const,
        indicator: (body: string, status: number) => status === 200 && /disallow:\s*\/admin|disallow:\s*\/backup|disallow:\s*\/api\/internal/i.test(body)
      }
    ];

    for (const p of probes) {
      try {
        const probeUrl = new URL(p.path, parsed.origin).toString();
        const res = await safeFetch(probeUrl, { timeoutMs: 5000, scopeConfig });

        if (p.indicator(res.body, res.statusCode)) {
          results.push({
            name: `File Probe: ${p.path}`,
            passed: false,
            finding: {
              title: p.title,
              severity: p.severity,
              category: 'Sensitive File Exposure',
              affected_url: probeUrl,
              description: `A probe to ${p.path} returned HTTP ${res.statusCode} with characteristic contents.`,
              evidence: `Status: ${res.statusCode}, Snippet: ${res.body.substring(0, 150).replace(/[\r\n]+/g, ' ')}`,
              impact: 'Sensitive source code, configuration variables, or administrative paths may be exposed to the public.',
              remediation: `Block direct public HTTP access to ${p.path} in server configuration.`,
              verification_status: 'New',
              manual_verification: `Verify access restriction with curl -I "${probeUrl}".`
            }
          });
        }
      } catch {
        // Skip on error
      }
    }

    return results;
  }

  // Check 10: Harmless Reflected Input Marker Check
  // Uses a purely benign alphanumeric test string with no script tags, no exploits
  public static async auditReflectedMarker(targetUrl: string, scopeConfig?: TargetScopeConfig): Promise<SecurityCheckResult> {
    const benignMarker = 'WbAuditTestToken' + Math.floor(100000 + Math.random() * 900000);
    try {
      const parsed = new URL(targetUrl);
      parsed.searchParams.set('wbhunter_test', benignMarker);
      const testUrl = parsed.toString();

      const res = await safeFetch(testUrl, { timeoutMs: 6000, scopeConfig });
      if (res.body.includes(benignMarker)) {
        return {
          name: 'Input Reflection: Harmless Test Marker Reflected',
          passed: false,
          finding: {
            title: 'Harmless Test Parameter Reflected in Response Body',
            severity: 'low',
            category: 'Input Validation',
            affected_url: testUrl,
            description: `The benign parameter "${benignMarker}" submitted via query string was reflected verbatim in the response body. This is an observation of reflection behavior, not an assertion of exploitable XSS.`,
            evidence: `Query parameter wbhunter_test was reflected in ${res.body.length} byte response.`,
            impact: 'If application fails to sanitize or contextually encode this input in an executable HTML context, Cross-Site Scripting (XSS) could be possible.',
            remediation: 'Ensure all user-supplied input is context-aware encoded (HTML entity, attribute, or JSON encoding) before rendering in templates.',
            verification_status: 'Needs Review',
            manual_verification: 'Review where the parameter appears in the DOM using DevTools Elements inspector to check if contextual encoding is enforced.'
          }
        };
      }
    } catch {
      // safe fallback
    }
    return { name: 'Input Reflection: No Immediate Unfiltered Marker Reflected', passed: true };
  }
}
