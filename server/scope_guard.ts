import dns from 'dns/promises';
import { URL } from 'url';

export interface ScopeValidationResult {
  allowed: boolean;
  reason?: string;
  normalizedUrl?: string;
  hostname?: string;
  resolvedIp?: string;
}

export interface TargetScopeConfig {
  targetId?: string;
  allowedHost: string;
  allowSubdomains?: boolean;
  excludedHosts?: string[];
  excludedPaths?: string[];
  userAuthorized: boolean;
  ownerConfirmation?: string;
}

export class ScopeGuard {
  // Reserved / Private IPv4 CIDR blocks
  private static isPrivateIpv4(ip: string): boolean {
    const parts = ip.split('.').map(Number);
    if (parts.length !== 4 || parts.some(isNaN)) return true;

    const [a, b, c, d] = parts;
    // 0.0.0.0/8
    if (a === 0) return true;
    // 127.0.0.0/8 (Loopback)
    if (a === 127) return true;
    // 10.0.0.0/8 (Private)
    if (a === 10) return true;
    // 172.16.0.0/12 (Private)
    if (a === 172 && b >= 16 && b <= 31) return true;
    // 192.168.0.0/16 (Private)
    if (a === 192 && b === 168) return true;
    // 169.254.0.0/16 (Link Local / Cloud Metadata)
    if (a === 169 && b === 254) return true;
    // 100.64.0.0/10 (CGNAT)
    if (a === 100 && b >= 64 && b <= 127) return true;
    // 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24 (Test nets)
    if (a === 192 && b === 0 && c === 2) return true;
    if (a === 198 && b === 51 && c === 100) return true;
    if (a === 203 && b === 0 && c === 113) return true;
    // 224.0.0.0/4 (Multicast) & 240.0.0.0/4 (Reserved)
    if (a >= 224) return true;

    return false;
  }

  // Reserved IPv6
  private static isPrivateIpv6(ip: string): boolean {
    const normalized = ip.toLowerCase();
    // Loopback
    if (normalized === '::1' || normalized === '0:0:0:0:0:0:0:1') return true;
    // Link local (fe80:)
    if (normalized.startsWith('fe80:') || normalized.startsWith('fe8') || normalized.startsWith('fe9') || normalized.startsWith('fea') || normalized.startsWith('feb')) return true;
    // Unique local (fc00:, fd00:)
    if (normalized.startsWith('fc') || normalized.startsWith('fd')) return true;
    // IPv4-mapped IPv6 ::ffff:x.x.x.x
    if (normalized.includes('::ffff:')) {
      const ipv4Part = normalized.split('::ffff:')[1];
      if (ipv4Part && ipv4Part.includes('.')) {
        return this.isPrivateIpv4(ipv4Part);
      }
    }
    return false;
  }

  /**
   * Validates and normalizes target input string
   */
  public static normalizeTargetInput(rawUrl: string): { valid: boolean; normalizedUrl?: string; hostname?: string; error?: string } {
    let input = rawUrl.trim();
    if (!input) {
      return { valid: false, error: 'Target URL or domain cannot be empty.' };
    }

    // Default to https:// if scheme is missing
    if (!/^https?:\/\//i.test(input)) {
      input = 'https://' + input;
    }

    try {
      const parsed = new URL(input);
      if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
        return { valid: false, error: `Prohibited protocol: ${parsed.protocol}. Only HTTP and HTTPS are permitted.` };
      }

      const hostname = parsed.hostname.toLowerCase();
      if (!hostname) {
        return { valid: false, error: 'Invalid hostname.' };
      }

      // Check obvious localhost keywords
      if (hostname === 'localhost' || hostname === '127.0.0.1' || hostname === '0.0.0.0' || hostname === '::1') {
        return { valid: false, error: 'Localhost and loopback testing is strictly prohibited by ScopeGuard.' };
      }

      // Cloud metadata hostnames
      if (hostname.includes('metadata.google.internal') || hostname.includes('169.254.169.254')) {
        return { valid: false, error: 'Cloud metadata service access is blocked.' };
      }

      return {
        valid: true,
        normalizedUrl: parsed.origin + (parsed.pathname === '/' ? '' : parsed.pathname),
        hostname,
      };
    } catch {
      return { valid: false, error: 'Malformed target URL format.' };
    }
  }

  /**
   * Deep DNS resolution & SSRF protection against resolved IP
   */
  public static async validateDestination(
    targetUrl: string,
    scopeConfig?: TargetScopeConfig
  ): Promise<ScopeValidationResult> {
    const norm = this.normalizeTargetInput(targetUrl);
    if (!norm.valid || !norm.normalizedUrl || !norm.hostname) {
      return { allowed: false, reason: norm.error || 'Invalid target destination' };
    }

    const { normalizedUrl, hostname } = norm;

    // Check scope authorization if config is provided
    if (scopeConfig) {
      if (!scopeConfig.userAuthorized) {
        return {
          allowed: false,
          reason: 'Target is not authorized. You must confirm testing authorization before issuing requests.',
          hostname,
          normalizedUrl
        };
      }

      const targetBaseHost = scopeConfig.allowedHost.toLowerCase();
      const isExactMatch = hostname === targetBaseHost;
      const isSubdomainMatch = scopeConfig.allowSubdomains && hostname.endsWith('.' + targetBaseHost);

      if (!isExactMatch && !isSubdomainMatch) {
        return {
          allowed: false,
          reason: `Host '${hostname}' is outside the approved target scope (${targetBaseHost}${scopeConfig.allowSubdomains ? ' and subdomains' : ''}).`,
          hostname,
          normalizedUrl
        };
      }

      // Check exclusions
      if (scopeConfig.excludedHosts?.some(ex => ex.toLowerCase() === hostname)) {
        return {
          allowed: false,
          reason: `Host '${hostname}' is on the target exclusion list.`,
          hostname,
          normalizedUrl
        };
      }

      const parsed = new URL(normalizedUrl);
      if (scopeConfig.excludedPaths?.some(ex => parsed.pathname.startsWith(ex))) {
        return {
          allowed: false,
          reason: `Path '${parsed.pathname}' is explicitly excluded from testing scope.`,
          hostname,
          normalizedUrl
        };
      }
    }

    // Direct IP check if hostname is already an IP literal
    if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(hostname)) {
      if (this.isPrivateIpv4(hostname)) {
        return {
          allowed: false,
          reason: `Access to private or reserved IP address '${hostname}' is strictly blocked by ScopeGuard (SSRF prevention).`,
          hostname
        };
      }
      return { allowed: true, normalizedUrl, hostname, resolvedIp: hostname };
    }

    if (hostname.includes(':')) {
      if (this.isPrivateIpv6(hostname)) {
        return {
          allowed: false,
          reason: `Access to private IPv6 address '${hostname}' is strictly blocked by ScopeGuard.`,
          hostname
        };
      }
      return { allowed: true, normalizedUrl, hostname, resolvedIp: hostname };
    }

    // Resolve DNS records to verify actual destination IP
    try {
      const addresses = await dns.resolve4(hostname);
      if (!addresses || addresses.length === 0) {
        return { allowed: false, reason: `Host '${hostname}' failed DNS resolution.` };
      }

      for (const ip of addresses) {
        if (this.isPrivateIpv4(ip)) {
          return {
            allowed: false,
            reason: `ScopeGuard blocked destination: Host '${hostname}' resolves to private/internal IP ${ip}.`,
            hostname,
            resolvedIp: ip
          };
        }
      }

      return {
        allowed: true,
        normalizedUrl,
        hostname,
        resolvedIp: addresses[0]
      };
    } catch (dnsErr: any) {
      // If IPv4 failed, attempt IPv6
      try {
        const addresses6 = await dns.resolve6(hostname);
        for (const ip of addresses6) {
          if (this.isPrivateIpv6(ip)) {
            return {
              allowed: false,
              reason: `ScopeGuard blocked destination: Host '${hostname}' resolves to private/internal IPv6 ${ip}.`,
              hostname,
              resolvedIp: ip
            };
          }
        }
        return {
          allowed: true,
          normalizedUrl,
          hostname,
          resolvedIp: addresses6[0]
        };
      } catch {
        return {
          allowed: false,
          reason: `DNS resolution error for '${hostname}': ${dnsErr?.message || 'Host not found'}.`,
          hostname
        };
      }
    }
  }
}
