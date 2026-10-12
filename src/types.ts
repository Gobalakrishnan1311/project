export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'informational';

export type FindingStatus = 'New' | 'Needs Review' | 'Confirmed' | 'False Positive' | 'Fixed' | 'Accepted Risk';

export interface Finding {
  id: string;
  scan_id: string;
  target_id: string;
  title: string;
  severity: Severity;
  category: string;
  affected_url: string;
  description: string;
  evidence: string;
  impact: string;
  remediation: string;
  verification_status: FindingStatus;
  first_discovered: string;
  last_observed: string;
  manual_verification: string;
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

export interface Project {
  id: string;
  name: string;
  description: string;
  created_at: string;
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

export interface DashboardMetrics {
  totalTargets: number;
  totalScans: number;
  completedScans: number;
  totalFindings: number;
  severityCounts: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    informational: number;
  };
}

export interface DnsRecords {
  hostname: string;
  a: string[];
  aaaa: string[];
  mx: Array<{ exchange: string; priority: number }>;
  ns: string[];
  txt: string[];
  cname: string[];
}

export interface HttpReconData {
  url: string;
  statusCode: number;
  responseTimeMs: number;
  headers: Record<string, string>;
  contentType: string;
  tlsInfo?: {
    authorized: boolean;
    validTo?: string;
    issuer?: string;
    subject?: string;
  };
  robotsTxt: string | null;
  sitemap: { found: boolean; preview: string };
  technologies: string[];
}
