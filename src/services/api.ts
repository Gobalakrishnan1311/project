import axios from 'axios';
import { Target, Scan, Finding, Project, DashboardMetrics, DnsRecords, HttpReconData } from '../types.ts';

const client = axios.create({
  baseURL: '/api',
  headers: {
    'Content-Type': 'application/json'
  }
});

export const api = {
  // Health
  getHealth: async () => {
    const res = await client.get('/health');
    return res.data;
  },

  // Dashboard
  getDashboard: async (): Promise<{
    metrics: DashboardMetrics;
    recentScans: Scan[];
    latestFindings: Finding[];
  }> => {
    const res = await client.get('/dashboard');
    return res.data;
  },

  // Projects
  getProjects: async (): Promise<Project[]> => {
    const res = await client.get('/projects');
    return res.data;
  },
  createProject: async (data: { name: string; description?: string }): Promise<Project> => {
    const res = await client.post('/projects', data);
    return res.data;
  },

  // Targets
  getTargets: async (): Promise<Target[]> => {
    const res = await client.get('/targets');
    return res.data;
  },
  createTarget: async (data: Partial<Target>): Promise<Target> => {
    const res = await client.post('/targets', data);
    return res.data;
  },
  getTarget: async (id: string): Promise<Target & { scans: Scan[]; findings: Finding[] }> => {
    const res = await client.get(`/targets/${id}`);
    return res.data;
  },
  deleteTarget: async (id: string) => {
    const res = await client.delete(`/targets/${id}`);
    return res.data;
  },

  // Scans
  getScans: async (): Promise<Scan[]> => {
    const res = await client.get('/scans');
    return res.data;
  },
  startScan: async (data: {
    target_id: string;
    timeout?: number;
    max_requests?: number;
    concurrency?: number;
    delay_ms?: number;
  }): Promise<Scan> => {
    const res = await client.post('/scans', data);
    return res.data;
  },
  getScanDetails: async (id: string): Promise<Scan & { logs: any[]; findings: Finding[] }> => {
    const res = await client.get(`/scans/${id}`);
    return res.data;
  },
  cancelScan: async (id: string) => {
    const res = await client.post(`/scans/${id}/cancel`);
    return res.data;
  },

  // Findings
  getFindings: async (params?: { target_id?: string; severity?: string; status?: string }): Promise<Finding[]> => {
    const res = await client.get('/findings', { params });
    return res.data;
  },
  updateFinding: async (id: string, data: { verification_status?: string; severity?: string; notes?: string }): Promise<Finding> => {
    const res = await client.patch(`/findings/${id}`, data);
    return res.data;
  },
  deleteFinding: async (id: string) => {
    const res = await client.delete(`/findings/${id}`);
    return res.data;
  },

  // Reconnaissance
  getDnsRecords: async (hostname: string): Promise<{ success: boolean; records: DnsRecords }> => {
    const res = await client.post('/recon/dns', { hostname });
    return res.data;
  },
  getHttpRecon: async (url: string): Promise<HttpReconData> => {
    const res = await client.post('/recon/http', { url });
    return res.data;
  },

  // HTTP Inspector
  sendInspectionRequest: async (data: {
    url: string;
    method?: string;
    headers?: Record<string, string>;
    timeout?: number;
  }) => {
    const res = await client.post('/inspector/request', data);
    return res.data;
  },

  // Seed demo
  seedDemo: async () => {
    const res = await client.post('/demo/seed');
    return res.data;
  }
};
