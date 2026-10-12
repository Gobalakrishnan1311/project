import React, { useState, useEffect } from 'react';
import { api } from '../services/api.ts';
import { Shield, ShieldAlert, CheckCircle2, RefreshCw, Database, Lock, Server } from 'lucide-react';

interface SettingsProps {
  onSeedDemo: () => void;
  isSeeding?: boolean;
}

export const Settings: React.FC<SettingsProps> = ({ onSeedDemo, isSeeding = false }) => {
  const [health, setHealth] = useState<any>(null);
  const [loadingHealth, setLoadingHealth] = useState(false);

  useEffect(() => {
    fetchHealth();
  }, []);

  const fetchHealth = async () => {
    setLoadingHealth(true);
    try {
      const data = await api.getHealth();
      setHealth(data);
    } catch {
      setHealth({ status: 'offline' });
    } finally {
      setLoadingHealth(false);
    }
  };

  const blockedRanges = [
    { label: 'Loopback / Localhost', spec: '127.0.0.0/8, ::1, 0.0.0.0/8', reason: 'Prevents internal node & container manipulation' },
    { label: 'RFC 1918 Private Class A', spec: '10.0.0.0/8', reason: 'Prevents intranet / VPC lateral movement' },
    { label: 'RFC 1918 Private Class B', spec: '172.16.0.0/12', reason: 'Prevents corporate LAN resource probing' },
    { label: 'RFC 1918 Private Class C', spec: '192.168.0.0/16', reason: 'Prevents local subnet discovery' },
    { label: 'Cloud Metadata (AWS/GCP/Azure)', spec: '169.254.169.254, 169.254.0.0/16', reason: 'Blocks IAM token & credential theft' },
    { label: 'IPv6 Link-Local & Unique Local', spec: 'fe80::/10, fc00::/7', reason: 'Blocks local IPv6 routing traversal' },
    { label: 'Carrier-Grade NAT (CGNAT)', spec: '100.64.0.0/10', reason: 'Prevents ISP gateway routing' },
    { label: 'Prohibited Protocol Schemes', spec: 'file://, gopher://, ftp://, dict://', reason: 'Prevents arbitrary local file extraction' }
  ];

  return (
    <div className="space-y-6">
      {/* ScopeGuard Architecture Overview */}
      <div className="p-5 rounded-lg bg-slate-900/60 border border-slate-800 space-y-3">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2.5">
            <Shield className="w-5 h-5 text-cyan-400" />
            <h2 className="text-sm font-semibold text-white tracking-tight">
              ScopeGuard Defensive Architecture & SSRF Guardrails
            </h2>
          </div>
          <span className="px-2.5 py-0.5 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 text-[11px] font-mono">
            Default-Deny Enforced
          </span>
        </div>

        <p className="text-xs text-slate-400 leading-relaxed">
          ScopeGuard is a mandatory, dedicated perimeter guard that validates every outbound network request before socket initialization. It inspects normalized hostnames, resolves DNS records prior to connection, intercepts redirects to prevent DNS rebinding attacks, and rejects all non-public destinations.
        </p>
      </div>

      {/* Blocked Destinations Matrix */}
      <div className="p-5 rounded-lg bg-slate-900/60 border border-slate-800 space-y-4">
        <h3 className="text-xs font-semibold text-white uppercase tracking-wider font-mono">
          Mandatory Prohibited CIDR & Destination Ranges
        </h3>

        <div className="rounded border border-slate-800 overflow-hidden">
          <table className="w-full text-left text-xs font-mono">
            <thead className="bg-slate-950 text-slate-400 border-b border-slate-800 text-[11px]">
              <tr>
                <th className="py-2.5 px-3">Boundary Name</th>
                <th className="py-2.5 px-3">Prohibited Subnet / Pattern</th>
                <th className="py-2.5 px-3">Security Rationale</th>
                <th className="py-2.5 px-3 text-right">Policy</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-850 bg-slate-950/60">
              {blockedRanges.map((range, idx) => (
                <tr key={idx} className="hover:bg-slate-900/40">
                  <td className="py-2 px-3 text-slate-200 font-medium">{range.label}</td>
                  <td className="py-2 px-3 text-cyan-400">{range.spec}</td>
                  <td className="py-2 px-3 text-slate-400 font-sans">{range.reason}</td>
                  <td className="py-2 px-3 text-right">
                    <span className="text-[10px] font-bold text-red-400 uppercase bg-red-500/10 border border-red-500/20 px-1.5 py-0.5 rounded">
                      BLOCKED
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Backend Health & Data Diagnostics */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {/* Backend Health */}
        <div className="p-4 rounded-lg bg-slate-900/60 border border-slate-800 space-y-3">
          <div className="flex items-center justify-between text-xs">
            <span className="font-semibold text-white flex items-center gap-1.5">
              <Server className="w-4 h-4 text-cyan-400" />
              <span>Backend Service Diagnostic</span>
            </span>
            <button
              onClick={fetchHealth}
              disabled={loadingHealth}
              className="text-slate-400 hover:text-white"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${loadingHealth ? 'animate-spin' : ''}`} />
            </button>
          </div>

          <div className="p-3 rounded bg-slate-950 font-mono text-xs space-y-1.5 border border-slate-850">
            <div className="flex justify-between">
              <span className="text-slate-500">Service:</span>
              <span className="text-slate-200">{health?.service || 'WebBug Hunter'}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-slate-500">Version:</span>
              <span className="text-slate-200">{health?.version || '1.0.0'}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-slate-500">Mode:</span>
              <span className="text-cyan-400">{health?.mode || 'defensive_audit'}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-slate-500">ScopeGuard Active:</span>
              <span className="text-emerald-400">Enforced</span>
            </div>
          </div>
        </div>

        {/* Demo Data Management */}
        <div className="p-4 rounded-lg bg-slate-900/60 border border-slate-800 space-y-3">
          <span className="font-semibold text-white text-xs flex items-center gap-1.5">
            <Database className="w-4 h-4 text-cyan-400" />
            <span>Demonstration & Scope Reset</span>
          </span>

          <p className="text-xs text-slate-400">
            Re-populate standard authorized test scopes, mock scans, and sample security audit findings for demonstrations or evaluation workflows.
          </p>

          <button
            onClick={onSeedDemo}
            disabled={isSeeding}
            className="flex items-center gap-1.5 px-3.5 py-1.5 text-xs font-medium text-white bg-slate-800 hover:bg-slate-700 border border-slate-700 rounded transition-colors disabled:opacity-50"
          >
            {isSeeding ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : <Database className="w-3.5 h-3.5 text-cyan-400" />}
            <span>{isSeeding ? 'Populating...' : 'Reset & Reload Demo Dataset'}</span>
          </button>
        </div>
      </div>

      {/* Source Code Download Section */}
      <div className="p-5 rounded-lg bg-slate-900/60 border border-slate-800 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
        <div className="space-y-1">
          <div className="flex items-center gap-2">
            <span className="text-xs font-semibold text-white">Full Source Code Package</span>
            <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">
              ZIP ARCHIVE
            </span>
          </div>
          <p className="text-xs text-slate-400 max-w-2xl">
            Download the complete project source code including frontend (React + Tailwind), backend (FastAPI + SQLAlchemy + ScopeGuard), security checks, test suites, Dockerfile, and setup instructions.
          </p>
        </div>

        <a
          href="/api/download/source"
          download="webbug-hunter-source.zip"
          className="flex items-center gap-2 px-4 py-2 font-medium text-xs text-white bg-cyan-600 hover:bg-cyan-500 rounded-md transition-colors shadow-sm whitespace-nowrap shrink-0"
        >
          <svg className="w-4 h-4 text-white" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
            <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/>
            <polyline points="7 10 12 15 17 10"/>
            <line x1="12" y1="15" x2="12" y2="3"/>
          </svg>
          <span>Download Source Code (.ZIP)</span>
        </a>
      </div>
    </div>
  );
};
