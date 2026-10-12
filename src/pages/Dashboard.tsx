import React from 'react';
import {
  Target,
  ShieldCheck,
  Bug,
  Activity,
  ArrowUpRight,
  ExternalLink,
  Play
} from 'lucide-react';
import { DashboardMetrics, Scan, Finding } from '../types.ts';
import { NavTab } from '../components/Sidebar.tsx';

interface DashboardProps {
  metrics: DashboardMetrics | null;
  recentScans: Scan[];
  latestFindings: Finding[];
  onNavigate: (tab: NavTab) => void;
  onSelectScan: (scanId: string) => void;
  onSelectFinding: (finding: Finding) => void;
  onStartQuickScan: (targetId: string) => void;
}

export const Dashboard: React.FC<DashboardProps> = ({
  metrics,
  recentScans,
  latestFindings,
  onNavigate,
  onSelectScan,
  onSelectFinding,
}) => {
  const severityColors = {
    critical: { text: 'text-red-400', bg: 'bg-red-500/10', border: 'border-red-500/20' },
    high: { text: 'text-amber-400', bg: 'bg-amber-500/10', border: 'border-amber-500/20' },
    medium: { text: 'text-yellow-400', bg: 'bg-yellow-500/10', border: 'border-yellow-500/20' },
    low: { text: 'text-cyan-400', bg: 'bg-cyan-500/10', border: 'border-cyan-500/20' },
    informational: { text: 'text-slate-400', bg: 'bg-slate-500/10', border: 'border-slate-500/20' }
  };

  const totalFindings = metrics?.totalFindings || 0;

  return (
    <div className="space-y-6">
      {/* 4 KPI Summary Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="p-4 rounded-lg bg-slate-900/60 border border-slate-800">
          <div className="flex items-center justify-between text-slate-400 mb-2">
            <span className="text-xs font-medium uppercase tracking-wider">Authorized Targets</span>
            <Target className="w-4 h-4 text-cyan-400" />
          </div>
          <div className="text-2xl font-bold font-mono tabular-nums text-white">
            {metrics?.totalTargets ?? 0}
          </div>
          <div className="text-xs text-slate-500 mt-1">
            Strictly scope-verified
          </div>
        </div>

        <div className="p-4 rounded-lg bg-slate-900/60 border border-slate-800">
          <div className="flex items-center justify-between text-slate-400 mb-2">
            <span className="text-xs font-medium uppercase tracking-wider">Total Scans Run</span>
            <Activity className="w-4 h-4 text-blue-400" />
          </div>
          <div className="text-2xl font-bold font-mono tabular-nums text-white">
            {metrics?.totalScans ?? 0}
          </div>
          <div className="text-xs text-slate-500 mt-1">
            {metrics?.completedScans ?? 0} completed successfully
          </div>
        </div>

        <div className="p-4 rounded-lg bg-slate-900/60 border border-slate-800">
          <div className="flex items-center justify-between text-slate-400 mb-2">
            <span className="text-xs font-medium uppercase tracking-wider">Identified Findings</span>
            <Bug className="w-4 h-4 text-amber-400" />
          </div>
          <div className="text-2xl font-bold font-mono tabular-nums text-white">
            {totalFindings}
          </div>
          <div className="text-xs text-slate-500 mt-1">
            Across active target scopes
          </div>
        </div>

        <div className="p-4 rounded-lg bg-slate-900/60 border border-slate-800">
          <div className="flex items-center justify-between text-slate-400 mb-2">
            <span className="text-xs font-medium uppercase tracking-wider">ScopeGuard Status</span>
            <ShieldCheck className="w-4 h-4 text-emerald-400" />
          </div>
          <div className="text-2xl font-bold font-mono text-emerald-400 flex items-center gap-2">
            Active
          </div>
          <div className="text-xs text-slate-500 mt-1">
            SSRF & DNS rebinding blocked
          </div>
        </div>
      </div>

      {/* Severity Breakdown Bar Strip */}
      <div className="p-5 rounded-lg bg-slate-900/60 border border-slate-800">
        <div className="flex items-center justify-between mb-3">
          <h2 className="text-sm font-semibold text-white tracking-tight">Findings by Severity</h2>
          <button
            onClick={() => onNavigate('findings')}
            className="text-xs text-cyan-400 hover:text-cyan-300 flex items-center gap-1"
          >
            <span>View all findings</span>
            <ArrowUpRight className="w-3.5 h-3.5" />
          </button>
        </div>

        {/* Proportional visual bar */}
        <div className="h-3 w-full bg-slate-950 rounded overflow-hidden flex mb-4 border border-slate-800/80">
          {totalFindings > 0 ? (
            <>
              {metrics?.severityCounts.critical ? (
                <div
                  style={{ width: `${(metrics.severityCounts.critical / totalFindings) * 100}%` }}
                  className="bg-red-500 h-full"
                  title={`Critical: ${metrics.severityCounts.critical}`}
                />
              ) : null}
              {metrics?.severityCounts.high ? (
                <div
                  style={{ width: `${(metrics.severityCounts.high / totalFindings) * 100}%` }}
                  className="bg-amber-500 h-full"
                  title={`High: ${metrics.severityCounts.high}`}
                />
              ) : null}
              {metrics?.severityCounts.medium ? (
                <div
                  style={{ width: `${(metrics.severityCounts.medium / totalFindings) * 100}%` }}
                  className="bg-yellow-500 h-full"
                  title={`Medium: ${metrics.severityCounts.medium}`}
                />
              ) : null}
              {metrics?.severityCounts.low ? (
                <div
                  style={{ width: `${(metrics.severityCounts.low / totalFindings) * 100}%` }}
                  className="bg-cyan-500 h-full"
                  title={`Low: ${metrics.severityCounts.low}`}
                />
              ) : null}
              {metrics?.severityCounts.informational ? (
                <div
                  style={{ width: `${(metrics.severityCounts.informational / totalFindings) * 100}%` }}
                  className="bg-slate-500 h-full"
                  title={`Informational: ${metrics.severityCounts.informational}`}
                />
              ) : null}
            </>
          ) : (
            <div className="w-full bg-slate-800/40 text-[10px] text-slate-500 flex items-center justify-center">
              No findings recorded
            </div>
          )}
        </div>

        {/* Severity counters */}
        <div className="grid grid-cols-2 sm:grid-cols-5 gap-3">
          {(['critical', 'high', 'medium', 'low', 'informational'] as const).map((sev) => {
            const count = metrics?.severityCounts[sev] || 0;
            const style = severityColors[sev];
            return (
              <div
                key={sev}
                className={`p-2.5 rounded-md ${style.bg} border ${style.border} flex flex-col`}
              >
                <span className={`text-[11px] font-semibold uppercase tracking-wider ${style.text}`}>
                  {sev}
                </span>
                <span className="text-xl font-bold font-mono tabular-nums text-white mt-1">
                  {count}
                </span>
              </div>
            );
          })}
        </div>
      </div>

      {/* Split Section: Recent Activity & Latest Findings */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Left: Recent Scans */}
        <div className="p-5 rounded-lg bg-slate-900/60 border border-slate-800 flex flex-col">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-sm font-semibold text-white tracking-tight">Recent Scans</h2>
            <button
              onClick={() => onNavigate('scanner')}
              className="text-xs text-cyan-400 hover:text-cyan-300 flex items-center gap-1"
            >
              <span>Launch Scan</span>
              <Play className="w-3 h-3" />
            </button>
          </div>

          {recentScans.length === 0 ? (
            <div className="flex-1 flex flex-col items-center justify-center py-8 text-slate-500 text-xs">
              <Activity className="w-8 h-8 text-slate-700 mb-2" />
              <span>No scans executed yet. Add a target and click Start Scan.</span>
            </div>
          ) : (
            <div className="space-y-2.5 flex-1">
              {recentScans.map((scan) => (
                <div
                  key={scan.id}
                  onClick={() => onSelectScan(scan.id)}
                  className="p-3 rounded-md bg-slate-950/70 border border-slate-800/80 hover:border-slate-700 cursor-pointer transition-colors flex items-center justify-between gap-3 text-xs"
                >
                  <div className="min-w-0">
                    <div className="font-mono text-slate-200 truncate font-medium">
                      {scan.target_hostname}
                    </div>
                    <div className="text-[11px] text-slate-500 mt-0.5 flex items-center gap-2">
                      <span>{new Date(scan.started_at).toLocaleTimeString()}</span>
                      <span>·</span>
                      <span>{scan.checks_run}/10 checks</span>
                      <span>·</span>
                      <span className="text-amber-400 font-mono">{scan.findings_count} findings</span>
                    </div>
                  </div>

                  <div className="shrink-0 flex items-center gap-2">
                    <span
                      className={`px-2 py-0.5 rounded text-[10px] font-mono uppercase tracking-wider ${
                        scan.status === 'completed'
                          ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20'
                          : scan.status === 'running'
                          ? 'bg-cyan-500/10 text-cyan-400 border border-cyan-500/20'
                          : scan.status === 'cancelled'
                          ? 'bg-slate-800 text-slate-400'
                          : 'bg-red-500/10 text-red-400'
                      }`}
                    >
                      {scan.status}
                    </span>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Right: Latest Findings */}
        <div className="p-5 rounded-lg bg-slate-900/60 border border-slate-800 flex flex-col">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-sm font-semibold text-white tracking-tight">Latest Security Findings</h2>
            <button
              onClick={() => onNavigate('findings')}
              className="text-xs text-cyan-400 hover:text-cyan-300 flex items-center gap-1"
            >
              <span>Manage all</span>
              <ExternalLink className="w-3 h-3" />
            </button>
          </div>

          {latestFindings.length === 0 ? (
            <div className="flex-1 flex flex-col items-center justify-center py-8 text-slate-500 text-xs">
              <Bug className="w-8 h-8 text-slate-700 mb-2" />
              <span>No findings discovered yet.</span>
            </div>
          ) : (
            <div className="space-y-2.5 flex-1">
              {latestFindings.map((finding) => {
                const style = severityColors[finding.severity];
                return (
                  <div
                    key={finding.id}
                    onClick={() => onSelectFinding(finding)}
                    className="p-3 rounded-md bg-slate-950/70 border border-slate-800/80 hover:border-slate-700 cursor-pointer transition-colors flex items-center justify-between gap-3 text-xs"
                  >
                    <div className="min-w-0">
                      <div className="text-slate-200 font-medium truncate">
                        {finding.title}
                      </div>
                      <div className="text-[11px] text-slate-500 mt-0.5 truncate flex items-center gap-2">
                        <span>{finding.category}</span>
                        <span>·</span>
                        <span className="font-mono text-slate-400">{finding.verification_status}</span>
                      </div>
                    </div>

                    <div className="shrink-0">
                      <span className={`px-2 py-0.5 rounded text-[10px] font-mono uppercase tracking-wider ${style.bg} ${style.text} border ${style.border}`}>
                        {finding.severity}
                      </span>
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
