import React from 'react';
import { Scan } from '../types.ts';
import { History as HistoryIcon, Clock, CheckCircle2, AlertTriangle, ArrowUpRight, Play } from 'lucide-react';
import { NavTab } from '../components/Sidebar.tsx';

interface HistoryProps {
  scans: Scan[];
  onSelectScan: (scanId: string) => void;
  onNavigate: (tab: NavTab) => void;
}

export const History: React.FC<HistoryProps> = ({ scans, onSelectScan, onNavigate }) => {
  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="p-5 rounded-lg bg-slate-900/60 border border-slate-800 space-y-1">
        <h2 className="text-sm font-semibold text-white tracking-tight">
          Audit Scan Execution History
        </h2>
        <p className="text-xs text-slate-400">
          Historical record of automated checks performed, duration, and vulnerabilities detected.
        </p>
      </div>

      {/* Scans List */}
      <div className="rounded-lg bg-slate-900/60 border border-slate-800 overflow-hidden">
        {scans.length === 0 ? (
          <div className="py-12 px-4 text-center text-slate-500 text-xs">
            <HistoryIcon className="w-8 h-8 text-slate-700 mx-auto mb-2" />
            <div>No previous scans in database.</div>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="bg-slate-950/80 text-slate-400 border-b border-slate-800 font-mono uppercase text-[11px]">
                <tr>
                  <th className="py-3 px-4 font-medium">Target Hostname</th>
                  <th className="py-3 px-4 font-medium">Status</th>
                  <th className="py-3 px-4 font-medium">Started At</th>
                  <th className="py-3 px-4 font-medium">Execution Scope</th>
                  <th className="py-3 px-4 font-medium">Findings Recorded</th>
                  <th className="py-3 px-4 font-medium text-right">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60">
                {scans.map((scan) => (
                  <tr key={scan.id} className="hover:bg-slate-850/40 transition-colors">
                    <td className="py-3 px-4">
                      <div className="font-mono font-medium text-slate-200">
                        {scan.target_hostname}
                      </div>
                      <div className="text-[11px] text-slate-500 truncate max-w-xs">
                        {scan.target_url}
                      </div>
                    </td>

                    <td className="py-3 px-4">
                      <span className={`px-2 py-0.5 rounded text-[10px] font-mono uppercase tracking-wider ${
                        scan.status === 'completed'
                          ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20'
                          : scan.status === 'running'
                          ? 'bg-cyan-500/10 text-cyan-400 border border-cyan-500/20'
                          : scan.status === 'cancelled'
                          ? 'bg-slate-800 text-slate-400'
                          : 'bg-red-500/10 text-red-400'
                      }`}>
                        {scan.status}
                      </span>
                    </td>

                    <td className="py-3 px-4 font-mono text-[11px] text-slate-400">
                      {new Date(scan.started_at).toLocaleString()}
                    </td>

                    <td className="py-3 px-4 font-mono text-[11px] text-slate-400">
                      {scan.checks_run} / 10 checks
                    </td>

                    <td className="py-3 px-4">
                      <span className="font-mono font-bold text-amber-400">
                        {scan.findings_count} findings
                      </span>
                    </td>

                    <td className="py-3 px-4 text-right">
                      <div className="flex items-center justify-end gap-2">
                        <button
                          onClick={() => {
                            onSelectScan(scan.id);
                            onNavigate('scanner');
                          }}
                          className="px-2.5 py-1 text-slate-300 hover:text-white bg-slate-950 border border-slate-800 hover:border-slate-700 rounded transition-colors text-[11px] font-mono"
                        >
                          View Logs
                        </button>
                        <button
                          onClick={() => onNavigate('reports')}
                          className="px-2.5 py-1 text-cyan-400 hover:text-cyan-300 bg-cyan-500/10 border border-cyan-500/20 rounded transition-colors text-[11px] font-mono"
                        >
                          Reports
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
};
