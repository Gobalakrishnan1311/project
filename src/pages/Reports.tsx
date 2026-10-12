import React, { useState } from 'react';
import { Scan, Finding } from '../types.ts';
import { FileText, Download, ShieldCheck, CheckCircle2, AlertTriangle, FileCode, FileSpreadsheet } from 'lucide-react';

interface ReportsProps {
  scans: Scan[];
  findings: Finding[];
}

export const Reports: React.FC<ReportsProps> = ({ scans, findings }) => {
  const [selectedScanId, setSelectedScanId] = useState<string>(scans[0]?.id || '');

  const activeScan = scans.find(s => s.id === selectedScanId);
  const scanFindings = findings.filter(f => f.scan_id === selectedScanId);

  const downloadReport = (format: 'html' | 'json' | 'csv') => {
    if (!selectedScanId) return;
    window.location.href = `/api/reports/${selectedScanId}/${format}`;
  };

  return (
    <div className="space-y-6">
      {/* Header Bar */}
      <div className="p-5 rounded-lg bg-slate-900/60 border border-slate-800 space-y-4">
        <div>
          <h2 className="text-sm font-semibold text-white tracking-tight">
            Security Compliance & Audit Reports
          </h2>
          <p className="text-xs text-slate-400 mt-0.5">
            Export structured audit documentation in HTML, JSON, or CSV formats with complete ScopeGuard verification metadata.
          </p>
        </div>

        {/* Scan Selector */}
        <div className="flex flex-col sm:flex-row items-start sm:items-center gap-3 text-xs">
          <label className="text-slate-400 font-medium shrink-0">Select Audit Scan:</label>
          <select
            value={selectedScanId}
            onChange={(e) => setSelectedScanId(e.target.value)}
            className="w-full sm:w-auto min-w-[280px] px-3 py-1.5 bg-slate-950 border border-slate-800 rounded text-slate-100 font-mono focus:outline-none focus:border-cyan-500"
          >
            {scans.length === 0 ? (
              <option value="">No scans available</option>
            ) : (
              scans.map((s) => (
                <option key={s.id} value={s.id}>
                  {s.target_hostname} — {new Date(s.started_at).toLocaleString()} ({s.findings_count} findings)
                </option>
              ))
            )}
          </select>
        </div>
      </div>

      {/* Report Preview & Download Actions */}
      {activeScan ? (
        <div className="space-y-4">
          {/* Download cards */}
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
            <div className="p-4 rounded-lg bg-slate-900/60 border border-slate-800 flex flex-col justify-between space-y-3">
              <div className="flex items-start gap-3">
                <div className="p-2 rounded bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">
                  <FileText className="w-5 h-5" />
                </div>
                <div>
                  <h3 className="text-xs font-semibold text-white">Interactive HTML Report</h3>
                  <p className="text-[11px] text-slate-400 mt-0.5">
                    Self-contained executive audit document with styled findings cards and triage data.
                  </p>
                </div>
              </div>
              <button
                onClick={() => downloadReport('html')}
                className="w-full flex items-center justify-center gap-1.5 px-3 py-1.5 text-xs font-medium text-white bg-cyan-600 hover:bg-cyan-500 rounded transition-colors"
              >
                <Download className="w-3.5 h-3.5" />
                <span>Export HTML</span>
              </button>
            </div>

            <div className="p-4 rounded-lg bg-slate-900/60 border border-slate-800 flex flex-col justify-between space-y-3">
              <div className="flex items-start gap-3">
                <div className="p-2 rounded bg-blue-500/10 text-blue-400 border border-blue-500/20">
                  <FileCode className="w-5 h-5" />
                </div>
                <div>
                  <h3 className="text-xs font-semibold text-white">Machine JSON Export</h3>
                  <p className="text-[11px] text-slate-400 mt-0.5">
                    Full structured schema for SIEM integration, CI/CD pipelines, or bug bounty platforms.
                  </p>
                </div>
              </div>
              <button
                onClick={() => downloadReport('json')}
                className="w-full flex items-center justify-center gap-1.5 px-3 py-1.5 text-xs font-medium text-white bg-slate-800 hover:bg-slate-700 rounded transition-colors"
              >
                <Download className="w-3.5 h-3.5" />
                <span>Export JSON</span>
              </button>
            </div>

            <div className="p-4 rounded-lg bg-slate-900/60 border border-slate-800 flex flex-col justify-between space-y-3">
              <div className="flex items-start gap-3">
                <div className="p-2 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                  <FileSpreadsheet className="w-5 h-5" />
                </div>
                <div>
                  <h3 className="text-xs font-semibold text-white">Spreadsheet CSV Report</h3>
                  <p className="text-[11px] text-slate-400 mt-0.5">
                    RFC 4180 tabular spreadsheet export ready for Excel, Google Sheets, or Jira imports.
                  </p>
                </div>
              </div>
              <button
                onClick={() => downloadReport('csv')}
                className="w-full flex items-center justify-center gap-1.5 px-3 py-1.5 text-xs font-medium text-white bg-slate-800 hover:bg-slate-700 rounded transition-colors"
              >
                <Download className="w-3.5 h-3.5" />
                <span>Export CSV</span>
              </button>
            </div>
          </div>

          {/* Report Summary Card */}
          <div className="p-5 rounded-lg bg-slate-900/60 border border-slate-800 space-y-4">
            <h3 className="text-xs font-semibold text-white uppercase tracking-wider font-mono">
              Report Content Summary Preview
            </h3>

            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs font-mono">
              <div className="p-3 rounded bg-slate-950 border border-slate-850">
                <span className="text-slate-500 text-[11px] block">Target Hostname</span>
                <span className="text-slate-200 font-semibold">{activeScan.target_hostname}</span>
              </div>
              <div className="p-3 rounded bg-slate-950 border border-slate-850">
                <span className="text-slate-500 text-[11px] block">Audit Execution Date</span>
                <span className="text-slate-200">{new Date(activeScan.started_at).toLocaleDateString()}</span>
              </div>
              <div className="p-3 rounded bg-slate-950 border border-slate-850">
                <span className="text-slate-500 text-[11px] block">Checks Performed</span>
                <span className="text-cyan-400 font-semibold">{activeScan.checks_run} / 10 checks</span>
              </div>
              <div className="p-3 rounded bg-slate-950 border border-slate-850">
                <span className="text-slate-500 text-[11px] block">Recorded Findings</span>
                <span className="text-amber-400 font-semibold">{scanFindings.length} findings</span>
              </div>
            </div>

            {/* Findings List Preview */}
            <div className="space-y-2 pt-2 border-t border-slate-800">
              <span className="text-xs font-medium text-slate-300 block">
                Included Findings ({scanFindings.length}):
              </span>
              {scanFindings.length === 0 ? (
                <div className="text-xs text-slate-500 italic">No security findings recorded for this scan.</div>
              ) : (
                <div className="space-y-1.5 max-h-60 overflow-y-auto">
                  {scanFindings.map((f) => (
                    <div key={f.id} className="p-2 rounded bg-slate-950 border border-slate-850 text-xs flex items-center justify-between">
                      <div className="flex items-center gap-2 truncate">
                        <span className="font-mono text-[10px] uppercase font-bold text-amber-400">
                          {f.severity}
                        </span>
                        <span className="text-slate-200 truncate">{f.title}</span>
                      </div>
                      <span className="text-[11px] font-mono text-slate-500 shrink-0">
                        {f.verification_status}
                      </span>
                    </div>
                  ))}
                </div>
              )}
            </div>

            {/* Sanitization statement */}
            <div className="p-3 rounded bg-emerald-500/5 border border-emerald-500/20 text-[11px] text-emerald-400 flex items-center gap-2">
              <ShieldCheck className="w-4 h-4 shrink-0" />
              <span>
                Report Sanitization Certified: Passwords, session cookies, and internal secret tokens are automatically redacted prior to export.
              </span>
            </div>
          </div>
        </div>
      ) : (
        <div className="p-12 text-center text-slate-500 text-xs rounded-lg bg-slate-900/60 border border-slate-800">
          <FileText className="w-8 h-8 text-slate-700 mx-auto mb-2" />
          <span>Execute a security scan to generate downloadable reports.</span>
        </div>
      )}
    </div>
  );
};
