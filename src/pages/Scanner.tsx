import React, { useState, useEffect } from 'react';
import { Target, Scan, Finding } from '../types.ts';
import { api } from '../services/api.ts';
import {
  Play,
  Square,
  RefreshCw,
  ShieldAlert,
  CheckCircle2,
  AlertCircle,
  FileText,
  Clock,
  Terminal,
  ChevronRight,
  ExternalLink
} from 'lucide-react';

interface ScannerProps {
  targets: Target[];
  selectedTargetId?: string;
  onNavigateFindings: () => void;
  onSelectFinding: (finding: Finding) => void;
}

export const Scanner: React.FC<ScannerProps> = ({
  targets = [],
  selectedTargetId = '',
  onNavigateFindings,
  onSelectFinding
}) => {
  const safeTargets = Array.isArray(targets) ? targets : [];
  const [currentTargetId, setCurrentTargetId] = useState(selectedTargetId || (safeTargets[0]?.id || ''));
  const [activeScan, setActiveScan] = useState<Scan | null>(null);
  const [scanLogs, setScanLogs] = useState<any[]>([]);
  const [scanFindings, setScanFindings] = useState<Finding[]>([]);
  const [isScanning, setIsScanning] = useState(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  // Scan config
  const [timeoutMs, setTimeoutMs] = useState(8000);
  const [maxRequests, setMaxRequests] = useState(50);
  const [concurrency, setConcurrency] = useState(2);
  const [delayMs, setDelayMs] = useState(250);

  // Sync selected target if prop changes
  useEffect(() => {
    if (selectedTargetId) {
      setCurrentTargetId(selectedTargetId);
    } else if (!currentTargetId && safeTargets.length > 0) {
      setCurrentTargetId(safeTargets[0].id);
    }
  }, [selectedTargetId, safeTargets]);

  // Polling active scan status
  useEffect(() => {
    let interval: any;
    if (activeScan && (activeScan.status === 'running' || activeScan.status === 'pending')) {
      interval = setInterval(async () => {
        try {
          const details = await api.getScanDetails(activeScan.id);
          setActiveScan(details);
          setScanLogs(details.logs || []);
          setScanFindings(details.findings || []);
          if (details.status !== 'running' && details.status !== 'pending') {
            setIsScanning(false);
          }
        } catch {
          // ignore transient poll error
        }
      }, 1500);
    }
    return () => clearInterval(interval);
  }, [activeScan]);

  const handleStartScan = async () => {
    if (!currentTargetId) {
      setErrorMsg('Please select an authorized target.');
      return;
    }
    setErrorMsg(null);
    setIsScanning(true);
    setScanLogs([]);
    setScanFindings([]);

    try {
      const scan = await api.startScan({
        target_id: currentTargetId,
        timeout: timeoutMs,
        max_requests: maxRequests,
        concurrency,
        delay_ms: delayMs
      });
      setActiveScan(scan);
    } catch (err: any) {
      setErrorMsg(err.response?.data?.error || err.message || 'Failed to start scan.');
      setIsScanning(false);
    }
  };

  const handleCancelScan = async () => {
    if (!activeScan) return;
    try {
      await api.cancelScan(activeScan.id);
      setActiveScan((prev) => prev ? { ...prev, status: 'cancelled' } : null);
      setIsScanning(false);
    } catch (err: any) {
      setErrorMsg(err.message || 'Failed to cancel scan.');
    }
  };

  const checksList = [
    { num: 1, name: 'Missing or Weak HTTP Security Headers', cat: 'Headers' },
    { num: 2, name: 'Missing or Permissive Content Security Policy (CSP)', cat: 'CSP' },
    { num: 3, name: 'Strict-Transport-Security (HSTS) Downgrade Mitigation', cat: 'TLS' },
    { num: 4, name: 'Cookie Security Flags (Secure, HttpOnly, SameSite)', cat: 'Session' },
    { num: 5, name: 'TLS Certificate Validity, Issuer & Expiration Inspection', cat: 'TLS' },
    { num: 6, name: 'Cross-Origin Resource Sharing (CORS) Insecurity Check', cat: 'Access' },
    { num: 7, name: 'Server Version & Software Banner Information Disclosure', cat: 'Disclosure' },
    { num: 8, name: 'Publicly Accessible Web Directory Indexing Listing', cat: 'Exposure' },
    { num: 9, name: 'Exposed Diagnostic & Configuration Files (.env, .git)', cat: 'Exposure' },
    { num: 10, name: 'Reflected-Input Harmless Benign Marker Audit', cat: 'Input' },
  ];

  const currentTarget = targets.find(t => t.id === currentTargetId);

  return (
    <div className="space-y-6">
      {/* Configuration & Controls */}
      <div className="p-5 rounded-lg bg-slate-900/60 border border-slate-800 space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
          <div>
            <h2 className="text-sm font-semibold text-white tracking-tight">
              Website Security Vulnerability Scanner
            </h2>
            <p className="text-xs text-slate-400 mt-0.5">
              Executes 10 modular, non-destructive security checks within authorized scope.
            </p>
          </div>

          <div className="flex items-center gap-2">
            {isScanning ? (
              <button
                onClick={handleCancelScan}
                className="flex items-center gap-1.5 px-3.5 py-1.5 text-xs font-medium text-white bg-red-600 hover:bg-red-500 rounded transition-colors shadow-sm"
              >
                <Square className="w-3.5 h-3.5" />
                <span>Cancel Scan</span>
              </button>
            ) : (
              <button
                onClick={handleStartScan}
                disabled={!currentTargetId || targets.length === 0}
                className="flex items-center gap-1.5 px-4 py-1.5 text-xs font-medium text-white bg-cyan-600 hover:bg-cyan-500 rounded transition-colors disabled:opacity-50 shadow-sm"
              >
                <Play className="w-3.5 h-3.5" />
                <span>Start Security Audit</span>
              </button>
            )}
          </div>
        </div>

        {errorMsg && (
          <div className="p-3 rounded bg-red-500/10 border border-red-500/20 text-red-300 text-xs flex items-center gap-2">
            <AlertCircle className="w-4 h-4 shrink-0 text-red-400" />
            <span>{errorMsg}</span>
          </div>
        )}

        {/* Target Select & Config Grid */}
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-3 text-xs pt-1">
          <div className="lg:col-span-2">
            <label className="block text-slate-400 font-medium mb-1">Target in Scope</label>
            <select
              value={currentTargetId}
              onChange={(e) => setCurrentTargetId(e.target.value)}
              disabled={isScanning}
              className="w-full px-3 py-1.5 bg-slate-950 border border-slate-800 rounded text-slate-100 font-mono focus:outline-none focus:border-cyan-500"
            >
              {safeTargets.map((t) => (
                <option key={t.id} value={t.id}>
                  {t.hostname || 'Target'} ({t.scheme || 'https'})
                </option>
              ))}
            </select>
            {currentTarget && (
              <span className="text-[11px] text-emerald-400/90 mt-1 block truncate">
                Authorized: {currentTarget.owner_confirmation}
              </span>
            )}
          </div>

          <div>
            <label className="block text-slate-400 font-medium mb-1">Timeout (ms)</label>
            <input
              type="number"
              value={timeoutMs}
              onChange={(e) => setTimeoutMs(Number(e.target.value))}
              disabled={isScanning}
              className="w-full px-2.5 py-1.5 bg-slate-950 border border-slate-800 rounded text-slate-200 font-mono"
            />
          </div>

          <div>
            <label className="block text-slate-400 font-medium mb-1">Concurrency</label>
            <input
              type="number"
              min="1"
              max="5"
              value={concurrency}
              onChange={(e) => setConcurrency(Number(e.target.value))}
              disabled={isScanning}
              className="w-full px-2.5 py-1.5 bg-slate-950 border border-slate-800 rounded text-slate-200 font-mono"
            />
          </div>

          <div>
            <label className="block text-slate-400 font-medium mb-1">Request Delay (ms)</label>
            <input
              type="number"
              min="0"
              max="2000"
              value={delayMs}
              onChange={(e) => setDelayMs(Number(e.target.value))}
              disabled={isScanning}
              className="w-full px-2.5 py-1.5 bg-slate-950 border border-slate-800 rounded text-slate-200 font-mono"
            />
          </div>
        </div>
      </div>

      {/* Active Scan Execution Progress */}
      {activeScan && (
        <div className="p-5 rounded-lg bg-slate-900/60 border border-slate-800 space-y-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <span className="text-xs font-semibold text-white">Scan Execution:</span>
              <span className="font-mono text-xs text-cyan-400">{activeScan.target_hostname}</span>
              <span className={`px-2 py-0.5 rounded text-[10px] font-mono uppercase tracking-wider ${
                activeScan.status === 'completed'
                  ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20'
                  : activeScan.status === 'running'
                  ? 'bg-cyan-500/10 text-cyan-400 border border-cyan-500/20'
                  : activeScan.status === 'cancelled'
                  ? 'bg-slate-800 text-slate-400'
                  : 'bg-red-500/10 text-red-400'
              }`}>
                {activeScan.status}
              </span>
            </div>

            <div className="text-xs font-mono text-slate-400">
              {activeScan.progress}%
            </div>
          </div>

          {/* Progress bar */}
          <div className="w-full h-2 bg-slate-950 rounded-full overflow-hidden border border-slate-800">
            <div
              style={{ width: `${activeScan.progress}%` }}
              className={`h-full transition-all duration-300 ${
                activeScan.status === 'completed'
                  ? 'bg-emerald-500'
                  : activeScan.status === 'cancelled'
                  ? 'bg-slate-600'
                  : activeScan.status === 'failed'
                  ? 'bg-red-500'
                  : 'bg-cyan-500'
              }`}
            />
          </div>
        </div>
      )}

      {/* Grid: 10 Modular Checks Checklist & Live Log Stream */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Left: 10 Checks Checklist */}
        <div className="p-5 rounded-lg bg-slate-900/60 border border-slate-800 flex flex-col">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-sm font-semibold text-white tracking-tight">
              10 Modular Security Checks
            </h3>
            <span className="text-[11px] font-mono text-slate-500">
              Safe & Non-Destructive
            </span>
          </div>

          <div className="space-y-2 flex-1">
            {checksList.map((check) => {
              const checkProgressLimit = check.num * 10;
              const isDone = activeScan ? activeScan.progress >= checkProgressLimit : false;
              const isCurrent = activeScan && activeScan.status === 'running' && activeScan.progress < checkProgressLimit && activeScan.progress >= (check.num - 1) * 10;

              return (
                <div
                  key={check.num}
                  className={`p-2.5 rounded-md border text-xs flex items-center justify-between transition-colors ${
                    isDone
                      ? 'bg-slate-950/80 border-slate-800 text-slate-200'
                      : isCurrent
                      ? 'bg-cyan-500/5 border-cyan-500/30 text-cyan-200'
                      : 'bg-slate-950/40 border-slate-850 text-slate-500'
                  }`}
                >
                  <div className="flex items-center gap-2.5 min-w-0">
                    <span className="font-mono text-[11px] text-slate-500 shrink-0">
                      #{check.num.toString().padStart(2, '0')}
                    </span>
                    <span className="truncate">{check.name}</span>
                  </div>

                  <div className="shrink-0 flex items-center gap-1.5">
                    {isCurrent ? (
                      <RefreshCw className="w-3.5 h-3.5 text-cyan-400 animate-spin" />
                    ) : isDone ? (
                      <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
                    ) : (
                      <span className="text-[10px] text-slate-600 font-mono">Queued</span>
                    )}
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* Right: Live Scan Logs Terminal */}
        <div className="p-5 rounded-lg bg-slate-900/60 border border-slate-800 flex flex-col">
          <div className="flex items-center justify-between mb-4">
            <div className="flex items-center gap-2">
              <Terminal className="w-4 h-4 text-cyan-400" />
              <h3 className="text-sm font-semibold text-white tracking-tight">Scan Activity Log</h3>
            </div>
            <span className="text-[11px] font-mono text-slate-500">
              {scanLogs.length} events
            </span>
          </div>

          <div className="flex-1 bg-slate-950 rounded border border-slate-850 p-3 font-mono text-[11px] space-y-1.5 overflow-y-auto max-h-[380px]">
            {scanLogs.length === 0 ? (
              <div className="text-slate-600 italic py-12 text-center">
                Waiting for scan execution. Activity will stream here in real time.
              </div>
            ) : (
              scanLogs.map((log, idx) => (
                <div key={idx} className="leading-tight flex items-start gap-2">
                  <span className="text-slate-600 shrink-0">
                    {new Date(log.timestamp).toLocaleTimeString()}
                  </span>
                  <span
                    className={`shrink-0 uppercase font-bold text-[9px] px-1 rounded ${
                      log.level === 'warn'
                        ? 'bg-amber-500/20 text-amber-300'
                        : log.level === 'error'
                        ? 'bg-red-500/20 text-red-300'
                        : 'bg-slate-800 text-slate-400'
                    }`}
                  >
                    {log.level}
                  </span>
                  <span
                    className={
                      log.level === 'warn'
                        ? 'text-amber-200'
                        : log.level === 'error'
                        ? 'text-red-200'
                        : 'text-slate-300'
                    }
                  >
                    {log.message}
                  </span>
                </div>
              ))
            )}
          </div>
        </div>
      </div>

      {/* Discovered Findings in this Scan */}
      {scanFindings.length > 0 && (
        <div className="p-5 rounded-lg bg-slate-900/60 border border-slate-800 space-y-3">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <ShieldAlert className="w-4 h-4 text-amber-400" />
              <h3 className="text-sm font-semibold text-white tracking-tight">
                Discovered Findings in this Audit ({scanFindings.length})
              </h3>
            </div>
            <button
              onClick={onNavigateFindings}
              className="text-xs text-cyan-400 hover:text-cyan-300 flex items-center gap-1"
            >
              <span>View in Findings Manager</span>
              <ChevronRight className="w-3.5 h-3.5" />
            </button>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
            {(Array.isArray(scanFindings) ? scanFindings : []).map((finding) => (
              <div
                key={finding.id || Math.random().toString()}
                onClick={() => onSelectFinding(finding)}
                className="p-3 rounded bg-slate-950 border border-slate-800 hover:border-slate-700 cursor-pointer transition-colors text-xs space-y-1.5"
              >
                <div className="flex items-center justify-between">
                  <span className="text-[10px] font-mono uppercase font-bold text-amber-400">
                    {finding.severity || 'info'}
                  </span>
                  <span className="text-[10px] text-slate-500 font-mono">
                    {finding.verification_status || 'New'}
                  </span>
                </div>
                <div className="text-slate-200 font-medium line-clamp-1">
                  {finding.title || 'Finding'}
                </div>
                <div className="text-[11px] text-slate-500 line-clamp-2">
                  {finding.description || ''}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
};
