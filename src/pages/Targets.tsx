import React, { useState } from 'react';
import { Target } from '../types.ts';
import { Plus, Trash2, Play, Search, Shield, AlertTriangle, ExternalLink, CheckCircle } from 'lucide-react';

interface TargetsProps {
  targets: Target[];
  onAddTarget: (targetData: Partial<Target>) => Promise<void>;
  onDeleteTarget: (targetId: string) => Promise<void>;
  onStartScan: (targetId: string) => void;
  onStartRecon: (url: string) => void;
  isAddModalOpen: boolean;
  setIsAddModalOpen: (open: boolean) => void;
}

export const Targets: React.FC<TargetsProps> = ({
  targets,
  onAddTarget,
  onDeleteTarget,
  onStartScan,
  onStartRecon,
  isAddModalOpen,
  setIsAddModalOpen
}) => {
  const [urlInput, setUrlInput] = useState('');
  const [allowSubdomains, setAllowSubdomains] = useState(false);
  const [authConfirmed, setAuthConfirmed] = useState(false);
  const [authDetails, setAuthDetails] = useState('');
  const [excludedHosts, setExcludedHosts] = useState('');
  const [excludedPaths, setExcludedPaths] = useState('');
  const [timeoutMs, setTimeoutMs] = useState(8000);
  const [maxRequests, setMaxRequests] = useState(50);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setErrorMsg(null);

    if (!urlInput.trim()) {
      setErrorMsg('Please enter a target URL or domain.');
      return;
    }

    if (!authConfirmed) {
      setErrorMsg('ScopeGuard requires explicit confirmation that you possess authorization to test this target.');
      return;
    }

    setIsSubmitting(true);
    try {
      await onAddTarget({
        url: urlInput.trim(),
        user_authorized: true,
        owner_confirmation: authDetails.trim() || 'Owner Authorization Certified in UI',
        allow_subdomains: allowSubdomains,
        excluded_hosts: excludedHosts.split(',').map(s => s.trim()).filter(Boolean),
        excluded_paths: excludedPaths.split(',').map(s => s.trim()).filter(Boolean),
        request_timeout: Number(timeoutMs) || 8000,
        max_requests: Number(maxRequests) || 50
      });
      // reset form
      setUrlInput('');
      setAuthConfirmed(false);
      setAuthDetails('');
      setExcludedHosts('');
      setExcludedPaths('');
      setIsAddModalOpen(false);
    } catch (err: any) {
      setErrorMsg(err.response?.data?.error || err.message || 'Failed to add target.');
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Header Bar */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h2 className="text-base font-semibold text-white tracking-tight">
            Target Management & Scope Boundaries
          </h2>
          <p className="text-xs text-slate-400 mt-0.5">
            Define testing boundaries, permitted domains, and enforce strict ScopeGuard verification.
          </p>
        </div>

        <button
          onClick={() => setIsAddModalOpen(true)}
          className="flex items-center gap-1.5 px-3.5 py-1.5 text-xs font-medium text-white bg-cyan-600 hover:bg-cyan-500 rounded-md transition-colors self-start sm:self-auto shadow-sm"
        >
          <Plus className="w-3.5 h-3.5" />
          <span>Add New Target</span>
        </button>
      </div>

      {/* Target Table */}
      <div className="rounded-lg bg-slate-900/60 border border-slate-800 overflow-hidden">
        {targets.length === 0 ? (
          <div className="py-12 px-4 text-center text-slate-500 text-xs">
            <Shield className="w-8 h-8 text-slate-700 mx-auto mb-2" />
            <div className="font-medium text-slate-400">No targets configured</div>
            <div className="mt-1">Add an authorized domain or click "Load Demo Data" from the top bar.</div>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="bg-slate-950/80 text-slate-400 border-b border-slate-800 font-mono uppercase text-[11px]">
                <tr>
                  <th className="py-3 px-4 font-medium">Target Hostname</th>
                  <th className="py-3 px-4 font-medium">Scheme</th>
                  <th className="py-3 px-4 font-medium">Scope Boundary</th>
                  <th className="py-3 px-4 font-medium">Authorization Proof</th>
                  <th className="py-3 px-4 font-medium">Limits</th>
                  <th className="py-3 px-4 font-medium">Status</th>
                  <th className="py-3 px-4 font-medium text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60">
                {targets.map((target) => (
                  <tr key={target.id} className="hover:bg-slate-850/40 transition-colors">
                    <td className="py-3 px-4">
                      <div className="font-mono font-medium text-slate-200">
                        {target.hostname}
                      </div>
                      <div className="text-[11px] text-slate-500 truncate max-w-xs">
                        {target.url}
                      </div>
                    </td>

                    <td className="py-3 px-4 font-mono text-slate-400 uppercase">
                      {target.scheme}
                    </td>

                    <td className="py-3 px-4">
                      <div className="text-slate-300">
                        {target.allow_subdomains ? 'Host + Subdomains (*)' : 'Exact Host Only'}
                      </div>
                      {target.excluded_hosts?.length > 0 && (
                        <div className="text-[11px] text-red-400/80 font-mono mt-0.5">
                          {target.excluded_hosts.length} exclusions
                        </div>
                      )}
                    </td>

                    <td className="py-3 px-4">
                      <div className="flex items-center gap-1.5 text-emerald-400">
                        <CheckCircle className="w-3.5 h-3.5" />
                        <span className="text-[11px] font-medium truncate max-w-[180px]" title={target.owner_confirmation}>
                          {target.owner_confirmation}
                        </span>
                      </div>
                    </td>

                    <td className="py-3 px-4 font-mono text-[11px] text-slate-400">
                      {target.request_timeout}ms · max {target.max_requests} reqs
                    </td>

                    <td className="py-3 px-4">
                      <span className={`px-2 py-0.5 rounded text-[10px] font-mono uppercase tracking-wider ${
                        target.status === 'completed'
                          ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20'
                          : target.status === 'scanning'
                          ? 'bg-cyan-500/10 text-cyan-400 border border-cyan-500/20'
                          : 'bg-slate-800 text-slate-400'
                      }`}>
                        {target.status}
                      </span>
                    </td>

                    <td className="py-3 px-4 text-right">
                      <div className="flex items-center justify-end gap-1.5">
                        <button
                          onClick={() => onStartRecon(target.url)}
                          className="p-1.5 text-slate-400 hover:text-cyan-400 hover:bg-slate-800 rounded transition-colors"
                          title="Run DNS & HTTP Reconnaissance"
                        >
                          <Search className="w-3.5 h-3.5" />
                        </button>
                        <button
                          onClick={() => onStartScan(target.id)}
                          className="p-1.5 text-slate-400 hover:text-emerald-400 hover:bg-slate-800 rounded transition-colors"
                          title="Execute Security Audit Scan"
                        >
                          <Play className="w-3.5 h-3.5" />
                        </button>
                        <button
                          onClick={() => onDeleteTarget(target.id)}
                          className="p-1.5 text-slate-400 hover:text-red-400 hover:bg-slate-800 rounded transition-colors"
                          title="Remove Target"
                        >
                          <Trash2 className="w-3.5 h-3.5" />
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

      {/* Add Target Modal */}
      {isAddModalOpen && (
        <div className="fixed inset-0 z-50 bg-black/70 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="w-full max-w-lg bg-slate-900 border border-slate-800 rounded-lg shadow-xl overflow-hidden">
            <div className="px-5 py-4 border-b border-slate-800 flex items-center justify-between">
              <h3 className="text-sm font-semibold text-white tracking-tight">
                Add Authorized Target to Scope
              </h3>
              <button
                onClick={() => setIsAddModalOpen(false)}
                className="text-slate-400 hover:text-white text-xs"
              >
                ✕
              </button>
            </div>

            <form onSubmit={handleSubmit} className="p-5 space-y-4 text-xs">
              {errorMsg && (
                <div className="p-3 rounded bg-red-500/10 border border-red-500/20 text-red-300 flex items-start gap-2">
                  <AlertTriangle className="w-4 h-4 shrink-0 text-red-400 mt-0.5" />
                  <span>{errorMsg}</span>
                </div>
              )}

              <div>
                <label className="block text-slate-300 font-medium mb-1">
                  Target Domain or URL *
                </label>
                <input
                  type="text"
                  placeholder="https://example.com or example.com"
                  value={urlInput}
                  onChange={(e) => setUrlInput(e.target.value)}
                  className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded text-slate-100 placeholder-slate-600 focus:outline-none focus:border-cyan-500 font-mono"
                  required
                />
                <span className="text-[11px] text-slate-500 mt-1 block">
                  Only public HTTP/HTTPS endpoints are accepted. Localhost and private IPs are blocked by ScopeGuard.
                </span>
              </div>

              {/* Subdomain Scope */}
              <div className="flex items-center gap-2">
                <input
                  type="checkbox"
                  id="subdomains"
                  checked={allowSubdomains}
                  onChange={(e) => setAllowSubdomains(e.target.checked)}
                  className="rounded border-slate-700 bg-slate-950 text-cyan-500 focus:ring-0"
                />
                <label htmlFor="subdomains" className="text-slate-300 select-none">
                  Authorize all subdomains (*.domain.com) in scope
                </label>
              </div>

              {/* Exclusions */}
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                <div>
                  <label className="block text-slate-400 mb-1">Excluded Hosts (comma-separated)</label>
                  <input
                    type="text"
                    placeholder="internal.example.com, payment.example.com"
                    value={excludedHosts}
                    onChange={(e) => setExcludedHosts(e.target.value)}
                    className="w-full px-2.5 py-1.5 bg-slate-950 border border-slate-800 rounded text-slate-200 placeholder-slate-600 font-mono text-[11px]"
                  />
                </div>
                <div>
                  <label className="block text-slate-400 mb-1">Excluded Paths (comma-separated)</label>
                  <input
                    type="text"
                    placeholder="/logout, /delete, /admin/reset"
                    value={excludedPaths}
                    onChange={(e) => setExcludedPaths(e.target.value)}
                    className="w-full px-2.5 py-1.5 bg-slate-950 border border-slate-800 rounded text-slate-200 placeholder-slate-600 font-mono text-[11px]"
                  />
                </div>
              </div>

              {/* Limits */}
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-slate-400 mb-1">Request Timeout (ms)</label>
                  <input
                    type="number"
                    min="1000"
                    max="30000"
                    value={timeoutMs}
                    onChange={(e) => setTimeoutMs(Number(e.target.value))}
                    className="w-full px-2.5 py-1.5 bg-slate-950 border border-slate-800 rounded text-slate-200 font-mono text-[11px]"
                  />
                </div>
                <div>
                  <label className="block text-slate-400 mb-1">Max Requests Limit</label>
                  <input
                    type="number"
                    min="5"
                    max="200"
                    value={maxRequests}
                    onChange={(e) => setMaxRequests(Number(e.target.value))}
                    className="w-full px-2.5 py-1.5 bg-slate-950 border border-slate-800 rounded text-slate-200 font-mono text-[11px]"
                  />
                </div>
              </div>

              {/* Authorization Certification */}
              <div className="p-3 rounded bg-slate-950 border border-slate-800 space-y-2">
                <div className="flex items-start gap-2">
                  <input
                    type="checkbox"
                    id="authProof"
                    checked={authConfirmed}
                    onChange={(e) => setAuthConfirmed(e.target.checked)}
                    className="mt-0.5 rounded border-slate-700 bg-slate-900 text-cyan-500 focus:ring-0"
                    required
                  />
                  <label htmlFor="authProof" className="text-slate-300 font-medium leading-tight select-none">
                    I certify that I am the authorized owner or hold explicit legal authorization to perform security testing on this target.
                  </label>
                </div>
                <div>
                  <input
                    type="text"
                    placeholder="Authorization proof or Bug Bounty Program ID (e.g., BB-2026-SCOPE)"
                    value={authDetails}
                    onChange={(e) => setAuthDetails(e.target.value)}
                    className="w-full px-2.5 py-1.5 bg-slate-900 border border-slate-800 rounded text-slate-200 placeholder-slate-600 text-[11px]"
                  />
                </div>
              </div>

              <div className="flex items-center justify-end gap-2 pt-2 border-t border-slate-800">
                <button
                  type="button"
                  onClick={() => setIsAddModalOpen(false)}
                  className="px-3 py-1.5 text-slate-400 hover:text-slate-200 transition-colors"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={isSubmitting || !authConfirmed}
                  className="px-4 py-1.5 font-medium text-white bg-cyan-600 hover:bg-cyan-500 rounded transition-colors disabled:opacity-50"
                >
                  {isSubmitting ? 'Validating Scope...' : 'Confirm & Add Target'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};
