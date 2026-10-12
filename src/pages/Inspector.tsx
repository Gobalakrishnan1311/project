import React, { useState } from 'react';
import { Target } from '../types.ts';
import { api } from '../services/api.ts';
import { Send, Clock, Shield, AlertCircle, Copy, Check, Lock, Cookie } from 'lucide-react';

interface InspectorProps {
  targets: Target[];
}

export const Inspector: React.FC<InspectorProps> = ({ targets = [] }) => {
  const safeTargets = Array.isArray(targets) ? targets : [];
  const [urlInput, setUrlInput] = useState(safeTargets[0]?.url || 'https://example.com');
  const [method, setMethod] = useState<'GET' | 'HEAD'>('GET');
  const [headersInput, setHeadersInput] = useState('User-Agent: WebBugHunter-Audit/1.0\nAccept: text/html,application/json');
  const [loading, setLoading] = useState(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);

  const [response, setResponse] = useState<{
    status: number;
    durationMs: number;
    headers: Record<string, string>;
    body: string;
    truncated?: boolean;
    tlsInfo?: any;
    cookies?: string;
  } | null>(null);

  const handleSend = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!urlInput.trim()) return;

    setLoading(true);
    setErrorMsg(null);

    // Parse headers
    const parsedHeaders: Record<string, string> = {};
    headersInput.split('\n').forEach(line => {
      const idx = line.indexOf(':');
      if (idx > 0) {
        const k = line.substring(0, idx).trim();
        const v = line.substring(idx + 1).trim();
        if (k && v) parsedHeaders[k] = v;
      }
    });

    try {
      const res = await api.sendInspectionRequest({
        url: urlInput.trim(),
        method,
        headers: parsedHeaders
      });
      setResponse(res);
    } catch (err: any) {
      setErrorMsg(err.response?.data?.error || err.message || 'Request failed.');
      setResponse(null);
    } finally {
      setLoading(false);
    }
  };

  const handleCopyBody = () => {
    if (response?.body) {
      navigator.clipboard.writeText(response.body);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  return (
    <div className="space-y-6">
      {/* Scope Warning Banner */}
      <div className="p-4 rounded-lg bg-slate-900/60 border border-slate-800 flex items-start gap-3 text-xs">
        <Shield className="w-4 h-4 text-cyan-400 shrink-0 mt-0.5" />
        <div className="space-y-1">
          <div className="font-semibold text-white">ScopeGuard Protected HTTP Inspector</div>
          <div className="text-slate-400 leading-normal">
            Every request is subject to strict SSRF validation. Localhost, RFC 1918 private subnets, and cloud metadata endpoints (169.254.169.254) are rejected by default. Only authorized targets in your active scope are allowed.
          </div>
        </div>
      </div>

      {/* Request Composer */}
      <form onSubmit={handleSend} className="p-5 rounded-lg bg-slate-900/60 border border-slate-800 space-y-4">
        <div className="flex flex-col sm:flex-row gap-3">
          <div className="w-28 shrink-0">
            <label className="block text-[11px] font-mono text-slate-400 mb-1 uppercase">Method</label>
            <select
              value={method}
              onChange={(e) => setMethod(e.target.value as 'GET' | 'HEAD')}
              className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded text-cyan-400 font-mono font-bold text-xs focus:outline-none"
            >
              <option value="GET">GET</option>
              <option value="HEAD">HEAD</option>
            </select>
          </div>

          <div className="flex-1">
            <label className="block text-[11px] font-mono text-slate-400 mb-1 uppercase">Target URL</label>
            <input
              type="text"
              value={urlInput}
              onChange={(e) => setUrlInput(e.target.value)}
              placeholder="https://example.com/api/test"
              className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded text-slate-100 font-mono text-xs focus:outline-none focus:border-cyan-500"
              required
            />
          </div>

          <div className="self-end shrink-0">
            <button
              type="submit"
              disabled={loading}
              className="flex items-center gap-1.5 px-4 py-2 font-medium text-xs text-white bg-cyan-600 hover:bg-cyan-500 rounded transition-colors disabled:opacity-50"
            >
              <Send className="w-3.5 h-3.5" />
              <span>{loading ? 'Sending...' : 'Send Request'}</span>
            </button>
          </div>
        </div>

        {/* Request Headers Editor */}
        <div>
          <label className="block text-[11px] font-mono text-slate-400 mb-1 uppercase">
            Request Headers (Header: Value per line)
          </label>
          <textarea
            rows={2}
            value={headersInput}
            onChange={(e) => setHeadersInput(e.target.value)}
            className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded text-slate-300 font-mono text-xs focus:outline-none focus:border-cyan-500"
          />
        </div>

        {errorMsg && (
          <div className="p-3 rounded bg-red-500/10 border border-red-500/20 text-red-300 text-xs flex items-center gap-2">
            <AlertCircle className="w-4 h-4 shrink-0 text-red-400" />
            <span>{errorMsg}</span>
          </div>
        )}
      </form>

      {/* Response Inspector */}
      {response && (
        <div className="space-y-4">
          {/* Status bar */}
          <div className="p-4 rounded-lg bg-slate-900/60 border border-slate-800 flex flex-wrap items-center justify-between gap-4 text-xs font-mono">
            <div className="flex items-center gap-4">
              <div className="flex items-center gap-2">
                <span className="text-slate-500">Status:</span>
                <span className={`font-bold px-2 py-0.5 rounded ${
                  response.status >= 200 && response.status < 300
                    ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20'
                    : response.status >= 300 && response.status < 400
                    ? 'bg-blue-500/10 text-blue-400 border border-blue-500/20'
                    : 'bg-amber-500/10 text-amber-400 border border-amber-500/20'
                }`}>
                  {response.status}
                </span>
              </div>

              <div className="flex items-center gap-1.5 text-slate-300">
                <Clock className="w-3.5 h-3.5 text-slate-500" />
                <span>{response.durationMs}ms</span>
              </div>

              {response.tlsInfo && (
                <div className="flex items-center gap-1 text-emerald-400">
                  <Lock className="w-3.5 h-3.5" />
                  <span>TLS Active</span>
                </div>
              )}
            </div>

            {response.body && (
              <button
                onClick={handleCopyBody}
                className="flex items-center gap-1 text-slate-400 hover:text-white px-2 py-1 rounded bg-slate-950 border border-slate-800 transition-colors"
              >
                {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                <span>{copied ? 'Copied' : 'Copy Body'}</span>
              </button>
            )}
          </div>

          {/* Response Headers */}
          <div className="p-4 rounded-lg bg-slate-900/60 border border-slate-800 space-y-2">
            <span className="text-xs font-semibold text-white">Response Headers</span>
            <div className="max-h-48 overflow-y-auto rounded border border-slate-800 bg-slate-950">
              <table className="w-full text-left text-xs font-mono">
                <tbody className="divide-y divide-slate-850">
                  {Object.entries(response.headers).map(([k, v]) => (
                    <tr key={k} className="hover:bg-slate-900/50">
                      <td className="py-1 px-3 text-cyan-400 font-medium whitespace-nowrap">{k}</td>
                      <td className="py-1 px-3 text-slate-300 break-all">{v}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

          {/* Cookies */}
          {response.cookies && (
            <div className="p-4 rounded-lg bg-slate-900/60 border border-slate-800 space-y-2">
              <div className="flex items-center gap-1.5 text-xs font-semibold text-white">
                <Cookie className="w-3.5 h-3.5 text-amber-400" />
                <span>Set-Cookie Response Directives</span>
              </div>
              <pre className="p-3 rounded bg-slate-950 font-mono text-xs text-slate-300 border border-slate-800 overflow-x-auto">
                {response.cookies}
              </pre>
            </div>
          )}

          {/* Response Body Text */}
          {method !== 'HEAD' && (
            <div className="p-4 rounded-lg bg-slate-900/60 border border-slate-800 space-y-2">
              <div className="flex items-center justify-between text-xs">
                <span className="font-semibold text-white">Response Body</span>
                {response.truncated && (
                  <span className="text-[11px] text-amber-400 font-mono">Truncated to 100KB</span>
                )}
              </div>
              <pre className="p-3 rounded bg-slate-950 font-mono text-xs text-slate-300 border border-slate-800 overflow-x-auto max-h-96">
                {response.body || '(Empty Response Body)'}
              </pre>
            </div>
          )}
        </div>
      )}
    </div>
  );
};
