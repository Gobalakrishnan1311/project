import React, { useState } from 'react';
import { Target, DnsRecords, HttpReconData } from '../types.ts';
import { api } from '../services/api.ts';
import { Search, Globe, Shield, RefreshCw, AlertCircle, FileCode, CheckCircle2, Lock } from 'lucide-react';

interface ReconProps {
  targets: Target[];
  defaultHost?: string;
}

export const Reconnaissance: React.FC<ReconProps> = ({ targets, defaultHost = '' }) => {
  const [targetInput, setTargetInput] = useState(defaultHost || (targets[0]?.url || 'https://example.com'));
  const [activeTab, setActiveTab] = useState<'dns' | 'http' | 'files'>('dns');
  const [loading, setLoading] = useState(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  const [dnsData, setDnsData] = useState<DnsRecords | null>(null);
  const [httpData, setHttpData] = useState<HttpReconData | null>(null);

  const handleRunRecon = async () => {
    if (!targetInput.trim()) return;
    setLoading(true);
    setErrorMsg(null);

    try {
      // 1. Run DNS Lookup
      const dnsRes = await api.getDnsRecords(targetInput.trim());
      setDnsData(dnsRes.records);

      // 2. Run HTTP Inspection
      const httpRes = await api.getHttpRecon(targetInput.trim());
      setHttpData(httpRes);
    } catch (err: any) {
      setErrorMsg(err.response?.data?.error || err.message || 'Reconnaissance failed.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Header and Input Bar */}
      <div className="p-5 rounded-lg bg-slate-900/60 border border-slate-800 space-y-4">
        <div>
          <h2 className="text-sm font-semibold text-white tracking-tight">
            Target Reconnaissance & Asset Fingerprinting
          </h2>
          <p className="text-xs text-slate-400 mt-0.5">
            Performs low-impact passive DNS lookups, TLS posture checks, robots.txt inspection, and technology identification.
          </p>
        </div>

        <div className="flex flex-col sm:flex-row gap-3">
          <div className="flex-1 relative">
            <input
              type="text"
              value={targetInput}
              onChange={(e) => setTargetInput(e.target.value)}
              placeholder="Enter authorized target (e.g., https://example.com)"
              className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded text-slate-100 placeholder-slate-600 focus:outline-none focus:border-cyan-500 font-mono text-xs"
            />
          </div>

          <div className="flex items-center gap-2">
            {targets.length > 0 && (
              <select
                onChange={(e) => setTargetInput(e.target.value)}
                value={targets.some(t => t.url === targetInput) ? targetInput : ''}
                className="px-2.5 py-2 bg-slate-950 border border-slate-800 rounded text-slate-300 text-xs focus:outline-none"
              >
                <option value="">Select Target...</option>
                {targets.map((t) => (
                  <option key={t.id} value={t.url}>{t.hostname}</option>
                ))}
              </select>
            )}

            <button
              onClick={handleRunRecon}
              disabled={loading}
              className="flex items-center gap-1.5 px-4 py-2 font-medium text-xs text-white bg-cyan-600 hover:bg-cyan-500 rounded transition-colors disabled:opacity-50 shrink-0"
            >
              {loading ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : <Search className="w-3.5 h-3.5" />}
              <span>{loading ? 'Probing Target...' : 'Inspect Target'}</span>
            </button>
          </div>
        </div>

        {errorMsg && (
          <div className="p-3 rounded bg-red-500/10 border border-red-500/20 text-red-300 text-xs flex items-center gap-2">
            <AlertCircle className="w-4 h-4 shrink-0 text-red-400" />
            <span>{errorMsg}</span>
          </div>
        )}
      </div>

      {/* Recon Category Tabs */}
      <div className="flex border-b border-slate-800 gap-6 text-xs font-medium">
        <button
          onClick={() => setActiveTab('dns')}
          className={`pb-2.5 transition-colors ${
            activeTab === 'dns'
              ? 'text-cyan-400 border-b-2 border-cyan-400'
              : 'text-slate-400 hover:text-slate-200'
          }`}
        >
          DNS Records (A, AAAA, MX, NS, TXT, CNAME)
        </button>
        <button
          onClick={() => setActiveTab('http')}
          className={`pb-2.5 transition-colors ${
            activeTab === 'http'
              ? 'text-cyan-400 border-b-2 border-cyan-400'
              : 'text-slate-400 hover:text-slate-200'
          }`}
        >
          HTTP Metadata & TLS Certificate
        </button>
        <button
          onClick={() => setActiveTab('files')}
          className={`pb-2.5 transition-colors ${
            activeTab === 'files'
              ? 'text-cyan-400 border-b-2 border-cyan-400'
              : 'text-slate-400 hover:text-slate-200'
          }`}
        >
          robots.txt, Sitemap & Tech Stack
        </button>
      </div>

      {/* Tab 1: DNS Records */}
      {activeTab === 'dns' && (
        <div className="space-y-4">
          {!dnsData ? (
            <div className="p-12 text-center text-slate-500 text-xs rounded-lg bg-slate-900/60 border border-slate-800">
              <Globe className="w-8 h-8 text-slate-700 mx-auto mb-2" />
              <span>Enter a domain and click "Inspect Target" to query DNS records.</span>
            </div>
          ) : (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {/* A & AAAA */}
              <div className="p-4 rounded-lg bg-slate-900/60 border border-slate-800 space-y-3">
                <div className="flex items-center justify-between text-xs">
                  <span className="font-semibold text-white">A Records (IPv4)</span>
                  <span className="font-mono text-cyan-400">{dnsData.a?.length || 0} found</span>
                </div>
                <div className="space-y-1">
                  {dnsData.a && dnsData.a.length > 0 ? (
                    dnsData.a.map((ip, i) => (
                      <div key={i} className="p-2 rounded bg-slate-950 font-mono text-xs text-slate-300 flex items-center justify-between">
                        <span>{ip}</span>
                        <span className="text-[10px] text-emerald-400 font-mono">Public Validated</span>
                      </div>
                    ))
                  ) : (
                    <div className="text-xs text-slate-500 italic">No A records found</div>
                  )}
                </div>

                <div className="pt-2 border-t border-slate-800/80">
                  <div className="flex items-center justify-between text-xs mb-2">
                    <span className="font-semibold text-white">AAAA Records (IPv6)</span>
                    <span className="font-mono text-cyan-400">{dnsData.aaaa?.length || 0} found</span>
                  </div>
                  {dnsData.aaaa && dnsData.aaaa.length > 0 ? (
                    dnsData.aaaa.map((ip6, i) => (
                      <div key={i} className="p-2 rounded bg-slate-950 font-mono text-[11px] text-slate-300 truncate">
                        {ip6}
                      </div>
                    ))
                  ) : (
                    <div className="text-xs text-slate-500 italic">No AAAA records</div>
                  )}
                </div>
              </div>

              {/* MX & NS */}
              <div className="p-4 rounded-lg bg-slate-900/60 border border-slate-800 space-y-3">
                <div className="flex items-center justify-between text-xs">
                  <span className="font-semibold text-white">Mail Exchangers (MX)</span>
                  <span className="font-mono text-cyan-400">{dnsData.mx?.length || 0} found</span>
                </div>
                <div className="space-y-1">
                  {dnsData.mx && dnsData.mx.length > 0 ? (
                    dnsData.mx.map((mx, i) => (
                      <div key={i} className="p-2 rounded bg-slate-950 font-mono text-xs text-slate-300 flex items-center justify-between">
                        <span className="truncate">{mx.exchange}</span>
                        <span className="text-[10px] text-slate-500 font-mono">Priority: {mx.priority}</span>
                      </div>
                    ))
                  ) : (
                    <div className="text-xs text-slate-500 italic">No MX records configured</div>
                  )}
                </div>

                <div className="pt-2 border-t border-slate-800/80">
                  <div className="flex items-center justify-between text-xs mb-2">
                    <span className="font-semibold text-white">Nameservers (NS)</span>
                    <span className="font-mono text-cyan-400">{dnsData.ns?.length || 0} found</span>
                  </div>
                  {dnsData.ns && dnsData.ns.length > 0 ? (
                    dnsData.ns.map((ns, i) => (
                      <div key={i} className="p-2 rounded bg-slate-950 font-mono text-xs text-slate-300 truncate">
                        {ns}
                      </div>
                    ))
                  ) : (
                    <div className="text-xs text-slate-500 italic">No NS records returned</div>
                  )}
                </div>
              </div>

              {/* TXT Records */}
              <div className="md:col-span-2 p-4 rounded-lg bg-slate-900/60 border border-slate-800 space-y-2">
                <div className="flex items-center justify-between text-xs">
                  <span className="font-semibold text-white">TXT Records (SPF / DKIM / Verification Tokens)</span>
                  <span className="font-mono text-cyan-400">{dnsData.txt?.length || 0} found</span>
                </div>
                <div className="space-y-1.5 max-h-56 overflow-y-auto">
                  {dnsData.txt && dnsData.txt.length > 0 ? (
                    dnsData.txt.map((txt, i) => (
                      <div key={i} className="p-2 rounded bg-slate-950 font-mono text-xs text-slate-300 break-all border border-slate-800/50">
                        {txt}
                      </div>
                    ))
                  ) : (
                    <div className="text-xs text-slate-500 italic">No TXT records found</div>
                  )}
                </div>
              </div>
            </div>
          )}
        </div>
      )}

      {/* Tab 2: HTTP Metadata & TLS */}
      {activeTab === 'http' && (
        <div className="space-y-4">
          {!httpData ? (
            <div className="p-12 text-center text-slate-500 text-xs rounded-lg bg-slate-900/60 border border-slate-800">
              <Shield className="w-8 h-8 text-slate-700 mx-auto mb-2" />
              <span>HTTP metadata will appear here after inspecting the target.</span>
            </div>
          ) : (
            <div className="space-y-4">
              {/* Quick stats strip */}
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                <div className="p-3 rounded bg-slate-900/60 border border-slate-800">
                  <div className="text-[11px] text-slate-500 uppercase font-medium">Status Code</div>
                  <div className="text-lg font-bold font-mono text-emerald-400 mt-0.5">
                    {httpData.statusCode} OK
                  </div>
                </div>

                <div className="p-3 rounded bg-slate-900/60 border border-slate-800">
                  <div className="text-[11px] text-slate-500 uppercase font-medium">Latency</div>
                  <div className="text-lg font-bold font-mono text-white mt-0.5">
                    {httpData.responseTimeMs} ms
                  </div>
                </div>

                <div className="p-3 rounded bg-slate-900/60 border border-slate-800">
                  <div className="text-[11px] text-slate-500 uppercase font-medium">Content Type</div>
                  <div className="text-xs font-mono text-slate-300 truncate mt-1">
                    {httpData.contentType}
                  </div>
                </div>

                <div className="p-3 rounded bg-slate-900/60 border border-slate-800">
                  <div className="text-[11px] text-slate-500 uppercase font-medium">TLS State</div>
                  <div className="text-xs font-mono text-emerald-400 flex items-center gap-1 mt-1">
                    <Lock className="w-3.5 h-3.5" />
                    <span>{httpData.tlsInfo?.authorized ? 'Valid Cert' : 'Plain / Self-Signed'}</span>
                  </div>
                </div>
              </div>

              {/* TLS Details */}
              {httpData.tlsInfo && (
                <div className="p-4 rounded-lg bg-slate-900/60 border border-slate-800 space-y-2 text-xs">
                  <div className="font-semibold text-white flex items-center gap-1.5">
                    <Lock className="w-4 h-4 text-cyan-400" />
                    <span>TLS Certificate Inspection</span>
                  </div>
                  <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 pt-1">
                    <div className="p-2.5 rounded bg-slate-950 font-mono">
                      <span className="text-slate-500 text-[11px] block">Subject Common Name:</span>
                      <span className="text-slate-200">{httpData.tlsInfo.subject || 'N/A'}</span>
                    </div>
                    <div className="p-2.5 rounded bg-slate-950 font-mono">
                      <span className="text-slate-500 text-[11px] block">Issuer Authority:</span>
                      <span className="text-slate-200">{httpData.tlsInfo.issuer || 'N/A'}</span>
                    </div>
                    <div className="p-2.5 rounded bg-slate-950 font-mono">
                      <span className="text-slate-500 text-[11px] block">Valid Until:</span>
                      <span className="text-slate-200">{httpData.tlsInfo.validTo ? new Date(httpData.tlsInfo.validTo).toLocaleDateString() : 'N/A'}</span>
                    </div>
                  </div>
                </div>
              )}

              {/* Response Headers Table */}
              <div className="p-4 rounded-lg bg-slate-900/60 border border-slate-800 space-y-2">
                <div className="text-xs font-semibold text-white">HTTP Response Headers</div>
                <div className="max-h-72 overflow-y-auto rounded border border-slate-800">
                  <table className="w-full text-left text-xs font-mono">
                    <thead className="bg-slate-950 text-slate-400 border-b border-slate-800 text-[11px]">
                      <tr>
                        <th className="py-2 px-3">Header Name</th>
                        <th className="py-2 px-3">Header Value</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-850 bg-slate-950/60">
                      {Object.entries(httpData.headers).map(([key, val]) => (
                        <tr key={key} className="hover:bg-slate-900/60">
                          <td className="py-1.5 px-3 text-cyan-400 font-medium whitespace-nowrap">{key}</td>
                          <td className="py-1.5 px-3 text-slate-300 break-all">{val}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            </div>
          )}
        </div>
      )}

      {/* Tab 3: robots.txt, Sitemap & Technologies */}
      {activeTab === 'files' && (
        <div className="space-y-4">
          {!httpData ? (
            <div className="p-12 text-center text-slate-500 text-xs rounded-lg bg-slate-900/60 border border-slate-800">
              <FileCode className="w-8 h-8 text-slate-700 mx-auto mb-2" />
              <span>Diagnostic file reconnaissance will appear here.</span>
            </div>
          ) : (
            <div className="space-y-4">
              {/* Detected technologies */}
              <div className="p-4 rounded-lg bg-slate-900/60 border border-slate-800 space-y-2 text-xs">
                <span className="font-semibold text-white">Detected Technologies & Stack Fingerprints</span>
                <div className="flex flex-wrap gap-2 pt-1">
                  {httpData.technologies.length > 0 ? (
                    httpData.technologies.map((tech, i) => (
                      <span key={i} className="px-2.5 py-1 rounded bg-cyan-500/10 text-cyan-300 border border-cyan-500/20 font-mono text-[11px]">
                        {tech}
                      </span>
                    ))
                  ) : (
                    <span className="text-slate-500 italic">No identifiable server version banners disclosed (Good hardening posture).</span>
                  )}
                </div>
              </div>

              {/* Robots.txt */}
              <div className="p-4 rounded-lg bg-slate-900/60 border border-slate-800 space-y-2 text-xs">
                <div className="flex items-center justify-between">
                  <span className="font-semibold text-white">robots.txt Inspection</span>
                  <span className="font-mono text-slate-400 text-[11px]">
                    {httpData.robotsTxt ? '200 OK (Disclosed)' : 'Not Found or Inaccessible'}
                  </span>
                </div>
                {httpData.robotsTxt ? (
                  <pre className="p-3 rounded bg-slate-950 font-mono text-xs text-slate-300 border border-slate-800 overflow-x-auto max-h-56">
                    {httpData.robotsTxt}
                  </pre>
                ) : (
                  <div className="text-slate-500 italic p-3 rounded bg-slate-950">
                    Target did not return a public robots.txt file.
                  </div>
                )}
              </div>

              {/* Sitemap.xml */}
              <div className="p-4 rounded-lg bg-slate-900/60 border border-slate-800 space-y-2 text-xs">
                <div className="flex items-center justify-between">
                  <span className="font-semibold text-white">sitemap.xml Discovery</span>
                  <span className="font-mono text-slate-400 text-[11px]">
                    {httpData.sitemap.found ? 'Discovered (XML)' : 'Not Found'}
                  </span>
                </div>
                {httpData.sitemap.found ? (
                  <pre className="p-3 rounded bg-slate-950 font-mono text-xs text-slate-300 border border-slate-800 overflow-x-auto max-h-56">
                    {httpData.sitemap.preview}
                  </pre>
                ) : (
                  <div className="text-slate-500 italic p-3 rounded bg-slate-950">
                    No public sitemap.xml discovered at root.
                  </div>
                )}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
};
