import React, { useState } from 'react';
import { Finding, Severity, FindingStatus } from '../types.ts';
import { Search, Filter, Trash2, Edit3, ShieldAlert, CheckCircle2, ChevronRight, X, ExternalLink } from 'lucide-react';

interface FindingsProps {
  findings: Finding[];
  onUpdateFinding: (id: string, data: { verification_status?: FindingStatus; severity?: Severity; notes?: string }) => Promise<void>;
  onDeleteFinding: (id: string) => Promise<void>;
  selectedFinding: Finding | null;
  setSelectedFinding: (finding: Finding | null) => void;
}

export const Findings: React.FC<FindingsProps> = ({
  findings,
  onUpdateFinding,
  onDeleteFinding,
  selectedFinding,
  setSelectedFinding
}) => {
  const [searchQuery, setSearchQuery] = useState('');
  const [severityFilter, setSeverityFilter] = useState<string>('all');
  const [statusFilter, setStatusFilter] = useState<string>('all');
  const [editStatus, setEditStatus] = useState<FindingStatus>('New');
  const [notes, setNotes] = useState('');
  const [isUpdating, setIsUpdating] = useState(false);

  const severityBadges: Record<Severity, { bg: string; text: string; border: string }> = {
    critical: { bg: 'bg-red-500/10', text: 'text-red-400', border: 'border-red-500/20' },
    high: { bg: 'bg-amber-500/10', text: 'text-amber-400', border: 'border-amber-500/20' },
    medium: { bg: 'bg-yellow-500/10', text: 'text-yellow-400', border: 'border-yellow-500/20' },
    low: { bg: 'bg-cyan-500/10', text: 'text-cyan-400', border: 'border-cyan-500/20' },
    informational: { bg: 'bg-slate-500/10', text: 'text-slate-400', border: 'border-slate-500/20' }
  };

  const filteredFindings = findings.filter(f => {
    const matchesSearch =
      f.title.toLowerCase().includes(searchQuery.toLowerCase()) ||
      f.category.toLowerCase().includes(searchQuery.toLowerCase()) ||
      f.affected_url.toLowerCase().includes(searchQuery.toLowerCase());

    const matchesSeverity = severityFilter === 'all' || f.severity === severityFilter;
    const matchesStatus = statusFilter === 'all' || f.verification_status === statusFilter;

    return matchesSearch && matchesSeverity && matchesStatus;
  });

  const handleOpenDetail = (f: Finding) => {
    setSelectedFinding(f);
    setEditStatus(f.verification_status);
    setNotes('');
  };

  const handleSaveUpdate = async () => {
    if (!selectedFinding) return;
    setIsUpdating(true);
    try {
      await onUpdateFinding(selectedFinding.id, {
        verification_status: editStatus,
        notes: notes.trim() || undefined
      });
      setSelectedFinding({
        ...selectedFinding,
        verification_status: editStatus,
        manual_verification: notes.trim()
          ? `${selectedFinding.manual_verification}\nNote: ${notes.trim()}`
          : selectedFinding.manual_verification
      });
      setNotes('');
    } finally {
      setIsUpdating(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Header & Filter Controls */}
      <div className="p-5 rounded-lg bg-slate-900/60 border border-slate-800 space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
          <div>
            <h2 className="text-sm font-semibold text-white tracking-tight">
              Vulnerability Findings Management
            </h2>
            <p className="text-xs text-slate-400 mt-0.5">
              Review observed weaknesses, audit evidence, verify status, and implement defensive remediations.
            </p>
          </div>
          <span className="text-xs font-mono text-slate-400">
            {filteredFindings.length} of {findings.length} findings
          </span>
        </div>

        {/* Filter bar */}
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 text-xs">
          <div className="relative">
            <Search className="w-3.5 h-3.5 text-slate-500 absolute left-3 top-2.5" />
            <input
              type="text"
              placeholder="Search title, category, or endpoint..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="w-full pl-8 pr-3 py-1.5 bg-slate-950 border border-slate-800 rounded text-slate-100 placeholder-slate-600 focus:outline-none focus:border-cyan-500"
            />
          </div>

          <div>
            <select
              value={severityFilter}
              onChange={(e) => setSeverityFilter(e.target.value)}
              className="w-full px-3 py-1.5 bg-slate-950 border border-slate-800 rounded text-slate-300 focus:outline-none"
            >
              <option value="all">All Severities</option>
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
              <option value="informational">Informational</option>
            </select>
          </div>

          <div>
            <select
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value)}
              className="w-full px-3 py-1.5 bg-slate-950 border border-slate-800 rounded text-slate-300 focus:outline-none"
            >
              <option value="all">All Verification Statuses</option>
              <option value="New">New</option>
              <option value="Needs Review">Needs Review</option>
              <option value="Confirmed">Confirmed</option>
              <option value="False Positive">False Positive</option>
              <option value="Fixed">Fixed</option>
              <option value="Accepted Risk">Accepted Risk</option>
            </select>
          </div>
        </div>
      </div>

      {/* Findings Table */}
      <div className="rounded-lg bg-slate-900/60 border border-slate-800 overflow-hidden">
        {filteredFindings.length === 0 ? (
          <div className="py-12 px-4 text-center text-slate-500 text-xs">
            <ShieldAlert className="w-8 h-8 text-slate-700 mx-auto mb-2" />
            <div>No matching findings found.</div>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="bg-slate-950/80 text-slate-400 border-b border-slate-800 font-mono uppercase text-[11px]">
                <tr>
                  <th className="py-3 px-4 font-medium">Severity</th>
                  <th className="py-3 px-4 font-medium">Title & Category</th>
                  <th className="py-3 px-4 font-medium">Affected Endpoint</th>
                  <th className="py-3 px-4 font-medium">Status</th>
                  <th className="py-3 px-4 font-medium">Discovered</th>
                  <th className="py-3 px-4 font-medium text-right">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60">
                {filteredFindings.map((finding) => {
                  const badge = severityBadges[finding.severity];
                  return (
                    <tr
                      key={finding.id}
                      onClick={() => handleOpenDetail(finding)}
                      className="hover:bg-slate-850/40 cursor-pointer transition-colors"
                    >
                      <td className="py-3 px-4">
                        <span className={`px-2 py-0.5 rounded text-[10px] font-mono uppercase font-bold tracking-wider ${badge.bg} ${badge.text} border ${badge.border}`}>
                          {finding.severity}
                        </span>
                      </td>

                      <td className="py-3 px-4">
                        <div className="font-medium text-slate-200">
                          {finding.title}
                        </div>
                        <div className="text-[11px] text-slate-500 font-mono mt-0.5">
                          {finding.category}
                        </div>
                      </td>

                      <td className="py-3 px-4 font-mono text-[11px] text-slate-400 truncate max-w-xs">
                        {finding.affected_url}
                      </td>

                      <td className="py-3 px-4">
                        <span className="text-[11px] font-mono text-slate-300 px-2 py-0.5 rounded bg-slate-950 border border-slate-800">
                          {finding.verification_status}
                        </span>
                      </td>

                      <td className="py-3 px-4 font-mono text-[11px] text-slate-500">
                        {new Date(finding.first_discovered).toLocaleDateString()}
                      </td>

                      <td className="py-3 px-4 text-right">
                        <ChevronRight className="w-4 h-4 text-slate-500 inline-block" />
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Finding Detail Modal / Drawer */}
      {selectedFinding && (
        <div className="fixed inset-0 z-50 bg-black/75 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="w-full max-w-2xl bg-slate-900 border border-slate-800 rounded-lg shadow-2xl max-h-[90vh] flex flex-col overflow-hidden">
            {/* Modal Header */}
            <div className="px-6 py-4 border-b border-slate-800 flex items-center justify-between">
              <div className="flex items-center gap-3">
                <span className={`px-2 py-0.5 rounded text-[10px] font-mono uppercase font-bold tracking-wider ${severityBadges[selectedFinding.severity].bg} ${severityBadges[selectedFinding.severity].text} border ${severityBadges[selectedFinding.severity].border}`}>
                  {selectedFinding.severity}
                </span>
                <h3 className="text-sm font-semibold text-white tracking-tight">
                  {selectedFinding.title}
                </h3>
              </div>
              <button
                onClick={() => setSelectedFinding(null)}
                className="text-slate-400 hover:text-white"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            {/* Modal Body */}
            <div className="p-6 overflow-y-auto space-y-4 text-xs">
              <div className="grid grid-cols-2 gap-3 p-3 rounded bg-slate-950 border border-slate-850 font-mono text-[11px]">
                <div>
                  <span className="text-slate-500 block">Category:</span>
                  <span className="text-slate-300">{selectedFinding.category}</span>
                </div>
                <div>
                  <span className="text-slate-500 block">Status:</span>
                  <span className="text-cyan-400">{selectedFinding.verification_status}</span>
                </div>
                <div className="col-span-2">
                  <span className="text-slate-500 block">Affected Endpoint:</span>
                  <span className="text-slate-300 break-all">{selectedFinding.affected_url}</span>
                </div>
              </div>

              {/* Description */}
              <div>
                <h4 className="text-slate-400 font-semibold mb-1 uppercase text-[11px] font-mono">Description</h4>
                <p className="text-slate-300 leading-relaxed bg-slate-950 p-3 rounded border border-slate-850">
                  {selectedFinding.description}
                </p>
              </div>

              {/* Impact */}
              <div>
                <h4 className="text-slate-400 font-semibold mb-1 uppercase text-[11px] font-mono">Security Impact</h4>
                <p className="text-slate-300 leading-relaxed bg-slate-950 p-3 rounded border border-slate-850">
                  {selectedFinding.impact}
                </p>
              </div>

              {/* Evidence */}
              <div>
                <h4 className="text-slate-400 font-semibold mb-1 uppercase text-[11px] font-mono">Observed Evidence</h4>
                <pre className="text-slate-300 font-mono text-[11px] bg-slate-950 p-3 rounded border border-slate-850 overflow-x-auto whitespace-pre-wrap">
                  {selectedFinding.evidence}
                </pre>
              </div>

              {/* Remediation Advice */}
              <div>
                <h4 className="text-emerald-400 font-semibold mb-1 uppercase text-[11px] font-mono">Defensive Remediation Advice</h4>
                <p className="text-slate-200 leading-relaxed bg-slate-950 p-3 rounded border border-slate-850">
                  {selectedFinding.remediation}
                </p>
              </div>

              {/* Manual Verification Guidance */}
              <div>
                <h4 className="text-cyan-400 font-semibold mb-1 uppercase text-[11px] font-mono">Manual Verification Guidance</h4>
                <pre className="text-slate-300 font-mono text-[11px] bg-slate-950 p-3 rounded border border-slate-850 overflow-x-auto whitespace-pre-wrap">
                  {selectedFinding.manual_verification}
                </pre>
              </div>

              {/* Verification Status & Notes form */}
              <div className="p-4 rounded bg-slate-950 border border-slate-800 space-y-3">
                <h4 className="text-white font-semibold">Triage & Verification Review</h4>
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                  <div>
                    <label className="block text-slate-400 text-[11px] mb-1">Update Status</label>
                    <select
                      value={editStatus}
                      onChange={(e) => setEditStatus(e.target.value as FindingStatus)}
                      className="w-full px-2.5 py-1.5 bg-slate-900 border border-slate-800 rounded text-slate-200"
                    >
                      <option value="New">New</option>
                      <option value="Needs Review">Needs Review</option>
                      <option value="Confirmed">Confirmed</option>
                      <option value="False Positive">False Positive</option>
                      <option value="Fixed">Fixed</option>
                      <option value="Accepted Risk">Accepted Risk</option>
                    </select>
                  </div>

                  <div>
                    <label className="block text-slate-400 text-[11px] mb-1">Add Analyst Verification Note</label>
                    <input
                      type="text"
                      placeholder="e.g. Manually verified with curl -I"
                      value={notes}
                      onChange={(e) => setNotes(e.target.value)}
                      className="w-full px-2.5 py-1.5 bg-slate-900 border border-slate-800 rounded text-slate-200 text-xs"
                    />
                  </div>
                </div>

                <div className="flex items-center justify-between pt-2">
                  <button
                    onClick={() => {
                      if (confirm('Are you sure you want to delete this finding?')) {
                        onDeleteFinding(selectedFinding.id);
                        setSelectedFinding(null);
                      }
                    }}
                    className="flex items-center gap-1 text-red-400 hover:text-red-300 transition-colors"
                  >
                    <Trash2 className="w-3.5 h-3.5" />
                    <span>Delete Finding</span>
                  </button>

                  <button
                    onClick={handleSaveUpdate}
                    disabled={isUpdating}
                    className="px-3.5 py-1.5 font-medium text-white bg-cyan-600 hover:bg-cyan-500 rounded transition-colors disabled:opacity-50"
                  >
                    {isUpdating ? 'Saving...' : 'Save Triage Update'}
                  </button>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
