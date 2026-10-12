import React from 'react';
import { Shield, Plus, RefreshCw, Database } from 'lucide-react';
import { NavTab } from './Sidebar.tsx';

interface TopBarProps {
  currentTab: NavTab;
  onOpenAddTarget: () => void;
  onSeedDemo: () => void;
  isSeeding?: boolean;
}

export const TopBar: React.FC<TopBarProps> = ({
  currentTab,
  onOpenAddTarget,
  onSeedDemo,
  isSeeding = false
}) => {
  const getTabTitle = (tab: NavTab) => {
    switch (tab) {
      case 'dashboard': return 'Dashboard Overview';
      case 'targets': return 'Target Scope Management';
      case 'recon': return 'Reconnaissance & DNS Inspector';
      case 'scanner': return 'Security Vulnerability Scanner';
      case 'inspector': return 'HTTP Request / Response Inspector';
      case 'findings': return 'Vulnerability Findings';
      case 'history': return 'Scan Execution History';
      case 'reports': return 'Compliance & Audit Reports';
      case 'settings': return 'ScopeGuard Rules & Settings';
    }
  };

  return (
    <header className="h-16 px-6 border-b border-slate-800 bg-slate-950/80 backdrop-blur flex items-center justify-between gap-8 shrink-0">
      {/* Zone 1: Breadcrumb Title */}
      <div className="flex items-center gap-2 min-w-0">
        <span className="text-xs text-slate-500 font-mono">Scope</span>
        <span className="text-xs text-slate-600 font-mono">/</span>
        <h1 className="text-sm font-semibold text-white truncate tracking-tight">
          {getTabTitle(currentTab)}
        </h1>
      </div>

      {/* Zone 2: Scope Status Guard */}
      <div className="hidden lg:flex items-center gap-4 text-xs font-mono text-slate-400">
        <div className="flex items-center gap-1.5 px-2.5 py-1 rounded bg-slate-900 border border-slate-800">
          <Shield className="w-3.5 h-3.5 text-cyan-400" />
          <span className="text-slate-300">SSRF Protection:</span>
          <span className="text-emerald-400 font-medium">RFC 1918 Denied</span>
        </div>
      </div>

      {/* Zone 3: Actions */}
      <div className="flex items-center gap-2.5 shrink-0">
        <a
          href="/api/download/source"
          download="webbug-hunter-source.zip"
          className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-cyan-300 bg-cyan-950/60 border border-cyan-800/80 rounded-md hover:bg-cyan-900/60 transition-colors"
          title="Download full project source code as a ZIP archive"
        >
          <svg className="w-3.5 h-3.5 text-cyan-400" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
            <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/>
            <polyline points="7 10 12 15 17 10"/>
            <line x1="12" y1="15" x2="12" y2="3"/>
          </svg>
          <span className="hidden sm:inline">Download Code (.ZIP)</span>
        </a>

        <button
          onClick={onSeedDemo}
          disabled={isSeeding}
          className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-slate-300 bg-slate-900 border border-slate-800 rounded-md hover:bg-slate-850 hover:text-white transition-colors disabled:opacity-50"
          title="Populate authorized demonstration target and findings"
        >
          {isSeeding ? (
            <RefreshCw className="w-3.5 h-3.5 animate-spin text-slate-400" />
          ) : (
            <Database className="w-3.5 h-3.5 text-cyan-400" />
          )}
          <span className="hidden sm:inline">Load Demo Data</span>
        </button>

        <button
          onClick={onOpenAddTarget}
          className="flex items-center gap-1.5 px-3.5 py-1.5 text-xs font-medium text-white bg-cyan-600 hover:bg-cyan-500 rounded-md transition-colors shadow-sm"
        >
          <Plus className="w-3.5 h-3.5" />
          <span>Add Target</span>
        </button>
      </div>
    </header>
  );
};
