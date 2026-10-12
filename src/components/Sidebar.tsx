import React from 'react';
import {
  LayoutDashboard,
  Target,
  Search,
  ShieldAlert,
  Send,
  Bug,
  History,
  FileText,
  Sliders,
  ShieldCheck
} from 'lucide-react';

export type NavTab =
  | 'dashboard'
  | 'targets'
  | 'recon'
  | 'scanner'
  | 'inspector'
  | 'findings'
  | 'history'
  | 'reports'
  | 'settings';

interface SidebarProps {
  currentTab: NavTab;
  onTabChange: (tab: NavTab) => void;
  findingsCount?: number;
}

export const Sidebar: React.FC<SidebarProps> = ({ currentTab, onTabChange, findingsCount = 0 }) => {
  const navItems: Array<{ id: NavTab; label: string; icon: React.ComponentType<{ className?: string }>; count?: number }> = [
    { id: 'dashboard', label: 'Overview', icon: LayoutDashboard },
    { id: 'targets', label: 'Target Scope', icon: Target },
    { id: 'recon', label: 'Reconnaissance', icon: Search },
    { id: 'scanner', label: 'Security Scanner', icon: ShieldAlert },
    { id: 'inspector', label: 'HTTP Inspector', icon: Send },
    { id: 'findings', label: 'Findings', icon: Bug, count: findingsCount },
    { id: 'history', label: 'Scan History', icon: History },
    { id: 'reports', label: 'Audit Reports', icon: FileText },
    { id: 'settings', label: 'Scope Policy', icon: Sliders },
  ];

  return (
    <aside className="w-64 bg-slate-950 border-r border-slate-850 flex flex-col shrink-0 select-none">
      {/* Brand Zone */}
      <div className="h-16 flex items-center px-5 border-b border-slate-800/80 gap-3">
        <div className="w-8 h-8 rounded-lg bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center text-cyan-400">
          <ShieldCheck className="w-5 h-5" />
        </div>
        <div className="flex flex-col">
          <span className="text-sm font-bold tracking-tight text-white whitespace-nowrap">
            WebBug Hunter
          </span>
          <span className="text-[11px] text-slate-500 font-mono tracking-wider">
            SECURITY TESTING
          </span>
        </div>
      </div>

      {/* Scope Mode Notice */}
      <div className="mx-3 my-3 p-2.5 rounded-md bg-slate-900/60 border border-slate-800 text-xs">
        <div className="flex items-center justify-between text-slate-400 mb-1">
          <span className="font-medium text-[11px] uppercase tracking-wider text-slate-500">ScopeGuard</span>
          <span className="text-[11px] text-cyan-400 font-mono">ENFORCED</span>
        </div>
        <p className="text-[11px] text-slate-400 leading-tight">
          Default-deny policy. All scans strictly limited to authorized hosts.
        </p>
      </div>

      {/* Nav List */}
      <nav className="flex-1 px-3 space-y-1 overflow-y-auto pt-1">
        {navItems.map((item) => {
          const Icon = item.icon;
          const isActive = currentTab === item.id;
          return (
            <button
              key={item.id}
              onClick={() => onTabChange(item.id)}
              className={`w-full flex items-center justify-between px-3 py-2 text-xs font-medium rounded-md transition-colors ${
                isActive
                  ? 'bg-cyan-500/10 text-cyan-300 border border-cyan-500/20'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900/40 border border-transparent'
              }`}
            >
              <div className="flex items-center gap-2.5 whitespace-nowrap">
                <Icon className={`w-4 h-4 ${isActive ? 'text-cyan-400' : 'text-slate-500'}`} />
                <span>{item.label}</span>
              </div>
              {item.count !== undefined && item.count > 0 && (
                <span className="text-[10px] font-mono tabular-nums px-1.5 py-0.2 rounded bg-slate-800 text-slate-300">
                  {item.count}
                </span>
              )}
            </button>
          );
        })}
      </nav>

      {/* Footer Info */}
      <div className="p-3 border-t border-slate-850 text-[11px] text-slate-500 flex items-center justify-between font-mono">
        <span>v1.0.0-auditor</span>
        <span>SSRF-Safe</span>
      </div>
    </aside>
  );
};
