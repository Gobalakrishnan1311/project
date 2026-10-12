/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState, useEffect } from 'react';
import { Sidebar, NavTab } from './components/Sidebar.tsx';
import { TopBar } from './components/TopBar.tsx';
import { Dashboard } from './pages/Dashboard.tsx';
import { Targets } from './pages/Targets.tsx';
import { Reconnaissance } from './pages/Reconnaissance.tsx';
import { Scanner } from './pages/Scanner.tsx';
import { Inspector } from './pages/Inspector.tsx';
import { Findings } from './pages/Findings.tsx';
import { History } from './pages/History.tsx';
import { Reports } from './pages/Reports.tsx';
import { Settings } from './pages/Settings.tsx';
import { api } from './services/api.ts';
import { Target, Scan, Finding, DashboardMetrics, FindingStatus, Severity } from './types.ts';
import { AlertCircle, CheckCircle } from 'lucide-react';

export default function App() {
  const [currentTab, setCurrentTab] = useState<NavTab>('dashboard');
  const [targets, setTargets] = useState<Target[]>([]);
  const [scans, setScans] = useState<Scan[]>([]);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [metrics, setMetrics] = useState<DashboardMetrics | null>(null);

  // Cross-page navigation state
  const [selectedTargetId, setSelectedTargetId] = useState<string>('');
  const [reconHost, setReconHost] = useState<string>('');
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null);
  const [isAddTargetModalOpen, setIsAddTargetModalOpen] = useState(false);
  const [isSeeding, setIsSeeding] = useState(false);
  const [toast, setToast] = useState<{ type: 'success' | 'error'; message: string } | null>(null);

  const showToast = (type: 'success' | 'error', message: string) => {
    setToast({ type, message });
    setTimeout(() => setToast(null), 3500);
  };

  const loadData = async () => {
    try {
      const [dashData, targetList, scanList, findingList] = await Promise.all([
        api.getDashboard().catch(() => null),
        api.getTargets().catch(() => []),
        api.getScans().catch(() => []),
        api.getFindings().catch(() => [])
      ]);

      if (dashData) {
        setMetrics(dashData.metrics);
      }
      setTargets(targetList);
      setScans(scanList);
      setFindings(findingList);
    } catch (err) {
      console.error('Failed to load initial data:', err);
    }
  };

  useEffect(() => {
    loadData();
    // Poll data periodically to keep dashboard & scans synchronized
    const interval = setInterval(loadData, 4000);
    return () => clearInterval(interval);
  }, []);

  const handleAddTarget = async (data: Partial<Target>) => {
    const newTarget = await api.createTarget(data);
    setTargets(prev => [newTarget, ...prev]);
    showToast('success', `Target ${newTarget.hostname} added to scope.`);
    loadData();
  };

  const handleDeleteTarget = async (id: string) => {
    await api.deleteTarget(id);
    setTargets(prev => prev.filter(t => t.id !== id));
    showToast('success', 'Target removed from scope.');
    loadData();
  };

  const handleStartScanFromTarget = (targetId: string) => {
    setSelectedTargetId(targetId);
    setCurrentTab('scanner');
  };

  const handleStartReconFromTarget = (url: string) => {
    setReconHost(url);
    setCurrentTab('recon');
  };

  const handleUpdateFinding = async (id: string, data: { verification_status?: FindingStatus; severity?: Severity; notes?: string }) => {
    const updated = await api.updateFinding(id, data);
    setFindings(prev => prev.map(f => f.id === id ? updated : f));
    showToast('success', 'Finding verification updated.');
    loadData();
  };

  const handleDeleteFinding = async (id: string) => {
    await api.deleteFinding(id);
    setFindings(prev => prev.filter(f => f.id !== id));
    showToast('success', 'Finding deleted.');
    loadData();
  };

  const handleSeedDemo = async () => {
    setIsSeeding(true);
    try {
      await api.seedDemo();
      await loadData();
      showToast('success', 'Demo authorized target and audit findings loaded.');
    } catch {
      showToast('error', 'Failed to seed demo data.');
    } finally {
      setIsSeeding(false);
    }
  };

  return (
    <div className="flex h-screen bg-slate-950 text-slate-100 overflow-hidden font-sans">
      {/* Toast notification */}
      {toast && (
        <div className="fixed top-4 right-4 z-50 flex items-center gap-2 px-4 py-2.5 rounded-lg shadow-xl text-xs font-medium animate-in fade-in slide-in-from-top-2 border backdrop-blur ${
          toast.type === 'success'
            ? 'bg-emerald-950/90 border-emerald-500/30 text-emerald-200'
            : 'bg-red-950/90 border-red-500/30 text-red-200'
        }">
          {toast.type === 'success' ? (
            <CheckCircle className="w-4 h-4 text-emerald-400 shrink-0" />
          ) : (
            <AlertCircle className="w-4 h-4 text-red-400 shrink-0" />
          )}
          <span>{toast.message}</span>
        </div>
      )}

      {/* Main Sidebar */}
      <Sidebar
        currentTab={currentTab}
        onTabChange={setCurrentTab}
        findingsCount={findings.length}
      />

      {/* Content Area */}
      <div className="flex-1 flex flex-col min-w-0 overflow-hidden">
        <TopBar
          currentTab={currentTab}
          onOpenAddTarget={() => setIsAddTargetModalOpen(true)}
          onSeedDemo={handleSeedDemo}
          isSeeding={isSeeding}
        />

        <main className="flex-1 overflow-y-auto p-6">
          <div className="max-w-7xl mx-auto">
            {currentTab === 'dashboard' && (
              <Dashboard
                metrics={metrics}
                recentScans={scans}
                latestFindings={findings}
                onNavigate={setCurrentTab}
                onSelectScan={(id) => {
                  setSelectedTargetId('');
                  setCurrentTab('history');
                }}
                onSelectFinding={(f) => {
                  setSelectedFinding(f);
                  setCurrentTab('findings');
                }}
                onStartQuickScan={handleStartScanFromTarget}
              />
            )}

            {currentTab === 'targets' && (
              <Targets
                targets={targets}
                onAddTarget={handleAddTarget}
                onDeleteTarget={handleDeleteTarget}
                onStartScan={handleStartScanFromTarget}
                onStartRecon={handleStartReconFromTarget}
                isAddModalOpen={isAddTargetModalOpen}
                setIsAddModalOpen={setIsAddTargetModalOpen}
              />
            )}

            {currentTab === 'recon' && (
              <Reconnaissance
                targets={targets}
                defaultHost={reconHost}
              />
            )}

            {currentTab === 'scanner' && (
              <Scanner
                targets={targets}
                selectedTargetId={selectedTargetId}
                onNavigateFindings={() => setCurrentTab('findings')}
                onSelectFinding={(f) => {
                  setSelectedFinding(f);
                  setCurrentTab('findings');
                }}
              />
            )}

            {currentTab === 'inspector' && (
              <Inspector targets={targets} />
            )}

            {currentTab === 'findings' && (
              <Findings
                findings={findings}
                onUpdateFinding={handleUpdateFinding}
                onDeleteFinding={handleDeleteFinding}
                selectedFinding={selectedFinding}
                setSelectedFinding={setSelectedFinding}
              />
            )}

            {currentTab === 'history' && (
              <History
                scans={scans}
                onSelectScan={(id) => {
                  setSelectedTargetId('');
                }}
                onNavigate={setCurrentTab}
              />
            )}

            {currentTab === 'reports' && (
              <Reports
                scans={scans}
                findings={findings}
              />
            )}

            {currentTab === 'settings' && (
              <Settings
                onSeedDemo={handleSeedDemo}
                isSeeding={isSeeding}
              />
            )}
          </div>
        </main>
      </div>
    </div>
  );
}
