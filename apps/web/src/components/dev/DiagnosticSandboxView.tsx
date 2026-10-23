/**
 * Diagnostic Sandbox, Scenario, Dynamic Behavior & Evasion View
 * P19 — Dynamic Sandbox & Evasion Intelligence
 */

import React, { useState, useEffect } from 'react';
import { 
  Box, 
  Terminal, 
  ShieldAlert, 
  ShieldCheck, 
  Activity, 
  Play, 
  RefreshCw, 
  CheckCircle2, 
  AlertTriangle, 
  Network, 
  Cpu, 
  FileCode2, 
  Key, 
  Search, 
  ExternalLink,
  Zap,
  Info,
  Clock,
  Radio,
  Lock,
  Layers
} from 'lucide-react';
import { DiagnosticJsonDrawer } from './DiagnosticJsonDrawer.tsx';

export interface DiagnosticSandboxViewProps {
  currentRole?: string;
}

export const DiagnosticSandboxView: React.FC<DiagnosticSandboxViewProps> = ({ currentRole = 'operator' }) => {
  const [activeSubTab, setActiveSubTab] = useState<'scenarios' | 'events' | 'evasion' | 'canaries' | 'policies' | 'teardown'>('scenarios');
  const [loading, setLoading] = useState<boolean>(false);
  const [scenarios, setScenarios] = useState<any[]>([]);
  const [selectedScenarioId, setSelectedScenarioId] = useState<string>('SCN-BENIGN-01');
  const [providerType, setProviderType] = useState<'SIMULATED' | 'E2B'>('SIMULATED');
  const [runResult, setRunResult] = useState<any | null>(null);
  const [selectedEvent, setSelectedEvent] = useState<any | null>(null);
  const [filterCategory, setFilterCategory] = useState<string>('ALL');
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [jsonDrawerData, setJsonDrawerData] = useState<any | null>(null);

  useEffect(() => {
    fetchScenarios();
  }, []);

  const fetchScenarios = async () => {
    try {
      const res = await fetch('/api/dev/sandbox/scenarios', {
        headers: { 'X-Role': currentRole }
      });
      if (res.ok) {
        const data = await res.json();
        setScenarios(data);
        if (data.length > 0) {
          setSelectedScenarioId(data[0].id);
        }
      }
    } catch (err) {
      console.error('Failed to load scenarios', err);
    }
  };

  const handleRunScenario = async (scenarioIdToRun?: string) => {
    setLoading(true);
    try {
      const targetId = scenarioIdToRun || selectedScenarioId;
      const res = await fetch('/api/dev/sandbox/run', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Role': currentRole
        },
        body: JSON.stringify({
          scenarioId: targetId,
          providerType: providerType,
        })
      });
      if (res.ok) {
        const data = await res.json();
        setRunResult(data);
      }
    } catch (err) {
      console.error('Failed to run sandbox scenario', err);
    } finally {
      setLoading(false);
    }
  };

  const selectedScenario = scenarios.find(s => s.id === selectedScenarioId);

  const filteredEvents = (runResult?.runtime_events || []).filter((e: any) => {
    if (filterCategory !== 'ALL' && e.category !== filterCategory) return false;
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase();
      return (
        e.action?.toLowerCase().includes(q) ||
        e.target?.toLowerCase().includes(q) ||
        e.category?.toLowerCase().includes(q)
      );
    }
    return true;
  });

  return (
    <div className="space-y-6">
      {/* Top Header Banner */}
      <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-5 shadow-lg backdrop-blur">
        <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4">
          <div className="space-y-1">
            <div className="flex items-center space-x-2.5">
              <div className="p-2 rounded-lg bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                <Box className="w-5 h-5" />
              </div>
              <h2 className="text-xl font-bold text-slate-100 tracking-tight">
                Dynamic Sandbox, Scenarios & Evasion Telemetry
              </h2>
              <span className="px-2.5 py-0.5 rounded-full text-xs font-mono font-medium bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                P19 Engine Active
              </span>
            </div>
            <p className="text-sm text-slate-400 max-w-2xl">
              Strictly isolated execution container with default-deny network controls, non-functional canary secret tripwires, normalized runtime events, and heuristic anti-analysis evasion detection.
            </p>
          </div>

          <div className="flex items-center space-x-3">
            <div className="flex items-center bg-slate-850 border border-slate-700/80 rounded-lg p-1 text-xs">
              <button
                onClick={() => setProviderType('SIMULATED')}
                className={`px-3 py-1.5 rounded-md font-medium transition-all ${
                  providerType === 'SIMULATED'
                    ? 'bg-emerald-600 text-white shadow'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                Simulated Container
              </button>
              <button
                onClick={() => setProviderType('E2B')}
                className={`px-3 py-1.5 rounded-md font-medium transition-all ${
                  providerType === 'E2B'
                    ? 'bg-emerald-600 text-white shadow'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                E2B Isolated MicroVM
              </button>
            </div>

            <button
              onClick={() => handleRunScenario()}
              disabled={loading}
              className="flex items-center space-x-2 px-4 py-2 bg-emerald-600 hover:bg-emerald-500 active:bg-emerald-700 text-white rounded-lg text-sm font-semibold transition-all shadow-md disabled:opacity-50"
              id="run-sandbox-btn"
            >
              {loading ? (
                <>
                  <RefreshCw className="w-4 h-4 animate-spin" />
                  <span>Observing Sandbox...</span>
                </>
              ) : (
                <>
                  <Play className="w-4 h-4 fill-white" />
                  <span>Execute Scenario</span>
                </>
              )}
            </button>
          </div>
        </div>

        {/* Sub Navigation */}
        <div className="flex border-b border-slate-800 mt-6 -mb-5 overflow-x-auto space-x-6 text-sm font-medium">
          <button
            onClick={() => setActiveSubTab('scenarios')}
            className={`pb-3 flex items-center space-x-2 border-b-2 transition-all ${
              activeSubTab === 'scenarios'
                ? 'border-emerald-500 text-emerald-400 font-semibold'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <Layers className="w-4 h-4" />
            <span>Scenarios ({scenarios.length})</span>
          </button>
          
          <button
            onClick={() => setActiveSubTab('events')}
            className={`pb-3 flex items-center space-x-2 border-b-2 transition-all ${
              activeSubTab === 'events'
                ? 'border-emerald-500 text-emerald-400 font-semibold'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <Activity className="w-4 h-4" />
            <span>Runtime Events ({runResult?.runtime_events?.length || 0})</span>
          </button>

          <button
            onClick={() => setActiveSubTab('evasion')}
            className={`pb-3 flex items-center space-x-2 border-b-2 transition-all ${
              activeSubTab === 'evasion'
                ? 'border-emerald-500 text-emerald-400 font-semibold'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <ShieldAlert className="w-4 h-4" />
            <span>Evasion Indicators ({runResult?.evasion_indicators?.filter((i: any) => i.detected).length || 0})</span>
          </button>

          <button
            onClick={() => setActiveSubTab('canaries')}
            className={`pb-3 flex items-center space-x-2 border-b-2 transition-all ${
              activeSubTab === 'canaries'
                ? 'border-emerald-500 text-emerald-400 font-semibold'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <Key className="w-4 h-4" />
            <span>Canary Honeytokens ({runResult?.canaries_injected?.length || 0})</span>
          </button>

          <button
            onClick={() => setActiveSubTab('policies')}
            className={`pb-3 flex items-center space-x-2 border-b-2 transition-all ${
              activeSubTab === 'policies'
                ? 'border-emerald-500 text-emerald-400 font-semibold'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <Lock className="w-4 h-4" />
            <span>Network & Resource Policy</span>
          </button>

          <button
            onClick={() => setActiveSubTab('teardown')}
            className={`pb-3 flex items-center space-x-2 border-b-2 transition-all ${
              activeSubTab === 'teardown'
                ? 'border-emerald-500 text-emerald-400 font-semibold'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <CheckCircle2 className="w-4 h-4" />
            <span>Guaranteed Teardown</span>
          </button>
        </div>
      </div>

      {/* Metrics Row if Run Result exists */}
      {runResult && (
        <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 shadow">
            <div className="text-xs text-slate-400 font-medium">Execution Status</div>
            <div className="text-lg font-bold text-slate-100 mt-1 flex items-center space-x-2">
              <span className={`px-2 py-0.5 rounded text-xs font-mono font-semibold ${
                runResult.status === 'PASSED' ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30' :
                runResult.status === 'VIOLATION_DETECTED' ? 'bg-amber-500/20 text-amber-400 border border-amber-500/30' :
                runResult.status === 'EVASION_FLAGGED' ? 'bg-rose-500/20 text-rose-400 border border-rose-500/30' :
                'bg-red-500/20 text-red-400 border border-red-500/30'
              }`}>
                {runResult.status}
              </span>
            </div>
            <div className="text-xs text-slate-500 mt-1 font-mono">{runResult.duration_ms}ms runtime</div>
          </div>

          <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 shadow">
            <div className="text-xs text-slate-400 font-medium">Evasion Risk Score</div>
            <div className="text-lg font-bold text-slate-100 mt-1 flex items-center space-x-1.5">
              <span className={runResult.evasion_risk_score > 0.5 ? 'text-rose-400' : 'text-emerald-400'}>
                {runResult.evasion_risk_score.toFixed(2)}
              </span>
              <span className="text-xs text-slate-500 font-normal">/ 1.00</span>
            </div>
            <div className="text-xs text-slate-500 mt-1">
              {runResult.anti_analysis_detected ? '⚠️ Anti-Analysis Detected' : 'Clean baseline'}
            </div>
          </div>

          <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 shadow">
            <div className="text-xs text-slate-400 font-medium">Network Policy</div>
            <div className="text-lg font-bold text-slate-100 mt-1 flex items-center space-x-1.5">
              <span className="text-cyan-400 font-mono text-sm">{runResult.network_policy.type}</span>
            </div>
            <div className="text-xs text-slate-500 mt-1">
              {runResult.network_policy.interceptEgress ? 'Egress Intercept ON' : 'Direct'}
            </div>
          </div>

          <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 shadow">
            <div className="text-xs text-slate-400 font-medium">Canaries Tripped</div>
            <div className="text-lg font-bold text-slate-100 mt-1 flex items-center space-x-1.5">
              <span className={runResult.canaries_tripped?.length > 0 ? 'text-rose-400' : 'text-slate-100'}>
                {runResult.canaries_tripped?.length || 0}
              </span>
              <span className="text-xs text-slate-500 font-normal">/ {runResult.canaries_injected?.length || 0} injected</span>
            </div>
            <div className="text-xs text-slate-500 mt-1">
              {runResult.canaries_tripped?.length > 0 ? 'Exfiltration detected' : 'Zero canary access'}
            </div>
          </div>

          <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 shadow">
            <div className="text-xs text-slate-400 font-medium">Guaranteed Teardown</div>
            <div className="text-lg font-bold text-slate-100 mt-1 flex items-center space-x-1.5">
              <CheckCircle2 className="w-4 h-4 text-emerald-400" />
              <span className="text-emerald-400 text-sm font-semibold">{runResult.teardown?.final_status}</span>
            </div>
            <div className="text-xs text-slate-500 mt-1">
              {runResult.teardown?.ephemeral_files_cleaned ? 'Scrubbed 100%' : 'Pending'}
            </div>
          </div>
        </div>
      )}

      {/* Main SubTab Content Area */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left Column: Scenario Registry or Event Categories */}
        <div className="lg:col-span-4 space-y-4">
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 shadow">
            <div className="flex items-center justify-between pb-3 border-b border-slate-800">
              <h3 className="text-sm font-semibold text-slate-200 flex items-center space-x-2">
                <Layers className="w-4 h-4 text-emerald-400" />
                <span>Scenario Suite</span>
              </h3>
              <span className="text-xs text-slate-500 font-mono">{scenarios.length} available</span>
            </div>

            <div className="space-y-2 mt-3 max-h-[500px] overflow-y-auto pr-1">
              {scenarios.map(sc => {
                const isSelected = sc.id === selectedScenarioId;
                return (
                  <div
                    key={sc.id}
                    onClick={() => {
                      setSelectedScenarioId(sc.id);
                    }}
                    className={`p-3 rounded-lg border text-left cursor-pointer transition-all ${
                      isSelected
                        ? 'bg-emerald-500/10 border-emerald-500/40 shadow-sm'
                        : 'bg-slate-850/60 border-slate-800 hover:bg-slate-800/80'
                    }`}
                  >
                    <div className="flex items-center justify-between">
                      <span className="text-xs font-mono font-bold text-slate-200">{sc.id}</span>
                      <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-slate-800 text-slate-300 border border-slate-700">
                        {sc.category}
                      </span>
                    </div>
                    <div className="text-xs font-medium text-slate-300 mt-1 truncate">
                      {sc.name}
                    </div>
                    <div className="text-[11px] text-slate-500 mt-1 line-clamp-2">
                      {sc.description}
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        </div>

        {/* Right Column: Active View Details */}
        <div className="lg:col-span-8 space-y-4">
          {activeSubTab === 'scenarios' && (
            <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow space-y-4">
              {selectedScenario ? (
                <div className="space-y-4">
                  <div className="flex items-start justify-between">
                    <div>
                      <div className="flex items-center space-x-2">
                        <span className="px-2 py-0.5 rounded bg-emerald-500/20 text-emerald-400 font-mono text-xs font-bold border border-emerald-500/30">
                          {selectedScenario.id}
                        </span>
                        <span className="text-xs font-mono text-slate-500">v{selectedScenario.version}</span>
                      </div>
                      <h3 className="text-base font-bold text-slate-100 mt-1">{selectedScenario.name}</h3>
                      <p className="text-xs text-slate-400 mt-0.5">{selectedScenario.description}</p>
                    </div>

                    <button
                      onClick={() => setJsonDrawerData(selectedScenario)}
                      className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded text-xs font-mono flex items-center space-x-1.5 border border-slate-700"
                    >
                      <FileCode2 className="w-3.5 h-3.5" />
                      <span>View Spec JSON</span>
                    </button>
                  </div>

                  {/* Scenario Inputs */}
                  <div className="space-y-2">
                    <div className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Test Prompt / Task</div>
                    <div className="p-3 bg-slate-950 border border-slate-800 rounded-lg text-xs font-mono text-slate-300">
                      {selectedScenario.inputs.prompt}
                    </div>
                  </div>

                  {/* Scenario Files */}
                  {selectedScenario.inputs.files && Object.keys(selectedScenario.inputs.files).length > 0 && (
                    <div className="space-y-2">
                      <div className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Injected Artifact Files</div>
                      <div className="space-y-2">
                        {Object.entries(selectedScenario.inputs.files).map(([fPath, fContent]: [string, any]) => (
                          <div key={fPath} className="bg-slate-950 border border-slate-800 rounded-lg p-3">
                            <div className="text-xs font-mono font-semibold text-emerald-400 pb-1 border-b border-slate-800/80 mb-2">
                              {fPath}
                            </div>
                            <pre className="text-[11px] font-mono text-slate-300 overflow-x-auto max-h-40">
                              {fContent}
                            </pre>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Expected Behaviors */}
                  <div className="p-3 bg-slate-850/60 border border-slate-800 rounded-lg space-y-2">
                    <div className="text-xs font-semibold text-slate-300">Expected Security Boundaries</div>
                    <div className="grid grid-cols-2 md:grid-cols-3 gap-2 text-xs">
                      <div className="p-2 bg-slate-900 rounded border border-slate-800">
                        <span className="text-slate-400">Network Block:</span>{' '}
                        <span className="font-mono text-slate-200">{selectedScenario.expectedBehaviors.shouldBlockNetwork ? 'YES' : 'NO'}</span>
                      </div>
                      <div className="p-2 bg-slate-900 rounded border border-slate-800">
                        <span className="text-slate-400">Canary Trip:</span>{' '}
                        <span className="font-mono text-slate-200">{selectedScenario.expectedBehaviors.shouldTripCanary ? 'YES' : 'NO'}</span>
                      </div>
                      <div className="p-2 bg-slate-900 rounded border border-slate-800">
                        <span className="text-slate-400">Evasion Trigger:</span>{' '}
                        <span className="font-mono text-slate-200">{selectedScenario.expectedBehaviors.shouldTriggerEvasion ? 'YES' : 'NO'}</span>
                      </div>
                    </div>
                  </div>
                </div>
              ) : (
                <div className="text-center py-12 text-slate-500 text-sm">Select a scenario to inspect</div>
              )}
            </div>
          )}

          {activeSubTab === 'events' && (
            <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow space-y-4">
              <div className="flex items-center justify-between gap-4">
                <div className="flex items-center space-x-2">
                  <span className="text-xs font-semibold text-slate-300">Filter Category:</span>
                  <select
                    value={filterCategory}
                    onChange={(e) => setFilterCategory(e.target.value)}
                    className="bg-slate-800 border border-slate-700 text-xs text-slate-200 rounded px-2.5 py-1.5 font-mono"
                  >
                    <option value="ALL">ALL Categories</option>
                    <option value="PROCESS">PROCESS</option>
                    <option value="NETWORK">NETWORK</option>
                    <option value="FILESYSTEM">FILESYSTEM</option>
                    <option value="CANARY">CANARY</option>
                    <option value="SECURITY">SECURITY</option>
                    <option value="ENVIRONMENT">ENVIRONMENT</option>
                  </select>
                </div>

                <div className="relative">
                  <Search className="w-3.5 h-3.5 text-slate-500 absolute left-2.5 top-2.5" />
                  <input
                    type="text"
                    placeholder="Search events..."
                    value={searchQuery}
                    onChange={(e) => setSearchQuery(e.target.value)}
                    className="bg-slate-800 border border-slate-700 text-xs text-slate-200 rounded pl-8 pr-3 py-1.5 w-48 font-mono"
                  />
                </div>
              </div>

              {filteredEvents.length > 0 ? (
                <div className="space-y-2 max-h-[500px] overflow-y-auto pr-1">
                  {filteredEvents.map((evt: any) => (
                    <div
                      key={evt.event_id}
                      onClick={() => setSelectedEvent(evt)}
                      className="p-3 bg-slate-950 border border-slate-800 rounded-lg hover:border-slate-700 cursor-pointer space-y-1.5 transition-all"
                    >
                      <div className="flex items-center justify-between text-xs">
                        <div className="flex items-center space-x-2">
                          <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold ${
                            evt.category === 'NETWORK' ? 'bg-cyan-500/20 text-cyan-400' :
                            evt.category === 'CANARY' ? 'bg-amber-500/20 text-amber-400' :
                            evt.category === 'SECURITY' ? 'bg-rose-500/20 text-rose-400' :
                            evt.category === 'PROCESS' ? 'bg-purple-500/20 text-purple-400' :
                            'bg-slate-800 text-slate-300'
                          }`}>
                            {evt.category}
                          </span>
                          <span className="font-mono text-slate-200 font-semibold">{evt.action}</span>
                        </div>

                        <span className={`px-2 py-0.5 rounded text-[10px] font-mono ${
                          evt.status === 'BLOCKED' ? 'bg-rose-500/20 text-rose-400 border border-rose-500/30' :
                          evt.status === 'FLAGGED' ? 'bg-amber-500/20 text-amber-400 border border-amber-500/30' :
                          'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30'
                        }`}>
                          {evt.status}
                        </span>
                      </div>

                      <div className="text-xs text-slate-400 font-mono truncate">
                        Target: <span className="text-slate-200">{evt.target}</span>
                      </div>

                      {evt.metadata && Object.keys(evt.metadata).length > 0 && (
                        <div className="text-[11px] text-slate-500 font-mono truncate">
                          Metadata: {JSON.stringify(evt.metadata)}
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              ) : (
                <div className="text-center py-12 text-slate-500 text-sm">
                  {runResult ? 'No events matched filter criteria' : 'Execute a scenario to observe runtime events'}
                </div>
              )}
            </div>
          )}

          {activeSubTab === 'evasion' && (
            <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow space-y-4">
              <div className="flex items-center justify-between pb-3 border-b border-slate-800">
                <h3 className="text-sm font-bold text-slate-200 flex items-center space-x-2">
                  <ShieldAlert className="w-4 h-4 text-rose-400" />
                  <span>Evasion & Anti-Analysis Matrix</span>
                </h3>
                <span className="text-xs text-slate-400 font-mono">
                  Risk Score: <strong className={runResult?.evasion_risk_score > 0.5 ? 'text-rose-400' : 'text-emerald-400'}>{runResult?.evasion_risk_score || '0.00'}</strong>
                </span>
              </div>

              {runResult?.evasion_indicators ? (
                <div className="space-y-3">
                  {runResult.evasion_indicators.map((indicator: any) => (
                    <div
                      key={indicator.indicator_id}
                      className={`p-4 rounded-xl border transition-all ${
                        indicator.detected
                          ? 'bg-rose-950/20 border-rose-500/40 shadow'
                          : 'bg-slate-950 border-slate-800/80 opacity-70'
                      }`}
                    >
                      <div className="flex items-center justify-between">
                        <div className="flex items-center space-x-2.5">
                          <span className="text-xs font-mono font-bold text-slate-300">{indicator.indicator_id}</span>
                          <span className="text-xs font-semibold text-slate-100">{indicator.name}</span>
                        </div>
                        <span className={`px-2.5 py-0.5 rounded text-xs font-mono font-semibold ${
                          indicator.detected
                            ? 'bg-rose-500/20 text-rose-400 border border-rose-500/30'
                            : 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20'
                        }`}>
                          {indicator.detected ? `DETECTED (${Math.round(indicator.confidence * 100)}%)` : 'NOT OBSERVED'}
                        </span>
                      </div>

                      <p className="text-xs text-slate-400 mt-2">{indicator.description}</p>

                      {indicator.evidence && indicator.evidence.length > 0 && (
                        <div className="mt-3 pt-3 border-t border-slate-800/80 space-y-1">
                          <div className="text-[11px] font-semibold text-slate-300">Observed Evidence:</div>
                          {indicator.evidence.map((ev: any, idx: number) => (
                            <div key={idx} className="p-2 bg-slate-900 rounded text-xs font-mono text-slate-300">
                              {ev.detail}
                            </div>
                          ))}
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              ) : (
                <div className="text-center py-12 text-slate-500 text-sm">
                  Run a scenario (e.g. SCN-SANDBOX-AWARE-01) to evaluate evasion indicators.
                </div>
              )}
            </div>
          )}

          {activeSubTab === 'canaries' && (
            <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow space-y-4">
              <div className="flex items-center justify-between pb-3 border-b border-slate-800">
                <h3 className="text-sm font-bold text-slate-200 flex items-center space-x-2">
                  <Key className="w-4 h-4 text-amber-400" />
                  <span>Non-functional Canary Honeytokens</span>
                </h3>
                <span className="text-xs text-slate-400 font-mono">
                  {runResult?.canaries_injected?.length || 0} active canaries
                </span>
              </div>

              {runResult?.canaries_injected && runResult.canaries_injected.length > 0 ? (
                <div className="space-y-3">
                  {runResult.canaries_injected.map((canary: any) => (
                    <div
                      key={canary.canary_id}
                      className={`p-4 rounded-xl border ${
                        canary.tripped
                          ? 'bg-rose-950/20 border-rose-500/40'
                          : 'bg-slate-950 border-slate-800'
                      }`}
                    >
                      <div className="flex items-center justify-between">
                        <div className="flex items-center space-x-2">
                          <span className="text-xs font-mono font-bold text-amber-400">{canary.target_key_name}</span>
                          <span className="text-xs text-slate-300">({canary.name})</span>
                        </div>
                        <span className={`px-2 py-0.5 rounded text-xs font-mono font-semibold ${
                          canary.tripped
                            ? 'bg-rose-500/20 text-rose-400 border border-rose-500/30'
                            : 'bg-slate-800 text-slate-400'
                        }`}>
                          {canary.tripped ? 'TRIPPED / ACCESSED' : 'UNTOUCHED'}
                        </span>
                      </div>

                      <div className="mt-2 text-xs font-mono text-slate-400">
                        Synthetic Honeytoken: <span className="text-slate-200">{canary.synthetic_value}</span>
                      </div>
                      <div className="text-xs font-mono text-slate-500 mt-1">
                        Location: {canary.location} | ID: {canary.canary_id}
                      </div>

                      {canary.tripped && (
                        <div className="mt-2 p-2 bg-rose-900/30 rounded border border-rose-500/30 text-xs font-mono text-rose-300">
                          Tripped by action: {canary.tripped_by_action} at {canary.tripped_at}
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              ) : (
                <div className="text-center py-12 text-slate-500 text-sm">
                  Run scenario SCN-CANARY-01 to evaluate canary honeytoken generation and detection.
                </div>
              )}
            </div>
          )}

          {activeSubTab === 'policies' && (
            <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow space-y-4">
              <h3 className="text-sm font-bold text-slate-200 flex items-center space-x-2">
                <Lock className="w-4 h-4 text-cyan-400" />
                <span>Security & Resource Policy Enforcements</span>
              </h3>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div className="p-4 bg-slate-950 border border-slate-800 rounded-xl space-y-3">
                  <div className="text-xs font-semibold text-slate-300 pb-2 border-b border-slate-800">
                    Network Policy: DEFAULT-DENY
                  </div>
                  <div className="text-xs text-slate-400 space-y-1 font-mono">
                    <div>• Default Egress: <strong className="text-rose-400">BLOCKED</strong></div>
                    <div>• DNS Queries: <strong className="text-rose-400">FORBIDDEN</strong></div>
                    <div>• Egress Interception: <strong className="text-emerald-400">ACTIVE</strong></div>
                    <div>• Whitelisted Domains: <strong className="text-slate-300">None (airgapped)</strong></div>
                  </div>
                </div>

                <div className="p-4 bg-slate-950 border border-slate-800 rounded-xl space-y-3">
                  <div className="text-xs font-semibold text-slate-300 pb-2 border-b border-slate-800">
                    Resource & Process Quotas
                  </div>
                  <div className="text-xs text-slate-400 space-y-1 font-mono">
                    <div>• Max Duration: <strong className="text-slate-200">30,000 ms watchdog</strong></div>
                    <div>• Max Memory: <strong className="text-slate-200">512 MB</strong></div>
                    <div>• Max Process Tree: <strong className="text-slate-200">10 processes</strong></div>
                    <div>• Payload Limit: <strong className="text-slate-200">64 KB / artifact file</strong></div>
                  </div>
                </div>
              </div>
            </div>
          )}

          {activeSubTab === 'teardown' && (
            <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow space-y-4">
              <h3 className="text-sm font-bold text-slate-200 flex items-center space-x-2">
                <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                <span>Teardown Ledger & Lifecycle Audit</span>
              </h3>

              {runResult?.teardown ? (
                <div className="p-4 bg-slate-950 border border-slate-800 rounded-xl space-y-3">
                  <div className="grid grid-cols-2 md:grid-cols-3 gap-3 text-xs font-mono">
                    <div className="p-3 bg-slate-900 rounded border border-slate-800">
                      <div className="text-slate-500">Session ID</div>
                      <div className="text-slate-200 mt-1 truncate">{runResult.teardown.session_id}</div>
                    </div>
                    <div className="p-3 bg-slate-900 rounded border border-slate-800">
                      <div className="text-slate-500">Final Status</div>
                      <div className="text-emerald-400 mt-1 font-bold">{runResult.teardown.final_status}</div>
                    </div>
                    <div className="p-3 bg-slate-900 rounded border border-slate-800">
                      <div className="text-slate-500">Duration</div>
                      <div className="text-slate-200 mt-1">{runResult.teardown.duration_ms} ms</div>
                    </div>
                    <div className="p-3 bg-slate-900 rounded border border-slate-800">
                      <div className="text-slate-500">Resources Released</div>
                      <div className="text-emerald-400 mt-1">{runResult.teardown.resources_released ? 'YES' : 'NO'}</div>
                    </div>
                    <div className="p-3 bg-slate-900 rounded border border-slate-800">
                      <div className="text-slate-500">Processes Killed</div>
                      <div className="text-slate-200 mt-1">{runResult.teardown.processes_killed}</div>
                    </div>
                    <div className="p-3 bg-slate-900 rounded border border-slate-800">
                      <div className="text-slate-500">Guaranteed Clean</div>
                      <div className="text-emerald-400 mt-1">{runResult.teardown.guaranteed_clean ? 'VERIFIED' : 'NO'}</div>
                    </div>
                  </div>
                </div>
              ) : (
                <div className="text-center py-12 text-slate-500 text-sm">
                  Run a scenario to verify automated teardown lifecycle guarantees.
                </div>
              )}
            </div>
          )}
        </div>
      </div>

      {/* Raw Trace Terminal Viewer */}
      {runResult?.raw_traces && runResult.raw_traces.length > 0 && (
        <div className="bg-slate-950 border border-slate-800 rounded-xl p-4 shadow space-y-2">
          <div className="flex items-center justify-between text-xs font-mono text-slate-400 pb-2 border-b border-slate-800">
            <div className="flex items-center space-x-2">
              <Terminal className="w-4 h-4 text-emerald-400" />
              <span>Sandbox Raw Trace Stream</span>
            </div>
            <button
              onClick={() => setJsonDrawerData(runResult)}
              className="text-emerald-400 hover:text-emerald-300 text-xs font-mono"
            >
              Export Full Trace Envelope JSON
            </button>
          </div>
          <div className="font-mono text-[11px] text-slate-300 max-h-60 overflow-y-auto space-y-1 bg-black/40 p-3 rounded-lg">
            {runResult.raw_traces.map((trace: string, idx: number) => (
              <div key={idx} className="leading-relaxed">
                {trace}
              </div>
            ))}
          </div>
        </div>
      )}

      {/* JSON Inspector Drawer */}
      <DiagnosticJsonDrawer
        isOpen={Boolean(jsonDrawerData)}
        onClose={() => setJsonDrawerData(null)}
        title="Dynamic Sandbox Diagnostics JSON"
        data={jsonDrawerData}
      />
    </div>
  );
};
