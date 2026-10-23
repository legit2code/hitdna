/**
 * Diagnostic Composition, SBOM/AI-BOM, Vulnerability & Reachability View
 * P17 — Dependency, SBOM/AI-BOM, Vulnerability & Reachability
 */

import React, { useState, useEffect } from 'react';
import { 
  Package, 
  Layers, 
  ShieldAlert, 
  ShieldCheck, 
  FileCode2, 
  Sparkles, 
  Cpu, 
  Radio, 
  Play, 
  RefreshCw, 
  CheckCircle2, 
  AlertTriangle, 
  ChevronRight, 
  Network, 
  Search, 
  ExternalLink,
  Code2,
  FileCheck,
  Zap,
  Info
} from 'lucide-react';
import { DiagnosticJsonDrawer } from './DiagnosticJsonDrawer.tsx';

export interface DiagnosticCompositionViewProps {
  currentRole?: string;
}

export const DiagnosticCompositionView: React.FC<DiagnosticCompositionViewProps> = ({ currentRole = 'operator' }) => {
  const [activeSubTab, setActiveSubTab] = useState<'reachability' | 'sbom' | 'aibom' | 'graph' | 'compliance' | 'advisories'>('reachability');
  const [loading, setLoading] = useState<boolean>(false);
  const [fixtures, setFixtures] = useState<any[]>([]);
  const [selectedFixtureId, setSelectedFixtureId] = useState<string>('SCENARIO-01-PRESENT-VS-REACHABLE');
  const [report, setReport] = useState<any | null>(null);
  const [selectedTrace, setSelectedTrace] = useState<any | null>(null);
  const [filterReachabilityStatus, setFilterReachabilityStatus] = useState<string>('ALL');
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [jsonDrawerData, setJsonDrawerData] = useState<any | null>(null);
  const [editorFiles, setEditorFiles] = useState<Array<{ path: string; content: string }>>([]);
  const [selectedFileIdx, setSelectedFileIdx] = useState<number>(0);

  useEffect(() => {
    fetchFixtures();
  }, []);

  const fetchFixtures = async () => {
    try {
      const res = await fetch('/api/dev/composition/fixtures', {
        headers: { 'X-Role': currentRole }
      });
      if (res.ok) {
        const data = await res.json();
        setFixtures(data);
        if (data.length > 0) {
          loadFixture(data[0]);
        }
      }
    } catch {
      // ignore
    }
  };

  const loadFixture = (fixture: any) => {
    setSelectedFixtureId(fixture.id);
    const filesArray = Object.entries(fixture.files).map(([path, content]) => ({
      path,
      content: String(content)
    }));
    setEditorFiles(filesArray);
    setSelectedFileIdx(0);
    runAnalysis(filesArray);
  };

  const runAnalysis = async (filesToAnalyze = editorFiles) => {
    setLoading(true);
    try {
      const filesObj: Record<string, string> = {};
      for (const f of filesToAnalyze) {
        filesObj[f.path] = f.content;
      }

      const res = await fetch('/api/dev/composition/analyze', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Role': currentRole,
        },
        body: JSON.stringify({
          artifactId: `art-${selectedFixtureId}`,
          files: filesObj,
        })
      });

      if (res.ok) {
        const data = await res.json();
        setReport(data);
        if (data.reachability_results?.length > 0) {
          setSelectedTrace(data.reachability_results[0]);
        } else {
          setSelectedTrace(null);
        }
      }
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  const filteredTraces = (report?.reachability_results || []).filter((trace: any) => {
    if (filterReachabilityStatus !== 'ALL' && trace.status !== filterReachabilityStatus) {
      return false;
    }
    if (searchQuery) {
      const q = searchQuery.toLowerCase();
      return trace.package_name.toLowerCase().includes(q) || trace.vulnerability_id.toLowerCase().includes(q);
    }
    return true;
  });

  return (
    <div className="space-y-6">
      {/* Top Banner & Control Bar */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 shadow-md">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
          <div className="flex items-center space-x-3">
            <div className="p-2.5 rounded-lg bg-cyan-500/10 border border-cyan-500/20 text-cyan-400">
              <Package className="w-5 h-5" />
            </div>
            <div>
              <div className="flex items-center space-x-2">
                <h2 className="text-sm font-bold text-slate-100 font-mono">P17 Composition & Reachability Console</h2>
                <span className="text-[10px] px-2 py-0.5 rounded bg-cyan-500/20 text-cyan-300 font-mono">
                  E29–E35 Engines
                </span>
                <span className="text-[10px] px-2 py-0.5 rounded bg-emerald-500/20 text-emerald-300 font-mono">
                  CycloneDX 1.5
                </span>
              </div>
              <p className="text-xs text-slate-400 font-mono mt-0.5">
                Strict separation of Dependency Presence vs Static/Dynamic Vulnerability Reachability
              </p>
            </div>
          </div>

          <div className="flex flex-wrap items-center gap-2">
            {/* Fixture Selector */}
            <div className="flex items-center space-x-2 bg-slate-950 px-3 py-1.5 rounded-lg border border-slate-800 text-xs font-mono">
              <span className="text-slate-400">Scenario:</span>
              <select
                value={selectedFixtureId}
                onChange={(e) => {
                  const target = fixtures.find(f => f.id === e.target.value);
                  if (target) loadFixture(target);
                }}
                className="bg-transparent text-cyan-300 focus:outline-none cursor-pointer text-xs"
              >
                {fixtures.map(f => (
                  <option key={f.id} value={f.id} className="bg-slate-900 text-slate-200">
                    {f.name}
                  </option>
                ))}
              </select>
            </div>

            <button
              onClick={() => runAnalysis()}
              disabled={loading}
              className="flex items-center space-x-1.5 px-3.5 py-1.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white font-mono text-xs font-semibold shadow transition-all disabled:opacity-50"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
              <span>{loading ? 'Analyzing...' : 'Run Pipeline'}</span>
            </button>
          </div>
        </div>

        {/* Live Metrics Grid */}
        {report && (
          <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-7 gap-2.5 mt-4 pt-4 border-t border-slate-800/80">
            <div className="bg-slate-950/60 p-2.5 rounded-lg border border-slate-800/60">
              <div className="text-[10px] text-slate-400 font-mono uppercase">Total Components</div>
              <div className="text-lg font-bold text-slate-200 font-mono">{report.metrics.total_dependencies}</div>
              <div className="text-[10px] text-slate-400 font-mono">{report.metrics.direct_dependencies_count} direct • {report.metrics.transitive_dependencies_count} trans</div>
            </div>

            <div className="bg-amber-950/20 p-2.5 rounded-lg border border-amber-500/20">
              <div className="text-[10px] text-amber-400 font-mono uppercase">Vuln Present</div>
              <div className="text-lg font-bold text-amber-300 font-mono">{report.metrics.vulnerabilities_present_count}</div>
              <div className="text-[10px] text-amber-400/70 font-mono">Installed / Unreached</div>
            </div>

            <div className="bg-rose-950/30 p-2.5 rounded-lg border border-rose-500/30">
              <div className="text-[10px] text-rose-400 font-mono uppercase">Vuln Reachable</div>
              <div className="text-lg font-bold text-rose-300 font-mono">{report.metrics.vulnerabilities_reachable_count}</div>
              <div className="text-[10px] text-rose-400/80 font-mono">Confirmed in Callflow</div>
            </div>

            <div className="bg-indigo-950/20 p-2.5 rounded-lg border border-indigo-500/20">
              <div className="text-[10px] text-indigo-400 font-mono uppercase">AI Models (BOM)</div>
              <div className="text-lg font-bold text-indigo-300 font-mono">{report.metrics.ai_models_count}</div>
              <div className="text-[10px] text-indigo-400/70 font-mono">{report.aibom.total_frameworks} Frameworks</div>
            </div>

            <div className="bg-purple-950/20 p-2.5 rounded-lg border border-purple-500/20">
              <div className="text-[10px] text-purple-400 font-mono uppercase">Prompt Templates</div>
              <div className="text-lg font-bold text-purple-300 font-mono">{report.aibom.prompt_templates.length}</div>
              <div className="text-[10px] text-purple-400/70 font-mono">System & User</div>
            </div>

            <div className="bg-slate-950/60 p-2.5 rounded-lg border border-slate-800/60">
              <div className="text-[10px] text-slate-400 font-mono uppercase">Ecosystem</div>
              <div className="text-sm font-bold text-cyan-300 font-mono uppercase mt-1">{report.primary_ecosystem}</div>
              <div className="text-[10px] text-slate-400 font-mono">{report.dependency_graph.root_name}</div>
            </div>

            <div className="bg-slate-950/60 p-2.5 rounded-lg border border-slate-800/60">
              <div className="text-[10px] text-slate-400 font-mono uppercase">SBOM State</div>
              <div className="text-sm font-bold text-emerald-400 font-mono flex items-center space-x-1 mt-1">
                <CheckCircle2 className="w-3.5 h-3.5" />
                <span>Deterministic</span>
              </div>
              <div className="text-[10px] text-slate-400 font-mono">CycloneDX 1.5 JSON</div>
            </div>
          </div>
        )}
      </div>

      {/* Sub-Navigation Tabs */}
      <div className="flex items-center space-x-2 border-b border-slate-800 pb-2 text-xs font-mono">
        <button
          onClick={() => setActiveSubTab('reachability')}
          className={`flex items-center space-x-1.5 px-3 py-1.5 rounded-lg font-semibold transition-all ${
            activeSubTab === 'reachability'
              ? 'bg-cyan-600 text-white shadow'
              : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
          }`}
        >
          <ShieldAlert className="w-3.5 h-3.5" />
          <span>Reachability Analysis ({report?.reachability_results?.length || 0})</span>
        </button>

        <button
          onClick={() => setActiveSubTab('sbom')}
          className={`flex items-center space-x-1.5 px-3 py-1.5 rounded-lg font-semibold transition-all ${
            activeSubTab === 'sbom'
              ? 'bg-cyan-600 text-white shadow'
              : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
          }`}
        >
          <FileCheck className="w-3.5 h-3.5" />
          <span>CycloneDX SBOM ({report?.sbom?.components?.length || 0})</span>
        </button>

        <button
          onClick={() => setActiveSubTab('aibom')}
          className={`flex items-center space-x-1.5 px-3 py-1.5 rounded-lg font-semibold transition-all ${
            activeSubTab === 'aibom'
              ? 'bg-cyan-600 text-white shadow'
              : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
          }`}
        >
          <Sparkles className="w-3.5 h-3.5" />
          <span>AI-BOM Inventory ({report?.aibom?.total_models || 0})</span>
        </button>

        <button
          onClick={() => setActiveSubTab('graph')}
          className={`flex items-center space-x-1.5 px-3 py-1.5 rounded-lg font-semibold transition-all ${
            activeSubTab === 'graph'
              ? 'bg-cyan-600 text-white shadow'
              : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
          }`}
        >
          <Network className="w-3.5 h-3.5" />
          <span>Dependency Graph</span>
        </button>

        <button
          onClick={() => setActiveSubTab('compliance')}
          className={`flex items-center space-x-1.5 px-3 py-1.5 rounded-lg font-semibold transition-all ${
            activeSubTab === 'compliance'
              ? 'bg-cyan-600 text-white shadow'
              : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
          }`}
        >
          <ShieldCheck className="w-3.5 h-3.5" />
          <span>License & Supply Risk ({report?.malicious_package_risks?.length || 0})</span>
        </button>
      </div>

      {/* Main Tab Content */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left Column: List / Explorer (7 Cols) */}
        <div className="lg:col-span-7 space-y-4">
          {activeSubTab === 'reachability' && (
            <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 space-y-4 shadow-sm">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                <div className="flex items-center space-x-2">
                  <span className="text-xs font-mono text-slate-300 font-bold">Reachability Status Filter:</span>
                  <select
                    value={filterReachabilityStatus}
                    onChange={(e) => setFilterReachabilityStatus(e.target.value)}
                    className="bg-slate-950 border border-slate-800 rounded px-2.5 py-1 text-xs font-mono text-cyan-300 focus:outline-none"
                  >
                    <option value="ALL">ALL STATUSES ({report?.reachability_results?.length || 0})</option>
                    <option value="VULNERABILITY_REACHABLE">REACHABLE ONLY</option>
                    <option value="VULNERABLE_PRESENT">PRESENT ONLY</option>
                    <option value="PRESENT_UNREACHED">PRESENT UNREACHED</option>
                    <option value="DYNAMICALLY_CONFIRMED_REACHABLE">DYNAMICALLY CONFIRMED</option>
                  </select>
                </div>

                <div className="relative flex-1 max-w-xs">
                  <Search className="w-3.5 h-3.5 absolute left-2.5 top-2.5 text-slate-400" />
                  <input
                    type="text"
                    placeholder="Search package or CVE..."
                    value={searchQuery}
                    onChange={(e) => setSearchQuery(e.target.value)}
                    className="w-full bg-slate-950 border border-slate-800 rounded-lg pl-8 pr-3 py-1 text-xs font-mono text-slate-200 placeholder-slate-400 focus:outline-none"
                  />
                </div>
              </div>

              {/* Table of Reachability Findings */}
              <div className="space-y-2 max-h-[500px] overflow-y-auto pr-1">
                {filteredTraces.length === 0 ? (
                  <div className="p-8 text-center border border-dashed border-slate-800 rounded-lg font-mono text-xs text-slate-400">
                    No reachability findings matching current criteria.
                  </div>
                ) : (
                  filteredTraces.map((trace: any, idx: number) => {
                    const isSelected = selectedTrace?.vulnerability_id === trace.vulnerability_id && selectedTrace?.package_name === trace.package_name;
                    const isReachable = trace.status === 'VULNERABILITY_REACHABLE' || trace.status === 'DYNAMICALLY_CONFIRMED_REACHABLE';

                    return (
                      <div
                        key={`${trace.vulnerability_id}-${trace.package_name}-${idx}`}
                        onClick={() => setSelectedTrace(trace)}
                        className={`p-3.5 rounded-lg border transition-all cursor-pointer font-mono text-xs ${
                          isSelected
                            ? 'bg-slate-800/90 border-cyan-500 ring-1 ring-cyan-500'
                            : 'bg-slate-950/70 border-slate-800 hover:border-slate-700 hover:bg-slate-900/60'
                        }`}
                      >
                        <div className="flex items-start justify-between gap-2">
                          <div className="space-y-1">
                            <div className="flex items-center space-x-2">
                              <span className="font-bold text-slate-100">{trace.package_name}</span>
                              <span className="text-[10px] text-slate-400">@{trace.installed_version}</span>
                              <span className={`text-[10px] px-2 py-0.5 rounded font-bold ${
                                isReachable
                                  ? 'bg-rose-500/20 text-rose-300 border border-rose-500/30'
                                  : 'bg-amber-500/20 text-amber-300 border border-amber-500/30'
                              }`}>
                                {trace.status}
                              </span>
                              {trace.runtime_confirmed && (
                                <span className="text-[10px] px-1.5 py-0.5 rounded bg-purple-500/20 text-purple-300 border border-purple-500/30">
                                  DYNAMIC
                                </span>
                              )}
                            </div>
                            <div className="text-[11px] text-cyan-400">{trace.vulnerability_id}</div>
                            <p className="text-[11px] text-slate-400 line-clamp-2 leading-relaxed">
                              {trace.evidence_description}
                            </p>
                          </div>

                          <div className="text-right space-y-1">
                            <div className="text-[10px] text-slate-400">Confidence</div>
                            <div className="text-xs font-bold text-emerald-400">{(trace.confidence * 100).toFixed(0)}%</div>
                          </div>
                        </div>

                        {/* Call path preview if reachable */}
                        {isReachable && trace.reachability_path?.length > 0 && (
                          <div className="mt-2.5 pt-2 border-t border-slate-800/80 flex items-center space-x-1.5 text-[10px] text-rose-300/90 overflow-x-auto">
                            <span className="text-slate-400">Call Path:</span>
                            {trace.reachability_path.map((step: string, sIdx: number) => (
                              <React.Fragment key={sIdx}>
                                <span className="px-1.5 py-0.5 rounded bg-rose-950/60 border border-rose-500/20 whitespace-nowrap">
                                  {step}
                                </span>
                                {sIdx < trace.reachability_path.length - 1 && (
                                  <ChevronRight className="w-3 h-3 text-slate-400 shrink-0" />
                                )}
                              </React.Fragment>
                            ))}
                          </div>
                        )}
                      </div>
                    );
                  })
                )}
              </div>
            </div>
          )}

          {activeSubTab === 'sbom' && (
            <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 space-y-4 shadow-sm">
              <div className="flex items-center justify-between">
                <div>
                  <h3 className="text-xs font-bold font-mono text-slate-200 uppercase tracking-wider">
                    CycloneDX 1.5 Components Table
                  </h3>
                  <p className="text-[11px] text-slate-400 font-mono mt-0.5">
                    Deterministic component enumeration with PURL and license attributes
                  </p>
                </div>
                <button
                  onClick={() => setJsonDrawerData(report?.sbom)}
                  className="flex items-center space-x-1 px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-cyan-300 text-xs font-mono"
                >
                  <Code2 className="w-3.5 h-3.5" />
                  <span>View Raw CycloneDX JSON</span>
                </button>
              </div>

              <div className="space-y-2 max-h-[500px] overflow-y-auto">
                {(report?.sbom?.components || []).map((comp: any, idx: number) => (
                  <div key={idx} className="p-3 bg-slate-950/70 border border-slate-800 rounded-lg font-mono text-xs flex items-center justify-between">
                    <div className="space-y-0.5">
                      <div className="flex items-center space-x-2">
                        <span className="font-bold text-slate-200">{comp.name}</span>
                        <span className="text-slate-400">@{comp.version}</span>
                        <span className="text-[10px] px-1.5 py-0.2 rounded bg-slate-800 text-slate-300">
                          {comp.type}
                        </span>
                      </div>
                      <div className="text-[10px] text-cyan-400 truncate max-w-md">{comp.purl}</div>
                    </div>
                    <div className="text-right text-[10px] text-slate-400">
                      <div>Scope: <span className="text-slate-200">{comp.scope || 'required'}</span></div>
                      <div>License: <span className="text-emerald-400">{comp.licenses?.[0]?.license?.name || 'N/A'}</span></div>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {activeSubTab === 'aibom' && (
            <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 space-y-4 shadow-sm">
              <div>
                <h3 className="text-xs font-bold font-mono text-slate-200 uppercase tracking-wider">
                  AI-BOM Inventory & Model Cards
                </h3>
                <p className="text-[11px] text-slate-400 font-mono mt-0.5">
                  AI/ML models, foundational provider endpoints, frameworks, and system prompts
                </p>
              </div>

              {/* Models Section */}
              <div className="space-y-3">
                <div className="text-xs font-bold text-cyan-400 font-mono flex items-center space-x-1.5">
                  <Cpu className="w-3.5 h-3.5" />
                  <span>Detected AI Models & Architectures ({report?.aibom?.models?.length || 0})</span>
                </div>

                <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5">
                  {(report?.aibom?.models || []).map((model: any, idx: number) => (
                    <div key={idx} className="p-3 bg-slate-950/70 border border-slate-800 rounded-lg font-mono text-xs space-y-1">
                      <div className="flex items-center justify-between">
                        <span className="font-bold text-slate-100">{model.name}</span>
                        <span className="text-[10px] px-1.5 py-0.5 rounded bg-indigo-500/20 text-indigo-300 uppercase">
                          {model.provider}
                        </span>
                      </div>
                      <div className="text-[10px] text-slate-400">Family: <span className="text-slate-200">{model.family || 'Custom'}</span></div>
                      <div className="text-[10px] text-slate-400">Task: <span className="text-slate-200">{model.task_type || 'chat'}</span></div>
                      <div className="text-[10px] text-slate-400 truncate">Source: <span className="text-cyan-300">{model.source_file}</span></div>
                    </div>
                  ))}
                </div>
              </div>

              {/* Frameworks Section */}
              <div className="space-y-3 pt-3 border-t border-slate-800">
                <div className="text-xs font-bold text-purple-400 font-mono flex items-center space-x-1.5">
                  <Sparkles className="w-3.5 h-3.5" />
                  <span>AI Agent Frameworks ({report?.aibom?.frameworks?.length || 0})</span>
                </div>

                <div className="flex flex-wrap gap-2">
                  {(report?.aibom?.frameworks || []).map((fw: any, idx: number) => (
                    <div key={idx} className="px-3 py-1.5 bg-slate-950/70 border border-slate-800 rounded-lg font-mono text-xs flex items-center space-x-2">
                      <span className="font-bold text-purple-300 uppercase">{fw.name}</span>
                      <span className="text-[10px] text-slate-400">@{fw.version || 'in-tree'}</span>
                    </div>
                  ))}
                </div>
              </div>

              {/* Prompt Templates Section */}
              <div className="space-y-3 pt-3 border-t border-slate-800">
                <div className="text-xs font-bold text-emerald-400 font-mono flex items-center space-x-1.5">
                  <FileCode2 className="w-3.5 h-3.5" />
                  <span>System Prompts & Templates ({report?.aibom?.prompt_templates?.length || 0})</span>
                </div>

                <div className="space-y-2">
                  {(report?.aibom?.prompt_templates || []).map((tmpl: any, idx: number) => (
                    <div key={idx} className="p-2.5 bg-slate-950/70 border border-slate-800 rounded-lg font-mono text-xs space-y-1">
                      <div className="flex items-center justify-between text-[11px]">
                        <span className="text-emerald-300 font-semibold">{tmpl.name}</span>
                        <span className="text-[10px] text-slate-400">{tmpl.source_file}</span>
                      </div>
                      <p className="text-[11px] text-slate-300 bg-slate-900/90 p-2 rounded border border-slate-800 italic">
                        "{tmpl.snippet}"
                      </p>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}

          {activeSubTab === 'graph' && (
            <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 space-y-4 shadow-sm font-mono text-xs">
              <div>
                <h3 className="text-xs font-bold text-slate-200 uppercase tracking-wider">
                  Direct vs Transitive Dependency Graph
                </h3>
                <p className="text-[11px] text-slate-400 mt-0.5">
                  Resolution tree with cycle detection
                </p>
              </div>

              {report?.dependency_graph?.circular_dependencies?.length > 0 ? (
                <div className="p-3 bg-rose-950/30 border border-rose-500/30 rounded-lg text-rose-300">
                  <div className="font-bold flex items-center space-x-1.5">
                    <AlertTriangle className="w-4 h-4" />
                    <span>Circular Dependencies Detected!</span>
                  </div>
                  <div className="mt-1 space-y-0.5 text-[11px]">
                    {report.dependency_graph.circular_dependencies.map((cycle: string[], cIdx: number) => (
                      <div key={cIdx}>{cycle.join(' -> ')}</div>
                    ))}
                  </div>
                </div>
              ) : (
                <div className="p-2.5 bg-emerald-950/20 border border-emerald-500/20 rounded-lg text-emerald-300 flex items-center space-x-2">
                  <CheckCircle2 className="w-4 h-4" />
                  <span>No circular dependencies found. Graph is a valid DAG.</span>
                </div>
              )}

              <div className="space-y-2">
                <div className="text-slate-400 font-semibold text-[11px]">Dependency Edges ({report?.dependency_graph?.edges?.length || 0}):</div>
                <div className="max-h-[350px] overflow-y-auto space-y-1.5">
                  {(report?.dependency_graph?.edges || []).map((edge: any, eIdx: number) => (
                    <div key={eIdx} className="p-2 bg-slate-950/70 border border-slate-800 rounded flex items-center justify-between text-[11px]">
                      <div className="flex items-center space-x-2 truncate">
                        <span className="text-slate-300">{edge.from_purl.split('/').pop()}</span>
                        <ChevronRight className="w-3 h-3 text-slate-400" />
                        <span className="text-cyan-400">{edge.to_purl.split('/').pop()}</span>
                      </div>
                      <span className="text-[10px] px-1.5 py-0.5 rounded bg-slate-800 text-slate-400">
                        {edge.scope}
                      </span>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}

          {activeSubTab === 'compliance' && (
            <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 space-y-4 shadow-sm font-mono text-xs">
              <div>
                <h3 className="text-xs font-bold text-slate-200 uppercase tracking-wider">
                  License & Malicious Package Scanner
                </h3>
                <p className="text-[11px] text-slate-400 mt-0.5">
                  SPDX 3.0 license categorization, strong copyleft risks, typo-squatting, and lifecycle script backdoors
                </p>
              </div>

              {/* Malicious Risks */}
              <div className="space-y-2">
                <div className="text-rose-400 font-bold flex items-center space-x-1.5">
                  <ShieldAlert className="w-4 h-4" />
                  <span>Malicious Package & Backdoor Findings ({report?.malicious_package_risks?.length || 0})</span>
                </div>

                {report?.malicious_package_risks?.length === 0 ? (
                  <div className="p-3 bg-emerald-950/20 border border-emerald-500/20 rounded-lg text-emerald-300 flex items-center space-x-2">
                    <CheckCircle2 className="w-4 h-4" />
                    <span>No typo-squatting or malicious install scripts detected.</span>
                  </div>
                ) : (
                  report.malicious_package_risks.map((risk: any, rIdx: number) => (
                    <div key={rIdx} className="p-3 bg-rose-950/40 border border-rose-500/30 rounded-lg text-rose-300 space-y-1">
                      <div className="flex items-center justify-between">
                        <span className="font-bold">{risk.package_name}</span>
                        <span className="text-[10px] px-2 py-0.5 rounded bg-rose-500/30 text-rose-200 uppercase">
                          {risk.risk_type}
                        </span>
                      </div>
                      <p className="text-[11px] text-rose-200/90">{risk.description}</p>
                    </div>
                  ))
                )}
              </div>

              {/* License Compliance */}
              <div className="space-y-2 pt-3 border-t border-slate-800">
                <div className="text-slate-300 font-bold">License Compliance Distribution:</div>
                <div className="space-y-1 max-h-[300px] overflow-y-auto">
                  {(report?.license_compliance || []).map((lic: any, lIdx: number) => (
                    <div key={lIdx} className="p-2.5 bg-slate-950/70 border border-slate-800 rounded flex items-center justify-between text-[11px]">
                      <div className="space-y-0.5">
                        <span className="font-bold text-slate-200">{lic.package_name}</span>
                        <div className="text-[10px] text-slate-400">SPDX: <span className="text-cyan-300">{lic.normalized_spdx}</span></div>
                      </div>
                      <span className={`text-[10px] px-2 py-0.5 rounded font-bold ${
                        lic.classification === 'PERMISSIVE'
                          ? 'bg-emerald-500/20 text-emerald-300'
                          : lic.classification === 'STRONG_COPYLEFT'
                          ? 'bg-rose-500/20 text-rose-300'
                          : 'bg-amber-500/20 text-amber-300'
                      }`}>
                        {lic.classification}
                      </span>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}
        </div>

        {/* Right Column: Inspector & Code Preview (5 Cols) */}
        <div className="lg:col-span-5 space-y-4">
          {/* Detail Inspector Card */}
          {selectedTrace ? (
            <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 space-y-3 font-mono text-xs shadow-md">
              <div className="flex items-center justify-between pb-2 border-b border-slate-800">
                <div className="flex items-center space-x-2">
                  <Info className="w-4 h-4 text-cyan-400" />
                  <span className="font-bold text-slate-200 uppercase">Reachability Inspector</span>
                </div>
                <span className={`text-[10px] px-2 py-0.5 rounded font-bold ${
                  selectedTrace.status === 'VULNERABILITY_REACHABLE'
                    ? 'bg-rose-500/20 text-rose-300'
                    : 'bg-amber-500/20 text-amber-300'
                }`}>
                  {selectedTrace.status}
                </span>
              </div>

              <div className="space-y-2">
                <div>
                  <span className="text-slate-400 text-[10px] uppercase">Vulnerability:</span>
                  <div className="font-bold text-cyan-300 text-sm">{selectedTrace.vulnerability_id}</div>
                </div>

                <div>
                  <span className="text-slate-400 text-[10px] uppercase">Target Package:</span>
                  <div className="text-slate-200">{selectedTrace.package_name} @ {selectedTrace.installed_version}</div>
                  <div className="text-[10px] text-slate-400 truncate">{selectedTrace.package_purl}</div>
                </div>

                <div>
                  <span className="text-slate-400 text-[10px] uppercase">Evidence & Callflow:</span>
                  <p className="text-[11px] text-slate-300 bg-slate-950 p-2.5 rounded border border-slate-800 leading-relaxed">
                    {selectedTrace.evidence_description}
                  </p>
                </div>

                <div>
                  <span className="text-slate-400 text-[10px] uppercase">Imported In Files:</span>
                  <div className="mt-1 space-y-1">
                    {selectedTrace.imported_in_files.length === 0 ? (
                      <span className="text-slate-400 italic">None (Unreferenced dependency)</span>
                    ) : (
                      selectedTrace.imported_in_files.map((file: string, fIdx: number) => (
                        <div key={fIdx} className="px-2 py-1 bg-slate-950 rounded border border-slate-800 text-cyan-300 text-[11px]">
                          {file}
                        </div>
                      ))
                    )}
                  </div>
                </div>

                {selectedTrace.target_vulnerable_symbols?.length > 0 && (
                  <div>
                    <span className="text-slate-400 text-[10px] uppercase">Vulnerable Function Symbols:</span>
                    <div className="flex flex-wrap gap-1 mt-1">
                      {selectedTrace.target_vulnerable_symbols.map((sym: string, sIdx: number) => (
                        <span key={sIdx} className="px-2 py-0.5 bg-rose-950/60 border border-rose-500/20 text-rose-300 rounded text-[10px]">
                          {sym}
                        </span>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            </div>
          ) : (
            <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 text-center text-slate-400 font-mono text-xs">
              Select a reachability trace on the left to view deep callflow diagnostics.
            </div>
          )}

          {/* Scenario Source Editor Preview */}
          <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden shadow-md">
            <div className="bg-slate-950 px-3 py-2 border-b border-slate-800 flex items-center justify-between">
              <div className="flex items-center space-x-1.5 overflow-x-auto">
                {editorFiles.map((file, idx) => (
                  <button
                    key={file.path}
                    onClick={() => setSelectedFileIdx(idx)}
                    className={`px-2.5 py-1 rounded text-xs font-mono transition-all ${
                      selectedFileIdx === idx
                        ? 'bg-slate-800 text-cyan-300 font-bold border border-slate-700'
                        : 'text-slate-400 hover:text-slate-200'
                    }`}
                  >
                    {file.path}
                  </button>
                ))}
              </div>
              <span className="text-[10px] text-slate-400 font-mono hidden sm:inline">Fixture Source</span>
            </div>

            <div className="p-3 bg-slate-950 max-h-[350px] overflow-y-auto">
              <textarea
                value={editorFiles[selectedFileIdx]?.content || ''}
                onChange={(e) => {
                  const updated = [...editorFiles];
                  updated[selectedFileIdx] = {
                    ...updated[selectedFileIdx],
                    content: e.target.value,
                  };
                  setEditorFiles(updated);
                }}
                rows={12}
                className="w-full bg-slate-900 text-slate-200 font-mono text-xs p-2.5 rounded border border-slate-800 focus:outline-none focus:border-cyan-500 leading-relaxed resize-none"
              />
            </div>
          </div>
        </div>
      </div>

      {/* JSON Drawer Modal */}
      {jsonDrawerData && (
        <DiagnosticJsonDrawer
          data={jsonDrawerData}
          title="CycloneDX 1.5 JSON Output"
          onClose={() => setJsonDrawerData(null)}
        />
      )}
    </div>
  );
};
