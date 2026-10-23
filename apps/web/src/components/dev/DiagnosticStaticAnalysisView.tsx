/**
 * Diagnostic Static Analysis & Control Flow View
 * P15 — Static Analysis & Control Flow
 */

import React, { useState, useEffect } from 'react';
import { 
  Code2, 
  GitFork, 
  GitBranch, 
  ShieldAlert, 
  Play, 
  CheckCircle2, 
  AlertTriangle, 
  FileCode2, 
  Network, 
  Layers, 
  RefreshCw, 
  Search, 
  Sparkles, 
  ExternalLink,
  ChevronRight,
  ChevronDown,
  Terminal,
  FileCheck,
  Ban,
  Radio,
  Zap,
  ShieldCheck
} from 'lucide-react';
import { DiagnosticJsonDrawer } from './DiagnosticJsonDrawer.tsx';

export interface DiagnosticStaticAnalysisViewProps {
  currentRole?: string;
}

export const DiagnosticStaticAnalysisView: React.FC<DiagnosticStaticAnalysisViewProps> = ({ currentRole = 'operator' }) => {
  const [activeSubTab, setActiveSubTab] = useState<'findings' | 'taint' | 'callgraph' | 'cfg' | 'symbols' | 'coverage' | 'rules'>('findings');
  const [loading, setLoading] = useState<boolean>(false);
  const [report, setReport] = useState<any | null>(null);
  const [selectedFinding, setSelectedFinding] = useState<any | null>(null);
  const [selectedTaintPath, setSelectedTaintPath] = useState<any | null>(null);
  const [filterTaintStatus, setFilterTaintStatus] = useState<string>('ALL');
  const [selectedCfg, setSelectedCfg] = useState<any | null>(null);
  const [selectedNode, setSelectedNode] = useState<string | null>(null);
  const [filterCategory, setFilterCategory] = useState<string>('ALL');
  const [filterSeverity, setFilterSeverity] = useState<string>('ALL');
  const [rulesData, setRulesData] = useState<any | null>(null);
  const [editorFiles, setEditorFiles] = useState<Array<{ path: string; content: string }>>([]);
  const [selectedFileIdx, setSelectedFileIdx] = useState<number>(0);
  const [jsonDrawerData, setJsonDrawerData] = useState<any | null>(null);

  // Load sample fixtures on mount
  useEffect(() => {
    loadFixturesAndAnalyze();
    fetchRules();
  }, []);

  const fetchRules = async () => {
    try {
      const res = await fetch('/api/dev/static-analysis/rules', {
        headers: { 'X-Role': currentRole }
      });
      if (res.ok) {
        setRulesData(await res.json());
      }
    } catch {
      // ignore
    }
  };

  const loadFixturesAndAnalyze = async () => {
    setLoading(true);
    try {
      const fixRes = await fetch('/api/dev/static-analysis/sample-fixtures', {
        headers: { 'X-Role': currentRole }
      });
      if (fixRes.ok) {
        const fixtures = await fixRes.json();
        const files = fixtures.multi_file_agent || [];
        setEditorFiles(files);
        await runAnalysis(files);
      }
    } catch (err: any) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  const runAnalysis = async (filesToAnalyze = editorFiles) => {
    setLoading(true);
    try {
      const res = await fetch('/api/dev/static-analysis/analyze', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Role': currentRole,
        },
        body: JSON.stringify({
          artifact_id: 'art_diagnostic_demo',
          files: filesToAnalyze,
        }),
      });

      if (res.ok) {
        const data = await res.json();
        setReport(data);
        if (data.cfgs && data.cfgs.length > 0) {
          setSelectedCfg(data.cfgs[0]);
        }
      }
    } catch (err: any) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  const handleContentChange = (newContent: string) => {
    const updated = [...editorFiles];
    updated[selectedFileIdx].content = newContent;
    setEditorFiles(updated);
  };

  const findings = report?.findings || [];
  const filteredFindings = findings.filter((f: any) => {
    if (filterCategory !== 'ALL' && f.category !== filterCategory) return false;
    if (filterSeverity !== 'ALL' && f.severity !== filterSeverity) return false;
    return true;
  });

  return (
    <div className="space-y-6">
      {/* Header & Overview Cards */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 bg-slate-900/80 border border-slate-800 rounded-xl p-5 shadow-lg">
        <div>
          <div className="flex items-center space-x-3">
            <div className="p-2 rounded-lg bg-cyan-500/10 border border-cyan-500/20 text-cyan-400">
              <Code2 className="w-5 h-5" />
            </div>
            <div>
              <h2 className="text-base font-bold text-slate-100 flex items-center gap-2">
                Static Analysis & Control Flow Engine
                <span className="px-2 py-0.5 rounded text-[11px] font-mono bg-cyan-500/10 text-cyan-400 border border-cyan-500/30">
                  v{report?.stage_run?.engine_version || '1.0.0'}
                </span>
                <span className="px-2 py-0.5 rounded text-[11px] font-mono bg-indigo-500/10 text-indigo-400 border border-indigo-500/30">
                  Ruleset v{report?.stage_run?.ruleset_version || '1.0.0'}
                </span>
              </h2>
              <p className="text-xs text-slate-400 mt-0.5">
                Strict structural analysis without execution: symbols, import graphs, call paths, CFGs, and source-located findings.
              </p>
            </div>
          </div>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={() => runAnalysis()}
            disabled={loading}
            className="flex items-center space-x-1.5 px-3 py-1.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-semibold shadow transition disabled:opacity-50"
            id="run-static-analysis-btn"
          >
            {loading ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : <Play className="w-3.5 h-3.5" />}
            <span>Analyze Workspace</span>
          </button>
          <button
            onClick={loadFixturesAndAnalyze}
            disabled={loading}
            className="flex items-center space-x-1.5 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-semibold border border-slate-700 transition"
          >
            <RefreshCw className="w-3.5 h-3.5" />
            <span>Reset Fixtures</span>
          </button>
        </div>
      </div>

      {/* Summary Metrics Bar */}
      {report && (
        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
          <div className="bg-slate-900/60 border border-slate-800/80 rounded-lg p-3">
            <div className="text-slate-400 text-xs font-mono">Total Findings</div>
            <div className="text-xl font-bold text-slate-100 font-mono mt-1">
              {report.summary_stats.total_findings}
            </div>
            <div className="text-[11px] text-slate-500 mt-0.5 font-mono">
              {report.summary_stats.findings_by_severity.CRITICAL} Crit • {report.summary_stats.findings_by_severity.HIGH} High
            </div>
          </div>

          <div className="bg-slate-900/60 border border-slate-800/80 rounded-lg p-3">
            <div className="text-slate-400 text-xs font-mono">Call Graph</div>
            <div className="text-xl font-bold text-cyan-400 font-mono mt-1">
              {Object.keys(report.call_graph.nodes).length} Nodes
            </div>
            <div className="text-[11px] text-slate-500 mt-0.5 font-mono">
              {report.call_graph.edges.length} Edges • {report.call_graph.entrypoints.length} Entrypoints
            </div>
          </div>

          <div className="bg-slate-900/60 border border-slate-800/80 rounded-lg p-3">
            <div className="text-slate-400 text-xs font-mono">CFGs Generated</div>
            <div className="text-xl font-bold text-indigo-400 font-mono mt-1">
              {report.cfgs.length} CFGs
            </div>
            <div className="text-[11px] text-slate-500 mt-0.5 font-mono">
              {report.summary_stats.high_complexity_functions} High Complexity (V&gt;10)
            </div>
          </div>

          <div className="bg-slate-900/60 border border-slate-800/80 rounded-lg p-3">
            <div className="text-slate-400 text-xs font-mono">Process / Network</div>
            <div className="text-xl font-bold text-rose-400 font-mono mt-1">
              {report.summary_stats.process_executions + report.summary_stats.network_calls}
            </div>
            <div className="text-[11px] text-slate-500 mt-0.5 font-mono">
              {report.summary_stats.process_executions} Proc • {report.summary_stats.network_calls} Net
            </div>
          </div>

          <div className="bg-slate-900/60 border border-slate-800/80 rounded-lg p-3">
            <div className="text-slate-400 text-xs font-mono">Tools & Secrets</div>
            <div className="text-xl font-bold text-amber-400 font-mono mt-1">
              {report.summary_stats.tools_declared + report.summary_stats.credentials_detected}
            </div>
            <div className="text-[11px] text-slate-500 mt-0.5 font-mono">
              {report.summary_stats.tools_declared} Tools • {report.summary_stats.credentials_detected} Creds
            </div>
          </div>

          <div className="bg-slate-900/60 border border-slate-800/80 rounded-lg p-3">
            <div className="text-slate-400 text-xs font-mono">Sound Coverage</div>
            <div className="text-xl font-bold text-emerald-400 font-mono mt-1">
              {report.coverage.coverage_percentage}%
            </div>
            <div className="text-[11px] text-slate-500 mt-0.5 font-mono">
              {report.coverage.analyzed_lines} / {report.coverage.total_lines} Lines
            </div>
          </div>
        </div>
      )}

      {/* Main Workspace: Left Editor, Right Diagnostic Sub-tabs */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left Col: Multi-file Interactive Code Inspector */}
        <div className="lg:col-span-5 space-y-3">
          <div className="bg-slate-900/80 border border-slate-800 rounded-xl overflow-hidden shadow">
            <div className="bg-slate-950 px-4 py-2.5 border-b border-slate-800 flex items-center justify-between">
              <div className="flex items-center space-x-2 text-xs font-mono text-slate-300">
                <FileCode2 className="w-4 h-4 text-cyan-400" />
                <span>Source Files ({editorFiles.length})</span>
              </div>
              <div className="text-[11px] text-slate-500 font-mono">
                Click file tab to inspect / edit
              </div>
            </div>

            {/* File Tabs */}
            <div className="flex border-b border-slate-800 bg-slate-900/50 overflow-x-auto text-xs font-mono">
              {editorFiles.map((file, idx) => {
                const isSelected = selectedFileIdx === idx;
                const fileFindingsCount = findings.filter((f: any) => f.source_span.file_path === file.path).length;

                return (
                  <button
                    key={file.path}
                    onClick={() => setSelectedFileIdx(idx)}
                    className={`px-3 py-2 border-r border-slate-800 flex items-center space-x-1.5 whitespace-nowrap transition ${
                      isSelected 
                        ? 'bg-slate-800 text-cyan-300 border-b-2 border-b-cyan-500 font-bold' 
                        : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/40'
                    }`}
                  >
                    <span>{file.path}</span>
                    {fileFindingsCount > 0 && (
                      <span className="px-1.5 py-0.2 rounded-full text-[10px] bg-rose-500/20 text-rose-300 font-mono">
                        {fileFindingsCount}
                      </span>
                    )}
                  </button>
                );
              })}
            </div>

            {/* Editor Area */}
            {editorFiles[selectedFileIdx] && (
              <div className="p-3 bg-slate-950 font-mono text-xs">
                <div className="flex justify-between items-center text-[11px] text-slate-500 mb-2 pb-1 border-b border-slate-800">
                  <span>{editorFiles[selectedFileIdx].path}</span>
                  <span>{editorFiles[selectedFileIdx].content.split('\n').length} lines</span>
                </div>
                <textarea
                  value={editorFiles[selectedFileIdx].content}
                  onChange={(e) => handleContentChange(e.target.value)}
                  className="w-full h-80 bg-slate-900/90 text-slate-200 font-mono text-xs p-3 rounded border border-slate-800 focus:border-cyan-500 focus:outline-none resize-none leading-relaxed"
                  spellCheck={false}
                />
              </div>
            )}
          </div>

          {/* File Classification Breakdown */}
          {report && (
            <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-4 shadow">
              <h3 className="text-xs font-bold text-slate-200 font-mono mb-2 flex items-center gap-1.5">
                <FileCheck className="w-3.5 h-3.5 text-cyan-400" />
                File Selection & Entrypoints
              </h3>
              <div className="space-y-1.5 text-xs font-mono max-h-48 overflow-y-auto">
                {report.file_selection.included_files.map((file: any) => (
                  <div key={file.path} className="flex items-center justify-between p-2 rounded bg-slate-950/60 border border-slate-800/60">
                    <div className="flex items-center space-x-2">
                      <span className={`w-2 h-2 rounded-full ${file.is_entrypoint ? 'bg-emerald-400' : 'bg-cyan-400'}`} />
                      <span className="text-slate-300">{file.path}</span>
                    </div>
                    <div className="flex items-center space-x-1.5">
                      <span className="px-1.5 py-0.5 rounded text-[10px] bg-slate-800 text-slate-400">
                        {file.category}
                      </span>
                      {file.is_entrypoint && (
                        <span className="px-1.5 py-0.5 rounded text-[10px] bg-emerald-500/20 text-emerald-300 border border-emerald-500/30">
                          ENTRYPOINT
                        </span>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>

        {/* Right Col: Diagnostics Sub-Tabs & Detailed Inspectors */}
        <div className="lg:col-span-7 space-y-4">
          {/* Sub-nav Tabs */}
          <div className="flex items-center space-x-1 bg-slate-900/90 p-1.5 rounded-xl border border-slate-800 text-xs font-mono overflow-x-auto">
            <button
              onClick={() => setActiveSubTab('findings')}
              className={`px-3 py-1.5 rounded-lg flex items-center space-x-1.5 transition ${
                activeSubTab === 'findings'
                  ? 'bg-cyan-600 text-white font-bold shadow'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
              }`}
            >
              <ShieldAlert className="w-3.5 h-3.5" />
              <span>Findings ({findings.length})</span>
            </button>

            <button
              onClick={() => setActiveSubTab('taint')}
              className={`px-3 py-1.5 rounded-lg flex items-center space-x-1.5 transition ${
                activeSubTab === 'taint'
                  ? 'bg-rose-600 text-white font-bold shadow'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
              }`}
              id="subnav-taint-tab-btn"
            >
              <Radio className="w-3.5 h-3.5" />
              <span>Taint Flows ({report?.taint_report?.paths?.length || 0})</span>
            </button>

            <button
              onClick={() => setActiveSubTab('callgraph')}
              className={`px-3 py-1.5 rounded-lg flex items-center space-x-1.5 transition ${
                activeSubTab === 'callgraph'
                  ? 'bg-cyan-600 text-white font-bold shadow'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
              }`}
            >
              <GitFork className="w-3.5 h-3.5" />
              <span>Call Graph</span>
            </button>

            <button
              onClick={() => setActiveSubTab('cfg')}
              className={`px-3 py-1.5 rounded-lg flex items-center space-x-1.5 transition ${
                activeSubTab === 'cfg'
                  ? 'bg-cyan-600 text-white font-bold shadow'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
              }`}
            >
              <GitBranch className="w-3.5 h-3.5" />
              <span>Control Flow (CFG)</span>
            </button>

            <button
              onClick={() => setActiveSubTab('symbols')}
              className={`px-3 py-1.5 rounded-lg flex items-center space-x-1.5 transition ${
                activeSubTab === 'symbols'
                  ? 'bg-cyan-600 text-white font-bold shadow'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
              }`}
            >
              <Layers className="w-3.5 h-3.5" />
              <span>Symbols & Imports</span>
            </button>

            <button
              onClick={() => setActiveSubTab('coverage')}
              className={`px-3 py-1.5 rounded-lg flex items-center space-x-1.5 transition ${
                activeSubTab === 'coverage'
                  ? 'bg-cyan-600 text-white font-bold shadow'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
              }`}
            >
              <CheckCircle2 className="w-3.5 h-3.5" />
              <span>Coverage & Soundness</span>
            </button>

            <button
              onClick={() => setActiveSubTab('rules')}
              className={`px-3 py-1.5 rounded-lg flex items-center space-x-1.5 transition ${
                activeSubTab === 'rules'
                  ? 'bg-cyan-600 text-white font-bold shadow'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
              }`}
            >
              <Sparkles className="w-3.5 h-3.5" />
              <span>Rules Catalog ({rulesData?.total_rules || 0})</span>
            </button>
          </div>

          {/* SubTab 1: Findings Table */}
          {activeSubTab === 'findings' && (
            <div className="space-y-4">
              {/* Category and Severity Filters */}
              <div className="flex flex-wrap gap-2 items-center justify-between text-xs font-mono bg-slate-900/60 p-3 rounded-lg border border-slate-800">
                <div className="flex items-center space-x-2">
                  <span className="text-slate-400">Category:</span>
                  <select
                    value={filterCategory}
                    onChange={(e) => setFilterCategory(e.target.value)}
                    className="bg-slate-950 border border-slate-800 text-slate-200 px-2 py-1 rounded focus:outline-none"
                  >
                    <option value="ALL">All Categories</option>
                    <option value="PROCESS_EXECUTION">Process Execution</option>
                    <option value="NETWORK">Network Egress</option>
                    <option value="FILESYSTEM">Filesystem Ops</option>
                    <option value="TOOL_DECLARATION">Tool Declarations</option>
                    <option value="CREDENTIAL_ACCESS">Credentials & Secrets</option>
                    <option value="CONTROL_FLOW_ANOMALY">CFG Anomalies</option>
                  </select>
                </div>

                <div className="flex items-center space-x-2">
                  <span className="text-slate-400">Severity:</span>
                  <select
                    value={filterSeverity}
                    onChange={(e) => setFilterSeverity(e.target.value)}
                    className="bg-slate-950 border border-slate-800 text-slate-200 px-2 py-1 rounded focus:outline-none"
                  >
                    <option value="ALL">All Severities</option>
                    <option value="CRITICAL">CRITICAL</option>
                    <option value="HIGH">HIGH</option>
                    <option value="MEDIUM">MEDIUM</option>
                    <option value="LOW">LOW</option>
                    <option value="INFO">INFO</option>
                  </select>
                </div>
              </div>

              {/* Findings List */}
              <div className="space-y-2.5 max-h-[500px] overflow-y-auto">
                {filteredFindings.length === 0 ? (
                  <div className="p-8 text-center bg-slate-900/40 border border-slate-800 rounded-xl font-mono text-xs text-slate-500">
                    No findings matched current filter criteria.
                  </div>
                ) : (
                  filteredFindings.map((finding: any) => {
                    const sevColor = 
                      finding.severity === 'CRITICAL' ? 'bg-rose-500/20 text-rose-300 border-rose-500/40' :
                      finding.severity === 'HIGH' ? 'bg-orange-500/20 text-orange-300 border-orange-500/40' :
                      finding.severity === 'MEDIUM' ? 'bg-amber-500/20 text-amber-300 border-amber-500/40' :
                      finding.severity === 'LOW' ? 'bg-blue-500/20 text-blue-300 border-blue-500/40' :
                      'bg-slate-700/30 text-slate-300 border-slate-600/40';

                    return (
                      <div
                        key={finding.finding_id}
                        onClick={() => setSelectedFinding(finding)}
                        className="bg-slate-900/80 border border-slate-800 hover:border-slate-700 rounded-xl p-4 transition cursor-pointer space-y-2 shadow-sm"
                      >
                        <div className="flex items-start justify-between gap-2">
                          <div className="flex items-center space-x-2">
                            <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold border ${sevColor}`}>
                              {finding.severity}
                            </span>
                            <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-slate-800 text-slate-400">
                              {finding.rule_id}
                            </span>
                            <h4 className="text-xs font-bold text-slate-100">{finding.title}</h4>
                          </div>
                          <span className="text-[11px] font-mono text-slate-500">
                            Confidence: {Math.round(finding.confidence * 100)}%
                          </span>
                        </div>

                        <p className="text-xs text-slate-300 leading-relaxed">
                          {finding.description}
                        </p>

                        {/* Source Span Pill */}
                        <div className="flex flex-wrap items-center justify-between gap-2 pt-2 border-t border-slate-800/80 text-[11px] font-mono text-slate-400">
                          <div className="flex items-center space-x-1 text-cyan-400">
                            <FileCode2 className="w-3.5 h-3.5" />
                            <span>{finding.source_span.file_path}:{finding.source_span.start_line}:{finding.source_span.start_col}</span>
                          </div>
                          {finding.interprocedural_trace && (
                            <span className="px-1.5 py-0.5 rounded bg-indigo-500/20 text-indigo-300 text-[10px] border border-indigo-500/30">
                              Trace: {finding.interprocedural_trace.length} steps from entrypoint
                            </span>
                          )}
                        </div>

                        {/* Interprocedural Trace Preview if present */}
                        {finding.interprocedural_trace && finding.interprocedural_trace.length > 0 && (
                          <div className="bg-slate-950 p-2 rounded text-[11px] font-mono text-slate-400 space-y-1">
                            <div className="text-slate-500 font-bold">Trace Reachability Path:</div>
                            {finding.interprocedural_trace.map((step: any, sIdx: number) => (
                              <div key={sIdx} className="flex items-center space-x-1.5 text-indigo-300">
                                <span>{step.step_number}.</span>
                                <span className="text-slate-200 font-bold">{step.file_path}</span>
                                <span className="text-slate-500">→</span>
                                <span className="text-cyan-300">{step.function_name}()</span>
                                {step.call_site && <span className="text-slate-400">calls {step.call_site}</span>}
                              </div>
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

          {/* SubTab: Taint Intelligence & Dataflow Propagation (P16) */}
          {activeSubTab === 'taint' && report?.taint_report && (
            <div className="space-y-4 font-mono text-xs">
              {/* Taint Header Summary Metrics */}
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-2.5">
                <div className="p-2.5 rounded-lg bg-slate-900/80 border border-slate-800">
                  <div className="text-slate-400 text-[11px]">Active Vulnerable</div>
                  <div className="text-lg font-bold text-rose-400 mt-0.5">
                    {report.taint_report.summary.active_vulnerable_paths}
                  </div>
                  <div className="text-[10px] text-slate-500">Unsanitized Flow</div>
                </div>

                <div className="p-2.5 rounded-lg bg-slate-900/80 border border-slate-800">
                  <div className="text-slate-400 text-[11px]">Sanitized</div>
                  <div className="text-lg font-bold text-emerald-400 mt-0.5">
                    {report.taint_report.summary.sanitized_paths}
                  </div>
                  <div className="text-[10px] text-slate-500">Neutralized Hash/Mask</div>
                </div>

                <div className="p-2.5 rounded-lg bg-slate-900/80 border border-slate-800">
                  <div className="text-slate-400 text-[11px]">Unreachable</div>
                  <div className="text-lg font-bold text-amber-400 mt-0.5">
                    {report.taint_report.summary.unreachable_paths}
                  </div>
                  <div className="text-[10px] text-slate-500">Dead Code Branch</div>
                </div>

                <div className="p-2.5 rounded-lg bg-slate-900/80 border border-slate-800">
                  <div className="text-slate-400 text-[11px]">Indeterminate</div>
                  <div className="text-lg font-bold text-purple-400 mt-0.5">
                    {report.taint_report.summary.indeterminate_paths}
                  </div>
                  <div className="text-[10px] text-slate-500">Dynamic Dispatch</div>
                </div>
              </div>

              {/* Status Filter */}
              <div className="flex items-center justify-between bg-slate-900/60 p-2.5 rounded-lg border border-slate-800">
                <div className="flex items-center space-x-2">
                  <span className="text-slate-400">Flow Status:</span>
                  <select
                    value={filterTaintStatus}
                    onChange={(e) => setFilterTaintStatus(e.target.value)}
                    className="bg-slate-950 border border-slate-800 text-slate-200 px-2 py-1 rounded focus:outline-none"
                  >
                    <option value="ALL">All Paths ({report.taint_report.paths.length})</option>
                    <option value="ACTIVE">ACTIVE ({report.taint_report.summary.active_vulnerable_paths})</option>
                    <option value="SANITIZED">SANITIZED ({report.taint_report.summary.sanitized_paths})</option>
                    <option value="UNREACHABLE">UNREACHABLE ({report.taint_report.summary.unreachable_paths})</option>
                    <option value="INDETERMINATE">INDETERMINATE ({report.taint_report.summary.indeterminate_paths})</option>
                  </select>
                </div>

                <div className="text-[11px] text-slate-500">
                  Registry v{report.taint_report.source_registry_version} • {report.taint_report.sources.length} Sources • {report.taint_report.sinks.length} Sinks
                </div>
              </div>

              {/* Paths List & Detail Inspector */}
              <div className="space-y-3">
                {report.taint_report.paths
                  .filter((p: any) => filterTaintStatus === 'ALL' || p.status === filterTaintStatus)
                  .map((path: any) => {
                    const isSelected = selectedTaintPath?.path_id === path.path_id;
                    const statusColor = 
                      path.status === 'ACTIVE' ? 'bg-rose-500/20 text-rose-300 border-rose-500/40' :
                      path.status === 'SANITIZED' ? 'bg-emerald-500/20 text-emerald-300 border-emerald-500/40' :
                      path.status === 'UNREACHABLE' ? 'bg-amber-500/20 text-amber-300 border-amber-500/40' :
                      'bg-purple-500/20 text-purple-300 border-purple-500/40';

                    return (
                      <div
                        key={path.path_id}
                        onClick={() => setSelectedTaintPath(isSelected ? null : path)}
                        className={`p-3.5 rounded-xl border transition cursor-pointer space-y-2.5 ${
                          isSelected 
                            ? 'bg-slate-900 border-cyan-500/50 shadow-md ring-1 ring-cyan-500/20' 
                            : 'bg-slate-900/60 border-slate-800 hover:border-slate-700'
                        }`}
                      >
                        {/* Path Header */}
                        <div className="flex items-center justify-between">
                          <div className="flex items-center space-x-2">
                            <span className="font-bold text-slate-200">{path.path_id}</span>
                            <span className={`px-2 py-0.5 rounded text-[10px] font-bold border ${statusColor}`}>
                              {path.status}
                            </span>
                            <span className="px-1.5 py-0.5 rounded bg-slate-800 text-slate-300 text-[10px]">
                              {path.flow_classification}
                            </span>
                          </div>

                          <div className="flex items-center space-x-2">
                            <span className="text-[11px] text-slate-400">
                              Confidence: <span className="font-bold text-cyan-300">{Math.round(path.confidence * 100)}%</span>
                            </span>
                            <span className="text-slate-600">•</span>
                            <span className="text-[11px] text-slate-400">{path.hops.length} steps</span>
                            {isSelected ? <ChevronDown className="w-4 h-4 text-cyan-400" /> : <ChevronRight className="w-4 h-4 text-slate-500" />}
                          </div>
                        </div>

                        {/* Source -> Sink Flow Preview */}
                        <div className="flex items-center space-x-2 text-[11px] text-slate-300 bg-slate-950/70 p-2 rounded border border-slate-850">
                          <span className="text-amber-400 font-bold">SOURCE:</span>
                          <span className="text-slate-200">{path.source.file_path}:{path.source.span.start_line}</span>
                          <span className="text-slate-500 font-mono">({path.source.category})</span>
                          <span className="text-slate-500">→</span>
                          <span className="text-rose-400 font-bold">SINK:</span>
                          <span className="text-slate-200">{path.sink.file_path}:{path.sink.span.start_line}</span>
                          <span className="text-slate-500 font-mono">({path.sink.category})</span>
                        </div>

                        {/* Expanded Path Detail Inspector */}
                        {isSelected && (
                          <div className="pt-3 border-t border-slate-800 space-y-3">
                            {/* Epistemic Alert Banner */}
                            <div className="bg-cyan-950/30 border border-cyan-500/30 rounded-lg p-2.5 text-cyan-300 space-y-1">
                              <div className="flex items-center space-x-1.5 font-bold text-[11px]">
                                <ShieldCheck className="w-3.5 h-3.5 text-cyan-400" />
                                <span>EPISTEMIC STATUS: {path.epistemic_label} ({path.evidence.epistemic_state})</span>
                              </div>
                              <p className="text-[10.5px] text-cyan-200/80 leading-relaxed">
                                {path.description}
                              </p>
                            </div>

                            {/* Source, Sink, Sanitizer Cards Grid */}
                            <div className="grid grid-cols-1 md:grid-cols-2 gap-2.5">
                              {/* Source Card */}
                              <div className="bg-slate-950 p-2.5 rounded-lg border border-amber-500/20 space-y-1">
                                <div className="flex justify-between items-center text-amber-400 font-bold text-[11px]">
                                  <span>SOURCE: {path.source.source_id}</span>
                                  <span className="text-[10px] text-slate-500">Line {path.source.span.start_line}:{path.source.span.start_col}</span>
                                </div>
                                <div className="text-[11px] text-slate-300">
                                  Symbol: <span className="font-bold text-cyan-300">{path.source.variable_name || path.source.span.symbol_hint || 'literal'}</span>
                                </div>
                                <div className="bg-slate-900 p-1.5 rounded text-[10px] text-amber-200/90 font-mono overflow-x-auto">
                                  {path.source.expression_text}
                                </div>
                              </div>

                              {/* Sink Card */}
                              <div className="bg-slate-950 p-2.5 rounded-lg border border-rose-500/20 space-y-1">
                                <div className="flex justify-between items-center text-rose-400 font-bold text-[11px]">
                                  <span>SINK: {path.sink.sink_id}</span>
                                  <span className="text-[10px] text-slate-500">Line {path.sink.span.start_line}:{path.sink.span.start_col}</span>
                                </div>
                                <div className="text-[11px] text-slate-300">
                                  Callee: <span className="font-bold text-rose-300">{path.sink.callee_name}()</span>
                                </div>
                                <div className="bg-slate-900 p-1.5 rounded text-[10px] text-rose-200/90 font-mono overflow-x-auto">
                                  {path.sink.call_expression_text}
                                </div>
                              </div>
                            </div>

                            {/* Sanitizer info if sanitized */}
                            {path.sanitizer && (
                              <div className="bg-emerald-950/30 border border-emerald-500/30 rounded-lg p-2.5 text-emerald-300 flex items-center justify-between">
                                <div>
                                  <span className="font-bold">Sanitizer Applied:</span> {path.sanitizer.transformer_name}() ({path.sanitizer.category})
                                </div>
                                <span className="px-2 py-0.5 rounded bg-emerald-500/20 text-emerald-300 text-[10px]">
                                  Power: {Math.round(path.sanitizer.neutralization_power * 100)}%
                                </span>
                              </div>
                            )}

                            {/* Hop-by-hop Trace Timeline */}
                            <div className="space-y-1.5 bg-slate-950 p-3 rounded-lg border border-slate-800">
                              <div className="text-slate-400 font-bold text-[11px] mb-2 flex justify-between">
                                <span>Dataflow Lineage Steps:</span>
                                <span className="text-[10px] text-slate-500">
                                  {path.is_interprocedural && 'Interprocedural • '}
                                  {path.is_cross_file && 'Cross-File • '}
                                  {path.hops.length} Total Hops
                                </span>
                              </div>

                              <div className="space-y-2">
                                {path.hops.map((hop: any, hIdx: number) => (
                                  <div key={hIdx} className="flex items-start space-x-2 text-[11px] border-l-2 border-slate-800 pl-2 ml-1">
                                    <span className="text-cyan-400 font-bold shrink-0">{hop.hop_number}.</span>
                                    <div className="space-y-0.5 flex-1">
                                      <div className="flex items-center space-x-1.5">
                                        <span className="px-1.5 py-0.2 rounded bg-slate-800 text-cyan-300 text-[10px] font-bold">
                                          {hop.hop_type}
                                        </span>
                                        <span className="text-slate-400">
                                          {hop.from_symbol ? `${hop.from_symbol} → ` : ''}{hop.to_symbol}
                                        </span>
                                        <span className="text-slate-600">•</span>
                                        <span className="text-slate-500 text-[10px]">
                                          {hop.file_path}:{hop.span.start_line}
                                        </span>
                                      </div>
                                      <div className="text-[10px] text-slate-400 font-mono bg-slate-900/60 px-2 py-0.5 rounded">
                                        {hop.expression_snippet}
                                      </div>
                                    </div>
                                  </div>
                                ))}
                              </div>
                            </div>

                            {/* View Raw Evidence Button */}
                            <div className="flex justify-end pt-1">
                              <button
                                onClick={(e) => {
                                  e.stopPropagation();
                                  setSelectedFinding(path.evidence);
                                }}
                                className="px-3 py-1 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded text-xs flex items-center space-x-1 font-mono transition"
                              >
                                <Terminal className="w-3.5 h-3.5 text-cyan-400" />
                                <span>Inspect Lineage Evidence JSON</span>
                              </button>
                            </div>
                          </div>
                        )}
                      </div>
                    );
                  })}
              </div>
            </div>
          )}

          {/* SubTab 2: Call Graph Visualizer */}
          {activeSubTab === 'callgraph' && report?.call_graph && (
            <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-5 space-y-4">
              <div className="flex items-center justify-between">
                <h3 className="text-xs font-bold text-slate-200 font-mono flex items-center gap-2">
                  <GitFork className="w-4 h-4 text-cyan-400" />
                  Call Graph & Reachability Map
                </h3>
                <span className="text-xs font-mono text-slate-500">
                  {Object.keys(report.call_graph.nodes).length} Nodes • {report.call_graph.edges.length} Edges
                </span>
              </div>

              {/* Call Nodes list */}
              <div className="space-y-2 max-h-96 overflow-y-auto font-mono text-xs">
                {Object.values(report.call_graph.nodes).map((node: any) => {
                  const isSelected = selectedNode === node.node_id;
                  const outgoingEdges = report.call_graph.edges.filter((e: any) => e.caller_node_id === node.node_id);
                  const reachable = report.call_graph.reachability_map[node.node_id] || [];

                  return (
                    <div
                      key={node.node_id}
                      onClick={() => setSelectedNode(isSelected ? null : node.node_id)}
                      className={`p-3 rounded-lg border transition cursor-pointer ${
                        isSelected 
                          ? 'bg-slate-800/90 border-cyan-500' 
                          : 'bg-slate-950/70 border-slate-800 hover:border-slate-700'
                      }`}
                    >
                      <div className="flex items-center justify-between">
                        <div className="flex items-center space-x-2">
                          <span className={`w-2 h-2 rounded-full ${node.is_entrypoint ? 'bg-emerald-400' : 'bg-cyan-400'}`} />
                          <span className="font-bold text-slate-100">{node.function_name}</span>
                          <span className="text-slate-500 text-[11px]">({node.file_path})</span>
                        </div>
                        <div className="flex items-center space-x-2 text-[10px]">
                          {node.is_entrypoint && (
                            <span className="px-1.5 py-0.5 rounded bg-emerald-500/20 text-emerald-300">ENTRY</span>
                          )}
                          <span className="text-slate-400">Calls: {outgoingEdges.length}</span>
                          <span className="text-indigo-400">Reachable: {reachable.length}</span>
                        </div>
                      </div>

                      {isSelected && outgoingEdges.length > 0 && (
                        <div className="mt-3 pt-2 border-t border-slate-800 space-y-1.5 pl-3 text-[11px]">
                          <div className="text-slate-400 font-bold">Outgoing Invocations:</div>
                          {outgoingEdges.map((edge: any) => (
                            <div key={edge.edge_id} className="flex items-center space-x-2 text-slate-300">
                              <ChevronRight className="w-3 h-3 text-cyan-400" />
                              <span>calls <code className="text-cyan-300 font-bold">{edge.callee_name}()</code></span>
                              <span className="text-slate-500">→</span>
                              <span className="text-slate-400">{edge.callee_node_id}</span>
                              {edge.is_cross_file && (
                                <span className="px-1 py-0.2 rounded text-[9px] bg-purple-500/20 text-purple-300">CROSS-FILE</span>
                              )}
                            </div>
                          ))}
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            </div>
          )}

          {/* SubTab 3: CFG Inspector */}
          {activeSubTab === 'cfg' && report?.cfgs && (
            <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-5 space-y-4">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                <h3 className="text-xs font-bold text-slate-200 font-mono flex items-center gap-2">
                  <GitBranch className="w-4 h-4 text-cyan-400" />
                  Control Flow Graph (CFG) Inspector
                </h3>
                <div className="flex items-center space-x-2">
                  <span className="text-xs font-mono text-slate-400">Function:</span>
                  <select
                    value={selectedCfg?.function_name || ''}
                    onChange={(e) => {
                      const found = report.cfgs.find((c: any) => c.function_name === e.target.value);
                      if (found) setSelectedCfg(found);
                    }}
                    className="bg-slate-950 border border-slate-800 text-slate-200 text-xs font-mono px-2 py-1 rounded focus:outline-none"
                  >
                    {report.cfgs.map((c: any) => (
                      <option key={`${c.file_path}:${c.function_name}`} value={c.function_name}>
                        {c.file_path} :: {c.function_name}()
                      </option>
                    ))}
                  </select>
                </div>
              </div>

              {selectedCfg && (
                <div className="space-y-4 font-mono text-xs">
                  {/* CFG Summary Bar */}
                  <div className="grid grid-cols-3 gap-3 bg-slate-950 p-3 rounded-lg border border-slate-800">
                    <div>
                      <div className="text-slate-500 text-[10px]">Cyclomatic Complexity</div>
                      <div className="text-base font-bold text-cyan-400 mt-0.5">
                        V(G) = {selectedCfg.cyclomatic_complexity}
                      </div>
                    </div>
                    <div>
                      <div className="text-slate-500 text-[10px]">Basic Blocks</div>
                      <div className="text-base font-bold text-indigo-400 mt-0.5">
                        {selectedCfg.blocks.length} Blocks
                      </div>
                    </div>
                    <div>
                      <div className="text-slate-500 text-[10px]">Dead Code Blocks</div>
                      <div className={`text-base font-bold mt-0.5 ${selectedCfg.has_unreachable_blocks ? 'text-rose-400' : 'text-emerald-400'}`}>
                        {selectedCfg.has_unreachable_blocks ? 'DETECTED' : 'NONE'}
                      </div>
                    </div>
                  </div>

                  {/* Basic Blocks list */}
                  <div className="space-y-2 max-h-80 overflow-y-auto">
                    {selectedCfg.blocks.map((b: any) => (
                      <div
                        key={b.block_id}
                        className={`p-3 rounded-lg border ${
                          b.is_dead_code 
                            ? 'bg-rose-950/30 border-rose-500/40 text-rose-200' 
                            : b.is_entry
                              ? 'bg-emerald-950/30 border-emerald-500/40 text-emerald-200'
                              : 'bg-slate-950 border-slate-800 text-slate-300'
                        }`}
                      >
                        <div className="flex items-center justify-between text-[11px] font-bold pb-1 mb-1 border-b border-slate-800/60">
                          <div className="flex items-center space-x-2">
                            <span>Block #{b.block_number} ({b.block_id})</span>
                            {b.is_entry && <span className="px-1.5 py-0.2 rounded bg-emerald-500/20 text-emerald-300 text-[9px]">ENTRY</span>}
                            {b.is_exit && <span className="px-1.5 py-0.2 rounded bg-slate-700 text-slate-300 text-[9px]">EXIT</span>}
                            {b.is_dead_code && <span className="px-1.5 py-0.2 rounded bg-rose-500/20 text-rose-300 text-[9px]">DEAD CODE</span>}
                          </div>
                          <span className="text-slate-500">Lines {b.start_line} - {b.end_line}</span>
                        </div>

                        <div className="space-y-1 py-1">
                          {b.statements.map((stmt: string, sIdx: number) => (
                            <div key={sIdx} className="text-slate-300 text-[11px] font-mono truncate">
                              • {stmt}
                            </div>
                          ))}
                        </div>

                        {b.successors.length > 0 && (
                          <div className="mt-2 pt-1 border-t border-slate-800/40 text-[10px] text-slate-400">
                            Successors: {b.successors.join(', ')}
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}

          {/* SubTab 4: Symbols & Imports */}
          {activeSubTab === 'symbols' && report?.symbol_graph && (
            <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-5 space-y-4">
              <h3 className="text-xs font-bold text-slate-200 font-mono flex items-center gap-2">
                <Layers className="w-4 h-4 text-cyan-400" />
                Cross-File Symbol Bindings & Imports
              </h3>

              <div className="space-y-3 font-mono text-xs max-h-96 overflow-y-auto">
                <div className="text-slate-400 font-bold text-[11px]">Cross-File Symbol Bindings:</div>
                {report.symbol_graph.cross_file_bindings.map((b: any) => (
                  <div key={b.binding_id} className="p-2.5 rounded-lg bg-slate-950 border border-slate-800 flex items-center justify-between">
                    <div className="space-y-0.5">
                      <div className="text-slate-200 font-bold">
                        {b.from_file} <span className="text-cyan-400">({b.from_symbol})</span>
                      </div>
                      <div className="text-slate-500 text-[11px]">
                        imports from {b.to_file} → <span className="text-indigo-300">{b.to_symbol}</span>
                      </div>
                    </div>
                    <span className="px-2 py-0.5 rounded text-[10px] bg-emerald-500/20 text-emerald-300 border border-emerald-500/30">
                      RESOLVED ({Math.round(b.confidence * 100)}%)
                    </span>
                  </div>
                ))}

                {report.symbol_graph.unresolved_imports.length > 0 && (
                  <div className="space-y-1.5 pt-2">
                    <div className="text-rose-400 font-bold text-[11px]">Unresolved Imports:</div>
                    {report.symbol_graph.unresolved_imports.map((u: any, uIdx: number) => (
                      <div key={uIdx} className="p-2 rounded bg-rose-950/20 border border-rose-500/30 text-rose-300 text-[11px]">
                        {u.from_file} imports '{u.specifier}' (Target file not found in workspace)
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>
          )}

          {/* SubTab 5: Coverage & Soundness */}
          {activeSubTab === 'coverage' && report?.coverage && (
            <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-5 space-y-4">
              <h3 className="text-xs font-bold text-slate-200 font-mono flex items-center gap-2">
                <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                Coverage & Soundness Assessment
              </h3>

              <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 font-mono text-xs">
                <div className="bg-slate-950 p-3 rounded-lg border border-slate-800">
                  <div className="text-slate-500 text-[10px]">Files Coverage</div>
                  <div className="text-base font-bold text-slate-100 mt-1">
                    {report.coverage.analyzed_files} / {report.coverage.total_files}
                  </div>
                </div>
                <div className="bg-slate-950 p-3 rounded-lg border border-slate-800">
                  <div className="text-slate-500 text-[10px]">Line Coverage</div>
                  <div className="text-base font-bold text-cyan-400 mt-1">
                    {report.coverage.coverage_percentage}%
                  </div>
                </div>
                <div className="bg-slate-950 p-3 rounded-lg border border-slate-800">
                  <div className="text-slate-500 text-[10px]">Total Functions</div>
                  <div className="text-base font-bold text-indigo-400 mt-1">
                    {report.coverage.total_functions}
                  </div>
                </div>
                <div className="bg-slate-950 p-3 rounded-lg border border-slate-800">
                  <div className="text-slate-500 text-[10px]">CFG Graphs</div>
                  <div className="text-base font-bold text-emerald-400 mt-1">
                    {report.coverage.cfg_covered_functions}
                  </div>
                </div>
              </div>

              {/* Unsupported Constructs / Partial coverage report */}
              {report.coverage.unsupported_constructs.length > 0 && (
                <div className="space-y-2 pt-2">
                  <h4 className="text-xs font-bold text-amber-300 font-mono flex items-center gap-1.5">
                    <AlertTriangle className="w-3.5 h-3.5 text-amber-400" />
                    Unsupported / Soundness Breaking Constructs
                  </h4>
                  <div className="space-y-1.5 font-mono text-xs">
                    {report.coverage.unsupported_constructs.map((un: any, uIdx: number) => (
                      <div key={uIdx} className="p-3 rounded-lg bg-amber-950/20 border border-amber-500/30 text-amber-200">
                        <div className="font-bold flex items-center justify-between">
                          <span>{un.construct}</span>
                          <span className="text-[10px] text-amber-400">{un.file_path}</span>
                        </div>
                        <p className="text-[11px] text-slate-400 mt-1">{un.reason}</p>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}

          {/* SubTab 6: Rules Catalog */}
          {activeSubTab === 'rules' && rulesData && (
            <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-5 space-y-4">
              <div className="flex items-center justify-between">
                <h3 className="text-xs font-bold text-slate-200 font-mono flex items-center gap-2">
                  <Sparkles className="w-4 h-4 text-cyan-400" />
                  Versioned Static Ruleset (v{rulesData.ruleset_version})
                </h3>
                <span className="text-xs font-mono text-slate-400">{rulesData.total_rules} Certified Rules</span>
              </div>

              <div className="space-y-2 max-h-96 overflow-y-auto font-mono text-xs">
                {rulesData.rules.map((rule: any) => (
                  <div key={rule.rule_id} className="p-3 rounded-lg bg-slate-950 border border-slate-800 space-y-1">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center space-x-2">
                        <span className="px-1.5 py-0.5 rounded text-[10px] bg-slate-800 text-cyan-300 font-bold">
                          {rule.rule_id}
                        </span>
                        <span className="font-bold text-slate-200">{rule.title}</span>
                      </div>
                      <span className="px-1.5 py-0.5 rounded text-[10px] bg-slate-800 text-slate-400">
                        {rule.category}
                      </span>
                    </div>
                    <p className="text-[11px] text-slate-400">{rule.description}</p>
                    <div className="text-[10px] text-slate-500 pt-1 border-t border-slate-850">
                      Remediation: {rule.remediation_hint}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      </div>

      {/* JSON Inspector Drawer */}
      {selectedFinding && (
        <DiagnosticJsonDrawer
          data={selectedFinding}
          title={`Finding Details • ${selectedFinding.rule_id}`}
          isOpen={Boolean(selectedFinding)}
          onClose={() => setSelectedFinding(null)}
        />
      )}
    </div>
  );
};
