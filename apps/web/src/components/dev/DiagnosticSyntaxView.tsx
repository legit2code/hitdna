import React, { useState, useEffect } from 'react';
import { 
  Code2, 
  Layers, 
  Cpu, 
  Settings, 
  Lock, 
  FileText, 
  Terminal, 
  CheckCircle2, 
  AlertTriangle, 
  XCircle, 
  Sparkles, 
  ShieldCheck, 
  Network, 
  Play, 
  RotateCw,
  Copy,
  Check,
  Binary,
  Workflow
} from 'lucide-react';

interface DiagnosticSyntaxViewProps {
  currentRole: string;
}

export const DiagnosticSyntaxView: React.FC<DiagnosticSyntaxViewProps> = ({ currentRole }) => {
  const [activeTab, setActiveTab] = useState<'inspector' | 'pipeline' | 'protocols' | 'frameworks' | 'config' | 'provenance'>('inspector');

  // Interactive Inspector state
  const [selectedFixture, setSelectedFixture] = useState<string>('mcp_agent');
  const [filePath, setFilePath] = useState<string>('agent/mcp_server.ts');
  const [sourceCode, setSourceCode] = useState<string>('');
  const [inspectResult, setInspectResult] = useState<any | null>(null);
  const [inspecting, setInspecting] = useState<boolean>(false);
  const [fixtures, setFixtures] = useState<Record<string, { path: string; content: string }>>({});
  const [copiedSpan, setCopiedSpan] = useState<string | null>(null);

  // Multi-file Pipeline state
  const [pipelineResult, setPipelineResult] = useState<any | null>(null);
  const [pipelineRunning, setPipelineRunning] = useState<boolean>(false);

  useEffect(() => {
    fetchSampleFixtures();
  }, []);

  const fetchSampleFixtures = async () => {
    try {
      const res = await fetch('/api/dev/syntax/sample-fixtures', {
        headers: { 'x-caim-role': currentRole },
      });
      if (res.ok) {
        const data = await res.json();
        setFixtures(data);
        if (data.mcp_agent) {
          setFilePath(data.mcp_agent.path);
          setSourceCode(data.mcp_agent.content);
        }
      }
    } catch (err) {
      console.error('Failed to load sample fixtures', err);
    }
  };

  const handleFixtureSelect = (key: string) => {
    setSelectedFixture(key);
    if (fixtures[key]) {
      setFilePath(fixtures[key].path);
      setSourceCode(fixtures[key].content);
      setInspectResult(null);
    }
  };

  const handleInspectFile = async () => {
    setInspecting(true);
    try {
      const res = await fetch('/api/dev/syntax/inspect-file', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-caim-role': currentRole,
        },
        body: JSON.stringify({ path: filePath, content: sourceCode }),
      });
      if (res.ok) {
        const data = await res.json();
        setInspectResult(data);
      }
    } catch (err) {
      console.error('Inspect file failed', err);
    } finally {
      setInspecting(false);
    }
  };

  const handleRunFullPipeline = async () => {
    setPipelineRunning(true);
    try {
      const files = Object.values(fixtures);
      const res = await fetch('/api/dev/syntax/process-artifact', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-caim-role': currentRole,
        },
        body: JSON.stringify({
          artifact_id: 'quarantined-agent-bundle-01',
          files,
        }),
      });
      if (res.ok) {
        const data = await res.json();
        setPipelineResult(data);
      }
    } catch (err) {
      console.error('Pipeline processing failed', err);
    } finally {
      setPipelineRunning(false);
    }
  };

  const copyToClipboard = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedSpan(id);
    setTimeout(() => setCopiedSpan(null), 2000);
  };

  return (
    <div className="space-y-6" id="diagnostic-syntax-root">
      {/* Header Bar */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 shadow-sm">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div className="flex items-center space-x-3">
            <div className="p-3 bg-indigo-950 border border-indigo-700/50 rounded-lg text-indigo-400">
              <Code2 className="w-6 h-6" />
            </div>
            <div>
              <h2 className="text-xl font-bold text-slate-100 flex items-center gap-2">
                Syntax, Protocol, Framework & Config Intelligence
                <span className="text-xs px-2.5 py-0.5 rounded-full bg-emerald-950 text-emerald-400 border border-emerald-800 font-mono">
                  P13 Active
                </span>
              </h2>
              <p className="text-sm text-slate-400 mt-1">
                Converts quarantined artifacts into structured source facts with exact line & column spans, protocol & framework telemetry, and cryptographic provenance.
              </p>
            </div>
          </div>
          <div className="flex items-center gap-3">
            <button
              onClick={handleRunFullPipeline}
              disabled={pipelineRunning}
              className="flex items-center gap-2 px-4 py-2 bg-indigo-600 hover:bg-indigo-500 text-white rounded-lg text-sm font-medium transition-colors disabled:opacity-50"
              id="run-bundle-pipeline-btn"
            >
              {pipelineRunning ? <RotateCw className="w-4 h-4 animate-spin" /> : <Play className="w-4 h-4" />}
              Process Artifact Bundle
            </button>
          </div>
        </div>

        {/* Tab Navigation */}
        <div className="flex items-center gap-2 mt-6 border-b border-slate-800 overflow-x-auto pb-px">
          {[
            { id: 'inspector', label: 'Interactive Inspector', icon: Terminal },
            { id: 'pipeline', label: 'Artifact Bundle Result', icon: Workflow },
            { id: 'protocols', label: 'Protocol Intelligence', icon: Network },
            { id: 'frameworks', label: 'Framework Fingerprinting', icon: Layers },
            { id: 'config', label: 'Config & Secret Extraction', icon: Settings },
            { id: 'provenance', label: 'Provenance & Invariants', icon: ShieldCheck },
          ].map((tab) => {
            const Icon = tab.icon;
            const isActive = activeTab === tab.id;
            return (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id as any)}
                className={`flex items-center gap-2 px-4 py-2.5 text-sm font-medium border-b-2 transition-colors whitespace-nowrap ${
                  isActive
                    ? 'border-indigo-500 text-indigo-400 bg-indigo-950/20'
                    : 'border-transparent text-slate-400 hover:text-slate-200 hover:border-slate-700'
                }`}
                id={`tab-${tab.id}`}
              >
                <Icon className="w-4 h-4" />
                {tab.label}
              </button>
            );
          })}
        </div>
      </div>

      {/* TAB 1: Interactive Inspector */}
      {activeTab === 'inspector' && (
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
          {/* Editor & Controls */}
          <div className="lg:col-span-6 space-y-4">
            <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-sm">
              <div className="flex items-center justify-between mb-4">
                <div className="flex items-center gap-2">
                  <Terminal className="w-4 h-4 text-indigo-400" />
                  <span className="text-sm font-semibold text-slate-200">Source Editor & Fixture Select</span>
                </div>
                <div className="flex items-center gap-2">
                  <select
                    value={selectedFixture}
                    onChange={(e) => handleFixtureSelect(e.target.value)}
                    className="bg-slate-800 border border-slate-700 text-slate-200 rounded-lg text-xs px-2.5 py-1.5 focus:outline-none focus:ring-1 focus:ring-indigo-500"
                    id="fixture-select"
                  >
                    <option value="mcp_agent">MCP Agent (TypeScript)</option>
                    <option value="python_agent">AutoGen & LangChain (Python)</option>
                    <option value="go_service">Gin Gateway (Go)</option>
                    <option value="dockerfile">Container (Dockerfile)</option>
                  </select>
                </div>
              </div>

              <div className="space-y-3">
                <div>
                  <label className="text-xs text-slate-400 block mb-1">File Path Virtual Virtual Location</label>
                  <input
                    type="text"
                    value={filePath}
                    onChange={(e) => setFilePath(e.target.value)}
                    className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs font-mono text-slate-200 focus:outline-none focus:border-indigo-500"
                    id="input-file-path"
                  />
                </div>

                <div>
                  <label className="text-xs text-slate-400 block mb-1">Quarantined Source Content</label>
                  <textarea
                    rows={16}
                    value={sourceCode}
                    onChange={(e) => setSourceCode(e.target.value)}
                    className="w-full bg-slate-950 border border-slate-800 rounded-lg p-3 text-xs font-mono text-slate-200 focus:outline-none focus:border-indigo-500 resize-none leading-relaxed"
                    id="textarea-source-content"
                  />
                </div>

                <div className="flex items-center justify-end gap-3 pt-2">
                  <button
                    onClick={handleInspectFile}
                    disabled={inspecting}
                    className="flex items-center gap-2 px-4 py-2 bg-indigo-600 hover:bg-indigo-500 text-white rounded-lg text-xs font-medium transition-colors disabled:opacity-50"
                    id="parse-file-btn"
                  >
                    {inspecting ? <RotateCw className="w-3.5 h-3.5 animate-spin" /> : <Sparkles className="w-3.5 h-3.5" />}
                    Parse & Extract Structured Facts
                  </button>
                </div>
              </div>
            </div>
          </div>

          {/* Facts Inspector Output */}
          <div className="lg:col-span-6 space-y-4">
            <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-sm min-h-[500px]">
              <div className="flex items-center justify-between mb-4 pb-3 border-b border-slate-800">
                <div className="flex items-center gap-2">
                  <Code2 className="w-4 h-4 text-emerald-400" />
                  <span className="text-sm font-semibold text-slate-200">Extracted AST & Semantic Source Facts</span>
                </div>
                {inspectResult && (
                  <span className={`text-xs px-2 py-0.5 rounded-full font-mono ${
                    inspectResult.status === 'SUCCESS' ? 'bg-emerald-950 text-emerald-400 border border-emerald-800' : 'bg-amber-950 text-amber-400 border border-amber-800'
                  }`}>
                    {inspectResult.status} ({Math.round(inspectResult.confidence * 100)}% Conf)
                  </span>
                )}
              </div>

              {!inspectResult ? (
                <div className="flex flex-col items-center justify-center py-20 text-slate-500">
                  <FileText className="w-10 h-10 mb-3 stroke-1 text-slate-600" />
                  <p className="text-sm">Click "Parse & Extract Structured Facts" to decompose code</p>
                  <p className="text-xs text-slate-600 mt-1">Extracts symbols, protocols, frameworks, environment vars, and exact spans</p>
                </div>
              ) : (
                <div className="space-y-4 overflow-y-auto max-h-[580px] pr-1">
                  {/* File Type & Detection */}
                  <div className="bg-slate-950/80 border border-slate-800/80 rounded-lg p-3">
                    <div className="text-xs font-semibold text-slate-300 mb-2 flex items-center justify-between">
                      <span>Encoding & Format Detection</span>
                      <span className="text-indigo-400 font-mono text-[11px]">{inspectResult.file_type.format_category}</span>
                    </div>
                    <div className="grid grid-cols-3 gap-2 text-xs font-mono">
                      <div className="bg-slate-900 p-2 rounded border border-slate-800">
                        <div className="text-[10px] text-slate-500">Language</div>
                        <div className="text-slate-200 truncate">{inspectResult.file_type.language}</div>
                      </div>
                      <div className="bg-slate-900 p-2 rounded border border-slate-800">
                        <div className="text-[10px] text-slate-500">Encoding</div>
                        <div className="text-slate-200">{inspectResult.file_type.encoding}</div>
                      </div>
                      <div className="bg-slate-900 p-2 rounded border border-slate-800">
                        <div className="text-[10px] text-slate-500">Byte Size</div>
                        <div className="text-slate-200">{inspectResult.file_type.byte_size} B</div>
                      </div>
                    </div>
                  </div>

                  {/* Symbols */}
                  <div className="bg-slate-950/80 border border-slate-800/80 rounded-lg p-3">
                    <div className="text-xs font-semibold text-slate-300 mb-2 flex items-center justify-between">
                      <span>Symbols & Declarations ({inspectResult.symbols.length})</span>
                    </div>
                    {inspectResult.symbols.length === 0 ? (
                      <div className="text-xs text-slate-500 italic">No top-level functions/classes declared</div>
                    ) : (
                      <div className="space-y-2 max-h-44 overflow-y-auto">
                        {inspectResult.symbols.map((sym: any, idx: number) => (
                          <div key={idx} className="bg-slate-900 p-2 rounded border border-slate-800 text-xs">
                            <div className="flex items-center justify-between">
                              <span className="font-mono font-medium text-amber-300">{sym.name}</span>
                              <span className="text-[10px] px-1.5 py-0.5 rounded bg-slate-800 text-slate-400 font-mono">{sym.kind}</span>
                            </div>
                            {sym.docstring && (
                              <p className="text-[11px] text-slate-400 mt-1 italic line-clamp-1">{sym.docstring}</p>
                            )}
                            <div className="mt-1.5 flex items-center justify-between text-[10px] text-slate-500 font-mono">
                              <span>Lines {sym.span.start_line}:{sym.span.start_column} - {sym.span.end_line}:{sym.span.end_column}</span>
                              <span className="text-slate-400">{sym.visibility}</span>
                            </div>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>

                  {/* Protocols Detected */}
                  <div className="bg-slate-950/80 border border-slate-800/80 rounded-lg p-3">
                    <div className="text-xs font-semibold text-slate-300 mb-2">
                      Protocols & Interfaces ({inspectResult.protocols.length})
                    </div>
                    {inspectResult.protocols.length === 0 ? (
                      <div className="text-xs text-slate-500 italic">No communication protocols detected</div>
                    ) : (
                      <div className="space-y-2">
                        {inspectResult.protocols.map((proto: any, idx: number) => (
                          <div key={idx} className="bg-slate-900 p-2.5 rounded border border-indigo-900/50 text-xs">
                            <div className="flex items-center justify-between font-semibold text-indigo-300">
                              <span>{proto.title}</span>
                              <span className="text-[10px] px-1.5 py-0.5 rounded bg-indigo-950 text-indigo-400 font-mono">{proto.protocol_kind}</span>
                            </div>
                            {proto.mcp_details && (
                              <div className="mt-2 text-[11px] text-slate-300 space-y-1">
                                <div>Role: <span className="font-mono text-emerald-400">{proto.mcp_details.role}</span></div>
                                <div>Transports: <span className="font-mono text-slate-400">{proto.mcp_details.transports?.join(', ')}</span></div>
                                <div>Tools: <span className="font-mono text-amber-300">{proto.mcp_details.tools?.map((t: any) => t.name).join(', ') || 'None'}</span></div>
                              </div>
                            )}
                          </div>
                        ))}
                      </div>
                    )}
                  </div>

                  {/* Frameworks Detected */}
                  <div className="bg-slate-950/80 border border-slate-800/80 rounded-lg p-3">
                    <div className="text-xs font-semibold text-slate-300 mb-2">
                      Frameworks Detected ({inspectResult.frameworks.length})
                    </div>
                    {inspectResult.frameworks.length === 0 ? (
                      <div className="text-xs text-slate-500 italic">No agent/backend frameworks detected</div>
                    ) : (
                      <div className="space-y-2">
                        {inspectResult.frameworks.map((fw: any, idx: number) => (
                          <div key={idx} className="bg-slate-900 p-2.5 rounded border border-slate-800 text-xs flex items-center justify-between">
                            <div>
                              <div className="font-semibold text-slate-200">{fw.framework_name}</div>
                              <div className="text-[10px] text-slate-400">{fw.framework_category}</div>
                            </div>
                            <div className="text-right">
                              <div className="text-[11px] font-mono text-emerald-400">{Math.round(fw.confidence * 100)}% Conf</div>
                              <div className="text-[10px] text-slate-500">{fw.evidence?.length} Evidence Items</div>
                            </div>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>

                  {/* Config & Environment */}
                  <div className="bg-slate-950/80 border border-slate-800/80 rounded-lg p-3">
                    <div className="text-xs font-semibold text-slate-300 mb-2">
                      Config & Environment References
                    </div>
                    <div className="grid grid-cols-2 gap-2 text-xs">
                      <div className="bg-slate-900 p-2 rounded border border-slate-800">
                        <div className="text-[10px] text-slate-500">Env Variables ({inspectResult.configuration?.env_vars?.length ?? 0})</div>
                        <div className="font-mono text-slate-300 mt-1 truncate">
                          {inspectResult.configuration?.env_vars?.map((e: any) => e.name).join(', ') || 'None'}
                        </div>
                      </div>
                      <div className="bg-slate-900 p-2 rounded border border-slate-800">
                        <div className="text-[10px] text-slate-500">Model References ({inspectResult.configuration?.models?.length ?? 0})</div>
                        <div className="font-mono text-slate-300 mt-1 truncate">
                          {inspectResult.configuration?.models?.map((m: any) => m.model_id).join(', ') || 'None'}
                        </div>
                      </div>
                    </div>
                  </div>
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {/* TAB 2: Artifact Bundle Pipeline */}
      {activeTab === 'pipeline' && (
        <div className="space-y-6">
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 shadow-sm">
            <div className="flex items-center justify-between mb-4">
              <div>
                <h3 className="text-base font-bold text-slate-100 flex items-center gap-2">
                  <Workflow className="w-5 h-5 text-indigo-400" />
                  Quarantined Multi-Language Artifact Bundle Execution
                </h3>
                <p className="text-xs text-slate-400 mt-1">
                  Processes heterogeneous artifacts (Python, TypeScript, Go, Dockerfile, requirements) across quarantine boundaries.
                </p>
              </div>
              <button
                onClick={handleRunFullPipeline}
                disabled={pipelineRunning}
                className="flex items-center gap-2 px-4 py-2 bg-indigo-600 hover:bg-indigo-500 text-white rounded-lg text-xs font-medium transition-colors disabled:opacity-50"
              >
                {pipelineRunning ? <RotateCw className="w-3.5 h-3.5 animate-spin" /> : <Play className="w-3.5 h-3.5" />}
                Run Full Bundle Execution
              </button>
            </div>

            {!pipelineResult ? (
              <div className="py-16 text-center text-slate-500">
                <Workflow className="w-10 h-10 mx-auto mb-2 stroke-1 text-slate-600" />
                <p className="text-sm">Click "Run Full Bundle Execution" to process the sample bundle</p>
              </div>
            ) : (
              <div className="space-y-6">
                {/* Aggregate Metrics Bar */}
                <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-7 gap-3">
                  <div className="bg-slate-950 p-3 rounded-lg border border-slate-800">
                    <div className="text-[10px] text-slate-500 uppercase tracking-wider">Total Files</div>
                    <div className="text-xl font-bold text-slate-100 font-mono mt-1">{pipelineResult.total_files}</div>
                  </div>
                  <div className="bg-slate-950 p-3 rounded-lg border border-slate-800">
                    <div className="text-[10px] text-slate-500 uppercase tracking-wider">Byte Coverage</div>
                    <div className="text-xl font-bold text-emerald-400 font-mono mt-1">
                      {Math.round(pipelineResult.byte_coverage_ratio * 100)}%
                    </div>
                  </div>
                  <div className="bg-slate-950 p-3 rounded-lg border border-slate-800">
                    <div className="text-[10px] text-slate-500 uppercase tracking-wider">Symbols</div>
                    <div className="text-xl font-bold text-indigo-400 font-mono mt-1">{pipelineResult.total_symbols}</div>
                  </div>
                  <div className="bg-slate-950 p-3 rounded-lg border border-slate-800">
                    <div className="text-[10px] text-slate-500 uppercase tracking-wider">Protocols</div>
                    <div className="text-xl font-bold text-cyan-400 font-mono mt-1">{pipelineResult.total_protocols}</div>
                  </div>
                  <div className="bg-slate-950 p-3 rounded-lg border border-slate-800">
                    <div className="text-[10px] text-slate-500 uppercase tracking-wider">Frameworks</div>
                    <div className="text-xl font-bold text-amber-400 font-mono mt-1">{pipelineResult.aggregate_frameworks?.length}</div>
                  </div>
                  <div className="bg-slate-950 p-3 rounded-lg border border-slate-800">
                    <div className="text-[10px] text-slate-500 uppercase tracking-wider">Env Variables</div>
                    <div className="text-xl font-bold text-purple-400 font-mono mt-1">{pipelineResult.total_env_vars}</div>
                  </div>
                  <div className="bg-slate-950 p-3 rounded-lg border border-slate-800">
                    <div className="text-[10px] text-slate-500 uppercase tracking-wider">Declared Tools</div>
                    <div className="text-xl font-bold text-pink-400 font-mono mt-1">{pipelineResult.total_tools}</div>
                  </div>
                </div>

                {/* File-by-File Breakdown Table */}
                <div className="bg-slate-950 border border-slate-800 rounded-lg overflow-hidden">
                  <div className="px-4 py-3 border-b border-slate-800 flex items-center justify-between">
                    <span className="text-xs font-semibold text-slate-300">File Decompositions ({pipelineResult.file_facts?.length})</span>
                    <span className="text-[11px] text-slate-500 font-mono">Artifact ID: {pipelineResult.artifact_id}</span>
                  </div>
                  <div className="overflow-x-auto">
                    <table className="w-full text-left text-xs">
                      <thead className="bg-slate-900/60 text-slate-400 border-b border-slate-800 font-medium">
                        <tr>
                          <th className="px-4 py-2.5">File Path</th>
                          <th className="px-3 py-2.5">Language / Format</th>
                          <th className="px-3 py-2.5">Status</th>
                          <th className="px-3 py-2.5">Parser</th>
                          <th className="px-3 py-2.5">Symbols</th>
                          <th className="px-3 py-2.5">Protocols</th>
                          <th className="px-3 py-2.5">Frameworks</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-slate-800/60">
                        {pipelineResult.file_facts?.map((ff: any, idx: number) => (
                          <tr key={idx} className="hover:bg-slate-900/30">
                            <td className="px-4 py-3 font-mono font-medium text-slate-200">{ff.file_path}</td>
                            <td className="px-3 py-3 text-slate-400">{ff.file_type.language} ({ff.file_type.format_category})</td>
                            <td className="px-3 py-3">
                              <span className={`px-2 py-0.5 rounded text-[10px] font-mono ${
                                ff.status === 'SUCCESS' ? 'bg-emerald-950 text-emerald-400 border border-emerald-800' : 'bg-amber-950 text-amber-400 border border-amber-800'
                              }`}>
                                {ff.status}
                              </span>
                            </td>
                            <td className="px-3 py-3 text-slate-400 font-mono text-[11px]">{ff.parser_id}</td>
                            <td className="px-3 py-3 text-amber-300 font-mono">{ff.symbols.length}</td>
                            <td className="px-3 py-3 text-cyan-300 font-mono">{ff.protocols.map((p: any) => p.protocol_kind).join(', ') || '-'}</td>
                            <td className="px-3 py-3 text-indigo-300 font-mono">{ff.frameworks.map((f: any) => f.framework_name).join(', ') || '-'}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              </div>
            )}
          </div>
        </div>
      )}

      {/* TAB 3: Protocols Explorer */}
      {activeTab === 'protocols' && (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-5">
          {[
            {
              name: 'Model Context Protocol (MCP)',
              status: 'Fully Supported',
              version: '2024-11-05',
              desc: 'Standardized client-server protocol for AI agent tool invocation, prompt templates, and resources.',
              features: ['Tool Schemas', 'Prompt Arguments', 'Resource URIs', 'Stdio/SSE Transports'],
            },
            {
              name: 'Agent-to-Agent (A2A)',
              status: 'Fully Supported',
              version: '1.0.0',
              desc: 'Peer-to-peer agent delegation, decentralized identity handshakes, and verifiable agent cards.',
              features: ['DID Handshakes', 'Task Delegation', 'Agent Cards', 'ED25519 Signatures'],
            },
            {
              name: 'OpenAPI & Swagger',
              status: 'Fully Supported',
              version: '3.0 / 3.1 / 2.0',
              desc: 'REST API path specifications, HTTP methods, operation IDs, and authentication schemas.',
              features: ['Path Route Matching', 'Operation IDs', 'Security Schemes', 'Parameter Types'],
            },
            {
              name: 'AsyncAPI',
              status: 'Fully Supported',
              version: '2.6 / 3.0',
              desc: 'Event-driven architecture specifications, message channels, and pub/sub bindings.',
              features: ['Channel Bindings', 'Event Schemas', 'Producer/Consumer Roles', 'Kafka/MQTT/WS'],
            },
            {
              name: 'gRPC & Protocol Buffers',
              status: 'Fully Supported',
              version: 'proto3 / proto2',
              desc: 'High-performance RPC service interfaces, message types, and bidirectional streaming.',
              features: ['Service Definitions', 'Streaming RPCs', 'Message Types', 'Package Namespaces'],
            },
            {
              name: 'JSON-RPC 2.0',
              status: 'Fully Supported',
              version: '2.0',
              desc: 'Lightweight JSON remote procedure call methods, request-response IDs, and notification dispatchers.',
              features: ['Method Registries', 'Notification Handlers', 'Batch Invocations', 'Error Formats'],
            },
          ].map((proto, idx) => (
            <div key={idx} className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-sm flex flex-col justify-between">
              <div>
                <div className="flex items-center justify-between mb-2">
                  <h4 className="text-sm font-bold text-slate-100">{proto.name}</h4>
                  <span className="text-[10px] px-2 py-0.5 rounded bg-indigo-950 text-indigo-400 border border-indigo-800 font-mono">
                    {proto.version}
                  </span>
                </div>
                <p className="text-xs text-slate-400 mb-4 leading-relaxed">{proto.desc}</p>
                <div className="space-y-1.5">
                  {proto.features.map((feat, fIdx) => (
                    <div key={fIdx} className="flex items-center gap-2 text-xs text-slate-300">
                      <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
                      <span>{feat}</span>
                    </div>
                  ))}
                </div>
              </div>
              <div className="mt-4 pt-3 border-t border-slate-800 flex items-center justify-between text-[11px] text-slate-500">
                <span>Coverage Status</span>
                <span className="text-emerald-400 font-medium">{proto.status}</span>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* TAB 4: Framework Fingerprinting */}
      {activeTab === 'frameworks' && (
        <div className="space-y-6">
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 shadow-sm">
            <h3 className="text-base font-bold text-slate-100 mb-2">Supported Agent & Backend Frameworks</h3>
            <p className="text-xs text-slate-400 mb-6">
              Deterministic AST and manifest dependency fingerprinting across agent orchestrators and backend runtimes.
            </p>

            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
              {[
                { name: 'LangChain / LangGraph', category: 'AGENT_FRAMEWORK', tech: 'Python / TypeScript', signals: 'Imports, ChatOpenAI, StateGraph, Chains' },
                { name: 'AutoGen', category: 'MULTI_AGENT', tech: 'Python', signals: 'ConversableAgent, UserProxyAgent, GroupChat' },
                { name: 'CrewAI', category: 'MULTI_AGENT', tech: 'Python', signals: 'Agent, Task, Crew, sequential process' },
                { name: 'LlamaIndex', category: 'AGENT_FRAMEWORK', tech: 'Python / TypeScript', signals: 'VectorStoreIndex, QueryEngine, Agents' },
                { name: 'Semantic Kernel', category: 'AGENT_FRAMEWORK', tech: 'Python / C#', signals: 'Kernel, sk_function, services' },
                { name: 'DSPy', category: 'LLM_ORCHESTRATOR', tech: 'Python', signals: 'dspy.Signature, dspy.Predict, CoT' },
                { name: 'Smolagents', category: 'AGENT_FRAMEWORK', tech: 'Python', signals: 'CodeAgent, ToolCallingAgent' },
                { name: 'FastAPI', category: 'BACKEND_WEB', tech: 'Python', signals: 'APIRouter, @app.get, @router.post' },
                { name: 'Gin', category: 'BACKEND_WEB', tech: 'Go', signals: 'gin.Default, r.POST, Context' },
                { name: 'NestJS / Express', category: 'BACKEND_WEB', tech: 'TypeScript / Node.js', signals: '@Controller, express(), app.use' },
              ].map((fw, idx) => (
                <div key={idx} className="bg-slate-950 p-4 rounded-lg border border-slate-800">
                  <div className="flex items-center justify-between mb-1">
                    <span className="text-sm font-semibold text-slate-200">{fw.name}</span>
                    <span className="text-[10px] px-2 py-0.5 rounded bg-slate-900 text-slate-400 font-mono">{fw.category}</span>
                  </div>
                  <div className="text-xs text-indigo-400 font-mono mb-2">{fw.tech}</div>
                  <div className="text-xs text-slate-400">
                    <span className="text-slate-500">Signatures: </span>{fw.signals}
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* TAB 5: Config & Secrets */}
      {activeTab === 'config' && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 shadow-sm space-y-4">
            <div className="flex items-center gap-2">
              <Settings className="w-5 h-5 text-indigo-400" />
              <h3 className="text-base font-bold text-slate-100">Configuration & Permissions Architecture</h3>
            </div>
            <p className="text-xs text-slate-400 leading-relaxed">
              Syntactically extracts environment variables, permission requests, tool definitions, and LLM model bindings without executing unverified code.
            </p>
            <div className="space-y-3">
              {[
                { cap: 'FILESYSTEM', desc: 'Direct filesystem I/O (fs.readFile, open(), os.mkdir)' },
                { cap: 'NETWORK', desc: 'Outbound HTTP requests (fetch, requests, axios, aiohttp)' },
                { cap: 'SUBPROCESS_EXEC', desc: 'OS process spawning (child_process, subprocess.run, exec)' },
                { cap: 'DATABASE', desc: 'Database connections (PostgreSQL, SQLite, Drizzle, Prisma)' },
                { cap: 'BROWSER_AUTOMATION', desc: 'Headless browsers (Playwright, Puppeteer, Selenium)' },
              ].map((item, idx) => (
                <div key={idx} className="bg-slate-950 p-3 rounded-lg border border-slate-800 flex items-center justify-between">
                  <div>
                    <div className="text-xs font-mono font-bold text-purple-400">{item.cap}</div>
                    <div className="text-[11px] text-slate-400">{item.desc}</div>
                  </div>
                  <span className="text-[10px] px-2 py-0.5 rounded bg-purple-950 text-purple-300 font-mono">AST Extracted</span>
                </div>
              ))}
            </div>
          </div>

          <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 shadow-sm space-y-4">
            <div className="flex items-center gap-2">
              <Lock className="w-5 h-5 text-amber-400" />
              <h3 className="text-base font-bold text-slate-100">Secret References & Vault Integration</h3>
            </div>
            <p className="text-xs text-slate-400 leading-relaxed">
              Detects API key tokens, certificates, and secret manager client invocations (AWS Secrets Manager, GCP Secret Manager, Azure Key Vault, HashiCorp Vault) with mandatory automatic masking.
            </p>
            <div className="bg-slate-950 p-4 rounded-lg border border-slate-800 space-y-3 text-xs">
              <div className="flex items-center justify-between border-b border-slate-800 pb-2">
                <span className="font-semibold text-slate-300">Secret Type</span>
                <span className="font-semibold text-slate-300">Masking Policy</span>
              </div>
              <div className="flex items-center justify-between font-mono">
                <span className="text-amber-300">OPENAI_API_KEY</span>
                <span className="text-slate-400">sk-proj-**** (Masked)</span>
              </div>
              <div className="flex items-center justify-between font-mono">
                <span className="text-amber-300">AWS_SECRET_ACCESS_KEY</span>
                <span className="text-slate-400">wJalrXU**** (Masked)</span>
              </div>
              <div className="flex items-center justify-between font-mono">
                <span className="text-amber-300">DATABASE_URL</span>
                <span className="text-slate-400">postgresql://user:****@host (Masked)</span>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* TAB 6: Provenance & Invariants */}
      {activeTab === 'provenance' && (
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 shadow-sm space-y-4">
          <div className="flex items-center gap-2">
            <ShieldCheck className="w-5 h-5 text-emerald-400" />
            <h3 className="text-base font-bold text-slate-100">Strict Non-Judgement & Exact Provenance Invariants</h3>
          </div>
          <p className="text-xs text-slate-400 leading-relaxed">
            The syntax intelligence layer adheres strictly to the CAIM isolation boundary:
          </p>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-4 pt-2">
            <div className="bg-slate-950 p-4 rounded-lg border border-slate-800">
              <div className="flex items-center gap-2 text-emerald-400 text-sm font-semibold mb-2">
                <CheckCircle2 className="w-4 h-4" />
                Zero Risk Judgments
              </div>
              <p className="text-xs text-slate-400 leading-relaxed">
                This layer strictly produces pure structured facts. No vulnerability scoring, policy gates, or risk classifications are emitted in syntax packages.
              </p>
            </div>

            <div className="bg-slate-950 p-4 rounded-lg border border-slate-800">
              <div className="flex items-center gap-2 text-emerald-400 text-sm font-semibold mb-2">
                <CheckCircle2 className="w-4 h-4" />
                Partial Coverage Tracking
              </div>
              <p className="text-xs text-slate-400 leading-relaxed">
                Parser failures or syntax errors become explicit partial coverage records with error locations, never hallucinated or fabricated facts.
              </p>
            </div>

            <div className="bg-slate-950 p-4 rounded-lg border border-slate-800">
              <div className="flex items-center gap-2 text-emerald-400 text-sm font-semibold mb-2">
                <CheckCircle2 className="w-4 h-4" />
                Exact Span Provenance
              </div>
              <p className="text-xs text-slate-400 leading-relaxed">
                Every extracted symbol, protocol, and configuration contains exact byte offsets and 1-indexed line/column spans tied to cryptographic input hashes.
              </p>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
