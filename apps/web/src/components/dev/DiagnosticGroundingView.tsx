import React, { useState, useEffect } from 'react';
import { 
  ShieldCheck, 
  ShieldAlert, 
  FileText, 
  CheckCircle2, 
  XCircle, 
  AlertTriangle, 
  Sparkles, 
  Database, 
  Layers, 
  Cpu, 
  Link2, 
  History, 
  RefreshCw, 
  Search,
  Code2,
  Lock,
  Eye,
  GitCompare
} from 'lucide-react';

interface DiagnosticGroundingViewProps {
  currentRole: string;
}

export const DiagnosticGroundingView: React.FC<DiagnosticGroundingViewProps> = ({ currentRole }) => {
  const [query, setQuery] = useState<string>('What critical vulnerabilities or code execution flows exist in agent agent-security-analyst-v1?');
  const [scopedAgentId, setScopedAgentId] = useState<string>('agent-security-analyst-v1');
  const [scopedVersionId, setScopedVersionId] = useState<string>('v1.0.0');
  const [callerRank, setCallerRank] = useState<number>(3); // SECRET rank
  const [callerVault, setCallerVault] = useState<boolean>(true);
  const [injectedDraft, setInjectedDraft] = useState<string>('');
  
  const [loading, setLoading] = useState<boolean>(false);
  const [synthesisResult, setSynthesisResult] = useState<any | null>(null);
  const [auditHistory, setAuditHistory] = useState<any[]>([]);
  const [activeTab, setActiveTab] = useState<'answer' | 'claims' | 'citations' | 'context' | 'audit'>('answer');
  const [error, setError] = useState<string | null>(null);

  const fetchAuditHistory = async () => {
    try {
      const res = await fetch('/api/dev/rag/audit-history', {
        headers: { 'X-Role': currentRole },
      });
      if (res.ok) {
        setAuditHistory(await res.json());
      }
    } catch {
      // Ignored
    }
  };

  useEffect(() => {
    fetchAuditHistory();
  }, []);

  const handleSynthesize = async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await fetch('/api/dev/rag/synthesize', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Role': currentRole,
        },
        body: JSON.stringify({
          query,
          scoped_agent_id: scopedAgentId || undefined,
          scoped_agent_version_id: scopedVersionId || undefined,
          injected_draft_for_testing: injectedDraft.trim() ? injectedDraft : undefined,
        }),
      });

      if (!res.ok) {
        const errData = await res.json().catch(() => ({}));
        throw new Error(errData.error || `HTTP ${res.status}`);
      }

      const data = await res.json();
      setSynthesisResult(data);
      fetchAuditHistory();
    } catch (err: any) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-6 font-mono">
      {/* Top Banner */}
      <div className="bg-slate-900 border border-slate-800 rounded-lg p-4 flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center space-x-2 text-cyan-400">
            <Sparkles className="w-5 h-5" />
            <h2 className="text-base font-bold tracking-tight">P24 RAG Context Assembly, Grounding & Citation Engine</h2>
          </div>
          <p className="text-xs text-slate-400 mt-1">
            Epistemic Abstention • Token Budgeting • Draft Claim Extraction • Machine-Resolvable Citations • Zero Fabrication
          </p>
        </div>
        <div className="flex items-center space-x-2">
          <button
            onClick={fetchAuditHistory}
            className="flex items-center space-x-1.5 px-3 py-1.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs transition"
          >
            <RefreshCw className="w-3.5 h-3.5" />
            <span>Refresh Audit</span>
          </button>
        </div>
      </div>

      {/* Query Formulation & Controls */}
      <div className="bg-slate-900/90 border border-slate-800 rounded-lg p-4 space-y-4">
        <div className="flex items-center justify-between">
          <label className="text-xs font-bold text-slate-300 flex items-center space-x-1.5">
            <Search className="w-4 h-4 text-cyan-400" />
            <span>RAG Query Input</span>
          </label>
          <div className="flex items-center space-x-2 text-xs">
            <span className="text-slate-400">Presets:</span>
            <button
              onClick={() => {
                setQuery('What critical vulnerabilities or code execution flows exist in agent agent-security-analyst-v1?');
                setInjectedDraft('');
              }}
              className="text-cyan-400 hover:underline"
            >
              Vuln / AST Flow
            </button>
            <span className="text-slate-600">•</span>
            <button
              onClick={() => {
                setQuery('Explain CVE-2026-44012 impact and CVSS severity score.');
                setInjectedDraft('');
              }}
              className="text-cyan-400 hover:underline"
            >
              CVE Lookup
            </button>
            <span className="text-slate-600">•</span>
            <button
              onClick={() => {
                setQuery('Is agent agent-security-analyst-v1 safe to deploy without changes?');
                setInjectedDraft('The agent is completely safe with no vulnerabilities found. [citation:vulnerability:CVE-2026-44012]');
              }}
              className="text-amber-400 hover:underline"
            >
              Contradiction Test
            </button>
            <span className="text-slate-600">•</span>
            <button
              onClick={() => {
                setQuery('What is the capital of Atlantis?');
                setInjectedDraft('');
              }}
              className="text-rose-400 hover:underline"
            >
              Abstain Test
            </button>
          </div>
        </div>

        <textarea
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          rows={2}
          placeholder="Enter inquiry..."
          className="w-full bg-slate-950 border border-slate-700 rounded p-2.5 text-xs text-slate-100 focus:outline-none focus:border-cyan-500 font-mono"
        />

        {/* Injected draft (optional for testing contradiction & claim extraction) */}
        <details className="text-xs text-slate-400">
          <summary className="cursor-pointer hover:text-cyan-300 font-semibold">
            Advanced: Override / Test Draft Text (for contradiction / claim pruning tests)
          </summary>
          <div className="mt-2 space-y-2">
            <textarea
              value={injectedDraft}
              onChange={(e) => setInjectedDraft(e.target.value)}
              rows={2}
              placeholder="Leave empty to let Gemini / Grounded Synthesizer generate answer, or paste custom draft with [citation:...] tags..."
              className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-xs text-slate-200 focus:outline-none focus:border-cyan-500 font-mono"
            />
          </div>
        </details>

        <div className="grid grid-cols-1 sm:grid-cols-4 gap-3 pt-2 border-t border-slate-800 text-xs">
          <div>
            <label className="text-slate-400 block mb-1">Clearance Rank</label>
            <select
              value={callerRank}
              onChange={(e) => setCallerRank(parseInt(e.target.value, 10))}
              className="w-full bg-slate-950 border border-slate-700 rounded px-2 py-1.5 text-slate-200"
            >
              <option value={0}>0 - PUBLIC_METADATA</option>
              <option value={1}>1 - INTERNAL</option>
              <option value={2}>2 - CONFIDENTIAL</option>
              <option value={3}>3 - SECRET</option>
              <option value={4}>4 - TOP_SECRET</option>
            </select>
          </div>

          <div>
            <label className="text-slate-400 block mb-1">Vault Access Grant</label>
            <button
              type="button"
              onClick={() => setCallerVault(!callerVault)}
              className={`w-full py-1.5 px-3 rounded flex items-center justify-center space-x-1.5 font-bold transition ${
                callerVault ? 'bg-amber-600/30 border border-amber-500 text-amber-300' : 'bg-slate-800 border border-slate-700 text-slate-400'
              }`}
            >
              <Lock className="w-3.5 h-3.5" />
              <span>{callerVault ? 'VAULT: GRANTED' : 'VAULT: BLOCKED'}</span>
            </button>
          </div>

          <div>
            <label className="text-slate-400 block mb-1">Scoped Agent ID</label>
            <input
              type="text"
              value={scopedAgentId}
              onChange={(e) => setScopedAgentId(e.target.value)}
              placeholder="e.g. agent-security-analyst-v1"
              className="w-full bg-slate-950 border border-slate-700 rounded px-2 py-1.5 text-slate-200"
            />
          </div>

          <div className="flex items-end">
            <button
              onClick={handleSynthesize}
              disabled={loading || !query.trim()}
              className="w-full py-2 bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white font-bold rounded flex items-center justify-center space-x-2 transition disabled:opacity-50 shadow"
            >
              {loading ? (
                <>
                  <RefreshCw className="w-4 h-4 animate-spin" />
                  <span>Synthesizing...</span>
                </>
              ) : (
                <>
                  <Sparkles className="w-4 h-4" />
                  <span>Execute RAG Pipeline</span>
                </>
              )}
            </button>
          </div>
        </div>

        {error && (
          <div className="bg-rose-950/50 border border-rose-800 rounded p-3 text-xs text-rose-300 flex items-center space-x-2">
            <AlertTriangle className="w-4 h-4 flex-shrink-0" />
            <span>Error: {error}</span>
          </div>
        )}
      </div>

      {/* Synthesis Result Display */}
      {synthesisResult && (
        <div className="space-y-4">
          {/* Epistemic Decision & Verdict Card */}
          <div className="bg-slate-900 border border-slate-800 rounded-lg p-5">
            <div className="flex flex-wrap items-center justify-between gap-3 border-b border-slate-800 pb-3">
              <div className="flex items-center space-x-3">
                <div
                  className={`px-3 py-1 rounded text-xs font-bold uppercase tracking-wider flex items-center space-x-1.5 ${
                    synthesisResult.epistemic_decision === 'ACCEPT'
                      ? 'bg-emerald-500/20 border border-emerald-500/40 text-emerald-400'
                      : synthesisResult.epistemic_decision === 'REMOVE_UNSUPPORTED'
                      ? 'bg-amber-500/20 border border-amber-500/40 text-amber-400'
                      : 'bg-rose-500/20 border border-rose-500/40 text-rose-400'
                  }`}
                >
                  {synthesisResult.epistemic_decision === 'ACCEPT' ? (
                    <CheckCircle2 className="w-4 h-4" />
                  ) : synthesisResult.epistemic_decision === 'REMOVE_UNSUPPORTED' ? (
                    <AlertTriangle className="w-4 h-4" />
                  ) : (
                    <XCircle className="w-4 h-4" />
                  )}
                  <span>Decision: {synthesisResult.epistemic_decision}</span>
                </div>

                <div className="px-2.5 py-1 rounded bg-slate-800 border border-slate-700 text-xs text-slate-300">
                  Grounding Verdict: <span className="font-bold text-cyan-300">{synthesisResult.grounding_verdict}</span>
                </div>
              </div>

              <div className="text-xs text-slate-400 flex items-center space-x-3">
                <span>Latency: <strong className="text-slate-200">{synthesisResult.audit.latency_ms}ms</strong></span>
                <span>•</span>
                <span>Context Hash: <code className="text-cyan-400">{synthesisResult.context_package.package_hash.substring(0, 10)}</code></span>
              </div>
            </div>

            {synthesisResult.abstention && (
              <div className="mt-3 bg-rose-950/40 border border-rose-800/60 rounded p-3 text-xs text-rose-200 flex items-start space-x-2">
                <ShieldAlert className="w-4 h-4 text-rose-400 flex-shrink-0 mt-0.5" />
                <div>
                  <div className="font-bold">EPISTEMIC ABSTENTION TRIGGERED</div>
                  <div className="text-rose-300/90 mt-0.5">{synthesisResult.abstention_reason}</div>
                </div>
              </div>
            )}

            {/* Final Answer Text */}
            <div className="mt-4 bg-slate-950 border border-slate-800 rounded-lg p-4">
              <div className="text-xs text-slate-400 font-semibold mb-2 flex items-center justify-between">
                <span className="flex items-center space-x-1.5">
                  <FileText className="w-4 h-4 text-cyan-400" />
                  <span>Grounding-Verified Answer</span>
                </span>
                <span className="text-[11px] text-slate-500 font-normal">
                  Citations Resolved: {synthesisResult.resolved_citations.length} valid / {synthesisResult.invalid_citations.length} rejected
                </span>
              </div>
              <div className="text-sm text-slate-100 leading-relaxed whitespace-pre-wrap font-sans">
                {synthesisResult.answer}
              </div>
            </div>
          </div>

          {/* Subnav Tabs */}
          <div className="flex border-b border-slate-800 space-x-2 text-xs">
            <button
              onClick={() => setActiveTab('answer')}
              className={`px-4 py-2 border-b-2 font-semibold transition ${
                activeTab === 'answer' ? 'border-cyan-500 text-cyan-400' : 'border-transparent text-slate-400 hover:text-slate-200'
              }`}
            >
              Draft vs Sanitized
            </button>
            <button
              onClick={() => setActiveTab('claims')}
              className={`px-4 py-2 border-b-2 font-semibold transition ${
                activeTab === 'claims' ? 'border-cyan-500 text-cyan-400' : 'border-transparent text-slate-400 hover:text-slate-200'
              }`}
            >
              Draft Claims ({synthesisResult.draft_claims.length})
            </button>
            <button
              onClick={() => setActiveTab('citations')}
              className={`px-4 py-2 border-b-2 font-semibold transition ${
                activeTab === 'citations' ? 'border-cyan-500 text-cyan-400' : 'border-transparent text-slate-400 hover:text-slate-200'
              }`}
            >
              Citations ({synthesisResult.resolved_citations.length + synthesisResult.invalid_citations.length})
            </button>
            <button
              onClick={() => setActiveTab('context')}
              className={`px-4 py-2 border-b-2 font-semibold transition ${
                activeTab === 'context' ? 'border-cyan-500 text-cyan-400' : 'border-transparent text-slate-400 hover:text-slate-200'
              }`}
            >
              Context Package ({synthesisResult.context_package.facts_count} facts)
            </button>
            <button
              onClick={() => setActiveTab('audit')}
              className={`px-4 py-2 border-b-2 font-semibold transition ${
                activeTab === 'audit' ? 'border-cyan-500 text-cyan-400' : 'border-transparent text-slate-400 hover:text-slate-200'
              }`}
            >
              Audit Log ({auditHistory.length})
            </button>
          </div>

          {/* Tab 1: Draft vs Final */}
          {activeTab === 'answer' && (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div className="bg-slate-900 border border-slate-800 rounded-lg p-4">
                <div className="text-xs font-bold text-slate-300 mb-2 flex items-center justify-between">
                  <span>Raw Draft Synthesis (Pre-Grounding)</span>
                  <span className="text-[10px] text-slate-500">Model: {synthesisResult.audit.model_name}</span>
                </div>
                <div className="bg-slate-950 border border-slate-800 rounded p-3 text-xs text-slate-300 leading-relaxed font-sans min-h-[160px]">
                  {synthesisResult.raw_draft_answer}
                </div>
              </div>

              <div className="bg-slate-900 border border-slate-800 rounded-lg p-4">
                <div className="text-xs font-bold text-slate-300 mb-2 flex items-center justify-between">
                  <span>Sanitized & Epistemically Revised Answer</span>
                  <span className="text-[10px] text-emerald-400">Status: PASS</span>
                </div>
                <div className="bg-slate-950 border border-emerald-900/40 rounded p-3 text-xs text-slate-100 leading-relaxed font-sans min-h-[160px]">
                  {synthesisResult.answer}
                </div>
              </div>
            </div>
          )}

          {/* Tab 2: Draft Claims */}
          {activeTab === 'claims' && (
            <div className="bg-slate-900 border border-slate-800 rounded-lg overflow-hidden">
              <div className="p-3 bg-slate-850 border-b border-slate-800 text-xs font-bold text-slate-300 flex items-center justify-between">
                <span>Extracted Propositional Claims & Grounding Matrix</span>
                <span className="text-[11px] text-slate-400">
                  Supported: {synthesisResult.grounded_claims.length} • Unsupported: {synthesisResult.unsupported_claims.length} • Contradicted: {synthesisResult.contradicted_claims.length}
                </span>
              </div>

              <div className="divide-y divide-slate-800">
                {synthesisResult.draft_claims.map((claim: any, idx: number) => (
                  <div key={idx} className="p-3.5 hover:bg-slate-850/50 transition flex items-start space-x-3 text-xs">
                    <div className="mt-0.5">
                      {claim.contradicted ? (
                        <XCircle className="w-4 h-4 text-rose-400" />
                      ) : claim.supported ? (
                        <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                      ) : (
                        <AlertTriangle className="w-4 h-4 text-amber-400" />
                      )}
                    </div>

                    <div className="flex-1 space-y-1.5">
                      <div className="text-slate-200 font-sans text-xs">{claim.statement}</div>

                      {claim.contradiction_reason && (
                        <div className="text-rose-400 text-[11px] bg-rose-950/30 p-2 rounded border border-rose-900/50">
                          Contradiction: {claim.contradiction_reason}
                        </div>
                      )}

                      <div className="flex flex-wrap items-center gap-2 text-[11px] text-slate-400">
                        <span className="px-1.5 py-0.5 rounded bg-slate-800 text-slate-300">
                          Grounding: {(claim.grounding_score * 100).toFixed(0)}%
                        </span>
                        <span className="px-1.5 py-0.5 rounded bg-slate-800 text-slate-300">
                          Substantive: {claim.is_substantive ? 'Yes' : 'No'}
                        </span>
                        {claim.supporting_fact_ids?.length > 0 && (
                          <span className="text-cyan-400">
                            Facts: {claim.supporting_fact_ids.join(', ')}
                          </span>
                        )}
                        {claim.supporting_evidence_ids?.length > 0 && (
                          <span className="text-indigo-400">
                            Evidence: {claim.supporting_evidence_ids.join(', ')}
                          </span>
                        )}
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Tab 3: Citations */}
          {activeTab === 'citations' && (
            <div className="space-y-4">
              <div className="bg-slate-900 border border-slate-800 rounded-lg p-4">
                <div className="text-xs font-bold text-slate-300 mb-3 flex items-center space-x-2">
                  <Link2 className="w-4 h-4 text-cyan-400" />
                  <span>Machine-Resolvable Citations (Rule: Never Fabricate Citation IDs)</span>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                  {synthesisResult.resolved_citations.map((c: any, i: number) => (
                    <div key={i} className="bg-slate-950 border border-emerald-900/50 rounded p-3 text-xs space-y-1">
                      <div className="flex items-center justify-between">
                        <code className="text-emerald-400 font-bold">{c.citation_raw}</code>
                        <span className="px-1.5 py-0.5 rounded bg-emerald-500/20 text-emerald-300 text-[10px] font-bold">
                          RESOLVED
                        </span>
                      </div>
                      <div className="text-slate-300 text-[11px]">Target: {c.target_type} ({c.target_id})</div>
                      {c.resolved_summary && (
                        <div className="text-slate-400 text-[11px]">{c.resolved_summary}</div>
                      )}
                    </div>
                  ))}

                  {synthesisResult.invalid_citations.map((c: any, i: number) => (
                    <div key={i} className="bg-slate-950 border border-rose-900/60 rounded p-3 text-xs space-y-1">
                      <div className="flex items-center justify-between">
                        <code className="text-rose-400 font-bold">{c.citation_raw}</code>
                        <span className="px-1.5 py-0.5 rounded bg-rose-500/20 text-rose-300 text-[10px] font-bold">
                          REJECTED / FABRICATED
                        </span>
                      </div>
                      <div className="text-rose-300 text-[11px]">Reason: {c.rejection_reason}</div>
                    </div>
                  ))}

                  {synthesisResult.resolved_citations.length === 0 && synthesisResult.invalid_citations.length === 0 && (
                    <div className="text-slate-500 text-xs py-4 col-span-2 text-center">
                      No citation tags present in the final output.
                    </div>
                  )}
                </div>
              </div>
            </div>
          )}

          {/* Tab 4: Context Package */}
          {activeTab === 'context' && (
            <div className="bg-slate-900 border border-slate-800 rounded-lg p-4 space-y-4">
              <div className="flex flex-wrap items-center justify-between gap-2 border-b border-slate-800 pb-3 text-xs">
                <div className="flex items-center space-x-2">
                  <Database className="w-4 h-4 text-cyan-400" />
                  <span className="font-bold text-slate-200">Assembled Context Package</span>
                </div>
                <div className="flex items-center space-x-4 text-slate-400">
                  <span>Tokens Est: <strong className="text-slate-200">{synthesisResult.context_package.total_tokens_estimated}</strong></span>
                  <span>Budget Util: <strong className="text-cyan-400">{(synthesisResult.context_package.budget_utilization_ratio * 100).toFixed(1)}%</strong></span>
                  <span>Deduplicated: <strong className="text-emerald-400">{synthesisResult.context_package.redundant_facts_pruned}</strong></span>
                </div>
              </div>

              {/* Version Groups */}
              {synthesisResult.context_package.version_groups?.length > 0 && (
                <div className="space-y-2">
                  <div className="text-xs font-bold text-slate-300 flex items-center space-x-1.5">
                    <GitCompare className="w-3.5 h-3.5 text-indigo-400" />
                    <span>Version & Temporal Grouping</span>
                  </div>
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                    {synthesisResult.context_package.version_groups.map((vg: any, idx: number) => (
                      <div key={idx} className="bg-slate-950 border border-slate-800 rounded p-2.5 text-xs">
                        <div className="font-bold text-indigo-300">
                          {vg.agent_id} @ {vg.agent_version_id}
                        </div>
                        <div className="text-slate-400 text-[11px] mt-1">
                          Runs: {vg.runs?.length || 0} • Unassigned facts: {vg.unassigned_facts?.length || 0}
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Isolated Prompt Sandbox */}
              <div>
                <div className="text-xs font-bold text-slate-300 mb-1 flex items-center space-x-1.5">
                  <Code2 className="w-3.5 h-3.5 text-amber-400" />
                  <span>Isolated Prompt Sandbox (Instruction vs Data Separation)</span>
                </div>
                <pre className="bg-slate-950 border border-slate-800 rounded p-3 text-[11px] text-slate-300 overflow-x-auto max-h-72 font-mono">
                  {synthesisResult.context_package.isolated_prompt_context}
                </pre>
              </div>
            </div>
          )}

          {/* Tab 5: Audit History */}
          {activeTab === 'audit' && (
            <div className="bg-slate-900 border border-slate-800 rounded-lg overflow-hidden">
              <div className="p-3 bg-slate-850 border-b border-slate-800 text-xs font-bold text-slate-300">
                Answer Audit History Logs
              </div>
              <div className="overflow-x-auto">
                <table className="w-full text-xs text-left">
                  <thead className="bg-slate-950 text-slate-400 border-b border-slate-800">
                    <tr>
                      <th className="p-2.5">Audit ID</th>
                      <th className="p-2.5">Query</th>
                      <th className="p-2.5">Decision</th>
                      <th className="p-2.5">Verdict</th>
                      <th className="p-2.5">Claims</th>
                      <th className="p-2.5">Citations</th>
                      <th className="p-2.5">Latency</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800">
                    {auditHistory.map((item, idx) => (
                      <tr key={idx} className="hover:bg-slate-850/50">
                        <td className="p-2.5 font-mono text-cyan-400">{item.audit_id}</td>
                        <td className="p-2.5 text-slate-300 max-w-xs truncate">{item.query}</td>
                        <td className="p-2.5">
                          <span
                            className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${
                              item.epistemic_decision === 'ACCEPT'
                                ? 'bg-emerald-500/20 text-emerald-300'
                                : item.epistemic_decision === 'REMOVE_UNSUPPORTED'
                                ? 'bg-amber-500/20 text-amber-300'
                                : 'bg-rose-500/20 text-rose-300'
                            }`}
                          >
                            {item.epistemic_decision}
                          </span>
                        </td>
                        <td className="p-2.5 text-slate-400">{item.grounding_verdict}</td>
                        <td className="p-2.5 text-slate-300">
                          {item.grounded_claims_count}/{item.draft_claims_count}
                        </td>
                        <td className="p-2.5 text-slate-300">
                          {item.valid_citations_count} valid
                        </td>
                        <td className="p-2.5 text-slate-400">{item.latency_ms}ms</td>
                      </tr>
                    ))}
                    {auditHistory.length === 0 && (
                      <tr>
                        <td colSpan={7} className="p-4 text-center text-slate-500">
                          No audit entries recorded yet.
                        </td>
                      </tr>
                    )}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
};
