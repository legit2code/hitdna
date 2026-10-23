import React, { useState, useEffect } from 'react';
import { 
  Sparkles, 
  Search, 
  Send, 
  ShieldCheck, 
  ShieldAlert, 
  FileText, 
  CheckCircle2, 
  XCircle, 
  AlertTriangle, 
  Database, 
  Layers, 
  Cpu, 
  Link2, 
  ExternalLink, 
  Clock, 
  RefreshCw, 
  Code2, 
  Lock, 
  Eye, 
  ChevronRight,
  Filter,
  Share2
} from 'lucide-react';
import { FieldHelpTooltip } from '../common/Affordances.tsx';
import { authenticatedFetch } from '../../lib/authClient.ts';

interface KnowledgeWorkflowViewProps {
  currentRole: string;
  initialQuery?: string;
  onNavigateToWorkflow?: (workflow: string, params?: any) => void;
}

export const KnowledgeWorkflowView: React.FC<KnowledgeWorkflowViewProps> = ({ currentRole, initialQuery, onNavigateToWorkflow }) => {
  const [query, setQuery] = useState<string>(initialQuery || 'What critical vulnerabilities, egress flows, or unparameterized queries exist in agent financial analyst?');
  const [scopedAgentId, setScopedAgentId] = useState<string>('agent-financial-analyst');
  const [scopedVersionId, setScopedVersionId] = useState<string>('v1.0.0');
  const [callerRank, setCallerRank] = useState<number>(3); // SECRET rank
  const [callerVault, setCallerVault] = useState<boolean>(true);
  
  const [loading, setLoading] = useState<boolean>(false);
  const [synthesisResult, setSynthesisResult] = useState<any | null>(null);
  const [activeTab, setActiveTab] = useState<'answer' | 'citations' | 'claims' | 'evidence' | 'projections'>('answer');
  const [error, setError] = useState<string | null>(null);
  const [selectedCitation, setSelectedCitation] = useState<any | null>(null);

  // Auto-run initial query if provided
  useEffect(() => {
    if (initialQuery) {
      handleSynthesize();
    }
  }, [initialQuery]);

  const handleSynthesize = async () => {
    if (!query.trim()) return;
    setLoading(true);
    setError(null);
    try {
      const res = await authenticatedFetch('/api/dev/rag/synthesize', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          query,
          scoped_agent_id: scopedAgentId || undefined,
          scoped_agent_version_id: scopedVersionId || undefined,
        }),
      });

      if (!res.ok) {
        const errData = await res.json().catch(() => ({}));
        throw new Error(errData.error || `HTTP ${res.status}`);
      }

      const data = await res.json();
      setSynthesisResult(data);
    } catch (err: any) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-6 font-sans">
      {/* Top Banner */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-sm">
        <div className="flex items-center space-x-3.5">
          <div className="h-11 w-11 rounded-xl bg-amber-500/10 border border-amber-500/30 flex items-center justify-center text-amber-400">
            <Sparkles className="h-6 w-6" />
          </div>
          <div>
            <div className="flex items-center space-x-2.5">
              <h1 className="text-lg font-bold text-slate-100 tracking-tight">Grounded Knowledge & Conversational RAG Engine</h1>
              <span className="px-2 py-0.5 rounded text-[11px] font-mono font-semibold bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                P22-P24 Synthesis Active
              </span>
              <FieldHelpTooltip customTitle="Grounded Knowledge RAG" customDescription="Epistemically grounded question answering requiring explicit citation spans, preventing hallucinations by rejecting unverified inferences." />
            </div>
            <p className="text-xs text-slate-400 mt-0.5">
              Ask natural language security questions with citation verifications, epistemic grounding, and scope filters.
            </p>
          </div>
        </div>

        <div className="flex items-center space-x-2.5">
          <button
            onClick={() => onNavigateToWorkflow?.('evidence')}
            className="flex items-center space-x-1.5 px-3.5 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 text-xs font-mono transition-colors"
          >
            <Share2 className="w-3.5 h-3.5 text-cyan-400" />
            <span>Evidence Graph</span>
          </button>
        </div>
      </div>

      {/* Query Bar & Scope Controls */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-4">
        <div className="flex flex-col sm:flex-row items-stretch sm:items-center gap-2">
          <div className="relative flex-1">
            <Search className="w-4 h-4 text-slate-500 absolute left-3.5 top-3" />
            <input
              type="text"
              placeholder="Ask any question about agent code, taint paths, sandbox execution, CVEs, or policy status..."
              value={query}
              onChange={e => setQuery(e.target.value)}
              onKeyDown={e => e.key === 'Enter' && handleSynthesize()}
              className="w-full bg-slate-950 border border-slate-800 rounded-xl pl-10 pr-4 py-2.5 text-xs text-slate-100 placeholder-slate-500 focus:outline-none focus:border-amber-500 font-mono shadow-inner"
            />
          </div>

          <button
            onClick={handleSynthesize}
            disabled={loading}
            className="flex items-center justify-center space-x-2 px-5 py-2.5 rounded-xl bg-amber-600 hover:bg-amber-500 text-white text-xs font-semibold shadow-md transition-colors disabled:opacity-50"
          >
            <Send className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
            <span>{loading ? 'Synthesizing...' : 'Run Query'}</span>
          </button>
        </div>

        {/* Scope & Boundary Configuration */}
        <div className="grid grid-cols-1 sm:grid-cols-4 gap-3 pt-3 border-t border-slate-800/80 font-mono text-xs">
          <div>
            <label className="text-slate-500 text-[10px] block mb-1">Scoped Agent</label>
            <select
              value={scopedAgentId}
              onChange={e => setScopedAgentId(e.target.value)}
              className="w-full bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-1.5 text-slate-300 text-xs focus:outline-none focus:border-amber-500"
            >
              <option value="">All Agents (Global)</option>
              <option value="agent-financial-analyst">agent-financial-analyst</option>
              <option value="agent-research-crawler">agent-research-crawler</option>
              <option value="agent-system-diagnostics">agent-system-diagnostics</option>
            </select>
          </div>

          <div>
            <label className="text-slate-500 text-[10px] block mb-1">Scoped Version</label>
            <input
              type="text"
              value={scopedVersionId}
              onChange={e => setScopedVersionId(e.target.value)}
              placeholder="e.g. v1.0.0"
              className="w-full bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-1.5 text-slate-300 text-xs focus:outline-none focus:border-amber-500 font-mono"
            />
          </div>

          <div>
            <label className="text-slate-500 text-[10px] block mb-1">Clearance Rank</label>
            <select
              value={callerRank}
              onChange={e => setCallerRank(Number(e.target.value))}
              className="w-full bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-1.5 text-slate-300 text-xs focus:outline-none focus:border-amber-500"
            >
              <option value={0}>PUBLIC_METADATA (0)</option>
              <option value={1}>INTERNAL (1)</option>
              <option value={2}>CONFIDENTIAL (2)</option>
              <option value={3}>SECRET (3)</option>
              <option value={4}>VAULT_RESTRICTED (4)</option>
            </select>
          </div>

          <div>
            <label className="text-slate-500 text-[10px] block mb-1">Vault Clearance</label>
            <div className="flex items-center space-x-2 pt-1.5">
              <input
                type="checkbox"
                id="vaultAccessCheck"
                checked={callerVault}
                onChange={e => setCallerVault(e.target.checked)}
                className="rounded border-slate-800 bg-slate-950 text-amber-500 focus:ring-amber-500 h-4 w-4"
              />
              <label htmlFor="vaultAccessCheck" className="text-xs text-slate-300">
                Grant Vault Read Access
              </label>
            </div>
          </div>
        </div>
      </div>

      {error && (
        <div className="p-4 rounded-xl bg-rose-950/40 border border-rose-500/30 text-rose-300 text-xs font-mono flex items-center space-x-2">
          <XCircle className="w-4 h-4 text-rose-400 shrink-0" />
          <span>Synthesis Error: {error}</span>
        </div>
      )}

      {/* Synthesis Results Display */}
      {synthesisResult && (
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-5">
          {/* Grounding Status Header */}
          <div className="flex flex-wrap items-center justify-between gap-3 border-b border-slate-800 pb-4">
            <div className="flex items-center space-x-3">
              <span className={`px-2.5 py-1 rounded-lg text-xs font-mono font-bold flex items-center space-x-1.5 ${
                synthesisResult.verdict === 'GROUNDED' ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30' :
                synthesisResult.verdict === 'PARTIAL_REFUSAL' ? 'bg-amber-500/20 text-amber-400 border border-amber-500/30' :
                'bg-rose-500/20 text-rose-400 border border-rose-500/30'
              }`}>
                {synthesisResult.verdict === 'GROUNDED' ? <CheckCircle2 className="w-3.5 h-3.5" /> : <AlertTriangle className="w-3.5 h-3.5" />}
                <span>VERDICT: {synthesisResult.verdict}</span>
              </span>

              <span className="text-xs font-mono text-slate-400">
                Grounding Score: <strong className="text-slate-200">{typeof synthesisResult.grounding_score === 'number' ? `${Math.round(synthesisResult.grounding_score * 100)}%` : 'NOT_CALCULATED'}</strong>
              </span>
            </div>

            <div className="flex items-center space-x-2 text-xs font-mono text-slate-400">
              <span>Citations: <strong className="text-cyan-400">{synthesisResult.citations?.length || 0}</strong></span>
              <span>•</span>
              <span>Claims: <strong className="text-emerald-400">{synthesisResult.verified_claims?.length || 0}</strong></span>
            </div>
          </div>

          {/* Navigation Tabs */}
          <div className="flex items-center space-x-1 border-b border-slate-800 pb-2 text-xs font-mono">
            <button
              onClick={() => setActiveTab('answer')}
              className={`px-3 py-1.5 rounded-lg font-medium transition-colors ${
                activeTab === 'answer' ? 'bg-amber-600 text-white' : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800'
              }`}
            >
              Synthesized Answer
            </button>
            <button
              onClick={() => setActiveTab('citations')}
              className={`px-3 py-1.5 rounded-lg font-medium transition-colors ${
                activeTab === 'citations' ? 'bg-amber-600 text-white' : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800'
              }`}
            >
              Citations ({synthesisResult.citations?.length || 0})
            </button>
            <button
              onClick={() => setActiveTab('claims')}
              className={`px-3 py-1.5 rounded-lg font-medium transition-colors ${
                activeTab === 'claims' ? 'bg-amber-600 text-white' : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800'
              }`}
            >
              Extracted Claims ({synthesisResult.verified_claims?.length || 0})
            </button>
          </div>

          {/* Tab 1: Synthesized Answer */}
          {activeTab === 'answer' && (
            <div className="space-y-4">
              <div className="bg-slate-950 p-5 rounded-xl border border-slate-800 leading-relaxed text-slate-200 text-xs whitespace-pre-wrap font-sans">
                {synthesisResult.answer || synthesisResult.synthesized_response || 'No answer generated.'}
              </div>

              {synthesisResult.abstentions && synthesisResult.abstentions.length > 0 && (
                <div className="bg-amber-950/20 border border-amber-500/30 p-4 rounded-xl space-y-2 text-xs">
                  <div className="flex items-center space-x-2 text-amber-400 font-mono font-semibold">
                    <AlertTriangle className="w-4 h-4" />
                    <span>Grounding Abstention & Refusal Transparency</span>
                  </div>
                  <ul className="list-disc list-inside text-amber-200/90 text-xs space-y-1 font-mono">
                    {synthesisResult.abstentions.map((item: any, i: number) => (
                      <li key={i}>{typeof item === 'string' ? item : item.reason || JSON.stringify(item)}</li>
                    ))}
                  </ul>
                </div>
              )}
            </div>
          )}

          {/* Tab 2: Citations */}
          {activeTab === 'citations' && (
            <div className="space-y-3">
              {(synthesisResult.citations || []).map((cit: any, idx: number) => (
                <div
                  key={idx}
                  onClick={() => setSelectedCitation(cit)}
                  className="bg-slate-950 p-4 rounded-xl border border-slate-800 hover:border-slate-700 transition-colors cursor-pointer space-y-2 text-xs"
                >
                  <div className="flex items-center justify-between font-mono">
                    <span className="text-cyan-400 font-semibold flex items-center space-x-1.5">
                      <Link2 className="w-3.5 h-3.5" />
                      <span>[{idx + 1}] {cit.source_locator || cit.document_id || `Citation-${idx + 1}`}</span>
                    </span>
                    <span className="text-emerald-400 text-[11px]">
                      Confidence: {typeof cit.confidence === 'number' ? `${Math.round(cit.confidence * 100)}%` : 'NOT_CALCULATED'}
                    </span>
                  </div>
                  <p className="text-slate-300 text-xs font-sans leading-relaxed">{cit.snippet || cit.text}</p>
                </div>
              ))}
            </div>
          )}

          {/* Tab 3: Claims */}
          {activeTab === 'claims' && (
            <div className="space-y-3">
              {(synthesisResult.verified_claims || []).map((clm: any, idx: number) => (
                <div key={idx} className="bg-slate-950 p-4 rounded-xl border border-slate-800 flex items-start justify-between gap-3 text-xs">
                  <div className="space-y-1">
                    <span className="text-emerald-400 font-mono text-[11px] font-semibold">{clm.claim_id || `CLM-${idx + 1}`}</span>
                    <p className="text-slate-200 text-xs font-sans">{clm.statement || clm.claim_text}</p>
                  </div>
                  <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-emerald-500/20 text-emerald-400 font-semibold shrink-0">
                    VERIFIED
                  </span>
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
};
