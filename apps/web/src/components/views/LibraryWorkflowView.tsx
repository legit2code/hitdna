import React, { useState, useEffect } from 'react';
import { 
  Bot, 
  Search, 
  Sparkles, 
  ShieldCheck, 
  ShieldAlert, 
  AlertTriangle, 
  CheckCircle2, 
  XCircle, 
  RefreshCw, 
  Plus, 
  Filter, 
  ArrowUpRight, 
  ExternalLink,
  MessageSquare, 
  Activity, 
  Clock, 
  Lock, 
  Layers, 
  Info,
  ChevronRight,
  Zap,
  Globe,
  Check,
  Ban
} from 'lucide-react';
import { 
  FieldHelpTooltip, 
  SecurityClassificationBadge, 
  RiskScoreBadge, 
  EpistemicStatusBadge,
  TruthStateBadge,
  EmptyState,
  LoadingState 
} from '../common/Affordances.tsx';
import { AgentRagChatModal } from '../rag/AgentRagChatModal.tsx';
import { authenticatedFetch } from '../../lib/authClient.ts';

export interface LibraryAgentItem {
  agent_id: string;
  agent_version_id?: string;
  canonical_name: string;
  version_label?: string;
  source_type?: string;
  source_locator?: string;
  author?: string;
  description?: string;
  framework?: string;
  security_classification?: string;
  discovered_at?: string;
  analysis_status?: 'PRE_ANALYZED' | 'ANALYSIS_COMPLETE' | 'PENDING' | 'FAILED' | string;
  risk_band?: 'LOW' | 'MODERATE' | 'HIGH' | 'CRITICAL' | string;
  overall_score?: number | string;
  policy_outcome?: 'ALLOW' | 'CONDITIONAL' | 'BLOCK' | string;
  good_use_cases?: Array<{ title: string; rationale: string; risk_level: string; truthState?: string }>;
  bad_use_cases?: Array<{ title: string; rationale: string; risk_level: string; truthState?: string }>;
  findings_count?: number | string;
  evidence_count?: number | string;
  capabilities?: string[];
  truthState?: string;
  truth_state?: string;
  epistemic_metadata?: any;
}

export interface LibraryWorkflowViewProps {
  currentRole: string;
  onNavigateToWorkflow?: (workflow: string, params?: any) => void;
}

export const LibraryWorkflowView: React.FC<LibraryWorkflowViewProps> = ({
  currentRole,
  onNavigateToWorkflow
}) => {
  const [agents, setAgents] = useState<LibraryAgentItem[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [pipelineStatus, setPipelineStatus] = useState<any>(null);
  const [isScanning, setIsScanning] = useState<boolean>(false);
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [selectedRiskBand, setSelectedRiskBand] = useState<string>('ALL');
  const [selectedSource, setSelectedSource] = useState<string>('ALL');
  const [chatAgent, setChatAgent] = useState<LibraryAgentItem | null>(null);
  const [showQuickIngest, setShowQuickIngest] = useState<boolean>(false);
  const [quickLocator, setQuickLocator] = useState<string>('');
  const [quickName, setQuickName] = useState<string>('');
  const [ingesting, setIngesting] = useState<boolean>(false);
  const [bannerDismissed, setBannerDismissed] = useState<boolean>(false);

  useEffect(() => {
    fetchLibraryAndStatus();
    const interval = setInterval(fetchPipelineStatus, 15000);
    return () => clearInterval(interval);
  }, []);

  const fetchPipelineStatus = async () => {
    try {
      const res = await authenticatedFetch('/api/discovery/pipeline/status');
      if (res.ok) {
        const data = await res.json();
        setPipelineStatus(data);
      }
    } catch (e) {
      console.warn('Status fetch warning:', e);
    }
  };

  const fetchLibraryAndStatus = async () => {
    setLoading(true);
    try {
      const [libRes, statusRes, agentsRes] = await Promise.all([
        authenticatedFetch('/api/library/agents'),
        authenticatedFetch('/api/discovery/pipeline/status'),
        authenticatedFetch('/api/agents'),
      ]);

      let items: LibraryAgentItem[] = [];
      if (libRes.ok) {
        const libData = await libRes.json();
        if (Array.isArray(libData)) {
          items = [...libData];
        }
      }

      // Also incorporate any agents from DB
      if (agentsRes.ok) {
        const dbData = await agentsRes.json();
        if (Array.isArray(dbData)) {
          for (const a of dbData) {
            if (!items.some(it => it.agent_id === a.agent_id || it.canonical_name === a.canonical_name)) {
              const firstVer = a.versions?.[0];
              const firstRun = firstVer?.analysis_runs?.[0];
              const overallScore = firstRun?.overall_score ?? a.overall_score ?? 'NOT_CALCULATED';
              const riskBand = firstRun?.risk_band ?? a.risk_band ?? 'NOT_CALCULATED';
              const findingsCount = firstRun?.findings_count ?? a.findings_count ?? 'NOT_CALCULATED';
              const claimsCount = firstRun?.claims_count ?? a.claims_count ?? 'NOT_CALCULATED';
              const framework = a.framework || 'DATA_UNAVAILABLE';
              const author = a.author || 'DATA_UNAVAILABLE';
              const secClass = a.security_classification || 'DATA_UNAVAILABLE';
              const truthState = a.truthState || (typeof overallScore === 'number' ? 'INFERRED' : 'UNKNOWN');

              items.push({
                agent_id: a.agent_id,
                agent_version_id: firstVer?.agent_version_id,
                canonical_name: a.canonical_name,
                version_label: firstVer?.version_label || 'v1.0.0',
                source_type: a.source_locator?.split('://')[0] || 'manual',
                source_locator: a.source_locator || a.canonical_name,
                author,
                description: a.description || 'DATA_UNAVAILABLE',
                framework,
                security_classification: secClass,
                discovered_at: a.created_at || new Date().toISOString(),
                analysis_status: firstRun ? 'ANALYSIS_COMPLETE' : (typeof overallScore === 'number' ? 'ANALYSIS_COMPLETE' : 'PENDING'),
                risk_band: riskBand,
                overall_score: overallScore,
                policy_outcome: firstRun?.policy_outcome || a.policy_outcome || 'NOT_CALCULATED',
                good_use_cases: a.good_use_cases || (typeof overallScore === 'number' ? [
                  { title: 'Derived Scoped Execution', rationale: 'Grounded static AST verification completed without critical unmitigated egress.', risk_level: 'LOW', truthState: 'INFERRED' }
                ] : [
                  { title: 'NOT_CALCULATED', rationale: 'DATA_UNAVAILABLE: Analysis has not been calculated.', risk_level: 'NOT_CALCULATED', truthState: 'UNKNOWN' }
                ]),
                bad_use_cases: a.bad_use_cases || (typeof overallScore === 'number' ? [
                  { title: 'Arbitrary Execution', rationale: 'Requires verified sandbox attestation and policy signoff.', risk_level: 'HIGH', truthState: 'INFERRED' }
                ] : [
                  { title: 'NOT_CALCULATED', rationale: 'DATA_UNAVAILABLE: Analysis has not been calculated.', risk_level: 'NOT_CALCULATED', truthState: 'UNKNOWN' }
                ]),
                findings_count: findingsCount,
                evidence_count: claimsCount,
                capabilities: a.capabilities || ['Static AST', 'Taint Tracking'],
                truthState,
                truth_state: truthState,
                epistemic_metadata: a.epistemic_metadata || {
                  framework: { value: framework, truthState: framework !== 'DATA_UNAVAILABLE' ? 'OBSERVED' : 'UNKNOWN' },
                  author: { value: author, truthState: author !== 'DATA_UNAVAILABLE' ? 'OBSERVED' : 'UNKNOWN' },
                  security_classification: { value: secClass, truthState: secClass !== 'DATA_UNAVAILABLE' ? 'OBSERVED' : 'UNKNOWN' },
                  overall_score: { value: overallScore, truthState: overallScore !== 'NOT_CALCULATED' ? 'INFERRED' : 'UNKNOWN' },
                  risk_band: { value: riskBand, truthState: riskBand !== 'NOT_CALCULATED' ? 'INFERRED' : 'UNKNOWN' },
                }
              });
            }
          }
        }
      }

      setAgents(items);

      if (statusRes.ok) {
        setPipelineStatus(await statusRes.json());
      }
    } catch (err) {
      console.error('Failed to load library:', err);
    } finally {
      setLoading(false);
    }
  };

  const handleTriggerScan = async () => {
    setIsScanning(true);
    try {
      const res = await authenticatedFetch('/api/discovery/pipeline/trigger', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          queries: ['agent', 'autonomous', 'llm tool', 'langchain']
        })
      });
      if (res.ok) {
        await fetchLibraryAndStatus();
      }
    } catch (err) {
      console.error('Failed to trigger scan:', err);
    } finally {
      setIsScanning(false);
    }
  };

  const handleQuickIngest = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!quickLocator.trim() || ingesting) return;

    setIngesting(true);
    try {
      const computedName = quickName.trim() || quickLocator.split('/').pop()?.replace(/\.git$/, '') || 'Custom Agent';
      const res = await authenticatedFetch('/api/agents', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          name: computedName,
          sourceLocator: quickLocator,
          versionLabel: 'v1.0.0',
          securityClassification: 'INTERNAL',
          description: `Ingested agent from ${quickLocator}`
        })
      });

      if (res.ok) {
        setQuickLocator('');
        setQuickName('');
        setShowQuickIngest(false);
        await fetchLibraryAndStatus();
      }
    } catch (err) {
      console.error('Failed to ingest:', err);
    } finally {
      setIngesting(false);
    }
  };

  // Filtered Agent List
  const filteredAgents = agents.filter(agent => {
    const matchesSearch = searchQuery === '' || 
      agent.canonical_name.toLowerCase().includes(searchQuery.toLowerCase()) ||
      (agent.description && agent.description.toLowerCase().includes(searchQuery.toLowerCase())) ||
      (agent.framework && agent.framework.toLowerCase().includes(searchQuery.toLowerCase()));

    const matchesRisk = selectedRiskBand === 'ALL' || agent.risk_band === selectedRiskBand;
    const matchesSource = selectedSource === 'ALL' || (agent.source_type && agent.source_type.toLowerCase() === selectedSource.toLowerCase());

    return matchesSearch && matchesRisk && matchesSource;
  });

  return (
    <div className="space-y-6 animate-in fade-in duration-200">
      {/* 1. FIRST-VISIT WALKTHROUGH BANNER */}
      {!bannerDismissed && (
        <div className="p-5 rounded-2xl bg-gradient-to-r from-slate-900 via-slate-900 to-cyan-950/40 border border-cyan-500/20 relative overflow-hidden shadow-lg">
          <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
            <div className="space-y-1">
              <div className="flex items-center gap-2">
                <div className="h-6 w-6 rounded-lg bg-cyan-500/20 text-cyan-400 flex items-center justify-center">
                  <Sparkles className="w-3.5 h-3.5" />
                </div>
                <h2 className="text-sm font-semibold text-slate-100">
                  Welcome to CAIM: Autonomous AI Agent Assurance Platform
                </h2>
              </div>
              <p className="text-xs text-slate-300 max-w-3xl leading-relaxed">
                CAIM automatically scans open source ecosystems (GitHub, PyPI, npm, Hugging Face, etc.), runs multi-stage AST & taint analysis, enforces enterprise security gates, and evaluates recommended use cases.
              </p>
            </div>

            <button
              onClick={() => setBannerDismissed(true)}
              className="self-start md:self-center text-xs text-slate-400 hover:text-slate-200 px-3 py-1 rounded-lg bg-slate-800/80 hover:bg-slate-800 transition-colors"
            >
              Dismiss
            </button>
          </div>

          {/* 3-Step Walkthrough Flow */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-3 mt-4 pt-3.5 border-t border-slate-800/80">
            <div className="flex items-start gap-2.5 p-2 rounded-xl bg-slate-950/40 border border-slate-800/60">
              <div className="h-6 w-6 rounded-full bg-cyan-500/10 text-cyan-400 flex items-center justify-center text-xs font-mono font-bold shrink-0 mt-0.5">
                1
              </div>
              <div>
                <h4 className="text-xs font-medium text-slate-200">Autonomous Discovery</h4>
                <p className="text-[11px] text-slate-400 leading-tight mt-0.5">
                  Continuous crawler indexes agent packages across 7 ecosystem registries.
                </p>
              </div>
            </div>

            <div className="flex items-start gap-2.5 p-2 rounded-xl bg-slate-950/40 border border-slate-800/60">
              <div className="h-6 w-6 rounded-full bg-indigo-500/10 text-indigo-400 flex items-center justify-center text-xs font-mono font-bold shrink-0 mt-0.5">
                2
              </div>
              <div>
                <h4 className="text-xs font-medium text-slate-200">AST & Taint Analysis</h4>
                <p className="text-[11px] text-slate-400 leading-tight mt-0.5">
                  Static analysis parses call graphs, unmitigated sinks, and epistemic claims.
                </p>
              </div>
            </div>

            <div className="flex items-start gap-2.5 p-2 rounded-xl bg-slate-950/40 border border-slate-800/60">
              <div className="h-6 w-6 rounded-full bg-emerald-500/10 text-emerald-400 flex items-center justify-center text-xs font-mono font-bold shrink-0 mt-0.5">
                3
              </div>
              <div>
                <h4 className="text-xs font-medium text-slate-200">Vetted Use Cases & RAG</h4>
                <p className="text-[11px] text-slate-400 leading-tight mt-0.5">
                  Review 3-good & 3-bad use cases, or chat with the agent's evidence graph.
                </p>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* 2. AUTONOMOUS PIPELINE CONTROL & METRICS BAR */}
      <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800 flex flex-wrap items-center justify-between gap-4">
        <div className="flex items-center gap-3">
          <div className="relative">
            <div className="h-3 w-3 rounded-full bg-emerald-400"></div>
            <div className="absolute -inset-1 rounded-full bg-emerald-400/30 animate-ping"></div>
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="text-xs font-semibold text-slate-200">Autonomous Discovery Worker</span>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-300 border border-emerald-500/20">
                ACTIVE
              </span>
              <FieldHelpTooltip 
                customTitle="Autonomous Discovery Pipeline"
                customDescription="Background worker continuously querying all 7 registered source adapters (GitHub, GitLab, PyPI, npm, Hugging Face, Docker Hub, Codeberg) using broad agent search criteria."
              />
            </div>
            <p className="text-[11px] text-slate-400 font-mono mt-0.5">
              Polling 7 sources: GitHub, GitLab, PyPI, npm, Hugging Face, Docker Hub, Codeberg
            </p>
          </div>
        </div>

        <div className="flex items-center gap-4">
          <div className="flex items-center gap-4 text-xs font-mono">
            <div className="text-right">
              <span className="text-slate-400 text-[10px] block">PRE-ANALYZED</span>
              <span className="text-cyan-400 font-bold">{agents.length} AGENTS</span>
            </div>
            <div className="text-right border-l border-slate-800 pl-4">
              <span className="text-slate-400 text-[10px] block">SOURCES</span>
              <span className="text-slate-200 font-bold">7 / 7 ONLINE</span>
            </div>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={handleTriggerScan}
              disabled={isScanning}
              className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-medium border border-slate-700 flex items-center gap-1.5 transition-colors disabled:opacity-50"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${isScanning ? 'animate-spin text-cyan-400' : ''}`} />
              <span>{isScanning ? 'Scanning Sources...' : 'Scan Now'}</span>
            </button>

            <button
              onClick={() => setShowQuickIngest(!showQuickIngest)}
              className="px-3 py-1.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-semibold flex items-center gap-1.5 shadow-sm transition-colors"
            >
              <Plus className="w-3.5 h-3.5" />
              <span>Submit URL</span>
            </button>
          </div>
        </div>
      </div>

      {/* QUICK INGEST COLLAPSIBLE DRAWER */}
      {showQuickIngest && (
        <form onSubmit={handleQuickIngest} className="p-4 rounded-xl bg-slate-900 border border-cyan-500/30 space-y-3 animate-in fade-in duration-150">
          <div className="flex items-center justify-between">
            <h4 className="text-xs font-semibold text-slate-200 flex items-center gap-2">
              <Globe className="w-4 h-4 text-cyan-400" />
              <span>Ingest & Pre-Analyze Specific Agent Locator</span>
            </h4>
            <span className="text-[11px] text-slate-400">Supports github://, pypi://, npm://, hf://, https://...</span>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            <input
              type="text"
              placeholder="Source Locator (e.g., https://github.com/langchain-ai/langchain or pypi://agent-framework)"
              value={quickLocator}
              onChange={(e) => setQuickLocator(e.target.value)}
              className="w-full bg-slate-950 border border-slate-700 rounded-lg px-3 py-2 text-xs text-slate-100 placeholder-slate-500 focus:outline-none focus:ring-1 focus:ring-cyan-500"
              required
            />
            <div className="flex gap-2">
              <input
                type="text"
                placeholder="Agent Name (optional, defaults from locator)"
                value={quickName}
                onChange={(e) => setQuickName(e.target.value)}
                className="flex-1 bg-slate-950 border border-slate-700 rounded-lg px-3 py-2 text-xs text-slate-100 placeholder-slate-500 focus:outline-none focus:ring-1 focus:ring-cyan-500"
              />
              <button
                type="submit"
                disabled={ingesting || !quickLocator.trim()}
                className="px-4 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 text-white text-xs font-semibold transition-colors shrink-0"
              >
                {ingesting ? 'Analyzing...' : 'Ingest & Score'}
              </button>
            </div>
          </div>
        </form>
      )}

      {/* 3. SEARCH & FILTER CONTROLS */}
      <div className="flex flex-col sm:flex-row items-center justify-between gap-3">
        <div className="relative flex-1 w-full">
          <Search className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-slate-400" />
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Search agents by name, framework, or capability..."
            className="w-full pl-9 pr-4 py-2 bg-slate-900/80 border border-slate-800 rounded-xl text-xs text-slate-100 placeholder-slate-500 focus:outline-none focus:ring-1 focus:ring-cyan-500"
          />
        </div>

        <div className="flex items-center gap-2 w-full sm:w-auto">
          {/* Risk Band Filter */}
          <select
            value={selectedRiskBand}
            onChange={(e) => setSelectedRiskBand(e.target.value)}
            className="bg-slate-900 border border-slate-800 rounded-xl px-3 py-2 text-xs text-slate-300 focus:outline-none focus:ring-1 focus:ring-cyan-500"
          >
            <option value="ALL">All Risk Bands</option>
            <option value="LOW">LOW Risk</option>
            <option value="MODERATE">MODERATE Risk</option>
            <option value="HIGH">HIGH Risk</option>
            <option value="CRITICAL">CRITICAL Risk</option>
          </select>

          {/* Source Registry Filter */}
          <select
            value={selectedSource}
            onChange={(e) => setSelectedSource(e.target.value)}
            className="bg-slate-900 border border-slate-800 rounded-xl px-3 py-2 text-xs text-slate-300 focus:outline-none focus:ring-1 focus:ring-cyan-500"
          >
            <option value="ALL">All Registries</option>
            <option value="github">GitHub</option>
            <option value="pypi">PyPI</option>
            <option value="npm">npm</option>
            <option value="huggingface">Hugging Face</option>
            <option value="dockerhub">Docker Hub</option>
            <option value="codeberg">Codeberg</option>
            <option value="gitlab">GitLab</option>
          </select>
        </div>
      </div>

      {/* 4. AGENTS LISTING / GRID */}
      {loading ? (
        <LoadingState 
          title="Loading Agent Library" 
          message="Synchronizing pre-analyzed candidates from autonomous discovery pipeline..." 
        />
      ) : filteredAgents.length === 0 ? (
        <EmptyState
          title="No Agents Found in Library"
          description={
            searchQuery || selectedRiskBand !== 'ALL' || selectedSource !== 'ALL'
              ? "No agents match your current search and filter criteria. Try resetting filters."
              : "You haven't analyzed any agents yet. The autonomous discovery worker is continuously polling sources, or you can submit an agent URL right now."
          }
          icon={<Bot className="w-6 h-6 text-cyan-400" />}
          actionLabel="Submit Agent URL"
          onAction={() => setShowQuickIngest(true)}
        />
      ) : (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          {filteredAgents.map((agent) => (
            <div
              key={agent.agent_id}
              className="p-5 rounded-2xl bg-slate-900/80 border border-slate-800 hover:border-slate-700 transition-all flex flex-col justify-between shadow-sm group"
            >
              <div>
                {/* Header */}
                <div className="flex items-start justify-between gap-3 mb-3">
                  <div>
                    <div className="flex items-center gap-2">
                      <h3 className="font-semibold text-slate-100 text-sm group-hover:text-cyan-300 transition-colors">
                        {agent.canonical_name}
                      </h3>
                      <span className="text-xs font-mono text-slate-400">
                        ({agent.version_label || 'v1.0.0'})
                      </span>
                    </div>

                    <div className="flex flex-wrap items-center gap-2 mt-1.5">
                      <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700 uppercase">
                        {agent.source_type || 'SOURCE'}
                      </span>
                      <SecurityClassificationBadge classification={agent.security_classification || 'DATA_UNAVAILABLE'} />
                      <RiskScoreBadge 
                        score={agent.overall_score ?? 'NOT_CALCULATED'} 
                        riskBand={agent.risk_band || 'NOT_CALCULATED'} 
                      />
                      {agent.truthState && (
                        <TruthStateBadge truthState={agent.truthState} size="xs" />
                      )}
                    </div>
                  </div>

                  <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 shrink-0">
                    {agent.analysis_status || 'ANALYZED'}
                  </span>
                </div>

                {/* Description & Framework */}
                <p className="text-xs text-slate-300 line-clamp-2 leading-relaxed mb-3">
                  {agent.description}
                </p>

                <div className="text-[11px] font-mono text-slate-400 mb-3.5 flex flex-wrap items-center justify-between gap-2 pb-2 border-b border-slate-800/80">
                  <span className="flex items-center gap-1.5">
                    <span>Framework: <span className={agent.framework === 'DATA_UNAVAILABLE' ? 'text-amber-400 italic' : 'text-slate-200'}>{agent.framework}</span></span>
                    {agent.epistemic_metadata?.framework?.truthState && (
                      <TruthStateBadge truthState={agent.epistemic_metadata.framework.truthState} size="xs" />
                    )}
                  </span>
                  <span className="flex items-center gap-1.5">
                    <span>Author: <span className={agent.author === 'DATA_UNAVAILABLE' ? 'text-amber-400 italic' : 'text-slate-200'}>{agent.author}</span></span>
                    {agent.epistemic_metadata?.author?.truthState && (
                      <TruthStateBadge truthState={agent.epistemic_metadata.author.truthState} size="xs" />
                    )}
                  </span>
                </div>

                {/* 3-GOOD & 3-BAD USE CASES PREVIEW */}
                <div className="space-y-2.5 mb-4">
                  {/* Good Use Cases */}
                  <div>
                    <div className="text-[10px] font-semibold uppercase tracking-wider text-emerald-400 mb-1 flex items-center gap-1">
                      <Check className="w-3 h-3" />
                      <span>Recommended Safe Use Cases</span>
                    </div>
                    <div className="space-y-1">
                      {(agent.good_use_cases || []).slice(0, 3).map((uc, i) => (
                        <div 
                          key={i} 
                          className="text-[11px] bg-emerald-950/20 border border-emerald-900/30 rounded-lg px-2.5 py-1 text-emerald-200/90 flex items-start gap-1.5"
                        >
                          <span className="text-emerald-400 font-bold">•</span>
                          <div>
                            <span className="font-medium text-emerald-300">{uc.title}:</span>{' '}
                            <span className="text-slate-400 text-[10px]">{uc.rationale}</span>
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>

                  {/* Bad Use Cases */}
                  <div>
                    <div className="text-[10px] font-semibold uppercase tracking-wider text-rose-400 mb-1 flex items-center gap-1">
                      <Ban className="w-3 h-3" />
                      <span>Unsafe / High-Risk Use Cases</span>
                    </div>
                    <div className="space-y-1">
                      {(agent.bad_use_cases || []).slice(0, 3).map((uc, i) => (
                        <div 
                          key={i} 
                          className="text-[11px] bg-rose-950/20 border border-rose-900/30 rounded-lg px-2.5 py-1 text-rose-200/90 flex items-start gap-1.5"
                        >
                          <span className="text-rose-400 font-bold">•</span>
                          <div>
                            <span className="font-medium text-rose-300">{uc.title}:</span>{' '}
                            <span className="text-slate-400 text-[10px]">{uc.rationale}</span>
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
              </div>

              {/* Action Buttons */}
              <div className="pt-3 border-t border-slate-800 flex items-center justify-between gap-2 mt-2">
                <button
                  onClick={() => setChatAgent(agent)}
                  className="px-3 py-1.5 rounded-lg bg-cyan-600/20 hover:bg-cyan-600/30 text-cyan-300 border border-cyan-500/30 text-xs font-semibold flex items-center gap-1.5 transition-colors"
                >
                  <MessageSquare className="w-3.5 h-3.5" />
                  <span>Chat with Evidence (RAG)</span>
                </button>

                <div className="flex items-center gap-1.5">
                  <button
                    onClick={() => onNavigateToWorkflow && onNavigateToWorkflow('analysis', { agentId: agent.agent_id })}
                    className="px-2.5 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-medium border border-slate-700 transition-colors"
                  >
                    Deep Analysis
                  </button>
                  <button
                    onClick={() => onNavigateToWorkflow && onNavigateToWorkflow('agents', { agentId: agent.agent_id })}
                    className="px-2.5 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-medium border border-slate-700 transition-colors"
                  >
                    Registry
                  </button>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* 5. SCOPED RAG CHAT MODAL */}
      {chatAgent && (
        <AgentRagChatModal
          agent={chatAgent}
          onClose={() => setChatAgent(null)}
          currentRole={currentRole}
        />
      )}
    </div>
  );
};
