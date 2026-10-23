import React, { useState, useEffect } from 'react';
import { 
  Globe, 
  Search, 
  Layers, 
  Network, 
  CheckCircle2, 
  AlertTriangle, 
  XCircle, 
  RotateCw, 
  ExternalLink, 
  Tag, 
  Share2, 
  GitFork, 
  FileCode, 
  Clock, 
  Sliders, 
  ShieldAlert, 
  ListFilter,
  Check,
  Zap,
  HelpCircle,
  Database
} from 'lucide-react';

interface DiagnosticDiscoveryViewProps {
  currentRole: string;
}

export const DiagnosticDiscoveryView: React.FC<DiagnosticDiscoveryViewProps> = ({ currentRole }) => {
  const [activeSection, setActiveSection] = useState<'overview' | 'search' | 'expansion' | 'classification' | 'identity' | 'review' | 'freshness'>('overview');

  // Source & Search Providers Telemetry
  const [sources, setSources] = useState<any[]>([]);
  const [sourcesLoading, setSourcesLoading] = useState<boolean>(true);

  // Query Strategies
  const [rules, setRules] = useState<any[]>([]);
  const [seedInput, setSeedInput] = useState<string>('caim autonomous agent');
  const [generatedQueries, setGeneratedQueries] = useState<any[]>([]);
  const [selectedSearchQuery, setSelectedSearchQuery] = useState<string>('');
  const [searchResults, setSearchResults] = useState<any | null>(null);
  const [searching, setSearching] = useState<boolean>(false);

  // Recursive Expansion
  const [expansionRoots, setExpansionRoots] = useState<string>('github://caim-org/autonomous-caim-agent\npypi://autonomous-caim-agent');
  const [maxDepth, setMaxDepth] = useState<number>(2);
  const [maxCandidates, setMaxCandidates] = useState<number>(30);
  const [expansionReport, setExpansionReport] = useState<any | null>(null);
  const [expanding, setExpanding] = useState<boolean>(false);

  // Classification
  const [classifyLocator, setClassifyLocator] = useState<string>('github://caim-org/autonomous-caim-agent');
  const [classificationResult, setClassificationResult] = useState<any | null>(null);
  const [classifying, setClassifying] = useState<boolean>(false);

  // Identity Resolution
  const [obsALocator, setObsALocator] = useState<string>('github://caim-org/autonomous-caim-agent');
  const [obsBLocator, setObsBLocator] = useState<string>('pypi://autonomous-caim-agent');
  const [identityResult, setIdentityResult] = useState<any | null>(null);
  const [resolvingIdentity, setResolvingIdentity] = useState<boolean>(false);
  const [candidateGraph, setCandidateGraph] = useState<any | null>(null);

  // Manual Review Queue
  const [reviewItems, setReviewItems] = useState<any[]>([]);
  const [reviewLoading, setReviewLoading] = useState<boolean>(false);
  const [selectedReviewItem, setSelectedReviewItem] = useState<any | null>(null);
  const [reviewNote, setReviewNote] = useState<string>('');

  // Freshness & Coverage Metrics
  const [freshnessWindow, setFreshnessWindow] = useState<'1h' | '24h' | '7d' | '30d'>('24h');
  const [freshnessMetrics, setFreshnessMetrics] = useState<any | null>(null);

  // Fetch initial source adapter and rule telemetry
  const fetchSourcesAndRules = async () => {
    setSourcesLoading(true);
    try {
      const headers = { 'X-Role': currentRole };
      const [srcRes, rulesRes, revRes, freshRes] = await Promise.all([
        fetch('/api/dev/sources', { headers }).then(r => r.json()),
        fetch('/api/dev/discovery/rules', { headers }).then(r => r.json()),
        fetch('/api/dev/discovery/review-queue', { headers }).then(r => r.json()),
        fetch(`/api/dev/discovery/freshness/metrics?window=${freshnessWindow}`, { headers }).then(r => r.json()),
      ]);
      setSources(Array.isArray(srcRes) ? srcRes : []);
      setRules(Array.isArray(rulesRes) ? rulesRes : []);
      setReviewItems(Array.isArray(revRes) ? revRes : []);
      setFreshnessMetrics(freshRes || null);
    } catch (err) {
      console.error('Failed to load discovery telemetry:', err);
    } finally {
      setSourcesLoading(false);
    }
  };

  useEffect(() => {
    fetchSourcesAndRules();
  }, [currentRole, freshnessWindow]);

  // Generate Queries
  const handleGenerateQueries = async () => {
    try {
      const res = await fetch('/api/dev/discovery/rules/generate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-Role': currentRole },
        body: JSON.stringify({ seed: seedInput }),
      });
      const data = await res.json();
      setGeneratedQueries(Array.isArray(data) ? data : []);
      if (data.length > 0) setSelectedSearchQuery(data[0].query);
    } catch (err) {
      console.error('Query generation failed:', err);
    }
  };

  // Run Search
  const handleRunSearch = async (q?: string) => {
    const queryToUse = q || selectedSearchQuery || seedInput;
    if (!queryToUse) return;
    setSearching(true);
    try {
      const res = await fetch('/api/dev/discovery/search', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-Role': currentRole },
        body: JSON.stringify({ query: queryToUse, count: 10 }),
      });
      const data = await res.json();
      setSearchResults(data);
    } catch (err) {
      console.error('Search failed:', err);
    } finally {
      setSearching(false);
    }
  };

  // Run Recursive Expansion
  const handleRunExpansion = async () => {
    const roots = expansionRoots.split('\n').map(s => s.trim()).filter(Boolean);
    if (roots.length === 0) return;
    setExpanding(true);
    try {
      const res = await fetch('/api/dev/discovery/expand', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-Role': currentRole },
        body: JSON.stringify({
          rootLocators: roots,
          maxDepth,
          maxCandidatesTotal: maxCandidates,
          maxCallsPerSource: 10,
        }),
      });
      const data = await res.json();
      setExpansionReport(data);
    } catch (err) {
      console.error('Expansion failed:', err);
    } finally {
      setExpanding(false);
    }
  };

  // Run Classification
  const handleClassify = async () => {
    if (!classifyLocator) return;
    setClassifying(true);
    try {
      const res = await fetch('/api/dev/discovery/classify', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-Role': currentRole },
        body: JSON.stringify({ locator: classifyLocator }),
      });
      const data = await res.json();
      setClassificationResult(data);
    } catch (err) {
      console.error('Classification failed:', err);
    } finally {
      setClassifying(false);
    }
  };

  // Run Identity Resolution
  const handleResolveIdentity = async () => {
    setResolvingIdentity(true);
    try {
      const obsA = {
        source_locator: obsALocator,
        source_type: obsALocator.startsWith('github://') ? 'github' : 'web',
        display_name: 'autonomous-caim-agent',
        publisher: 'caim-org',
        repository_url: 'https://github.com/caim-org/autonomous-caim-agent',
        homepage_url: 'https://caim.dev/agents/autonomous',
        version: '1.0.0',
      };
      const obsB = {
        source_locator: obsBLocator,
        source_type: obsBLocator.startsWith('pypi://') ? 'pypi' : 'web',
        display_name: 'autonomous-caim-agent',
        publisher: 'caim-org',
        repository_url: 'https://github.com/caim-org/autonomous-caim-agent',
        homepage_url: 'https://caim.dev/agents/autonomous',
        version: '1.0.0',
      };

      const res = await fetch('/api/dev/discovery/resolve-identity', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-Role': currentRole },
        body: JSON.stringify({ observationA: obsA, observationB: obsB }),
      });
      const data = await res.json();
      setIdentityResult(data);

      // Also trigger candidate graph build
      const graphRes = await fetch('/api/dev/discovery/resolve-identity', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-Role': currentRole },
        body: JSON.stringify({
          observations: [
            obsA,
            obsB,
            {
              source_locator: 'docker://caim-org/autonomous-sandbox:latest',
              source_type: 'dockerhub',
              display_name: 'autonomous-sandbox',
              publisher: 'caim-org',
              version: 'latest',
            },
            {
              source_locator: 'hf://caim-org/caim-reasoner-7b',
              source_type: 'huggingface',
              display_name: 'caim-reasoner-7b',
              publisher: 'caim-org',
              version: 'v1.0',
            },
          ],
        }),
      });
      const graphData = await graphRes.json();
      setCandidateGraph(graphData);
    } catch (err) {
      console.error('Identity resolution failed:', err);
    } finally {
      setResolvingIdentity(false);
    }
  };

  // Resolve Manual Review Item
  const handleResolveReview = async (id: string, status: 'RESOLVED_CANONICAL' | 'RESOLVED_DISTINCT' | 'REJECTED') => {
    try {
      const res = await fetch('/api/dev/discovery/review-queue/resolve', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-Role': currentRole },
        body: JSON.stringify({
          id,
          status,
          review_note: reviewNote || 'Resolved via Engineering Console',
        }),
      });
      if (res.ok) {
        setSelectedReviewItem(null);
        setReviewNote('');
        fetchSourcesAndRules();
      }
    } catch (err) {
      console.error('Failed to resolve review item:', err);
    }
  };

  const getOutcomeBadgeColor = (outcome: string) => {
    switch (outcome) {
      case 'SAME_CANONICAL_AGENT': return 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30';
      case 'SAME_AGENT_DIFFERENT_VERSION': return 'bg-cyan-500/10 text-cyan-400 border-cyan-500/30';
      case 'SAME_AGENT_DIFFERENT_DISTRIBUTION': return 'bg-blue-500/10 text-blue-400 border-blue-500/30';
      case 'RELATED_ENTITY': return 'bg-purple-500/10 text-purple-400 border-purple-500/30';
      case 'FORK_OR_DERIVATIVE': return 'bg-amber-500/10 text-amber-400 border-amber-500/30';
      case 'MIRROR': return 'bg-teal-500/10 text-teal-400 border-teal-500/30';
      case 'UNRESOLVED': return 'bg-red-500/10 text-red-400 border-red-500/30';
      case 'DISTINCT': return 'bg-slate-500/10 text-slate-400 border-slate-500/30';
      default: return 'bg-slate-500/10 text-slate-400 border-slate-500/30';
    }
  };

  return (
    <div className="space-y-6">
      {/* Sub-Navigation */}
      <div className="flex flex-wrap items-center justify-between border-b border-slate-800 pb-3 gap-2">
        <div className="flex items-center space-x-1 sm:space-x-2 overflow-x-auto">
          {[
            { id: 'overview', label: 'Source & Search Adapters', icon: Database },
            { id: 'search', label: 'Web Discovery & Strategies', icon: Search },
            { id: 'expansion', label: 'Recursive Expansion', icon: Network },
            { id: 'classification', label: 'Taxonomy Classifier', icon: Tag },
            { id: 'identity', label: 'Identity Resolution', icon: Share2 },
            { id: 'review', label: `Manual Review Queue (${reviewItems.filter(i => i.status === 'PENDING_REVIEW').length})`, icon: ShieldAlert },
            { id: 'freshness', label: 'Coverage & Freshness', icon: Clock },
          ].map(sec => {
            const Icon = sec.icon;
            const isActive = activeSection === sec.id;
            return (
              <button
                key={sec.id}
                onClick={() => setActiveSection(sec.id as any)}
                className={`flex items-center space-x-1.5 px-3 py-1.5 rounded-md text-xs font-medium transition-all ${
                  isActive 
                    ? 'bg-cyan-500/10 text-cyan-400 border border-cyan-500/30 shadow-sm' 
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50'
                }`}
              >
                <Icon className="h-3.5 w-3.5" />
                <span>{sec.label}</span>
              </button>
            );
          })}
        </div>

        <button
          onClick={fetchSourcesAndRules}
          disabled={sourcesLoading}
          className="flex items-center space-x-1.5 px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-mono border border-slate-700"
        >
          <RotateCw className={`h-3 w-3 ${sourcesLoading ? 'animate-spin' : ''}`} />
          <span>Refresh</span>
        </button>
      </div>

      {/* SECTION 1: SOURCE & SEARCH ADAPTERS OVERVIEW */}
      {activeSection === 'overview' && (
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <div>
              <h3 className="text-sm font-semibold text-slate-100 flex items-center space-x-2">
                <span>Structured & Unstructured Discovery Adapters</span>
                <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-cyan-900/40 text-cyan-300 border border-cyan-700/40">
                  {sources.length} Registered Providers
                </span>
              </h3>
              <p className="text-xs text-slate-400 mt-0.5">
                Universal SourceAdapter and WebSearchProvider telemetry across public repositories, package registries, model hubs, container registries, and web engines.
              </p>
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
            {sources.map(s => {
              const isHealthy = s.health?.status === 'HEALTHY';
              const isDegraded = s.health?.status === 'DEGRADED';
              return (
                <div key={s.sourceType} className="p-4 rounded-lg bg-slate-900/60 border border-slate-800 flex flex-col justify-between">
                  <div className="space-y-2">
                    <div className="flex items-center justify-between">
                      <span className="font-mono text-xs font-semibold text-slate-200 uppercase">{s.sourceName}</span>
                      <span className={`text-[10px] font-mono px-2 py-0.5 rounded border ${
                        isHealthy ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30' :
                        isDegraded ? 'bg-amber-500/10 text-amber-400 border-amber-500/30' :
                        'bg-red-500/10 text-red-400 border-red-500/30'
                      }`}>
                        {s.health?.status || 'UNKNOWN'}
                      </span>
                    </div>

                    <p className="text-[11px] text-slate-400">
                      Auth Mode: <span className="font-mono text-slate-300">{s.policy?.auth_mode || 'ANONYMOUS'}</span>
                    </p>

                    <div className="text-[10px] font-mono bg-slate-950 p-2 rounded border border-slate-800 space-y-1 text-slate-400">
                      <div className="flex justify-between">
                        <span>Rate Remaining:</span>
                        <span className="text-cyan-400">{s.rateLimit?.remaining ?? 'N/A'} / {s.rateLimit?.limit ?? 'N/A'}</span>
                      </div>
                      <div className="flex justify-between">
                        <span>Max Page Size:</span>
                        <span>{s.policy?.max_page_size || 20}</span>
                      </div>
                    </div>
                  </div>

                  <div className="mt-3 pt-2 border-t border-slate-800/80 flex items-center justify-between text-[10px] text-slate-500 font-mono">
                    <span>v{s.adapterVersion}</span>
                    <span>{s.health?.latency_ms ? `${s.health.latency_ms}ms` : 'Ready'}</span>
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* SECTION 2: WEB DISCOVERY & STRATEGIES */}
      {activeSection === 'search' && (
        <div className="space-y-6">
          {/* Query Rule Strategy Registry */}
          <div className="p-4 rounded-lg bg-slate-900/60 border border-slate-800 space-y-3">
            <h3 className="text-sm font-semibold text-slate-100 flex items-center space-x-2">
              <Sliders className="h-4 w-4 text-cyan-400" />
              <span>Query Strategy & Archetype Registry</span>
            </h3>
            <p className="text-xs text-slate-400">
              Configured query formulation rules for targeted artifact retrieval and discovery sweeps.
            </p>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-3 mt-2">
              {rules.map(r => (
                <div key={r.id} className="p-3 rounded bg-slate-950/60 border border-slate-800 text-xs space-y-1">
                  <div className="flex items-center justify-between">
                    <span className="font-mono text-cyan-400 font-semibold">{r.name}</span>
                    <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-slate-800 text-slate-300">
                      {r.family}
                    </span>
                  </div>
                  <p className="text-slate-400 font-mono text-[11px] bg-slate-900/80 p-1.5 rounded">
                    {r.template}
                  </p>
                  <p className="text-slate-500 text-[10px]">{r.description}</p>
                </div>
              ))}
            </div>
          </div>

          {/* Live Search & Generator Sandbox */}
          <div className="p-4 rounded-lg bg-slate-900/60 border border-slate-800 space-y-4">
            <h3 className="text-sm font-semibold text-slate-100 flex items-center space-x-2">
              <Search className="h-4 w-4 text-cyan-400" />
              <span>Web Search & Discovery Execution (Brave Provider)</span>
            </h3>

            <div className="flex flex-col sm:flex-row gap-2">
              <input
                type="text"
                value={seedInput}
                onChange={e => setSeedInput(e.target.value)}
                placeholder="Enter seed concept (e.g. autonomous agent, caim, mcp)"
                className="flex-1 px-3 py-2 rounded bg-slate-950 border border-slate-800 text-xs text-slate-200 focus:outline-none focus:border-cyan-500"
              />
              <button
                onClick={handleGenerateQueries}
                className="px-4 py-2 rounded bg-slate-800 hover:bg-slate-700 text-xs font-semibold text-slate-200 border border-slate-700 flex items-center justify-center space-x-1.5"
              >
                <Zap className="h-3.5 w-3.5 text-cyan-400" />
                <span>Generate Queries</span>
              </button>
              <button
                onClick={() => handleRunSearch()}
                disabled={searching}
                className="px-4 py-2 rounded bg-cyan-600 hover:bg-cyan-500 text-xs font-semibold text-white flex items-center justify-center space-x-1.5"
              >
                <Search className={`h-3.5 w-3.5 ${searching ? 'animate-spin' : ''}`} />
                <span>Execute Search</span>
              </button>
            </div>

            {/* Generated Query Pills */}
            {generatedQueries.length > 0 && (
              <div className="space-y-2">
                <span className="text-xs font-mono text-slate-400">Generated Query Strategies:</span>
                <div className="flex flex-wrap gap-2">
                  {generatedQueries.map((gq, idx) => (
                    <button
                      key={idx}
                      onClick={() => {
                        setSelectedSearchQuery(gq.query);
                        handleRunSearch(gq.query);
                      }}
                      className="px-2.5 py-1 rounded bg-slate-950 hover:bg-slate-800 border border-slate-800 text-[11px] font-mono text-cyan-300 transition-all text-left"
                    >
                      {gq.query}
                    </button>
                  ))}
                </div>
              </div>
            )}

            {/* Search Results Display */}
            {searchResults && (
              <div className="space-y-3 pt-3 border-t border-slate-800">
                <div className="flex items-center justify-between text-xs text-slate-400 font-mono">
                  <span>Provider: {searchResults.provider} • Query: "{searchResults.query}"</span>
                  <span>Discovered: {searchResults.items?.length || 0} results</span>
                </div>

                <div className="space-y-2">
                  {searchResults.items?.map((item: any, i: number) => (
                    <div key={i} className="p-3 rounded bg-slate-950 border border-slate-800/80 text-xs space-y-1">
                      <div className="flex items-center justify-between">
                        <a href={item.url} target="_blank" rel="noreferrer" className="text-cyan-400 font-semibold hover:underline flex items-center space-x-1">
                          <span>{item.title}</span>
                          <ExternalLink className="h-3 w-3" />
                        </a>
                        <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-900 text-slate-400 border border-slate-800">
                          {item.source_hostname}
                        </span>
                      </div>
                      <p className="text-slate-300 text-[11px]">{item.description}</p>
                      <div className="flex items-center justify-between text-[10px] text-slate-500 font-mono pt-1">
                        <span>Confidence: {(item.confidence * 100).toFixed(0)}%</span>
                        <span>{item.published_at ? new Date(item.published_at).toLocaleDateString() : 'Recent'}</span>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        </div>
      )}

      {/* SECTION 3: RECURSIVE EXPANSION */}
      {activeSection === 'expansion' && (
        <div className="p-4 rounded-lg bg-slate-900/60 border border-slate-800 space-y-4">
          <div className="flex items-center justify-between">
            <div>
              <h3 className="text-sm font-semibold text-slate-100 flex items-center space-x-2">
                <Network className="h-4 w-4 text-cyan-400" />
                <span>Recursive Relationship Expansion Explorer</span>
              </h3>
              <p className="text-xs text-slate-400 mt-0.5">
                Polymorphically traverses candidate trees across repositories, packages, models, and sandboxes with strict depth and rate limit budget guards.
              </p>
            </div>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
            <div className="lg:col-span-1 space-y-3">
              <div>
                <label className="text-xs font-mono text-slate-400 block mb-1">Seed Root Locators (One per line):</label>
                <textarea
                  value={expansionRoots}
                  onChange={e => setExpansionRoots(e.target.value)}
                  rows={4}
                  className="w-full px-3 py-2 rounded bg-slate-950 border border-slate-800 text-xs font-mono text-slate-200 focus:outline-none focus:border-cyan-500"
                />
              </div>

              <div className="grid grid-cols-2 gap-2">
                <div>
                  <label className="text-[11px] font-mono text-slate-400 block">Max Depth:</label>
                  <input
                    type="number"
                    min={1}
                    max={5}
                    value={maxDepth}
                    onChange={e => setMaxDepth(parseInt(e.target.value, 10))}
                    className="w-full px-2.5 py-1.5 rounded bg-slate-950 border border-slate-800 text-xs font-mono text-slate-200"
                  />
                </div>
                <div>
                  <label className="text-[11px] font-mono text-slate-400 block">Max Candidates:</label>
                  <input
                    type="number"
                    min={5}
                    max={100}
                    value={maxCandidates}
                    onChange={e => setMaxCandidates(parseInt(e.target.value, 10))}
                    className="w-full px-2.5 py-1.5 rounded bg-slate-950 border border-slate-800 text-xs font-mono text-slate-200"
                  />
                </div>
              </div>

              <button
                onClick={handleRunExpansion}
                disabled={expanding}
                className="w-full py-2 rounded bg-cyan-600 hover:bg-cyan-500 text-xs font-semibold text-white flex items-center justify-center space-x-1.5"
              >
                <Network className={`h-3.5 w-3.5 ${expanding ? 'animate-spin' : ''}`} />
                <span>Run Recursive Expansion</span>
              </button>
            </div>

            <div className="lg:col-span-2 p-3 rounded bg-slate-950 border border-slate-800 min-h-[220px]">
              {expansionReport ? (
                <div className="space-y-3">
                  <div className="flex flex-wrap items-center justify-between gap-2 text-xs font-mono pb-2 border-b border-slate-800">
                    <span className="text-emerald-400">Expansion Completed ({expansionReport.duration_ms}ms)</span>
                    <span className="text-slate-400">
                      Depth: {expansionReport.depth_reached} • Discovered: {expansionReport.total_candidates_discovered}
                    </span>
                    {expansionReport.budget_exhausted && (
                      <span className="text-amber-400 bg-amber-500/10 px-2 py-0.5 rounded border border-amber-500/30">
                        Budget Guard: {expansionReport.budget_exhaustion_reason}
                      </span>
                    )}
                  </div>

                  <div className="space-y-2 max-h-[350px] overflow-y-auto font-mono text-xs text-slate-300">
                    {expansionReport.tree?.map((node: any, idx: number) => (
                      <div key={idx} className="p-2 rounded bg-slate-900/60 border border-slate-800/80 space-y-1">
                        <div className="flex items-center space-x-2 text-cyan-400 font-semibold">
                          <Tag className="h-3 w-3" />
                          <span>{node.locator}</span>
                          <span className="text-[10px] text-slate-500">[{node.source_type}]</span>
                        </div>
                        {node.children?.length > 0 && (
                          <div className="pl-4 border-l border-slate-800 space-y-1 mt-1">
                            {node.children.map((child: any, cIdx: number) => (
                              <div key={cIdx} className="text-[11px] text-slate-400 flex items-center space-x-1.5">
                                <span className="text-slate-600">↳</span>
                                <span className="text-amber-300/80 font-mono text-[10px]">[{child.relationship_type}]</span>
                                <span className="text-slate-300">{child.locator}</span>
                              </div>
                            ))}
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                </div>
              ) : (
                <div className="h-full flex items-center justify-center text-xs font-mono text-slate-500">
                  Ready to execute recursive discovery expansion tree.
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {/* SECTION 4: ARTIFACT CLASSIFICATION TAXONOMY */}
      {activeSection === 'classification' && (
        <div className="p-4 rounded-lg bg-slate-900/60 border border-slate-800 space-y-4">
          <div>
            <h3 className="text-sm font-semibold text-slate-100 flex items-center space-x-2">
              <Tag className="h-4 w-4 text-cyan-400" />
              <span>Artifact Classification Taxonomy & Confidence Evaluator</span>
            </h3>
            <p className="text-xs text-slate-400 mt-0.5">
              Classifies discovery candidates into CAIM taxonomy: AUTONOMOUS_AGENT, AGENT_FRAMEWORK_SDK, REASONING_MODEL, TOOL_OR_PLUGIN, CONTAINER_SANDBOX, AGENT_SPECIFICATION, EVALUATION_BENCHMARK.
            </p>
          </div>

          <div className="flex gap-2">
            <input
              type="text"
              value={classifyLocator}
              onChange={e => setClassifyLocator(e.target.value)}
              placeholder="Enter locator (e.g. github://caim-org/autonomous-caim-agent, hf://caim-org/reasoner)"
              className="flex-1 px-3 py-2 rounded bg-slate-950 border border-slate-800 text-xs font-mono text-slate-200 focus:outline-none focus:border-cyan-500"
            />
            <button
              onClick={handleClassify}
              disabled={classifying}
              className="px-4 py-2 rounded bg-cyan-600 hover:bg-cyan-500 text-xs font-semibold text-white flex items-center space-x-1.5"
            >
              <Tag className={`h-3.5 w-3.5 ${classifying ? 'animate-spin' : ''}`} />
              <span>Classify</span>
            </button>
          </div>

          {classificationResult && (
            <div className="p-4 rounded bg-slate-950 border border-slate-800 space-y-4">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <div className="flex items-center space-x-2">
                  <span className="text-xs font-mono text-slate-400">Primary Classification:</span>
                  <span className="text-xs font-mono font-bold px-2.5 py-1 rounded bg-cyan-500/10 text-cyan-400 border border-cyan-500/30">
                    {classificationResult.primary_category}
                  </span>
                </div>
                <div className="text-xs font-mono text-slate-400">
                  Confidence: <span className="text-emerald-400 font-bold">{(classificationResult.confidence * 100).toFixed(0)}%</span>
                </div>
              </div>

              <p className="text-xs text-slate-300 bg-slate-900/60 p-2.5 rounded border border-slate-800/80">
                {classificationResult.rationale}
              </p>

              <div className="space-y-2">
                <span className="text-xs font-mono text-slate-400">Evaluated Taxonomy Signals:</span>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                  {classificationResult.signals?.map((sig: any, idx: number) => (
                    <div key={idx} className="p-2 rounded bg-slate-900 border border-slate-800 text-xs space-y-1">
                      <div className="flex items-center justify-between">
                        <span className="font-mono text-slate-300 font-semibold">{sig.feature}</span>
                        <span className="text-[10px] font-mono text-emerald-400">Weight: +{sig.weight}</span>
                      </div>
                      <p className="text-[11px] text-slate-400">{sig.evidence}</p>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}
        </div>
      )}

      {/* SECTION 5: IDENTITY RESOLUTION */}
      {activeSection === 'identity' && (
        <div className="space-y-6">
          <div className="p-4 rounded-lg bg-slate-900/60 border border-slate-800 space-y-4">
            <div>
              <h3 className="text-sm font-semibold text-slate-100 flex items-center space-x-2">
                <Share2 className="h-4 w-4 text-cyan-400" />
                <span>Identity Resolution & Canonical Candidate Graph Engine</span>
              </h3>
              <p className="text-xs text-slate-400 mt-0.5">
                Resolves cross-source observations into canonical clusters with 8 outcomes: SAME_CANONICAL_AGENT, SAME_AGENT_DIFFERENT_VERSION, SAME_AGENT_DIFFERENT_DISTRIBUTION, RELATED_ENTITY, FORK_OR_DERIVATIVE, MIRROR, UNRESOLVED, DISTINCT.
              </p>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
              <div>
                <label className="text-xs font-mono text-slate-400 block mb-1">Observation A Locator:</label>
                <input
                  type="text"
                  value={obsALocator}
                  onChange={e => setObsALocator(e.target.value)}
                  className="w-full px-3 py-2 rounded bg-slate-950 border border-slate-800 text-xs font-mono text-slate-200"
                />
              </div>
              <div>
                <label className="text-xs font-mono text-slate-400 block mb-1">Observation B Locator:</label>
                <input
                  type="text"
                  value={obsBLocator}
                  onChange={e => setObsBLocator(e.target.value)}
                  className="w-full px-3 py-2 rounded bg-slate-950 border border-slate-800 text-xs font-mono text-slate-200"
                />
              </div>
            </div>

            <button
              onClick={handleResolveIdentity}
              disabled={resolvingIdentity}
              className="py-2 px-4 rounded bg-cyan-600 hover:bg-cyan-500 text-xs font-semibold text-white flex items-center justify-center space-x-1.5"
            >
              <Share2 className={`h-3.5 w-3.5 ${resolvingIdentity ? 'animate-spin' : ''}`} />
              <span>Evaluate Identity Resolution</span>
            </button>

            {/* Comparison Outcome */}
            {identityResult && (
              <div className="p-4 rounded bg-slate-950 border border-slate-800 space-y-3">
                <div className="flex items-center justify-between">
                  <div className="flex items-center space-x-2">
                    <span className="text-xs font-mono text-slate-400">Resolution Outcome:</span>
                    <span className={`text-xs font-mono font-bold px-2.5 py-1 rounded border ${getOutcomeBadgeColor(identityResult.outcome)}`}>
                      {identityResult.outcome}
                    </span>
                  </div>
                  <span className="text-xs font-mono text-slate-400">
                    Composite Confidence: <span className="text-emerald-400 font-bold">{(identityResult.confidence * 100).toFixed(0)}%</span>
                  </span>
                </div>

                <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 text-center text-xs font-mono pt-2">
                  <div className="p-2 rounded bg-slate-900 border border-slate-800">
                    <span className="text-[10px] text-slate-500 block">Publisher Match</span>
                    <span className="text-slate-200 font-bold">{(identityResult.evidence?.publisher_match * 100).toFixed(0)}%</span>
                  </div>
                  <div className="p-2 rounded bg-slate-900 border border-slate-800">
                    <span className="text-[10px] text-slate-500 block">Repo Match</span>
                    <span className="text-slate-200 font-bold">{(identityResult.evidence?.repo_match * 100).toFixed(0)}%</span>
                  </div>
                  <div className="p-2 rounded bg-slate-900 border border-slate-800">
                    <span className="text-[10px] text-slate-500 block">Manifest Match</span>
                    <span className="text-slate-200 font-bold">{(identityResult.evidence?.manifest_match * 100).toFixed(0)}%</span>
                  </div>
                  <div className="p-2 rounded bg-slate-900 border border-slate-800">
                    <span className="text-[10px] text-slate-500 block">Cross-Distribution</span>
                    <span className="text-slate-200 font-bold">{(identityResult.evidence?.distribution_match * 100).toFixed(0)}%</span>
                  </div>
                </div>
              </div>
            )}
          </div>

          {/* Canonical Candidate Graph */}
          {candidateGraph && (
            <div className="p-4 rounded-lg bg-slate-900/60 border border-slate-800 space-y-3">
              <h3 className="text-sm font-semibold text-slate-100 flex items-center space-x-2">
                <Network className="h-4 w-4 text-cyan-400" />
                <span>Canonical Candidate Clusters ({candidateGraph.nodes?.length} Clusters)</span>
              </h3>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                {candidateGraph.nodes?.map((node: any, idx: number) => (
                  <div key={idx} className="p-3 rounded bg-slate-950 border border-slate-800 text-xs space-y-2">
                    <div className="flex items-center justify-between">
                      <span className="font-mono font-semibold text-cyan-300">{node.canonical_name}</span>
                      <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">
                        {node.classification}
                      </span>
                    </div>

                    <div className="space-y-1 font-mono text-[11px] text-slate-400">
                      <p>Locators ({node.locators?.length}):</p>
                      <ul className="list-disc pl-4 space-y-0.5 text-slate-300">
                        {node.locators?.map((loc: string, lIdx: number) => (
                          <li key={lIdx}>{loc}</li>
                        ))}
                      </ul>
                    </div>

                    <div className="flex items-center justify-between text-[10px] text-slate-500 font-mono pt-1 border-t border-slate-800/80">
                      <span>Sources: {node.sources?.join(', ')}</span>
                      <span>Cluster ID: {node.id}</span>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      {/* SECTION 6: MANUAL REVIEW QUEUE */}
      {activeSection === 'review' && (
        <div className="p-4 rounded-lg bg-slate-900/60 border border-slate-800 space-y-4">
          <div className="flex items-center justify-between">
            <div>
              <h3 className="text-sm font-semibold text-slate-100 flex items-center space-x-2">
                <ShieldAlert className="h-4 w-4 text-amber-400" />
                <span>Manual Review Queue for Identity Conflicts</span>
              </h3>
              <p className="text-xs text-slate-400 mt-0.5">
                Audit and operator override queue for unresolved, high-value identity ambiguities and mismatched publisher credentials.
              </p>
            </div>
          </div>

          <div className="space-y-3">
            {reviewItems.map(item => (
              <div key={item.id} className="p-4 rounded bg-slate-950 border border-slate-800 text-xs space-y-3">
                <div className="flex items-center justify-between">
                  <div className="flex items-center space-x-2">
                    <span className="font-mono text-amber-400 font-semibold">{item.id}</span>
                    <span className={`text-[10px] font-mono px-2 py-0.5 rounded border ${
                      item.status === 'PENDING_REVIEW' ? 'bg-amber-500/10 text-amber-400 border-amber-500/30' :
                      item.status === 'RESOLVED_CANONICAL' ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30' :
                      'bg-slate-500/10 text-slate-400 border-slate-500/30'
                    }`}>
                      {item.status}
                    </span>
                  </div>
                  <span className="text-[10px] font-mono text-slate-500">
                    Created: {new Date(item.created_at).toLocaleString()}
                  </span>
                </div>

                <p className="text-slate-300 bg-slate-900/60 p-2 rounded border border-slate-800/80">
                  {item.conflict_summary}
                </p>

                <div className="font-mono text-[11px] text-slate-400">
                  <span>Candidate Locators: </span>
                  <span className="text-cyan-300">{item.candidate_locators?.join(' <=> ')}</span>
                </div>

                {item.status === 'PENDING_REVIEW' && (
                  <div className="pt-2 border-t border-slate-800/80 flex flex-wrap items-center gap-2">
                    <input
                      type="text"
                      placeholder="Operator review audit note..."
                      value={selectedReviewItem?.id === item.id ? reviewNote : ''}
                      onChange={e => {
                        setSelectedReviewItem(item);
                        setReviewNote(e.target.value);
                      }}
                      className="flex-1 px-3 py-1.5 rounded bg-slate-900 border border-slate-800 text-xs text-slate-200"
                    />
                    <button
                      onClick={() => handleResolveReview(item.id, 'RESOLVED_CANONICAL')}
                      className="px-3 py-1.5 rounded bg-emerald-600 hover:bg-emerald-500 text-xs font-semibold text-white"
                    >
                      Resolve Canonical
                    </button>
                    <button
                      onClick={() => handleResolveReview(item.id, 'RESOLVED_DISTINCT')}
                      className="px-3 py-1.5 rounded bg-slate-700 hover:bg-slate-600 text-xs font-semibold text-slate-200"
                    >
                      Resolve Distinct
                    </button>
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>
      )}

      {/* SECTION 7: COVERAGE & FRESHNESS METRICS */}
      {activeSection === 'freshness' && (
        <div className="p-4 rounded-lg bg-slate-900/60 border border-slate-800 space-y-4">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <div>
              <h3 className="text-sm font-semibold text-slate-100 flex items-center space-x-2">
                <Clock className="h-4 w-4 text-cyan-400" />
                <span>Coverage & Freshness Telemetry</span>
              </h3>
              <p className="text-xs text-slate-400 mt-0.5">
                Staleness evaluation, TTL scheduling, and source coverage metrics across time windows.
              </p>
            </div>

            <div className="flex items-center space-x-1 bg-slate-950 p-1 rounded border border-slate-800">
              {(['1h', '24h', '7d', '30d'] as const).map(w => (
                <button
                  key={w}
                  onClick={() => setFreshnessWindow(w)}
                  className={`px-2.5 py-1 rounded text-xs font-mono transition-all ${
                    freshnessWindow === w ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/30' : 'text-slate-400 hover:text-slate-200'
                  }`}
                >
                  {w}
                </button>
              ))}
            </div>
          </div>

          {/* Prominent Bounded Coverage Notice */}
          <div className="p-3 rounded bg-amber-950/30 border border-amber-500/30 flex items-center space-x-2 text-xs text-amber-300">
            <AlertTriangle className="h-4 w-4 shrink-0 text-amber-400" />
            <span>
              <strong>System Directives Enforced:</strong> Bounded Public Discovery Sample — Never claim complete Internet coverage.
            </span>
          </div>

          {freshnessMetrics && (
            <div className="space-y-4">
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                <div className="p-3 rounded bg-slate-950 border border-slate-800 text-center">
                  <span className="text-[10px] font-mono text-slate-400 block">Total Observed</span>
                  <span className="text-lg font-bold font-mono text-slate-100">{freshnessMetrics.total_observed}</span>
                </div>
                <div className="p-3 rounded bg-slate-950 border border-slate-800 text-center">
                  <span className="text-[10px] font-mono text-slate-400 block">Fresh Ratio</span>
                  <span className="text-lg font-bold font-mono text-emerald-400">
                    {(freshnessMetrics.freshness_ratio * 100).toFixed(0)}%
                  </span>
                </div>
                <div className="p-3 rounded bg-slate-950 border border-slate-800 text-center">
                  <span className="text-[10px] font-mono text-slate-400 block">Stale Count</span>
                  <span className="text-lg font-bold font-mono text-amber-400">{freshnessMetrics.stale_count}</span>
                </div>
                <div className="p-3 rounded bg-slate-950 border border-slate-800 text-center">
                  <span className="text-[10px] font-mono text-slate-400 block">Expired Count</span>
                  <span className="text-lg font-bold font-mono text-red-400">{freshnessMetrics.expired_count}</span>
                </div>
              </div>

              <div className="p-3 rounded bg-slate-950 border border-slate-800 space-y-2">
                <span className="text-xs font-mono text-slate-400">Source Freshness Breakdown:</span>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                  {Object.entries(freshnessMetrics.by_source || {}).map(([src, stats]: [string, any]) => (
                    <div key={src} className="p-2 rounded bg-slate-900 border border-slate-800 flex items-center justify-between text-xs font-mono">
                      <span className="text-slate-300 uppercase font-semibold">{src}</span>
                      <span className="text-slate-400">
                        {stats.fresh} fresh / {stats.total} total ({((stats.freshness_ratio || 0) * 100).toFixed(0)}%)
                      </span>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
};
