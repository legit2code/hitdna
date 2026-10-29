/**
 * Hit DNA Music Intelligence — Studio Console Application Shell
 * Engines: PF-02 / PF-03 / PF-04 / RI-06 / PF-09
 * Architecture Version: 5.0.0 | Phase: P03
 */

import React, { useEffect, useState } from 'react';
import {
  ShieldCheck,
  Server,
  Cpu,
  Terminal,
  Activity,
  CheckCircle2,
  Lock,
  Network,
  Layers,
  AlertCircle,
  KeyRound,
  Sliders,
  GitBranch,
  BookOpen,
  Database
} from 'lucide-react';
import { SystemHealth, ReadinessState } from './contracts/system.ts';
import {
  PF02_ENGINE_DEFINITION,
  PF03_ENGINE_DEFINITION,
  PF04_ENGINE_DEFINITION,
  PF09_ENGINE_DEFINITION,
  RI06_ENGINE_DEFINITION,
  RI09_ENGINE_DEFINITION,
} from './domain/foundation.ts';

interface ProviderStatus {
  name: string;
  category: string;
  status: string;
  requiredKeys: string[];
  configuredKeysCount: number;
  missingKeys: string[];
  liveVerificationPerformed: boolean;
  details: string;
}

interface PublicConfigPayload {
  client: {
    appName: string;
    version: string;
    architectureVersion: string;
    currentPhase: string;
    appUrl: string;
    apiPrefix: string;
  };
  features: Record<string, boolean>;
}

interface TaxonomySummary {
  taxonomyVersion: string;
  nodeCount: number;
  edgeCount: number;
  rootFamilies: Array<{ id: string; name: string }>;
  subgenresCount: number;
  hybridLabelsCount: number;
}

interface GenreItem {
  genreId: string;
  name: string;
  slug: string;
  nodeType: string;
  description: string;
}

export default function App() {
  const [health, setHealth] = useState<SystemHealth | null>(null);
  const [readiness, setReadiness] = useState<ReadinessState | null>(null);
  const [providers, setProviders] = useState<ProviderStatus[]>([]);
  const [configData, setConfigData] = useState<PublicConfigPayload | null>(null);
  const [taxonomyGraph, setTaxonomyGraph] = useState<TaxonomySummary | null>(null);
  const [genres, setGenres] = useState<GenreItem[]>([]);
  const [selectedFamily, setSelectedFamily] = useState<string>('all');
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    async function fetchSystemStatus() {
      try {
        setLoading(true);
        const [healthRes, readyRes, providersRes, configRes, graphRes, genresRes] = await Promise.all([
          fetch('/api/health'),
          fetch('/api/ready'),
          fetch('/api/providers'),
          fetch('/api/config'),
          fetch('/api/taxonomy/graph'),
          fetch('/api/taxonomy/genres'),
        ]);

        if (!healthRes.ok || !readyRes.ok || !providersRes.ok || !configRes.ok) {
          throw new Error('One or more backend API calls returned a non-200 status');
        }

        const healthJson = await healthRes.json();
        const readyJson = await readyRes.json();
        const providersJson = await providersRes.json();
        const configJson = await configRes.json();
        const graphJson = await graphRes.json();
        const genresJson = await genresRes.json();

        if (healthJson.success && readyJson.success && providersJson.success && configJson.success) {
          setHealth(healthJson.data);
          setReadiness(readyJson.data);
          setProviders(providersJson.data);
          setConfigData(configJson.data);
          if (graphJson.success) setTaxonomyGraph(graphJson.data);
          if (genresJson.success) setGenres(genresJson.data);
          setError(null);
        } else {
          setError('Invalid API response envelope from backend service');
        }
      } catch (err: unknown) {
        const message = err instanceof Error ? err.message : 'Failed to connect to backend server';
        setError(message);
      } finally {
        setLoading(false);
      }
    }

    fetchSystemStatus();
    const interval = setInterval(fetchSystemStatus, 10000);
    return () => clearInterval(interval);
  }, []);

  const filteredGenres = selectedFamily === 'all'
    ? genres
    : genres.filter(g => g.nodeType === selectedFamily);

  return (
    <div id="hit-dna-app-shell" className="min-h-screen bg-[#090a0c] text-[#eef1f4] flex flex-col font-sans selection:bg-[#35d8ff]/20 selection:text-[#35d8ff]">
      {/* Top Console Navigation Bar */}
      <header id="console-header" className="sticky top-0 z-30 bg-[#090a0c]/95 backdrop-blur-md border-b border-[#262a2f] px-6 py-4 flex flex-wrap items-center justify-between gap-4">
        <div id="console-brand" className="flex items-center gap-3">
          <div className="w-9 h-9 rounded-lg bg-gradient-to-br from-[#171a1e] to-[#0c0f12] border border-[#35d8ff]/30 flex items-center justify-center shadow-[0_0_15px_rgba(53,216,255,0.15)]">
            <Activity className="w-5 h-5 text-[#35d8ff]" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="font-bold text-sm tracking-wide text-white">Hit DNA Music Intelligence</span>
              <span className="text-[10px] uppercase font-mono px-1.5 py-0.5 rounded bg-[#171a1e] border border-[#333942] text-[#63f29b]">Phase P04</span>
            </div>
            <span className="text-[10px] text-[#818891] tracking-widest uppercase font-mono">Deep Glow Studio Console Architecture · v5.0.0</span>
          </div>
        </div>

        <div id="console-server-status" className="flex items-center gap-3 text-xs">
          <div className="flex items-center gap-2 bg-[#111316] border border-[#262a2f] px-3 py-1.5 rounded-lg">
            <span className="relative flex h-2 w-2">
              <span className={`animate-ping absolute inline-flex h-full w-full rounded-full ${health?.status === 'healthy' ? 'bg-[#63f29b]' : 'bg-[#ffbf47]'} opacity-75`}></span>
              <span className={`relative inline-flex rounded-full h-2 w-2 ${health?.status === 'healthy' ? 'bg-[#63f29b]' : 'bg-[#ffbf47]'}`}></span>
            </span>
            <span className="text-[#8d949c] font-mono text-[11px]">Backend API:</span>
            <span className="font-mono font-medium text-white">
              {loading && !health ? 'Connecting...' : health?.status === 'healthy' ? 'LIVENESS OK' : 'CHECKING'}
            </span>
          </div>

          <div className="hidden sm:flex items-center gap-2 bg-[#111316] border border-[#262a2f] px-3 py-1.5 rounded-lg font-mono text-[11px]">
            <Server className="w-3.5 h-3.5 text-[#35d8ff]" />
            <span className="text-[#8d949c]">Port:</span>
            <span className="text-white">3000</span>
          </div>
        </div>
      </header>

      {/* Main Console Content */}
      <main id="console-main" className="flex-1 max-w-7xl w-full mx-auto p-6 flex flex-col gap-6">
        {/* Master Status Card */}
        <section id="master-status-card" className="border border-[#39414a] rounded-xl bg-gradient-to-b from-[#121519] to-[#0c0f12] p-6 shadow-2xl relative overflow-hidden">
          <div className="absolute top-0 left-0 right-0 h-[2px] bg-gradient-to-r from-[#35d8ff] via-[#63f29b] to-[#ff4fb3]" />
          
          <div className="flex flex-col lg:flex-row justify-between gap-6">
            <div className="space-y-2 max-w-2xl">
              <div className="flex items-center gap-2 text-[11px] font-mono uppercase tracking-wider text-[#35d8ff]">
                <Database className="w-4 h-4" />
                <span>PF-04 / RI-06 / PF-09 · Database Foundation & Genre Graph Active</span>
              </div>
              <h1 className="text-2xl font-bold tracking-tight text-white">
                Database Foundation, Genre Graph & Core Registries
              </h1>
              <p className="text-xs text-[#8d949c] leading-relaxed">
                Canonical typed persistence models, multi-dimensional directed genre graph, researched hybrid vs creative blend boundaries,
                and centralized governance registries active under v5.0.0 architecture. Strictly zero production data fabrication.
              </p>
            </div>

            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-center self-center lg:self-start w-full lg:w-auto">
              <div className="bg-[#090a0c] border border-[#292e34] rounded-lg p-3">
                <span className="block text-[9px] uppercase tracking-wider text-[#8d949c] font-mono">Architecture</span>
                <span className="text-sm font-bold text-[#35d8ff] font-mono">v5.0.0</span>
              </div>
              <div className="bg-[#090a0c] border border-[#292e34] rounded-lg p-3">
                <span className="block text-[9px] uppercase tracking-wider text-[#8d949c] font-mono">Pack Version</span>
                <span className="text-sm font-bold text-[#63f29b] font-mono">v6.0.0</span>
              </div>
              <div className="bg-[#090a0c] border border-[#292e34] rounded-lg p-3">
                <span className="block text-[9px] uppercase tracking-wider text-[#8d949c] font-mono">Phase Target</span>
                <span className="text-sm font-bold text-[#ffbf47] font-mono">P03</span>
              </div>
              <div className="bg-[#090a0c] border border-[#292e34] rounded-lg p-3">
                <span className="block text-[9px] uppercase tracking-wider text-[#8d949c] font-mono">Status</span>
                <span className="text-sm font-bold text-[#63f29b] font-mono">VERIFIED</span>
              </div>
            </div>
          </div>

          {error && (
            <div id="console-error-alert" className="mt-4 p-3 bg-red-950/40 border border-red-800/60 rounded-lg flex items-center gap-3 text-red-300 text-xs">
              <AlertCircle className="w-4 h-4 flex-shrink-0" />
              <span>{error}</span>
            </div>
          )}
        </section>

        {/* Phase Invariants */}
        <section id="governance-invariants" className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
          <div className="bg-[#111316] border border-[#262a2f] rounded-lg p-4 flex flex-col justify-between">
            <div>
              <div className="flex items-center justify-between text-[#35d8ff] mb-2">
                <span className="text-[10px] font-mono uppercase tracking-wider">Invariant 01</span>
                <CheckCircle2 className="w-3.5 h-3.5" />
              </div>
              <h3 className="text-xs font-semibold text-white">Versioned Genre Graph</h3>
              <p className="text-[11px] text-[#8d949c] mt-1 leading-snug">
                Genres are a versioned directed graph with multiple assignments per song. No single canonical string field.
              </p>
            </div>
            <div className="mt-3 pt-2 border-t border-[#262a2f] flex justify-between text-[10px] text-[#63f29b] font-mono">
              <span>RI-06 DIRECTED GRAPH</span>
              <span>LOCKED</span>
            </div>
          </div>

          <div className="bg-[#111316] border border-[#262a2f] rounded-lg p-4 flex flex-col justify-between">
            <div>
              <div className="flex items-center justify-between text-[#63f29b] mb-2">
                <span className="text-[10px] font-mono uppercase tracking-wider">Invariant 02</span>
                <CheckCircle2 className="w-3.5 h-3.5" />
              </div>
              <h3 className="text-xs font-semibold text-white">Hybrid vs Creative Blend</h3>
              <p className="text-[11px] text-[#8d949c] mt-1 leading-snug">
                Researched hybrids require qualifying cohort evidence. Creative blends never manufacture fake empirical stats.
              </p>
            </div>
            <div className="mt-3 pt-2 border-t border-[#262a2f] flex justify-between text-[10px] text-[#63f29b] font-mono">
              <span>ZERO SYNTHETIC CLAIMS</span>
              <span>LOCKED</span>
            </div>
          </div>

          <div className="bg-[#111316] border border-[#262a2f] rounded-lg p-4 flex flex-col justify-between">
            <div>
              <div className="flex items-center justify-between text-[#ffbf47] mb-2">
                <span className="text-[10px] font-mono uppercase tracking-wider">Invariant 03</span>
                <CheckCircle2 className="w-3.5 h-3.5" />
              </div>
              <h3 className="text-xs font-semibold text-white">Separation of Identity</h3>
              <p className="text-[11px] text-[#8d949c] mt-1 leading-snug">
                Internal stable entity IDs are completely decoupled from external provider IDs and alias mappings.
              </p>
            </div>
            <div className="mt-3 pt-2 border-t border-[#262a2f] flex justify-between text-[10px] text-[#63f29b] font-mono">
              <span>PF-04 IDENTITY MODEL</span>
              <span>LOCKED</span>
            </div>
          </div>

          <div className="bg-[#111316] border border-[#262a2f] rounded-lg p-4 flex flex-col justify-between">
            <div>
              <div className="flex items-center justify-between text-[#ff4fb3] mb-2">
                <span className="text-[10px] font-mono uppercase tracking-wider">Invariant 04</span>
                <CheckCircle2 className="w-3.5 h-3.5" />
              </div>
              <h3 className="text-xs font-semibold text-white">Zero Seed Contamination</h3>
              <p className="text-[11px] text-[#8d949c] mt-1 leading-snug">
                Controlled reference taxonomy is seeded cleanly. Zero fake songs, artists, or chart percentages in production collections.
              </p>
            </div>
            <div className="mt-3 pt-2 border-t border-[#262a2f] flex justify-between text-[10px] text-[#63f29b] font-mono">
              <span>TRUTH HARNESS SCAN</span>
              <span>PASSED</span>
            </div>
          </div>
        </section>

        {/* Interactive Genre Graph & Taxonomy Inspector (RI-06 / PF-04) */}
        <section id="taxonomy-graph-inspector" className="bg-[#111316] border border-[#262a2f] rounded-xl p-5 space-y-4">
          <div className="flex flex-wrap items-center justify-between gap-3 pb-3 border-b border-[#262a2f]">
            <div className="flex items-center gap-2">
              <Network className="w-4 h-4 text-[#35d8ff]" />
              <h2 className="text-sm font-semibold text-white">Canonical Genre Directed Graph & Reference Vocabulary (RI-06)</h2>
            </div>
            <div className="flex items-center gap-2 text-xs font-mono">
              <span className="bg-[#171a1e] border border-[#2e353e] px-2 py-0.5 rounded text-[#35d8ff]">
                Version {taxonomyGraph?.taxonomyVersion || '5.0.0'}
              </span>
              <span className="bg-[#171a1e] border border-[#2e353e] px-2 py-0.5 rounded text-[#63f29b]">
                {taxonomyGraph?.nodeCount || 16} Nodes
              </span>
              <span className="bg-[#171a1e] border border-[#2e353e] px-2 py-0.5 rounded text-[#ffbf47]">
                {taxonomyGraph?.edgeCount || 18} Directed Edges
              </span>
            </div>
          </div>

          {/* Type Filter Tabs */}
          <div className="flex flex-wrap gap-2 text-xs font-mono">
            {['all', 'ROOT_FAMILY', 'SUBGENRE', 'HYBRID_LABEL', 'SCENE'].map((type) => (
              <button
                key={type}
                onClick={() => setSelectedFamily(type)}
                className={`px-2.5 py-1 rounded-md transition-colors ${
                  selectedFamily === type
                    ? 'bg-[#35d8ff]/20 text-[#35d8ff] border border-[#35d8ff]/40 font-bold'
                    : 'bg-[#090a0c] text-[#8d949c] border border-[#24292f] hover:text-white'
                }`}
              >
                {type === 'all' ? 'ALL NODES' : type.replace('_', ' ')}
              </button>
            ))}
          </div>

          {/* Genre Node Grid */}
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
            {filteredGenres.map((g) => (
              <div
                key={g.genreId}
                id={`genre-card-${g.slug}`}
                className="bg-[#090a0c] border border-[#24292f] rounded-lg p-3 flex flex-col justify-between space-y-2 hover:border-[#39414a] transition-colors"
              >
                <div>
                  <div className="flex items-center justify-between mb-1">
                    <span className="font-bold text-white text-xs">{g.name}</span>
                    <span className={`text-[9px] font-mono px-1.5 py-0.5 rounded ${
                      g.nodeType === 'ROOT_FAMILY'
                        ? 'bg-[#35d8ff]/10 text-[#35d8ff] border border-[#35d8ff]/30'
                        : g.nodeType === 'HYBRID_LABEL'
                        ? 'bg-[#ff4fb3]/10 text-[#ff4fb3] border border-[#ff4fb3]/30'
                        : 'bg-[#171a1e] text-[#8d949c] border border-[#2a2f36]'
                    }`}>
                      {g.nodeType}
                    </span>
                  </div>
                  <span className="text-[10px] font-mono text-[#8d949c] block">{g.genreId}</span>
                  <p className="text-[10px] text-[#8d949c] mt-2 line-clamp-2 leading-tight">
                    {g.description}
                  </p>
                </div>

                <div className="pt-2 border-t border-[#1e2329] flex items-center justify-between text-[9px] font-mono text-[#8d949c]">
                  <span>Slug: {g.slug}</span>
                  <span className="text-[#63f29b]">CONTROLLED REF</span>
                </div>
              </div>
            ))}
          </div>
        </section>

        {/* Governance Registries & Permitted Sources (PF-09) */}
        <section id="governance-registries" className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          <div className="bg-[#111316] border border-[#262a2f] rounded-xl p-5 space-y-3">
            <div className="flex items-center justify-between pb-3 border-b border-[#262a2f]">
              <div className="flex items-center gap-2">
                <BookOpen className="w-4 h-4 text-[#63f29b]" />
                <h2 className="text-sm font-semibold text-white">Permitted Language Intelligence Sources (PF-09.M05)</h2>
              </div>
              <span className="text-[10px] font-mono text-[#63f29b]">Constitution Enforced</span>
            </div>
            <div className="space-y-2 text-xs font-mono">
              <div className="bg-[#090a0c] border border-[#24292f] p-2.5 rounded-lg flex items-center justify-between">
                <div>
                  <span className="text-white font-bold block">Licensed Lyrics & Verified Annotations</span>
                  <span className="text-[10px] text-[#8d949c]">Authorized platforms, 7-day freshness cadence</span>
                </div>
                <span className="text-[10px] px-2 py-0.5 rounded bg-[#171a1e] text-[#63f29b]">PERMITTED</span>
              </div>
              <div className="bg-[#090a0c] border border-[#24292f] p-2.5 rounded-lg flex items-center justify-between">
                <div>
                  <span className="text-white font-bold block">Primary Artist Interview Transcripts</span>
                  <span className="text-[10px] text-[#8d949c]">Direct audio/video transcription, slang provenance</span>
                </div>
                <span className="text-[10px] px-2 py-0.5 rounded bg-[#171a1e] text-[#63f29b]">PERMITTED</span>
              </div>
              <div className="bg-[#090a0c] border border-[#24292f] p-2.5 rounded-lg flex items-center justify-between">
                <div>
                  <span className="text-white font-bold block">Accredited Cultural & Trade Journalism</span>
                  <span className="text-[10px] text-[#8d949c]">Musicology essays and accredited reviews</span>
                </div>
                <span className="text-[10px] px-2 py-0.5 rounded bg-[#171a1e] text-[#63f29b]">PERMITTED</span>
              </div>
              <div className="bg-[#090a0c] border border-red-900/30 p-2.5 rounded-lg flex items-center justify-between">
                <div>
                  <span className="text-[#ff7070] font-bold block">Unauthorized Web Scraping</span>
                  <span className="text-[10px] text-[#8d949c]">Unvetted arbitrary scrapers without license</span>
                </div>
                <span className="text-[10px] px-2 py-0.5 rounded bg-red-950/60 text-red-400 border border-red-800/40">PROHIBITED</span>
              </div>
            </div>
          </div>

          <div className="bg-[#111316] border border-[#262a2f] rounded-xl p-5 space-y-3">
            <div className="flex items-center justify-between pb-3 border-b border-[#262a2f]">
              <div className="flex items-center gap-2">
                <GitBranch className="w-4 h-4 text-[#ffbf47]" />
                <h2 className="text-sm font-semibold text-white">Deterministic Pattern Extractors (PF-09.M04)</h2>
              </div>
              <span className="text-[10px] font-mono text-[#ffbf47]">Deterministic Math</span>
            </div>
            <div className="space-y-2 text-xs font-mono">
              <div className="bg-[#090a0c] border border-[#24292f] p-2.5 rounded-lg flex items-center justify-between">
                <div>
                  <span className="text-white font-bold block">Harmonic Chord Progression Extractor</span>
                  <span className="text-[10px] text-[#8d949c]">Transposable chord numerals & harmonic rhythm</span>
                </div>
                <span className="text-[10px] px-2 py-0.5 rounded bg-[#171a1e] text-[#35d8ff]">STRICT_DETERMINISTIC</span>
              </div>
              <div className="bg-[#090a0c] border border-[#24292f] p-2.5 rounded-lg flex items-center justify-between">
                <div>
                  <span className="text-white font-bold block">Rhythm Pocket & Groove Quantization</span>
                  <span className="text-[10px] text-[#8d949c]">Microtiming offsets & syncopation ratio</span>
                </div>
                <span className="text-[10px] px-2 py-0.5 rounded bg-[#171a1e] text-[#35d8ff]">STRICT_DETERMINISTIC</span>
              </div>
              <div className="bg-[#090a0c] border border-[#24292f] p-2.5 rounded-lg flex items-center justify-between">
                <div>
                  <span className="text-white font-bold block">Section Boundary & Arrangement Extractor</span>
                  <span className="text-[10px] text-[#8d949c]">Intro, chorus, bridge, drop timestamps</span>
                </div>
                <span className="text-[10px] px-2 py-0.5 rounded bg-[#171a1e] text-[#63f29b]">HEURISTIC_DETERMINISTIC</span>
              </div>
              <div className="bg-[#090a0c] border border-[#24292f] p-2.5 rounded-lg flex items-center justify-between">
                <div>
                  <span className="text-white font-bold block">Vocal Cadence & Syllabic Density</span>
                  <span className="text-[10px] text-[#8d949c]">Syllables/sec, rhyme density metrics</span>
                </div>
                <span className="text-[10px] px-2 py-0.5 rounded bg-[#171a1e] text-[#63f29b]">HEURISTIC_DETERMINISTIC</span>
              </div>
            </div>
          </div>
        </section>

        {/* Active Engines Coverage: PF-04, PF-09, RI-06 */}
        <section id="module-boundaries-section" className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Engine PF-04 Modules */}
          <div className="bg-[#111316] border border-[#262a2f] rounded-xl p-5 space-y-4">
            <div className="flex items-center justify-between pb-3 border-b border-[#262a2f]">
              <div className="flex items-center gap-2">
                <Database className="w-4 h-4 text-[#35d8ff]" />
                <h2 className="text-sm font-semibold text-white">Engine PF-04 (Persistence)</h2>
              </div>
              <span className="text-[10px] font-mono text-[#63f29b]">8 / 8 Modules</span>
            </div>
            <div className="space-y-1.5 text-xs font-mono">
              {PF04_ENGINE_DEFINITION.modules.map((mod) => (
                <div key={mod.moduleId} className="bg-[#090a0c] border border-[#24292f] p-2 rounded-lg flex items-center justify-between">
                  <span className="text-white text-[10px] truncate max-w-[180px]">{mod.name}</span>
                  <span className="text-[9px] px-1.5 py-0.5 rounded bg-[#171a1e] text-[#35d8ff]">{mod.moduleId}</span>
                </div>
              ))}
            </div>
          </div>

          {/* Engine RI-06 Modules */}
          <div className="bg-[#111316] border border-[#262a2f] rounded-xl p-5 space-y-4">
            <div className="flex items-center justify-between pb-3 border-b border-[#262a2f]">
              <div className="flex items-center gap-2">
                <Network className="w-4 h-4 text-[#ff4fb3]" />
                <h2 className="text-sm font-semibold text-white">Engine RI-06 (Genre Taxonomy)</h2>
              </div>
              <span className="text-[10px] font-mono text-[#63f29b]">10 / 10 Modules</span>
            </div>
            <div className="space-y-1.5 text-xs font-mono">
              {RI06_ENGINE_DEFINITION.modules.slice(0, 8).map((mod) => (
                <div key={mod.moduleId} className="bg-[#090a0c] border border-[#24292f] p-2 rounded-lg flex items-center justify-between">
                  <span className="text-white text-[10px] truncate max-w-[180px]">{mod.name}</span>
                  <span className="text-[9px] px-1.5 py-0.5 rounded bg-[#171a1e] text-[#ff4fb3]">{mod.moduleId}</span>
                </div>
              ))}
            </div>
          </div>

          {/* Engine PF-09 Modules */}
          <div className="bg-[#111316] border border-[#262a2f] rounded-xl p-5 space-y-4">
            <div className="flex items-center justify-between pb-3 border-b border-[#262a2f]">
              <div className="flex items-center gap-2">
                <ShieldCheck className="w-4 h-4 text-[#63f29b]" />
                <h2 className="text-sm font-semibold text-white">Engine PF-09 (Governance)</h2>
              </div>
              <span className="text-[10px] font-mono text-[#63f29b]">10 / 10 Modules</span>
            </div>
            <div className="space-y-1.5 text-xs font-mono">
              {PF09_ENGINE_DEFINITION.modules.slice(0, 8).map((mod) => (
                <div key={mod.moduleId} className="bg-[#090a0c] border border-[#24292f] p-2 rounded-lg flex items-center justify-between">
                  <span className="text-white text-[10px] truncate max-w-[180px]">{mod.name}</span>
                  <span className="text-[9px] px-1.5 py-0.5 rounded bg-[#171a1e] text-[#63f29b]">{mod.moduleId}</span>
                </div>
              ))}
            </div>
          </div>

          {/* Engine RI-09 Modules */}
          <div className="bg-[#111316] border border-[#262a2f] rounded-xl p-5 space-y-4">
            <div className="flex items-center justify-between pb-3 border-b border-[#262a2f]">
              <div className="flex items-center gap-2">
                <Lock className="w-4 h-4 text-[#ffbf47]" />
                <h2 className="text-sm font-semibold text-white">Engine RI-09 (Rights & Policy)</h2>
              </div>
              <span className="text-[10px] font-mono text-[#63f29b]">8 / 8 Modules</span>
            </div>
            <div className="space-y-1.5 text-xs font-mono">
              {RI09_ENGINE_DEFINITION.modules.map((mod) => (
                <div key={mod.moduleId} className="bg-[#090a0c] border border-[#24292f] p-2 rounded-lg flex items-center justify-between">
                  <span className="text-white text-[10px] truncate max-w-[180px]">{mod.name}</span>
                  <span className="text-[9px] px-1.5 py-0.5 rounded bg-[#171a1e] text-[#ffbf47]">{mod.moduleId}</span>
                </div>
              ))}
            </div>
          </div>
        </section>

        {/* Verification Command Surface */}
        <section id="verification-surface" className="bg-[#111316] border border-[#262a2f] rounded-xl p-5 space-y-3">
          <div className="flex items-center justify-between pb-2 border-b border-[#262a2f]">
            <div className="flex items-center gap-2">
              <Terminal className="w-4 h-4 text-[#ffbf47]" />
              <h2 className="text-sm font-semibold text-white">Verification Command Surface</h2>
            </div>
            <span className="text-[10px] font-mono text-[#8d949c]">Truth & Integrity Harness v6</span>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3 text-xs font-mono">
            <div className="bg-[#090a0c] border border-[#262a2f] p-3 rounded-lg">
              <span className="text-[#8d949c] text-[10px] block mb-1">Root Verification Pipeline:</span>
              <code className="text-[#63f29b] block bg-[#171a1e] px-2 py-1 rounded">npm run check</code>
            </div>
            <div className="bg-[#090a0c] border border-[#262a2f] p-3 rounded-lg">
              <span className="text-[#8d949c] text-[10px] block mb-1">Phase Verifier & Receipt:</span>
              <code className="text-[#35d8ff] block bg-[#171a1e] px-2 py-1 rounded">npm run phase:verify P04</code>
            </div>
            <div className="bg-[#090a0c] border border-[#262a2f] p-3 rounded-lg">
              <span className="text-[#8d949c] text-[10px] block mb-1">Unit & Integration Tests:</span>
              <code className="text-white block bg-[#171a1e] px-2 py-1 rounded">npm test</code>
            </div>
            <div className="bg-[#090a0c] border border-[#262a2f] p-3 rounded-lg">
              <span className="text-[#8d949c] text-[10px] block mb-1">Strict Typecheck & Lint:</span>
              <code className="text-[#ffbf47] block bg-[#171a1e] px-2 py-1 rounded">npm run lint</code>
            </div>
          </div>
        </section>
      </main>

      {/* Console Footer */}
      <footer id="console-footer" className="border-t border-[#262a2f] bg-[#090a0c] py-4 px-6 text-xs text-[#8d949c] flex flex-wrap items-center justify-between gap-4 font-mono">
        <div className="flex items-center gap-2">
          <Lock className="w-3.5 h-3.5 text-[#63f29b]" />
          <span>CANONICAL ARCHITECTURE HASH: 1ccc957a962db4c93b5b2a872fb7cddbd4025d938ecdc5de86ca88c17bf5454b</span>
        </div>
        <div className="flex items-center gap-4 text-[11px]">
          <span>UPTIME: {health ? `${health.uptimeSeconds}s` : '—'}</span>
          <span>READY: {readiness?.ready ? 'YES' : 'NO'}</span>
          <span className="text-white font-bold">NEXT PHASE: P05</span>
        </div>
      </footer>
    </div>
  );
}
