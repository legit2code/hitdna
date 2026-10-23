import React, { useState, useEffect } from 'react';
import {
  GitBranch,
  ExternalLink,
  Clock,
  Layers,
  ArrowRight,
  ShieldCheck,
  AlertCircle,
  Hash,
  Database,
  Info,
  RefreshCw,
  CornerDownRight,
  FileCode,
  Package,
  Globe,
  GitFork
} from 'lucide-react';
import { authenticatedFetch } from '../../lib/authClient.ts';

export interface DiscoveryLineageNode {
  depth: number;
  node_type: 'ROOT' | 'PIVOT' | 'TARGET';
  id?: string;
  label: string;
  url: string;
  edge_type?: string;
  discovered_at?: string;
  evidence?: {
    type: string;
    location: string;
    snippet_hash?: string;
  };
  decision?: string;
  rejection_reason?: string;
}

export interface DiscoveryLineageResponse {
  agent_id: string;
  canonical_name: string;
  found: boolean;
  depth: number;
  root_source: {
    id: string;
    source_adapter: string;
    root_type: string;
    root_value: string;
    created_at: string;
  } | null;
  immediate_parent: {
    edge_id: string;
    parent_edge_id?: string | null;
    source_candidate_id?: string | null;
    source_agent_id?: string | null;
    edge_type: string;
    discovered_url: string;
    crawl_depth: number;
    extractor: string;
    evidence_type: string;
    evidence_location: string;
    evidence_snippet_hash?: string;
    discovered_at: string;
  } | null;
  ancestor_chain: DiscoveryLineageNode[];
  full_path: string[];
}

export interface DescendantNode {
  edge_id: string;
  depth: number;
  edge_type: string;
  target_candidate_id: string;
  target_agent_id?: string;
  target_url: string;
  extractor: string;
  evidence: {
    type: string;
    location: string;
    snippet_hash?: string;
  };
  status: string;
  discovered_at: string;
}

export interface DiscoveredDescendantsResponse {
  agent_id: string;
  canonical_name: string;
  total_descendants: number;
  max_depth: number;
  descendants: DescendantNode[];
}

interface AgentDiscoveryLineageViewProps {
  agentId: string;
  canonicalName: string;
  sourceLocator?: string;
  createdAt?: string;
}

export const AgentDiscoveryLineageView: React.FC<AgentDiscoveryLineageViewProps> = ({
  agentId,
  canonicalName,
  sourceLocator,
  createdAt,
}) => {
  const [lineage, setLineage] = useState<DiscoveryLineageResponse | null>(null);
  const [descendants, setDescendants] = useState<DiscoveredDescendantsResponse | null>(null);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  const fetchLineage = async () => {
    setIsLoading(true);
    setError(null);
    try {
      const [linRes, descRes] = await Promise.allSettled([
        authenticatedFetch(`/api/agents/${agentId}/discovery-lineage`),
        authenticatedFetch(`/api/agents/${agentId}/discovered-descendants`),
      ]);

      if (linRes.status === 'fulfilled' && linRes.value.ok) {
        const data = await linRes.value.json();
        setLineage(data);
      } else {
        // Honest fallback if endpoint returns 404
        setLineage({
          agent_id: agentId,
          canonical_name: canonicalName,
          found: false,
          depth: 0,
          root_source: null,
          immediate_parent: null,
          ancestor_chain: [],
          full_path: [],
        });
      }

      if (descRes.status === 'fulfilled' && descRes.value.ok) {
        const descData = await descRes.value.json();
        setDescendants(descData);
      } else {
        setDescendants(null);
      }
    } catch (err: any) {
      setError(err?.message || 'Failed to load discovery lineage');
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    if (agentId) {
      fetchLineage();
    }
  }, [agentId]);

  const getEdgeTypeBadge = (edgeType?: string) => {
    switch (edgeType) {
      case 'ROOT_SOURCE':
        return <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-emerald-500/20 text-emerald-400 border border-emerald-500/30">ROOT SOURCE</span>;
      case 'README_LINK':
        return <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-cyan-500/20 text-cyan-400 border border-cyan-500/30">README LINK</span>;
      case 'DEPENDENCY':
      case 'DEV_DEPENDENCY':
        return <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-blue-500/20 text-blue-400 border border-blue-500/30">DEPENDENCY</span>;
      case 'MCP_REFERENCE':
        return <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-purple-500/20 text-purple-400 border border-purple-500/30">MCP SERVER</span>;
      case 'MAINTAINER_OTHER_REPO':
        return <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-indigo-500/20 text-indigo-400 border border-indigo-500/30">MAINTAINER REPO</span>;
      case 'FORK':
        return <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-amber-500/20 text-amber-400 border border-amber-500/30">FORK EXTENSION</span>;
      default:
        return <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-slate-700/50 text-slate-300 border border-slate-600">{edgeType || 'PIVOT'}</span>;
    }
  };

  if (isLoading) {
    return (
      <div id="lineage-loading-state" className="p-8 text-center space-y-3 font-mono text-xs">
        <RefreshCw className="w-6 h-6 text-cyan-500 animate-spin mx-auto" />
        <p className="text-slate-400">Reconstructing ancestor lineage from source.discovery_edges...</p>
      </div>
    );
  }

  const hasLineage = lineage && lineage.found && lineage.ancestor_chain.length > 0;

  return (
    <div id="agent-discovery-lineage-container" className="space-y-6">
      {/* Header bar */}
      <div className="flex items-center justify-between border-b border-slate-800 pb-4">
        <div>
          <h3 className="text-sm font-bold text-slate-200 flex items-center gap-2">
            <GitBranch className="w-4 h-4 text-cyan-400" />
            Discovery Graph Lineage & Provenance
          </h3>
          <p className="text-xs text-slate-400 mt-0.5">
            Reconstructed directly from <code className="text-cyan-300">source.discovery_edges</code> database table.
          </p>
        </div>
        <button
          id="refresh-lineage-btn"
          onClick={fetchLineage}
          className="px-3 py-1.5 rounded-lg border border-slate-800 bg-slate-900 hover:bg-slate-800 text-xs font-mono text-slate-300 flex items-center gap-1.5 transition-colors"
        >
          <RefreshCw className="w-3.5 h-3.5 text-slate-400" />
          Refresh Graph
        </button>
      </div>

      {error && (
        <div className="p-3 bg-rose-500/10 border border-rose-500/30 rounded-lg text-rose-400 text-xs font-mono flex items-center gap-2">
          <AlertCircle className="w-4 h-4 shrink-0" />
          {error}
        </div>
      )}

      {/* Honest Empty State */}
      {!hasLineage && (
        <div id="lineage-empty-card" className="bg-slate-900/60 border border-slate-800 rounded-xl p-6 text-center space-y-4">
          <div className="w-12 h-12 rounded-full bg-slate-800 flex items-center justify-center mx-auto text-slate-400">
            <Info className="w-6 h-6 text-slate-400" />
          </div>
          <div className="max-w-md mx-auto space-y-2">
            <span className="px-2.5 py-1 rounded-full text-[10px] font-mono uppercase bg-slate-800 text-slate-400 border border-slate-700">
              Direct / Seed Ingestion
            </span>
            <h4 className="text-sm font-semibold text-slate-200">No Multi-Hop Discovery Lineage</h4>
            <p className="text-xs text-slate-400 leading-relaxed">
              This agent was ingested directly from a configured root seed or registered manually without traversing multi-hop pivot signals.
              No ancestor edges exist in <code className="text-slate-300">source.discovery_edges</code> for this entity.
            </p>
          </div>

          <div className="bg-slate-950 p-4 rounded-lg border border-slate-850 max-w-lg mx-auto text-left font-mono text-xs space-y-1.5 text-slate-400">
            <div className="flex justify-between">
              <span className="text-slate-500">Source Locator:</span>
              <span className="text-slate-300 truncate max-w-xs">{sourceLocator || 'Direct API registration'}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-slate-500">First Seen:</span>
              <span className="text-slate-300">{createdAt ? new Date(createdAt).toLocaleString() : 'N/A'}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-slate-500">Lineage Depth:</span>
              <span className="text-slate-300">0 (Direct)</span>
            </div>
          </div>
        </div>
      )}

      {/* Active Lineage Display */}
      {hasLineage && (
        <div className="space-y-6">
          {/* Summary KPI Strip */}
          <div className="grid grid-cols-1 sm:grid-cols-4 gap-3">
            <div className="bg-slate-950 p-3.5 rounded-xl border border-slate-800">
              <span className="text-slate-500 text-[10px] font-mono block">CRAWL DEPTH</span>
              <span className="text-cyan-400 text-lg font-bold font-mono">Depth {lineage.depth}</span>
              <span className="text-slate-500 text-[10px] block mt-0.5">
                {lineage.depth === 0 ? 'Direct root seed' : `${lineage.depth} pivot hop(s) from root`}
              </span>
            </div>

            <div className="bg-slate-950 p-3.5 rounded-xl border border-slate-800">
              <span className="text-slate-500 text-[10px] font-mono block">ROOT ADAPTER</span>
              <span className="text-emerald-400 text-sm font-bold font-mono uppercase truncate block">
                {lineage.root_source?.source_adapter || 'N/A'}
              </span>
              <span className="text-slate-500 text-[10px] block mt-0.5 truncate" title={lineage.root_source?.root_value}>
                {lineage.root_source?.root_type || 'SEED'}
              </span>
            </div>

            <div className="bg-slate-950 p-3.5 rounded-xl border border-slate-800">
              <span className="text-slate-500 text-[10px] font-mono block">IMMEDIATE EDGE</span>
              <span className="text-purple-400 text-sm font-bold font-mono truncate block">
                {lineage.immediate_parent?.edge_type || 'ROOT_SOURCE'}
              </span>
              <span className="text-slate-500 text-[10px] block mt-0.5 truncate">
                Extractor: {lineage.immediate_parent?.extractor || 'seed_loader'}
              </span>
            </div>

            <div className="bg-slate-950 p-3.5 rounded-xl border border-slate-800">
              <span className="text-slate-500 text-[10px] font-mono block">DOWNSTREAM DESCENDANTS</span>
              <span className="text-amber-400 text-lg font-bold font-mono">
                {descendants?.total_descendants || 0}
              </span>
              <span className="text-slate-500 text-[10px] block mt-0.5">
                Agents/candidates spawned
              </span>
            </div>
          </div>

          {/* Breadcrumb Tree Path Visualizer */}
          <div className="bg-slate-950 p-5 rounded-xl border border-slate-800 space-y-4">
            <div className="flex items-center justify-between border-b border-slate-900 pb-3">
              <span className="font-bold text-xs text-slate-300 font-mono flex items-center gap-1.5">
                <Layers className="w-4 h-4 text-cyan-400" />
                Ancestor Provenance Chain (Root → Target)
              </span>
              <span className="text-[11px] font-mono text-slate-500">
                {lineage.ancestor_chain.length} node(s) in traversed graph
              </span>
            </div>

            {/* Stepper Timeline */}
            <div className="relative pl-6 space-y-6 before:absolute before:left-2.5 before:top-2 before:bottom-2 before:w-0.5 before:bg-slate-800">
              {lineage.ancestor_chain.map((node, idx) => {
                const isRoot = node.node_type === 'ROOT';
                const isTarget = node.node_type === 'TARGET';

                return (
                  <div key={idx} className="relative group">
                    {/* Circle marker */}
                    <div
                      className={`absolute -left-6 top-1 w-5 h-5 rounded-full border-2 flex items-center justify-center text-[10px] font-bold ${
                        isRoot
                          ? 'bg-emerald-950 border-emerald-500 text-emerald-400'
                          : isTarget
                          ? 'bg-cyan-950 border-cyan-400 text-cyan-300 ring-2 ring-cyan-500/20'
                          : 'bg-blue-950 border-blue-500 text-blue-400'
                      }`}
                    >
                      {node.depth}
                    </div>

                    {/* Card */}
                    <div
                      className={`p-4 rounded-xl border transition-all ${
                        isTarget
                          ? 'bg-slate-900/90 border-cyan-500/40 shadow-sm shadow-cyan-500/5'
                          : 'bg-slate-900/50 border-slate-800/80 hover:border-slate-700'
                      }`}
                    >
                      <div className="flex flex-wrap items-center justify-between gap-2 mb-2">
                        <div className="flex items-center gap-2">
                          <span
                            className={`px-2 py-0.5 rounded text-[10px] font-mono font-semibold uppercase ${
                              isRoot
                                ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30'
                                : isTarget
                                ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/30'
                                : 'bg-blue-500/20 text-blue-300 border border-blue-500/30'
                            }`}
                          >
                            {node.node_type} (Depth {node.depth})
                          </span>
                          {getEdgeTypeBadge(node.edge_type)}
                        </div>

                        {node.discovered_at && (
                          <span className="text-[11px] font-mono text-slate-500 flex items-center gap-1">
                            <Clock className="w-3 h-3 text-slate-500" />
                            {new Date(node.discovered_at).toLocaleString()}
                          </span>
                        )}
                      </div>

                      {/* Label & URL */}
                      <div className="space-y-1">
                        <a
                          href={node.url}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="text-xs font-mono font-medium text-slate-200 hover:text-cyan-300 transition-colors flex items-center gap-1.5 break-all"
                        >
                          {node.url}
                          <ExternalLink className="w-3 h-3 text-slate-500 shrink-0" />
                        </a>
                      </div>

                      {/* Evidence Container */}
                      {node.evidence && (
                        <div className="mt-3 p-2.5 rounded-lg bg-slate-950 border border-slate-850 font-mono text-[11px] space-y-1">
                          <div className="flex items-center justify-between text-slate-400">
                            <span className="text-slate-500 flex items-center gap-1">
                              <FileCode className="w-3 h-3 text-slate-500" />
                              Evidence Type:
                            </span>
                            <span className="text-slate-300">{node.evidence.type}</span>
                          </div>
                          <div className="flex items-center justify-between text-slate-400">
                            <span className="text-slate-500 flex items-center gap-1">
                              <Layers className="w-3 h-3 text-slate-500" />
                              Evidence Location:
                            </span>
                            <span className="text-cyan-400 font-semibold">{node.evidence.location}</span>
                          </div>
                          {node.evidence.snippet_hash && (
                            <div className="flex items-center justify-between text-slate-400">
                              <span className="text-slate-500 flex items-center gap-1">
                                <Hash className="w-3 h-3 text-slate-500" />
                                Snippet Hash:
                              </span>
                              <span className="text-slate-400 text-[10px] truncate max-w-xs font-mono">
                                {node.evidence.snippet_hash}
                              </span>
                            </div>
                          )}
                        </div>
                      )}
                    </div>
                  </div>
                );
              })}
            </div>
          </div>

          {/* Descendants (Reverse Traversal) */}
          <div className="bg-slate-950 p-5 rounded-xl border border-slate-800 space-y-4">
            <div className="flex items-center justify-between border-b border-slate-900 pb-3">
              <span className="font-bold text-xs text-slate-300 font-mono flex items-center gap-1.5">
                <CornerDownRight className="w-4 h-4 text-amber-400" />
                Discovered Descendants (Reverse Traversal)
              </span>
              <span className="text-[11px] font-mono text-slate-500">
                {descendants?.total_descendants || 0} downstream pivot(s)
              </span>
            </div>

            {(!descendants || descendants.descendants.length === 0) ? (
              <div className="p-4 text-center text-slate-500 font-mono text-xs">
                No downstream candidates or verified agents have been discovered from this agent yet.
              </div>
            ) : (
              <div className="space-y-3">
                {descendants.descendants.map((desc, idx) => (
                  <div
                    key={desc.edge_id || idx}
                    className="p-3.5 rounded-lg bg-slate-900/60 border border-slate-850 font-mono text-xs space-y-2"
                  >
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-2">
                        <span className="px-2 py-0.5 rounded text-[10px] bg-amber-500/20 text-amber-400 border border-amber-500/30">
                          +Hop {desc.depth}
                        </span>
                        {getEdgeTypeBadge(desc.edge_type)}
                      </div>
                      <span className="text-[10px] text-slate-500">
                        {new Date(desc.discovered_at).toLocaleString()}
                      </span>
                    </div>

                    <div className="flex items-center justify-between text-slate-200">
                      <a
                        href={desc.target_url}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="text-xs hover:text-cyan-300 transition-colors flex items-center gap-1.5 truncate max-w-md"
                      >
                        {desc.target_url}
                        <ExternalLink className="w-3 h-3 text-slate-500 shrink-0" />
                      </a>
                      <span className="text-[11px] text-slate-400">Extractor: {desc.extractor}</span>
                    </div>

                    {desc.evidence && (
                      <div className="text-[10px] text-slate-500 flex items-center gap-2 pt-1 border-t border-slate-850">
                        <span>Location: <strong className="text-slate-400">{desc.evidence.location}</strong></span>
                        {desc.evidence.snippet_hash && (
                          <span>Hash: <strong className="text-slate-400">{desc.evidence.snippet_hash.slice(0, 16)}...</strong></span>
                        )}
                      </div>
                    )}
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
};
