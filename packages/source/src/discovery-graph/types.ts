/**
 * Architecture V2.0.1 — Discovery Graph Foundation Types
 * Physical Schema: source.discovery_roots, source.discovery_candidates, source.discovery_edges
 */

export type DiscoveryCandidateStatus =
  | 'DISCOVERED'
  | 'QUEUED'
  | 'FETCHING'
  | 'FETCHED'
  | 'CLASSIFYING'
  | 'VERIFIED_AGENT'
  | 'VERIFIED_NON_AGENT'
  | 'REJECTED'
  | 'DUPLICATE'
  | 'FAILED'
  | 'ROBOTS_BLOCKED'
  | 'RATE_LIMITED'
  | 'ACQUIRED'
  | 'IGNORED';

export type DiscoveryEdgeType =
  | 'ROOT_SOURCE'
  | 'README_LINK'
  | 'RELATED_PROJECT'
  | 'DEPENDENCY'
  | 'DEV_DEPENDENCY'
  | 'UPSTREAM_SOURCE'
  | 'MAINTAINER_OTHER_REPO'
  | 'FORK'
  | 'MCP_REFERENCE'
  | 'DEMO_LINK'
  | (string & {});

export type EdgeDecision =
  | 'PENDING'
  | 'QUEUED'
  | 'ACCEPTED'
  | 'REJECTED'
  | 'DEFERRED_CYCLE_BUDGET';

export type RejectionReason =
  | 'DEPTH_LIMIT'
  | 'PARENT_FANOUT_LIMIT'
  | 'ROOT_BUDGET_EXCEEDED'
  | 'CYCLE_BUDGET_EXCEEDED'
  | 'DUPLICATE'
  | 'ROBOTS_BLOCKED'
  | 'RATE_LIMITED'
  | 'UNRESOLVABLE_DOMAIN'
  | 'NON_AGENT_FILTER'
  | 'INVALID_LOCATOR'
  | 'GENERAL_LIBRARY'
  | 'DOCUMENTATION_ONLY'
  | 'UNRELATED_DOMAIN'
  | 'SOCIAL_PROFILE'
  | 'ASSET_OR_BADGE'
  | 'DONATION_LINK'
  | 'CORPORATE_OR_TERMS'
  | 'ANALYTICS_OR_AD'
  | 'LICENSE_PAGE'
  | 'STALE_FORK'
  | 'LOW_RELEVANCE';

export interface DiscoveryRootRecord {
  id: string;
  source_adapter: string;
  root_type: string;
  root_value: string;
  created_at: string;
  created_by: string;
  active: boolean;
  metadata_json: Record<string, any>;
}

export interface DiscoveryCandidateRecord {
  id: string;
  canonical_url: string;
  normalized_url: string;
  candidate_type: string;
  domain: string;
  content_hash: string | null;
  status: DiscoveryCandidateStatus;
  first_seen_at: string;
  last_seen_at: string;
  queued_at: string | null;
  processed_at: string | null;
  relevance_score: number;
  discovery_confidence: number;
  classification_confidence: number | null;
  classification: string | null;
  rejection_reason: string | null;
  metadata_json: Record<string, any>;
}

export interface DiscoveryEdgeRecord {
  id: string;
  root_seed_id: string;
  parent_edge_id: string | null;
  source_candidate_id: string | null;
  source_agent_id: string | null;
  target_candidate_id: string;
  discovered_url: string;
  normalized_url: string;
  edge_type: DiscoveryEdgeType;
  crawl_depth: number;
  extractor: string;
  evidence_type: string;
  evidence_location: string;
  evidence_snippet_hash: string | null;
  source_content_hash: string | null;
  discovered_at: string;
  queued_at: string | null;
  decision: EdgeDecision;
  rejection_reason: string | null;
  metadata_json: Record<string, any>;
}

export interface CrawlBoundariesConfig {
  max_crawl_depth: number;                // Mandatory = 4 (depth 0 = root)
  max_pivots_per_parent: number;          // Fanout limit per parent
  max_discoveries_per_root_per_cycle: number; // Cap per root in a single cycle
  max_pivots_per_discovery_cycle: number; // Global cap per cycle
  per_domain_concurrency?: number;        // Fairness limit
  enforce_relevance_gate?: boolean;       // If set, enforce relevance gate on pivots missing relevance_gate_decision
  skip_relevance_gate?: boolean;          // If set, bypass relevance gate
}

export interface RelevanceGateDecision {
  accepted: boolean;
  rejection_reason: RejectionReason | string | null;
  gate_reason: string;
  heuristic_used: string;
  is_llm_used: false;
}

export interface ExtractedPivot {
  discovered_url: string;
  normalized_url: string;
  canonical_url: string;
  candidate_type: string;
  domain: string;
  edge_type: DiscoveryEdgeType;
  extractor: string;
  evidence_type: string;
  evidence_location: string;
  evidence_snippet_hash?: string | null;
  discovery_confidence: number;
  metadata?: Record<string, any>;
  relevance_gate_decision?: RelevanceGateDecision;
}

export interface DiscoveryCycleReport {
  cycle_id: string;
  started_at: string;
  completed_at: string;
  roots_processed: number;
  candidates_evaluated: number;
  candidates_queued: number;
  edges_created: number;
  rejections_by_reason: Record<string, number>;
  safeguards_triggered: {
    depth_limit: number;
    parent_fanout_limit: number;
    root_budget_exceeded: number;
    cycle_budget_retained: number;
  };
}

export interface LineageEvidence {
  type: string;
  location: string;
  snippet_hash: string | null;
}

export interface LineageImmediateParent {
  edge_id: string;
  parent_agent_id: string | null;
  parent_candidate_id: string | null;
  parent_url: string | null;
  edge_type: DiscoveryEdgeType | string;
  evidence: LineageEvidence;
  crawl_depth: number;
  discovered_at: string;
}

export interface LineageRootSource {
  root_id: string;
  source_adapter: string;
  root_type: string;
  root_value: string;
  created_at: string;
  metadata?: Record<string, any>;
}

export interface LineageNode {
  depth: number;
  node_type: 'ROOT' | 'PIVOT' | 'TARGET';
  id: string;
  label: string;
  url: string;
  source_adapter?: string;
  edge_type?: DiscoveryEdgeType | string;
  evidence?: LineageEvidence;
  discovered_at: string;
  agent_id?: string | null;
  candidate_id?: string | null;
}

export interface DiscoveryLineageResponse {
  agent_id: string;
  candidate_id: string | null;
  canonical_name?: string | null;
  found: boolean;
  message?: string;
  immediate_parent: LineageImmediateParent | null;
  root_source: LineageRootSource | null;
  edge_type: DiscoveryEdgeType | string | null;
  evidence: LineageEvidence | null;
  depth: number;
  timestamps: {
    discovered_at: string | null;
    queued_at: string | null;
    first_seen_at: string | null;
  };
  ancestor_chain: LineageNode[];
  full_path: string[];
  raw_edges: DiscoveryEdgeRecord[];
}

export interface DescendantNode {
  depth: number;
  edge_id: string;
  edge_type: DiscoveryEdgeType | string;
  target_candidate_id: string;
  target_url: string;
  target_agent_id: string | null;
  target_status: string;
  decision: string;
  rejection_reason: string | null;
  evidence: LineageEvidence;
  discovered_at: string;
  children?: DescendantNode[];
}

export interface DiscoveredDescendantsResponse {
  agent_id: string;
  candidate_id: string | null;
  canonical_name?: string | null;
  total_descendants: number;
  max_depth: number;
  descendants: DescendantNode[];
  tree: DescendantNode[];
}

export interface DiscoveryObservabilityMetrics {
  discovery_candidates_seen_total: number;
  discovery_candidates_queued_total: number;
  discovery_candidates_verified_total: number;
  discovery_candidates_rejected_total: number;
  discovery_duplicates_total: number;
  discovery_pivots_generated_total: number;
  discovery_depth_rejections_total: number;
  discovery_budget_rejections_total: number;
  discovery_ssrf_rejections_total: number;
  discovery_robots_rejections_total: number;
  discovery_rate_limit_events_total: number;
  discovery_fetch_failures_total: number;
  discovery_source_latency: number;
  discovery_queue_depth: number;
  discovery_agents_per_root: number;
  discovery_pivot_conversion_rate: number;
}
