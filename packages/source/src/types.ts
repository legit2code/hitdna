import { z } from 'zod';
import { ProvenanceRecord, ProvenanceRecordSchema } from '../../contracts/src/provenance.ts';

// ---------------------------------------------------------------------------
// 1. Normalized Error Hierarchy & Auth Status Enums
// ---------------------------------------------------------------------------

export type SourceAuthMode = 'AUTHENTICATED' | 'ANONYMOUS' | 'DEGRADED' | 'DISABLED';
export type SourceAuthStatus = 'AUTHENTICATED' | 'ANONYMOUS' | 'MISSING_CREDENTIALS' | 'INVALID_CREDENTIALS' | 'EXPIRED_CREDENTIALS';
export type AdapterHealthStatus = 'HEALTHY' | 'DEGRADED' | 'DISABLED' | 'UNHEALTHY';

export type CandidateTypeHint = 
  | 'AGENT_REPOSITORY' 
  | 'PACKAGE_DISTRIBUTION' 
  | 'MODEL_WEIGHTS' 
  | 'CONTAINER_IMAGE' 
  | 'DATASET' 
  | 'TOOL_SPECIFICATION' 
  | 'UNSPECIFIED';

export type ArtifactType = 
  | 'SOURCE_ARCHIVE' 
  | 'GIT_REPOSITORY' 
  | 'PACKAGE_DISTRIBUTION'
  | 'WHEEL' 
  | 'SDIST' 
  | 'NPM_TARBALL' 
  | 'MODEL_FILE' 
  | 'MODEL_WEIGHTS_TREE'
  | 'CONTAINER_MANIFEST' 
  | 'CONTAINER_LAYER' 
  | 'DOCUMENTATION' 
  | 'SPECIFICATION'
  | 'OTHER';

export type RelationshipType = 
  | 'DEPENDENCY' 
  | 'DEV_DEPENDENCY' 
  | 'PEER_DEPENDENCY' 
  | 'UPSTREAM_SOURCE' 
  | 'FORK_OF' 
  | 'MAINTAINED_BY' 
  | 'BASE_IMAGE' 
  | 'BASE_MODEL' 
  | 'DATASET_REFERENCE' 
  | 'HOMEPAGE' 
  | 'DOCUMENTATION_LINK'
  | 'RELATED_PACKAGE';

export type ChangeTokenType = 'ETAG' | 'COMMIT_SHA' | 'VERSION' | 'DIGEST' | 'TIMESTAMP';

// ---------------------------------------------------------------------------
// 2. Data Transfer Objects & Schemas
// ---------------------------------------------------------------------------

export interface RateLimitState {
  limit: number;
  remaining: number;
  reset_at: string; // ISO datetime
  window_seconds: number;
  is_exhausted: boolean;
}

export interface SourcePolicy {
  source_type: string;
  source_name: string;
  auth_mode: SourceAuthMode;
  max_page_size: number;
  rate_limit_per_minute: number;
  retry_policy: {
    max_retries: number;
    backoff_factor: number;
    initial_delay_ms: number;
  };
  supported_query_families: string[];
  capabilities: {
    can_stream: boolean;
    can_search: boolean;
    provides_dependencies: boolean;
    provides_artifacts: boolean;
    requires_auth: boolean;
  };
}

export interface AdapterHealth {
  status: AdapterHealthStatus;
  auth_status: SourceAuthStatus;
  message: string;
  latency_ms?: number;
  rate_limit: RateLimitState;
  checked_at: string;
}

export interface CursorState {
  page?: number;
  offset?: number;
  token?: string;
  next_url?: string;
  last_id?: string;
  custom?: Record<string, unknown>;
}

export interface DiscoveryCriteria {
  query?: string;
  ecosystem?: string;
  tags?: string[];
  time_window?: {
    since?: string;
    until?: string;
  };
  limit?: number;
  sort?: 'stars' | 'updated' | 'relevance' | 'downloads' | 'recent';
  order?: 'asc' | 'desc';
  filters?: Record<string, unknown>;
}

export interface DiscoveryCandidate {
  source_locator: string;
  display_name: string;
  source_type: string;
  type_hint: CandidateTypeHint;
  confidence: number;
  summary?: string;
  raw_metadata: Record<string, unknown>;
  created_at?: string;
  updated_at?: string;
  discovered_at: string;
}

export interface DiscoveryResult {
  candidates: DiscoveryCandidate[];
  next_cursor: CursorState | null;
  has_more: boolean;
  rate_limit: RateLimitState;
  provenance: ProvenanceRecord;
}

export interface SourceMetadataResult {
  source_locator: string;
  raw_metadata: Record<string, unknown>;
  content_hash: string;
  observed_at: string;
  etag?: string;
  provenance: ProvenanceRecord;
}

export interface ArtifactLocatorEntry {
  artifact_type: ArtifactType;
  locator: string;
  filename?: string;
  size_bytes?: number;
  checksum_sha256?: string;
  mime_type?: string;
  download_url?: string;
  is_primary: boolean;
  metadata?: Record<string, unknown>;
}

export interface ResolvedArtifactLocatorsResult {
  source_locator: string;
  primary_locator: string;
  artifacts: ArtifactLocatorEntry[];
  provenance: ProvenanceRecord;
}

export interface CandidateRelationship {
  from_locator: string;
  target_locator: string;
  relationship_type: RelationshipType;
  target_type_hint?: CandidateTypeHint;
  depth: number;
  metadata?: Record<string, unknown>;
}

export interface DiscoveryRelationshipsResult {
  source_locator: string;
  relationships: CandidateRelationship[];
  provenance: ProvenanceRecord;
}

export interface ChangeTokenResult {
  source_locator: string;
  change_token: string;
  token_type: ChangeTokenType;
  last_modified?: string;
}

// ---------------------------------------------------------------------------
// 3. The Universal Shared Source Adapter Contract
// ---------------------------------------------------------------------------

export interface SourceAdapter {
  /**
   * The unique source type identifier (e.g. 'github', 'gitlab', 'pypi', 'npm', 'huggingface', 'dockerhub', 'codeberg')
   */
  readonly sourceType: string;

  /**
   * Human-readable display name of the source provider
   */
  readonly sourceName: string;

  /**
   * Semantic version of this adapter implementation
   */
  readonly adapterVersion: string;

  /**
   * Discovers candidate entities matching discovery criteria with cursor-based pagination.
   */
  discover(criteria: DiscoveryCriteria, cursor?: CursorState | null): Promise<DiscoveryResult>;

  /**
   * Fetches the complete, raw, unmodified metadata for a given source locator.
   */
  fetch_metadata(locator: string): Promise<SourceMetadataResult>;

  /**
   * Resolves all downloadable or referenceable artifact locators for a candidate.
   */
  resolve_artifact_locators(candidate: DiscoveryCandidate | string): Promise<ResolvedArtifactLocatorsResult>;

  /**
   * Enumerates all immediate relationships (dependencies, parent/forks, maintainers) for a candidate.
   */
  enumerate_relationships(candidate: DiscoveryCandidate | string): Promise<DiscoveryRelationshipsResult>;

  /**
   * Retrieves a lightweight change token (ETag, commit SHA, version, digest, timestamp) for rapid staleness checks.
   */
  get_change_token(candidate: DiscoveryCandidate | string): Promise<ChangeTokenResult>;

  /**
   * Returns the current rate limit tracking state for this source provider.
   */
  get_rate_limit_state(): RateLimitState;

  /**
   * Returns the operational policy, capability flags, and constraints for this source provider.
   */
  get_source_policy(): SourcePolicy;

  /**
   * Performs an operational health and credentials check against the source provider.
   */
  health_check(): Promise<AdapterHealth>;

  /**
   * Generates a compliant provenance record for an operation performed by this adapter.
   */
  generate_provenance(action: string, inputHashes?: string[], ruleId?: string): ProvenanceRecord;
}

// ---------------------------------------------------------------------------
// 4. HTTP Fetcher / Transport Interface for Unit Testing & Inversion of Control
// ---------------------------------------------------------------------------

export interface HttpResponse<T = any> {
  status: number;
  statusText: string;
  headers: Record<string, string>;
  data: T;
}

export type HttpFetcher = (url: string, options?: {
  method?: string;
  headers?: Record<string, string>;
  body?: string;
  timeoutMs?: number;
  sourceType?: string;
  pinnedTarget?: any;
}) => Promise<HttpResponse>;

// ---------------------------------------------------------------------------
// 5. P12 Web Search Provider & Brave Search Contracts
// ---------------------------------------------------------------------------

export interface WebSearchItem {
  title: string;
  url: string;
  description: string;
  source_hostname: string;
  published_at?: string;
  language?: string;
  raw_metadata?: Record<string, unknown>;
  confidence: number;
  discovered_at: string;
}

export interface WebSearchOptions {
  count?: number;
  offset?: number;
  country?: string;
  freshness?: 'pd' | 'pw' | 'pm' | 'py' | string; // past day, past week, past month, past year
  safesearch?: 'strict' | 'moderate' | 'off';
  domain_filter?: string[];
  search_lang?: string;
}

export interface WebSearchResult {
  query: string;
  provider: string;
  items: WebSearchItem[];
  total_results?: number;
  rate_limit: RateLimitState;
  provenance: ProvenanceRecord;
}

export interface WebSearchProvider {
  readonly providerName: string;
  readonly providerVersion: string;
  search(query: string, options?: WebSearchOptions): Promise<WebSearchResult>;
  get_rate_limit_state(): RateLimitState;
  health_check(): Promise<AdapterHealth>;
  generate_provenance(action: string, inputHashes?: string[], ruleId?: string): ProvenanceRecord;
}

// ---------------------------------------------------------------------------
// 6. P12 Query Strategy & Rules Registry
// ---------------------------------------------------------------------------

export type QueryFamily = 
  | 'AGENT_DISCOVERY' 
  | 'TOOL_ECOSYSTEM' 
  | 'MODEL_WEIGHTS' 
  | 'CODE_REPOSITORY' 
  | 'PACKAGE_DISTRIBUTION' 
  | 'CONTAINER_SANDBOX' 
  | 'SPECIFICATION_STANDARD' 
  | 'FRESHNESS_SWEEP';

export interface QueryRule {
  id: string;
  name: string;
  family: QueryFamily;
  template: string; // e.g. "{seed} autonomous agent OR multi-agent"
  description: string;
  target_sources?: string[];
  priority: number; // 1 (highest) to 10
  tags: string[];
  enabled: boolean;
}

// ---------------------------------------------------------------------------
// 7. P12 Freshness & Staleness Scheduling
// ---------------------------------------------------------------------------

export type FreshnessStatus = 'FRESH' | 'STALE' | 'EXPIRED' | 'UNKNOWN';

export interface FreshnessEvaluation {
  source_locator: string;
  source_type: string;
  status: FreshnessStatus;
  last_observed_at: string;
  age_seconds: number;
  ttl_seconds: number;
  change_token?: string;
  token_type?: ChangeTokenType;
  recommended_next_check: string;
}

export interface FreshnessMetrics {
  window: '1h' | '24h' | '7d' | '30d';
  total_observed: number;
  fresh_count: number;
  stale_count: number;
  expired_count: number;
  freshness_ratio: number;
  by_source: Record<string, { total: number; fresh: number; stale: number; freshness_ratio: number }>;
  by_strategy: Record<string, { total: number; fresh: number; stale: number }>;
  sample_coverage_note: string; // "Bounded Public Discovery Sample — Never complete Internet coverage"
}

// ---------------------------------------------------------------------------
// 8. P12 Artifact Classification Taxonomy
// ---------------------------------------------------------------------------

export type ArtifactTaxonomyCategory = 
  | 'AUTONOMOUS_AGENT' 
  | 'AGENT_FRAMEWORK_SDK' 
  | 'REASONING_MODEL' 
  | 'TOOL_OR_PLUGIN' 
  | 'CONTAINER_SANDBOX' 
  | 'AGENT_SPECIFICATION' 
  | 'EVALUATION_BENCHMARK' 
  | 'UNKNOWN_OR_UNCLASSIFIED';

export interface ClassificationSignal {
  feature: string;
  weight: number;
  matched: boolean;
  evidence: string;
}

export interface ArtifactClassification {
  primary_category: ArtifactTaxonomyCategory;
  confidence: number; // 0.0 to 1.0
  secondary_categories: Array<{ category: ArtifactTaxonomyCategory; confidence: number }>;
  signals: ClassificationSignal[];
  rationale: string;
  classified_at: string;
  provenance: ProvenanceRecord;
}

// ---------------------------------------------------------------------------
// 9. P12 Identity Resolution & Canonical Candidate Graph
// ---------------------------------------------------------------------------

export type IdentityResolutionOutcome = 
  | 'SAME_CANONICAL_AGENT' 
  | 'SAME_AGENT_DIFFERENT_VERSION' 
  | 'SAME_AGENT_DIFFERENT_DISTRIBUTION' 
  | 'RELATED_ENTITY' 
  | 'FORK_OR_DERIVATIVE' 
  | 'MIRROR' 
  | 'UNRESOLVED' 
  | 'DISTINCT';

export interface IdentityEvidenceScore {
  publisher_match: number;    // 0.0 - 1.0
  repo_match: number;         // 0.0 - 1.0
  homepage_match: number;     // 0.0 - 1.0
  manifest_match: number;     // 0.0 - 1.0
  checksum_match: number;     // 0.0 - 1.0
  distribution_match: number; // 0.0 - 1.0
  similarity_score: number;   // 0.0 - 1.0
  composite_confidence: number;
  details: string[];
}

export interface IdentityComparisonResult {
  source_a_locator: string;
  source_b_locator: string;
  outcome: IdentityResolutionOutcome;
  confidence: number;
  evidence: IdentityEvidenceScore;
  is_provisional: boolean;
  conflict_reasons?: string[];
  resolved_at: string;
  provenance: ProvenanceRecord;
}

export interface IdentityCandidateNode {
  id: string; // Canonical identifier or provisional cluster ID
  locators: string[];
  primary_locator: string;
  canonical_name: string;
  classification: ArtifactTaxonomyCategory;
  sources: string[];
  versions: string[];
  distributions: string[];
  metadata_summary: Record<string, unknown>;
  confidence: number;
  is_canonical: boolean;
  provisional: boolean;
}

export interface IdentityCandidateEdge {
  from: string;
  to: string;
  outcome: IdentityResolutionOutcome;
  confidence: number;
  evidence_summary: string;
  provenance_id: string;
}

export interface IdentityCandidateGraph {
  nodes: IdentityCandidateNode[];
  edges: IdentityCandidateEdge[];
  unresolved_conflicts_count: number;
  graph_provenance: ProvenanceRecord;
}

// ---------------------------------------------------------------------------
// 10. P12 Manual Review Queue for High-Value Unresolved Identity Conflicts
// ---------------------------------------------------------------------------

export type ManualReviewStatus = 'PENDING_REVIEW' | 'RESOLVED_CANONICAL' | 'RESOLVED_DISTINCT' | 'REJECTED';

export interface ManualReviewItem {
  id: string;
  created_at: string;
  updated_at: string;
  candidate_locators: string[];
  conflict_summary: string;
  suggested_outcome: IdentityResolutionOutcome;
  confidence: number;
  evidence: IdentityEvidenceScore;
  status: ManualReviewStatus;
  reviewed_by?: string;
  review_note?: string;
  resolved_outcome?: IdentityResolutionOutcome;
  resolved_canonical_id?: string;
}

// ---------------------------------------------------------------------------
// 11. P12 Recursive Expansion with Depth & Budget Controls
// ---------------------------------------------------------------------------

export interface ExpansionBudget {
  max_depth: number;
  max_total_candidates: number;
  max_calls_per_source: number;
  max_time_ms: number;
  stop_on_rate_limit_remaining: number;
}

export interface ExpansionTreeNode {
  locator: string;
  depth: number;
  source_type: string;
  discovered_from?: string;
  relationship_type?: string;
  children: ExpansionTreeNode[];
}

export interface RecursiveExpansionReport {
  expansion_id: string;
  root_locators: string[];
  depth_reached: number;
  total_nodes_visited: number;
  total_candidates_discovered: number;
  tree: ExpansionTreeNode[];
  budget_exhausted: boolean;
  budget_exhaustion_reason?: 'MAX_DEPTH' | 'MAX_CANDIDATES' | 'MAX_CALLS_PER_SOURCE' | 'TIMEOUT' | 'RATE_LIMIT_GUARD';
  duration_ms: number;
  provenance: ProvenanceRecord;
}

// ---------------------------------------------------------------------------
// 12. Prompt 04: Immutable Version Resolution & Provider Integrity Types
// ---------------------------------------------------------------------------

export type HashAlgorithm = 'sha256' | 'sha512' | 'sha1' | 'md5';

export interface ProviderIntegrityMetadata {
  algorithm: HashAlgorithm;
  expected_value: string;
  sri_string?: string;
  encoding: 'hex' | 'base64';
}

export interface ImmutableResolutionResult {
  source_type: string;
  mutable_locator: string;
  immutable_locator: string;
  resolved_version: string;
  commit_sha?: string;
  distribution_filename?: string;
  manifest_digest?: string;
  integrity_metadata?: ProviderIntegrityMetadata;
  is_immutable: boolean;
  metadata: Record<string, unknown>;
  is_container_artifact: boolean;
  is_source_code: boolean;
  acquisition_supported: boolean;
  unsupported_reason?: string;
  pivot_required?: boolean;
  canonical_pivots?: Array<{ provider: string; locator: string }>;
  resolved_at: string;
}

export interface IntegrityCheckResult {
  verified: boolean;
  algorithm: HashAlgorithm;
  expected: string;
  actual: string;
  matched: boolean;
  error?: string;
}

