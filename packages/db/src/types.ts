import { z } from 'zod';

// Security Domain Types
export const SecurityClassificationSchema = z.object({
  security_classification_id: z.string().uuid(),
  code: z.enum(['PUBLIC_METADATA', 'INTERNAL', 'SENSITIVE', 'VAULT_RESTRICTED']),
  rank: z.number().int().min(0).max(3),
  description: z.string(),
  created_at: z.string().datetime().optional(),
});
export type SecurityClassification = z.infer<typeof SecurityClassificationSchema>;

export const TenantSchema = z.object({
  tenant_id: z.string().uuid(),
  tenant_key: z.string(),
  display_name: z.string(),
  status: z.enum(['ACTIVE', 'SUSPENDED', 'DECOMMISSIONED']).default('ACTIVE'),
  created_at: z.string().datetime().optional(),
  updated_at: z.string().datetime().nullable().optional(),
});
export type Tenant = z.infer<typeof TenantSchema>;

export const AccessScopeSchema = z.object({
  scope_id: z.string().uuid(),
  scope_type: z.enum(['PLATFORM', 'ORGANIZATION']),
  tenant_id: z.string().uuid().nullable().optional(),
  created_at: z.string().datetime().optional(),
});
export type AccessScope = z.infer<typeof AccessScopeSchema>;

export const TenantMembershipSchema = z.object({
  tenant_membership_id: z.string().uuid(),
  tenant_id: z.string().uuid(),
  principal_id: z.string(),
  role_id: z.string().uuid(),
  status: z.enum(['ACTIVE', 'SUSPENDED', 'REVOKED']).default('ACTIVE'),
  joined_at: z.string().datetime().optional(),
  revoked_at: z.string().datetime().nullable().optional(),
});
export type TenantMembership = z.infer<typeof TenantMembershipSchema>;

export const RoleSchema = z.object({
  role_id: z.string().uuid(),
  role_key: z.string(),
  description: z.string(),
  status: z.enum(['ACTIVE', 'DEPRECATED']).default('ACTIVE'),
  created_at: z.string().datetime().optional(),
});
export type Role = z.infer<typeof RoleSchema>;

export const UserRoleSchema = z.object({
  user_role_id: z.string().uuid(),
  principal_id: z.string(),
  role_id: z.string().uuid(),
  granted_by: z.string(),
  granted_at: z.string().datetime().optional(),
  revoked_at: z.string().datetime().nullable().optional(),
});
export type UserRole = z.infer<typeof UserRoleSchema>;

export const AccessGrantSchema = z.object({
  access_grant_id: z.string().uuid(),
  principal_id: z.string(),
  grant_type: z.string(),
  target_scope: z.string().uuid().nullable().optional(),
  granted_by: z.string(),
  granted_at: z.string().datetime().optional(),
  expires_at: z.string().datetime().nullable().optional(),
  revoked_at: z.string().datetime().nullable().optional(),
});
export type AccessGrant = z.infer<typeof AccessGrantSchema>;

// Core Identity Domain Types
export const CanonicalAgentSchema = z.object({
  agent_id: z.string().uuid(),
  canonical_name: z.string().min(1),
  agent_type_concept_id: z.string().uuid().nullable().optional(),
  status: z.enum(['ACTIVE', 'DEPRECATED', 'SUSPENDED', 'MERGED']).default('ACTIVE'),
  identity_confidence: z.number().min(0).max(1).default(1.0),
  first_seen_at: z.string().datetime().optional(),
  last_seen_at: z.string().datetime().optional(),
  created_at: z.string().datetime().optional(),
  updated_at: z.string().datetime().nullable().optional(),
});
export type CanonicalAgent = z.infer<typeof CanonicalAgentSchema>;

export const AgentVersionSchema = z.object({
  agent_version_id: z.string().uuid(),
  agent_id: z.string().uuid(),
  version_label: z.string().nullable().optional(),
  source_commit: z.string().nullable().optional(),
  content_fingerprint: z.string(),
  release_date: z.string().datetime().nullable().optional(),
  supersedes_version_id: z.string().uuid().nullable().optional(),
  observed_at: z.string().datetime().optional(),
  created_at: z.string().datetime().optional(),
});
export type AgentVersion = z.infer<typeof AgentVersionSchema>;

export const PublisherSchema = z.object({
  publisher_id: z.string().uuid(),
  publisher_type_concept_id: z.string().uuid().nullable().optional(),
  canonical_name: z.string().min(1),
  verified_state: z.enum(['UNVERIFIED', 'VERIFIED', 'FLAGGED', 'REVOKED']).default('UNVERIFIED'),
  first_seen_at: z.string().datetime().optional(),
  last_seen_at: z.string().datetime().optional(),
  created_at: z.string().datetime().optional(),
});
export type Publisher = z.infer<typeof PublisherSchema>;

export const OrganizationSchema = z.object({
  organization_id: z.string().uuid(),
  organization_type_concept_id: z.string().uuid().nullable().optional(),
  canonical_name: z.string().min(1),
  homepage: z.string().url().nullable().optional(),
  verified_state: z.enum(['UNVERIFIED', 'VERIFIED', 'FLAGGED', 'REVOKED']).default('UNVERIFIED'),
  created_at: z.string().datetime().optional(),
});
export type Organization = z.infer<typeof OrganizationSchema>;

export const EntityRefSchema = z.object({
  entity_ref_id: z.string().uuid(),
  entity_kind: z.string(),
  native_id: z.string().uuid(),
  agent_id: z.string().uuid().nullable().optional(),
  agent_version_id: z.string().uuid().nullable().optional(),
  analysis_run_id: z.string().uuid().nullable().optional(),
  security_classification_id: z.string().uuid(),
  created_at: z.string().datetime().optional(),
});
export type EntityRef = z.infer<typeof EntityRefSchema>;

export const ExternalAliasSchema = z.object({
  external_alias_id: z.string().uuid(),
  entity_ref_id: z.string().uuid(),
  source_adapter_id: z.string().uuid().nullable().optional(),
  alias_type: z.string(),
  alias_value: z.string(),
  confidence: z.number().min(0).max(1).default(1.0),
  observed_at: z.string().datetime().optional(),
  created_at: z.string().datetime().optional(),
});
export type ExternalAlias = z.infer<typeof ExternalAliasSchema>;

// Source and Artifact Domain Types
export const SourceAdapterSchema = z.object({
  source_adapter_id: z.string().uuid(),
  adapter_key: z.string(),
  adapter_version: z.string(),
  source_type: z.string(),
  status: z.enum(['ACTIVE', 'DEPRECATED', 'DISABLED']).default('ACTIVE'),
  created_at: z.string().datetime().optional(),
});
export type SourceAdapter = z.infer<typeof SourceAdapterSchema>;

export const SourceObservationSchema = z.object({
  source_observation_id: z.string().uuid(),
  candidate_id: z.string().uuid().nullable().optional(),
  source_adapter_id: z.string().uuid(),
  source_locator: z.string(),
  observed_at: z.string().datetime().optional(),
  raw_metadata_locator: z.string().nullable().optional(),
  content_hash: z.string().nullable().optional(),
  scope_id: z.string().uuid(),
  security_classification_id: z.string().uuid(),
  created_at: z.string().datetime().optional(),
});
export type SourceObservation = z.infer<typeof SourceObservationSchema>;

export const DistributionSchema = z.object({
  distribution_id: z.string().uuid(),
  agent_version_id: z.string().uuid(),
  distribution_type_concept_id: z.string().uuid().nullable().optional(),
  ecosystem: z.string().nullable().optional(),
  locator: z.string(),
  version: z.string().nullable().optional(),
  publisher_id: z.string().uuid().nullable().optional(),
  source_observation_id: z.string().uuid(),
  created_at: z.string().datetime().optional(),
});
export type Distribution = z.infer<typeof DistributionSchema>;

export const ArtifactSchema = z.object({
  artifact_id: z.string().uuid(),
  agent_version_id: z.string().uuid().nullable().optional(),
  distribution_id: z.string().uuid().nullable().optional(),
  source_observation_id: z.string().uuid(),
  artifact_type_concept_id: z.string().uuid().nullable().optional(),
  content_hash: z.string(),
  storage_locator: z.string(),
  size_bytes: z.number().int().nullable().optional(),
  security_classification_id: z.string().uuid(),
  created_at: z.string().datetime().optional(),
});
export type Artifact = z.infer<typeof ArtifactSchema>;

export const ArtifactFileSchema = z.object({
  artifact_file_id: z.string().uuid(),
  artifact_id: z.string().uuid(),
  path: z.string(),
  media_type: z.string(),
  size_bytes: z.number().int().default(0),
  content_hash: z.string(),
  language_hint: z.string().nullable().optional(),
  created_at: z.string().datetime().optional(),
});
export type ArtifactFile = z.infer<typeof ArtifactFileSchema>;

export const SourceSpanSchema = z.object({
  source_span_id: z.string().uuid(),
  artifact_file_id: z.string().uuid(),
  start_line: z.number().int(),
  start_col: z.number().int(),
  end_line: z.number().int(),
  end_col: z.number().int(),
  byte_offset_start: z.number().int().nullable().optional(),
  byte_offset_end: z.number().int().nullable().optional(),
  symbol_hint: z.string().nullable().optional(),
  created_at: z.string().datetime().optional(),
});
export type SourceSpan = z.infer<typeof SourceSpanSchema>;

// Analysis Domain Types
export const AnalysisRunSchema = z.object({
  analysis_run_id: z.string().uuid(),
  agent_version_id: z.string().uuid(),
  scope_id: z.string().uuid(),
  pipeline_version: z.string(),
  caim_version: z.string(),
  ontology_version: z.string(),
  trigger_type: z.enum(['SCHEDULED', 'MANUAL', 'WEBHOOK', 'EVENT', 'VALIDATION_REPLAY']),
  status: z.enum(['PENDING', 'RUNNING', 'COMPLETED', 'PARTIAL', 'FAILED', 'CANCELLED']).default('PENDING'),
  static_status: z.string().optional(),
  dynamic_status: z.string().optional(),
  overall_status: z.string().optional(),
  execution_summary: z.record(z.string(), z.unknown()).optional(),
  started_at: z.string().datetime().optional(),
  completed_at: z.string().datetime().nullable().optional(),
  created_at: z.string().datetime().optional(),
});
export type AnalysisRun = z.infer<typeof AnalysisRunSchema>;

export const AnalysisStageRunSchema = z.object({
  stage_run_id: z.string().uuid(),
  analysis_run_id: z.string().uuid(),
  engine_key: z.string(),
  engine_version: z.string(),
  ruleset_version: z.string().nullable().optional(),
  model_version: z.string().nullable().optional(),
  input_snapshot_hash: z.string().nullable().optional(),
  status: z.enum(['PENDING', 'RUNNING', 'COMPLETED', 'FAILED', 'SKIPPED']).default('PENDING'),
  started_at: z.string().datetime().optional(),
  completed_at: z.string().datetime().nullable().optional(),
  failure_code: z.string().nullable().optional(),
  metrics: z.record(z.string(), z.unknown()).nullable().optional(),
  created_at: z.string().datetime().optional(),
});
export type AnalysisStageRun = z.infer<typeof AnalysisStageRunSchema>;

// Ontology Domain Types
export const OntologyVersionSchema = z.object({
  ontology_version_id: z.string().uuid(),
  version_label: z.string(),
  status: z.enum(['DRAFT', 'ACTIVE', 'DEPRECATED', 'SUPERSEDED']).default('ACTIVE'),
  released_at: z.string().datetime().nullable().optional(),
  supersedes_version_id: z.string().uuid().nullable().optional(),
  created_at: z.string().datetime().optional(),
});
export type OntologyVersion = z.infer<typeof OntologyVersionSchema>;

export const OntologyConceptSchema = z.object({
  concept_id: z.string().uuid(),
  ontology_version_id: z.string().uuid(),
  namespace: z.string(),
  canonical_name: z.string(),
  concept_type: z.string(),
  parent_concept_id: z.string().uuid().nullable().optional(),
  status: z.enum(['ACTIVE', 'DEPRECATED']).default('ACTIVE'),
  created_at: z.string().datetime().optional(),
});
export type OntologyConcept = z.infer<typeof OntologyConceptSchema>;

export const VersionRegistryEntrySchema = z.object({
  version_registry_id: z.string().uuid(),
  artifact_type: z.string(),
  artifact_key: z.string(),
  version: z.string(),
  status: z.enum(['DRAFT', 'ACTIVE', 'DEPRECATED', 'REVOKED']).default('ACTIVE'),
  content_hash: z.string(),
  activated_at: z.string().datetime().nullable().optional(),
  deprecated_at: z.string().datetime().nullable().optional(),
  created_at: z.string().datetime().optional(),
});
export type VersionRegistryEntry = z.infer<typeof VersionRegistryEntrySchema>;

// --- Epistemic Truth State & Observability Metadata (P04) ---
export const TRUTH_STATES = [
  'OBSERVED',
  'STATICALLY_DERIVED',
  'INFERRED',
  'SIMULATED',
  'EXTERNAL',
  'USER_DECLARED',
  'FIXTURE',
  'UNKNOWN',
] as const;
export const TruthStateSchema = z.enum(TRUTH_STATES);
export type TruthState = z.infer<typeof TruthStateSchema>;

// --- P04 Analysis Findings & Graph Types ---

export const StaticFindingSchema = z.object({
  finding_id: z.string().uuid(),
  analysis_run_id: z.string().uuid(),
  stage_run_id: z.string().uuid().nullable().optional(),
  entity_ref_id: z.string().uuid().nullable().optional(),
  source_span_id: z.string().uuid().nullable().optional(),
  rule_id: z.string(),
  finding_type: z.string(),
  severity: z.enum(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFORMATIONAL']),
  confidence: z.number().min(0).max(1).default(1.0),
  message: z.string(),
  location_hint: z.string().nullable().optional(),
  raw_payload: z.record(z.string(), z.unknown()).nullable().optional(),
  truth_state: TruthStateSchema.optional(),
  truthState: TruthStateSchema.optional(),
  source_id: z.string().optional(),
  sourceId: z.string().optional(),
  evidence_id: z.string().uuid().nullable().optional(),
  evidenceId: z.string().uuid().nullable().optional(),
  analyzer_version: z.string().optional(),
  analyzerVersion: z.string().optional(),
  observed_at: z.string().datetime().optional(),
  observedAt: z.string().datetime().optional(),
  limitations: z.string().nullable().optional(),
  created_at: z.string().datetime().optional(),
}).refine((data) => (data.truthState !== undefined && data.truthState !== null) || (data.truth_state !== undefined && data.truth_state !== null), {
  message: 'truthState is mandatory and must be explicitly specified (no default value permitted)',
  path: ['truthState'],
});
export type StaticFinding = z.infer<typeof StaticFindingSchema>;

export type CreateStaticFindingInput = Omit<StaticFinding, 'created_at'> & ({ truthState: TruthState } | { truth_state: TruthState });

export const CallGraphNodeSchema = z.object({
  node_id: z.string().uuid(),
  analysis_run_id: z.string().uuid(),
  stage_run_id: z.string().uuid().nullable().optional(),
  source_span_id: z.string().uuid().nullable().optional(),
  symbol_name: z.string(),
  node_type: z.string(),
  qualified_name: z.string(),
  properties: z.record(z.string(), z.unknown()).nullable().optional(),
  created_at: z.string().datetime().optional(),
});
export type CallGraphNode = z.infer<typeof CallGraphNodeSchema>;

export const CallGraphEdgeSchema = z.object({
  edge_id: z.string().uuid(),
  analysis_run_id: z.string().uuid(),
  caller_node_id: z.string().uuid(),
  callee_node_id: z.string().uuid(),
  call_type: z.enum(['DIRECT', 'DYNAMIC', 'DISPATCH', 'ASYNC']).default('DIRECT'),
  call_site_span_id: z.string().uuid().nullable().optional(),
  created_at: z.string().datetime().optional(),
});
export type CallGraphEdge = z.infer<typeof CallGraphEdgeSchema>;

export const TaintFlowSchema = z.object({
  taint_flow_id: z.string().uuid(),
  analysis_run_id: z.string().uuid(),
  stage_run_id: z.string().uuid().nullable().optional(),
  source_span_id: z.string().uuid().nullable().optional(),
  sink_span_id: z.string().uuid().nullable().optional(),
  source_type: z.string(),
  sink_type: z.string(),
  sanitizer_type: z.string().nullable().optional(),
  confidence: z.number().min(0).max(1).default(1.0),
  path_summary: z.string(),
  created_at: z.string().datetime().optional(),
});
export type TaintFlow = z.infer<typeof TaintFlowSchema>;

export const SbomComponentSchema = z.object({
  sbom_component_id: z.string().uuid(),
  analysis_run_id: z.string().uuid(),
  stage_run_id: z.string().uuid().nullable().optional(),
  purl: z.string().nullable().optional(),
  name: z.string(),
  version: z.string(),
  ecosystem: z.string(),
  license_expression: z.string().nullable().optional(),
  created_at: z.string().datetime().optional(),
});
export type SbomComponent = z.infer<typeof SbomComponentSchema>;

export const SbomDependencySchema = z.object({
  sbom_dependency_id: z.string().uuid(),
  analysis_run_id: z.string().uuid(),
  parent_component_id: z.string().uuid(),
  child_component_id: z.string().uuid(),
  dependency_scope: z.enum(['RUNTIME', 'DEV', 'OPTIONAL', 'PEER', 'TRANSITIVE']).default('RUNTIME'),
  created_at: z.string().datetime().optional(),
});
export type SbomDependency = z.infer<typeof SbomDependencySchema>;

export const RuntimeEventSchema = z.object({
  runtime_event_id: z.string().uuid(),
  analysis_run_id: z.string().uuid(),
  stage_run_id: z.string().uuid().nullable().optional(),
  entity_ref_id: z.string().uuid().nullable().optional(),
  event_type: z.string(),
  event_timestamp: z.string().datetime().optional(),
  duration_ms: z.number().int().nullable().optional(),
  source_locator: z.string().nullable().optional(),
  payload: z.record(z.string(), z.unknown()).nullable().optional(),
  status: z.enum(['RECORDED', 'ANOMALY', 'VIOLATION']).default('RECORDED'),
  truth_state: TruthStateSchema.optional(),
  truthState: TruthStateSchema.optional(),
  source_id: z.string().optional(),
  sourceId: z.string().optional(),
  evidence_id: z.string().uuid().nullable().optional(),
  evidenceId: z.string().uuid().nullable().optional(),
  analyzer_version: z.string().optional(),
  analyzerVersion: z.string().optional(),
  observed_at: z.string().datetime().optional(),
  observedAt: z.string().datetime().optional(),
  confidence: z.number().min(0).max(1).default(1.0),
  limitations: z.string().nullable().optional(),
  created_at: z.string().datetime().optional(),
}).refine((data) => (data.truthState !== undefined && data.truthState !== null) || (data.truth_state !== undefined && data.truth_state !== null), {
  message: 'truthState is mandatory and must be explicitly specified (no default value permitted)',
  path: ['truthState'],
});
export type RuntimeEvent = z.infer<typeof RuntimeEventSchema>;

export type CreateRuntimeEventInput = Omit<RuntimeEvent, 'created_at'> & ({ truthState: TruthState } | { truth_state: TruthState });

// --- P04 Intel Evidence, Assertions, Claims & Contradictions ---

export const ExternalIntelligenceRefSchema = z.object({
  intel_ref_id: z.string().uuid(),
  source_name: z.string(),
  external_id: z.string(),
  title: z.string(),
  url: z.string().nullable().optional(),
  severity: z.string().nullable().optional(),
  cvss_score: z.number().nullable().optional(),
  epss_score: z.number().nullable().optional(),
  published_date: z.string().nullable().optional(),
  created_at: z.string().datetime().optional(),
});
export type ExternalIntelligenceRef = z.infer<typeof ExternalIntelligenceRefSchema>;

export const EvidenceSchema = z.object({
  evidence_id: z.string().uuid(),
  analysis_run_id: z.string().uuid(),
  scope_id: z.string().uuid().optional(),
  stage_run_id: z.string().uuid().nullable().optional(),
  entity_ref_id: z.string().uuid().nullable().optional(),
  evidence_type: z.enum(['STATIC_CODE', 'AST_MATCH', 'DYNAMIC_CALL', 'METADATA_MANIFEST', 'EXTERNAL_INTEL', 'HEURISTIC']),
  source_span_id: z.string().uuid().nullable().optional(),
  source_observation_id: z.string().uuid().nullable().optional(),
  artifact_id: z.string().uuid().nullable().optional(),
  static_finding_id: z.string().uuid().nullable().optional(),
  runtime_event_id: z.string().uuid().nullable().optional(),
  external_intel_ref_id: z.string().uuid().nullable().optional(),
  description: z.string(),
  confidence: z.number().min(0).max(1).default(1.0),
  weight: z.number().min(0).max(1).default(1.0),
  truth_state: TruthStateSchema.optional(),
  truthState: TruthStateSchema.optional(),
  source_id: z.string().optional(),
  sourceId: z.string().optional(),
  analyzer_version: z.string().optional(),
  analyzerVersion: z.string().optional(),
  observed_at: z.string().datetime().optional(),
  observedAt: z.string().datetime().optional(),
  limitations: z.string().nullable().optional(),
  created_at: z.string().datetime().optional(),
}).refine((data) => (data.truthState !== undefined && data.truthState !== null) || (data.truth_state !== undefined && data.truth_state !== null), {
  message: 'truthState is mandatory and must be explicitly specified (no default value permitted)',
  path: ['truthState'],
});
export type Evidence = z.infer<typeof EvidenceSchema>;

export type CreateEvidenceInput = Omit<Evidence, 'created_at'> & ({ truthState: TruthState } | { truth_state: TruthState });

export const AssertionSchema = z.object({
  assertion_id: z.string().uuid(),
  analysis_run_id: z.string().uuid(),
  scope_id: z.string().uuid().optional(),
  stage_run_id: z.string().uuid().nullable().optional(),
  entity_ref_id: z.string().uuid().nullable().optional(),
  assertion_key: z.string(),
  concept_id: z.string().uuid().nullable().optional(),
  predicate: z.string(),
  subject_ref_id: z.string().uuid(),
  object_ref_id: z.string().uuid().nullable().optional(),
  assertion_value: z.string().nullable().optional(),
  confidence: z.number().min(0).max(1).default(1.0),
  uncertainty_score: z.number().min(0).max(1).default(0.0),
  uncertainty_factors: z.record(z.string(), z.unknown()).nullable().optional(),
  calibration_version: z.string().nullable().optional(),
  engine_key: z.string(),
  rule_id: z.string().nullable().optional(),
  created_at: z.string().datetime().optional(),
});
export type Assertion = z.infer<typeof AssertionSchema>;

export const AssertionEvidenceLinkSchema = z.object({
  link_id: z.string().uuid(),
  assertion_id: z.string().uuid(),
  evidence_id: z.string().uuid(),
  relationship_type: z.enum(['SUPPORTS', 'REFUTES', 'CONTEXTUALIZES']).default('SUPPORTS'),
  relevance_weight: z.number().min(0).max(1).default(1.0),
  created_at: z.string().datetime().optional(),
});
export type AssertionEvidenceLink = z.infer<typeof AssertionEvidenceLinkSchema>;

export const ClaimSchema = z.object({
  claim_id: z.string().uuid(),
  analysis_run_id: z.string().uuid(),
  scope_id: z.string().uuid().optional(),
  entity_ref_id: z.string().uuid().nullable().optional(),
  claim_type: z.enum(['SECURITY_POSTURE', 'CAPABILITY', 'COMPLIANCE', 'BEHAVIORAL_SAFETY', 'DATA_INTEGRITY', 'SUPPLY_CHAIN']),
  claim_text: z.string(),
  state: z.enum(['SUPPORTED', 'REFUTED', 'CONTESTED', 'UNVERIFIED']).default('SUPPORTED'),
  confidence: z.number().min(0).max(1).default(1.0),
  uncertainty_score: z.number().min(0).max(1).default(0.0),
  truth_state: TruthStateSchema.optional(),
  truthState: TruthStateSchema.optional(),
  source_id: z.string().optional(),
  sourceId: z.string().optional(),
  evidence_id: z.string().uuid().nullable().optional(),
  evidenceId: z.string().uuid().nullable().optional(),
  analyzer_version: z.string().optional(),
  analyzerVersion: z.string().optional(),
  observed_at: z.string().datetime().optional(),
  observedAt: z.string().datetime().optional(),
  limitations: z.string().nullable().optional(),
  created_at: z.string().datetime().optional(),
}).refine((data) => (data.truthState !== undefined && data.truthState !== null) || (data.truth_state !== undefined && data.truth_state !== null), {
  message: 'truthState is mandatory and must be explicitly specified (no default value permitted)',
  path: ['truthState'],
});
export type Claim = z.infer<typeof ClaimSchema>;

export type CreateClaimInput = Omit<Claim, 'created_at'> & ({ truthState: TruthState } | { truth_state: TruthState });

export const ClaimEvidenceLinkSchema = z.object({
  link_id: z.string().uuid(),
  claim_id: z.string().uuid(),
  evidence_id: z.string().uuid(),
  support_type: z.enum(['DIRECT_SUPPORT', 'INDIRECT_SUPPORT', 'CONTRADICTORY', 'MITIGATING']).default('DIRECT_SUPPORT'),
  weight: z.number().min(0).max(1).default(1.0),
  created_at: z.string().datetime().optional(),
});
export type ClaimEvidenceLink = z.infer<typeof ClaimEvidenceLinkSchema>;

export const ClaimSupportLinkSchema = z.object({
  link_id: z.string().uuid(),
  claim_id: z.string().uuid(),
  assertion_id: z.string().uuid(),
  link_type: z.enum(['SUPPORTS', 'CONTRADICTS', 'DERIVED_FROM']).default('SUPPORTS'),
  created_at: z.string().datetime().optional(),
});
export type ClaimSupportLink = z.infer<typeof ClaimSupportLinkSchema>;

export const ContradictionSchema = z.object({
  contradiction_id: z.string().uuid(),
  analysis_run_id: z.string().uuid(),
  claim_a_id: z.string().uuid().nullable().optional(),
  claim_b_id: z.string().uuid().nullable().optional(),
  assertion_a_id: z.string().uuid().nullable().optional(),
  assertion_b_id: z.string().uuid().nullable().optional(),
  conflict_reason: z.string(),
  severity: z.enum(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']),
  resolution_status: z.enum(['UNRESOLVED', 'RESOLVED_A', 'RESOLVED_B', 'ACCEPTED_AMBIGUITY']).default('UNRESOLVED'),
  created_at: z.string().datetime().optional(),
});
export type Contradiction = z.infer<typeof ContradictionSchema>;

// --- P04 Intel Risks, Scoring, Policies, Decisions & Recommendations ---

export const RiskSchema = z.object({
  risk_id: z.string().uuid(),
  analysis_run_id: z.string().uuid(),
  entity_ref_id: z.string().uuid().nullable().optional(),
  claim_id: z.string().uuid().nullable().optional(),
  risk_type: z.string(),
  title: z.string(),
  description: z.string(),
  severity: z.enum(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFORMATIONAL']),
  likelihood: z.number().min(0).max(1).default(1.0),
  impact: z.number().min(0).max(1).default(1.0),
  risk_score: z.number().default(0.0),
  remediation_guidance: z.string().nullable().optional(),
  created_at: z.string().datetime().optional(),
});
export type Risk = z.infer<typeof RiskSchema>;

export const ScoreModelSchema = z.object({
  score_model_id: z.string().uuid(),
  model_key: z.string(),
  version: z.string(),
  formula_type: z.string(),
  status: z.enum(['ACTIVE', 'DEPRECATED']).default('ACTIVE'),
  created_at: z.string().datetime().optional(),
});
export type ScoreModel = z.infer<typeof ScoreModelSchema>;

export const ScoreDimensionSchema = z.object({
  dimension_id: z.string().uuid(),
  score_model_id: z.string().uuid(),
  dimension_key: z.string(),
  display_name: z.string(),
  weight: z.number().min(0).max(1).default(1.0),
  created_at: z.string().datetime().optional(),
});
export type ScoreDimension = z.infer<typeof ScoreDimensionSchema>;

export const ScoreResultSchema = z.object({
  score_result_id: z.string().uuid(),
  analysis_run_id: z.string().uuid(),
  score_model_id: z.string().uuid(),
  overall_score: z.number(),
  grade: z.string().nullable().optional(),
  calibration_version: z.string(),
  created_at: z.string().datetime().optional(),
});
export type ScoreResult = z.infer<typeof ScoreResultSchema>;

export const ScoreDimensionValueSchema = z.object({
  score_dimension_value_id: z.string().uuid(),
  score_result_id: z.string().uuid(),
  dimension_id: z.string().uuid(),
  raw_value: z.number(),
  weighted_value: z.number(),
  created_at: z.string().datetime().optional(),
});
export type ScoreDimensionValue = z.infer<typeof ScoreDimensionValueSchema>;

export const PolicyVersionSchema = z.object({
  policy_version_id: z.string().uuid(),
  policy_key: z.string(),
  version: z.string(),
  name: z.string(),
  description: z.string().nullable().optional(),
  status: z.enum(['ACTIVE', 'DEPRECATED', 'DRAFT']).default('ACTIVE'),
  created_at: z.string().datetime().optional(),
});
export type PolicyVersion = z.infer<typeof PolicyVersionSchema>;

export const PolicyRuleSchema = z.object({
  rule_id: z.string().uuid(),
  policy_version_id: z.string().uuid(),
  rule_key: z.string(),
  rule_name: z.string(),
  severity: z.enum(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']),
  condition_expression: z.string(),
  created_at: z.string().datetime().optional(),
});
export type PolicyRule = z.infer<typeof PolicyRuleSchema>;

export const PolicyDecisionSchema = z.object({
  decision_id: z.string().uuid(),
  analysis_run_id: z.string().uuid(),
  policy_version_id: z.string().uuid(),
  decision: z.enum(['PASS', 'FAIL', 'WARN', 'MANUAL_REVIEW']),
  evaluation_summary: z.string(),
  created_at: z.string().datetime().optional(),
});
export type PolicyDecision = z.infer<typeof PolicyDecisionSchema>;

export const PolicyDecisionReasonSchema = z.object({
  reason_id: z.string().uuid(),
  decision_id: z.string().uuid(),
  rule_id: z.string().uuid().nullable().optional(),
  risk_id: z.string().uuid().nullable().optional(),
  reason_text: z.string(),
  is_blocking: z.boolean().default(false),
  created_at: z.string().datetime().optional(),
});
export type PolicyDecisionReason = z.infer<typeof PolicyDecisionReasonSchema>;

export const RecommendationSchema = z.object({
  recommendation_id: z.string().uuid(),
  analysis_run_id: z.string().uuid(),
  entity_ref_id: z.string().uuid().nullable().optional(),
  risk_id: z.string().uuid().nullable().optional(),
  recommendation_type: z.string(),
  title: z.string(),
  action_steps: z.string(),
  priority: z.enum(['P0', 'P1', 'P2', 'P3']),
  effort_estimate: z.enum(['LOW', 'MEDIUM', 'HIGH']).nullable().optional(),
  created_at: z.string().datetime().optional(),
});
export type Recommendation = z.infer<typeof RecommendationSchema>;

export const UseCaseSchema = z.object({
  use_case_id: z.string().uuid(),
  use_case_key: z.string(),
  title: z.string(),
  description: z.string(),
  category: z.string(),
  created_at: z.string().datetime().optional(),
});
export type UseCase = z.infer<typeof UseCaseSchema>;

export const UseCaseEvaluationSchema = z.object({
  evaluation_id: z.string().uuid(),
  analysis_run_id: z.string().uuid(),
  use_case_id: z.string().uuid(),
  suitability: z.enum(['APPROVED', 'CONDITIONALLY_APPROVED', 'DISAPPROVED', 'UNKNOWN']),
  suitability_score: z.number().min(0).max(1).default(1.0),
  justification: z.string(),
  created_at: z.string().datetime().optional(),
});
export type UseCaseEvaluation = z.infer<typeof UseCaseEvaluationSchema>;

// --- Intel Lineage & Provenance Types ---

export const LineageEdgeSchema = z.object({
  lineage_edge_id: z.string().uuid(),
  from_entity_ref_id: z.string().uuid(),
  to_entity_ref_id: z.string().uuid(),
  lineage_type: z.string(),
  analysis_run_id: z.string().uuid().nullable().optional(),
  stage_run_id: z.string().uuid().nullable().optional(),
  transformation_version: z.string().nullable().optional(),
  confidence: z.number().min(0).max(1).default(1.0),
  created_at: z.string().datetime().optional(),
});
export type LineageEdge = z.infer<typeof LineageEdgeSchema>;

export interface BackwardLineageNode {
  claim: Claim;
  assertions: Array<{
    assertion: Assertion;
    link_type: string;
    evidence: Array<{
      evidence: Evidence;
      relationship_type: string;
      finding?: StaticFinding | null;
      sourceSpan?: SourceSpan | null;
      observation?: SourceObservation | null;
      artifact?: Artifact | null;
    }>;
  }>;
  directEvidence: Array<{
    evidence: Evidence;
    support_type: string;
    finding?: StaticFinding | null;
    sourceSpan?: SourceSpan | null;
    observation?: SourceObservation | null;
    artifact?: Artifact | null;
  }>;
}

// --- P05 Knowledge & RAG Types ---

export const KnowledgeObjectSchema = z.object({
  knowledge_object_id: z.string().uuid(),
  entity_ref_id: z.string().uuid(),
  object_type: z.string(),
  agent_id: z.string().uuid().nullable().optional(),
  agent_version_id: z.string().uuid().nullable().optional(),
  analysis_run_id: z.string().uuid().nullable().optional(),
  security_classification_id: z.string().uuid(),
  projection_version: z.string(),
  created_at: z.string().datetime().optional(),
  updated_at: z.string().datetime().optional(),
});
export type KnowledgeObject = z.infer<typeof KnowledgeObjectSchema>;

export const KnowledgeProjectionSchema = z.object({
  knowledge_projection_id: z.string().uuid(),
  knowledge_object_id: z.string().uuid(),
  projection_type: z.string(),
  projection_version: z.string(),
  payload: z.record(z.string(), z.unknown()).default({}),
  stale: z.boolean().default(false),
  indexed_at: z.string().datetime().nullable().optional(),
  created_at: z.string().datetime().optional(),
});
export type KnowledgeProjection = z.infer<typeof KnowledgeProjectionSchema>;

export const KnowledgeChunkSchema = z.object({
  knowledge_chunk_id: z.string().uuid(),
  knowledge_projection_id: z.string().uuid(),
  sequence: z.number().int(),
  content_hash: z.string(),
  text_or_locator: z.string(),
  token_count: z.number().int().nullable().optional(),
  security_classification_id: z.string().uuid(),
  created_at: z.string().datetime().optional(),
});
export type KnowledgeChunk = z.infer<typeof KnowledgeChunkSchema>;

export const EmbeddingSchema = z.object({
  embedding_id: z.string().uuid(),
  knowledge_chunk_id: z.string().uuid().nullable().optional(),
  knowledge_object_id: z.string().uuid().nullable().optional(),
  embedding_model_version: z.string(),
  dimensions: z.number().int(),
  vector: z.string().nullable().optional(),
  created_at: z.string().datetime().optional(),
});
export type Embedding = z.infer<typeof EmbeddingSchema>;

export const IndexStateSchema = z.object({
  index_state_id: z.string().uuid(),
  knowledge_object_id: z.string().uuid(),
  index_type: z.string(),
  index_version: z.string(),
  source_version_hash: z.string(),
  stale: z.boolean().default(false),
  last_indexed_at: z.string().datetime().optional(),
});
export type IndexState = z.infer<typeof IndexStateSchema>;

export const QuerySessionSchema = z.object({
  query_session_id: z.string().uuid(),
  principal_id: z.string(),
  started_at: z.string().datetime().optional(),
  ended_at: z.string().datetime().nullable().optional(),
  access_context_hash: z.string(),
  created_at: z.string().datetime().optional(),
});
export type QuerySession = z.infer<typeof QuerySessionSchema>;

export const QuerySchema = z.object({
  query_id: z.string().uuid(),
  query_session_id: z.string().uuid().nullable().optional(),
  principal_id: z.string(),
  query_text_or_hash: z.string(),
  received_at: z.string().datetime().optional(),
  intent_type: z.string().nullable().optional(),
  security_classification_id: z.string().uuid(),
  created_at: z.string().datetime().optional(),
});
export type Query = z.infer<typeof QuerySchema>;

export const QueryPlanSchema = z.object({
  query_plan_id: z.string().uuid(),
  query_id: z.string().uuid(),
  planner_version: z.string(),
  plan_payload: z.record(z.string(), z.unknown()).default({}),
  cost_budget: z.number().nullable().optional(),
  created_at: z.string().datetime().optional(),
});
export type QueryPlan = z.infer<typeof QueryPlanSchema>;

export const RetrievalRunSchema = z.object({
  retrieval_run_id: z.string().uuid(),
  query_plan_id: z.string().uuid(),
  retrieval_type: z.string(),
  index_version: z.string().nullable().optional(),
  started_at: z.string().datetime().optional(),
  completed_at: z.string().datetime().nullable().optional(),
  status: z.enum(['PENDING', 'RUNNING', 'COMPLETED', 'FAILED']).default('PENDING'),
  created_at: z.string().datetime().optional(),
});
export type RetrievalRun = z.infer<typeof RetrievalRunSchema>;

export const RetrievalResultSchema = z.object({
  retrieval_result_id: z.string().uuid(),
  retrieval_run_id: z.string().uuid(),
  knowledge_object_id: z.string().uuid(),
  rank: z.number().int(),
  score: z.number().nullable().optional(),
  retrieval_method: z.string(),
  authorized: z.boolean().default(true),
});
export type RetrievalResult = z.infer<typeof RetrievalResultSchema>;

export const ContextPackageSchema = z.object({
  context_package_id: z.string().uuid(),
  query_id: z.string().uuid(),
  assembler_version: z.string(),
  content_hash: z.string(),
  token_count: z.number().int().default(0),
  storage_locator: z.string().nullable().optional(),
  created_at: z.string().datetime().optional(),
});
export type ContextPackage = z.infer<typeof ContextPackageSchema>;

export const AnswerSchema = z.object({
  answer_id: z.string().uuid(),
  query_id: z.string().uuid(),
  context_package_id: z.string().uuid().nullable().optional(),
  model_version: z.string(),
  prompt_version: z.string(),
  answer_text_or_locator: z.string(),
  status: z.enum(['PENDING', 'GENERATING', 'COMPLETED', 'FAILED']).default('COMPLETED'),
  created_at: z.string().datetime().optional(),
});
export type Answer = z.infer<typeof AnswerSchema>;

export const AnswerClaimSchema = z.object({
  answer_claim_id: z.string().uuid(),
  answer_id: z.string().uuid(),
  sequence: z.number().int(),
  claim_text: z.string(),
  grounding_state: z.enum(['GROUNDED', 'PARTIALLY_GROUNDED', 'UNGROUNDED', 'CONTRADICTED']).default('UNGROUNDED'),
  confidence: z.number().min(0).max(1).default(1.0),
  truth_state: TruthStateSchema.optional(),
  truthState: TruthStateSchema.optional(),
  source_id: z.string().optional(),
  sourceId: z.string().optional(),
  evidence_id: z.string().uuid().nullable().optional(),
  evidenceId: z.string().uuid().nullable().optional(),
  analyzer_version: z.string().optional(),
  analyzerVersion: z.string().optional(),
  observed_at: z.string().datetime().optional(),
  observedAt: z.string().datetime().optional(),
  limitations: z.string().nullable().optional(),
}).refine((data) => (data.truthState !== undefined && data.truthState !== null) || (data.truth_state !== undefined && data.truth_state !== null), {
  message: 'truthState is mandatory and must be explicitly specified (no default value permitted)',
  path: ['truthState'],
});
export type AnswerClaim = z.infer<typeof AnswerClaimSchema>;

export type CreateAnswerClaimInput = AnswerClaim & ({ truthState: TruthState } | { truth_state: TruthState });

// --- Ops Telemetry Records Types ---
export const TelemetryRecordSchema = z.object({
  telemetry_id: z.string().uuid(),
  truth_state: TruthStateSchema.optional(),
  truthState: TruthStateSchema.optional(),
  source_id: z.string().optional(),
  sourceId: z.string().optional(),
  evidence_id: z.string().uuid().nullable().optional(),
  evidenceId: z.string().uuid().nullable().optional(),
  analyzer_version: z.string().optional(),
  analyzerVersion: z.string().optional(),
  observed_at: z.string().datetime().optional(),
  observedAt: z.string().datetime().optional(),
  confidence: z.number().min(0).max(1).default(1.0),
  limitations: z.string().nullable().optional(),
  metric_name: z.string().nullable().optional(),
  payload: z.record(z.string(), z.unknown()).default({}),
  created_at: z.string().datetime().optional(),
}).refine((data) => (data.truthState !== undefined && data.truthState !== null) || (data.truth_state !== undefined && data.truth_state !== null), {
  message: 'truthState is mandatory and must be explicitly specified (no default value permitted)',
  path: ['truthState'],
});
export type TelemetryRecord = z.infer<typeof TelemetryRecordSchema>;

export type CreateTelemetryRecordInput = Omit<TelemetryRecord, 'created_at'> & ({ truthState: TruthState } | { truth_state: TruthState });

export const CitationSchema = z.object({
  citation_id: z.string().uuid(),
  answer_id: z.string().uuid(),
  answer_claim_id: z.string().uuid().nullable().optional(),
  target_entity_ref_id: z.string().uuid(),
  citation_type: z.string(),
  locator_payload: z.record(z.string(), z.unknown()).default({}),
  sequence: z.number().int(),
});
export type Citation = z.infer<typeof CitationSchema>;

export const GroundingResultSchema = z.object({
  grounding_result_id: z.string().uuid(),
  answer_id: z.string().uuid(),
  grounding_ruleset_version: z.string(),
  supported_claims: z.number().int().default(0),
  unsupported_claims: z.number().int().default(0),
  contradiction_count: z.number().int().default(0),
  verdict: z.enum(['PASSED', 'FAILED', 'WARNING', 'UNKNOWN']),
  created_at: z.string().datetime().optional(),
});
export type GroundingResult = z.infer<typeof GroundingResultSchema>;

// --- P05 Lifecycle & Validation Types ---

export const VersionDiffSchema = z.object({
  version_diff_id: z.string().uuid(),
  left_entity_ref_id: z.string().uuid(),
  right_entity_ref_id: z.string().uuid(),
  diff_type: z.string(),
  engine_version: z.string(),
  created_at: z.string().datetime().optional(),
});
export type VersionDiff = z.infer<typeof VersionDiffSchema>;

export const DiffItemSchema = z.object({
  diff_item_id: z.string().uuid(),
  version_diff_id: z.string().uuid(),
  change_type: z.enum(['ADDED', 'MODIFIED', 'REMOVED', 'UNCHANGED']),
  subject_entity_ref_id: z.string().uuid().nullable().optional(),
  before_payload: z.record(z.string(), z.unknown()).nullable().optional(),
  after_payload: z.record(z.string(), z.unknown()).nullable().optional(),
  significance: z.enum(['BREAKING', 'MAJOR', 'MINOR', 'INFORMATIONAL']).default('MINOR'),
  created_at: z.string().datetime().optional(),
});
export type DiffItem = z.infer<typeof DiffItemSchema>;

export const ModificationWorkspaceSchema = z.object({
  modification_workspace_id: z.string().uuid(),
  base_agent_version_id: z.string().uuid(),
  created_by: z.string(),
  status: z.enum(['OPEN', 'APPLIED', 'COMMITTED', 'DISCARDED']).default('OPEN'),
  created_at: z.string().datetime().optional(),
});
export type ModificationWorkspace = z.infer<typeof ModificationWorkspaceSchema>;

export const ModificationChangeSchema = z.object({
  modification_change_id: z.string().uuid(),
  modification_workspace_id: z.string().uuid(),
  artifact_file_id: z.string().uuid().nullable().optional(),
  source_span_id: z.string().uuid().nullable().optional(),
  change_type: z.enum(['CREATE', 'UPDATE', 'DELETE', 'PATCH']),
  patch_locator: z.string(),
  author_type: z.enum(['HUMAN', 'AGENT', 'AUTOMATED_REMEDIATION']).default('HUMAN'),
  created_at: z.string().datetime().optional(),
});
export type ModificationChange = z.infer<typeof ModificationChangeSchema>;

export const ApprovalSchema = z.object({
  approval_id: z.string().uuid(),
  approval_type: z.string(),
  target_entity_ref_id: z.string().uuid(),
  approver_id: z.string(),
  decision: z.enum(['APPROVED', 'REJECTED', 'PENDING', 'REVOKED']),
  rationale: z.string().nullable().optional(),
  decided_at: z.string().datetime().optional(),
});
export type Approval = z.infer<typeof ApprovalSchema>;

export const ImpactAssessmentSchema = z.object({
  impact_assessment_id: z.string().uuid(),
  modification_workspace_id: z.string().uuid(),
  engine_version: z.string(),
  scope_state: z.string().default('CALCULATED'),
  created_at: z.string().datetime().optional(),
});
export type ImpactAssessment = z.infer<typeof ImpactAssessmentSchema>;

export const ImpactItemSchema = z.object({
  impact_item_id: z.string().uuid(),
  impact_assessment_id: z.string().uuid(),
  target_entity_ref_id: z.string().uuid(),
  impact_type: z.string(),
  severity: z.enum(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'NONE']),
  required_action: z.string(),
});
export type ImpactItem = z.infer<typeof ImpactItemSchema>;

export const ValidationRunSchema = z.object({
  validation_run_id: z.string().uuid(),
  validation_type: z.enum(['SOURCE_MODIFICATION', 'ANALYTICAL_REEVALUATION', 'POLICY_REEVALUATION', 'SCENARIO_REEVALUATION']),
  baseline_agent_version_id: z.string().uuid(),
  modified_agent_version_id: z.string().uuid(),
  baseline_analysis_run_id: z.string().uuid(),
  modified_analysis_run_id: z.string().uuid(),
  validation_analysis_run_id: z.string().uuid(),
  scenario_pack_id: z.string().uuid().nullable().optional(),
  validation_plan_version: z.string(),
  policy_ruleset_version: z.string().nullable().optional(),
  scope_id: z.string().uuid(),
  status: z.enum(['PENDING', 'RUNNING', 'PASSED', 'FAILED', 'ERROR']).default('PENDING'),
  started_at: z.string().datetime().optional(),
  completed_at: z.string().datetime().nullable().optional(),
  created_at: z.string().datetime().optional(),
});
export type ValidationRun = z.infer<typeof ValidationRunSchema>;

export const ValidationResultSchema = z.object({
  validation_result_id: z.string().uuid(),
  validation_run_id: z.string().uuid(),
  result_type: z.string(),
  target_entity_ref_id: z.string().uuid().nullable().optional(),
  status: z.enum(['PASSED', 'FAILED', 'INCONCLUSIVE', 'SKIPPED']),
  before_value: z.record(z.string(), z.unknown()).nullable().optional(),
  after_value: z.record(z.string(), z.unknown()).nullable().optional(),
  evidence_id: z.string().uuid().nullable().optional(),
  created_at: z.string().datetime().optional(),
});
export type ValidationResult = z.infer<typeof ValidationResultSchema>;

export const PackageSchema = z.object({
  package_id: z.string().uuid(),
  agent_version_id: z.string().uuid(),
  analysis_run_id: z.string().uuid(),
  manifest_hash: z.string(),
  storage_locator: z.string(),
  status: z.enum(['GENERATED', 'VALIDATED', 'SIGNED', 'SHIPPED', 'DEPRECATED']).default('GENERATED'),
  created_at: z.string().datetime().optional(),
});
export type Package = z.infer<typeof PackageSchema>;

export const PackageContentSchema = z.object({
  package_content_id: z.string().uuid(),
  package_id: z.string().uuid(),
  entity_ref_id: z.string().uuid().nullable().optional(),
  content_type: z.string(),
  storage_locator: z.string().nullable().optional(),
  content_hash: z.string(),
  sequence: z.number().int().default(1),
});
export type PackageContent = z.infer<typeof PackageContentSchema>;

export const AttestationSchema = z.object({
  attestation_id: z.string().uuid(),
  package_id: z.string().uuid(),
  attestation_type: z.string(),
  schema_version: z.string(),
  payload_hash: z.string(),
  storage_locator: z.string(),
  created_at: z.string().datetime().optional(),
});
export type Attestation = z.infer<typeof AttestationSchema>;

export const SignatureSchema = z.object({
  signature_id: z.string().uuid(),
  target_entity_ref_id: z.string().uuid(),
  signature_scheme: z.string(),
  key_version: z.string(),
  signature_locator: z.string(),
  signed_at: z.string().datetime().optional(),
});
export type Signature = z.infer<typeof SignatureSchema>;

export const ShipmentSchema = z.object({
  shipment_id: z.string().uuid(),
  package_id: z.string().uuid(),
  target_type: z.string(),
  target_locator: z.string(),
  status: z.enum(['PENDING', 'IN_TRANSIT', 'DELIVERED', 'FAILED']).default('PENDING'),
  shipped_at: z.string().datetime().nullable().optional(),
  receipt_locator: z.string().nullable().optional(),
  created_at: z.string().datetime().optional(),
});
export type Shipment = z.infer<typeof ShipmentSchema>;

// --- P05 Ops, Workflows, Audit & Evaluations Types ---

export const WorkflowDefinitionSchema = z.object({
  workflow_definition_id: z.string().uuid(),
  workflow_key: z.string(),
  version: z.string(),
  status: z.enum(['ACTIVE', 'DEPRECATED', 'DRAFT']).default('ACTIVE'),
  definition_payload: z.record(z.string(), z.unknown()).default({}),
  created_at: z.string().datetime().optional(),
});
export type WorkflowDefinition = z.infer<typeof WorkflowDefinitionSchema>;

export const WorkflowRunSchema = z.object({
  workflow_run_id: z.string().uuid(),
  workflow_definition_id: z.string().uuid(),
  agent_id: z.string().uuid().nullable().optional(),
  agent_version_id: z.string().uuid().nullable().optional(),
  analysis_run_id: z.string().uuid().nullable().optional(),
  status: z.enum(['PENDING', 'RUNNING', 'COMPLETED', 'FAILED', 'CANCELLED']).default('PENDING'),
  correlation_id: z.string(),
  started_at: z.string().datetime().optional(),
  completed_at: z.string().datetime().nullable().optional(),
  created_at: z.string().datetime().optional(),
});
export type WorkflowRun = z.infer<typeof WorkflowRunSchema>;

export const JobSchema = z.object({
  job_id: z.string().uuid(),
  workflow_run_id: z.string().uuid().nullable().optional(),
  stage_run_id: z.string().uuid().nullable().optional(),
  queue_key: z.string(),
  idempotency_key: z.string(),
  priority: z.number().int().default(10),
  status: z.enum(['QUEUED', 'LEASED', 'RUNNING', 'COMPLETED', 'FAILED', 'DEAD_LETTER']).default('QUEUED'),
  next_attempt_at: z.string().datetime().optional(),
  payload: z.record(z.string(), z.unknown()).default({}),
  created_at: z.string().datetime().optional(),
});
export type Job = z.infer<typeof JobSchema>;

export const JobAttemptSchema = z.object({
  job_attempt_id: z.string().uuid(),
  job_id: z.string().uuid(),
  attempt_no: z.number().int(),
  worker_id: z.string().nullable().optional(),
  leased_at: z.string().datetime().nullable().optional(),
  lease_expires_at: z.string().datetime().nullable().optional(),
  completed_at: z.string().datetime().nullable().optional(),
  failure_class: z.string().nullable().optional(),
  failure_code: z.string().nullable().optional(),
  error_message: z.string().nullable().optional(),
  created_at: z.string().datetime().optional(),
});
export type JobAttempt = z.infer<typeof JobAttemptSchema>;

export const DeadLetterJobSchema = z.object({
  dead_letter_job_id: z.string().uuid(),
  job_id: z.string().uuid(),
  final_failure_code: z.string(),
  payload_snapshot_locator: z.string().nullable().optional(),
  dead_lettered_at: z.string().datetime().optional(),
  resolution_state: z.enum(['UNRESOLVED', 'REPLAYED', 'DISCARDED', 'RESOLVED_MANUALLY']).default('UNRESOLVED'),
});
export type DeadLetterJob = z.infer<typeof DeadLetterJobSchema>;

export const LifecycleStateTransitionSchema = z.object({
  state_transition_id: z.string().uuid(),
  entity_ref_id: z.string().uuid(),
  from_state: z.string().nullable().optional(),
  to_state: z.string(),
  transition_reason: z.string(),
  actor_ref: z.string().nullable().optional(),
  occurred_at: z.string().datetime().optional(),
});
export type LifecycleStateTransition = z.infer<typeof LifecycleStateTransitionSchema>;

export const OutboxEventSchema = z.object({
  event_id: z.string().uuid(),
  event_type: z.string(),
  aggregate_entity_ref_id: z.string().uuid().nullable().optional(),
  payload: z.record(z.string(), z.unknown()).default({}),
  schema_version: z.string().default('1.0.0'),
  correlation_id: z.string(),
  causation_id: z.string().nullable().optional(),
  status: z.enum(['PENDING', 'DELIVERED', 'FAILED', 'DEAD_LETTER']).default('PENDING'),
  occurred_at: z.string().datetime().optional(),
  published_at: z.string().datetime().nullable().optional(),
});
export type OutboxEvent = z.infer<typeof OutboxEventSchema>;

export const OutboxDeliverySchema = z.object({
  delivery_id: z.string().uuid(),
  event_id: z.string().uuid(),
  target_subscriber: z.string(),
  status: z.enum(['PENDING', 'DELIVERED', 'FAILED']).default('PENDING'),
  attempt_count: z.number().int().default(0),
  delivered_at: z.string().datetime().nullable().optional(),
  last_error: z.string().nullable().optional(),
});
export type OutboxDelivery = z.infer<typeof OutboxDeliverySchema>;

export const AuditEventSchema = z.object({
  audit_event_id: z.string().uuid(),
  principal_or_service_id: z.string(),
  action: z.string(),
  target_entity_ref_id: z.string().uuid().nullable().optional(),
  outcome: z.enum(['SUCCESS', 'DENIED', 'ERROR']),
  occurred_at: z.string().datetime().optional(),
  correlation_id: z.string(),
  metadata: z.record(z.string(), z.unknown()).default({}),
});
export type AuditEvent = z.infer<typeof AuditEventSchema>;

export const EvaluationDatasetSchema = z.object({
  evaluation_dataset_id: z.string().uuid(),
  name: z.string(),
  version: z.string(),
  scope: z.string().default('SYSTEM'),
  status: z.enum(['ACTIVE', 'DEPRECATED', 'DRAFT']).default('ACTIVE'),
  created_at: z.string().datetime().optional(),
});
export type EvaluationDataset = z.infer<typeof EvaluationDatasetSchema>;

export const EvaluationCaseSchema = z.object({
  evaluation_case_id: z.string().uuid(),
  evaluation_dataset_id: z.string().uuid(),
  input_entity_ref_id: z.string().uuid().nullable().optional(),
  expected_payload: z.record(z.string(), z.unknown()).default({}),
  tags: z.array(z.string()).default([]),
  created_at: z.string().datetime().optional(),
});
export type EvaluationCase = z.infer<typeof EvaluationCaseSchema>;

export const EvaluationRunSchema = z.object({
  evaluation_run_id: z.string().uuid(),
  evaluation_dataset_id: z.string().uuid(),
  engine_key: z.string(),
  engine_version: z.string(),
  ruleset_version: z.string().nullable().optional(),
  started_at: z.string().datetime().optional(),
  completed_at: z.string().datetime().nullable().optional(),
  status: z.enum(['PENDING', 'RUNNING', 'COMPLETED', 'FAILED']).default('PENDING'),
  created_at: z.string().datetime().optional(),
});
export type EvaluationRun = z.infer<typeof EvaluationRunSchema>;

export const EvaluationResultSchema = z.object({
  evaluation_result_id: z.string().uuid(),
  evaluation_run_id: z.string().uuid(),
  evaluation_case_id: z.string().uuid().nullable().optional(),
  metric_key: z.string(),
  metric_value: z.number(),
  pass: z.boolean(),
  details: z.record(z.string(), z.unknown()).nullable().optional(),
  created_at: z.string().datetime().optional(),
});
export type EvaluationResult = z.infer<typeof EvaluationResultSchema>;

export const GoldenCorpusItemSchema = z.object({
  golden_corpus_item_id: z.string().uuid(),
  entity_ref_id: z.string().uuid().nullable().optional(),
  fixture_locator: z.string(),
  corpus_version: z.string(),
  truth_status: z.string().default('VERIFIED'),
  tags: z.array(z.string()).default([]),
  created_at: z.string().datetime().optional(),
});
export type GoldenCorpusItem = z.infer<typeof GoldenCorpusItemSchema>;

export const CostUsageEventSchema = z.object({
  cost_usage_event_id: z.string().uuid(),
  usage_type: z.string(),
  quantity: z.number(),
  unit: z.string(),
  provider: z.string(),
  unit_cost_snapshot: z.number().nullable().optional(),
  agent_id: z.string().uuid().nullable().optional(),
  analysis_run_id: z.string().uuid().nullable().optional(),
  job_id: z.string().uuid().nullable().optional(),
  query_id: z.string().uuid().nullable().optional(),
  occurred_at: z.string().datetime().optional(),
});
export type CostUsageEvent = z.infer<typeof CostUsageEventSchema>;

export interface DatabaseQueryResult<R = Record<string, unknown>> {
  rows: R[];
  rowCount?: number | null;
  command?: string;
  oid?: number;
  fields?: unknown[];
}

export interface DatabasePrincipalContext {
  principal_id?: string;
  principalId?: string;
  is_authenticated?: boolean;
  tenant_id?: string | null;
  tenantId?: string | null;
  roles?: string[];
  is_service?: boolean;
  accessible_scope_ids?: string[];
  service_name?: string;
  max_classification_rank?: number;
  maximumClassification?: number;
  grants?: string[];
  capabilities?: string[];
}

export interface SecurityContextOptions {
  readOnly?: boolean;
  isolationLevel?: 'READ COMMITTED' | 'REPEATABLE READ' | 'SERIALIZABLE';
  systemBypass?: boolean;
}

export interface TenantContextTx {
  query<R extends Record<string, unknown> = Record<string, unknown>>(
    text: string,
    params?: unknown[]
  ): Promise<DatabaseQueryResult<R>>;
  principal: DatabasePrincipalContext;
  tenantId: string | null;
  isSystem: boolean;
  client?: unknown;
  repositories: any;
}

export interface SystemContextTx {
  query<R extends Record<string, unknown> = Record<string, unknown>>(
    text: string,
    params?: unknown[]
  ): Promise<DatabaseQueryResult<R>>;
  actor: string;
  reason: string;
  principal?: DatabasePrincipalContext;
  isSystem: true;
  client?: unknown;
  repositories: any;
}

export interface SystemTxContextInput {
  actor: string;
  reason: string;
  principal?: DatabasePrincipalContext;
}

export interface DatabaseClient {
  query<R extends Record<string, unknown> = Record<string, unknown>>(
    text: string,
    params?: unknown[]
  ): Promise<DatabaseQueryResult<R>>;
  withTenantTx<T>(
    principal: DatabasePrincipalContext,
    fn: (tx: TenantContextTx) => Promise<T>,
    options?: SecurityContextOptions
  ): Promise<T>;
  withSystemTx<T>(
    context: SystemTxContextInput,
    fn: (tx: SystemContextTx) => Promise<T>,
    options?: SecurityContextOptions
  ): Promise<T>;
  release?: () => void;
  close?: () => Promise<void>;
  healthCheck?: () => Promise<{ ok: boolean; latencyMs: number; error?: string }>;
}

