/**
 * CANE (Canonical Agent Normalized Entities) — Type Definitions
 * P14 — CAIM & Ontology Canonicalization
 */

import { 
  CaimManifest, 
  CaimAgent, 
  CaimAgentVersion, 
  CaimComponent, 
  CaimDependencyRelationship, 
  CaimTool, 
  CaimToolBinding, 
  CaimProtocolInstance, 
  CaimProtocolCapability, 
  CaimCapabilityInstance, 
  CaimPermission, 
  CaimEntrypoint, 
  CaimRuntimeEnvironment, 
  CaimEndpoint, 
  CaimModelReference, 
  CaimDatasetReference, 
  CaimPromptAsset, 
  CaimConfiguration, 
  CaimCredentialReference, 
  CaimDataAccessRequirement,
  DeclarationState,
  SecurityClassification,
} from '../../../caim/src/index.ts';

import { 
  OntologyConcept, 
  OntologyRelationship, 
  OntologyMappingRule, 
  OntologyInferenceRule, 
  InferenceProvenance 
} from '../types.ts';

import { 
  SourceSpan, 
  SymbolFact, 
  ImportFact, 
  ExportFact, 
  CallSiteFact, 
  EnvVarRef, 
  ProtocolFact, 
  FrameworkFingerprint, 
  ArtifactParseResult, 
  ParsedSourceFacts,
  ToolDeclaration,
  ModelReference,
  PermissionRef
} from '../../../syntax/src/index.ts';

import { ProvenanceRecord, SourceSpanLocator } from '../../../contracts/src/index.ts';

export const CANE_SPEC_VERSION = '1.0.0' as const;
export const CANE_MAPPING_REGISTRY_VERSION = '1.0.0' as const;

/**
 * Normalized Source Fact representation ready for canonical transformation
 */
export interface NormalizedSourceFactItem<T = unknown> {
  fact_id: string;
  source_ecosystem: 'javascript' | 'typescript' | 'python' | 'go' | 'rust' | 'json' | 'yaml' | 'toml' | 'dockerfile' | 'generic';
  file_path: string;
  fact_category: 'symbol' | 'import' | 'export' | 'call_site' | 'env_var' | 'dependency' | 'protocol' | 'framework' | 'config' | 'permission' | 'tool';
  raw_value: T;
  span?: SourceSpan;
  metadata?: Record<string, unknown>;
}

export interface NormalizedSourceFacts {
  artifact_id: string;
  agent_id: string;
  agent_version_id: string;
  file_paths: string[];
  facts: NormalizedSourceFactItem[];
  symbols: SymbolFact[];
  imports: ImportFact[];
  exports: ExportFact[];
  call_sites: CallSiteFact[];
  env_vars: EnvVarRef[];
  tools: ToolDeclaration[];
  models: ModelReference[];
  permissions: PermissionRef[];
  dependencies: Array<{ name: string; version: string; kind: string; file_path: string; span?: SourceSpan }>;
  protocols: ProtocolFact[];
  frameworks: FrameworkFingerprint[];
  unrecognized_extensions: Record<string, unknown>;
  provenance: ProvenanceRecord;
}

/**
 * Mapping Rule definition linking source AST/Pattern constructs to CAIM & Ontology
 */
export interface CaneMappingRule {
  rule_id: string;
  rule_name: string;
  source_ecosystems: Array<'javascript' | 'typescript' | 'python' | 'go' | 'rust' | 'generic'>;
  match_type: 'EXACT_CALLEE' | 'REGEX_CALLEE' | 'DECORATOR' | 'IMPORT_SPECIFIER' | 'PROTOCOL_REG' | 'CONFIG_KEY' | 'STRUCTURAL';
  source_pattern: string;
  target_canonical_key: string;
  target_concept_id: string;
  target_entity_type: 'CAPABILITY' | 'TOOL' | 'PROTOCOL' | 'PERMISSION' | 'RUNTIME' | 'MODEL' | 'ENDPOINT';
  base_confidence: number;
  description: string;
  version: string;
  security_sensitive: boolean;
}

/**
 * Evaluated mapping execution result with source lineage
 */
export interface CaneMappingMatch {
  rule_id: string;
  rule_version: string;
  source_fact_id: string;
  source_ecosystem: string;
  file_path: string;
  matched_construct: string;
  target_canonical_key: string;
  target_concept_id: string;
  target_entity_type: string;
  confidence: number;
  span?: SourceSpan;
  provenance: ProvenanceRecord;
}

/**
 * Result of Taxonomic or Structural Inference
 */
export interface CaneInferredConcept {
  inference_id: string;
  inference_rule_id: string;
  derived_concept_id: string;
  canonical_key: string;
  epistemic_state: 'INFERRED_STATIC' | 'SYNTHESIZED';
  confidence: number;
  antecedent_concept_ids: string[];
  antecedent_entity_ids: string[];
  provenance: InferenceProvenance;
  rationale: string;
}

/**
 * Comprehensive Canonicalization Output
 */
export interface CanonicalizationResult {
  caim_manifest: CaimManifest;
  ontology_concepts: OntologyConcept[];
  ontology_relationships: OntologyRelationship[];
  mapping_matches: CaneMappingMatch[];
  inferences: CaneInferredConcept[];
  provenance_records: ProvenanceRecord[];
  unmapped_extensions: Record<string, unknown>;
  diagnostics: {
    total_source_facts: number;
    total_mappings_applied: number;
    total_capabilities: number;
    total_tools: number;
    total_dependencies: number;
    total_protocols: number;
    total_inferences: number;
    average_mapping_confidence: number;
    security_guard_status: 'ENFORCED' | 'PASSED' | 'VIOLATION_BLOCKED';
    processing_time_ms: number;
  };
}
