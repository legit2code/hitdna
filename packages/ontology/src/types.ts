/**
 * Agent Ontology & Controlled Vocabulary — V2.0.1
 * Formal concepts, namespaces, relationships, mapping rules, and inference provenance.
 */

export const ONTOLOGY_SPEC_VERSION = '2.0.1' as const;

export type OntologyNamespace =
  | 'agent'
  | 'capability'
  | 'permission'
  | 'behavior'
  | 'protocol'
  | 'vulnerability'
  | 'risk'
  | 'epistemic'
  | 'evidence'
  | 'decision'
  | 'compliance';

export type OntologyConceptStatus = 'ACTIVE' | 'DEPRECATED' | 'SUPERSEDED';

export type OntologyPredicate =
  | 'IS_A'
  | 'REQUIRES'
  | 'EXPOSES'
  | 'IMPLEMENTS'
  | 'CALLS'
  | 'INFLUENCES'
  | 'CONTRADICTS'
  | 'MITIGATES'
  | 'DERIVED_FROM'
  | 'BOUND_TO';

export type MappingType = 'EXACT' | 'REGEX' | 'SEMANTIC_SIMILARITY' | 'STRUCTURAL_PROJECTION';

/**
 * 1. Ontology Concept Definition
 */
export interface OntologyConcept {
  concept_id: string;
  ontology_version: string;
  namespace: OntologyNamespace;
  canonical_key: string;
  display_name: string;
  description: string;
  parent_concept_id?: string;
  aliases: string[];
  status: OntologyConceptStatus;
}

/**
 * 2. Ontology Relationship (Concept-to-Concept or Semantic Triple)
 */
export interface OntologyRelationship {
  relationship_id: string;
  ontology_version: string;
  subject_concept_id: string;
  predicate: OntologyPredicate;
  object_concept_id: string;
  confidence: number;
}

/**
 * 3. Mapping Rule (Source observation to Ontology Concept)
 */
export interface OntologyMappingRule {
  rule_id: string;
  rule_name: string;
  source_ecosystem: string;
  source_pattern: string;
  target_concept_id: string;
  mapping_type: MappingType;
  confidence: number;
  mapping_version: string;
}

/**
 * 4. Inference Rule (Concept graph reasoning to derived concept)
 */
export interface OntologyInferenceRule {
  inference_rule_id: string;
  rule_name: string;
  antecedent_concept_ids: string[];
  consequent_concept_id: string;
  predicate: OntologyPredicate;
  calibration_version: string;
  minimum_confidence: number;
}

/**
 * 5. Inference Provenance (Deterministic record of conceptual inference)
 */
export interface InferenceProvenance {
  provenance_id: string;
  inference_rule_id: string;
  engine_key: string;
  engine_version: string;
  input_entity_ref_ids: string[];
  derived_concept_id: string;
  confidence: number;
  inferred_at: string;
}

/**
 * 6. Version Reference & Deprecation
 */
export interface OntologyVersionRef {
  ontology_version_id: string;
  version_label: string;
  status: 'DRAFT' | 'ACTIVE' | 'DEPRECATED' | 'SUPERSEDED';
  released_at?: string;
  supersedes_version_id?: string;
}

export interface OntologyDeprecation {
  deprecation_id: string;
  deprecated_concept_id: string;
  superseded_by_concept_id?: string;
  reason: string;
  effective_version: string;
}
