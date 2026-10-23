import { z } from 'zod';

const uuidRegex = /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/;
const uuidSchema = z.string().regex(uuidRegex, 'Invalid UUID');

export const OntologyNamespaceSchema = z.enum([
  'agent',
  'capability',
  'permission',
  'behavior',
  'protocol',
  'vulnerability',
  'risk',
  'epistemic',
  'evidence',
  'decision',
  'compliance',
]);

export const OntologyPredicateSchema = z.enum([
  'IS_A',
  'REQUIRES',
  'EXPOSES',
  'IMPLEMENTS',
  'CALLS',
  'INFLUENCES',
  'CONTRADICTS',
  'MITIGATES',
  'DERIVED_FROM',
  'BOUND_TO',
]);

export const OntologyConceptSchema = z.object({
  concept_id: z.string().min(1),
  ontology_version: z.string().min(1),
  namespace: OntologyNamespaceSchema,
  canonical_key: z.string().min(1),
  display_name: z.string().min(1),
  description: z.string(),
  parent_concept_id: z.string().optional(),
  aliases: z.array(z.string()).default([]),
  status: z.enum(['ACTIVE', 'DEPRECATED', 'SUPERSEDED']).default('ACTIVE'),
});

export const OntologyRelationshipSchema = z.object({
  relationship_id: uuidSchema,
  ontology_version: z.string().min(1),
  subject_concept_id: z.string().min(1),
  predicate: OntologyPredicateSchema,
  object_concept_id: z.string().min(1),
  confidence: z.number().min(0).max(1).default(1.0),
});

export const OntologyMappingRuleSchema = z.object({
  rule_id: z.string().min(1),
  rule_name: z.string().min(1),
  source_ecosystem: z.string().min(1),
  source_pattern: z.string().min(1),
  target_concept_id: z.string().min(1),
  mapping_type: z.enum(['EXACT', 'REGEX', 'SEMANTIC_SIMILARITY', 'STRUCTURAL_PROJECTION']),
  confidence: z.number().min(0).max(1).default(1.0),
  mapping_version: z.string().min(1),
});

export const OntologyInferenceRuleSchema = z.object({
  inference_rule_id: z.string().min(1),
  rule_name: z.string().min(1),
  antecedent_concept_ids: z.array(z.string().min(1)).min(1),
  consequent_concept_id: z.string().min(1),
  predicate: OntologyPredicateSchema,
  calibration_version: z.string().min(1),
  minimum_confidence: z.number().min(0).max(1).default(0.8),
});

export const InferenceProvenanceSchema = z.object({
  provenance_id: uuidSchema,
  inference_rule_id: z.string().min(1),
  engine_key: z.string().min(1),
  engine_version: z.string().min(1),
  input_entity_ref_ids: z.array(uuidSchema).min(1),
  derived_concept_id: z.string().min(1),
  confidence: z.number().min(0).max(1),
  inferred_at: z.string().datetime(),
});

export const OntologyVersionRefSchema = z.object({
  ontology_version_id: uuidSchema,
  version_label: z.string().min(1),
  status: z.enum(['DRAFT', 'ACTIVE', 'DEPRECATED', 'SUPERSEDED']).default('ACTIVE'),
  released_at: z.string().datetime().optional(),
  supersedes_version_id: uuidSchema.optional(),
});

export const OntologyDeprecationSchema = z.object({
  deprecation_id: uuidSchema,
  deprecated_concept_id: z.string().min(1),
  superseded_by_concept_id: z.string().optional(),
  reason: z.string().min(1),
  effective_version: z.string().min(1),
});
