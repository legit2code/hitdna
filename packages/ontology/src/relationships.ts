import { OntologyRelationship, OntologyPredicate, ONTOLOGY_SPEC_VERSION } from './types.ts';
import { OntologyRelationshipSchema } from './schemas.ts';

export function createOntologyRelationship(params: {
  relationship_id?: string;
  subject_concept_id: string;
  predicate: OntologyPredicate;
  object_concept_id: string;
  confidence?: number;
  ontology_version?: string;
}): OntologyRelationship {
  const rel: OntologyRelationship = {
    relationship_id: params.relationship_id || crypto.randomUUID(),
    ontology_version: params.ontology_version || ONTOLOGY_SPEC_VERSION,
    subject_concept_id: params.subject_concept_id,
    predicate: params.predicate,
    object_concept_id: params.object_concept_id,
    confidence: params.confidence ?? 1.0,
  };
  return OntologyRelationshipSchema.parse(rel) as OntologyRelationship;
}

export const CORE_RELATIONSHIP_PREDICATES: OntologyPredicate[] = [
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
];
