import { OntologyVersionRef, OntologyDeprecation, ONTOLOGY_SPEC_VERSION } from './types.ts';
import { OntologyVersionRefSchema, OntologyDeprecationSchema } from './schemas.ts';

export const CURRENT_ONTOLOGY_VERSION_REF: OntologyVersionRef = {
  ontology_version_id: '00000000-0000-0000-0000-000000000001',
  version_label: ONTOLOGY_SPEC_VERSION,
  status: 'ACTIVE',
  released_at: '2026-08-22T00:00:00Z',
};

export function validateOntologyVersionRef(ref: unknown): OntologyVersionRef {
  return OntologyVersionRefSchema.parse(ref) as OntologyVersionRef;
}

export function validateOntologyDeprecation(dep: unknown): OntologyDeprecation {
  return OntologyDeprecationSchema.parse(dep) as OntologyDeprecation;
}
