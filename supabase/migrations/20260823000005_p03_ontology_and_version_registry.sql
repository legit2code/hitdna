-- Migration: 20260823000005_p03_ontology_and_version_registry.sql
-- Purpose: Create CAIM Ontology model, Concept mappings, Version Registry, and Compatibility Rules
-- Document Reference: Architecture V2.0.1 Document 17 & Document 18

-- 1. Version Registry Table
CREATE TABLE IF NOT EXISTS ops.version_registry (
  version_registry_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  artifact_type text NOT NULL,
  artifact_key text NOT NULL,
  version text NOT NULL,
  status text NOT NULL DEFAULT 'ACTIVE' CHECK (status IN ('DRAFT', 'ACTIVE', 'DEPRECATED', 'REVOKED')),
  content_hash text NOT NULL,
  activated_at timestamptz NULL,
  deprecated_at timestamptz NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT uq_version_registry_entry UNIQUE (artifact_type, artifact_key, version)
);

-- Activation Rule: At most one ACTIVE version per (artifact_type, artifact_key)
CREATE UNIQUE INDEX IF NOT EXISTS uq_version_registry_single_active ON ops.version_registry (artifact_type, artifact_key) WHERE status = 'ACTIVE';
CREATE INDEX IF NOT EXISTS idx_version_registry_lookup ON ops.version_registry(artifact_type, artifact_key, status);

-- 2. Compatibility Rules Table
CREATE TABLE IF NOT EXISTS ops.compatibility_rules (
  compatibility_rule_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  left_registry_id uuid NOT NULL REFERENCES ops.version_registry(version_registry_id) ON DELETE CASCADE,
  right_registry_id uuid NOT NULL REFERENCES ops.version_registry(version_registry_id) ON DELETE CASCADE,
  compatibility_state text NOT NULL CHECK (compatibility_state IN ('COMPATIBLE', 'INCOMPATIBLE', 'DEPRECATED_COMPATIBLE')),
  rationale text NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_compatibility_rules_left ON ops.compatibility_rules(left_registry_id);
CREATE INDEX IF NOT EXISTS idx_compatibility_rules_right ON ops.compatibility_rules(right_registry_id);

-- 3. Ontology Versions Table
CREATE TABLE IF NOT EXISTS ontology.ontology_versions (
  ontology_version_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  version_label text UNIQUE NOT NULL,
  status text NOT NULL DEFAULT 'ACTIVE' CHECK (status IN ('DRAFT', 'ACTIVE', 'DEPRECATED', 'SUPERSEDED')),
  released_at timestamptz NULL,
  supersedes_version_id uuid NULL REFERENCES ontology.ontology_versions(ontology_version_id),
  created_at timestamptz NOT NULL DEFAULT now()
);

-- 4. Ontology Concepts Table
CREATE TABLE IF NOT EXISTS ontology.ontology_concepts (
  concept_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  ontology_version_id uuid NOT NULL REFERENCES ontology.ontology_versions(ontology_version_id) ON DELETE CASCADE,
  namespace text NOT NULL,
  canonical_name text NOT NULL,
  concept_type text NOT NULL,
  parent_concept_id uuid NULL REFERENCES ontology.ontology_concepts(concept_id),
  status text NOT NULL DEFAULT 'ACTIVE' CHECK (status IN ('ACTIVE', 'DEPRECATED')),
  created_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT uq_ontology_concept UNIQUE (ontology_version_id, namespace, canonical_name)
);

CREATE INDEX IF NOT EXISTS idx_ontology_concepts_type ON ontology.ontology_concepts(concept_type);
CREATE INDEX IF NOT EXISTS idx_ontology_concepts_parent ON ontology.ontology_concepts(parent_concept_id);

-- 5. Ontology Concept Aliases Table
CREATE TABLE IF NOT EXISTS ontology.ontology_concept_aliases (
  concept_alias_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  concept_id uuid NOT NULL REFERENCES ontology.ontology_concepts(concept_id) ON DELETE CASCADE,
  alias text NOT NULL,
  language text NULL,
  ecosystem text NULL,
  confidence numeric(5,4) NOT NULL DEFAULT 1.0000 CHECK (confidence >= 0 AND confidence <= 1),
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_ontology_aliases_concept ON ontology.ontology_concept_aliases(concept_id);
CREATE INDEX IF NOT EXISTS idx_ontology_aliases_value ON ontology.ontology_concept_aliases(alias);

-- 6. Ontology Relationship Types Table
CREATE TABLE IF NOT EXISTS ontology.ontology_relationship_types (
  relationship_type_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  ontology_version_id uuid NOT NULL REFERENCES ontology.ontology_versions(ontology_version_id) ON DELETE CASCADE,
  canonical_name text NOT NULL,
  domain_types text[] NULL,
  range_types text[] NULL,
  transitive boolean NOT NULL DEFAULT false,
  is_symmetric boolean NOT NULL DEFAULT false,
  inverse_id uuid NULL REFERENCES ontology.ontology_relationship_types(relationship_type_id),
  created_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT uq_ontology_rel_type UNIQUE (ontology_version_id, canonical_name)
);

-- 7. Ontology Relationships Table
CREATE TABLE IF NOT EXISTS ontology.ontology_relationships (
  ontology_relationship_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  ontology_version_id uuid NOT NULL REFERENCES ontology.ontology_versions(ontology_version_id) ON DELETE CASCADE,
  subject_concept_id uuid NOT NULL REFERENCES ontology.ontology_concepts(concept_id) ON DELETE CASCADE,
  relationship_type_id uuid NOT NULL REFERENCES ontology.ontology_relationship_types(relationship_type_id) ON DELETE CASCADE,
  object_concept_id uuid NOT NULL REFERENCES ontology.ontology_concepts(concept_id) ON DELETE CASCADE,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_ontology_rel_subject ON ontology.ontology_relationships(subject_concept_id);
CREATE INDEX IF NOT EXISTS idx_ontology_rel_object ON ontology.ontology_relationships(object_concept_id);

-- 8. Ontology Mapping Rules Table
CREATE TABLE IF NOT EXISTS ontology.ontology_mapping_rules (
  mapping_rule_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  ontology_version_id uuid NOT NULL REFERENCES ontology.ontology_versions(ontology_version_id) ON DELETE CASCADE,
  source_namespace text NOT NULL,
  matcher text NOT NULL,
  target_concept_id uuid NOT NULL REFERENCES ontology.ontology_concepts(concept_id) ON DELETE CASCADE,
  confidence_policy jsonb NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_ontology_mapping_source ON ontology.ontology_mapping_rules(source_namespace);

-- 9. Ontology Inference Rules Table
CREATE TABLE IF NOT EXISTS ontology.ontology_inference_rules (
  inference_rule_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  ontology_version_id uuid NOT NULL REFERENCES ontology.ontology_versions(ontology_version_id) ON DELETE CASCADE,
  rule_type text NOT NULL,
  antecedent jsonb NOT NULL,
  consequent jsonb NOT NULL,
  evidence_requirement text NOT NULL,
  security_relevance text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);

-- 10. Ontology Deprecations Table
CREATE TABLE IF NOT EXISTS ontology.ontology_deprecations (
  ontology_deprecation_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  ontology_version_id uuid NOT NULL REFERENCES ontology.ontology_versions(ontology_version_id) ON DELETE CASCADE,
  deprecated_entity_type text NOT NULL,
  deprecated_id uuid NOT NULL,
  replacement_id uuid NULL,
  migration_rule text NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);

-- 11. Ontology Change Log Table
CREATE TABLE IF NOT EXISTS ontology.ontology_change_log (
  ontology_change_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  ontology_version_id uuid NOT NULL REFERENCES ontology.ontology_versions(ontology_version_id) ON DELETE CASCADE,
  change_type text NOT NULL,
  target_id uuid NULL,
  rationale text NOT NULL,
  approved_by text NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);
