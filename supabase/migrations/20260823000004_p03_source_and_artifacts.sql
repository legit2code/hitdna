-- Migration: 20260823000004_p03_source_and_artifacts.sql
-- Purpose: Create Source Adapters, Discovery, Observations, Distributions, Artifacts, Spans, External Aliases, Canonical Relationships, and Lineage Edges
-- Document Reference: Architecture V2.0.1 Document 17 & Document 18

-- 1. Source Adapters Table
CREATE TABLE IF NOT EXISTS source.source_adapters (
  source_adapter_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  adapter_key text UNIQUE NOT NULL,
  adapter_version text NOT NULL,
  source_type text NOT NULL,
  status text NOT NULL DEFAULT 'ACTIVE' CHECK (status IN ('ACTIVE', 'DEPRECATED', 'DISABLED')),
  created_at timestamptz NOT NULL DEFAULT now()
);

-- 2. Discovery Runs Table
CREATE TABLE IF NOT EXISTS source.discovery_runs (
  discovery_run_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  strategy_version text NOT NULL,
  started_at timestamptz NOT NULL DEFAULT now(),
  completed_at timestamptz NULL,
  status text NOT NULL DEFAULT 'RUNNING' CHECK (status IN ('RUNNING', 'COMPLETED', 'FAILED', 'CANCELLED')),
  correlation_id text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);

-- 3. Discovery Queries Table
CREATE TABLE IF NOT EXISTS source.discovery_queries (
  discovery_query_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  discovery_run_id uuid NOT NULL REFERENCES source.discovery_runs(discovery_run_id) ON DELETE CASCADE,
  source_adapter_id uuid NOT NULL REFERENCES source.source_adapters(source_adapter_id),
  query_family text NOT NULL,
  query_text_hash text NOT NULL,
  cursor_state jsonb NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);

-- 4. Discovery Candidates Table
CREATE TABLE IF NOT EXISTS source.discovery_candidates (
  candidate_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  discovery_run_id uuid NOT NULL REFERENCES source.discovery_runs(discovery_run_id) ON DELETE CASCADE,
  discovery_query_id uuid NULL REFERENCES source.discovery_queries(discovery_query_id) ON DELETE SET NULL,
  source_locator text NOT NULL,
  type_hint text NULL,
  confidence numeric(5,4) NOT NULL DEFAULT 1.0000 CHECK (confidence >= 0 AND confidence <= 1),
  status text NOT NULL DEFAULT 'DISCOVERED' CHECK (status IN ('DISCOVERED', 'ACQUIRED', 'REJECTED', 'IGNORED')),
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_discovery_candidates_run ON source.discovery_candidates(discovery_run_id);
CREATE INDEX IF NOT EXISTS idx_discovery_candidates_locator ON source.discovery_candidates(source_locator);

-- 5. Discovery Relationships Table
CREATE TABLE IF NOT EXISTS source.discovery_relationships (
  discovery_relationship_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  from_candidate_id uuid NOT NULL REFERENCES source.discovery_candidates(candidate_id) ON DELETE CASCADE,
  to_candidate_id uuid NULL REFERENCES source.discovery_candidates(candidate_id) ON DELETE SET NULL,
  target_locator text NULL,
  relationship_type text NOT NULL,
  depth integer NOT NULL DEFAULT 0,
  created_at timestamptz NOT NULL DEFAULT now()
);

-- 6. Source Observations Table (Scope-Bearing Root Observation)
CREATE TABLE IF NOT EXISTS source.source_observations (
  source_observation_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  candidate_id uuid NULL REFERENCES source.discovery_candidates(candidate_id) ON DELETE SET NULL,
  source_adapter_id uuid NOT NULL REFERENCES source.source_adapters(source_adapter_id),
  source_locator text NOT NULL,
  observed_at timestamptz NOT NULL DEFAULT now(),
  raw_metadata_locator text NULL,
  content_hash text NULL,
  scope_id uuid NOT NULL REFERENCES security.access_scopes(scope_id),
  security_classification_id uuid NOT NULL REFERENCES security.security_classifications(security_classification_id),
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_source_observations_adapter ON source.source_observations(source_adapter_id);
CREATE INDEX IF NOT EXISTS idx_source_observations_locator ON source.source_observations(source_locator);
CREATE INDEX IF NOT EXISTS idx_source_observations_scope ON source.source_observations(scope_id);

-- 7. Acquisition Runs Table
CREATE TABLE IF NOT EXISTS source.acquisition_runs (
  acquisition_run_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  source_observation_id uuid NOT NULL REFERENCES source.source_observations(source_observation_id) ON DELETE CASCADE,
  candidate_id uuid NULL REFERENCES source.discovery_candidates(candidate_id) ON DELETE SET NULL,
  status text NOT NULL DEFAULT 'COMPLETED' CHECK (status IN ('RUNNING', 'COMPLETED', 'FAILED')),
  bytes bigint NOT NULL DEFAULT 0,
  failure_code text NULL,
  started_at timestamptz NOT NULL DEFAULT now(),
  completed_at timestamptz NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);

-- 8. Distributions Table
CREATE TABLE IF NOT EXISTS core.distributions (
  distribution_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  agent_version_id uuid NOT NULL REFERENCES core.agent_versions(agent_version_id) ON DELETE CASCADE,
  distribution_type_concept_id uuid NULL,
  ecosystem text NULL,
  locator text NOT NULL,
  version text NULL,
  publisher_id uuid NULL REFERENCES core.publishers(publisher_id) ON DELETE SET NULL,
  source_observation_id uuid NOT NULL REFERENCES source.source_observations(source_observation_id),
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_distributions_agent_version ON core.distributions(agent_version_id);
CREATE INDEX IF NOT EXISTS idx_distributions_observation ON core.distributions(source_observation_id);

-- 9. Artifacts Table (Immutable Content with Hash Integrity Constraint)
CREATE TABLE IF NOT EXISTS source.artifacts (
  artifact_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  agent_version_id uuid NULL REFERENCES core.agent_versions(agent_version_id) ON DELETE CASCADE,
  distribution_id uuid NULL REFERENCES core.distributions(distribution_id) ON DELETE SET NULL,
  source_observation_id uuid NOT NULL REFERENCES source.source_observations(source_observation_id),
  artifact_type_concept_id uuid NULL,
  content_hash text NOT NULL,
  storage_locator text NOT NULL,
  size_bytes bigint NULL,
  security_classification_id uuid NOT NULL REFERENCES security.security_classifications(security_classification_id),
  created_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT ck_artifact_hash_format CHECK (length(content_hash) >= 32)
);

CREATE INDEX IF NOT EXISTS idx_artifacts_agent_version ON source.artifacts(agent_version_id);
CREATE INDEX IF NOT EXISTS idx_artifacts_content_hash ON source.artifacts(content_hash);
CREATE INDEX IF NOT EXISTS idx_artifacts_observation ON source.artifacts(source_observation_id);

-- 10. Artifact Files Table
CREATE TABLE IF NOT EXISTS source.artifact_files (
  artifact_file_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  artifact_id uuid NOT NULL REFERENCES source.artifacts(artifact_id) ON DELETE CASCADE,
  path text NOT NULL,
  media_type text NOT NULL,
  size_bytes bigint NOT NULL DEFAULT 0,
  content_hash text NOT NULL,
  language_hint text NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT uq_artifact_files_path UNIQUE (artifact_id, path)
);

CREATE INDEX IF NOT EXISTS idx_artifact_files_artifact ON source.artifact_files(artifact_id);

-- 11. Source Spans Table
CREATE TABLE IF NOT EXISTS source.source_spans (
  source_span_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  artifact_file_id uuid NOT NULL REFERENCES source.artifact_files(artifact_file_id) ON DELETE CASCADE,
  start_line integer NOT NULL,
  start_col integer NOT NULL,
  end_line integer NOT NULL,
  end_col integer NOT NULL,
  byte_offset_start integer NULL,
  byte_offset_end integer NULL,
  symbol_hint text NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT ck_source_span_lines CHECK (start_line <= end_line)
);

CREATE INDEX IF NOT EXISTS idx_source_spans_file ON source.source_spans(artifact_file_id);

-- 12. External Aliases Table (Source-Scoped External Aliases)
CREATE TABLE IF NOT EXISTS core.external_aliases (
  external_alias_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  entity_ref_id uuid NOT NULL REFERENCES core.entity_refs(entity_ref_id) ON DELETE CASCADE,
  source_adapter_id uuid NULL REFERENCES source.source_adapters(source_adapter_id),
  alias_type text NOT NULL,
  alias_value text NOT NULL,
  confidence numeric(5,4) NOT NULL DEFAULT 1.0000 CHECK (confidence >= 0 AND confidence <= 1),
  observed_at timestamptz NOT NULL DEFAULT now(),
  created_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT uq_external_alias_scoped UNIQUE (alias_type, alias_value, source_adapter_id)
);

CREATE INDEX IF NOT EXISTS idx_external_aliases_entity ON core.external_aliases(entity_ref_id);

-- 13. Canonical Relationships Table
CREATE TABLE IF NOT EXISTS core.canonical_relationships (
  canonical_relationship_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  subject_entity_ref_id uuid NOT NULL REFERENCES core.entity_refs(entity_ref_id) ON DELETE CASCADE,
  predicate_concept_id uuid NOT NULL,
  object_entity_ref_id uuid NOT NULL REFERENCES core.entity_refs(entity_ref_id) ON DELETE CASCADE,
  confidence numeric(5,4) NOT NULL DEFAULT 1.0000 CHECK (confidence >= 0 AND confidence <= 1),
  source_observation_id uuid NULL REFERENCES source.source_observations(source_observation_id),
  source_artifact_id uuid NULL REFERENCES source.artifacts(artifact_id),
  valid_from timestamptz NULL,
  valid_to timestamptz NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_canonical_rel_subject ON core.canonical_relationships(subject_entity_ref_id);
CREATE INDEX IF NOT EXISTS idx_canonical_rel_object ON core.canonical_relationships(object_entity_ref_id);

-- 14. Intel Lineage Edges Table (Provenance Spine)
CREATE TABLE IF NOT EXISTS intel.lineage_edges (
  lineage_edge_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  from_entity_ref_id uuid NOT NULL REFERENCES core.entity_refs(entity_ref_id) ON DELETE CASCADE,
  to_entity_ref_id uuid NOT NULL REFERENCES core.entity_refs(entity_ref_id) ON DELETE CASCADE,
  lineage_type text NOT NULL,
  analysis_run_id uuid NULL,
  stage_run_id uuid NULL,
  transformation_version text NULL,
  confidence numeric(5,4) NOT NULL DEFAULT 1.0000 CHECK (confidence >= 0 AND confidence <= 1),
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_lineage_from ON intel.lineage_edges(from_entity_ref_id);
CREATE INDEX IF NOT EXISTS idx_lineage_to ON intel.lineage_edges(to_entity_ref_id);
CREATE INDEX IF NOT EXISTS idx_lineage_run_stage ON intel.lineage_edges(analysis_run_id, stage_run_id);
