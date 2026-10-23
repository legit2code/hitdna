-- Migration: 20260823000003_p03_core_identity_and_registries.sql
-- Purpose: Create CanonicalAgent, AgentVersion, Publishers, Ecosystem Organizations, and Entity Reference spine
-- Document Reference: Architecture V2.0.1 Document 17 & Document 18

-- 1. Canonical Agents Table
CREATE TABLE IF NOT EXISTS core.canonical_agents (
  agent_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  canonical_name text NOT NULL,
  agent_type_concept_id uuid NULL,
  status text NOT NULL DEFAULT 'ACTIVE' CHECK (status IN ('ACTIVE', 'DEPRECATED', 'SUSPENDED', 'MERGED')),
  identity_confidence numeric(5,4) NOT NULL DEFAULT 1.0000 CHECK (identity_confidence >= 0 AND identity_confidence <= 1),
  first_seen_at timestamptz NOT NULL DEFAULT now(),
  last_seen_at timestamptz NOT NULL DEFAULT now(),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_canonical_agents_active_name ON core.canonical_agents (lower(canonical_name)) WHERE status = 'ACTIVE';
CREATE INDEX IF NOT EXISTS idx_canonical_agents_status ON core.canonical_agents(status);

-- 2. Agent Versions Table (Enforces: AgentVersion belongs to exactly ONE CanonicalAgent)
CREATE TABLE IF NOT EXISTS core.agent_versions (
  agent_version_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  agent_id uuid NOT NULL REFERENCES core.canonical_agents(agent_id) ON DELETE CASCADE,
  version_label text NULL,
  source_commit text NULL,
  content_fingerprint text NOT NULL,
  release_date timestamptz NULL,
  supersedes_version_id uuid NULL REFERENCES core.agent_versions(agent_version_id),
  observed_at timestamptz NOT NULL DEFAULT now(),
  created_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT uq_agent_versions_fingerprint UNIQUE (agent_id, content_fingerprint)
);

CREATE INDEX IF NOT EXISTS idx_agent_versions_agent_observed ON core.agent_versions(agent_id, observed_at DESC);
CREATE INDEX IF NOT EXISTS idx_agent_versions_supersedes ON core.agent_versions(supersedes_version_id);

-- 3. Publishers Table (Public ecosystem publishers)
CREATE TABLE IF NOT EXISTS core.publishers (
  publisher_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  publisher_type_concept_id uuid NULL,
  canonical_name text NOT NULL,
  verified_state text NOT NULL DEFAULT 'UNVERIFIED' CHECK (verified_state IN ('UNVERIFIED', 'VERIFIED', 'FLAGGED', 'REVOKED')),
  first_seen_at timestamptz NOT NULL DEFAULT now(),
  last_seen_at timestamptz NOT NULL DEFAULT now(),
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_publishers_name ON core.publishers(canonical_name);

-- 4. Organizations Table (Ecosystem organizations/maintainers; NOT SaaS tenant table)
CREATE TABLE IF NOT EXISTS core.organizations (
  organization_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_type_concept_id uuid NULL,
  canonical_name text NOT NULL,
  homepage text NULL,
  verified_state text NOT NULL DEFAULT 'UNVERIFIED' CHECK (verified_state IN ('UNVERIFIED', 'VERIFIED', 'FLAGGED', 'REVOKED')),
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_organizations_name ON core.organizations(canonical_name);

-- 5. Entity References Table (Universal Addressing Layer)
CREATE TABLE IF NOT EXISTS core.entity_refs (
  entity_ref_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  entity_kind text NOT NULL,
  native_id uuid NOT NULL,
  agent_id uuid NULL REFERENCES core.canonical_agents(agent_id) ON DELETE CASCADE,
  agent_version_id uuid NULL REFERENCES core.agent_versions(agent_version_id) ON DELETE CASCADE,
  analysis_run_id uuid NULL,
  security_classification_id uuid NOT NULL REFERENCES security.security_classifications(security_classification_id),
  created_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT uq_entity_refs_kind_native UNIQUE (entity_kind, native_id)
);

CREATE INDEX IF NOT EXISTS idx_entity_refs_native ON core.entity_refs(native_id);
CREATE INDEX IF NOT EXISTS idx_entity_refs_agent ON core.entity_refs(agent_id);
CREATE INDEX IF NOT EXISTS idx_entity_refs_agent_version ON core.entity_refs(agent_version_id);
CREATE INDEX IF NOT EXISTS idx_entity_refs_analysis_run ON core.entity_refs(analysis_run_id);

-- 6. Organization Relationships Table
CREATE TABLE IF NOT EXISTS core.organization_relationships (
  organization_relationship_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  subject_entity_ref_id uuid NOT NULL REFERENCES core.entity_refs(entity_ref_id) ON DELETE CASCADE,
  relationship_concept_id uuid NOT NULL,
  object_entity_ref_id uuid NOT NULL REFERENCES core.entity_refs(entity_ref_id) ON DELETE CASCADE,
  valid_from timestamptz NULL,
  valid_to timestamptz NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_org_rel_subject ON core.organization_relationships(subject_entity_ref_id);
CREATE INDEX IF NOT EXISTS idx_org_rel_object ON core.organization_relationships(object_entity_ref_id);
