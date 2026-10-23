-- Migration: 20260823000024_p40_discovery_graph_foundation.sql
-- Purpose: Provision Discovery Graph Foundation (discovery_roots, discovery_candidates, discovery_edges, extensible lookup types)
-- Document Reference: Architecture V2.0.1 (Discovery Graph Foundation - Step 1 of 5)

-- 1. Discovery Edge Types Extensible Lookup Table
CREATE TABLE IF NOT EXISTS source.discovery_edge_types (
  edge_type text PRIMARY KEY,
  description text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);

INSERT INTO source.discovery_edge_types (edge_type, description) VALUES
  ('ROOT_SOURCE', 'Initial root seed source'),
  ('README_LINK', 'Hyperlink extracted from README documentation'),
  ('RELATED_PROJECT', 'Related or suggested project reference'),
  ('DEPENDENCY', 'Runtime or package dependency'),
  ('DEV_DEPENDENCY', 'Development or build dependency'),
  ('PEER_DEPENDENCY', 'Peer or optional package dependency'),
  ('UPSTREAM_SOURCE', 'Upstream source repository link'),
  ('MAINTAINER_OTHER_REPO', 'Other project by same maintainer or organization'),
  ('FORK', 'Repository fork relationship'),
  ('MCP_REFERENCE', 'Model Context Protocol server or tool reference'),
  ('DEMO_LINK', 'Live demo or application link')
ON CONFLICT (edge_type) DO NOTHING;

-- 2. Discovery Roots Table
CREATE TABLE IF NOT EXISTS source.discovery_roots (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  source_adapter text NOT NULL,
  root_type text NOT NULL,
  root_value text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  created_by text NOT NULL DEFAULT 'system',
  active boolean NOT NULL DEFAULT true,
  metadata_json jsonb NOT NULL DEFAULT '{}'::jsonb
);

CREATE INDEX IF NOT EXISTS idx_discovery_roots_adapter ON source.discovery_roots(source_adapter);
CREATE INDEX IF NOT EXISTS idx_discovery_roots_active ON source.discovery_roots(active);

-- 3. Discovery Candidates Table (Ensure all columns exist from V2.0.1 Part A & Part E)
ALTER TABLE source.discovery_candidates ADD COLUMN IF NOT EXISTS id uuid DEFAULT gen_random_uuid();
ALTER TABLE source.discovery_candidates ADD COLUMN IF NOT EXISTS canonical_url text;
ALTER TABLE source.discovery_candidates ADD COLUMN IF NOT EXISTS normalized_url text;
ALTER TABLE source.discovery_candidates ADD COLUMN IF NOT EXISTS candidate_type text DEFAULT 'PACKAGE';
ALTER TABLE source.discovery_candidates ADD COLUMN IF NOT EXISTS domain text DEFAULT '';
ALTER TABLE source.discovery_candidates ADD COLUMN IF NOT EXISTS content_hash text;
ALTER TABLE source.discovery_candidates ADD COLUMN IF NOT EXISTS first_seen_at timestamptz DEFAULT now();
ALTER TABLE source.discovery_candidates ADD COLUMN IF NOT EXISTS last_seen_at timestamptz DEFAULT now();
ALTER TABLE source.discovery_candidates ADD COLUMN IF NOT EXISTS queued_at timestamptz;
ALTER TABLE source.discovery_candidates ADD COLUMN IF NOT EXISTS processed_at timestamptz;
ALTER TABLE source.discovery_candidates ADD COLUMN IF NOT EXISTS relevance_score numeric(5,4) DEFAULT 0.0000;
ALTER TABLE source.discovery_candidates ADD COLUMN IF NOT EXISTS discovery_confidence numeric(5,4) DEFAULT 0.0000;
ALTER TABLE source.discovery_candidates ADD COLUMN IF NOT EXISTS classification_confidence numeric(5,4);
ALTER TABLE source.discovery_candidates ADD COLUMN IF NOT EXISTS classification text;
ALTER TABLE source.discovery_candidates ADD COLUMN IF NOT EXISTS rejection_reason text;
ALTER TABLE source.discovery_candidates ADD COLUMN IF NOT EXISTS metadata_json jsonb DEFAULT '{}'::jsonb;

-- Populate id from candidate_id if present
UPDATE source.discovery_candidates SET id = candidate_id WHERE id IS NULL;

-- Allow NULL for legacy columns from early migration 4
ALTER TABLE source.discovery_candidates ALTER COLUMN discovery_run_id DROP NOT NULL;
ALTER TABLE source.discovery_candidates ALTER COLUMN source_locator DROP NOT NULL;

-- Update status check constraint to include all required V2.0.1 status values
ALTER TABLE source.discovery_candidates DROP CONSTRAINT IF EXISTS discovery_candidates_constraint_2;
ALTER TABLE source.discovery_candidates DROP CONSTRAINT IF EXISTS discovery_candidates_status_check;
ALTER TABLE source.discovery_candidates ADD CONSTRAINT discovery_candidates_status_check CHECK (
  status IN (
    'DISCOVERED',
    'QUEUED',
    'FETCHING',
    'FETCHED',
    'CLASSIFYING',
    'VERIFIED_AGENT',
    'VERIFIED_NON_AGENT',
    'REJECTED',
    'DUPLICATE',
    'FAILED',
    'ROBOTS_BLOCKED',
    'RATE_LIMITED',
    'ACQUIRED',
    'IGNORED'
  )
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_discovery_candidates_norm_url ON source.discovery_candidates(normalized_url);
CREATE INDEX IF NOT EXISTS idx_discovery_candidates_status ON source.discovery_candidates(status);
CREATE INDEX IF NOT EXISTS idx_discovery_candidates_domain ON source.discovery_candidates(domain);

-- 4. Discovery Edges Table
CREATE TABLE IF NOT EXISTS source.discovery_edges (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  root_seed_id uuid NOT NULL REFERENCES source.discovery_roots(id) ON DELETE CASCADE,
  parent_edge_id uuid NULL REFERENCES source.discovery_edges(id) ON DELETE SET NULL,
  source_candidate_id uuid NULL,
  source_agent_id uuid NULL,
  target_candidate_id uuid NOT NULL,
  discovered_url text NOT NULL,
  normalized_url text NOT NULL,
  edge_type text NOT NULL REFERENCES source.discovery_edge_types(edge_type),
  crawl_depth integer NOT NULL DEFAULT 0,
  extractor text NOT NULL,
  evidence_type text NOT NULL,
  evidence_location text NOT NULL,
  evidence_snippet_hash text NULL,
  source_content_hash text NULL,
  discovered_at timestamptz NOT NULL DEFAULT now(),
  queued_at timestamptz NULL,
  decision text NOT NULL DEFAULT 'PENDING',
  rejection_reason text NULL,
  metadata_json jsonb NOT NULL DEFAULT '{}'::jsonb
);

CREATE INDEX IF NOT EXISTS idx_discovery_edges_root ON source.discovery_edges(root_seed_id);
CREATE INDEX IF NOT EXISTS idx_discovery_edges_target ON source.discovery_edges(target_candidate_id);
CREATE INDEX IF NOT EXISTS idx_discovery_edges_parent ON source.discovery_edges(parent_edge_id);
CREATE INDEX IF NOT EXISTS idx_discovery_edges_source ON source.discovery_edges(source_candidate_id);
CREATE INDEX IF NOT EXISTS idx_discovery_edges_decision ON source.discovery_edges(decision);

-- 5. Public Views for Schema Transparency
CREATE OR REPLACE VIEW public.discovery_roots AS SELECT * FROM source.discovery_roots;
CREATE OR REPLACE VIEW public.discovery_candidates AS SELECT * FROM source.discovery_candidates;
CREATE OR REPLACE VIEW public.discovery_edges AS SELECT * FROM source.discovery_edges;
CREATE OR REPLACE VIEW public.discovery_edge_types AS SELECT * FROM source.discovery_edge_types;
