-- Migration: 20260823000017_p36_composer_capability_and_audit.sql
-- Purpose: Create dedicated per-principal capability grants and audit log for Composer engine
-- Document Reference: Architecture V2.0.1 Document 13 (Authentication & Access Control) & Document 36 (Composer Capability)

-- 1. Dedicated, per-principal restricted capability grants table
CREATE TABLE IF NOT EXISTS security.restricted_capability_grants (
  grant_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  capability_key text NOT NULL,
  principal_id uuid NOT NULL REFERENCES security.principals(principal_id) ON DELETE CASCADE,
  granted_by uuid NOT NULL REFERENCES security.principals(principal_id),
  justification text NOT NULL,
  scope_limitations jsonb NULL,
  granted_at timestamptz NOT NULL DEFAULT now(),
  revoked_at timestamptz NULL
);

CREATE INDEX IF NOT EXISTS idx_capability_grants_principal ON security.restricted_capability_grants(principal_id);
CREATE INDEX IF NOT EXISTS idx_capability_grants_key ON security.restricted_capability_grants(capability_key);

-- Seed authoritative grant: composer:full_access for platform owner admin@caim.internal if principal exists
INSERT INTO security.restricted_capability_grants (
  grant_id,
  capability_key,
  principal_id,
  granted_by,
  justification,
  scope_limitations,
  granted_at,
  revoked_at
)
SELECT
  '00000000-0000-0000-0002-000000000001',
  'composer:full_access',
  p.principal_id,
  p.principal_id,
  'Platform owner — unrestricted composer access',
  NULL,
  now(),
  NULL
FROM security.principals p
WHERE p.principal_id = '00000000-0000-0000-0001-000000000001'
ON CONFLICT (grant_id) DO NOTHING;

-- 2. Audit Trail table for all Composer generation attempts
CREATE TABLE IF NOT EXISTS security.composer_generation_log (
  log_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  principal_id uuid NOT NULL REFERENCES security.principals(principal_id) ON DELETE CASCADE,
  technique_category text NOT NULL,
  request_text text NOT NULL,
  source_agents_retrieved text[] NOT NULL DEFAULT '{}',
  generated_artifact_id text NULL,
  static_analysis_result_summary jsonb NULL,
  status text NOT NULL,
  refusal_reason text NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_composer_gen_log_principal ON security.composer_generation_log(principal_id);
CREATE INDEX IF NOT EXISTS idx_composer_gen_log_created_at ON security.composer_generation_log(created_at);
CREATE INDEX IF NOT EXISTS idx_composer_gen_log_category ON security.composer_generation_log(technique_category);
