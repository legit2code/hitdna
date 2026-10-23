-- Migration: 20260823000022_p38_tenant_classification_and_complete_rls.sql
-- Purpose: Authoritative Tenant Table Classification registry & RLS enforcement across all TENANT_OWNED and TENANT_SHARED tables
-- References: Architecture V2 Document 13, Document 18, Document 21

-- 1. Create Tenant Table Classification Registry
CREATE TABLE IF NOT EXISTS security.table_tenant_classifications (
  table_schema text NOT NULL,
  table_name text NOT NULL,
  classification text NOT NULL CHECK (classification IN ('TENANT_OWNED', 'TENANT_SHARED', 'GLOBAL')),
  description text,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (table_schema, table_name)
);

CREATE OR REPLACE VIEW security.tenant_classifications AS 
SELECT table_schema, table_name, classification, description, created_at
FROM security.table_tenant_classifications;

-- 2. Populate All 18 Multi-Tenant (TENANT_OWNED / TENANT_SHARED) Tables
INSERT INTO security.table_tenant_classifications (table_schema, table_name, classification, description)
VALUES
  ('security', 'tenants', 'TENANT_OWNED', 'Tenant directory registry'),
  ('security', 'tenant_memberships', 'TENANT_OWNED', 'Tenant user memberships'),
  ('security', 'access_scopes', 'TENANT_SHARED', 'Platform and tenant organization access scopes'),
  ('security', 'access_grants', 'TENANT_SHARED', 'Granular capability access grants'),
  ('security', 'principals', 'TENANT_OWNED', 'Security principals and user identities'),
  ('source', 'source_observations', 'TENANT_SHARED', 'Root scope bearing observation records'),
  ('analysis', 'analysis_runs', 'TENANT_SHARED', 'Root scope bearing analysis runs'),
  ('analysis', 'analysis_stage_runs', 'TENANT_SHARED', 'Derived analysis pipeline stage executions'),
  ('analysis', 'static_findings', 'TENANT_SHARED', 'Derived static analysis AST/linter findings'),
  ('intel', 'evidence', 'TENANT_SHARED', 'Discrete evidence items with scope'),
  ('intel', 'assertions', 'TENANT_SHARED', 'Normalized assertions with scope'),
  ('intel', 'claims', 'TENANT_SHARED', 'Verified intelligence claims with scope'),
  ('intel', 'risks', 'TENANT_SHARED', 'Derived STRIDE/ATLAS risks'),
  ('intel', 'policy_decisions', 'TENANT_SHARED', 'Derived governance policy admission decisions'),
  ('intel', 'recommendations', 'TENANT_SHARED', 'Derived remediation recommendations'),
  ('lifecycle', 'validation_runs', 'TENANT_SHARED', 'Root scope bearing validation runs'),
  ('lifecycle', 'validation_results', 'TENANT_SHARED', 'Derived validation test results'),
  ('lifecycle', 'modification_workspaces', 'TENANT_OWNED', 'Private tenant agent modification workspaces')
ON CONFLICT (table_schema, table_name) DO UPDATE SET
  classification = EXCLUDED.classification,
  description = EXCLUDED.description;

-- 3. Populate Reference & Baseline Tables as GLOBAL
INSERT INTO security.table_tenant_classifications (table_schema, table_name, classification, description)
VALUES
  ('core', 'canonical_agents', 'GLOBAL', 'Canonical agent definitions'),
  ('core', 'agent_versions', 'GLOBAL', 'Published agent version corpus'),
  ('core', 'organizations', 'GLOBAL', 'Public agent maintainers and organizations'),
  ('ontology', 'ontology_versions', 'GLOBAL', 'CAIM ontology version baselines'),
  ('ontology', 'ontology_concepts', 'GLOBAL', 'Canonical CAIM ontology concepts'),
  ('ops', 'version_registry', 'GLOBAL', 'Platform version registry artifacts'),
  ('ops', 'golden_corpus_items', 'GLOBAL', 'Certified ground-truth evaluation items'),
  ('security', 'security_classifications', 'GLOBAL', 'Classification ranks and labels'),
  ('security', 'roles', 'GLOBAL', 'Standard platform security roles'),
  ('intel', 'score_models', 'GLOBAL', 'Scoring algorithm formulas'),
  ('intel', 'policy_versions', 'GLOBAL', 'Platform governance admission policies')
ON CONFLICT (table_schema, table_name) DO UPDATE SET
  classification = EXCLUDED.classification,
  description = EXCLUDED.description;

-- 4. Ensure Application Roles Exist
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'authenticated') THEN
    CREATE ROLE authenticated NOLOGIN NOINHERIT;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'anon') THEN
    CREATE ROLE anon NOLOGIN NOINHERIT;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'service_role') THEN
    CREATE ROLE service_role NOLOGIN NOINHERIT;
  END IF;
END$$;

GRANT USAGE ON SCHEMA security, source, core, ontology, analysis, intel, knowledge, lifecycle, ops, api TO authenticated, anon, service_role;
GRANT ALL ON ALL TABLES IN SCHEMA security, source, core, ontology, analysis, intel, knowledge, lifecycle, ops, api TO authenticated, service_role;
GRANT SELECT ON ALL TABLES IN SCHEMA security, source, core, ontology, analysis, intel, knowledge, lifecycle, ops, api TO anon;

-- 5. Enable and Force Row-Level Security on All 18 Multi-Tenant Tables
ALTER TABLE security.tenants ENABLE ROW LEVEL SECURITY;
ALTER TABLE security.tenants FORCE ROW LEVEL SECURITY;

ALTER TABLE security.tenant_memberships ENABLE ROW LEVEL SECURITY;
ALTER TABLE security.tenant_memberships FORCE ROW LEVEL SECURITY;

ALTER TABLE security.access_scopes ENABLE ROW LEVEL SECURITY;
ALTER TABLE security.access_scopes FORCE ROW LEVEL SECURITY;

ALTER TABLE security.access_grants ENABLE ROW LEVEL SECURITY;
ALTER TABLE security.access_grants FORCE ROW LEVEL SECURITY;

ALTER TABLE security.principals ENABLE ROW LEVEL SECURITY;
ALTER TABLE security.principals FORCE ROW LEVEL SECURITY;

ALTER TABLE source.source_observations ENABLE ROW LEVEL SECURITY;
ALTER TABLE source.source_observations FORCE ROW LEVEL SECURITY;

ALTER TABLE analysis.analysis_runs ENABLE ROW LEVEL SECURITY;
ALTER TABLE analysis.analysis_runs FORCE ROW LEVEL SECURITY;

ALTER TABLE analysis.analysis_stage_runs ENABLE ROW LEVEL SECURITY;
ALTER TABLE analysis.analysis_stage_runs FORCE ROW LEVEL SECURITY;

ALTER TABLE analysis.static_findings ENABLE ROW LEVEL SECURITY;
ALTER TABLE analysis.static_findings FORCE ROW LEVEL SECURITY;

ALTER TABLE intel.evidence ENABLE ROW LEVEL SECURITY;
ALTER TABLE intel.evidence FORCE ROW LEVEL SECURITY;

ALTER TABLE intel.assertions ENABLE ROW LEVEL SECURITY;
ALTER TABLE intel.assertions FORCE ROW LEVEL SECURITY;

ALTER TABLE intel.claims ENABLE ROW LEVEL SECURITY;
ALTER TABLE intel.claims FORCE ROW LEVEL SECURITY;

ALTER TABLE intel.risks ENABLE ROW LEVEL SECURITY;
ALTER TABLE intel.risks FORCE ROW LEVEL SECURITY;

ALTER TABLE intel.policy_decisions ENABLE ROW LEVEL SECURITY;
ALTER TABLE intel.policy_decisions FORCE ROW LEVEL SECURITY;

ALTER TABLE intel.recommendations ENABLE ROW LEVEL SECURITY;
ALTER TABLE intel.recommendations FORCE ROW LEVEL SECURITY;

ALTER TABLE lifecycle.validation_runs ENABLE ROW LEVEL SECURITY;
ALTER TABLE lifecycle.validation_runs FORCE ROW LEVEL SECURITY;

ALTER TABLE lifecycle.validation_results ENABLE ROW LEVEL SECURITY;
ALTER TABLE lifecycle.validation_results FORCE ROW LEVEL SECURITY;

ALTER TABLE lifecycle.modification_workspaces ENABLE ROW LEVEL SECURITY;
ALTER TABLE lifecycle.modification_workspaces FORCE ROW LEVEL SECURITY;

-- 6. Define Explicit RLS Policies for Previously Missing Tables

-- 6.1 security.tenants
DROP POLICY IF EXISTS tenants_tenant_isolation_policy ON security.tenants;
CREATE POLICY tenants_tenant_isolation_policy ON security.tenants
  FOR ALL
  USING (
    security.current_tenant_id() IS NULL 
    OR tenant_id = security.current_tenant_id()
  )
  WITH CHECK (
    security.current_tenant_id() IS NULL 
    OR tenant_id = security.current_tenant_id()
  );

-- 6.2 security.tenant_memberships
DROP POLICY IF EXISTS tenant_memberships_isolation_policy ON security.tenant_memberships;
CREATE POLICY tenant_memberships_isolation_policy ON security.tenant_memberships
  FOR ALL
  USING (
    security.current_tenant_id() IS NULL 
    OR tenant_id = security.current_tenant_id()
  )
  WITH CHECK (
    security.current_tenant_id() IS NULL 
    OR tenant_id = security.current_tenant_id()
  );

-- 6.3 security.access_scopes
DROP POLICY IF EXISTS access_scopes_isolation_policy ON security.access_scopes;
CREATE POLICY access_scopes_isolation_policy ON security.access_scopes
  FOR ALL
  USING (
    scope_type = 'PLATFORM' 
    OR security.current_tenant_id() IS NULL 
    OR tenant_id = security.current_tenant_id()
  )
  WITH CHECK (
    scope_type = 'PLATFORM' 
    OR security.current_tenant_id() IS NULL 
    OR tenant_id = security.current_tenant_id()
  );

-- 6.4 security.access_grants
DROP POLICY IF EXISTS access_grants_isolation_policy ON security.access_grants;
CREATE POLICY access_grants_isolation_policy ON security.access_grants
  FOR ALL
  USING (
    target_scope IS NULL 
    OR security.is_scope_accessible(target_scope)
  )
  WITH CHECK (
    target_scope IS NULL 
    OR security.is_scope_accessible(target_scope)
  );

-- 6.5 security.principals
DROP POLICY IF EXISTS principals_isolation_policy ON security.principals;
CREATE POLICY principals_isolation_policy ON security.principals
  FOR ALL
  USING (
    tenant_id IS NULL 
    OR security.current_tenant_id() IS NULL 
    OR tenant_id = security.current_tenant_id()
  )
  WITH CHECK (
    tenant_id IS NULL 
    OR security.current_tenant_id() IS NULL 
    OR tenant_id = security.current_tenant_id()
  );

-- 6.6 source.source_observations
DROP POLICY IF EXISTS source_observations_scope_policy ON source.source_observations;
CREATE POLICY source_observations_scope_policy ON source.source_observations
  FOR ALL
  USING (security.is_scope_accessible(scope_id))
  WITH CHECK (security.is_scope_accessible(scope_id));

-- 6.7 analysis.analysis_stage_runs
DROP POLICY IF EXISTS analysis_stage_runs_scope_policy ON analysis.analysis_stage_runs;
CREATE POLICY analysis_stage_runs_scope_policy ON analysis.analysis_stage_runs
  FOR ALL
  USING (
    EXISTS (
      SELECT 1 FROM analysis.analysis_runs r
      WHERE r.analysis_run_id = analysis_stage_runs.analysis_run_id
        AND security.is_scope_accessible(r.scope_id)
    )
  )
  WITH CHECK (
    EXISTS (
      SELECT 1 FROM analysis.analysis_runs r
      WHERE r.analysis_run_id = analysis_stage_runs.analysis_run_id
        AND security.is_scope_accessible(r.scope_id)
    )
  );

-- 6.8 analysis.static_findings
DROP POLICY IF EXISTS static_findings_scope_policy ON analysis.static_findings;
CREATE POLICY static_findings_scope_policy ON analysis.static_findings
  FOR ALL
  USING (
    EXISTS (
      SELECT 1 FROM analysis.analysis_runs r
      WHERE r.analysis_run_id = static_findings.analysis_run_id
        AND security.is_scope_accessible(r.scope_id)
    )
  )
  WITH CHECK (
    EXISTS (
      SELECT 1 FROM analysis.analysis_runs r
      WHERE r.analysis_run_id = static_findings.analysis_run_id
        AND security.is_scope_accessible(r.scope_id)
    )
  );

-- 6.9 intel.risks
DROP POLICY IF EXISTS risks_scope_policy ON intel.risks;
CREATE POLICY risks_scope_policy ON intel.risks
  FOR ALL
  USING (
    analysis_run_id IS NULL OR
    EXISTS (
      SELECT 1 FROM analysis.analysis_runs r
      WHERE r.analysis_run_id = risks.analysis_run_id
        AND security.is_scope_accessible(r.scope_id)
    )
  )
  WITH CHECK (
    analysis_run_id IS NULL OR
    EXISTS (
      SELECT 1 FROM analysis.analysis_runs r
      WHERE r.analysis_run_id = risks.analysis_run_id
        AND security.is_scope_accessible(r.scope_id)
    )
  );

-- 6.10 intel.policy_decisions
DROP POLICY IF EXISTS policy_decisions_scope_policy ON intel.policy_decisions;
CREATE POLICY policy_decisions_scope_policy ON intel.policy_decisions
  FOR ALL
  USING (
    analysis_run_id IS NULL OR
    EXISTS (
      SELECT 1 FROM analysis.analysis_runs r
      WHERE r.analysis_run_id = policy_decisions.analysis_run_id
        AND security.is_scope_accessible(r.scope_id)
    )
  )
  WITH CHECK (
    analysis_run_id IS NULL OR
    EXISTS (
      SELECT 1 FROM analysis.analysis_runs r
      WHERE r.analysis_run_id = policy_decisions.analysis_run_id
        AND security.is_scope_accessible(r.scope_id)
    )
  );

-- 6.11 intel.recommendations
DROP POLICY IF EXISTS recommendations_scope_policy ON intel.recommendations;
CREATE POLICY recommendations_scope_policy ON intel.recommendations
  FOR ALL
  USING (
    analysis_run_id IS NULL OR
    EXISTS (
      SELECT 1 FROM analysis.analysis_runs r
      WHERE r.analysis_run_id = recommendations.analysis_run_id
        AND security.is_scope_accessible(r.scope_id)
    )
  )
  WITH CHECK (
    analysis_run_id IS NULL OR
    EXISTS (
      SELECT 1 FROM analysis.analysis_runs r
      WHERE r.analysis_run_id = recommendations.analysis_run_id
        AND security.is_scope_accessible(r.scope_id)
    )
  );

-- 6.12 lifecycle.validation_results
DROP POLICY IF EXISTS validation_results_scope_policy ON lifecycle.validation_results;
CREATE POLICY validation_results_scope_policy ON lifecycle.validation_results
  FOR ALL
  USING (
    EXISTS (
      SELECT 1 FROM lifecycle.validation_runs v
      WHERE v.validation_run_id = validation_results.validation_run_id
        AND security.is_scope_accessible(v.scope_id)
    )
  )
  WITH CHECK (
    EXISTS (
      SELECT 1 FROM lifecycle.validation_runs v
      WHERE v.validation_run_id = validation_results.validation_run_id
        AND security.is_scope_accessible(v.scope_id)
    )
  );

-- 6.13 lifecycle.modification_workspaces
DROP POLICY IF EXISTS modification_workspaces_isolation_policy ON lifecycle.modification_workspaces;
CREATE POLICY modification_workspaces_isolation_policy ON lifecycle.modification_workspaces
  FOR ALL
  USING (
    security.current_tenant_id() IS NULL
    OR EXISTS (
      SELECT 1 FROM security.principals p
      WHERE p.principal_id::text = modification_workspaces.created_by
        AND (p.tenant_id IS NULL OR p.tenant_id = security.current_tenant_id())
    )
  )
  WITH CHECK (
    security.current_tenant_id() IS NULL
    OR EXISTS (
      SELECT 1 FROM security.principals p
      WHERE p.principal_id::text = modification_workspaces.created_by
        AND (p.tenant_id IS NULL OR p.tenant_id = security.current_tenant_id())
    )
  );
