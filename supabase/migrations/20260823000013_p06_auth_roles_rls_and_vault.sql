-- Migration: 20260823000013_p06_auth_roles_rls_and_vault.sql
-- Purpose: Complete Authentication, Roles, Access Scopes, RLS & Vault Boundaries
-- Document Reference: Architecture V2.0.1 Document 13 (Security Classification & RLS) & Document 21 (Tenant Scope)

-- 1. Ensure Standard Business Roles in security.roles
INSERT INTO security.roles (role_id, role_key, description, status)
VALUES
  ('00000000-0000-0000-0000-000000000020', 'admin', 'Full administrative authority across platform and tenant scopes', 'ACTIVE'),
  ('00000000-0000-0000-0000-000000000021', 'reviewer', 'Review, verification, validation comparison and package approval authority', 'ACTIVE'),
  ('00000000-0000-0000-0000-000000000022', 'analyst', 'Analytical query execution, static findings review and evidence exploration', 'ACTIVE'),
  ('00000000-0000-0000-0000-000000000023', 'vault_reader', 'Access to vault-restricted taint paths, traces and confidential disclosures', 'ACTIVE'),
  ('00000000-0000-0000-0000-000000000024', 'system_service', 'Automated backend pipeline and worker daemon execution identity', 'ACTIVE'),
  ('00000000-0000-0000-0000-000000000025', 'user', 'Standard user with read access to public metadata and authorized tenant entities', 'ACTIVE'),
  ('00000000-0000-0000-0000-000000000026', 'release_approver', 'Authority to approve validation runs, sign packages and authorize shipments', 'ACTIVE'),
  ('00000000-0000-0000-0000-000000000027', 'auditor', 'Read-only access to immutable audit events, compliance logs and governance state', 'ACTIVE'),
  ('00000000-0000-0000-0000-000000000028', 'operator', 'Pipeline execution, worker queues, dead letter inspection and operational management', 'ACTIVE'),
  ('00000000-0000-0000-0000-000000000029', 'anonymous', 'Unauthenticated public access restricted strictly to public metadata', 'ACTIVE')
ON CONFLICT (role_key) DO UPDATE SET
  description = EXCLUDED.description,
  status = EXCLUDED.status;

-- 2. Security Classification Resolution Functions
CREATE OR REPLACE FUNCTION security.get_classification_rank(p_classification_id uuid)
RETURNS integer AS $$
DECLARE
  v_rank integer;
BEGIN
  SELECT rank INTO v_rank
  FROM security.security_classifications
  WHERE security_classification_id = p_classification_id;
  RETURN COALESCE(v_rank, 3);
END;
$$ LANGUAGE plpgsql STABLE;

CREATE OR REPLACE FUNCTION security.get_max_classification(p_id_a uuid, p_id_b uuid)
RETURNS uuid AS $$
DECLARE
  v_rank_a integer;
  v_rank_b integer;
BEGIN
  IF p_id_a IS NULL THEN RETURN p_id_b; END IF;
  IF p_id_b IS NULL THEN RETURN p_id_a; END IF;
  
  v_rank_a := security.get_classification_rank(p_id_a);
  v_rank_b := security.get_classification_rank(p_id_b);
  
  IF v_rank_a >= v_rank_b THEN
    RETURN p_id_a;
  ELSE
    RETURN p_id_b;
  END IF;
END;
$$ LANGUAGE plpgsql STABLE;

-- 3. Tenant and Scope Resolution Functions
CREATE OR REPLACE FUNCTION security.current_tenant_id()
RETURNS uuid AS $$
DECLARE
  v_tenant text;
BEGIN
  v_tenant := COALESCE(
    current_setting('request.jwt.claim.tenant_id', true),
    (current_setting('request.jwt.claims', true)::jsonb ->> 'tenant_id'),
    current_setting('app.current_tenant_id', true)
  );
  IF v_tenant IS NULL OR v_tenant = '' THEN
    RETURN NULL;
  END IF;
  RETURN v_tenant::uuid;
EXCEPTION WHEN OTHERS THEN
  RETURN NULL;
END;
$$ LANGUAGE plpgsql STABLE;

CREATE OR REPLACE FUNCTION security.current_principal_id()
RETURNS text AS $$
BEGIN
  RETURN COALESCE(
    current_setting('request.jwt.claim.sub', true),
    (current_setting('request.jwt.claims', true)::jsonb ->> 'sub'),
    current_user
  );
EXCEPTION WHEN OTHERS THEN
  RETURN current_user;
END;
$$ LANGUAGE plpgsql STABLE;

CREATE OR REPLACE FUNCTION security.is_scope_accessible(p_scope_id uuid, p_tenant_id uuid DEFAULT NULL)
RETURNS boolean AS $$
DECLARE
  v_scope_type text;
  v_scope_tenant_id uuid;
  v_effective_tenant uuid;
BEGIN
  IF p_scope_id IS NULL THEN RETURN true; END IF;
  
  SELECT scope_type, tenant_id INTO v_scope_type, v_scope_tenant_id
  FROM security.access_scopes
  WHERE scope_id = p_scope_id;
  
  -- PLATFORM scope is accessible across tenants (subject to classification and role)
  IF v_scope_type = 'PLATFORM' THEN
    RETURN true;
  END IF;
  
  v_effective_tenant := COALESCE(p_tenant_id, security.current_tenant_id());
  
  IF v_effective_tenant IS NOT NULL AND v_scope_tenant_id = v_effective_tenant THEN
    RETURN true;
  END IF;
  
  RETURN false;
END;
$$ LANGUAGE plpgsql STABLE;

-- 4. Enable Row Level Security (RLS) & Define Tenant Scope Enforcement Policies (Architecture Document 21)

-- 4.1 Analysis Runs RLS
ALTER TABLE analysis.analysis_runs ENABLE ROW LEVEL SECURITY;

CREATE POLICY analysis_runs_select_scope_policy ON analysis.analysis_runs
  FOR SELECT
  USING (security.is_scope_accessible(scope_id));

CREATE POLICY analysis_runs_insert_scope_policy ON analysis.analysis_runs
  FOR INSERT
  WITH CHECK (security.is_scope_accessible(scope_id));

CREATE POLICY analysis_runs_update_scope_policy ON analysis.analysis_runs
  FOR UPDATE
  USING (security.is_scope_accessible(scope_id))
  WITH CHECK (security.is_scope_accessible(scope_id));

CREATE POLICY analysis_runs_delete_scope_policy ON analysis.analysis_runs
  FOR DELETE
  USING (security.is_scope_accessible(scope_id));

-- 4.2 Validation Runs RLS
ALTER TABLE lifecycle.validation_runs ENABLE ROW LEVEL SECURITY;

CREATE POLICY validation_runs_select_scope_policy ON lifecycle.validation_runs
  FOR SELECT
  USING (security.is_scope_accessible(scope_id));

CREATE POLICY validation_runs_insert_scope_policy ON lifecycle.validation_runs
  FOR INSERT
  WITH CHECK (security.is_scope_accessible(scope_id));

CREATE POLICY validation_runs_update_scope_policy ON lifecycle.validation_runs
  FOR UPDATE
  USING (security.is_scope_accessible(scope_id))
  WITH CHECK (security.is_scope_accessible(scope_id));

CREATE POLICY validation_runs_delete_scope_policy ON lifecycle.validation_runs
  FOR DELETE
  USING (security.is_scope_accessible(scope_id));

-- 4.3 Evidence RLS
ALTER TABLE intel.evidence ENABLE ROW LEVEL SECURITY;

CREATE POLICY evidence_select_scope_policy ON intel.evidence
  FOR SELECT
  USING (security.is_scope_accessible(scope_id));

CREATE POLICY evidence_insert_scope_policy ON intel.evidence
  FOR INSERT
  WITH CHECK (security.is_scope_accessible(scope_id));

CREATE POLICY evidence_update_scope_policy ON intel.evidence
  FOR UPDATE
  USING (security.is_scope_accessible(scope_id))
  WITH CHECK (security.is_scope_accessible(scope_id));

CREATE POLICY evidence_delete_scope_policy ON intel.evidence
  FOR DELETE
  USING (security.is_scope_accessible(scope_id));

-- 4.4 Assertions RLS
ALTER TABLE intel.assertions ENABLE ROW LEVEL SECURITY;

CREATE POLICY assertions_select_scope_policy ON intel.assertions
  FOR SELECT
  USING (security.is_scope_accessible(scope_id));

CREATE POLICY assertions_insert_scope_policy ON intel.assertions
  FOR INSERT
  WITH CHECK (security.is_scope_accessible(scope_id));

CREATE POLICY assertions_update_scope_policy ON intel.assertions
  FOR UPDATE
  USING (security.is_scope_accessible(scope_id))
  WITH CHECK (security.is_scope_accessible(scope_id));

CREATE POLICY assertions_delete_scope_policy ON intel.assertions
  FOR DELETE
  USING (security.is_scope_accessible(scope_id));

-- 4.5 Claims RLS
ALTER TABLE intel.claims ENABLE ROW LEVEL SECURITY;

CREATE POLICY claims_select_scope_policy ON intel.claims
  FOR SELECT
  USING (security.is_scope_accessible(scope_id));

CREATE POLICY claims_insert_scope_policy ON intel.claims
  FOR INSERT
  WITH CHECK (security.is_scope_accessible(scope_id));

CREATE POLICY claims_update_scope_policy ON intel.claims
  FOR UPDATE
  USING (security.is_scope_accessible(scope_id))
  WITH CHECK (security.is_scope_accessible(scope_id));

CREATE POLICY claims_delete_scope_policy ON intel.claims
  FOR DELETE
  USING (security.is_scope_accessible(scope_id));

-- 5. Create Curated API Schema Views for Browser & API Clients
-- Public / Tenant Authorized Agent Views
CREATE OR REPLACE VIEW api.v_canonical_agents AS
SELECT 
  a.agent_id,
  a.canonical_name,
  a.agent_type_concept_id,
  a.status,
  a.identity_confidence,
  a.first_seen_at,
  a.last_seen_at,
  a.created_at
FROM core.canonical_agents a
WHERE a.status != 'DEPRECATED';

CREATE OR REPLACE VIEW api.v_agent_versions AS
SELECT 
  v.agent_version_id,
  v.agent_id,
  v.version_label,
  v.source_commit,
  v.content_fingerprint,
  v.release_date,
  v.supersedes_version_id,
  v.observed_at,
  v.created_at
FROM core.agent_versions v;

CREATE OR REPLACE VIEW api.v_analysis_findings AS
SELECT 
  f.finding_id,
  f.analysis_run_id,
  f.stage_run_id,
  f.entity_ref_id,
  f.source_span_id,
  f.rule_id,
  f.finding_type,
  f.severity,
  f.confidence,
  f.message,
  f.location_hint,
  f.raw_payload,
  f.created_at
FROM analysis.static_findings f;

CREATE OR REPLACE VIEW api.v_audit_events AS
SELECT 
  ae.audit_event_id,
  ae.principal_or_service_id,
  ae.action,
  ae.target_entity_ref_id,
  ae.outcome,
  ae.occurred_at,
  ae.correlation_id,
  ae.metadata
FROM ops.audit_events ae;

CREATE OR REPLACE VIEW api.v_grounded_answers AS
SELECT 
  ans.answer_id,
  ans.query_id,
  ans.context_package_id,
  ans.model_version,
  ans.prompt_version,
  ans.answer_text_or_locator,
  ans.status,
  ans.created_at
FROM knowledge.answers ans;

CREATE OR REPLACE VIEW api.v_packages AS
SELECT 
  p.package_id,
  p.agent_version_id,
  p.analysis_run_id,
  p.manifest_hash,
  p.storage_locator,
  p.status,
  p.created_at
FROM lifecycle.packages p;
