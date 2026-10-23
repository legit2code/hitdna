-- Migration: 20260823000025_p41_fail_closed_rls_and_security_context.sql
-- Purpose: Convert PostgreSQL RLS policies across all 18 multi-tenant tables from fail-open to FAIL-CLOSED.
-- Invariants:
--   1. Missing, invalid, or empty tenant context DENIES access (zero rows returned).
--   2. RLS policies require: security.current_tenant_id() IS NOT NULL AND tenant_id = security.current_tenant_id()
--   3. No "security.current_tenant_id() IS NULL" permissive fallback.
--   4. Scope validation denies NULL scope_id and requires valid authenticated tenant.
--   5. Explicit, audited system bypass mechanism (security.is_system_bypass()) for verified internal system workers.
-- References: Architecture V2 Document 13, Document 18, Document 21

-- 1. Helper Function: Explicit Privileged System Context Check
CREATE OR REPLACE FUNCTION security.is_system_bypass()
RETURNS boolean AS $$
DECLARE
  v_bypass text;
  v_is_system text;
  v_principal text;
BEGIN
  v_bypass := current_setting('app.system_bypass', true);
  v_is_system := current_setting('app.is_system_context', true);
  v_principal := current_setting('app.current_principal_id', true);

  -- FAIL CLOSED: System bypass requires explicit dual flag AND recognized non-anonymous principal
  IF v_bypass = 'true' AND v_is_system = 'true' AND v_principal IS NOT NULL AND v_principal NOT IN ('', 'anonymous') THEN
    RETURN true;
  END IF;

  RETURN false;
EXCEPTION WHEN OTHERS THEN
  RETURN false;
END;
$$ LANGUAGE plpgsql STABLE;

-- 2. Tenant Context Resolution Function (Strict UUID Parsing, Fail Closed)
CREATE OR REPLACE FUNCTION security.current_tenant_id()
RETURNS uuid AS $$
DECLARE
  v_tenant text;
BEGIN
  -- Strict extraction from session transaction context
  v_tenant := NULLIF(TRIM(current_setting('app.current_tenant_id', true)), '');
  
  IF v_tenant IS NULL THEN
    RETURN NULL;
  END IF;

  RETURN v_tenant::uuid;
EXCEPTION WHEN OTHERS THEN
  RETURN NULL;
END;
$$ LANGUAGE plpgsql STABLE;

-- 3. Scope Accessibility Function (Fail Closed on NULL or Unauthenticated)
CREATE OR REPLACE FUNCTION security.is_scope_accessible(p_scope_id uuid, p_tenant_id uuid DEFAULT NULL)
RETURNS boolean AS $$
DECLARE
  v_scope_type text;
  v_scope_tenant_id uuid;
  v_effective_tenant uuid;
BEGIN
  -- FAIL CLOSED: NULL scope_id must be denied immediately!
  IF p_scope_id IS NULL THEN
    RETURN false;
  END IF;

  -- Privileged system context bypass
  IF security.is_system_bypass() THEN
    RETURN true;
  END IF;

  SELECT scope_type, tenant_id INTO v_scope_type, v_scope_tenant_id
  FROM security.access_scopes
  WHERE scope_id = p_scope_id;

  IF NOT FOUND THEN
    RETURN false;
  END IF;

  -- PLATFORM scope is accessible across tenants
  IF v_scope_type = 'PLATFORM' THEN
    RETURN true;
  END IF;

  v_effective_tenant := COALESCE(p_tenant_id, security.current_tenant_id());

  -- FAIL CLOSED: If effective tenant context is missing/NULL, deny access!
  IF v_effective_tenant IS NULL THEN
    RETURN false;
  END IF;

  IF v_scope_tenant_id IS NOT NULL AND v_scope_tenant_id = v_effective_tenant THEN
    RETURN true;
  END IF;

  RETURN false;
END;
$$ LANGUAGE plpgsql STABLE;

-- 4. Fail-Closed RLS Policies on TENANT_OWNED and TENANT_SHARED Tables

-- 4.1 security.tenants
DROP POLICY IF EXISTS tenants_tenant_isolation_policy ON security.tenants;
CREATE POLICY tenants_tenant_isolation_policy ON security.tenants
  FOR ALL
  USING (
    security.is_system_bypass() OR (
      security.current_tenant_id() IS NOT NULL 
      AND tenant_id = security.current_tenant_id()
    )
  )
  WITH CHECK (
    security.is_system_bypass() OR (
      security.current_tenant_id() IS NOT NULL 
      AND tenant_id = security.current_tenant_id()
    )
  );

-- 4.2 security.tenant_memberships
DROP POLICY IF EXISTS tenant_memberships_isolation_policy ON security.tenant_memberships;
CREATE POLICY tenant_memberships_isolation_policy ON security.tenant_memberships
  FOR ALL
  USING (
    security.is_system_bypass() OR (
      security.current_tenant_id() IS NOT NULL 
      AND tenant_id = security.current_tenant_id()
    )
  )
  WITH CHECK (
    security.is_system_bypass() OR (
      security.current_tenant_id() IS NOT NULL 
      AND tenant_id = security.current_tenant_id()
    )
  );

-- 4.3 security.access_scopes
DROP POLICY IF EXISTS access_scopes_isolation_policy ON security.access_scopes;
CREATE POLICY access_scopes_isolation_policy ON security.access_scopes
  FOR ALL
  USING (
    security.is_system_bypass() OR
    scope_type = 'PLATFORM' OR (
      security.current_tenant_id() IS NOT NULL 
      AND tenant_id = security.current_tenant_id()
    )
  )
  WITH CHECK (
    security.is_system_bypass() OR (
      security.current_tenant_id() IS NOT NULL 
      AND tenant_id = security.current_tenant_id()
    )
  );

-- 4.4 security.access_grants
DROP POLICY IF EXISTS access_grants_isolation_policy ON security.access_grants;
CREATE POLICY access_grants_isolation_policy ON security.access_grants
  FOR ALL
  USING (
    security.is_system_bypass() OR (
      target_scope IS NOT NULL 
      AND security.is_scope_accessible(target_scope)
    )
  )
  WITH CHECK (
    security.is_system_bypass() OR (
      target_scope IS NOT NULL 
      AND security.is_scope_accessible(target_scope)
    )
  );

-- 4.5 security.principals
DROP POLICY IF EXISTS principals_isolation_policy ON security.principals;
CREATE POLICY principals_isolation_policy ON security.principals
  FOR ALL
  USING (
    security.is_system_bypass() OR (
      security.current_tenant_id() IS NOT NULL 
      AND tenant_id = security.current_tenant_id()
    )
  )
  WITH CHECK (
    security.is_system_bypass() OR (
      security.current_tenant_id() IS NOT NULL 
      AND tenant_id = security.current_tenant_id()
    )
  );

-- 4.6 source.source_observations
DROP POLICY IF EXISTS source_observations_scope_policy ON source.source_observations;
CREATE POLICY source_observations_scope_policy ON source.source_observations
  FOR ALL
  USING (
    security.is_system_bypass() OR (
      scope_id IS NOT NULL 
      AND security.is_scope_accessible(scope_id)
    )
  )
  WITH CHECK (
    security.is_system_bypass() OR (
      scope_id IS NOT NULL 
      AND security.is_scope_accessible(scope_id)
    )
  );

-- 4.7 analysis.analysis_runs
DROP POLICY IF EXISTS analysis_runs_select_scope_policy ON analysis.analysis_runs;
DROP POLICY IF EXISTS analysis_runs_insert_scope_policy ON analysis.analysis_runs;
DROP POLICY IF EXISTS analysis_runs_update_scope_policy ON analysis.analysis_runs;
DROP POLICY IF EXISTS analysis_runs_delete_scope_policy ON analysis.analysis_runs;
DROP POLICY IF EXISTS analysis_runs_scope_policy ON analysis.analysis_runs;
CREATE POLICY analysis_runs_scope_policy ON analysis.analysis_runs
  FOR ALL
  USING (
    security.is_system_bypass() OR (
      scope_id IS NOT NULL 
      AND security.is_scope_accessible(scope_id)
    )
  )
  WITH CHECK (
    security.is_system_bypass() OR (
      scope_id IS NOT NULL 
      AND security.is_scope_accessible(scope_id)
    )
  );

-- 4.8 analysis.analysis_stage_runs
DROP POLICY IF EXISTS analysis_stage_runs_scope_policy ON analysis.analysis_stage_runs;
CREATE POLICY analysis_stage_runs_scope_policy ON analysis.analysis_stage_runs
  FOR ALL
  USING (
    security.is_system_bypass() OR
    EXISTS (
      SELECT 1 FROM analysis.analysis_runs r
      WHERE r.analysis_run_id = analysis_stage_runs.analysis_run_id
        AND r.scope_id IS NOT NULL
        AND security.is_scope_accessible(r.scope_id)
    )
  )
  WITH CHECK (
    security.is_system_bypass() OR
    EXISTS (
      SELECT 1 FROM analysis.analysis_runs r
      WHERE r.analysis_run_id = analysis_stage_runs.analysis_run_id
        AND r.scope_id IS NOT NULL
        AND security.is_scope_accessible(r.scope_id)
      )
  );

-- 4.9 analysis.static_findings
DROP POLICY IF EXISTS static_findings_scope_policy ON analysis.static_findings;
CREATE POLICY static_findings_scope_policy ON analysis.static_findings
  FOR ALL
  USING (
    security.is_system_bypass() OR
    EXISTS (
      SELECT 1 FROM analysis.analysis_runs r
      WHERE r.analysis_run_id = static_findings.analysis_run_id
        AND r.scope_id IS NOT NULL
        AND security.is_scope_accessible(r.scope_id)
    )
  )
  WITH CHECK (
    security.is_system_bypass() OR
    EXISTS (
      SELECT 1 FROM analysis.analysis_runs r
      WHERE r.analysis_run_id = static_findings.analysis_run_id
        AND r.scope_id IS NOT NULL
        AND security.is_scope_accessible(r.scope_id)
    )
  );

-- 4.10 intel.evidence
DROP POLICY IF EXISTS evidence_select_scope_policy ON intel.evidence;
DROP POLICY IF EXISTS evidence_insert_scope_policy ON intel.evidence;
DROP POLICY IF EXISTS evidence_update_scope_policy ON intel.evidence;
DROP POLICY IF EXISTS evidence_delete_scope_policy ON intel.evidence;
DROP POLICY IF EXISTS evidence_scope_policy ON intel.evidence;
CREATE POLICY evidence_scope_policy ON intel.evidence
  FOR ALL
  USING (
    security.is_system_bypass() OR (
      scope_id IS NOT NULL 
      AND security.is_scope_accessible(scope_id)
    )
  )
  WITH CHECK (
    security.is_system_bypass() OR (
      scope_id IS NOT NULL 
      AND security.is_scope_accessible(scope_id)
    )
  );

-- 4.11 intel.assertions
DROP POLICY IF EXISTS assertions_select_scope_policy ON intel.assertions;
DROP POLICY IF EXISTS assertions_insert_scope_policy ON intel.assertions;
DROP POLICY IF EXISTS assertions_update_scope_policy ON intel.assertions;
DROP POLICY IF EXISTS assertions_delete_scope_policy ON intel.assertions;
DROP POLICY IF EXISTS assertions_scope_policy ON intel.assertions;
CREATE POLICY assertions_scope_policy ON intel.assertions
  FOR ALL
  USING (
    security.is_system_bypass() OR (
      scope_id IS NOT NULL 
      AND security.is_scope_accessible(scope_id)
    )
  )
  WITH CHECK (
    security.is_system_bypass() OR (
      scope_id IS NOT NULL 
      AND security.is_scope_accessible(scope_id)
    )
  );

-- 4.12 intel.claims
DROP POLICY IF EXISTS claims_select_scope_policy ON intel.claims;
DROP POLICY IF EXISTS claims_insert_scope_policy ON intel.claims;
DROP POLICY IF EXISTS claims_update_scope_policy ON intel.claims;
DROP POLICY IF EXISTS claims_delete_scope_policy ON intel.claims;
DROP POLICY IF EXISTS claims_scope_policy ON intel.claims;
CREATE POLICY claims_scope_policy ON intel.claims
  FOR ALL
  USING (
    security.is_system_bypass() OR (
      scope_id IS NOT NULL 
      AND security.is_scope_accessible(scope_id)
    )
  )
  WITH CHECK (
    security.is_system_bypass() OR (
      scope_id IS NOT NULL 
      AND security.is_scope_accessible(scope_id)
    )
  );

-- 4.13 intel.risks
DROP POLICY IF EXISTS risks_scope_policy ON intel.risks;
CREATE POLICY risks_scope_policy ON intel.risks
  FOR ALL
  USING (
    security.is_system_bypass() OR (
      analysis_run_id IS NOT NULL AND
      EXISTS (
        SELECT 1 FROM analysis.analysis_runs r
        WHERE r.analysis_run_id = risks.analysis_run_id
          AND r.scope_id IS NOT NULL
          AND security.is_scope_accessible(r.scope_id)
      )
    )
  )
  WITH CHECK (
    security.is_system_bypass() OR (
      analysis_run_id IS NOT NULL AND
      EXISTS (
        SELECT 1 FROM analysis.analysis_runs r
        WHERE r.analysis_run_id = risks.analysis_run_id
          AND r.scope_id IS NOT NULL
          AND security.is_scope_accessible(r.scope_id)
      )
    )
  );

-- 4.14 intel.policy_decisions
DROP POLICY IF EXISTS policy_decisions_scope_policy ON intel.policy_decisions;
CREATE POLICY policy_decisions_scope_policy ON intel.policy_decisions
  FOR ALL
  USING (
    security.is_system_bypass() OR (
      analysis_run_id IS NOT NULL AND
      EXISTS (
        SELECT 1 FROM analysis.analysis_runs r
        WHERE r.analysis_run_id = policy_decisions.analysis_run_id
          AND r.scope_id IS NOT NULL
          AND security.is_scope_accessible(r.scope_id)
      )
    )
  )
  WITH CHECK (
    security.is_system_bypass() OR (
      analysis_run_id IS NOT NULL AND
      EXISTS (
        SELECT 1 FROM analysis.analysis_runs r
        WHERE r.analysis_run_id = policy_decisions.analysis_run_id
          AND r.scope_id IS NOT NULL
          AND security.is_scope_accessible(r.scope_id)
      )
    )
  );

-- 4.15 intel.recommendations
DROP POLICY IF EXISTS recommendations_scope_policy ON intel.recommendations;
CREATE POLICY recommendations_scope_policy ON intel.recommendations
  FOR ALL
  USING (
    security.is_system_bypass() OR (
      analysis_run_id IS NOT NULL AND
      EXISTS (
        SELECT 1 FROM analysis.analysis_runs r
        WHERE r.analysis_run_id = recommendations.analysis_run_id
          AND r.scope_id IS NOT NULL
          AND security.is_scope_accessible(r.scope_id)
      )
    )
  )
  WITH CHECK (
    security.is_system_bypass() OR (
      analysis_run_id IS NOT NULL AND
      EXISTS (
        SELECT 1 FROM analysis.analysis_runs r
        WHERE r.analysis_run_id = recommendations.analysis_run_id
          AND r.scope_id IS NOT NULL
          AND security.is_scope_accessible(r.scope_id)
      )
    )
  );

-- 4.16 lifecycle.validation_runs
DROP POLICY IF EXISTS validation_runs_select_scope_policy ON lifecycle.validation_runs;
DROP POLICY IF EXISTS validation_runs_insert_scope_policy ON lifecycle.validation_runs;
DROP POLICY IF EXISTS validation_runs_update_scope_policy ON lifecycle.validation_runs;
DROP POLICY IF EXISTS validation_runs_delete_scope_policy ON lifecycle.validation_runs;
DROP POLICY IF EXISTS validation_runs_scope_policy ON lifecycle.validation_runs;
CREATE POLICY validation_runs_scope_policy ON lifecycle.validation_runs
  FOR ALL
  USING (
    security.is_system_bypass() OR (
      scope_id IS NOT NULL 
      AND security.is_scope_accessible(scope_id)
    )
  )
  WITH CHECK (
    security.is_system_bypass() OR (
      scope_id IS NOT NULL 
      AND security.is_scope_accessible(scope_id)
    )
  );

-- 4.17 lifecycle.validation_results
DROP POLICY IF EXISTS validation_results_scope_policy ON lifecycle.validation_results;
CREATE POLICY validation_results_scope_policy ON lifecycle.validation_results
  FOR ALL
  USING (
    security.is_system_bypass() OR
    EXISTS (
      SELECT 1 FROM lifecycle.validation_runs v
      WHERE v.validation_run_id = validation_results.validation_run_id
        AND v.scope_id IS NOT NULL
        AND security.is_scope_accessible(v.scope_id)
    )
  )
  WITH CHECK (
    security.is_system_bypass() OR
    EXISTS (
      SELECT 1 FROM lifecycle.validation_runs v
      WHERE v.validation_run_id = validation_results.validation_run_id
        AND v.scope_id IS NOT NULL
        AND security.is_scope_accessible(v.scope_id)
    )
  );

-- 4.18 lifecycle.modification_workspaces
DROP POLICY IF EXISTS modification_workspaces_isolation_policy ON lifecycle.modification_workspaces;
CREATE POLICY modification_workspaces_isolation_policy ON lifecycle.modification_workspaces
  FOR ALL
  USING (
    security.is_system_bypass() OR (
      security.current_tenant_id() IS NOT NULL AND
      EXISTS (
        SELECT 1 FROM security.principals p
        WHERE p.principal_id::text = modification_workspaces.created_by
          AND p.tenant_id = security.current_tenant_id()
      )
    )
  )
  WITH CHECK (
    security.is_system_bypass() OR (
      security.current_tenant_id() IS NOT NULL AND
      EXISTS (
        SELECT 1 FROM security.principals p
        WHERE p.principal_id::text = modification_workspaces.created_by
          AND p.tenant_id = security.current_tenant_id()
      )
    )
  );
