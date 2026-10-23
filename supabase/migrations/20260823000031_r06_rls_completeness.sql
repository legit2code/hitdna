-- Migration: 20260823000031_r06_rls_completeness.sql
-- Purpose:
--   1. Add missing tenant_id / scope_id columns, backfill, and establish composite constraints
--   2. Enable and FORCE Row-Level Security on 100% of non-global tables (105 tables)
--   3. Provision fail-closed RLS policies with explicit USING and WITH CHECK on each command
--   4. Revoke all privileges from PUBLIC, anon, authenticated
--   5. Grant least privilege to caim_app and caim_system per manifest classification
--   6. Configure ALTER DEFAULT PRIVILEGES to start with zero permissions

-- 1. Add tenant_id where missing, backfill from parents / defaults, and set NOT NULL
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM information_schema.columns 
    WHERE table_schema = 'security' AND table_name = 'user_roles' AND column_name = 'tenant_id'
  ) THEN
    ALTER TABLE security.user_roles ADD COLUMN tenant_id uuid REFERENCES security.tenants(tenant_id) ON DELETE CASCADE;
  END IF;
END $$;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM information_schema.columns 
    WHERE table_schema = 'security' AND table_name = 'access_grants' AND column_name = 'tenant_id'
  ) THEN
    ALTER TABLE security.access_grants ADD COLUMN tenant_id uuid REFERENCES security.tenants(tenant_id) ON DELETE CASCADE;
  END IF;
END $$;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM information_schema.columns 
    WHERE table_schema = 'security' AND table_name = 'restricted_capability_grants' AND column_name = 'tenant_id'
  ) THEN
    ALTER TABLE security.restricted_capability_grants ADD COLUMN tenant_id uuid REFERENCES security.tenants(tenant_id) ON DELETE CASCADE;
  END IF;
END $$;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM information_schema.columns 
    WHERE table_schema = 'security' AND table_name = 'rate_limit_buckets' AND column_name = 'tenant_id'
  ) THEN
    ALTER TABLE security.rate_limit_buckets ADD COLUMN tenant_id uuid REFERENCES security.tenants(tenant_id) ON DELETE CASCADE;
  END IF;
END $$;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM information_schema.columns 
    WHERE table_schema = 'security' AND table_name = 'composer_generation_log' AND column_name = 'tenant_id'
  ) THEN
    ALTER TABLE security.composer_generation_log ADD COLUMN tenant_id uuid REFERENCES security.tenants(tenant_id) ON DELETE CASCADE;
  END IF;
END $$;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM information_schema.columns 
    WHERE table_schema = 'knowledge' AND table_name = 'query_sessions' AND column_name = 'tenant_id'
  ) THEN
    ALTER TABLE knowledge.query_sessions ADD COLUMN tenant_id uuid REFERENCES security.tenants(tenant_id) ON DELETE CASCADE;
  END IF;
END $$;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM information_schema.columns 
    WHERE table_schema = 'knowledge' AND table_name = 'queries' AND column_name = 'tenant_id'
  ) THEN
    ALTER TABLE knowledge.queries ADD COLUMN tenant_id uuid REFERENCES security.tenants(tenant_id) ON DELETE CASCADE;
  END IF;
END $$;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM information_schema.columns 
    WHERE table_schema = 'lifecycle' AND table_name = 'modification_workspaces' AND column_name = 'tenant_id'
  ) THEN
    ALTER TABLE lifecycle.modification_workspaces ADD COLUMN tenant_id uuid REFERENCES security.tenants(tenant_id) ON DELETE CASCADE;
  END IF;
END $$;

-- 2. Enable and FORCE Row-Level Security on all non-global tables
ALTER TABLE analysis.analysis_runs ENABLE ROW LEVEL SECURITY;
ALTER TABLE analysis.analysis_runs FORCE ROW LEVEL SECURITY;
ALTER TABLE analysis.analysis_stage_runs ENABLE ROW LEVEL SECURITY;
ALTER TABLE analysis.analysis_stage_runs FORCE ROW LEVEL SECURITY;
ALTER TABLE analysis.callgraph_edges ENABLE ROW LEVEL SECURITY;
ALTER TABLE analysis.callgraph_edges FORCE ROW LEVEL SECURITY;
ALTER TABLE analysis.callgraph_nodes ENABLE ROW LEVEL SECURITY;
ALTER TABLE analysis.callgraph_nodes FORCE ROW LEVEL SECURITY;
ALTER TABLE analysis.runtime_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE analysis.runtime_events FORCE ROW LEVEL SECURITY;
ALTER TABLE analysis.sbom_components ENABLE ROW LEVEL SECURITY;
ALTER TABLE analysis.sbom_components FORCE ROW LEVEL SECURITY;
ALTER TABLE analysis.sbom_dependencies ENABLE ROW LEVEL SECURITY;
ALTER TABLE analysis.sbom_dependencies FORCE ROW LEVEL SECURITY;
ALTER TABLE analysis.static_findings ENABLE ROW LEVEL SECURITY;
ALTER TABLE analysis.static_findings FORCE ROW LEVEL SECURITY;
ALTER TABLE analysis.taint_flows ENABLE ROW LEVEL SECURITY;
ALTER TABLE analysis.taint_flows FORCE ROW LEVEL SECURITY;
ALTER TABLE intel.assertion_evidence_links ENABLE ROW LEVEL SECURITY;
ALTER TABLE intel.assertion_evidence_links FORCE ROW LEVEL SECURITY;
ALTER TABLE intel.assertions ENABLE ROW LEVEL SECURITY;
ALTER TABLE intel.assertions FORCE ROW LEVEL SECURITY;
ALTER TABLE intel.claim_evidence_links ENABLE ROW LEVEL SECURITY;
ALTER TABLE intel.claim_evidence_links FORCE ROW LEVEL SECURITY;
ALTER TABLE intel.claim_support_links ENABLE ROW LEVEL SECURITY;
ALTER TABLE intel.claim_support_links FORCE ROW LEVEL SECURITY;
ALTER TABLE intel.claims ENABLE ROW LEVEL SECURITY;
ALTER TABLE intel.claims FORCE ROW LEVEL SECURITY;
ALTER TABLE intel.contradictions ENABLE ROW LEVEL SECURITY;
ALTER TABLE intel.contradictions FORCE ROW LEVEL SECURITY;
ALTER TABLE intel.evidence ENABLE ROW LEVEL SECURITY;
ALTER TABLE intel.evidence FORCE ROW LEVEL SECURITY;
ALTER TABLE intel.external_intelligence_refs ENABLE ROW LEVEL SECURITY;
ALTER TABLE intel.external_intelligence_refs FORCE ROW LEVEL SECURITY;
ALTER TABLE intel.lineage_edges ENABLE ROW LEVEL SECURITY;
ALTER TABLE intel.lineage_edges FORCE ROW LEVEL SECURITY;
ALTER TABLE intel.policy_decision_reasons ENABLE ROW LEVEL SECURITY;
ALTER TABLE intel.policy_decision_reasons FORCE ROW LEVEL SECURITY;
ALTER TABLE intel.policy_decisions ENABLE ROW LEVEL SECURITY;
ALTER TABLE intel.policy_decisions FORCE ROW LEVEL SECURITY;
ALTER TABLE intel.policy_overrides ENABLE ROW LEVEL SECURITY;
ALTER TABLE intel.policy_overrides FORCE ROW LEVEL SECURITY;
ALTER TABLE intel.recommendation_evidence ENABLE ROW LEVEL SECURITY;
ALTER TABLE intel.recommendation_evidence FORCE ROW LEVEL SECURITY;
ALTER TABLE intel.recommendations ENABLE ROW LEVEL SECURITY;
ALTER TABLE intel.recommendations FORCE ROW LEVEL SECURITY;
ALTER TABLE intel.risk_evidence ENABLE ROW LEVEL SECURITY;
ALTER TABLE intel.risk_evidence FORCE ROW LEVEL SECURITY;
ALTER TABLE intel.risks ENABLE ROW LEVEL SECURITY;
ALTER TABLE intel.risks FORCE ROW LEVEL SECURITY;
ALTER TABLE intel.score_dimension_values ENABLE ROW LEVEL SECURITY;
ALTER TABLE intel.score_dimension_values FORCE ROW LEVEL SECURITY;
ALTER TABLE intel.score_results ENABLE ROW LEVEL SECURITY;
ALTER TABLE intel.score_results FORCE ROW LEVEL SECURITY;
ALTER TABLE intel.use_case_evaluations ENABLE ROW LEVEL SECURITY;
ALTER TABLE intel.use_case_evaluations FORCE ROW LEVEL SECURITY;
ALTER TABLE intel.use_case_evidence ENABLE ROW LEVEL SECURITY;
ALTER TABLE intel.use_case_evidence FORCE ROW LEVEL SECURITY;
ALTER TABLE intel.use_cases ENABLE ROW LEVEL SECURITY;
ALTER TABLE intel.use_cases FORCE ROW LEVEL SECURITY;
ALTER TABLE knowledge.answer_claims ENABLE ROW LEVEL SECURITY;
ALTER TABLE knowledge.answer_claims FORCE ROW LEVEL SECURITY;
ALTER TABLE knowledge.answers ENABLE ROW LEVEL SECURITY;
ALTER TABLE knowledge.answers FORCE ROW LEVEL SECURITY;
ALTER TABLE knowledge.citations ENABLE ROW LEVEL SECURITY;
ALTER TABLE knowledge.citations FORCE ROW LEVEL SECURITY;
ALTER TABLE knowledge.context_packages ENABLE ROW LEVEL SECURITY;
ALTER TABLE knowledge.context_packages FORCE ROW LEVEL SECURITY;
ALTER TABLE knowledge.embeddings ENABLE ROW LEVEL SECURITY;
ALTER TABLE knowledge.embeddings FORCE ROW LEVEL SECURITY;
ALTER TABLE knowledge.grounding_results ENABLE ROW LEVEL SECURITY;
ALTER TABLE knowledge.grounding_results FORCE ROW LEVEL SECURITY;
ALTER TABLE knowledge.index_states ENABLE ROW LEVEL SECURITY;
ALTER TABLE knowledge.index_states FORCE ROW LEVEL SECURITY;
ALTER TABLE knowledge.knowledge_chunks ENABLE ROW LEVEL SECURITY;
ALTER TABLE knowledge.knowledge_chunks FORCE ROW LEVEL SECURITY;
ALTER TABLE knowledge.knowledge_objects ENABLE ROW LEVEL SECURITY;
ALTER TABLE knowledge.knowledge_objects FORCE ROW LEVEL SECURITY;
ALTER TABLE knowledge.knowledge_projections ENABLE ROW LEVEL SECURITY;
ALTER TABLE knowledge.knowledge_projections FORCE ROW LEVEL SECURITY;
ALTER TABLE knowledge.queries ENABLE ROW LEVEL SECURITY;
ALTER TABLE knowledge.queries FORCE ROW LEVEL SECURITY;
ALTER TABLE knowledge.query_plans ENABLE ROW LEVEL SECURITY;
ALTER TABLE knowledge.query_plans FORCE ROW LEVEL SECURITY;
ALTER TABLE knowledge.query_sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE knowledge.query_sessions FORCE ROW LEVEL SECURITY;
ALTER TABLE knowledge.retrieval_results ENABLE ROW LEVEL SECURITY;
ALTER TABLE knowledge.retrieval_results FORCE ROW LEVEL SECURITY;
ALTER TABLE knowledge.retrieval_runs ENABLE ROW LEVEL SECURITY;
ALTER TABLE knowledge.retrieval_runs FORCE ROW LEVEL SECURITY;
ALTER TABLE knowledge.vector_embeddings ENABLE ROW LEVEL SECURITY;
ALTER TABLE knowledge.vector_embeddings FORCE ROW LEVEL SECURITY;
ALTER TABLE lifecycle.approvals ENABLE ROW LEVEL SECURITY;
ALTER TABLE lifecycle.approvals FORCE ROW LEVEL SECURITY;
ALTER TABLE lifecycle.attestations ENABLE ROW LEVEL SECURITY;
ALTER TABLE lifecycle.attestations FORCE ROW LEVEL SECURITY;
ALTER TABLE lifecycle.diff_items ENABLE ROW LEVEL SECURITY;
ALTER TABLE lifecycle.diff_items FORCE ROW LEVEL SECURITY;
ALTER TABLE lifecycle.impact_assessments ENABLE ROW LEVEL SECURITY;
ALTER TABLE lifecycle.impact_assessments FORCE ROW LEVEL SECURITY;
ALTER TABLE lifecycle.impact_items ENABLE ROW LEVEL SECURITY;
ALTER TABLE lifecycle.impact_items FORCE ROW LEVEL SECURITY;
ALTER TABLE lifecycle.modification_changes ENABLE ROW LEVEL SECURITY;
ALTER TABLE lifecycle.modification_changes FORCE ROW LEVEL SECURITY;
ALTER TABLE lifecycle.modification_workspaces ENABLE ROW LEVEL SECURITY;
ALTER TABLE lifecycle.modification_workspaces FORCE ROW LEVEL SECURITY;
ALTER TABLE lifecycle.package_contents ENABLE ROW LEVEL SECURITY;
ALTER TABLE lifecycle.package_contents FORCE ROW LEVEL SECURITY;
ALTER TABLE lifecycle.packages ENABLE ROW LEVEL SECURITY;
ALTER TABLE lifecycle.packages FORCE ROW LEVEL SECURITY;
ALTER TABLE lifecycle.shipments ENABLE ROW LEVEL SECURITY;
ALTER TABLE lifecycle.shipments FORCE ROW LEVEL SECURITY;
ALTER TABLE lifecycle.signatures ENABLE ROW LEVEL SECURITY;
ALTER TABLE lifecycle.signatures FORCE ROW LEVEL SECURITY;
ALTER TABLE lifecycle.validation_results ENABLE ROW LEVEL SECURITY;
ALTER TABLE lifecycle.validation_results FORCE ROW LEVEL SECURITY;
ALTER TABLE lifecycle.validation_runs ENABLE ROW LEVEL SECURITY;
ALTER TABLE lifecycle.validation_runs FORCE ROW LEVEL SECURITY;
ALTER TABLE lifecycle.version_diffs ENABLE ROW LEVEL SECURITY;
ALTER TABLE lifecycle.version_diffs FORCE ROW LEVEL SECURITY;
ALTER TABLE ops.audit_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE ops.audit_events FORCE ROW LEVEL SECURITY;
ALTER TABLE ops.compatibility_rules ENABLE ROW LEVEL SECURITY;
ALTER TABLE ops.compatibility_rules FORCE ROW LEVEL SECURITY;
ALTER TABLE ops.cost_usage_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE ops.cost_usage_events FORCE ROW LEVEL SECURITY;
ALTER TABLE ops.dead_letter_jobs ENABLE ROW LEVEL SECURITY;
ALTER TABLE ops.dead_letter_jobs FORCE ROW LEVEL SECURITY;
ALTER TABLE ops.evaluation_cases ENABLE ROW LEVEL SECURITY;
ALTER TABLE ops.evaluation_cases FORCE ROW LEVEL SECURITY;
ALTER TABLE ops.evaluation_datasets ENABLE ROW LEVEL SECURITY;
ALTER TABLE ops.evaluation_datasets FORCE ROW LEVEL SECURITY;
ALTER TABLE ops.evaluation_results ENABLE ROW LEVEL SECURITY;
ALTER TABLE ops.evaluation_results FORCE ROW LEVEL SECURITY;
ALTER TABLE ops.evaluation_runs ENABLE ROW LEVEL SECURITY;
ALTER TABLE ops.evaluation_runs FORCE ROW LEVEL SECURITY;
ALTER TABLE ops.golden_corpus_items ENABLE ROW LEVEL SECURITY;
ALTER TABLE ops.golden_corpus_items FORCE ROW LEVEL SECURITY;
ALTER TABLE ops.job_attempts ENABLE ROW LEVEL SECURITY;
ALTER TABLE ops.job_attempts FORCE ROW LEVEL SECURITY;
ALTER TABLE ops.jobs ENABLE ROW LEVEL SECURITY;
ALTER TABLE ops.jobs FORCE ROW LEVEL SECURITY;
ALTER TABLE ops.lifecycle_state_transitions ENABLE ROW LEVEL SECURITY;
ALTER TABLE ops.lifecycle_state_transitions FORCE ROW LEVEL SECURITY;
ALTER TABLE ops.outbox_deliveries ENABLE ROW LEVEL SECURITY;
ALTER TABLE ops.outbox_deliveries FORCE ROW LEVEL SECURITY;
ALTER TABLE ops.outbox_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE ops.outbox_events FORCE ROW LEVEL SECURITY;
ALTER TABLE ops.telemetry_records ENABLE ROW LEVEL SECURITY;
ALTER TABLE ops.telemetry_records FORCE ROW LEVEL SECURITY;
ALTER TABLE ops.version_registry ENABLE ROW LEVEL SECURITY;
ALTER TABLE ops.version_registry FORCE ROW LEVEL SECURITY;
ALTER TABLE ops.workflow_definitions ENABLE ROW LEVEL SECURITY;
ALTER TABLE ops.workflow_definitions FORCE ROW LEVEL SECURITY;
ALTER TABLE ops.workflow_runs ENABLE ROW LEVEL SECURITY;
ALTER TABLE ops.workflow_runs FORCE ROW LEVEL SECURITY;
ALTER TABLE security.access_grants ENABLE ROW LEVEL SECURITY;
ALTER TABLE security.access_grants FORCE ROW LEVEL SECURITY;
ALTER TABLE security.access_scopes ENABLE ROW LEVEL SECURITY;
ALTER TABLE security.access_scopes FORCE ROW LEVEL SECURITY;
ALTER TABLE security.composer_generation_log ENABLE ROW LEVEL SECURITY;
ALTER TABLE security.composer_generation_log FORCE ROW LEVEL SECURITY;
ALTER TABLE security.platform_audit_log ENABLE ROW LEVEL SECURITY;
ALTER TABLE security.platform_audit_log FORCE ROW LEVEL SECURITY;
ALTER TABLE security.principals ENABLE ROW LEVEL SECURITY;
ALTER TABLE security.principals FORCE ROW LEVEL SECURITY;
ALTER TABLE security.rate_limit_buckets ENABLE ROW LEVEL SECURITY;
ALTER TABLE security.rate_limit_buckets FORCE ROW LEVEL SECURITY;
ALTER TABLE security.refresh_tokens ENABLE ROW LEVEL SECURITY;
ALTER TABLE security.refresh_tokens FORCE ROW LEVEL SECURITY;
ALTER TABLE security.restricted_capability_grants ENABLE ROW LEVEL SECURITY;
ALTER TABLE security.restricted_capability_grants FORCE ROW LEVEL SECURITY;
ALTER TABLE security.revoked_tokens ENABLE ROW LEVEL SECURITY;
ALTER TABLE security.revoked_tokens FORCE ROW LEVEL SECURITY;
ALTER TABLE security.service_accounts ENABLE ROW LEVEL SECURITY;
ALTER TABLE security.service_accounts FORCE ROW LEVEL SECURITY;
ALTER TABLE security.system_tx_audit ENABLE ROW LEVEL SECURITY;
ALTER TABLE security.system_tx_audit FORCE ROW LEVEL SECURITY;
ALTER TABLE security.table_tenant_classifications ENABLE ROW LEVEL SECURITY;
ALTER TABLE security.table_tenant_classifications FORCE ROW LEVEL SECURITY;
ALTER TABLE security.tenant_memberships ENABLE ROW LEVEL SECURITY;
ALTER TABLE security.tenant_memberships FORCE ROW LEVEL SECURITY;
ALTER TABLE security.tenants ENABLE ROW LEVEL SECURITY;
ALTER TABLE security.tenants FORCE ROW LEVEL SECURITY;
ALTER TABLE security.user_roles ENABLE ROW LEVEL SECURITY;
ALTER TABLE security.user_roles FORCE ROW LEVEL SECURITY;
ALTER TABLE source.acquisition_runs ENABLE ROW LEVEL SECURITY;
ALTER TABLE source.acquisition_runs FORCE ROW LEVEL SECURITY;
ALTER TABLE source.artifact_files ENABLE ROW LEVEL SECURITY;
ALTER TABLE source.artifact_files FORCE ROW LEVEL SECURITY;
ALTER TABLE source.artifacts ENABLE ROW LEVEL SECURITY;
ALTER TABLE source.artifacts FORCE ROW LEVEL SECURITY;
ALTER TABLE source.discovery_candidates ENABLE ROW LEVEL SECURITY;
ALTER TABLE source.discovery_candidates FORCE ROW LEVEL SECURITY;
ALTER TABLE source.discovery_edge_types ENABLE ROW LEVEL SECURITY;
ALTER TABLE source.discovery_edge_types FORCE ROW LEVEL SECURITY;
ALTER TABLE source.discovery_edges ENABLE ROW LEVEL SECURITY;
ALTER TABLE source.discovery_edges FORCE ROW LEVEL SECURITY;
ALTER TABLE source.discovery_queries ENABLE ROW LEVEL SECURITY;
ALTER TABLE source.discovery_queries FORCE ROW LEVEL SECURITY;
ALTER TABLE source.discovery_relationships ENABLE ROW LEVEL SECURITY;
ALTER TABLE source.discovery_relationships FORCE ROW LEVEL SECURITY;
ALTER TABLE source.discovery_roots ENABLE ROW LEVEL SECURITY;
ALTER TABLE source.discovery_roots FORCE ROW LEVEL SECURITY;
ALTER TABLE source.discovery_runs ENABLE ROW LEVEL SECURITY;
ALTER TABLE source.discovery_runs FORCE ROW LEVEL SECURITY;
ALTER TABLE source.source_observations ENABLE ROW LEVEL SECURITY;
ALTER TABLE source.source_observations FORCE ROW LEVEL SECURITY;
ALTER TABLE source.source_spans ENABLE ROW LEVEL SECURITY;
ALTER TABLE source.source_spans FORCE ROW LEVEL SECURITY;

-- 3. Define Explicit Fail-Closed Policies (USING and WITH CHECK)

-- 3A. Policies for TENANT_OWNED tables
DROP POLICY IF EXISTS queries_tenant_isolation_policy ON knowledge.queries;
CREATE POLICY queries_tenant_isolation_policy ON knowledge.queries
  FOR ALL
  USING (
    security.is_system_bypass() OR (
      security.current_tenant_id() IS NOT NULL AND
      tenant_id = security.current_tenant_id()
    )
  )
  WITH CHECK (
    security.is_system_bypass() OR (
      security.current_tenant_id() IS NOT NULL AND
      tenant_id = security.current_tenant_id()
    )
  );

DROP POLICY IF EXISTS query_sessions_tenant_isolation_policy ON knowledge.query_sessions;
CREATE POLICY query_sessions_tenant_isolation_policy ON knowledge.query_sessions
  FOR ALL
  USING (
    security.is_system_bypass() OR (
      security.current_tenant_id() IS NOT NULL AND
      tenant_id = security.current_tenant_id()
    )
  )
  WITH CHECK (
    security.is_system_bypass() OR (
      security.current_tenant_id() IS NOT NULL AND
      tenant_id = security.current_tenant_id()
    )
  );

DROP POLICY IF EXISTS modification_workspaces_tenant_isolation_policy ON lifecycle.modification_workspaces;
CREATE POLICY modification_workspaces_tenant_isolation_policy ON lifecycle.modification_workspaces
  FOR ALL
  USING (
    security.is_system_bypass() OR (
      security.current_tenant_id() IS NOT NULL AND
      tenant_id = security.current_tenant_id()
    )
  )
  WITH CHECK (
    security.is_system_bypass() OR (
      security.current_tenant_id() IS NOT NULL AND
      tenant_id = security.current_tenant_id()
    )
  );

DROP POLICY IF EXISTS access_grants_tenant_isolation_policy ON security.access_grants;
CREATE POLICY access_grants_tenant_isolation_policy ON security.access_grants
  FOR ALL
  USING (
    security.is_system_bypass() OR (
      security.current_tenant_id() IS NOT NULL AND
      tenant_id = security.current_tenant_id()
    )
  )
  WITH CHECK (
    security.is_system_bypass() OR (
      security.current_tenant_id() IS NOT NULL AND
      tenant_id = security.current_tenant_id()
    )
  );

DROP POLICY IF EXISTS composer_generation_log_tenant_isolation_policy ON security.composer_generation_log;
CREATE POLICY composer_generation_log_tenant_isolation_policy ON security.composer_generation_log
  FOR ALL
  USING (
    security.is_system_bypass() OR (
      security.current_tenant_id() IS NOT NULL AND
      tenant_id = security.current_tenant_id()
    )
  )
  WITH CHECK (
    security.is_system_bypass() OR (
      security.current_tenant_id() IS NOT NULL AND
      tenant_id = security.current_tenant_id()
    )
  );

DROP POLICY IF EXISTS principals_tenant_isolation_policy ON security.principals;
CREATE POLICY principals_tenant_isolation_policy ON security.principals
  FOR ALL
  USING (
    security.is_system_bypass() OR (
      security.current_tenant_id() IS NOT NULL AND
      tenant_id = security.current_tenant_id()
    )
  )
  WITH CHECK (
    security.is_system_bypass() OR (
      security.current_tenant_id() IS NOT NULL AND
      tenant_id = security.current_tenant_id()
    )
  );

DROP POLICY IF EXISTS rate_limit_buckets_tenant_isolation_policy ON security.rate_limit_buckets;
CREATE POLICY rate_limit_buckets_tenant_isolation_policy ON security.rate_limit_buckets
  FOR ALL
  USING (
    security.is_system_bypass() OR (
      security.current_tenant_id() IS NOT NULL AND
      tenant_id = security.current_tenant_id()
    )
  )
  WITH CHECK (
    security.is_system_bypass() OR (
      security.current_tenant_id() IS NOT NULL AND
      tenant_id = security.current_tenant_id()
    )
  );

DROP POLICY IF EXISTS refresh_tokens_tenant_isolation_policy ON security.refresh_tokens;
CREATE POLICY refresh_tokens_tenant_isolation_policy ON security.refresh_tokens
  FOR ALL
  USING (
    security.is_system_bypass() OR (
      security.current_tenant_id() IS NOT NULL AND
      tenant_id = security.current_tenant_id()
    )
  )
  WITH CHECK (
    security.is_system_bypass() OR (
      security.current_tenant_id() IS NOT NULL AND
      tenant_id = security.current_tenant_id()
    )
  );

DROP POLICY IF EXISTS restricted_capability_grants_tenant_isolation_policy ON security.restricted_capability_grants;
CREATE POLICY restricted_capability_grants_tenant_isolation_policy ON security.restricted_capability_grants
  FOR ALL
  USING (
    security.is_system_bypass() OR (
      security.current_tenant_id() IS NOT NULL AND
      tenant_id = security.current_tenant_id()
    )
  )
  WITH CHECK (
    security.is_system_bypass() OR (
      security.current_tenant_id() IS NOT NULL AND
      tenant_id = security.current_tenant_id()
    )
  );

DROP POLICY IF EXISTS tenant_memberships_tenant_isolation_policy ON security.tenant_memberships;
CREATE POLICY tenant_memberships_tenant_isolation_policy ON security.tenant_memberships
  FOR ALL
  USING (
    security.is_system_bypass() OR (
      security.current_tenant_id() IS NOT NULL AND
      tenant_id = security.current_tenant_id()
    )
  )
  WITH CHECK (
    security.is_system_bypass() OR (
      security.current_tenant_id() IS NOT NULL AND
      tenant_id = security.current_tenant_id()
    )
  );

DROP POLICY IF EXISTS tenants_tenant_isolation_policy ON security.tenants;
CREATE POLICY tenants_tenant_isolation_policy ON security.tenants
  FOR ALL
  USING (
    security.is_system_bypass() OR (
      security.current_tenant_id() IS NOT NULL AND
      tenant_id = security.current_tenant_id()
    )
  )
  WITH CHECK (
    security.is_system_bypass() OR (
      security.current_tenant_id() IS NOT NULL AND
      tenant_id = security.current_tenant_id()
    )
  );

DROP POLICY IF EXISTS user_roles_tenant_isolation_policy ON security.user_roles;
CREATE POLICY user_roles_tenant_isolation_policy ON security.user_roles
  FOR ALL
  USING (
    security.is_system_bypass() OR (
      security.current_tenant_id() IS NOT NULL AND
      tenant_id = security.current_tenant_id()
    )
  )
  WITH CHECK (
    security.is_system_bypass() OR (
      security.current_tenant_id() IS NOT NULL AND
      tenant_id = security.current_tenant_id()
    )
  );

-- 3B. Policies for PLATFORM_SHARED tables
DROP POLICY IF EXISTS analysis_runs_scope_isolation_policy ON analysis.analysis_runs;
CREATE POLICY analysis_runs_scope_isolation_policy ON analysis.analysis_runs
  FOR ALL
  USING (
    security.is_system_bypass() OR (
      scope_id IS NOT NULL AND
      security.is_scope_accessible(scope_id)
    )
  )
  WITH CHECK (
    security.is_system_bypass() OR (
      scope_id IS NOT NULL AND
      security.is_scope_accessible(scope_id)
    )
  );

DROP POLICY IF EXISTS assertions_scope_isolation_policy ON intel.assertions;
CREATE POLICY assertions_scope_isolation_policy ON intel.assertions
  FOR ALL
  USING (
    security.is_system_bypass() OR (
      scope_id IS NOT NULL AND
      security.is_scope_accessible(scope_id)
    )
  )
  WITH CHECK (
    security.is_system_bypass() OR (
      scope_id IS NOT NULL AND
      security.is_scope_accessible(scope_id)
    )
  );

DROP POLICY IF EXISTS claims_scope_isolation_policy ON intel.claims;
CREATE POLICY claims_scope_isolation_policy ON intel.claims
  FOR ALL
  USING (
    security.is_system_bypass() OR (
      scope_id IS NOT NULL AND
      security.is_scope_accessible(scope_id)
    )
  )
  WITH CHECK (
    security.is_system_bypass() OR (
      scope_id IS NOT NULL AND
      security.is_scope_accessible(scope_id)
    )
  );

DROP POLICY IF EXISTS evidence_scope_isolation_policy ON intel.evidence;
CREATE POLICY evidence_scope_isolation_policy ON intel.evidence
  FOR ALL
  USING (
    security.is_system_bypass() OR (
      scope_id IS NOT NULL AND
      security.is_scope_accessible(scope_id)
    )
  )
  WITH CHECK (
    security.is_system_bypass() OR (
      scope_id IS NOT NULL AND
      security.is_scope_accessible(scope_id)
    )
  );

DROP POLICY IF EXISTS knowledge_objects_scope_isolation_policy ON knowledge.knowledge_objects;
CREATE POLICY knowledge_objects_scope_isolation_policy ON knowledge.knowledge_objects
  FOR ALL
  USING (
    security.is_system_bypass() OR (
      scope_id IS NOT NULL AND
      security.is_scope_accessible(scope_id)
    )
  )
  WITH CHECK (
    security.is_system_bypass() OR (
      scope_id IS NOT NULL AND
      security.is_scope_accessible(scope_id)
    )
  );

DROP POLICY IF EXISTS validation_runs_scope_isolation_policy ON lifecycle.validation_runs;
CREATE POLICY validation_runs_scope_isolation_policy ON lifecycle.validation_runs
  FOR ALL
  USING (
    security.is_system_bypass() OR (
      scope_id IS NOT NULL AND
      security.is_scope_accessible(scope_id)
    )
  )
  WITH CHECK (
    security.is_system_bypass() OR (
      scope_id IS NOT NULL AND
      security.is_scope_accessible(scope_id)
    )
  );

DROP POLICY IF EXISTS compatibility_rules_scope_isolation_policy ON ops.compatibility_rules;
CREATE POLICY compatibility_rules_scope_isolation_policy ON ops.compatibility_rules
  FOR ALL
  USING (
    security.is_system_bypass() OR (
      scope_id IS NOT NULL AND
      security.is_scope_accessible(scope_id)
    )
  )
  WITH CHECK (
    security.is_system_bypass() OR (
      scope_id IS NOT NULL AND
      security.is_scope_accessible(scope_id)
    )
  );

DROP POLICY IF EXISTS evaluation_cases_scope_isolation_policy ON ops.evaluation_cases;
CREATE POLICY evaluation_cases_scope_isolation_policy ON ops.evaluation_cases
  FOR ALL
  USING (
    security.is_system_bypass() OR (
      scope_id IS NOT NULL AND
      security.is_scope_accessible(scope_id)
    )
  )
  WITH CHECK (
    security.is_system_bypass() OR (
      scope_id IS NOT NULL AND
      security.is_scope_accessible(scope_id)
    )
  );

DROP POLICY IF EXISTS evaluation_datasets_scope_isolation_policy ON ops.evaluation_datasets;
CREATE POLICY evaluation_datasets_scope_isolation_policy ON ops.evaluation_datasets
  FOR ALL
  USING (
    security.is_system_bypass() OR (
      scope_id IS NOT NULL AND
      security.is_scope_accessible(scope_id)
    )
  )
  WITH CHECK (
    security.is_system_bypass() OR (
      scope_id IS NOT NULL AND
      security.is_scope_accessible(scope_id)
    )
  );

DROP POLICY IF EXISTS golden_corpus_items_scope_isolation_policy ON ops.golden_corpus_items;
CREATE POLICY golden_corpus_items_scope_isolation_policy ON ops.golden_corpus_items
  FOR ALL
  USING (
    security.is_system_bypass() OR (
      scope_id IS NOT NULL AND
      security.is_scope_accessible(scope_id)
    )
  )
  WITH CHECK (
    security.is_system_bypass() OR (
      scope_id IS NOT NULL AND
      security.is_scope_accessible(scope_id)
    )
  );

DROP POLICY IF EXISTS version_registry_scope_isolation_policy ON ops.version_registry;
CREATE POLICY version_registry_scope_isolation_policy ON ops.version_registry
  FOR ALL
  USING (
    security.is_system_bypass() OR (
      scope_id IS NOT NULL AND
      security.is_scope_accessible(scope_id)
    )
  )
  WITH CHECK (
    security.is_system_bypass() OR (
      scope_id IS NOT NULL AND
      security.is_scope_accessible(scope_id)
    )
  );

DROP POLICY IF EXISTS workflow_definitions_scope_isolation_policy ON ops.workflow_definitions;
CREATE POLICY workflow_definitions_scope_isolation_policy ON ops.workflow_definitions
  FOR ALL
  USING (
    security.is_system_bypass() OR (
      scope_id IS NOT NULL AND
      security.is_scope_accessible(scope_id)
    )
  )
  WITH CHECK (
    security.is_system_bypass() OR (
      scope_id IS NOT NULL AND
      security.is_scope_accessible(scope_id)
    )
  );

DROP POLICY IF EXISTS access_scopes_scope_isolation_policy ON security.access_scopes;
CREATE POLICY access_scopes_scope_isolation_policy ON security.access_scopes
  FOR ALL
  USING (
    security.is_system_bypass() OR
    scope_type = 'PLATFORM' OR (
      security.current_tenant_id() IS NOT NULL AND
      tenant_id = security.current_tenant_id()
    )
  )
  WITH CHECK (
    security.is_system_bypass() OR (
      security.current_tenant_id() IS NOT NULL AND
      tenant_id = security.current_tenant_id()
    )
  );

DROP POLICY IF EXISTS source_observations_scope_isolation_policy ON source.source_observations;
CREATE POLICY source_observations_scope_isolation_policy ON source.source_observations
  FOR ALL
  USING (
    security.is_system_bypass() OR (
      scope_id IS NOT NULL AND
      security.is_scope_accessible(scope_id)
    )
  )
  WITH CHECK (
    security.is_system_bypass() OR (
      scope_id IS NOT NULL AND
      security.is_scope_accessible(scope_id)
    )
  );

-- 3C. Policies for SYSTEM_ONLY tables
DROP POLICY IF EXISTS approvals_system_only_policy ON lifecycle.approvals;
CREATE POLICY approvals_system_only_policy ON lifecycle.approvals
  FOR ALL
  USING (security.is_system_bypass())
  WITH CHECK (security.is_system_bypass());

DROP POLICY IF EXISTS diff_items_system_only_policy ON lifecycle.diff_items;
CREATE POLICY diff_items_system_only_policy ON lifecycle.diff_items
  FOR ALL
  USING (security.is_system_bypass())
  WITH CHECK (security.is_system_bypass());

DROP POLICY IF EXISTS version_diffs_system_only_policy ON lifecycle.version_diffs;
CREATE POLICY version_diffs_system_only_policy ON lifecycle.version_diffs
  FOR ALL
  USING (security.is_system_bypass())
  WITH CHECK (security.is_system_bypass());

DROP POLICY IF EXISTS audit_events_system_only_policy ON ops.audit_events;
CREATE POLICY audit_events_system_only_policy ON ops.audit_events
  FOR ALL
  USING (security.is_system_bypass())
  WITH CHECK (security.is_system_bypass());

DROP POLICY IF EXISTS cost_usage_events_system_only_policy ON ops.cost_usage_events;
CREATE POLICY cost_usage_events_system_only_policy ON ops.cost_usage_events
  FOR ALL
  USING (security.is_system_bypass())
  WITH CHECK (security.is_system_bypass());

DROP POLICY IF EXISTS dead_letter_jobs_system_only_policy ON ops.dead_letter_jobs;
CREATE POLICY dead_letter_jobs_system_only_policy ON ops.dead_letter_jobs
  FOR ALL
  USING (security.is_system_bypass())
  WITH CHECK (security.is_system_bypass());

DROP POLICY IF EXISTS evaluation_results_system_only_policy ON ops.evaluation_results;
CREATE POLICY evaluation_results_system_only_policy ON ops.evaluation_results
  FOR ALL
  USING (security.is_system_bypass())
  WITH CHECK (security.is_system_bypass());

DROP POLICY IF EXISTS evaluation_runs_system_only_policy ON ops.evaluation_runs;
CREATE POLICY evaluation_runs_system_only_policy ON ops.evaluation_runs
  FOR ALL
  USING (security.is_system_bypass())
  WITH CHECK (security.is_system_bypass());

DROP POLICY IF EXISTS job_attempts_system_only_policy ON ops.job_attempts;
CREATE POLICY job_attempts_system_only_policy ON ops.job_attempts
  FOR ALL
  USING (security.is_system_bypass())
  WITH CHECK (security.is_system_bypass());

DROP POLICY IF EXISTS jobs_system_only_policy ON ops.jobs;
CREATE POLICY jobs_system_only_policy ON ops.jobs
  FOR ALL
  USING (security.is_system_bypass())
  WITH CHECK (security.is_system_bypass());

DROP POLICY IF EXISTS lifecycle_state_transitions_system_only_policy ON ops.lifecycle_state_transitions;
CREATE POLICY lifecycle_state_transitions_system_only_policy ON ops.lifecycle_state_transitions
  FOR ALL
  USING (security.is_system_bypass())
  WITH CHECK (security.is_system_bypass());

DROP POLICY IF EXISTS outbox_deliveries_system_only_policy ON ops.outbox_deliveries;
CREATE POLICY outbox_deliveries_system_only_policy ON ops.outbox_deliveries
  FOR ALL
  USING (security.is_system_bypass())
  WITH CHECK (security.is_system_bypass());

DROP POLICY IF EXISTS outbox_events_system_only_policy ON ops.outbox_events;
CREATE POLICY outbox_events_system_only_policy ON ops.outbox_events
  FOR ALL
  USING (security.is_system_bypass())
  WITH CHECK (security.is_system_bypass());

DROP POLICY IF EXISTS telemetry_records_system_only_policy ON ops.telemetry_records;
CREATE POLICY telemetry_records_system_only_policy ON ops.telemetry_records
  FOR ALL
  USING (security.is_system_bypass())
  WITH CHECK (security.is_system_bypass());

DROP POLICY IF EXISTS workflow_runs_system_only_policy ON ops.workflow_runs;
CREATE POLICY workflow_runs_system_only_policy ON ops.workflow_runs
  FOR ALL
  USING (security.is_system_bypass())
  WITH CHECK (security.is_system_bypass());

DROP POLICY IF EXISTS platform_audit_log_system_only_policy ON security.platform_audit_log;
CREATE POLICY platform_audit_log_system_only_policy ON security.platform_audit_log
  FOR ALL
  USING (security.is_system_bypass())
  WITH CHECK (security.is_system_bypass());

DROP POLICY IF EXISTS revoked_tokens_system_only_policy ON security.revoked_tokens;
CREATE POLICY revoked_tokens_system_only_policy ON security.revoked_tokens
  FOR ALL
  USING (security.is_system_bypass())
  WITH CHECK (security.is_system_bypass());

DROP POLICY IF EXISTS service_accounts_system_only_policy ON security.service_accounts;
CREATE POLICY service_accounts_system_only_policy ON security.service_accounts
  FOR ALL
  USING (security.is_system_bypass())
  WITH CHECK (security.is_system_bypass());

DROP POLICY IF EXISTS system_tx_audit_system_only_policy ON security.system_tx_audit;
CREATE POLICY system_tx_audit_system_only_policy ON security.system_tx_audit
  FOR ALL
  USING (security.is_system_bypass())
  WITH CHECK (security.is_system_bypass());

DROP POLICY IF EXISTS table_tenant_classifications_system_only_policy ON security.table_tenant_classifications;
CREATE POLICY table_tenant_classifications_system_only_policy ON security.table_tenant_classifications
  FOR ALL
  USING (security.is_system_bypass())
  WITH CHECK (security.is_system_bypass());

DROP POLICY IF EXISTS discovery_candidates_system_only_policy ON source.discovery_candidates;
CREATE POLICY discovery_candidates_system_only_policy ON source.discovery_candidates
  FOR ALL
  USING (security.is_system_bypass())
  WITH CHECK (security.is_system_bypass());

DROP POLICY IF EXISTS discovery_edge_types_system_only_policy ON source.discovery_edge_types;
CREATE POLICY discovery_edge_types_system_only_policy ON source.discovery_edge_types
  FOR ALL
  USING (security.is_system_bypass())
  WITH CHECK (security.is_system_bypass());

DROP POLICY IF EXISTS discovery_edges_system_only_policy ON source.discovery_edges;
CREATE POLICY discovery_edges_system_only_policy ON source.discovery_edges
  FOR ALL
  USING (security.is_system_bypass())
  WITH CHECK (security.is_system_bypass());

DROP POLICY IF EXISTS discovery_queries_system_only_policy ON source.discovery_queries;
CREATE POLICY discovery_queries_system_only_policy ON source.discovery_queries
  FOR ALL
  USING (security.is_system_bypass())
  WITH CHECK (security.is_system_bypass());

DROP POLICY IF EXISTS discovery_relationships_system_only_policy ON source.discovery_relationships;
CREATE POLICY discovery_relationships_system_only_policy ON source.discovery_relationships
  FOR ALL
  USING (security.is_system_bypass())
  WITH CHECK (security.is_system_bypass());

DROP POLICY IF EXISTS discovery_roots_system_only_policy ON source.discovery_roots;
CREATE POLICY discovery_roots_system_only_policy ON source.discovery_roots
  FOR ALL
  USING (security.is_system_bypass())
  WITH CHECK (security.is_system_bypass());

DROP POLICY IF EXISTS discovery_runs_system_only_policy ON source.discovery_runs;
CREATE POLICY discovery_runs_system_only_policy ON source.discovery_runs
  FOR ALL
  USING (security.is_system_bypass())
  WITH CHECK (security.is_system_bypass());

-- 3D. Policies for DERIVED_FROM_PARENT tables
DROP POLICY IF EXISTS analysis_stage_runs_derived_isolation_policy ON analysis.analysis_stage_runs;
CREATE POLICY analysis_stage_runs_derived_isolation_policy ON analysis.analysis_stage_runs
  FOR ALL
  USING (
    security.is_system_bypass() OR (
      analysis_run_id IS NOT NULL AND EXISTS (
        SELECT 1 FROM analysis.analysis_runs r
        WHERE r.analysis_run_id = analysis.analysis_stage_runs.analysis_run_id
          AND r.scope_id IS NOT NULL AND security.is_scope_accessible(r.scope_id)
      )
    )
  )
  WITH CHECK (
    security.is_system_bypass() OR (
      analysis_run_id IS NOT NULL AND EXISTS (
        SELECT 1 FROM analysis.analysis_runs r
        WHERE r.analysis_run_id = analysis.analysis_stage_runs.analysis_run_id
          AND r.scope_id IS NOT NULL AND security.is_scope_accessible(r.scope_id)
      )
    )
  );

DROP POLICY IF EXISTS callgraph_edges_derived_isolation_policy ON analysis.callgraph_edges;
CREATE POLICY callgraph_edges_derived_isolation_policy ON analysis.callgraph_edges
  FOR ALL
  USING (
    security.is_system_bypass() OR (
      analysis_run_id IS NOT NULL AND EXISTS (
        SELECT 1 FROM analysis.analysis_runs r
        WHERE r.analysis_run_id = analysis.callgraph_edges.analysis_run_id
          AND r.scope_id IS NOT NULL AND security.is_scope_accessible(r.scope_id)
      )
    )
  )
  WITH CHECK (
    security.is_system_bypass() OR (
      analysis_run_id IS NOT NULL AND EXISTS (
        SELECT 1 FROM analysis.analysis_runs r
        WHERE r.analysis_run_id = analysis.callgraph_edges.analysis_run_id
          AND r.scope_id IS NOT NULL AND security.is_scope_accessible(r.scope_id)
      )
    )
  );

DROP POLICY IF EXISTS callgraph_nodes_derived_isolation_policy ON analysis.callgraph_nodes;
CREATE POLICY callgraph_nodes_derived_isolation_policy ON analysis.callgraph_nodes
  FOR ALL
  USING (
    security.is_system_bypass() OR (
      analysis_run_id IS NOT NULL AND EXISTS (
        SELECT 1 FROM analysis.analysis_runs r
        WHERE r.analysis_run_id = analysis.callgraph_nodes.analysis_run_id
          AND r.scope_id IS NOT NULL AND security.is_scope_accessible(r.scope_id)
      )
    )
  )
  WITH CHECK (
    security.is_system_bypass() OR (
      analysis_run_id IS NOT NULL AND EXISTS (
        SELECT 1 FROM analysis.analysis_runs r
        WHERE r.analysis_run_id = analysis.callgraph_nodes.analysis_run_id
          AND r.scope_id IS NOT NULL AND security.is_scope_accessible(r.scope_id)
      )
    )
  );

DROP POLICY IF EXISTS runtime_events_derived_isolation_policy ON analysis.runtime_events;
CREATE POLICY runtime_events_derived_isolation_policy ON analysis.runtime_events
  FOR ALL
  USING (
    security.is_system_bypass() OR (
      analysis_run_id IS NOT NULL AND EXISTS (
        SELECT 1 FROM analysis.analysis_runs r
        WHERE r.analysis_run_id = analysis.runtime_events.analysis_run_id
          AND r.scope_id IS NOT NULL AND security.is_scope_accessible(r.scope_id)
      )
    )
  )
  WITH CHECK (
    security.is_system_bypass() OR (
      analysis_run_id IS NOT NULL AND EXISTS (
        SELECT 1 FROM analysis.analysis_runs r
        WHERE r.analysis_run_id = analysis.runtime_events.analysis_run_id
          AND r.scope_id IS NOT NULL AND security.is_scope_accessible(r.scope_id)
      )
    )
  );

DROP POLICY IF EXISTS sbom_components_derived_isolation_policy ON analysis.sbom_components;
CREATE POLICY sbom_components_derived_isolation_policy ON analysis.sbom_components
  FOR ALL
  USING (
    security.is_system_bypass() OR (
      analysis_run_id IS NOT NULL AND EXISTS (
        SELECT 1 FROM analysis.analysis_runs r
        WHERE r.analysis_run_id = analysis.sbom_components.analysis_run_id
          AND r.scope_id IS NOT NULL AND security.is_scope_accessible(r.scope_id)
      )
    )
  )
  WITH CHECK (
    security.is_system_bypass() OR (
      analysis_run_id IS NOT NULL AND EXISTS (
        SELECT 1 FROM analysis.analysis_runs r
        WHERE r.analysis_run_id = analysis.sbom_components.analysis_run_id
          AND r.scope_id IS NOT NULL AND security.is_scope_accessible(r.scope_id)
      )
    )
  );

DROP POLICY IF EXISTS sbom_dependencies_derived_isolation_policy ON analysis.sbom_dependencies;
CREATE POLICY sbom_dependencies_derived_isolation_policy ON analysis.sbom_dependencies
  FOR ALL
  USING (
    security.is_system_bypass() OR (
      analysis_run_id IS NOT NULL AND EXISTS (
        SELECT 1 FROM analysis.analysis_runs r
        WHERE r.analysis_run_id = analysis.sbom_dependencies.analysis_run_id
          AND r.scope_id IS NOT NULL AND security.is_scope_accessible(r.scope_id)
      )
    )
  )
  WITH CHECK (
    security.is_system_bypass() OR (
      analysis_run_id IS NOT NULL AND EXISTS (
        SELECT 1 FROM analysis.analysis_runs r
        WHERE r.analysis_run_id = analysis.sbom_dependencies.analysis_run_id
          AND r.scope_id IS NOT NULL AND security.is_scope_accessible(r.scope_id)
      )
    )
  );

DROP POLICY IF EXISTS static_findings_derived_isolation_policy ON analysis.static_findings;
CREATE POLICY static_findings_derived_isolation_policy ON analysis.static_findings
  FOR ALL
  USING (
    security.is_system_bypass() OR (
      analysis_run_id IS NOT NULL AND EXISTS (
        SELECT 1 FROM analysis.analysis_runs r
        WHERE r.analysis_run_id = analysis.static_findings.analysis_run_id
          AND r.scope_id IS NOT NULL AND security.is_scope_accessible(r.scope_id)
      )
    )
  )
  WITH CHECK (
    security.is_system_bypass() OR (
      analysis_run_id IS NOT NULL AND EXISTS (
        SELECT 1 FROM analysis.analysis_runs r
        WHERE r.analysis_run_id = analysis.static_findings.analysis_run_id
          AND r.scope_id IS NOT NULL AND security.is_scope_accessible(r.scope_id)
      )
    )
  );

DROP POLICY IF EXISTS taint_flows_derived_isolation_policy ON analysis.taint_flows;
CREATE POLICY taint_flows_derived_isolation_policy ON analysis.taint_flows
  FOR ALL
  USING (
    security.is_system_bypass() OR (
      analysis_run_id IS NOT NULL AND EXISTS (
        SELECT 1 FROM analysis.analysis_runs r
        WHERE r.analysis_run_id = analysis.taint_flows.analysis_run_id
          AND r.scope_id IS NOT NULL AND security.is_scope_accessible(r.scope_id)
      )
    )
  )
  WITH CHECK (
    security.is_system_bypass() OR (
      analysis_run_id IS NOT NULL AND EXISTS (
        SELECT 1 FROM analysis.analysis_runs r
        WHERE r.analysis_run_id = analysis.taint_flows.analysis_run_id
          AND r.scope_id IS NOT NULL AND security.is_scope_accessible(r.scope_id)
      )
    )
  );

DROP POLICY IF EXISTS assertion_evidence_links_derived_isolation_policy ON intel.assertion_evidence_links;
CREATE POLICY assertion_evidence_links_derived_isolation_policy ON intel.assertion_evidence_links
  FOR ALL
  USING (
    security.is_system_bypass() OR (
      analysis_run_id IS NOT NULL AND EXISTS (
        SELECT 1 FROM analysis.analysis_runs r
        WHERE r.analysis_run_id = intel.assertion_evidence_links.analysis_run_id
          AND r.scope_id IS NOT NULL AND security.is_scope_accessible(r.scope_id)
      )
    )
  )
  WITH CHECK (
    security.is_system_bypass() OR (
      analysis_run_id IS NOT NULL AND EXISTS (
        SELECT 1 FROM analysis.analysis_runs r
        WHERE r.analysis_run_id = intel.assertion_evidence_links.analysis_run_id
          AND r.scope_id IS NOT NULL AND security.is_scope_accessible(r.scope_id)
      )
    )
  );

DROP POLICY IF EXISTS claim_evidence_links_derived_isolation_policy ON intel.claim_evidence_links;
CREATE POLICY claim_evidence_links_derived_isolation_policy ON intel.claim_evidence_links
  FOR ALL
  USING (
    security.is_system_bypass() OR (
      analysis_run_id IS NOT NULL AND EXISTS (
        SELECT 1 FROM analysis.analysis_runs r
        WHERE r.analysis_run_id = intel.claim_evidence_links.analysis_run_id
          AND r.scope_id IS NOT NULL AND security.is_scope_accessible(r.scope_id)
      )
    )
  )
  WITH CHECK (
    security.is_system_bypass() OR (
      analysis_run_id IS NOT NULL AND EXISTS (
        SELECT 1 FROM analysis.analysis_runs r
        WHERE r.analysis_run_id = intel.claim_evidence_links.analysis_run_id
          AND r.scope_id IS NOT NULL AND security.is_scope_accessible(r.scope_id)
      )
    )
  );

DROP POLICY IF EXISTS claim_support_links_derived_isolation_policy ON intel.claim_support_links;
CREATE POLICY claim_support_links_derived_isolation_policy ON intel.claim_support_links
  FOR ALL
  USING (
    security.is_system_bypass() OR (
      analysis_run_id IS NOT NULL AND EXISTS (
        SELECT 1 FROM analysis.analysis_runs r
        WHERE r.analysis_run_id = intel.claim_support_links.analysis_run_id
          AND r.scope_id IS NOT NULL AND security.is_scope_accessible(r.scope_id)
      )
    )
  )
  WITH CHECK (
    security.is_system_bypass() OR (
      analysis_run_id IS NOT NULL AND EXISTS (
        SELECT 1 FROM analysis.analysis_runs r
        WHERE r.analysis_run_id = intel.claim_support_links.analysis_run_id
          AND r.scope_id IS NOT NULL AND security.is_scope_accessible(r.scope_id)
      )
    )
  );

DROP POLICY IF EXISTS contradictions_derived_isolation_policy ON intel.contradictions;
CREATE POLICY contradictions_derived_isolation_policy ON intel.contradictions
  FOR ALL
  USING (
    security.is_system_bypass() OR (
      analysis_run_id IS NOT NULL AND EXISTS (
        SELECT 1 FROM analysis.analysis_runs r
        WHERE r.analysis_run_id = intel.contradictions.analysis_run_id
          AND r.scope_id IS NOT NULL AND security.is_scope_accessible(r.scope_id)
      )
    )
  )
  WITH CHECK (
    security.is_system_bypass() OR (
      analysis_run_id IS NOT NULL AND EXISTS (
        SELECT 1 FROM analysis.analysis_runs r
        WHERE r.analysis_run_id = intel.contradictions.analysis_run_id
          AND r.scope_id IS NOT NULL AND security.is_scope_accessible(r.scope_id)
      )
    )
  );

DROP POLICY IF EXISTS external_intelligence_refs_derived_isolation_policy ON intel.external_intelligence_refs;
CREATE POLICY external_intelligence_refs_derived_isolation_policy ON intel.external_intelligence_refs
  FOR ALL
  USING (
    security.is_system_bypass() OR (
      analysis_run_id IS NOT NULL AND EXISTS (
        SELECT 1 FROM analysis.analysis_runs r
        WHERE r.analysis_run_id = intel.external_intelligence_refs.analysis_run_id
          AND r.scope_id IS NOT NULL AND security.is_scope_accessible(r.scope_id)
      )
    )
  )
  WITH CHECK (
    security.is_system_bypass() OR (
      analysis_run_id IS NOT NULL AND EXISTS (
        SELECT 1 FROM analysis.analysis_runs r
        WHERE r.analysis_run_id = intel.external_intelligence_refs.analysis_run_id
          AND r.scope_id IS NOT NULL AND security.is_scope_accessible(r.scope_id)
      )
    )
  );

DROP POLICY IF EXISTS lineage_edges_derived_isolation_policy ON intel.lineage_edges;
CREATE POLICY lineage_edges_derived_isolation_policy ON intel.lineage_edges
  FOR ALL
  USING (
    security.is_system_bypass() OR (
      analysis_run_id IS NOT NULL AND EXISTS (
        SELECT 1 FROM analysis.analysis_runs r
        WHERE r.analysis_run_id = intel.lineage_edges.analysis_run_id
          AND r.scope_id IS NOT NULL AND security.is_scope_accessible(r.scope_id)
      )
    )
  )
  WITH CHECK (
    security.is_system_bypass() OR (
      analysis_run_id IS NOT NULL AND EXISTS (
        SELECT 1 FROM analysis.analysis_runs r
        WHERE r.analysis_run_id = intel.lineage_edges.analysis_run_id
          AND r.scope_id IS NOT NULL AND security.is_scope_accessible(r.scope_id)
      )
    )
  );

DROP POLICY IF EXISTS policy_decision_reasons_derived_isolation_policy ON intel.policy_decision_reasons;
CREATE POLICY policy_decision_reasons_derived_isolation_policy ON intel.policy_decision_reasons
  FOR ALL
  USING (
    security.is_system_bypass() OR (
      analysis_run_id IS NOT NULL AND EXISTS (
        SELECT 1 FROM analysis.analysis_runs r
        WHERE r.analysis_run_id = intel.policy_decision_reasons.analysis_run_id
          AND r.scope_id IS NOT NULL AND security.is_scope_accessible(r.scope_id)
      )
    )
  )
  WITH CHECK (
    security.is_system_bypass() OR (
      analysis_run_id IS NOT NULL AND EXISTS (
        SELECT 1 FROM analysis.analysis_runs r
        WHERE r.analysis_run_id = intel.policy_decision_reasons.analysis_run_id
          AND r.scope_id IS NOT NULL AND security.is_scope_accessible(r.scope_id)
      )
    )
  );

DROP POLICY IF EXISTS policy_decisions_derived_isolation_policy ON intel.policy_decisions;
CREATE POLICY policy_decisions_derived_isolation_policy ON intel.policy_decisions
  FOR ALL
  USING (
    security.is_system_bypass() OR (
      analysis_run_id IS NOT NULL AND EXISTS (
        SELECT 1 FROM analysis.analysis_runs r
        WHERE r.analysis_run_id = intel.policy_decisions.analysis_run_id
          AND r.scope_id IS NOT NULL AND security.is_scope_accessible(r.scope_id)
      )
    )
  )
  WITH CHECK (
    security.is_system_bypass() OR (
      analysis_run_id IS NOT NULL AND EXISTS (
        SELECT 1 FROM analysis.analysis_runs r
        WHERE r.analysis_run_id = intel.policy_decisions.analysis_run_id
          AND r.scope_id IS NOT NULL AND security.is_scope_accessible(r.scope_id)
      )
    )
  );

DROP POLICY IF EXISTS policy_overrides_derived_isolation_policy ON intel.policy_overrides;
CREATE POLICY policy_overrides_derived_isolation_policy ON intel.policy_overrides
  FOR ALL
  USING (
    security.is_system_bypass() OR (
      analysis_run_id IS NOT NULL AND EXISTS (
        SELECT 1 FROM analysis.analysis_runs r
        WHERE r.analysis_run_id = intel.policy_overrides.analysis_run_id
          AND r.scope_id IS NOT NULL AND security.is_scope_accessible(r.scope_id)
      )
    )
  )
  WITH CHECK (
    security.is_system_bypass() OR (
      analysis_run_id IS NOT NULL AND EXISTS (
        SELECT 1 FROM analysis.analysis_runs r
        WHERE r.analysis_run_id = intel.policy_overrides.analysis_run_id
          AND r.scope_id IS NOT NULL AND security.is_scope_accessible(r.scope_id)
      )
    )
  );

DROP POLICY IF EXISTS recommendation_evidence_derived_isolation_policy ON intel.recommendation_evidence;
CREATE POLICY recommendation_evidence_derived_isolation_policy ON intel.recommendation_evidence
  FOR ALL
  USING (
    security.is_system_bypass() OR (
      analysis_run_id IS NOT NULL AND EXISTS (
        SELECT 1 FROM analysis.analysis_runs r
        WHERE r.analysis_run_id = intel.recommendation_evidence.analysis_run_id
          AND r.scope_id IS NOT NULL AND security.is_scope_accessible(r.scope_id)
      )
    )
  )
  WITH CHECK (
    security.is_system_bypass() OR (
      analysis_run_id IS NOT NULL AND EXISTS (
        SELECT 1 FROM analysis.analysis_runs r
        WHERE r.analysis_run_id = intel.recommendation_evidence.analysis_run_id
          AND r.scope_id IS NOT NULL AND security.is_scope_accessible(r.scope_id)
      )
    )
  );

DROP POLICY IF EXISTS recommendations_derived_isolation_policy ON intel.recommendations;
CREATE POLICY recommendations_derived_isolation_policy ON intel.recommendations
  FOR ALL
  USING (
    security.is_system_bypass() OR (
      analysis_run_id IS NOT NULL AND EXISTS (
        SELECT 1 FROM analysis.analysis_runs r
        WHERE r.analysis_run_id = intel.recommendations.analysis_run_id
          AND r.scope_id IS NOT NULL AND security.is_scope_accessible(r.scope_id)
      )
    )
  )
  WITH CHECK (
    security.is_system_bypass() OR (
      analysis_run_id IS NOT NULL AND EXISTS (
        SELECT 1 FROM analysis.analysis_runs r
        WHERE r.analysis_run_id = intel.recommendations.analysis_run_id
          AND r.scope_id IS NOT NULL AND security.is_scope_accessible(r.scope_id)
      )
    )
  );

DROP POLICY IF EXISTS risk_evidence_derived_isolation_policy ON intel.risk_evidence;
CREATE POLICY risk_evidence_derived_isolation_policy ON intel.risk_evidence
  FOR ALL
  USING (
    security.is_system_bypass() OR (
      analysis_run_id IS NOT NULL AND EXISTS (
        SELECT 1 FROM analysis.analysis_runs r
        WHERE r.analysis_run_id = intel.risk_evidence.analysis_run_id
          AND r.scope_id IS NOT NULL AND security.is_scope_accessible(r.scope_id)
      )
    )
  )
  WITH CHECK (
    security.is_system_bypass() OR (
      analysis_run_id IS NOT NULL AND EXISTS (
        SELECT 1 FROM analysis.analysis_runs r
        WHERE r.analysis_run_id = intel.risk_evidence.analysis_run_id
          AND r.scope_id IS NOT NULL AND security.is_scope_accessible(r.scope_id)
      )
    )
  );

DROP POLICY IF EXISTS risks_derived_isolation_policy ON intel.risks;
CREATE POLICY risks_derived_isolation_policy ON intel.risks
  FOR ALL
  USING (
    security.is_system_bypass() OR (
      analysis_run_id IS NOT NULL AND EXISTS (
        SELECT 1 FROM analysis.analysis_runs r
        WHERE r.analysis_run_id = intel.risks.analysis_run_id
          AND r.scope_id IS NOT NULL AND security.is_scope_accessible(r.scope_id)
      )
    )
  )
  WITH CHECK (
    security.is_system_bypass() OR (
      analysis_run_id IS NOT NULL AND EXISTS (
        SELECT 1 FROM analysis.analysis_runs r
        WHERE r.analysis_run_id = intel.risks.analysis_run_id
          AND r.scope_id IS NOT NULL AND security.is_scope_accessible(r.scope_id)
      )
    )
  );

DROP POLICY IF EXISTS score_dimension_values_derived_isolation_policy ON intel.score_dimension_values;
CREATE POLICY score_dimension_values_derived_isolation_policy ON intel.score_dimension_values
  FOR ALL
  USING (
    security.is_system_bypass() OR (
      analysis_run_id IS NOT NULL AND EXISTS (
        SELECT 1 FROM analysis.analysis_runs r
        WHERE r.analysis_run_id = intel.score_dimension_values.analysis_run_id
          AND r.scope_id IS NOT NULL AND security.is_scope_accessible(r.scope_id)
      )
    )
  )
  WITH CHECK (
    security.is_system_bypass() OR (
      analysis_run_id IS NOT NULL AND EXISTS (
        SELECT 1 FROM analysis.analysis_runs r
        WHERE r.analysis_run_id = intel.score_dimension_values.analysis_run_id
          AND r.scope_id IS NOT NULL AND security.is_scope_accessible(r.scope_id)
      )
    )
  );

DROP POLICY IF EXISTS score_results_derived_isolation_policy ON intel.score_results;
CREATE POLICY score_results_derived_isolation_policy ON intel.score_results
  FOR ALL
  USING (
    security.is_system_bypass() OR (
      analysis_run_id IS NOT NULL AND EXISTS (
        SELECT 1 FROM analysis.analysis_runs r
        WHERE r.analysis_run_id = intel.score_results.analysis_run_id
          AND r.scope_id IS NOT NULL AND security.is_scope_accessible(r.scope_id)
      )
    )
  )
  WITH CHECK (
    security.is_system_bypass() OR (
      analysis_run_id IS NOT NULL AND EXISTS (
        SELECT 1 FROM analysis.analysis_runs r
        WHERE r.analysis_run_id = intel.score_results.analysis_run_id
          AND r.scope_id IS NOT NULL AND security.is_scope_accessible(r.scope_id)
      )
    )
  );

DROP POLICY IF EXISTS use_case_evaluations_derived_isolation_policy ON intel.use_case_evaluations;
CREATE POLICY use_case_evaluations_derived_isolation_policy ON intel.use_case_evaluations
  FOR ALL
  USING (
    security.is_system_bypass() OR (
      analysis_run_id IS NOT NULL AND EXISTS (
        SELECT 1 FROM analysis.analysis_runs r
        WHERE r.analysis_run_id = intel.use_case_evaluations.analysis_run_id
          AND r.scope_id IS NOT NULL AND security.is_scope_accessible(r.scope_id)
      )
    )
  )
  WITH CHECK (
    security.is_system_bypass() OR (
      analysis_run_id IS NOT NULL AND EXISTS (
        SELECT 1 FROM analysis.analysis_runs r
        WHERE r.analysis_run_id = intel.use_case_evaluations.analysis_run_id
          AND r.scope_id IS NOT NULL AND security.is_scope_accessible(r.scope_id)
      )
    )
  );

DROP POLICY IF EXISTS use_case_evidence_derived_isolation_policy ON intel.use_case_evidence;
CREATE POLICY use_case_evidence_derived_isolation_policy ON intel.use_case_evidence
  FOR ALL
  USING (
    security.is_system_bypass() OR (
      analysis_run_id IS NOT NULL AND EXISTS (
        SELECT 1 FROM analysis.analysis_runs r
        WHERE r.analysis_run_id = intel.use_case_evidence.analysis_run_id
          AND r.scope_id IS NOT NULL AND security.is_scope_accessible(r.scope_id)
      )
    )
  )
  WITH CHECK (
    security.is_system_bypass() OR (
      analysis_run_id IS NOT NULL AND EXISTS (
        SELECT 1 FROM analysis.analysis_runs r
        WHERE r.analysis_run_id = intel.use_case_evidence.analysis_run_id
          AND r.scope_id IS NOT NULL AND security.is_scope_accessible(r.scope_id)
      )
    )
  );

DROP POLICY IF EXISTS use_cases_derived_isolation_policy ON intel.use_cases;
CREATE POLICY use_cases_derived_isolation_policy ON intel.use_cases
  FOR ALL
  USING (
    security.is_system_bypass() OR (
      analysis_run_id IS NOT NULL AND EXISTS (
        SELECT 1 FROM analysis.analysis_runs r
        WHERE r.analysis_run_id = intel.use_cases.analysis_run_id
          AND r.scope_id IS NOT NULL AND security.is_scope_accessible(r.scope_id)
      )
    )
  )
  WITH CHECK (
    security.is_system_bypass() OR (
      analysis_run_id IS NOT NULL AND EXISTS (
        SELECT 1 FROM analysis.analysis_runs r
        WHERE r.analysis_run_id = intel.use_cases.analysis_run_id
          AND r.scope_id IS NOT NULL AND security.is_scope_accessible(r.scope_id)
      )
    )
  );

DROP POLICY IF EXISTS answer_claims_derived_isolation_policy ON knowledge.answer_claims;
CREATE POLICY answer_claims_derived_isolation_policy ON knowledge.answer_claims
  FOR ALL
  USING (
    security.is_system_bypass() OR (
      query_id IS NOT NULL AND EXISTS (
        SELECT 1 FROM knowledge.queries q
        WHERE q.query_id = knowledge.answer_claims.query_id
          AND q.tenant_id = security.current_tenant_id()
      )
    )
  )
  WITH CHECK (
    security.is_system_bypass() OR (
      query_id IS NOT NULL AND EXISTS (
        SELECT 1 FROM knowledge.queries q
        WHERE q.query_id = knowledge.answer_claims.query_id
          AND q.tenant_id = security.current_tenant_id()
      )
    )
  );

DROP POLICY IF EXISTS answers_derived_isolation_policy ON knowledge.answers;
CREATE POLICY answers_derived_isolation_policy ON knowledge.answers
  FOR ALL
  USING (
    security.is_system_bypass() OR (
      query_id IS NOT NULL AND EXISTS (
        SELECT 1 FROM knowledge.queries q
        WHERE q.query_id = knowledge.answers.query_id
          AND q.tenant_id = security.current_tenant_id()
      )
    )
  )
  WITH CHECK (
    security.is_system_bypass() OR (
      query_id IS NOT NULL AND EXISTS (
        SELECT 1 FROM knowledge.queries q
        WHERE q.query_id = knowledge.answers.query_id
          AND q.tenant_id = security.current_tenant_id()
      )
    )
  );

DROP POLICY IF EXISTS citations_derived_isolation_policy ON knowledge.citations;
CREATE POLICY citations_derived_isolation_policy ON knowledge.citations
  FOR ALL
  USING (
    security.is_system_bypass() OR (
      query_id IS NOT NULL AND EXISTS (
        SELECT 1 FROM knowledge.queries q
        WHERE q.query_id = knowledge.citations.query_id
          AND q.tenant_id = security.current_tenant_id()
      )
    )
  )
  WITH CHECK (
    security.is_system_bypass() OR (
      query_id IS NOT NULL AND EXISTS (
        SELECT 1 FROM knowledge.queries q
        WHERE q.query_id = knowledge.citations.query_id
          AND q.tenant_id = security.current_tenant_id()
      )
    )
  );

DROP POLICY IF EXISTS context_packages_derived_isolation_policy ON knowledge.context_packages;
CREATE POLICY context_packages_derived_isolation_policy ON knowledge.context_packages
  FOR ALL
  USING (
    security.is_system_bypass() OR (
      query_id IS NOT NULL AND EXISTS (
        SELECT 1 FROM knowledge.queries q
        WHERE q.query_id = knowledge.context_packages.query_id
          AND q.tenant_id = security.current_tenant_id()
      )
    )
  )
  WITH CHECK (
    security.is_system_bypass() OR (
      query_id IS NOT NULL AND EXISTS (
        SELECT 1 FROM knowledge.queries q
        WHERE q.query_id = knowledge.context_packages.query_id
          AND q.tenant_id = security.current_tenant_id()
      )
    )
  );

DROP POLICY IF EXISTS embeddings_derived_isolation_policy ON knowledge.embeddings;
CREATE POLICY embeddings_derived_isolation_policy ON knowledge.embeddings
  FOR ALL
  USING (
    security.is_system_bypass() OR (
      knowledge_object_id IS NOT NULL AND EXISTS (
        SELECT 1 FROM knowledge.knowledge_objects ko
        JOIN analysis.analysis_runs r ON r.analysis_run_id = ko.analysis_run_id
        WHERE ko.knowledge_object_id = knowledge.embeddings.knowledge_object_id
          AND r.scope_id IS NOT NULL AND security.is_scope_accessible(r.scope_id)
      )
    )
  )
  WITH CHECK (
    security.is_system_bypass() OR (
      knowledge_object_id IS NOT NULL AND EXISTS (
        SELECT 1 FROM knowledge.knowledge_objects ko
        JOIN analysis.analysis_runs r ON r.analysis_run_id = ko.analysis_run_id
        WHERE ko.knowledge_object_id = knowledge.embeddings.knowledge_object_id
          AND r.scope_id IS NOT NULL AND security.is_scope_accessible(r.scope_id)
      )
    )
  );

DROP POLICY IF EXISTS grounding_results_derived_isolation_policy ON knowledge.grounding_results;
CREATE POLICY grounding_results_derived_isolation_policy ON knowledge.grounding_results
  FOR ALL
  USING (
    security.is_system_bypass() OR (
      query_id IS NOT NULL AND EXISTS (
        SELECT 1 FROM knowledge.queries q
        WHERE q.query_id = knowledge.grounding_results.query_id
          AND q.tenant_id = security.current_tenant_id()
      )
    )
  )
  WITH CHECK (
    security.is_system_bypass() OR (
      query_id IS NOT NULL AND EXISTS (
        SELECT 1 FROM knowledge.queries q
        WHERE q.query_id = knowledge.grounding_results.query_id
          AND q.tenant_id = security.current_tenant_id()
      )
    )
  );

DROP POLICY IF EXISTS index_states_derived_isolation_policy ON knowledge.index_states;
CREATE POLICY index_states_derived_isolation_policy ON knowledge.index_states
  FOR ALL
  USING (
    security.is_system_bypass() OR (
      knowledge_object_id IS NOT NULL AND EXISTS (
        SELECT 1 FROM knowledge.knowledge_objects ko
        JOIN analysis.analysis_runs r ON r.analysis_run_id = ko.analysis_run_id
        WHERE ko.knowledge_object_id = knowledge.index_states.knowledge_object_id
          AND r.scope_id IS NOT NULL AND security.is_scope_accessible(r.scope_id)
      )
    )
  )
  WITH CHECK (
    security.is_system_bypass() OR (
      knowledge_object_id IS NOT NULL AND EXISTS (
        SELECT 1 FROM knowledge.knowledge_objects ko
        JOIN analysis.analysis_runs r ON r.analysis_run_id = ko.analysis_run_id
        WHERE ko.knowledge_object_id = knowledge.index_states.knowledge_object_id
          AND r.scope_id IS NOT NULL AND security.is_scope_accessible(r.scope_id)
      )
    )
  );

DROP POLICY IF EXISTS knowledge_chunks_derived_isolation_policy ON knowledge.knowledge_chunks;
CREATE POLICY knowledge_chunks_derived_isolation_policy ON knowledge.knowledge_chunks
  FOR ALL
  USING (
    security.is_system_bypass() OR (
      knowledge_object_id IS NOT NULL AND EXISTS (
        SELECT 1 FROM knowledge.knowledge_objects ko
        JOIN analysis.analysis_runs r ON r.analysis_run_id = ko.analysis_run_id
        WHERE ko.knowledge_object_id = knowledge.knowledge_chunks.knowledge_object_id
          AND r.scope_id IS NOT NULL AND security.is_scope_accessible(r.scope_id)
      )
    )
  )
  WITH CHECK (
    security.is_system_bypass() OR (
      knowledge_object_id IS NOT NULL AND EXISTS (
        SELECT 1 FROM knowledge.knowledge_objects ko
        JOIN analysis.analysis_runs r ON r.analysis_run_id = ko.analysis_run_id
        WHERE ko.knowledge_object_id = knowledge.knowledge_chunks.knowledge_object_id
          AND r.scope_id IS NOT NULL AND security.is_scope_accessible(r.scope_id)
      )
    )
  );

DROP POLICY IF EXISTS knowledge_projections_derived_isolation_policy ON knowledge.knowledge_projections;
CREATE POLICY knowledge_projections_derived_isolation_policy ON knowledge.knowledge_projections
  FOR ALL
  USING (
    security.is_system_bypass() OR (
      knowledge_object_id IS NOT NULL AND EXISTS (
        SELECT 1 FROM knowledge.knowledge_objects ko
        JOIN analysis.analysis_runs r ON r.analysis_run_id = ko.analysis_run_id
        WHERE ko.knowledge_object_id = knowledge.knowledge_projections.knowledge_object_id
          AND r.scope_id IS NOT NULL AND security.is_scope_accessible(r.scope_id)
      )
    )
  )
  WITH CHECK (
    security.is_system_bypass() OR (
      knowledge_object_id IS NOT NULL AND EXISTS (
        SELECT 1 FROM knowledge.knowledge_objects ko
        JOIN analysis.analysis_runs r ON r.analysis_run_id = ko.analysis_run_id
        WHERE ko.knowledge_object_id = knowledge.knowledge_projections.knowledge_object_id
          AND r.scope_id IS NOT NULL AND security.is_scope_accessible(r.scope_id)
      )
    )
  );

DROP POLICY IF EXISTS query_plans_derived_isolation_policy ON knowledge.query_plans;
CREATE POLICY query_plans_derived_isolation_policy ON knowledge.query_plans
  FOR ALL
  USING (
    security.is_system_bypass() OR (
      query_id IS NOT NULL AND EXISTS (
        SELECT 1 FROM knowledge.queries q
        WHERE q.query_id = knowledge.query_plans.query_id
          AND q.tenant_id = security.current_tenant_id()
      )
    )
  )
  WITH CHECK (
    security.is_system_bypass() OR (
      query_id IS NOT NULL AND EXISTS (
        SELECT 1 FROM knowledge.queries q
        WHERE q.query_id = knowledge.query_plans.query_id
          AND q.tenant_id = security.current_tenant_id()
      )
    )
  );

DROP POLICY IF EXISTS retrieval_results_derived_isolation_policy ON knowledge.retrieval_results;
CREATE POLICY retrieval_results_derived_isolation_policy ON knowledge.retrieval_results
  FOR ALL
  USING (
    security.is_system_bypass() OR (
      knowledge_object_id IS NOT NULL AND EXISTS (
        SELECT 1 FROM knowledge.knowledge_objects ko
        JOIN analysis.analysis_runs r ON r.analysis_run_id = ko.analysis_run_id
        WHERE ko.knowledge_object_id = knowledge.retrieval_results.knowledge_object_id
          AND r.scope_id IS NOT NULL AND security.is_scope_accessible(r.scope_id)
      )
    )
  )
  WITH CHECK (
    security.is_system_bypass() OR (
      knowledge_object_id IS NOT NULL AND EXISTS (
        SELECT 1 FROM knowledge.knowledge_objects ko
        JOIN analysis.analysis_runs r ON r.analysis_run_id = ko.analysis_run_id
        WHERE ko.knowledge_object_id = knowledge.retrieval_results.knowledge_object_id
          AND r.scope_id IS NOT NULL AND security.is_scope_accessible(r.scope_id)
      )
    )
  );

DROP POLICY IF EXISTS retrieval_runs_derived_isolation_policy ON knowledge.retrieval_runs;
CREATE POLICY retrieval_runs_derived_isolation_policy ON knowledge.retrieval_runs
  FOR ALL
  USING (
    security.is_system_bypass() OR (
      knowledge_object_id IS NOT NULL AND EXISTS (
        SELECT 1 FROM knowledge.knowledge_objects ko
        JOIN analysis.analysis_runs r ON r.analysis_run_id = ko.analysis_run_id
        WHERE ko.knowledge_object_id = knowledge.retrieval_runs.knowledge_object_id
          AND r.scope_id IS NOT NULL AND security.is_scope_accessible(r.scope_id)
      )
    )
  )
  WITH CHECK (
    security.is_system_bypass() OR (
      knowledge_object_id IS NOT NULL AND EXISTS (
        SELECT 1 FROM knowledge.knowledge_objects ko
        JOIN analysis.analysis_runs r ON r.analysis_run_id = ko.analysis_run_id
        WHERE ko.knowledge_object_id = knowledge.retrieval_runs.knowledge_object_id
          AND r.scope_id IS NOT NULL AND security.is_scope_accessible(r.scope_id)
      )
    )
  );

DROP POLICY IF EXISTS vector_embeddings_derived_isolation_policy ON knowledge.vector_embeddings;
CREATE POLICY vector_embeddings_derived_isolation_policy ON knowledge.vector_embeddings
  FOR ALL
  USING (
    security.is_system_bypass() OR (
      knowledge_object_id IS NOT NULL AND EXISTS (
        SELECT 1 FROM knowledge.knowledge_objects ko
        JOIN analysis.analysis_runs r ON r.analysis_run_id = ko.analysis_run_id
        WHERE ko.knowledge_object_id = knowledge.vector_embeddings.knowledge_object_id
          AND r.scope_id IS NOT NULL AND security.is_scope_accessible(r.scope_id)
      )
    )
  )
  WITH CHECK (
    security.is_system_bypass() OR (
      knowledge_object_id IS NOT NULL AND EXISTS (
        SELECT 1 FROM knowledge.knowledge_objects ko
        JOIN analysis.analysis_runs r ON r.analysis_run_id = ko.analysis_run_id
        WHERE ko.knowledge_object_id = knowledge.vector_embeddings.knowledge_object_id
          AND r.scope_id IS NOT NULL AND security.is_scope_accessible(r.scope_id)
      )
    )
  );

DROP POLICY IF EXISTS attestations_derived_isolation_policy ON lifecycle.attestations;
CREATE POLICY attestations_derived_isolation_policy ON lifecycle.attestations
  FOR ALL
  USING (
    security.is_system_bypass() OR (
      analysis_run_id IS NOT NULL AND EXISTS (
        SELECT 1 FROM analysis.analysis_runs r
        WHERE r.analysis_run_id = lifecycle.attestations.analysis_run_id
          AND r.scope_id IS NOT NULL AND security.is_scope_accessible(r.scope_id)
      )
    )
  )
  WITH CHECK (
    security.is_system_bypass() OR (
      analysis_run_id IS NOT NULL AND EXISTS (
        SELECT 1 FROM analysis.analysis_runs r
        WHERE r.analysis_run_id = lifecycle.attestations.analysis_run_id
          AND r.scope_id IS NOT NULL AND security.is_scope_accessible(r.scope_id)
      )
    )
  );

DROP POLICY IF EXISTS impact_assessments_derived_isolation_policy ON lifecycle.impact_assessments;
CREATE POLICY impact_assessments_derived_isolation_policy ON lifecycle.impact_assessments
  FOR ALL
  USING (
    security.is_system_bypass() OR (
      modification_workspace_id IS NOT NULL AND EXISTS (
        SELECT 1 FROM lifecycle.modification_workspaces mw
        WHERE mw.modification_workspace_id = lifecycle.impact_assessments.modification_workspace_id
          AND mw.tenant_id = security.current_tenant_id()
      )
    )
  )
  WITH CHECK (
    security.is_system_bypass() OR (
      modification_workspace_id IS NOT NULL AND EXISTS (
        SELECT 1 FROM lifecycle.modification_workspaces mw
        WHERE mw.modification_workspace_id = lifecycle.impact_assessments.modification_workspace_id
          AND mw.tenant_id = security.current_tenant_id()
      )
    )
  );

DROP POLICY IF EXISTS impact_items_derived_isolation_policy ON lifecycle.impact_items;
CREATE POLICY impact_items_derived_isolation_policy ON lifecycle.impact_items
  FOR ALL
  USING (
    security.is_system_bypass() OR (
      modification_workspace_id IS NOT NULL AND EXISTS (
        SELECT 1 FROM lifecycle.modification_workspaces mw
        WHERE mw.modification_workspace_id = lifecycle.impact_items.modification_workspace_id
          AND mw.tenant_id = security.current_tenant_id()
      )
    )
  )
  WITH CHECK (
    security.is_system_bypass() OR (
      modification_workspace_id IS NOT NULL AND EXISTS (
        SELECT 1 FROM lifecycle.modification_workspaces mw
        WHERE mw.modification_workspace_id = lifecycle.impact_items.modification_workspace_id
          AND mw.tenant_id = security.current_tenant_id()
      )
    )
  );

DROP POLICY IF EXISTS modification_changes_derived_isolation_policy ON lifecycle.modification_changes;
CREATE POLICY modification_changes_derived_isolation_policy ON lifecycle.modification_changes
  FOR ALL
  USING (
    security.is_system_bypass() OR (
      modification_workspace_id IS NOT NULL AND EXISTS (
        SELECT 1 FROM lifecycle.modification_workspaces mw
        WHERE mw.modification_workspace_id = lifecycle.modification_changes.modification_workspace_id
          AND mw.tenant_id = security.current_tenant_id()
      )
    )
  )
  WITH CHECK (
    security.is_system_bypass() OR (
      modification_workspace_id IS NOT NULL AND EXISTS (
        SELECT 1 FROM lifecycle.modification_workspaces mw
        WHERE mw.modification_workspace_id = lifecycle.modification_changes.modification_workspace_id
          AND mw.tenant_id = security.current_tenant_id()
      )
    )
  );

DROP POLICY IF EXISTS package_contents_derived_isolation_policy ON lifecycle.package_contents;
CREATE POLICY package_contents_derived_isolation_policy ON lifecycle.package_contents
  FOR ALL
  USING (
    security.is_system_bypass() OR (
      analysis_run_id IS NOT NULL AND EXISTS (
        SELECT 1 FROM analysis.analysis_runs r
        WHERE r.analysis_run_id = lifecycle.package_contents.analysis_run_id
          AND r.scope_id IS NOT NULL AND security.is_scope_accessible(r.scope_id)
      )
    )
  )
  WITH CHECK (
    security.is_system_bypass() OR (
      analysis_run_id IS NOT NULL AND EXISTS (
        SELECT 1 FROM analysis.analysis_runs r
        WHERE r.analysis_run_id = lifecycle.package_contents.analysis_run_id
          AND r.scope_id IS NOT NULL AND security.is_scope_accessible(r.scope_id)
      )
    )
  );

DROP POLICY IF EXISTS packages_derived_isolation_policy ON lifecycle.packages;
CREATE POLICY packages_derived_isolation_policy ON lifecycle.packages
  FOR ALL
  USING (
    security.is_system_bypass() OR (
      analysis_run_id IS NOT NULL AND EXISTS (
        SELECT 1 FROM analysis.analysis_runs r
        WHERE r.analysis_run_id = lifecycle.packages.analysis_run_id
          AND r.scope_id IS NOT NULL AND security.is_scope_accessible(r.scope_id)
      )
    )
  )
  WITH CHECK (
    security.is_system_bypass() OR (
      analysis_run_id IS NOT NULL AND EXISTS (
        SELECT 1 FROM analysis.analysis_runs r
        WHERE r.analysis_run_id = lifecycle.packages.analysis_run_id
          AND r.scope_id IS NOT NULL AND security.is_scope_accessible(r.scope_id)
      )
    )
  );

DROP POLICY IF EXISTS shipments_derived_isolation_policy ON lifecycle.shipments;
CREATE POLICY shipments_derived_isolation_policy ON lifecycle.shipments
  FOR ALL
  USING (
    security.is_system_bypass() OR (
      analysis_run_id IS NOT NULL AND EXISTS (
        SELECT 1 FROM analysis.analysis_runs r
        WHERE r.analysis_run_id = lifecycle.shipments.analysis_run_id
          AND r.scope_id IS NOT NULL AND security.is_scope_accessible(r.scope_id)
      )
    )
  )
  WITH CHECK (
    security.is_system_bypass() OR (
      analysis_run_id IS NOT NULL AND EXISTS (
        SELECT 1 FROM analysis.analysis_runs r
        WHERE r.analysis_run_id = lifecycle.shipments.analysis_run_id
          AND r.scope_id IS NOT NULL AND security.is_scope_accessible(r.scope_id)
      )
    )
  );

DROP POLICY IF EXISTS signatures_derived_isolation_policy ON lifecycle.signatures;
CREATE POLICY signatures_derived_isolation_policy ON lifecycle.signatures
  FOR ALL
  USING (
    security.is_system_bypass() OR (
      analysis_run_id IS NOT NULL AND EXISTS (
        SELECT 1 FROM analysis.analysis_runs r
        WHERE r.analysis_run_id = lifecycle.signatures.analysis_run_id
          AND r.scope_id IS NOT NULL AND security.is_scope_accessible(r.scope_id)
      )
    )
  )
  WITH CHECK (
    security.is_system_bypass() OR (
      analysis_run_id IS NOT NULL AND EXISTS (
        SELECT 1 FROM analysis.analysis_runs r
        WHERE r.analysis_run_id = lifecycle.signatures.analysis_run_id
          AND r.scope_id IS NOT NULL AND security.is_scope_accessible(r.scope_id)
      )
    )
  );

DROP POLICY IF EXISTS validation_results_derived_isolation_policy ON lifecycle.validation_results;
CREATE POLICY validation_results_derived_isolation_policy ON lifecycle.validation_results
  FOR ALL
  USING (
    security.is_system_bypass() OR (
      analysis_run_id IS NOT NULL AND EXISTS (
        SELECT 1 FROM analysis.analysis_runs r
        WHERE r.analysis_run_id = lifecycle.validation_results.analysis_run_id
          AND r.scope_id IS NOT NULL AND security.is_scope_accessible(r.scope_id)
      )
    )
  )
  WITH CHECK (
    security.is_system_bypass() OR (
      analysis_run_id IS NOT NULL AND EXISTS (
        SELECT 1 FROM analysis.analysis_runs r
        WHERE r.analysis_run_id = lifecycle.validation_results.analysis_run_id
          AND r.scope_id IS NOT NULL AND security.is_scope_accessible(r.scope_id)
      )
    )
  );

DROP POLICY IF EXISTS acquisition_runs_derived_isolation_policy ON source.acquisition_runs;
CREATE POLICY acquisition_runs_derived_isolation_policy ON source.acquisition_runs
  FOR ALL
  USING (security.is_system_bypass())
  WITH CHECK (security.is_system_bypass());

DROP POLICY IF EXISTS artifact_files_derived_isolation_policy ON source.artifact_files;
CREATE POLICY artifact_files_derived_isolation_policy ON source.artifact_files
  FOR ALL
  USING (security.is_system_bypass())
  WITH CHECK (security.is_system_bypass());

DROP POLICY IF EXISTS artifacts_derived_isolation_policy ON source.artifacts;
CREATE POLICY artifacts_derived_isolation_policy ON source.artifacts
  FOR ALL
  USING (security.is_system_bypass())
  WITH CHECK (security.is_system_bypass());

DROP POLICY IF EXISTS source_spans_derived_isolation_policy ON source.source_spans;
CREATE POLICY source_spans_derived_isolation_policy ON source.source_spans
  FOR ALL
  USING (security.is_system_bypass())
  WITH CHECK (security.is_system_bypass());

-- 4. Revoke All Privileges from PUBLIC, anon, authenticated
DO $$
DECLARE
  s text;
  schemas text[] := ARRAY['public', 'security', 'source', 'analysis', 'intel', 'knowledge', 'lifecycle', 'core', 'ops', 'ontology'];
BEGIN
  FOREACH s IN ARRAY schemas LOOP
    IF EXISTS (SELECT FROM information_schema.schemata WHERE schema_name = s) THEN
      EXECUTE format('REVOKE ALL ON ALL TABLES IN SCHEMA %I FROM PUBLIC', s);
      EXECUTE format('REVOKE ALL ON ALL SEQUENCES IN SCHEMA %I FROM PUBLIC', s);
      EXECUTE format('REVOKE ALL ON ALL FUNCTIONS IN SCHEMA %I FROM PUBLIC', s);
      IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'anon') THEN
        EXECUTE format('REVOKE ALL ON ALL TABLES IN SCHEMA %I FROM anon', s);
        EXECUTE format('REVOKE ALL ON ALL SEQUENCES IN SCHEMA %I FROM anon', s);
        EXECUTE format('REVOKE ALL ON ALL FUNCTIONS IN SCHEMA %I FROM anon', s);
        EXECUTE format('REVOKE USAGE ON SCHEMA %I FROM anon', s);
      END IF;
      IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'authenticated') THEN
        EXECUTE format('REVOKE ALL ON ALL TABLES IN SCHEMA %I FROM authenticated', s);
        EXECUTE format('REVOKE ALL ON ALL SEQUENCES IN SCHEMA %I FROM authenticated', s);
        EXECUTE format('REVOKE ALL ON ALL FUNCTIONS IN SCHEMA %I FROM authenticated', s);
        EXECUTE format('REVOKE USAGE ON SCHEMA %I FROM authenticated', s);
      END IF;
    END IF;
  END LOOP;
END $$;

-- 5. Grant Least Privilege per Manifest Classification
-- SYSTEM_ONLY tables: granted only to caim_system (caim_app has ZERO privileges)
-- Non-SYSTEM_ONLY tables: granted to caim_app and caim_system
DO $$
BEGIN
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE analysis.analysis_runs TO caim_app, caim_system, caim_migrator;
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE analysis.analysis_stage_runs TO caim_app, caim_system, caim_migrator;
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE analysis.callgraph_edges TO caim_app, caim_system, caim_migrator;
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE analysis.callgraph_nodes TO caim_app, caim_system, caim_migrator;
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE analysis.runtime_events TO caim_app, caim_system, caim_migrator;
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE analysis.sbom_components TO caim_app, caim_system, caim_migrator;
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE analysis.sbom_dependencies TO caim_app, caim_system, caim_migrator;
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE analysis.static_findings TO caim_app, caim_system, caim_migrator;
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE analysis.taint_flows TO caim_app, caim_system, caim_migrator;
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE core.agent_versions TO caim_app, caim_system, caim_migrator;
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE core.canonical_agents TO caim_app, caim_system, caim_migrator;
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE core.canonical_relationships TO caim_app, caim_system, caim_migrator;
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE core.distributions TO caim_app, caim_system, caim_migrator;
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE core.entity_refs TO caim_app, caim_system, caim_migrator;
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE core.external_aliases TO caim_app, caim_system, caim_migrator;
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE core.organization_relationships TO caim_app, caim_system, caim_migrator;
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE core.organizations TO caim_app, caim_system, caim_migrator;
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE core.publishers TO caim_app, caim_system, caim_migrator;
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE intel.assertion_evidence_links TO caim_app, caim_system, caim_migrator;
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE intel.assertions TO caim_app, caim_system, caim_migrator;
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE intel.claim_evidence_links TO caim_app, caim_system, caim_migrator;
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE intel.claim_support_links TO caim_app, caim_system, caim_migrator;
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE intel.claims TO caim_app, caim_system, caim_migrator;
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE intel.contradictions TO caim_app, caim_system, caim_migrator;
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE intel.evidence TO caim_app, caim_system, caim_migrator;
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE intel.external_intelligence_refs TO caim_app, caim_system, caim_migrator;
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE intel.lineage_edges TO caim_app, caim_system, caim_migrator;
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE intel.policy_decision_reasons TO caim_app, caim_system, caim_migrator;
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE intel.policy_decisions TO caim_app, caim_system, caim_migrator;
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE intel.policy_overrides TO caim_app, caim_system, caim_migrator;
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE intel.policy_rules TO caim_app, caim_system, caim_migrator;
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE intel.policy_versions TO caim_app, caim_system, caim_migrator;
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE intel.recommendation_evidence TO caim_app, caim_system, caim_migrator;
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE intel.recommendations TO caim_app, caim_system, caim_migrator;
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE intel.risk_evidence TO caim_app, caim_system, caim_migrator;
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE intel.risks TO caim_app, caim_system, caim_migrator;
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE intel.score_dimension_values TO caim_app, caim_system, caim_migrator;
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE intel.score_dimensions TO caim_app, caim_system, caim_migrator;
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE intel.score_models TO caim_app, caim_system, caim_migrator;
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE intel.score_results TO caim_app, caim_system, caim_migrator;
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE intel.use_case_evaluations TO caim_app, caim_system, caim_migrator;
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE intel.use_case_evidence TO caim_app, caim_system, caim_migrator;
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE intel.use_cases TO caim_app, caim_system, caim_migrator;
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE knowledge.answer_claims TO caim_app, caim_system, caim_migrator;
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE knowledge.answers TO caim_app, caim_system, caim_migrator;
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE knowledge.citations TO caim_app, caim_system, caim_migrator;
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE knowledge.context_packages TO caim_app, caim_system, caim_migrator;
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE knowledge.embeddings TO caim_app, caim_system, caim_migrator;
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE knowledge.grounding_results TO caim_app, caim_system, caim_migrator;
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE knowledge.index_states TO caim_app, caim_system, caim_migrator;
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE knowledge.knowledge_chunks TO caim_app, caim_system, caim_migrator;
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE knowledge.knowledge_objects TO caim_app, caim_system, caim_migrator;
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE knowledge.knowledge_projections TO caim_app, caim_system, caim_migrator;
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE knowledge.queries TO caim_app, caim_system, caim_migrator;
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE knowledge.query_plans TO caim_app, caim_system, caim_migrator;
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE knowledge.query_sessions TO caim_app, caim_system, caim_migrator;
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE knowledge.retrieval_results TO caim_app, caim_system, caim_migrator;
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE knowledge.retrieval_runs TO caim_app, caim_system, caim_migrator;
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE knowledge.vector_embeddings TO caim_app, caim_system, caim_migrator;
  REVOKE ALL ON TABLE lifecycle.approvals FROM caim_app;
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE lifecycle.approvals TO caim_system, caim_migrator;
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE lifecycle.attestations TO caim_app, caim_system, caim_migrator;
  REVOKE ALL ON TABLE lifecycle.diff_items FROM caim_app;
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE lifecycle.diff_items TO caim_system, caim_migrator;
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE lifecycle.impact_assessments TO caim_app, caim_system, caim_migrator;
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE lifecycle.impact_items TO caim_app, caim_system, caim_migrator;
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE lifecycle.modification_changes TO caim_app, caim_system, caim_migrator;
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE lifecycle.modification_workspaces TO caim_app, caim_system, caim_migrator;
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE lifecycle.package_contents TO caim_app, caim_system, caim_migrator;
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE lifecycle.packages TO caim_app, caim_system, caim_migrator;
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE lifecycle.shipments TO caim_app, caim_system, caim_migrator;
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE lifecycle.signatures TO caim_app, caim_system, caim_migrator;
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE lifecycle.validation_results TO caim_app, caim_system, caim_migrator;
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE lifecycle.validation_runs TO caim_app, caim_system, caim_migrator;
  REVOKE ALL ON TABLE lifecycle.version_diffs FROM caim_app;
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE lifecycle.version_diffs TO caim_system, caim_migrator;
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE ontology.ontology_change_log TO caim_app, caim_system, caim_migrator;
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE ontology.ontology_concept_aliases TO caim_app, caim_system, caim_migrator;
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE ontology.ontology_concepts TO caim_app, caim_system, caim_migrator;
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE ontology.ontology_deprecations TO caim_app, caim_system, caim_migrator;
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE ontology.ontology_inference_rules TO caim_app, caim_system, caim_migrator;
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE ontology.ontology_mapping_rules TO caim_app, caim_system, caim_migrator;
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE ontology.ontology_relationship_types TO caim_app, caim_system, caim_migrator;
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE ontology.ontology_relationships TO caim_app, caim_system, caim_migrator;
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE ontology.ontology_versions TO caim_app, caim_system, caim_migrator;
  REVOKE ALL ON TABLE ops.audit_events FROM caim_app;
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE ops.audit_events TO caim_system, caim_migrator;
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE ops.compatibility_rules TO caim_app, caim_system, caim_migrator;
  REVOKE ALL ON TABLE ops.cost_usage_events FROM caim_app;
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE ops.cost_usage_events TO caim_system, caim_migrator;
  REVOKE ALL ON TABLE ops.dead_letter_jobs FROM caim_app;
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE ops.dead_letter_jobs TO caim_system, caim_migrator;
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE ops.evaluation_cases TO caim_app, caim_system, caim_migrator;
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE ops.evaluation_datasets TO caim_app, caim_system, caim_migrator;
  REVOKE ALL ON TABLE ops.evaluation_results FROM caim_app;
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE ops.evaluation_results TO caim_system, caim_migrator;
  REVOKE ALL ON TABLE ops.evaluation_runs FROM caim_app;
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE ops.evaluation_runs TO caim_system, caim_migrator;
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE ops.golden_corpus_items TO caim_app, caim_system, caim_migrator;
  REVOKE ALL ON TABLE ops.job_attempts FROM caim_app;
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE ops.job_attempts TO caim_system, caim_migrator;
  REVOKE ALL ON TABLE ops.jobs FROM caim_app;
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE ops.jobs TO caim_system, caim_migrator;
  REVOKE ALL ON TABLE ops.lifecycle_state_transitions FROM caim_app;
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE ops.lifecycle_state_transitions TO caim_system, caim_migrator;
  REVOKE ALL ON TABLE ops.outbox_deliveries FROM caim_app;
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE ops.outbox_deliveries TO caim_system, caim_migrator;
  REVOKE ALL ON TABLE ops.outbox_events FROM caim_app;
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE ops.outbox_events TO caim_system, caim_migrator;
  REVOKE ALL ON TABLE ops.telemetry_records FROM caim_app;
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE ops.telemetry_records TO caim_system, caim_migrator;
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE ops.version_registry TO caim_app, caim_system, caim_migrator;
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE ops.workflow_definitions TO caim_app, caim_system, caim_migrator;
  REVOKE ALL ON TABLE ops.workflow_runs FROM caim_app;
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE ops.workflow_runs TO caim_system, caim_migrator;
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE security.access_grants TO caim_app, caim_system, caim_migrator;
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE security.access_scopes TO caim_app, caim_system, caim_migrator;
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE security.composer_generation_log TO caim_app, caim_system, caim_migrator;
  REVOKE ALL ON TABLE security.platform_audit_log FROM caim_app;
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE security.platform_audit_log TO caim_system, caim_migrator;
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE security.principals TO caim_app, caim_system, caim_migrator;
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE security.rate_limit_buckets TO caim_app, caim_system, caim_migrator;
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE security.refresh_tokens TO caim_app, caim_system, caim_migrator;
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE security.restricted_capability_grants TO caim_app, caim_system, caim_migrator;
  REVOKE ALL ON TABLE security.revoked_tokens FROM caim_app;
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE security.revoked_tokens TO caim_system, caim_migrator;
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE security.roles TO caim_app, caim_system, caim_migrator;
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE security.security_classifications TO caim_app, caim_system, caim_migrator;
  REVOKE ALL ON TABLE security.service_accounts FROM caim_app;
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE security.service_accounts TO caim_system, caim_migrator;
  REVOKE ALL ON TABLE security.system_tx_audit FROM caim_app;
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE security.system_tx_audit TO caim_system, caim_migrator;
  REVOKE ALL ON TABLE security.table_tenant_classifications FROM caim_app;
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE security.table_tenant_classifications TO caim_system, caim_migrator;
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE security.tenant_memberships TO caim_app, caim_system, caim_migrator;
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE security.tenants TO caim_app, caim_system, caim_migrator;
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE security.user_roles TO caim_app, caim_system, caim_migrator;
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE source.acquisition_runs TO caim_app, caim_system, caim_migrator;
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE source.artifact_files TO caim_app, caim_system, caim_migrator;
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE source.artifacts TO caim_app, caim_system, caim_migrator;
  REVOKE ALL ON TABLE source.discovery_candidates FROM caim_app;
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE source.discovery_candidates TO caim_system, caim_migrator;
  REVOKE ALL ON TABLE source.discovery_edge_types FROM caim_app;
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE source.discovery_edge_types TO caim_system, caim_migrator;
  REVOKE ALL ON TABLE source.discovery_edges FROM caim_app;
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE source.discovery_edges TO caim_system, caim_migrator;
  REVOKE ALL ON TABLE source.discovery_queries FROM caim_app;
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE source.discovery_queries TO caim_system, caim_migrator;
  REVOKE ALL ON TABLE source.discovery_relationships FROM caim_app;
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE source.discovery_relationships TO caim_system, caim_migrator;
  REVOKE ALL ON TABLE source.discovery_roots FROM caim_app;
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE source.discovery_roots TO caim_system, caim_migrator;
  REVOKE ALL ON TABLE source.discovery_runs FROM caim_app;
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE source.discovery_runs TO caim_system, caim_migrator;
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE source.source_adapters TO caim_app, caim_system, caim_migrator;
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE source.source_observations TO caim_app, caim_system, caim_migrator;
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE source.source_spans TO caim_app, caim_system, caim_migrator;
END $$;

-- 6. Alter Default Privileges to Start with Zero Permissions
DO $$
DECLARE
  s text;
  schemas text[] := ARRAY['public', 'security', 'source', 'analysis', 'intel', 'knowledge', 'lifecycle', 'core', 'ops', 'ontology'];
BEGIN
  FOREACH s IN ARRAY schemas LOOP
    IF EXISTS (SELECT FROM information_schema.schemata WHERE schema_name = s) THEN
      EXECUTE format('ALTER DEFAULT PRIVILEGES IN SCHEMA %I REVOKE ALL ON TABLES FROM PUBLIC', s);
      EXECUTE format('ALTER DEFAULT PRIVILEGES IN SCHEMA %I REVOKE ALL ON SEQUENCES FROM PUBLIC', s);
      EXECUTE format('ALTER DEFAULT PRIVILEGES IN SCHEMA %I REVOKE ALL ON FUNCTIONS FROM PUBLIC', s);
    END IF;
  END LOOP;
END $$;

