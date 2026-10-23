-- Migration: 20260823000011_p05_lifecycle_and_validation.sql
-- Purpose: Create ModificationWorkspaces, Change Sets, Approvals, Diffs, ImpactAssessments, ValidationRuns (Locked V2.0.1 Shape with Composite FKs), Packages, Attestations, Signatures, and Shipments
-- Document Reference: Architecture V2.0.1 Document 17, 18, 21, 21B

-- 1. Version Diffs Table (Differential Analysis)
CREATE TABLE IF NOT EXISTS lifecycle.version_diffs (
  version_diff_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  left_entity_ref_id uuid NOT NULL REFERENCES core.entity_refs(entity_ref_id) ON DELETE CASCADE,
  right_entity_ref_id uuid NOT NULL REFERENCES core.entity_refs(entity_ref_id) ON DELETE CASCADE,
  diff_type text NOT NULL,
  engine_version text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_version_diffs_left ON lifecycle.version_diffs(left_entity_ref_id);
CREATE INDEX IF NOT EXISTS idx_version_diffs_right ON lifecycle.version_diffs(right_entity_ref_id);

-- 2. Diff Items Table
CREATE TABLE IF NOT EXISTS lifecycle.diff_items (
  diff_item_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  version_diff_id uuid NOT NULL REFERENCES lifecycle.version_diffs(version_diff_id) ON DELETE CASCADE,
  change_type text NOT NULL CHECK (change_type IN ('ADDED', 'MODIFIED', 'REMOVED', 'UNCHANGED')),
  subject_entity_ref_id uuid NULL REFERENCES core.entity_refs(entity_ref_id) ON DELETE SET NULL,
  before_payload jsonb NULL,
  after_payload jsonb NULL,
  significance text NOT NULL DEFAULT 'MINOR' CHECK (significance IN ('BREAKING', 'MAJOR', 'MINOR', 'INFORMATIONAL')),
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_diff_items_diff ON lifecycle.diff_items(version_diff_id);

-- 3. Modification Workspaces Table
CREATE TABLE IF NOT EXISTS lifecycle.modification_workspaces (
  modification_workspace_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  base_agent_version_id uuid NOT NULL REFERENCES core.agent_versions(agent_version_id) ON DELETE CASCADE,
  created_by text NOT NULL,
  status text NOT NULL DEFAULT 'OPEN' CHECK (status IN ('OPEN', 'APPLIED', 'COMMITTED', 'DISCARDED')),
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_modification_workspaces_version ON lifecycle.modification_workspaces(base_agent_version_id);
CREATE INDEX IF NOT EXISTS idx_modification_workspaces_status ON lifecycle.modification_workspaces(status);

-- 4. Modification Changes Table (Change Sets)
CREATE TABLE IF NOT EXISTS lifecycle.modification_changes (
  modification_change_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  modification_workspace_id uuid NOT NULL REFERENCES lifecycle.modification_workspaces(modification_workspace_id) ON DELETE CASCADE,
  artifact_file_id uuid NULL REFERENCES source.artifact_files(artifact_file_id) ON DELETE SET NULL,
  source_span_id uuid NULL REFERENCES source.source_spans(source_span_id) ON DELETE SET NULL,
  change_type text NOT NULL CHECK (change_type IN ('CREATE', 'UPDATE', 'DELETE', 'PATCH')),
  patch_locator text NOT NULL,
  author_type text NOT NULL DEFAULT 'HUMAN' CHECK (author_type IN ('HUMAN', 'AGENT', 'AUTOMATED_REMEDIATION')),
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_modification_changes_workspace ON lifecycle.modification_changes(modification_workspace_id);

-- 5. Approvals Table
CREATE TABLE IF NOT EXISTS lifecycle.approvals (
  approval_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  approval_type text NOT NULL,
  target_entity_ref_id uuid NOT NULL REFERENCES core.entity_refs(entity_ref_id) ON DELETE CASCADE,
  approver_id text NOT NULL,
  decision text NOT NULL CHECK (decision IN ('APPROVED', 'REJECTED', 'PENDING', 'REVOKED')),
  rationale text NULL,
  decided_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_approvals_target ON lifecycle.approvals(target_entity_ref_id);
CREATE INDEX IF NOT EXISTS idx_approvals_approver ON lifecycle.approvals(approver_id);
CREATE INDEX IF NOT EXISTS idx_approvals_decision ON lifecycle.approvals(decision);

-- 6. Impact Assessments Table (Impact Analysis)
CREATE TABLE IF NOT EXISTS lifecycle.impact_assessments (
  impact_assessment_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  modification_workspace_id uuid NOT NULL REFERENCES lifecycle.modification_workspaces(modification_workspace_id) ON DELETE CASCADE,
  engine_version text NOT NULL,
  scope_state text NOT NULL DEFAULT 'CALCULATED',
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_impact_assessments_workspace ON lifecycle.impact_assessments(modification_workspace_id);

-- 7. Impact Items Table
CREATE TABLE IF NOT EXISTS lifecycle.impact_items (
  impact_item_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  impact_assessment_id uuid NOT NULL REFERENCES lifecycle.impact_assessments(impact_assessment_id) ON DELETE CASCADE,
  target_entity_ref_id uuid NOT NULL REFERENCES core.entity_refs(entity_ref_id) ON DELETE CASCADE,
  impact_type text NOT NULL,
  severity text NOT NULL CHECK (severity IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'NONE')),
  required_action text NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_impact_items_assessment ON lifecycle.impact_items(impact_assessment_id);
CREATE INDEX IF NOT EXISTS idx_impact_items_target ON lifecycle.impact_items(target_entity_ref_id);

-- 8. Validation Runs Table (Locked Document 21B Shape with Composite Foreign Keys)
CREATE TABLE IF NOT EXISTS lifecycle.validation_runs (
  validation_run_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  validation_type text NOT NULL,
  baseline_agent_version_id uuid NOT NULL REFERENCES core.agent_versions(agent_version_id),
  modified_agent_version_id uuid NOT NULL REFERENCES core.agent_versions(agent_version_id),
  baseline_analysis_run_id uuid NOT NULL,
  modified_analysis_run_id uuid NOT NULL,
  validation_analysis_run_id uuid NOT NULL REFERENCES analysis.analysis_runs(analysis_run_id),
  scenario_pack_id uuid NULL,
  validation_plan_version text NOT NULL,
  policy_ruleset_version text NULL,
  scope_id uuid NOT NULL REFERENCES security.access_scopes(scope_id),
  status text NOT NULL DEFAULT 'PENDING' CHECK (status IN ('PENDING', 'RUNNING', 'PASSED', 'FAILED', 'ERROR')),
  started_at timestamptz NOT NULL DEFAULT now(),
  completed_at timestamptz NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  
  -- Mandatory CHECK constraints on validation_type and invariants (Document 21B Section 5)
  CONSTRAINT chk_validation_type CHECK (validation_type IN ('SOURCE_MODIFICATION', 'ANALYTICAL_REEVALUATION', 'POLICY_REEVALUATION', 'SCENARIO_REEVALUATION')),
  CONSTRAINT chk_validation_source_mod CHECK (validation_type != 'SOURCE_MODIFICATION' OR baseline_agent_version_id != modified_agent_version_id),

  -- Mandatory composite foreign keys enforcing ownership integrity
  CONSTRAINT fk_val_baseline_run_version
    FOREIGN KEY (baseline_analysis_run_id, baseline_agent_version_id)
    REFERENCES analysis.analysis_runs(analysis_run_id, agent_version_id)
    ON DELETE RESTRICT,
  CONSTRAINT fk_val_modified_run_version
    FOREIGN KEY (modified_analysis_run_id, modified_agent_version_id)
    REFERENCES analysis.analysis_runs(analysis_run_id, agent_version_id)
    ON DELETE RESTRICT
);

CREATE INDEX IF NOT EXISTS idx_validation_runs_baseline ON lifecycle.validation_runs(baseline_analysis_run_id, baseline_agent_version_id);
CREATE INDEX IF NOT EXISTS idx_validation_runs_modified ON lifecycle.validation_runs(modified_analysis_run_id, modified_agent_version_id);
CREATE INDEX IF NOT EXISTS idx_validation_runs_val_analysis ON lifecycle.validation_runs(validation_analysis_run_id);
CREATE INDEX IF NOT EXISTS idx_validation_runs_scope ON lifecycle.validation_runs(scope_id);
CREATE INDEX IF NOT EXISTS idx_validation_runs_status ON lifecycle.validation_runs(status);

-- 9. Validation Results Table
CREATE TABLE IF NOT EXISTS lifecycle.validation_results (
  validation_result_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  validation_run_id uuid NOT NULL REFERENCES lifecycle.validation_runs(validation_run_id) ON DELETE CASCADE,
  result_type text NOT NULL,
  target_entity_ref_id uuid NULL REFERENCES core.entity_refs(entity_ref_id) ON DELETE SET NULL,
  status text NOT NULL CHECK (status IN ('PASSED', 'FAILED', 'INCONCLUSIVE', 'SKIPPED')),
  before_value jsonb NULL,
  after_value jsonb NULL,
  evidence_id uuid NULL REFERENCES intel.evidence(evidence_id) ON DELETE SET NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_validation_results_run ON lifecycle.validation_results(validation_run_id);
CREATE INDEX IF NOT EXISTS idx_validation_results_status ON lifecycle.validation_results(status);

-- 10. Packages Table (Release Container Metadata)
CREATE TABLE IF NOT EXISTS lifecycle.packages (
  package_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  agent_version_id uuid NOT NULL REFERENCES core.agent_versions(agent_version_id),
  analysis_run_id uuid NOT NULL REFERENCES analysis.analysis_runs(analysis_run_id),
  manifest_hash text NOT NULL,
  storage_locator text NOT NULL,
  status text NOT NULL DEFAULT 'GENERATED' CHECK (status IN ('GENERATED', 'VALIDATED', 'SIGNED', 'SHIPPED', 'DEPRECATED')),
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_packages_agent_version ON lifecycle.packages(agent_version_id);
CREATE INDEX IF NOT EXISTS idx_packages_analysis_run ON lifecycle.packages(analysis_run_id);
CREATE INDEX IF NOT EXISTS idx_packages_manifest ON lifecycle.packages(manifest_hash);

-- 11. Package Contents Table
CREATE TABLE IF NOT EXISTS lifecycle.package_contents (
  package_content_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  package_id uuid NOT NULL REFERENCES lifecycle.packages(package_id) ON DELETE CASCADE,
  entity_ref_id uuid NULL REFERENCES core.entity_refs(entity_ref_id) ON DELETE SET NULL,
  content_type text NOT NULL,
  storage_locator text NULL,
  content_hash text NOT NULL,
  sequence integer NOT NULL DEFAULT 1
);

CREATE INDEX IF NOT EXISTS idx_package_contents_package ON lifecycle.package_contents(package_id);

-- 12. Attestations Table
CREATE TABLE IF NOT EXISTS lifecycle.attestations (
  attestation_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  package_id uuid NOT NULL REFERENCES lifecycle.packages(package_id) ON DELETE CASCADE,
  attestation_type text NOT NULL,
  schema_version text NOT NULL,
  payload_hash text NOT NULL,
  storage_locator text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_attestations_package ON lifecycle.attestations(package_id);

-- 13. Signatures Table
CREATE TABLE IF NOT EXISTS lifecycle.signatures (
  signature_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  target_entity_ref_id uuid NOT NULL REFERENCES core.entity_refs(entity_ref_id) ON DELETE CASCADE,
  signature_scheme text NOT NULL,
  key_version text NOT NULL,
  signature_locator text NOT NULL,
  signed_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_signatures_target ON lifecycle.signatures(target_entity_ref_id);

-- 14. Shipments Table
CREATE TABLE IF NOT EXISTS lifecycle.shipments (
  shipment_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  package_id uuid NOT NULL REFERENCES lifecycle.packages(package_id) ON DELETE CASCADE,
  target_type text NOT NULL,
  target_locator text NOT NULL,
  status text NOT NULL DEFAULT 'PENDING' CHECK (status IN ('PENDING', 'IN_TRANSIT', 'DELIVERED', 'FAILED')),
  shipped_at timestamptz NULL,
  receipt_locator text NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_shipments_package ON lifecycle.shipments(package_id);
CREATE INDEX IF NOT EXISTS idx_shipments_status ON lifecycle.shipments(status);
