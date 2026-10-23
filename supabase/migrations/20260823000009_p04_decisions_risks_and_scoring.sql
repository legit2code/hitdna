-- Migration: 20260823000009_p04_decisions_risks_and_scoring.sql
-- Purpose: Create Risks, Score Models, Score Results, Policy Decisions, Recommendations, and Use Cases
-- Document Reference: Architecture V2.0.1 Document 17, 18, 21

-- 1. Risks Table
CREATE TABLE IF NOT EXISTS intel.risks (
  risk_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  analysis_run_id uuid NOT NULL REFERENCES analysis.analysis_runs(analysis_run_id) ON DELETE CASCADE,
  entity_ref_id uuid NULL REFERENCES core.entity_refs(entity_ref_id) ON DELETE CASCADE,
  claim_id uuid NULL REFERENCES intel.claims(claim_id) ON DELETE SET NULL,
  risk_type text NOT NULL,
  title text NOT NULL,
  description text NOT NULL,
  severity text NOT NULL CHECK (severity IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFORMATIONAL')),
  likelihood numeric(5,4) NOT NULL DEFAULT 1.0000 CHECK (likelihood >= 0 AND likelihood <= 1),
  impact numeric(5,4) NOT NULL DEFAULT 1.0000 CHECK (impact >= 0 AND impact <= 1),
  risk_score numeric(5,4) NOT NULL DEFAULT 0.0000,
  remediation_guidance text NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_risks_run ON intel.risks(analysis_run_id);
CREATE INDEX IF NOT EXISTS idx_risks_severity ON intel.risks(severity);
CREATE INDEX IF NOT EXISTS idx_risks_claim ON intel.risks(claim_id);

-- 2. Score Models Table
CREATE TABLE IF NOT EXISTS intel.score_models (
  score_model_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  model_key text NOT NULL,
  version text NOT NULL,
  formula_type text NOT NULL,
  status text NOT NULL DEFAULT 'ACTIVE' CHECK (status IN ('ACTIVE', 'DEPRECATED')),
  created_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT uq_score_model_version UNIQUE (model_key, version)
);

-- 3. Score Dimensions Table
CREATE TABLE IF NOT EXISTS intel.score_dimensions (
  dimension_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  score_model_id uuid NOT NULL REFERENCES intel.score_models(score_model_id) ON DELETE CASCADE,
  dimension_key text NOT NULL,
  display_name text NOT NULL,
  weight numeric(5,4) NOT NULL DEFAULT 1.0000,
  created_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT uq_score_dimension_key UNIQUE (score_model_id, dimension_key)
);

-- 4. Score Results Table
CREATE TABLE IF NOT EXISTS intel.score_results (
  score_result_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  analysis_run_id uuid NOT NULL REFERENCES analysis.analysis_runs(analysis_run_id) ON DELETE CASCADE,
  score_model_id uuid NOT NULL REFERENCES intel.score_models(score_model_id),
  overall_score numeric(6,4) NOT NULL,
  grade text NULL,
  calibration_version text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT uq_score_result_run_model UNIQUE (analysis_run_id, score_model_id)
);

CREATE INDEX IF NOT EXISTS idx_score_results_run ON intel.score_results(analysis_run_id);

-- 5. Score Dimension Values Table
CREATE TABLE IF NOT EXISTS intel.score_dimension_values (
  score_dimension_value_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  score_result_id uuid NOT NULL REFERENCES intel.score_results(score_result_id) ON DELETE CASCADE,
  dimension_id uuid NOT NULL REFERENCES intel.score_dimensions(dimension_id) ON DELETE CASCADE,
  raw_value numeric(6,4) NOT NULL,
  weighted_value numeric(6,4) NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT uq_score_dimension_value UNIQUE (score_result_id, dimension_id)
);

CREATE INDEX IF NOT EXISTS idx_dimension_values_result ON intel.score_dimension_values(score_result_id);

-- 6. Policy Versions Table
CREATE TABLE IF NOT EXISTS intel.policy_versions (
  policy_version_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  policy_key text NOT NULL,
  version text NOT NULL,
  name text NOT NULL,
  description text NULL,
  status text NOT NULL DEFAULT 'ACTIVE' CHECK (status IN ('ACTIVE', 'DEPRECATED', 'DRAFT')),
  created_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT uq_policy_key_version UNIQUE (policy_key, version)
);

-- 7. Policy Rules Table
CREATE TABLE IF NOT EXISTS intel.policy_rules (
  rule_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  policy_version_id uuid NOT NULL REFERENCES intel.policy_versions(policy_version_id) ON DELETE CASCADE,
  rule_key text NOT NULL,
  rule_name text NOT NULL,
  severity text NOT NULL CHECK (severity IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW')),
  condition_expression text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT uq_policy_rule_key UNIQUE (policy_version_id, rule_key)
);

-- 8. Policy Decisions Table
CREATE TABLE IF NOT EXISTS intel.policy_decisions (
  decision_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  analysis_run_id uuid NOT NULL REFERENCES analysis.analysis_runs(analysis_run_id) ON DELETE CASCADE,
  policy_version_id uuid NOT NULL REFERENCES intel.policy_versions(policy_version_id),
  decision text NOT NULL CHECK (decision IN ('PASS', 'FAIL', 'WARN', 'MANUAL_REVIEW')),
  evaluation_summary text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT uq_policy_decision_run UNIQUE (analysis_run_id, policy_version_id)
);

CREATE INDEX IF NOT EXISTS idx_policy_decisions_run ON intel.policy_decisions(analysis_run_id);
CREATE INDEX IF NOT EXISTS idx_policy_decisions_decision ON intel.policy_decisions(decision);

-- 9. Policy Decision Reasons Table
CREATE TABLE IF NOT EXISTS intel.policy_decision_reasons (
  reason_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  decision_id uuid NOT NULL REFERENCES intel.policy_decisions(decision_id) ON DELETE CASCADE,
  rule_id uuid NULL REFERENCES intel.policy_rules(rule_id) ON DELETE SET NULL,
  risk_id uuid NULL REFERENCES intel.risks(risk_id) ON DELETE SET NULL,
  reason_text text NOT NULL,
  is_blocking boolean NOT NULL DEFAULT false,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_policy_reasons_decision ON intel.policy_decision_reasons(decision_id);

-- 10. Recommendations Table
CREATE TABLE IF NOT EXISTS intel.recommendations (
  recommendation_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  analysis_run_id uuid NOT NULL REFERENCES analysis.analysis_runs(analysis_run_id) ON DELETE CASCADE,
  entity_ref_id uuid NULL REFERENCES core.entity_refs(entity_ref_id) ON DELETE CASCADE,
  risk_id uuid NULL REFERENCES intel.risks(risk_id) ON DELETE SET NULL,
  recommendation_type text NOT NULL,
  title text NOT NULL,
  action_steps text NOT NULL,
  priority text NOT NULL CHECK (priority IN ('P0', 'P1', 'P2', 'P3')),
  effort_estimate text NULL CHECK (effort_estimate IN ('LOW', 'MEDIUM', 'HIGH')),
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_recommendations_run ON intel.recommendations(analysis_run_id);
CREATE INDEX IF NOT EXISTS idx_recommendations_priority ON intel.recommendations(priority);

-- 11. Use Cases Table
CREATE TABLE IF NOT EXISTS intel.use_cases (
  use_case_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  use_case_key text UNIQUE NOT NULL,
  title text NOT NULL,
  description text NOT NULL,
  category text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);

-- 12. Use Case Evaluations Table
CREATE TABLE IF NOT EXISTS intel.use_case_evaluations (
  evaluation_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  analysis_run_id uuid NOT NULL REFERENCES analysis.analysis_runs(analysis_run_id) ON DELETE CASCADE,
  use_case_id uuid NOT NULL REFERENCES intel.use_cases(use_case_id) ON DELETE CASCADE,
  suitability text NOT NULL CHECK (suitability IN ('APPROVED', 'CONDITIONALLY_APPROVED', 'DISAPPROVED', 'UNKNOWN')),
  suitability_score numeric(5,4) NOT NULL DEFAULT 1.0000 CHECK (suitability_score >= 0 AND suitability_score <= 1),
  justification text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT uq_use_case_eval_run UNIQUE (analysis_run_id, use_case_id)
);

CREATE INDEX IF NOT EXISTS idx_use_case_eval_run ON intel.use_case_evaluations(analysis_run_id);
