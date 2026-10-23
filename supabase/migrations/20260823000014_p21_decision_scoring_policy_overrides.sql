-- Migration: 20260823000014_p21_decision_scoring_policy_overrides.sql
-- Purpose: Support Risk Evidence Links, Policy Outcomes & Overrides, Recommendation Evidence, and Use Case Evidence
-- Document Reference: Architecture V2.0.1 Document 17, 18, 21

-- 1. Risk Evidence Junction Table
CREATE TABLE IF NOT EXISTS intel.risk_evidence (
  risk_evidence_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  risk_id uuid NOT NULL REFERENCES intel.risks(risk_id) ON DELETE CASCADE,
  evidence_id uuid NOT NULL REFERENCES intel.evidence(evidence_id) ON DELETE CASCADE,
  relevance_score numeric(5,4) NOT NULL DEFAULT 1.0000 CHECK (relevance_score >= 0 AND relevance_score <= 1),
  notes text NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT uq_risk_evidence UNIQUE (risk_id, evidence_id)
);

CREATE INDEX IF NOT EXISTS idx_risk_evidence_risk ON intel.risk_evidence(risk_id);
CREATE INDEX IF NOT EXISTS idx_risk_evidence_evidence ON intel.risk_evidence(evidence_id);

-- 2. Policy Overrides & Audit Trail Table
CREATE TABLE IF NOT EXISTS intel.policy_overrides (
  override_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  analysis_run_id uuid NOT NULL REFERENCES analysis.analysis_runs(analysis_run_id) ON DELETE CASCADE,
  policy_decision_id uuid NULL REFERENCES intel.policy_decisions(decision_id) ON DELETE SET NULL,
  original_outcome text NOT NULL,
  overridden_outcome text NOT NULL CHECK (overridden_outcome IN ('ALLOW', 'ALLOW_WITH_WARNING', 'REQUIRE_REVIEW', 'RESTRICT', 'QUARANTINE', 'DENY_SHIPPING')),
  reason text NOT NULL,
  justification_details text NULL,
  approver_id text NOT NULL,
  approver_role text NOT NULL,
  status text NOT NULL DEFAULT 'ACTIVE' CHECK (status IN ('ACTIVE', 'SUPERSEDED', 'REVOKED')),
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_policy_overrides_run ON intel.policy_overrides(analysis_run_id);
CREATE INDEX IF NOT EXISTS idx_policy_overrides_status ON intel.policy_overrides(status);

-- 3. Recommendation Evidence Junction Table
CREATE TABLE IF NOT EXISTS intel.recommendation_evidence (
  recommendation_evidence_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  recommendation_id uuid NOT NULL REFERENCES intel.recommendations(recommendation_id) ON DELETE CASCADE,
  evidence_id uuid NOT NULL REFERENCES intel.evidence(evidence_id) ON DELETE CASCADE,
  created_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT uq_recommendation_evidence UNIQUE (recommendation_id, evidence_id)
);

CREATE INDEX IF NOT EXISTS idx_rec_evidence_rec ON intel.recommendation_evidence(recommendation_id);
CREATE INDEX IF NOT EXISTS idx_rec_evidence_ev ON intel.recommendation_evidence(evidence_id);

-- 4. Use Case Evidence Junction Table
CREATE TABLE IF NOT EXISTS intel.use_case_evidence (
  use_case_evidence_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  evaluation_id uuid NOT NULL REFERENCES intel.use_case_evaluations(evaluation_id) ON DELETE CASCADE,
  evidence_id uuid NOT NULL REFERENCES intel.evidence(evidence_id) ON DELETE CASCADE,
  created_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT uq_use_case_evidence UNIQUE (evaluation_id, evidence_id)
);

CREATE INDEX IF NOT EXISTS idx_use_case_evidence_eval ON intel.use_case_evidence(evaluation_id);
CREATE INDEX IF NOT EXISTS idx_use_case_evidence_ev ON intel.use_case_evidence(evidence_id);
