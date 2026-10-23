-- Migration: 20260823000021_p04_truth_state_and_epistemic_metadata.sql
-- Description: Mandate truthState and epistemic provenance metadata on evidence, findings, claims, and telemetry records.
-- Constraints: NOT NULL, enum check, no default value permitted.

-- 1. Truth State Enum Type
CREATE TYPE core.truth_state AS ENUM (
  'OBSERVED',
  'STATICALLY_DERIVED',
  'INFERRED',
  'SIMULATED',
  'EXTERNAL',
  'USER_DECLARED',
  'FIXTURE',
  'UNKNOWN'
);

-- 2. intel.evidence table
ALTER TABLE intel.evidence ADD COLUMN truth_state core.truth_state NOT NULL;
ALTER TABLE intel.evidence ADD CONSTRAINT chk_evidence_truth_state CHECK (truth_state IN ('OBSERVED', 'STATICALLY_DERIVED', 'INFERRED', 'SIMULATED', 'EXTERNAL', 'USER_DECLARED', 'FIXTURE', 'UNKNOWN'));
ALTER TABLE intel.evidence ADD COLUMN source_id text NOT NULL;
ALTER TABLE intel.evidence ADD COLUMN analyzer_version text NOT NULL;
ALTER TABLE intel.evidence ADD COLUMN observed_at timestamptz NOT NULL;
ALTER TABLE intel.evidence ADD COLUMN limitations text NULL;

-- 3. analysis.static_findings table
ALTER TABLE analysis.static_findings ADD COLUMN truth_state core.truth_state NOT NULL;
ALTER TABLE analysis.static_findings ADD CONSTRAINT chk_static_findings_truth_state CHECK (truth_state IN ('OBSERVED', 'STATICALLY_DERIVED', 'INFERRED', 'SIMULATED', 'EXTERNAL', 'USER_DECLARED', 'FIXTURE', 'UNKNOWN'));
ALTER TABLE analysis.static_findings ADD COLUMN source_id text NOT NULL;
ALTER TABLE analysis.static_findings ADD COLUMN evidence_id uuid NULL REFERENCES intel.evidence(evidence_id) ON DELETE SET NULL;
ALTER TABLE analysis.static_findings ADD COLUMN analyzer_version text NOT NULL;
ALTER TABLE analysis.static_findings ADD COLUMN observed_at timestamptz NOT NULL;
ALTER TABLE analysis.static_findings ADD COLUMN limitations text NULL;

-- 4. intel.claims table
ALTER TABLE intel.claims ADD COLUMN truth_state core.truth_state NOT NULL;
ALTER TABLE intel.claims ADD CONSTRAINT chk_claims_truth_state CHECK (truth_state IN ('OBSERVED', 'STATICALLY_DERIVED', 'INFERRED', 'SIMULATED', 'EXTERNAL', 'USER_DECLARED', 'FIXTURE', 'UNKNOWN'));
ALTER TABLE intel.claims ADD COLUMN source_id text NOT NULL;
ALTER TABLE intel.claims ADD COLUMN evidence_id uuid NULL REFERENCES intel.evidence(evidence_id) ON DELETE SET NULL;
ALTER TABLE intel.claims ADD COLUMN analyzer_version text NOT NULL;
ALTER TABLE intel.claims ADD COLUMN observed_at timestamptz NOT NULL;
ALTER TABLE intel.claims ADD COLUMN limitations text NULL;

-- 5. knowledge.answer_claims table
ALTER TABLE knowledge.answer_claims ADD COLUMN truth_state core.truth_state NOT NULL;
ALTER TABLE knowledge.answer_claims ADD CONSTRAINT chk_answer_claims_truth_state CHECK (truth_state IN ('OBSERVED', 'STATICALLY_DERIVED', 'INFERRED', 'SIMULATED', 'EXTERNAL', 'USER_DECLARED', 'FIXTURE', 'UNKNOWN'));
ALTER TABLE knowledge.answer_claims ADD COLUMN source_id text NOT NULL;
ALTER TABLE knowledge.answer_claims ADD COLUMN evidence_id uuid NULL REFERENCES intel.evidence(evidence_id) ON DELETE SET NULL;
ALTER TABLE knowledge.answer_claims ADD COLUMN analyzer_version text NOT NULL;
ALTER TABLE knowledge.answer_claims ADD COLUMN observed_at timestamptz NOT NULL;
ALTER TABLE knowledge.answer_claims ADD COLUMN limitations text NULL;

-- 6. analysis.runtime_events table (telemetry / sandbox events)
ALTER TABLE analysis.runtime_events ADD COLUMN truth_state core.truth_state NOT NULL;
ALTER TABLE analysis.runtime_events ADD CONSTRAINT chk_runtime_events_truth_state CHECK (truth_state IN ('OBSERVED', 'STATICALLY_DERIVED', 'INFERRED', 'SIMULATED', 'EXTERNAL', 'USER_DECLARED', 'FIXTURE', 'UNKNOWN'));
ALTER TABLE analysis.runtime_events ADD COLUMN source_id text NOT NULL;
ALTER TABLE analysis.runtime_events ADD COLUMN evidence_id uuid NULL REFERENCES intel.evidence(evidence_id) ON DELETE SET NULL;
ALTER TABLE analysis.runtime_events ADD COLUMN analyzer_version text NOT NULL;
ALTER TABLE analysis.runtime_events ADD COLUMN observed_at timestamptz NOT NULL;
ALTER TABLE analysis.runtime_events ADD COLUMN confidence numeric(5,4) NOT NULL DEFAULT 1.0000 CHECK (confidence >= 0 AND confidence <= 1);
ALTER TABLE analysis.runtime_events ADD COLUMN limitations text NULL;

-- 7. ops.telemetry_records table (system telemetry)
CREATE TABLE IF NOT EXISTS ops.telemetry_records (
  telemetry_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  truth_state core.truth_state NOT NULL,
  source_id text NOT NULL,
  evidence_id uuid NULL REFERENCES intel.evidence(evidence_id) ON DELETE SET NULL,
  analyzer_version text NOT NULL,
  observed_at timestamptz NOT NULL,
  confidence numeric(5,4) NOT NULL CHECK (confidence >= 0 AND confidence <= 1),
  limitations text NULL,
  metric_name text NULL,
  payload jsonb NOT NULL DEFAULT '{}',
  created_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT chk_telemetry_records_truth_state CHECK (truth_state IN ('OBSERVED', 'STATICALLY_DERIVED', 'INFERRED', 'SIMULATED', 'EXTERNAL', 'USER_DECLARED', 'FIXTURE', 'UNKNOWN'))
);

CREATE INDEX IF NOT EXISTS idx_telemetry_records_truth_state ON ops.telemetry_records(truth_state);
CREATE INDEX IF NOT EXISTS idx_telemetry_records_source ON ops.telemetry_records(source_id);
CREATE INDEX IF NOT EXISTS idx_telemetry_records_observed_at ON ops.telemetry_records(observed_at DESC);
