-- Migration: 20260823000006_p03_analysis_foundation.sql
-- Purpose: Create AnalysisRun and AnalysisStageRun foundation with mandatory scope, composite unique constraints for P05 validation referential integrity and derived scope enforcement
-- Document Reference: Architecture V2.0.1 Document 21, 21B, 17, 18

-- 1. Analysis Runs Table (ROOT_SCOPE_BEARING entity)
CREATE TABLE IF NOT EXISTS analysis.analysis_runs (
  analysis_run_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  agent_version_id uuid NOT NULL REFERENCES core.agent_versions(agent_version_id) ON DELETE CASCADE,
  scope_id uuid NOT NULL REFERENCES security.access_scopes(scope_id),
  pipeline_version text NOT NULL,
  caim_version text NOT NULL,
  ontology_version text NOT NULL,
  trigger_type text NOT NULL CHECK (trigger_type IN ('SCHEDULED', 'MANUAL', 'WEBHOOK', 'EVENT', 'VALIDATION_REPLAY')),
  status text NOT NULL DEFAULT 'PENDING' CHECK (status IN ('PENDING', 'RUNNING', 'COMPLETED', 'PARTIAL', 'FAILED', 'CANCELLED')),
  static_status text NULL,
  dynamic_status text NULL,
  overall_status text NULL,
  execution_summary jsonb NULL,
  started_at timestamptz NOT NULL DEFAULT now(),
  completed_at timestamptz NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  
  -- Mandatory composite unique constraints for downstream integrity:
  -- 1) P05 ValidationRun composite FK: (analysis_run_id, agent_version_id)
  CONSTRAINT uq_analysis_runs_agent_version UNIQUE (analysis_run_id, agent_version_id),
  -- 2) Derived inherited-scope enforcement FK: (analysis_run_id, scope_id)
  CONSTRAINT uq_analysis_runs_scope UNIQUE (analysis_run_id, scope_id)
);

CREATE INDEX IF NOT EXISTS idx_analysis_runs_agent_started ON analysis.analysis_runs(agent_version_id, started_at DESC);
CREATE INDEX IF NOT EXISTS idx_analysis_runs_scope ON analysis.analysis_runs(scope_id);
CREATE INDEX IF NOT EXISTS idx_analysis_runs_status ON analysis.analysis_runs(status);

-- 2. Analysis Stage Runs Table
CREATE TABLE IF NOT EXISTS analysis.analysis_stage_runs (
  stage_run_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  analysis_run_id uuid NOT NULL REFERENCES analysis.analysis_runs(analysis_run_id) ON DELETE CASCADE,
  engine_key text NOT NULL,
  engine_version text NOT NULL,
  ruleset_version text NULL,
  model_version text NULL,
  input_snapshot_hash text NULL,
  status text NOT NULL DEFAULT 'PENDING' CHECK (status IN ('PENDING', 'RUNNING', 'COMPLETED', 'FAILED', 'SKIPPED')),
  started_at timestamptz NOT NULL DEFAULT now(),
  completed_at timestamptz NULL,
  failure_code text NULL,
  metrics jsonb NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT uq_analysis_stage_runs_engine UNIQUE (analysis_run_id, engine_key)
);

CREATE INDEX IF NOT EXISTS idx_analysis_stage_runs_analysis ON analysis.analysis_stage_runs(analysis_run_id);
CREATE INDEX IF NOT EXISTS idx_analysis_stage_runs_status ON analysis.analysis_stage_runs(status);
