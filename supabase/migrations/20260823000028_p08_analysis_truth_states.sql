-- Migration: 20260823000028_p08_analysis_truth_states.sql
-- Purpose: Add PARTIAL status to analysis_runs and add explicit static/dynamic/overall status & execution summary columns
-- Document Reference: Architecture V2.0.1 Document 21, P08 Truth States

ALTER TABLE analysis.analysis_runs DROP CONSTRAINT IF EXISTS analysis_runs_status_check;
ALTER TABLE analysis.analysis_runs ADD CONSTRAINT analysis_runs_status_check CHECK (status IN ('PENDING', 'RUNNING', 'COMPLETED', 'PARTIAL', 'FAILED', 'CANCELLED'));

ALTER TABLE analysis.analysis_runs ADD COLUMN IF NOT EXISTS static_status text NULL;
ALTER TABLE analysis.analysis_runs ADD COLUMN IF NOT EXISTS dynamic_status text NULL;
ALTER TABLE analysis.analysis_runs ADD COLUMN IF NOT EXISTS overall_status text NULL;
ALTER TABLE analysis.analysis_runs ADD COLUMN IF NOT EXISTS execution_summary jsonb NULL;
