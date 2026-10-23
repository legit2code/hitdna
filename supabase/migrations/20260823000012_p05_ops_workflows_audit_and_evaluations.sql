-- Migration: 20260823000012_p05_ops_workflows_audit_and_evaluations.sql
-- Purpose: Create WorkflowRuns, Jobs, JobAttempts, DeadLetterJobs, LifecycleStateTransitions, OutboxEvents/Deliveries, AuditEvents, EvaluationDatasets/Cases/Runs/Results, GoldenCorpusItems, and CostUsageEvents
-- Document Reference: Architecture V2.0.1 Document 17, 18, 21

-- 1. Workflow Definitions Table
CREATE TABLE IF NOT EXISTS ops.workflow_definitions (
  workflow_definition_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  workflow_key text NOT NULL,
  version text NOT NULL,
  status text NOT NULL DEFAULT 'ACTIVE' CHECK (status IN ('ACTIVE', 'DEPRECATED', 'DRAFT')),
  definition_payload jsonb NOT NULL DEFAULT '{}',
  created_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT uq_workflow_def_key_ver UNIQUE (workflow_key, version)
);

-- 2. Workflow Runs Table
CREATE TABLE IF NOT EXISTS ops.workflow_runs (
  workflow_run_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  workflow_definition_id uuid NOT NULL REFERENCES ops.workflow_definitions(workflow_definition_id),
  agent_id uuid NULL REFERENCES core.canonical_agents(agent_id) ON DELETE SET NULL,
  agent_version_id uuid NULL REFERENCES core.agent_versions(agent_version_id) ON DELETE SET NULL,
  analysis_run_id uuid NULL REFERENCES analysis.analysis_runs(analysis_run_id) ON DELETE SET NULL,
  status text NOT NULL DEFAULT 'PENDING' CHECK (status IN ('PENDING', 'RUNNING', 'COMPLETED', 'FAILED', 'CANCELLED', 'PAUSED', 'AWAITING_APPROVAL')),
  correlation_id text NOT NULL,
  started_at timestamptz NOT NULL DEFAULT now(),
  completed_at timestamptz NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_workflow_runs_def ON ops.workflow_runs(workflow_definition_id);
CREATE INDEX IF NOT EXISTS idx_workflow_runs_status ON ops.workflow_runs(status);
CREATE INDEX IF NOT EXISTS idx_workflow_runs_correlation ON ops.workflow_runs(correlation_id);

-- 3. Jobs Table (Worker Queue Engine)
CREATE TABLE IF NOT EXISTS ops.jobs (
  job_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  workflow_run_id uuid NULL REFERENCES ops.workflow_runs(workflow_run_id) ON DELETE CASCADE,
  stage_run_id uuid NULL REFERENCES analysis.analysis_stage_runs(stage_run_id) ON DELETE SET NULL,
  queue_key text NOT NULL,
  idempotency_key text UNIQUE NOT NULL,
  priority integer NOT NULL DEFAULT 10,
  status text NOT NULL DEFAULT 'QUEUED' CHECK (status IN ('QUEUED', 'LEASED', 'RUNNING', 'COMPLETED', 'FAILED', 'DEAD_LETTER', 'RETRYING', 'CANCELLED')),
  next_attempt_at timestamptz NOT NULL DEFAULT now(),
  payload jsonb NOT NULL DEFAULT '{}',
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_jobs_status_next_attempt ON ops.jobs(status, next_attempt_at);
CREATE INDEX IF NOT EXISTS idx_jobs_workflow_run ON ops.jobs(workflow_run_id);
CREATE INDEX IF NOT EXISTS idx_jobs_queue_key ON ops.jobs(queue_key);

-- 4. Job Attempts Table
CREATE TABLE IF NOT EXISTS ops.job_attempts (
  job_attempt_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  job_id uuid NOT NULL REFERENCES ops.jobs(job_id) ON DELETE CASCADE,
  attempt_no integer NOT NULL,
  worker_id text NULL,
  leased_at timestamptz NULL,
  lease_expires_at timestamptz NULL,
  completed_at timestamptz NULL,
  failure_class text NULL,
  failure_code text NULL,
  error_message text NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT uq_job_attempt_no UNIQUE (job_id, attempt_no)
);

CREATE INDEX IF NOT EXISTS idx_job_attempts_job ON ops.job_attempts(job_id);

-- 5. Dead Letter Jobs Table
CREATE TABLE IF NOT EXISTS ops.dead_letter_jobs (
  dead_letter_job_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  job_id uuid NOT NULL REFERENCES ops.jobs(job_id) ON DELETE CASCADE,
  final_failure_code text NOT NULL,
  payload_snapshot_locator text NULL,
  dead_lettered_at timestamptz NOT NULL DEFAULT now(),
  resolution_state text NOT NULL DEFAULT 'UNRESOLVED' CHECK (resolution_state IN ('UNRESOLVED', 'REPLAYED', 'DISCARDED', 'RESOLVED_MANUALLY'))
);

CREATE INDEX IF NOT EXISTS idx_dead_letter_jobs_job ON ops.dead_letter_jobs(job_id);
CREATE INDEX IF NOT EXISTS idx_dead_letter_jobs_res ON ops.dead_letter_jobs(resolution_state);

-- 6. Lifecycle State Transitions Table
CREATE TABLE IF NOT EXISTS ops.lifecycle_state_transitions (
  state_transition_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  entity_ref_id uuid NOT NULL REFERENCES core.entity_refs(entity_ref_id) ON DELETE CASCADE,
  from_state text NULL,
  to_state text NOT NULL,
  transition_reason text NOT NULL,
  actor_ref text NULL,
  occurred_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_state_transitions_entity ON ops.lifecycle_state_transitions(entity_ref_id);
CREATE INDEX IF NOT EXISTS idx_state_transitions_time ON ops.lifecycle_state_transitions(occurred_at DESC);

-- 7. Outbox Events Table
CREATE TABLE IF NOT EXISTS ops.outbox_events (
  event_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  event_type text NOT NULL,
  aggregate_entity_ref_id uuid NULL REFERENCES core.entity_refs(entity_ref_id) ON DELETE SET NULL,
  payload jsonb NOT NULL DEFAULT '{}',
  schema_version text NOT NULL DEFAULT '1.0.0',
  correlation_id text NOT NULL,
  causation_id text NULL,
  status text NOT NULL DEFAULT 'PENDING' CHECK (status IN ('PENDING', 'DELIVERED', 'FAILED', 'DEAD_LETTER')),
  occurred_at timestamptz NOT NULL DEFAULT now(),
  published_at timestamptz NULL
);

CREATE INDEX IF NOT EXISTS idx_outbox_events_status ON ops.outbox_events(status);
CREATE INDEX IF NOT EXISTS idx_outbox_events_type ON ops.outbox_events(event_type);
CREATE INDEX IF NOT EXISTS idx_outbox_events_correlation ON ops.outbox_events(correlation_id);

-- 8. Outbox Deliveries Table
CREATE TABLE IF NOT EXISTS ops.outbox_deliveries (
  delivery_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  event_id uuid NOT NULL REFERENCES ops.outbox_events(event_id) ON DELETE CASCADE,
  target_subscriber text NOT NULL,
  status text NOT NULL DEFAULT 'PENDING' CHECK (status IN ('PENDING', 'DELIVERED', 'FAILED')),
  attempt_count integer NOT NULL DEFAULT 0,
  delivered_at timestamptz NULL,
  last_error text NULL
);

CREATE INDEX IF NOT EXISTS idx_outbox_deliveries_event ON ops.outbox_deliveries(event_id);
CREATE INDEX IF NOT EXISTS idx_outbox_deliveries_status ON ops.outbox_deliveries(status);

-- 9. Audit Events Table (Immutable High-Assurance Log)
CREATE TABLE IF NOT EXISTS ops.audit_events (
  audit_event_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  principal_or_service_id text NOT NULL,
  action text NOT NULL,
  target_entity_ref_id uuid NULL REFERENCES core.entity_refs(entity_ref_id) ON DELETE SET NULL,
  outcome text NOT NULL CHECK (outcome IN ('SUCCESS', 'DENIED', 'ERROR')),
  occurred_at timestamptz NOT NULL DEFAULT now(),
  correlation_id text NOT NULL,
  metadata jsonb NOT NULL DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_audit_events_occurred ON ops.audit_events(occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_events_target ON ops.audit_events(target_entity_ref_id);
CREATE INDEX IF NOT EXISTS idx_audit_events_principal ON ops.audit_events(principal_or_service_id);

-- 10. Evaluation Datasets Table (Corpus Versioning)
CREATE TABLE IF NOT EXISTS ops.evaluation_datasets (
  evaluation_dataset_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name text NOT NULL,
  version text NOT NULL,
  scope text NOT NULL DEFAULT 'SYSTEM',
  status text NOT NULL DEFAULT 'ACTIVE' CHECK (status IN ('ACTIVE', 'DEPRECATED', 'DRAFT')),
  created_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT uq_eval_dataset_name_ver UNIQUE (name, version)
);

-- 11. Evaluation Cases Table
CREATE TABLE IF NOT EXISTS ops.evaluation_cases (
  evaluation_case_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  evaluation_dataset_id uuid NOT NULL REFERENCES ops.evaluation_datasets(evaluation_dataset_id) ON DELETE CASCADE,
  input_entity_ref_id uuid NULL REFERENCES core.entity_refs(entity_ref_id) ON DELETE SET NULL,
  expected_payload jsonb NOT NULL DEFAULT '{}',
  tags jsonb NOT NULL DEFAULT '[]',
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_evaluation_cases_dataset ON ops.evaluation_cases(evaluation_dataset_id);

-- 12. Evaluation Runs Table
CREATE TABLE IF NOT EXISTS ops.evaluation_runs (
  evaluation_run_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  evaluation_dataset_id uuid NOT NULL REFERENCES ops.evaluation_datasets(evaluation_dataset_id) ON DELETE CASCADE,
  engine_key text NOT NULL,
  engine_version text NOT NULL,
  ruleset_version text NULL,
  started_at timestamptz NOT NULL DEFAULT now(),
  completed_at timestamptz NULL,
  status text NOT NULL DEFAULT 'PENDING' CHECK (status IN ('PENDING', 'RUNNING', 'COMPLETED', 'FAILED')),
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_evaluation_runs_dataset ON ops.evaluation_runs(evaluation_dataset_id);
CREATE INDEX IF NOT EXISTS idx_evaluation_runs_status ON ops.evaluation_runs(status);

-- 13. Evaluation Results Table
CREATE TABLE IF NOT EXISTS ops.evaluation_results (
  evaluation_result_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  evaluation_run_id uuid NOT NULL REFERENCES ops.evaluation_runs(evaluation_run_id) ON DELETE CASCADE,
  evaluation_case_id uuid NULL REFERENCES ops.evaluation_cases(evaluation_case_id) ON DELETE SET NULL,
  metric_key text NOT NULL,
  metric_value numeric(10,4) NOT NULL,
  pass boolean NOT NULL,
  details jsonb NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_evaluation_results_run ON ops.evaluation_results(evaluation_run_id);

-- 14. Golden Corpus Items Table
CREATE TABLE IF NOT EXISTS ops.golden_corpus_items (
  golden_corpus_item_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  entity_ref_id uuid NULL REFERENCES core.entity_refs(entity_ref_id) ON DELETE SET NULL,
  fixture_locator text NOT NULL,
  corpus_version text NOT NULL,
  truth_status text NOT NULL DEFAULT 'VERIFIED',
  tags jsonb NOT NULL DEFAULT '[]',
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_golden_corpus_version ON ops.golden_corpus_items(corpus_version);

-- 15. Cost Usage Events Table
CREATE TABLE IF NOT EXISTS ops.cost_usage_events (
  cost_usage_event_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  usage_type text NOT NULL,
  quantity numeric(12,4) NOT NULL,
  unit text NOT NULL,
  provider text NOT NULL,
  unit_cost_snapshot numeric(10,6) NULL,
  agent_id uuid NULL REFERENCES core.canonical_agents(agent_id) ON DELETE SET NULL,
  analysis_run_id uuid NULL REFERENCES analysis.analysis_runs(analysis_run_id) ON DELETE SET NULL,
  job_id uuid NULL REFERENCES ops.jobs(job_id) ON DELETE SET NULL,
  query_id uuid NULL REFERENCES knowledge.queries(query_id) ON DELETE SET NULL,
  occurred_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_cost_usage_occurred ON ops.cost_usage_events(occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_cost_usage_agent ON ops.cost_usage_events(agent_id);
CREATE INDEX IF NOT EXISTS idx_cost_usage_run ON ops.cost_usage_events(analysis_run_id);
