-- Migration: 20260823000010_p05_knowledge_and_rag.sql
-- Purpose: Create KnowledgeObjects, Projections, Chunks, Embeddings, Query Plans, Retrieval Runs, Answers, Claims, Citations, and Grounding Results
-- Document Reference: Architecture V2.0.1 Document 17 & Document 18

-- 1. Knowledge Objects Table
CREATE TABLE IF NOT EXISTS knowledge.knowledge_objects (
  knowledge_object_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  entity_ref_id uuid NOT NULL REFERENCES core.entity_refs(entity_ref_id) ON DELETE CASCADE,
  object_type text NOT NULL,
  agent_id uuid NULL REFERENCES core.canonical_agents(agent_id) ON DELETE CASCADE,
  agent_version_id uuid NULL REFERENCES core.agent_versions(agent_version_id) ON DELETE CASCADE,
  analysis_run_id uuid NULL REFERENCES analysis.analysis_runs(analysis_run_id) ON DELETE CASCADE,
  security_classification_id uuid NOT NULL REFERENCES security.security_classifications(security_classification_id),
  projection_version text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT uq_knowledge_object_proj UNIQUE (entity_ref_id, projection_version)
);

CREATE INDEX IF NOT EXISTS idx_knowledge_objects_agent_ver_run ON knowledge.knowledge_objects(agent_id, agent_version_id, analysis_run_id);
CREATE INDEX IF NOT EXISTS idx_knowledge_objects_entity ON knowledge.knowledge_objects(entity_ref_id);

-- 2. Knowledge Projections Table (Derivative, Rebuildable Views)
CREATE TABLE IF NOT EXISTS knowledge.knowledge_projections (
  knowledge_projection_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  knowledge_object_id uuid NOT NULL REFERENCES knowledge.knowledge_objects(knowledge_object_id) ON DELETE CASCADE,
  projection_type text NOT NULL,
  projection_version text NOT NULL,
  payload jsonb NOT NULL DEFAULT '{}',
  stale boolean NOT NULL DEFAULT false,
  indexed_at timestamptz NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_knowledge_projections_object ON knowledge.knowledge_projections(knowledge_object_id);
CREATE INDEX IF NOT EXISTS idx_knowledge_projections_stale ON knowledge.knowledge_projections(stale);

-- 3. Knowledge Chunks Table
CREATE TABLE IF NOT EXISTS knowledge.knowledge_chunks (
  knowledge_chunk_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  knowledge_projection_id uuid NOT NULL REFERENCES knowledge.knowledge_projections(knowledge_projection_id) ON DELETE CASCADE,
  sequence integer NOT NULL,
  content_hash text NOT NULL,
  text_or_locator text NOT NULL,
  token_count integer NULL,
  security_classification_id uuid NOT NULL REFERENCES security.security_classifications(security_classification_id),
  created_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT uq_knowledge_chunk_seq UNIQUE (knowledge_projection_id, sequence)
);

CREATE INDEX IF NOT EXISTS idx_knowledge_chunks_proj ON knowledge.knowledge_chunks(knowledge_projection_id);
CREATE INDEX IF NOT EXISTS idx_knowledge_chunks_hash ON knowledge.knowledge_chunks(content_hash);

-- 4. Embeddings Table (Derivative Vector Representations)
CREATE TABLE IF NOT EXISTS knowledge.embeddings (
  embedding_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  knowledge_chunk_id uuid NULL REFERENCES knowledge.knowledge_chunks(knowledge_chunk_id) ON DELETE CASCADE,
  knowledge_object_id uuid NULL REFERENCES knowledge.knowledge_objects(knowledge_object_id) ON DELETE CASCADE,
  embedding_model_version text NOT NULL,
  dimensions integer NOT NULL,
  vector text NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_embeddings_model_version ON knowledge.embeddings(embedding_model_version);
CREATE INDEX IF NOT EXISTS idx_embeddings_chunk ON knowledge.embeddings(knowledge_chunk_id);
CREATE INDEX IF NOT EXISTS idx_embeddings_object ON knowledge.embeddings(knowledge_object_id);

-- 5. Index States Table
CREATE TABLE IF NOT EXISTS knowledge.index_states (
  index_state_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  knowledge_object_id uuid NOT NULL REFERENCES knowledge.knowledge_objects(knowledge_object_id) ON DELETE CASCADE,
  index_type text NOT NULL,
  index_version text NOT NULL,
  source_version_hash text NOT NULL,
  stale boolean NOT NULL DEFAULT false,
  last_indexed_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT uq_index_state_obj_type_ver UNIQUE (knowledge_object_id, index_type, index_version)
);

CREATE INDEX IF NOT EXISTS idx_index_states_obj ON knowledge.index_states(knowledge_object_id);

-- 6. Query Sessions Table
CREATE TABLE IF NOT EXISTS knowledge.query_sessions (
  query_session_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  principal_id text NOT NULL,
  started_at timestamptz NOT NULL DEFAULT now(),
  ended_at timestamptz NULL,
  access_context_hash text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);

-- 7. Queries Table
CREATE TABLE IF NOT EXISTS knowledge.queries (
  query_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  query_session_id uuid NULL REFERENCES knowledge.query_sessions(query_session_id) ON DELETE SET NULL,
  principal_id text NOT NULL,
  query_text_or_hash text NOT NULL,
  received_at timestamptz NOT NULL DEFAULT now(),
  intent_type text NULL,
  security_classification_id uuid NOT NULL REFERENCES security.security_classifications(security_classification_id),
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_queries_session ON knowledge.queries(query_session_id);
CREATE INDEX IF NOT EXISTS idx_queries_principal ON knowledge.queries(principal_id);

-- 8. Query Plans Table
CREATE TABLE IF NOT EXISTS knowledge.query_plans (
  query_plan_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  query_id uuid NOT NULL REFERENCES knowledge.queries(query_id) ON DELETE CASCADE,
  planner_version text NOT NULL,
  plan_payload jsonb NOT NULL DEFAULT '{}',
  cost_budget numeric(10,4) NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_query_plans_query ON knowledge.query_plans(query_id);

-- 9. Retrieval Runs Table
CREATE TABLE IF NOT EXISTS knowledge.retrieval_runs (
  retrieval_run_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  query_plan_id uuid NOT NULL REFERENCES knowledge.query_plans(query_plan_id) ON DELETE CASCADE,
  retrieval_type text NOT NULL,
  index_version text NULL,
  started_at timestamptz NOT NULL DEFAULT now(),
  completed_at timestamptz NULL,
  status text NOT NULL DEFAULT 'PENDING' CHECK (status IN ('PENDING', 'RUNNING', 'COMPLETED', 'FAILED')),
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_retrieval_runs_plan ON knowledge.retrieval_runs(query_plan_id);

-- 10. Retrieval Results Table
CREATE TABLE IF NOT EXISTS knowledge.retrieval_results (
  retrieval_result_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  retrieval_run_id uuid NOT NULL REFERENCES knowledge.retrieval_runs(retrieval_run_id) ON DELETE CASCADE,
  knowledge_object_id uuid NOT NULL REFERENCES knowledge.knowledge_objects(knowledge_object_id) ON DELETE CASCADE,
  rank integer NOT NULL,
  score numeric(6,4) NULL,
  retrieval_method text NOT NULL,
  authorized boolean NOT NULL DEFAULT true
);

CREATE INDEX IF NOT EXISTS idx_retrieval_results_run ON knowledge.retrieval_results(retrieval_run_id);
CREATE INDEX IF NOT EXISTS idx_retrieval_results_object ON knowledge.retrieval_results(knowledge_object_id);

-- 11. Context Packages Table
CREATE TABLE IF NOT EXISTS knowledge.context_packages (
  context_package_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  query_id uuid NOT NULL REFERENCES knowledge.queries(query_id) ON DELETE CASCADE,
  assembler_version text NOT NULL,
  content_hash text NOT NULL,
  token_count integer NOT NULL DEFAULT 0,
  storage_locator text NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_context_packages_query ON knowledge.context_packages(query_id);

-- 12. Answers Table
CREATE TABLE IF NOT EXISTS knowledge.answers (
  answer_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  query_id uuid NOT NULL REFERENCES knowledge.queries(query_id) ON DELETE CASCADE,
  context_package_id uuid NULL REFERENCES knowledge.context_packages(context_package_id) ON DELETE SET NULL,
  model_version text NOT NULL,
  prompt_version text NOT NULL,
  answer_text_or_locator text NOT NULL,
  status text NOT NULL DEFAULT 'COMPLETED' CHECK (status IN ('PENDING', 'GENERATING', 'COMPLETED', 'FAILED')),
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_answers_query ON knowledge.answers(query_id);

-- 13. Answer Claims Table
CREATE TABLE IF NOT EXISTS knowledge.answer_claims (
  answer_claim_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  answer_id uuid NOT NULL REFERENCES knowledge.answers(answer_id) ON DELETE CASCADE,
  sequence integer NOT NULL,
  claim_text text NOT NULL,
  grounding_state text NOT NULL DEFAULT 'UNGROUNDED' CHECK (grounding_state IN ('GROUNDED', 'PARTIALLY_GROUNDED', 'UNGROUNDED', 'CONTRADICTED')),
  confidence numeric(5,4) NOT NULL DEFAULT 1.0000 CHECK (confidence >= 0 AND confidence <= 1)
);

CREATE INDEX IF NOT EXISTS idx_answer_claims_answer ON knowledge.answer_claims(answer_id);

-- 14. Citations Table
CREATE TABLE IF NOT EXISTS knowledge.citations (
  citation_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  answer_id uuid NOT NULL REFERENCES knowledge.answers(answer_id) ON DELETE CASCADE,
  answer_claim_id uuid NULL REFERENCES knowledge.answer_claims(answer_claim_id) ON DELETE CASCADE,
  target_entity_ref_id uuid NOT NULL REFERENCES core.entity_refs(entity_ref_id) ON DELETE CASCADE,
  citation_type text NOT NULL,
  locator_payload jsonb NOT NULL DEFAULT '{}',
  sequence integer NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_citations_answer ON knowledge.citations(answer_id);
CREATE INDEX IF NOT EXISTS idx_citations_claim ON knowledge.citations(answer_claim_id);
CREATE INDEX IF NOT EXISTS idx_citations_target ON knowledge.citations(target_entity_ref_id);

-- 15. Grounding Results Table
CREATE TABLE IF NOT EXISTS knowledge.grounding_results (
  grounding_result_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  answer_id uuid NOT NULL REFERENCES knowledge.answers(answer_id) ON DELETE CASCADE,
  grounding_ruleset_version text NOT NULL,
  supported_claims integer NOT NULL DEFAULT 0,
  unsupported_claims integer NOT NULL DEFAULT 0,
  contradiction_count integer NOT NULL DEFAULT 0,
  verdict text NOT NULL CHECK (verdict IN ('PASSED', 'FAILED', 'WARNING', 'UNKNOWN')),
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_grounding_results_answer ON knowledge.grounding_results(answer_id);
