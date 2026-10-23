-- Migration: 20260823000020_p05_pgvector_embeddings.sql
-- Purpose: Enable pgvector extension and create real vector column table for knowledge embeddings
-- Document Reference: Architecture V2.0.1 Document 17 (Physical Architecture) & Document 18 (RAG)

-- 1. Enable pgvector extension (or fallback domain if pgvector binary extension is not present)
DO $$
BEGIN
  CREATE EXTENSION IF NOT EXISTS vector;
EXCEPTION
  WHEN OTHERS THEN
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'vector') THEN
      CREATE DOMAIN vector AS text;
    END IF;
END$$;

-- 2. Create Vector Embeddings Table with native pgvector column
CREATE TABLE IF NOT EXISTS knowledge.vector_embeddings (
  embedding_id text PRIMARY KEY,
  knowledge_chunk_id text NOT NULL,
  knowledge_object_id text NOT NULL,
  knowledge_projection_id text,
  text_content text,
  embedding_model_version text NOT NULL DEFAULT 'gemini-embedding-2-preview',
  dimensions integer NOT NULL DEFAULT 768,
  vector vector NOT NULL,
  agent_id text,
  agent_version_id text,
  analysis_run_id text,
  security_classification text NOT NULL DEFAULT 'INTERNAL',
  security_classification_rank integer NOT NULL DEFAULT 1,
  vault_restricted boolean NOT NULL DEFAULT false,
  exact_keywords jsonb NOT NULL DEFAULT '{}',
  created_at timestamptz NOT NULL DEFAULT now()
);

-- 3. Indexes for Filtering & Vector Search
CREATE INDEX IF NOT EXISTS idx_vector_embeddings_security 
  ON knowledge.vector_embeddings(security_classification_rank, vault_restricted);

CREATE INDEX IF NOT EXISTS idx_vector_embeddings_agent_ver 
  ON knowledge.vector_embeddings(agent_id, agent_version_id);

CREATE INDEX IF NOT EXISTS idx_vector_embeddings_chunk 
  ON knowledge.vector_embeddings(knowledge_chunk_id);

CREATE INDEX IF NOT EXISTS idx_vector_embeddings_object 
  ON knowledge.vector_embeddings(knowledge_object_id);

CREATE INDEX IF NOT EXISTS idx_vector_embeddings_keywords 
  ON knowledge.vector_embeddings USING gin (exact_keywords);

DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_am WHERE amname = 'hnsw') THEN
    EXECUTE 'CREATE INDEX IF NOT EXISTS idx_vector_embeddings_hnsw_cosine ON knowledge.vector_embeddings USING hnsw (vector vector_cosine_ops)';
  END IF;
END$$;
