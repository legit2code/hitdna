-- Migration: 20260823000001_p03_extensions_and_schemas.sql
-- Purpose: Provision extensions and private non-public authoritative schemas
-- Document Reference: Architecture V2.0.1 Document 17 (Physical Architecture)

-- 1. Enable Required Extensions
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- Note: In managed PostgreSQL / Supabase, pgvector extension is enabled via:
-- CREATE EXTENSION IF NOT EXISTS vector;
-- In environments where pgvector is compiled, vector type is available.

-- 2. Create Authoritative Physical Schemas
CREATE SCHEMA IF NOT EXISTS source;
CREATE SCHEMA IF NOT EXISTS core;
CREATE SCHEMA IF NOT EXISTS ontology;
CREATE SCHEMA IF NOT EXISTS analysis;
CREATE SCHEMA IF NOT EXISTS intel;
CREATE SCHEMA IF NOT EXISTS knowledge;
CREATE SCHEMA IF NOT EXISTS lifecycle;
CREATE SCHEMA IF NOT EXISTS ops;
CREATE SCHEMA IF NOT EXISTS security;
CREATE SCHEMA IF NOT EXISTS api;

-- 3. Document Schema Descriptions
COMMENT ON SCHEMA source IS 'Discovery, acquisition, raw artifact and span metadata';
COMMENT ON SCHEMA core IS 'Canonical identity, CAIM entities, external aliases, distributions and relationships';
COMMENT ON SCHEMA ontology IS 'CAIM ontology versions, concepts, relationship types, mapping and inference rules';
COMMENT ON SCHEMA analysis IS 'Static, CFG, taint, dependency, sandbox, runtime and validation analysis runs';
COMMENT ON SCHEMA intel IS 'Evidence, assertions, claims, contradictions, risk, scores and policy decisions';
COMMENT ON SCHEMA knowledge IS 'RAG projections, chunks, vector embeddings, retrieval and grounded answers';
COMMENT ON SCHEMA lifecycle IS 'Modification workspaces, diffs, approvals, impact, validation, packages and shipments';
COMMENT ON SCHEMA ops IS 'Workflows, worker queues, audit events, evaluations, cost and version registry';
COMMENT ON SCHEMA security IS 'Tenants, memberships, access scopes, roles, user grants and data classifications';
COMMENT ON SCHEMA api IS 'Curated views and RPC interface layer, no direct base tables';
