# Database Foundation & Supabase Schema Architecture

**V2.0.1 Implementation Baseline — Prompt P03**

This directory houses the authoritative database migrations, extensions, reference seed data, and schema specifications for the Agent Evaluation & Observability Platform.

---

## 1. Physical Schema Layout

Authoritative base tables are strictly isolated into non-public PostgreSQL schemas:

| Schema | Role & Content |
|---|---|
| `security` | Tenant spine, access scopes, roles, user grants, security classifications |
| `core` | Canonical agent identity, agent versions, publishers, ecosystem organizations, entity references, distributions, external aliases, canonical relationships |
| `source` | Source adapters, discovery runs, queries, candidates, source observations, acquisition runs, artifacts, files, source spans |
| `ontology` | CAIM ontology versions, concepts, concept aliases, relationship types, mapping rules, inference rules |
| `analysis` | Analysis runs, stage runs, static analysis, call graph, taint, sbom, sandbox runs, runtime events |
| `intel` | Lineage edges, evidence, assertions, claims, contradictions, risks, score models, policy decisions |
| `knowledge` | RAG projections, knowledge chunks, pgvector embeddings, query plans, grounding |
| `lifecycle` | Diff items, modification workspaces, validation runs, packages, attestations, shipments |
| `ops` | Workflows, job queues, domain events, audit log, cost usage, version registry, compatibility rules |
| `api` | Curated client-facing views and RPC security boundary; zero authoritative base tables |

---

## 2. Core Architectural Invariants Enforced in P03

1. **UUID Internal ID Strategy**:
   - Primary and foreign keys strictly use UUID (`uuid`).
   - Prefixing (such as `AGT_`) is strictly an API/presentation concern.

2. **CanonicalAgent & AgentVersion Separation**:
   - `core.agent_versions` references exactly one `core.canonical_agents(agent_id)` with `ON DELETE CASCADE`.
   - Content fingerprint uniqueness enforced per agent via `UNIQUE(agent_id, content_fingerprint)`.

3. **Tenant & Scope Invariants (Document 21)**:
   - `security.tenants` represents SaaS / customer tenant accounts.
   - `core.organizations` represents discovered open-source/ecosystem publishers and organizations, NOT customer tenant identity.
   - `security.access_scopes` enforces:
     - `scope_type IN ('PLATFORM', 'ORGANIZATION')`
     - When `scope_type = 'PLATFORM'`, `tenant_id` MUST be `NULL`.
     - When `scope_type = 'ORGANIZATION'`, `tenant_id` MUST NOT be `NULL`.
     - Exactly one active `PLATFORM` scope platform-wide (`uq_single_platform_scope`).
     - Exactly one `ORGANIZATION` scope per tenant (`uq_tenant_organization_scope`).

4. **AnalysisRun Foundation & Composite Constraints**:
   - `analysis.analysis_runs` is a scope-bearing root entity with required `scope_id uuid NOT NULL`.
   - `UNIQUE(analysis_run_id, agent_version_id)` is enforced for P05 ValidationRun composite foreign keys.
   - `UNIQUE(analysis_run_id, scope_id)` is enforced for derived inherited-scope verification.

5. **Source-Scoped External Aliases**:
   - `core.external_aliases` enforces source adapter isolation: `UNIQUE(alias_type, alias_value, source_adapter_id)`.

6. **Artifact Integrity & Content Hashing**:
   - `source.artifacts` enforces cryptographic SHA-256 hash formatting on `content_hash`.
   - `source.artifact_files` enforces path uniqueness per artifact: `UNIQUE(artifact_id, path)`.

7. **Version Registry Governance**:
   - `ops.version_registry` enforces uniqueness per artifact entry: `UNIQUE(artifact_type, artifact_key, version)`.
   - Enforces at most one `ACTIVE` version per artifact key via partial unique index `uq_version_registry_single_active`.

8. **Partitioning Guardrail**:
   - Initial physical table partitioning is `ACCEPTED_DEFERRED`. Tables are created unpartitioned in P03, preserving partition-ready composite indexes and time keys.

---

## 3. Migration Sequence

Migrations are executed in exact alphanumeric order:

1. `20260823000001_p03_extensions_and_schemas.sql` — Extensions and non-public schema creation.
2. `20260823000002_p03_security_tenants_and_scopes.sql` — Security classifications, tenants, memberships, roles, access scopes.
3. `20260823000003_p03_core_identity_and_registries.sql` — CanonicalAgent, AgentVersion, publishers, organizations, entity_refs.
4. `20260823000004_p03_source_and_artifacts.sql` — Source adapters, discovery, observations, distributions, artifacts, files, spans, aliases, canonical relationships, lineage edges.
5. `20260823000005_p03_ontology_and_version_registry.sql` — CAIM ontology versions, concepts, relationship types, mapping rules, version registry.
6. `20260823000006_p03_analysis_foundation.sql` — AnalysisRun and AnalysisStageRun with composite unique constraints.

---

## 4. Verification & Testing

Tests are integrated into the automated Vitest test runner and CI pipeline:
- Clean database instantiation and sequential migration execution.
- Foreign key integrity verification.
- Scope invariant checks (`PLATFORM` vs `ORGANIZATION`).
- Composite unique key verification (`analysis_run_id, agent_version_id`, `analysis_run_id, scope_id`).
- Reference seed data ingestion and verification.
