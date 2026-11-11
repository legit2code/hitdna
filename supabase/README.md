# PostgreSQL and Supabase Database Architecture

This directory contains the ordered SQL migrations and seed assets for the CAIM V2.0.1 database. The migrations define the authoritative PostgreSQL schema, tenant/security boundaries, domain tables, constraints, indexes, and row-level security policies.

## Schema domains

| Schema | Responsibility |
|---|---|
| `security` | Tenants, memberships, roles, grants, classifications and access scopes. |
| `core` | Canonical agent identity, versions, organizations, entity references and registries. |
| `source` | Source adapters, discovery, observations, acquisition, artifacts and source spans. |
| `ontology` | CAIM ontology versions, concepts, aliases and mapping/inference rules. |
| `analysis` | Analysis runs/stages, static findings, dependency data, sandbox runs and runtime events. |
| `intel` | Lineage, evidence, assertions, claims, risks, scores and policy decisions. |
| `knowledge` | Retrieval projections, chunks, embeddings and grounding records. |
| `lifecycle` | Diffs, modification workspaces, validation, packages, attestations and shipments. |
| `ops` | Jobs, events, queues, audit, evaluations, cost and version governance. |
| `api` | Curated client-facing views and RPC boundary; not the home for authoritative base tables. |

## Core invariants

- Domain primary and foreign keys use UUIDs; display prefixes belong at the API boundary.
- SaaS tenant identity is stored under `security.tenants`; discovered ecosystem organizations belong under `core.organizations`.
- `security.access_scopes` distinguishes PLATFORM and ORGANIZATION scopes.
- Scope and security classification are independent access-control dimensions.
- Derived records inherit scope from authoritative parent records. Composite foreign keys and controlled write paths prevent scope drift.
- RLS protects user-reachable objects; backend services use explicit service identity and authorized tenant scope.
- Initial table partitioning is deferred until workload evidence and a governed decision justify it.

## Migration workflow

Migrations are stored in `migrations/` and are applied in lexical order. The current repository includes migrations for the foundation, analysis/intelligence, knowledge/lifecycle/operations, auth/RLS, pgvector, truth-state enforcement, discovery graph, audit durability, and subsequent security/reliability hardening.

Use the repository migration runner and safety checks rather than applying ad hoc DDL. Production startup verifies the schema but deliberately does not execute migrations automatically. Apply migrations through a controlled deployment step before rolling out a server version that requires them.

See [migrations README](migrations/README.md) and `docs/architecture/v2/17_Physical_PostgreSQL_Supabase_Data_Architecture.md` for the detailed physical design.
