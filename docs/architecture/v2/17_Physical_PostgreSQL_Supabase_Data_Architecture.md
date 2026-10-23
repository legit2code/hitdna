# Physical PostgreSQL / Supabase Data Architecture

**Document:** 17  
**Status:** V2.0.1 Controlled Implementation Baseline — physical design locked for P03/P05 migrations subject only to ADR change control  
**Mapped logical tables:** 150

## 1. Schema Layout

The physical baseline uses non-public PostgreSQL schemas for authoritative data and reserves an API-facing schema/views/RPC layer for controlled exposure.

```text
source      discovery, acquisition, raw artifact metadata
core        canonical identity, CAIM objects, cross-domain reference index
ontology    ontology versions/concepts/rules
analysis    static, dependency, sandbox, runtime analysis
intel       lineage, evidence, assertions, claims, risk, score, policy
knowledge   RAG projections, chunks, embeddings, query/answer audit
lifecycle   versions/diffs/modification/validation/package/shipping
ops         workflows, jobs, events, evaluation, audit, cost, version governance
security    tenants, memberships, access scopes, roles, grants, classifications
api         curated views/RPC only; no authoritative base tables
```

This is intentionally different from putting every table in `public`.

## 2. Supabase Exposure Pattern

Recommended pattern:

```text
Browser / Client
    ↓
Supabase Auth
    ↓
api schema views + RPC
    ↓
RLS / security-definer functions only where justified
    ↓
private authoritative schemas
```

Backend workers use dedicated service identities and least-privilege grants to specific schemas/functions.

## 3. Standard Physical Types

Baseline choices:

| Logical type | PostgreSQL baseline |
|---|---|
| Primary/foreign ID | `uuid` |
| Timestamp | `timestamptz` |
| Hash / external immutable digest | `text` (`sha256:<hex>`) or `bytea` after benchmark/ergonomic review |
| Small controlled state | lookup FK or constrained `text`; avoid hardcoding fast-changing ontology as enums |
| Flexible external payload | `jsonb` |
| Large payload | object storage + `storage_locator` + content hash |
| Confidence | `numeric(5,4)` or equivalent 0–1 check |
| Score | `numeric(7,3)` with model-specific bounds |
| Embedding | `vector`/`halfvec` in pgvector, grouped by compatible embedding space |
| Ordered sequence | `integer` |
| Size/counters | `bigint` where unbounded growth is plausible |

Physical UUID presentation prefixes such as `AGT_` are an API/display concern; database referential integrity uses UUID keys. **UUID is RESOLVED for V2.0.1 and is not an open implementation choice.**

## 4. Required Shared Columns

Most durable tables should include as applicable:

```sql
id / domain-specific uuid primary key
created_at timestamptz not null default now()
updated_at timestamptz -- mutable entities only
security_classification_id uuid
scope_id uuid -- required on scope-bearing root/derived families per Document 21
created_by_service text
schema_version text
```

Conclusion-affecting analytical records additionally require:

```sql
analysis_run_id uuid not null
stage_run_id uuid null -- when exact producer stage matters
```

## 5. Core Transaction Boundaries

### Discovery acquisition transaction
Create/update discovery observation metadata and enqueue acquisition using a transactional outbox event; actual remote download is asynchronous.

### Canonicalization transaction
Write canonical entities/relationships + lineage edges atomically for one canonicalization unit where practical.

### Analysis stage transaction
An `analysis_stage_run` transitions independently. Stage output rows and the stage completion state should commit atomically so downstream engines never consume half-completed output as complete.

### Evidence/claim transaction
Evidence is immutable. Assertion/claim creation can be separate transactions but support links must be complete before status becomes `ACTIVE/CONFIRMED`.

### Policy/shipping transaction
Shipping eligibility is calculated from persisted policy/validation state. Package creation never implicitly changes policy state.

## 6. `entity_refs` Physical Role

`core.entity_refs` is the intentionally generic address layer for:
- lineage;
- citations;
- canonical graph edges;
- audit targets;
- extensions;
- cross-domain support links.

It should contain:

```text
entity_ref_id uuid PK
entity_kind text not null
native_id uuid not null
agent_id uuid null
agent_version_id uuid null
analysis_run_id uuid null
security_classification_id uuid not null
created_at timestamptz not null
unique(entity_kind, native_id)
```

The physical database cannot use a conventional FK from `native_id` to many possible tables. Referential correctness is therefore enforced through controlled registration functions/triggers and integrity tests. Typed FKs remain preferred wherever the target type is known.

## 7. Analysis Run / Stage Run Baseline

`analysis.analysis_runs` is immutable except lifecycle/status timestamps. It is `ROOT_SCOPE_BEARING` and includes `scope_id uuid NOT NULL`. P03 MUST create `UNIQUE (analysis_run_id, agent_version_id)` for ValidationRun referential integrity and `UNIQUE (analysis_run_id, scope_id)` for inherited-scope enforcement.

`analysis.analysis_stage_runs` contains the exact engine execution:

```text
stage_run_id uuid PK
analysis_run_id uuid FK
engine_key text
engine_version text
ruleset_version text null
model_version text null
input_snapshot_hash text null
status text
started_at timestamptz
completed_at timestamptz null
failure_code text null
metrics jsonb null
```

Unique constraints may prevent duplicate active stage execution for the same analysis/engine/configuration while still permitting explicit retries/replays.

## 8. Lineage Baseline

`intel.lineage_edges` is append-only and indexed both directions.

Required access paths:
- conclusion backward to evidence/source;
- source forward to affected conclusions;
- analysis-run lineage;
- stage-run lineage.

Do not store the entire lineage graph as one JSON document.

## 9. Evidence / Assertion / Claim Physical Separation

Use normalized M:N support tables:

```text
intel.evidence_items
intel.assertions
intel.assertion_evidence
intel.claims
intel.claim_assertions
intel.risks
intel.risk_claims
```

This deliberately avoids embedding arrays of evidence IDs inside a claim JSONB payload.

## 10. Ontology Physical Design

Ontology is relational because it requires stable IDs, hierarchy traversal, aliases, deprecation and versioned rules.

Use recursive CTEs for baseline hierarchy traversal. Introduce closure/materialized path tables only if benchmarks show repeated hierarchy queries need them.

## 11. Runtime Data

Bulk traces stay in object storage.

`analysis.runtime_events` contains normalized queryable events and should be designed for high write volume.

Recommended key dimensions:

```text
analysis_run_id
sandbox_run_id
scenario_run_id
event_type_concept_id
occurred_at
subject_entity_ref_id
object_entity_ref_id
security_classification_id
payload jsonb
```

Time partitioning is **ACCEPTED_DEFERRED**. P03/P05 MUST NOT independently partition runtime/event tables. Preserve time keys and partition-ready indexes; introduce physical partitions only after measured workload thresholds justify the operational complexity and an implementation ADR records the change.

## 12. RAG / pgvector Physical Design

Authoritative knowledge remains in domain tables. `knowledge.*` is derivative.

Use:

```text
knowledge_objects
→ knowledge_projections
→ knowledge_chunks
→ embeddings
```

Each embedding belongs to an embedding model/version/dimension space. Do not mix incompatible vector dimensions in one ANN index.

For active compatible spaces, HNSW is the default index candidate; exact/IVFFlat alternatives remain benchmark-driven.

Metadata fields required for retrieval filtering should be indexed relationally and not hidden inside the vector payload.

## 13. Queue / Job Physical Design

`ops.jobs` and `ops.job_attempts` are the platform's business/workflow ledger.

Actual queue delivery may map to Supabase Queues/PGMQ rather than implementing a home-grown queue in these tables.

Conceptually:

```text
ops.jobs            durable logical work item
PGMQ message        delivery/visibility/ack mechanics
ops.job_attempts    worker execution history
```

This prevents coupling business status to queue implementation internals.

## 14. Transactional Outbox

`ops.domain_events` acts as an outbox.

Business state + event row are committed in the same transaction. A publisher marks events published only after successful queue/event delivery.

Key columns:

```text
domain_event_id uuid PK
event_type text
aggregate_entity_ref_id uuid null
payload jsonb
schema_version text
correlation_id uuid
causation_id uuid null
occurred_at timestamptz
published_at timestamptz null
```

## 15. RLS Placement

RLS should be applied to all user-reachable objects. Sensitive authoritative schemas should not be broadly exposed to the Data API.

The `api` schema should expose:
- safe views;
- bounded RPC functions;
- user-owned query/history objects as appropriate.

Service workers receive explicit schema/table/function privileges rather than blanket application-user permissions.

## 16. Object Storage Layout

```text
quarantine/{source_observation_id}/...
library/{agent_id}/{agent_version_id}/...
parsed/{analysis_run_id}/{artifact_file_id}/...
sandbox-traces/{analysis_run_id}/{sandbox_run_id}/...
knowledge-context/{query_id}/...
packages/{agent_id}/{agent_version_id}/{package_id}/...
attestations/{package_id}/...
```

Every stored object has DB metadata containing hash, size, security class, producer and retention class.

## 17. Physical Naming Rules

- snake_case tables/columns;
- singular ID column names (`agent_id`, not generic `id`) on high-value domain tables;
- FK columns match target PK names;
- join table names describe both concepts;
- versioned configuration objects have `version` plus immutable content hash;
- timestamps use `_at` suffix;
- booleans use `is_` / `has_` prefixes;
- do not encode ontology concepts in table names when they are data-driven.

## 18. Soft Delete / Supersession

Canonical/intelligence history uses explicit status and supersession links. Hard deletion is reserved for retention/privacy policy actions, not ordinary correction.

## 19. Physical Table Catalog

See `18A_Physical_Table_Catalog.csv` for all 150 logical tables mapped to physical schema, RLS posture, partition candidate and index guidance. Documents `21`, `21A` and `21B` are authoritative for tenant scope inheritance and ValidationRun cardinality.

## 20. Tenant Scope Spine — Locked V2.0.1

Tenant isolation is resolved by `security.tenants`, `security.tenant_memberships` and `security.access_scopes`; see Document 21.

Scope is separate from security classification. Scope-bearing rows use a non-null `scope_id`. `ROOT_SCOPE_BEARING` operations select PLATFORM or ORGANIZATION according to authenticated context/provenance. `DERIVED_INHERITED_SCOPE` rows do not choose their own scope.

For simple AnalysisRun-derived rows the preferred integrity pattern is:

```text
analysis_runs UNIQUE(analysis_run_id, scope_id)
child FOREIGN KEY(analysis_run_id, scope_id)
      REFERENCES analysis_runs(analysis_run_id, scope_id)
```

For multi-parent derivations, controlled write functions/repositories resolve scope and reject more than one distinct organization tenant. Do not use application-supplied tenant IDs as the source of truth.

`core.organizations` continues to represent discovered publishers/maintainers and MUST NOT be reused as the tenant registry.

## 21. ValidationRun Triad — Locked V2.0.1

`lifecycle.validation_runs` stores three distinct analysis references:

```text
baseline_analysis_run_id
modified_analysis_run_id
validation_analysis_run_id
```

alongside baseline/modified AgentVersion IDs and `validation_type`.

P03 creates `UNIQUE (analysis_run_id, agent_version_id)` on `analysis.analysis_runs`.
P05 creates composite foreign keys for baseline and modified pairs so the database guarantees that each AnalysisRun belongs to the stated AgentVersion.

See `21B_Validation_Run_Cardinality_and_Constraints.md` for the complete locked shape and validation-type invariants.
