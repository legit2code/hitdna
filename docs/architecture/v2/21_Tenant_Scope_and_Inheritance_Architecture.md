# Tenant Scope & Inheritance Architecture

**Document:** 21  
**Version:** 2.0.1  
**Status:** LOCKED — V2 Controlled Implementation Baseline

## 1. Decision

The platform is **tenant-ready from the first production schema** while remaining operable as a single-organization deployment.

Tenant ownership is not modeled by blindly adding an independently writable `organization_id` to every table.
Instead the physical model introduces an explicit security scope:

```text
security.tenants
security.tenant_memberships
security.access_scopes
```

`core.organizations` remains the canonical entity for publishers, maintainers and organizations discovered in the public agent ecosystem. It is **not** the SaaS/customer tenant table.

## 2. Physical Scope Model

```text
security.tenants
  tenant_id uuid PK
  tenant_key text UNIQUE
  display_name text
  status text
  created_at timestamptz

security.tenant_memberships
  tenant_membership_id uuid PK
  tenant_id uuid FK
  principal_id uuid/text -- resolved from Supabase Auth principal
  role_id uuid FK
  status text
  joined_at timestamptz
  revoked_at timestamptz null
  UNIQUE(tenant_id, principal_id, role_id) where active as implemented

security.access_scopes
  scope_id uuid PK
  scope_type text CHECK scope_type IN ('PLATFORM','ORGANIZATION')
  tenant_id uuid null FK security.tenants
  created_at timestamptz
```

Invariants:

```text
scope_type = PLATFORM     → tenant_id IS NULL
scope_type = ORGANIZATION → tenant_id IS NOT NULL
```

There is exactly one active PLATFORM scope. Each active tenant has one canonical ORGANIZATION scope unless an ADR explicitly introduces sub-scopes later.

## 3. Scope Behavior Classes

The architecture uses four implementation behaviors:

### PLATFORM_GLOBAL
Rows are part of the shared platform/reference corpus and always use the PLATFORM scope or are inherently global registries.
Examples: ontology/ruleset definitions, public vulnerability advisories, source-adapter definitions, global reference catalogs.

### ORGANIZATION_SCOPED
Rows are always owned by a tenant organization.
Examples: tenant memberships, user query sessions, private modification workspaces, tenant-specific approvals and tenant-private configuration.

### ROOT_SCOPE_BEARING
The creating operation selects the root scope from authenticated context and input provenance.
Examples: SourceObservation, Artifact/AgentVersion when private or public, AnalysisRun, WorkflowRun and some AuditEvents.

A root row may be PLATFORM or ORGANIZATION. This is what prevents the schema from assuming that identical public analysis must be duplicated for every tenant forever.

### DERIVED_INHERITED_SCOPE
The row **may not choose its own scope**. Its `scope_id` is derived from authoritative parents by database-enforced rules or controlled write functions.
Examples: AnalysisStageRun, StaticFinding, RuntimeEvent, Evidence, Assertion, Claim, Risk, Score, most KnowledgeProjections and Package/Validation derivatives.

`DERIVED_INHERITED_SCOPE` is a behavior class, not a stored value of `scope_type`.

## 4. Derived Scope Resolution

For a derived object with one scoped parent:

```text
child.scope_id = parent.scope_id
```

For a derived object with multiple authoritative inputs:

```text
all PLATFORM inputs
  → PLATFORM scope

PLATFORM inputs + inputs from exactly one ORGANIZATION tenant
  → that ORGANIZATION scope

inputs from more than one distinct ORGANIZATION tenant
  → REJECT by default
```

Cross-tenant aggregation requires a future explicit ADR, authorization policy and declassification/aggregation rule. It is not permitted implicitly.

Security classification remains a separate protection axis:

```text
output_classification >= max(input_classifications)
```

Therefore every derived output has both:

```text
scope_id
security_classification_id
```

where required by the family matrix.

## 5. Database Enforcement Pattern

For parent-owned derived rows, use composite keys to make scope drift impossible.

Example:

```sql
ALTER TABLE analysis.analysis_runs
  ADD CONSTRAINT uq_analysis_runs_id_scope
  UNIQUE (analysis_run_id, scope_id);

-- Example derived row:
FOREIGN KEY (analysis_run_id, scope_id)
  REFERENCES analysis.analysis_runs (analysis_run_id, scope_id);
```

This prevents an application from creating a Claim/Evidence/Finding for an AnalysisRun while assigning a different tenant scope.

Where a row derives from multiple parent types, writes go through a controlled repository/function/trigger that calls the scope resolver and rejects conflicting tenant inputs. Callers do not supply an arbitrary final `scope_id`.

PostgreSQL generated columns are **not** used for cross-table scope inheritance because generated expressions cannot safely derive arbitrary values from other rows. Composite FKs and controlled database write paths are the baseline mechanism.

## 6. AnalysisRun Scope & Reuse

`analysis.analysis_runs` is `ROOT_SCOPE_BEARING`, not permanently organization-only.

Default policy:

- tenant-private artifact/input → ORGANIZATION;
- tenant-specific scenario, policy or restricted input → ORGANIZATION;
- public/global artifact with a shareable, deterministic analysis profile → eligible for PLATFORM;
- if an equivalent PLATFORM run already exists and reuse policy permits it, an organization request may consume that shared run rather than recompute it;
- organization-scoped runtime/sandbox activity never becomes global merely because the source agent is public.

The reuse key is implementation-versioned and must include the inputs capable of changing results (agent version/content, pipeline/analyzer/ruleset/CAIM/ontology/scenario/model configuration as applicable). Reuse must never cross a security or scope boundary.

This design allows future compute reuse without weakening private analysis isolation.

## 7. Scope Propagation Examples

```text
AnalysisRun(scope=A)
  → AnalysisStageRun(scope=A)
  → StaticFinding(scope=A)
  → Evidence(scope=A)
  → Assertion(scope=A)
  → Claim(scope=A)
  → Risk(scope=A)
  → Score(scope=A)
```

For PolicyDecision:

```text
PLATFORM AnalysisRun + PLATFORM PolicySet → PLATFORM
PLATFORM AnalysisRun + tenant PolicySet   → tenant ORGANIZATION
Tenant AnalysisRun + compatible tenant PolicySet → same tenant
Tenant A AnalysisRun + Tenant B PolicySet → REJECT
```

Knowledge projections/chunks/embeddings inherit the scope of the authoritative knowledge object and may never broaden it.

## 8. RLS

RLS evaluates both role/grant and scope:

```text
principal
→ tenant memberships / platform role
→ authorized scope_ids
→ classification threshold / object grant
→ row access
```

PLATFORM scope may be readable according to normal role/classification policy.
ORGANIZATION scope is only readable by principals/services authorized for that tenant scope.

Service credentials do not make tenant isolation optional. Backend services must establish an explicit scope context for scoped operations.

## 9. Object Storage

Scoped objects include their `scope_id` or tenant-derived opaque prefix in storage metadata/path policy. A database row may not grant access to an object stored under a conflicting scope.

## 10. Locked Decision

This tenant model replaces DEF-006. Multi-tenant product behavior may evolve, but the **scope spine is not deferred**. Any future alternative requires an ADR and migration plan.
