# Security Classification & RLS Data Overlay

**Document:** 13  
**Status:** V2.0.1 controlled baseline; classification + tenant scope model locked, exact SQL predicates implemented in P06.

## 1. Classification Levels

```text
PUBLIC_METADATA
INTERNAL
SENSITIVE
VAULT_RESTRICTED
```

Classification represents required protection, not risk severity.

## 2. Default Classification by Data Family

### PUBLIC_METADATA
Usually eligible:
- canonical agent identity;
- public publisher metadata;
- public distributions;
- public component names/versions;
- public vulnerability IDs;
- language/protocol classifications.

### INTERNAL
Usually includes:
- workflow state;
- scoring configuration;
- ontology/ruleset internals;
- evaluation results;
- internal cost information.

### SENSITIVE
Usually includes:
- source code snapshots not intended for broad access;
- source spans;
- endpoints;
- tool bindings;
- static findings;
- recommendations;
- query histories;
- generated context.

### VAULT_RESTRICTED
Default for:
- credential references;
- secret-related configuration;
- taint paths exposing sensitive flow;
- raw sandbox traces;
- sensitive runtime events;
- high-severity exploit/evasion findings;
- misuse-case details;
- policy decisions containing sensitive evidence;
- modification workspaces/patches;
- restricted prompts;
- restricted audit/security events.

## 3. Inheritance

Security classification must propagate through derivation.

Default rule:

```text
output_classification >= max(input_classifications)
```

A controlled declassification rule may lower classification only when an authorized transformation proves sensitive material has been removed.

## 4. RAG Rule

Authorization occurs before model context construction.

```text
Principal
→ Roles / Grants
→ Authorized Entity Universe
→ Relational / Vector / Graph / Evidence Retrieval
→ Context Assembly
→ LLM
```

Never retrieve vault data and depend on the model to hide it.

## 5. Logical Access Model

`roles` + `user_roles` define broad role membership.

`access_grants` supports scoped privileges such as:
- vault_reader;
- reviewer;
- modification_approver;
- package_shipper;
- audit_reader;
- admin.

Supabase Auth remains the identity provider; these entities model application authorization.

## 6. Suggested Role Matrix

| Capability | Standard User | Analyst | Vault Reader | Reviewer | Admin |
|---|---:|---:|---:|---:|---:|
| Public/canonical metadata | Read | Read | Read | Read | Full |
| Static findings | Limited | Read | Read | Read | Full |
| Runtime summaries | Limited | Read | Read | Read | Full |
| Raw sandbox traces | No | Limited | Read | Read | Full |
| Taint/credential evidence | No | Limited | Read | Read | Full |
| Sensitive misuse cases | No | Limited | Read | Read | Full |
| Modification workspace | No | Limited | Limited | Approve | Full |
| Ship package | No | No | No | Conditional | Full |
| Audit log | No | Limited | Limited | Read | Full |

Exact roles remain a security-design decision; the logical model supports them.

## 7. RLS Design Principles

1. Default deny for restricted families.
2. Database-enforced rules, not UI-only filtering.
3. Service-role access isolated to backend workers.
4. RAG service uses caller-aware access scope.
5. Audit writes cannot be bypassed for privileged actions.
6. Package/modification approvals use explicit approver identity.
7. Query logs must not leak restricted retrieved content.
8. Security-class changes invalidate derivative indexes.

## 8. Object Storage

Buckets/prefixes should be logically separated:

```text
quarantine/
library/
parsed/
sandbox-traces/
knowledge-context/
packages/
attestations/
```

Storage access should mirror row-level authorization metadata rather than using public buckets for convenience.

## 9. Tenant Scope Is a Separate Security Axis

Security classification answers **how sensitive** a row is. Tenant scope answers **who owns/is allowed to see the row**. Both must authorize access.

```text
security classification: PUBLIC_METADATA / INTERNAL / SENSITIVE / VAULT_RESTRICTED
scope: PLATFORM / ORGANIZATION
```

The scope spine is `security.access_scopes`; see Document 21.

RLS authorization conceptually requires:

```text
authorized_scope(scope_id)
AND authorized_classification(security_classification_id)
AND role/object grant
```

A row cannot become cross-tenant because application code supplies a different tenant identifier. DERIVED_INHERITED_SCOPE rows obtain the authoritative `scope_id` from parents through composite FK/controlled write paths.

Scope propagation and classification propagation are both monotonic by default:

```text
scope: PLATFORM + Tenant A input → Tenant A
classification: output >= max(inputs)
```

Mixing Tenant A and Tenant B derived inputs is rejected unless a future explicit cross-tenant aggregation ADR authorizes the operation.
