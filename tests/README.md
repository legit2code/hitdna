# Test Suite Guide

CAIM uses Vitest for unit, contract, integration, architecture, security, and end-to-end tests. Tests are distributed across `src/__tests__/`, package/worker test folders, `scripts/`, and this top-level `tests/` directory.

## Common commands

```bash
pnpm test                 # default/fast suite
pnpm run test:slow        # canonical slow suites
pnpm run test:all         # all configured suites
pnpm run test:integration # foundation integration suite
pnpm run test:e2e         # full-pipeline E2E suite
```

The canonical slow suite list is maintained in `vitest.config.ts`. It includes sandbox, release/DR, performance, cross-tenant RLS, and verification-infrastructure coverage. The default suite excludes these slow files unless they are explicitly selected.

## Coverage areas

- API contracts and HTTP error/limit/header behavior.
- Authentication, authorization, CSRF, tenant scope and RLS.
- Database adapter, migrations, migration idempotence and transaction boundaries.
- Source acquisition, discovery graph and scheduled discovery.
- Syntax, static analysis, taint and dependency reachability.
- Sandbox execution and evasion controls.
- Decision policy, knowledge retrieval and grounded synthesis.
- Lifecycle validation, packaging, signatures and shipping truth states.
- Audit hash-chain integrity, concurrency, restart recovery and tamper detection.
- Architecture boundaries, client isolation, artifact hygiene and release gates.

## External infrastructure

Some checks require a real PostgreSQL server, E2B sandbox, KMS/signing service, object storage, or deployment target. A test that cannot run without its external dependency is not evidence that the integration passed. Use the certification receipts and truth ledger to distinguish executed checks from external prerequisites.
