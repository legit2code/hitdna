# CAIM — Agent Lifecycle Intelligence Platform

CAIM is an agent lifecycle intelligence and assurance platform. It is designed to discover agent artifacts, normalize their identity and structure, analyze source and runtime behavior, build evidence-backed risk decisions, manage lifecycle changes, and produce traceable packages and attestations.

This repository is the actively developed implementation of the CAIM V2.0.1 architecture baseline. It contains a React 19 console, an Express API, shared TypeScript packages, domain workers, PostgreSQL/Supabase migrations, automated tests, and verification/release tooling.

> **Important:** A generated status report, architecture specification, local test pass, or mock-provider receipt is not equivalent to a live production deployment. The generated report records 33 migrations and 115 test files as of 2026-10-12, but also records that the database catalog was not connected during generation and that 32 of 81 engines were classified as stubs. Check the latest generated report and truth ledger before making readiness claims.

## Product goals and lifecycle

The platform's workflows support this high-level lifecycle:

1. **Discover:** query source ecosystems, collect candidate agent repositories, and record source observations.
2. **Acquire and normalize:** retrieve untrusted artifacts, preserve provenance, resolve canonical identity, and parse supported source languages.
3. **Analyze:** run syntax intelligence, static rules, control-flow and taint analysis, dependency/SBOM analysis, capability inference, and optional isolated dynamic execution.
4. **Establish evidence:** persist findings, lineage, assertions, claims, uncertainty/truth states, and confidence metadata.
5. **Decide:** calculate risk and scores, evaluate policy, and produce recommendations.
6. **Retrieve knowledge:** index governed content, perform hybrid retrieval, synthesize grounded answers, and validate citations.
7. **Manage changes:** compare immutable versions, plan modifications, validate changes, and preserve review/approval records.
8. **Package and ship:** create deterministic artifacts, manifests, SBOMs, signatures, attestations, and shipping decisions.
9. **Operate and verify:** monitor jobs and traces, maintain durable audit evidence, evaluate a golden corpus, and run release gates.

The platform is intended for analysts, developers, operators, auditors, and release approvers. The UI exposes these capabilities as separate workflow screens.

## Architecture

```text
.
├── apps/
│   ├── server/                  # Express API, middleware, routes and service container
│   └── web/                     # React 19 SPA and workflow views
├── packages/
│   ├── api/                     # API router, adapters, envelopes, errors and OpenAPI
│   ├── auth/                    # Principals, JWT, RBAC, CSRF, rate limiting and audit
│   ├── caim/                    # Common Artifact Intelligence Model
│   ├── config/                  # Zod configuration schemas and secret boundaries
│   ├── contracts/               # Shared domain contracts and truth-state models
│   ├── db/                      # PostgreSQL adapters, repositories and migrations
│   ├── lifecycle/               # Lifecycle state machine and validation
│   ├── ontology/                # CANE normalization and concept mappings
│   ├── packaging/               # Bundling, SBOM, manifests, signatures and shipping
│   ├── source/                  # Source adapters, discovery and provenance
│   ├── syntax/                  # Multi-language parsing and syntax intelligence
│   └── workflow/                # Queues, outbox, telemetry, evaluation and DR
├── workers/
│   ├── discovery/               # Discovery pipeline
│   ├── semantic/                # Semantic and syntax processing
│   ├── static-analysis/          # CFG, call graph, rules and taint
│   ├── composition/              # SBOM, AI-BOM and dependency reachability
│   ├── sandbox-orchestrator/     # Isolated runtime and evasion telemetry
│   ├── decision/                 # Capability, risk, scoring and policy
│   ├── knowledge/                # Embeddings, retrieval and grounded synthesis
│   ├── lifecycle/                # Differential analysis and revalidation
│   ├── evaluation/               # Golden-corpus regression evaluation
│   ├── composer/                 # Agent composition/capability workflows
│   └── cloudflare-scheduler/     # Cloudflare scheduled-worker entrypoint
├── supabase/
│   ├── migrations/               # Ordered PostgreSQL schema/RLS migrations
│   └── seed.sql                  # Reference/bootstrap seed data
├── docs/
│   ├── architecture/v2/          # Controlled architecture specifications
│   ├── implementation/           # Generated status, truth ledger and decisions
│   ├── certification/            # External-provider and release receipts
│   └── security/                 # Security and audit policy
├── src/__tests__/                # Platform-level tests
├── tests/                        # Integration, security, RLS and E2E tests
├── scripts/                      # Build, discovery, audit and release tooling
├── server.ts                     # Production/development process entrypoint
└── package.json                  # Workspace scripts and dependencies
```

## Technology stack

- **Runtime:** Node.js 22 or newer.
- **Package manager:** pnpm 9.15.9 (pinned in `package.json`).
- **Language:** TypeScript 5.8, ESM source modules.
- **Web:** React 19, Vite 6, Tailwind CSS 4, Lucide, Motion.
- **HTTP:** Express 4 and Helmet.
- **Validation:** Zod 4.
- **Persistence:** PostgreSQL via `pg`, with Supabase-oriented schemas and RLS migrations; `pg-mem` is used for local/test fallback.
- **AI:** Google GenAI SDK (Gemini).
- **Dynamic execution:** E2B integration plus a simulated provider for controlled tests.
- **Testing/build:** Vitest 4, ESLint 9, TypeScript, esbuild, tsx, Supertest and autocannon.

## Prerequisites

- Node.js >= 22.
- Corepack-enabled pnpm 9.15.9.
- PostgreSQL for persistent database development and production.
- Gemini API key for model-backed functions.
- Optional integration credentials as required: GitHub, Hugging Face, E2B, Supabase, signing/KMS, and Brave Search.

## Quick start

Enable Corepack and install the exact locked dependency graph:

```bash
corepack enable
pnpm install --frozen-lockfile
```

Create a local environment file:

```bash
cp .env.example .env
```

Set the credentials and runtime settings needed by your environment. Do not commit `.env` or real secrets.

Start the local server:

```bash
pnpm run dev
```

The default application port is 3000 unless overridden through the configuration variables/CLI supported by the current config loader. The Express process serves Vite middleware in development.

## Commands

| Command | Purpose |
|---|---|
| `pnpm run dev` | Starts `server.ts` with tsx. |
| `pnpm run build` | Builds the Vite SPA and bundles the Node server to `dist/server.cjs`. |
| `pnpm start` | Runs the production server bundle. |
| `pnpm run preview` | Runs Vite preview. |
| `pnpm run lint` | Runs ESLint over the repository. |
| `pnpm run typecheck` | Runs TypeScript with `--noEmit`. |
| `pnpm test` / `pnpm run test:fast` | Runs the fast/default Vitest suite. |
| `pnpm run test:slow` | Runs the canonical slow suite set (sandbox, release/DR, performance, cross-tenant and verification infrastructure). |
| `pnpm run test:all` | Includes fast and slow tests. |
| `pnpm run test:integration` | Runs the foundation integration suite. |
| `pnpm run test:e2e` | Runs the full-pipeline E2E test file. |
| `pnpm run scan:secrets` | Runs the repository secret scanner. |
| `pnpm run migrations:safety` | Runs migration safety checks. |
| `pnpm run dr:rehearse` | Runs the disaster-recovery rehearsal engine. |
| `pnpm run release:check` | Evaluates release readiness gates. |
| `pnpm run discovery:cycle` | Runs the discovery-cycle script. |
| `pnpm exec tsx scripts/generate-status.ts` | Regenerates machine-derived implementation status. |
| `pnpm exec tsx scripts/dist-hygiene.ts` | Checks distribution artifact hygiene. |
| `pnpm run check` | Runs lint, typecheck, default tests, release checks and build. |

The package manager is intentionally pinned. Use pnpm rather than npm, yarn, or bun so workspace resolution and the lockfile remain reproducible.

## Environment configuration

The canonical example is `.env.example`; schema validation and environment parsing live in `packages/config`.

| Variable | Description |
|---|---|
| `NODE_ENV`, `APP_ENV` | Runtime/application environment. |
| `APP_PORT`, `PORT`, `HOST` | Listener configuration; precedence is implemented in `getServerConfig()`. |
| `APP_URL`, `CORS_ALLOWED_ORIGINS`, `TRUST_PROXY` | Public URL, CORS allow-list, and reverse-proxy trust. |
| `BODY_LIMIT`, `INGESTION_BODY_LIMIT`, `SHUTDOWN_TIMEOUT_MS` | Request size and shutdown controls. |
| `GEMINI_API_KEY` | Server-side Gemini access. Never expose to the browser. |
| `GEMINI_MODEL_DEFAULT`, `GEMINI_MODEL_PRO`, `GEMINI_MODEL_EMBEDDING` | Model identifiers. |
| `MODEL_TEMPERATURE`, `MODEL_MAX_OUTPUT_TOKENS` | Generation parameters. |
| `DATABASE_URL`, `SUPABASE_DB_URL`, `POSTGRES_URL` | PostgreSQL connection URL candidates. |
| `SUPABASE_URL`, `SUPABASE_SERVICE_ROLE_KEY` | Supabase service integration. |
| `JWT_SECRET`, `SERVICE_TO_SERVICE_SECRET`, `CAIM_DISCOVERY_SERVICE_TOKEN` | Authentication and service-to-service secrets. |
| `SERVICE_AUTHORIZED_TENANTS` | JSON map of service identities to permitted tenant scopes. |
| `SIGNING_KEY_ID`, `SIGNING_ALGORITHM`, `SIGNING_PRIVATE_KEY`, `SIGNING_PUBLIC_KEY` | Signing key metadata/material. Private material must be managed securely. |
| `GITHUB_TOKEN`, `HUGGINGFACE_API_KEY`, `E2B_API_KEY`, `BRAVE_API_KEY`, `SENTRY_DSN` | Optional source, search, sandbox, and monitoring providers. |
| `FEATURE_*` | Feature switches for sandboxing, evasion detection, taint, RAG, monitoring, remediation, and AI-BOM. |

Not every variable is listed in this overview. Check the config schema and loader for exact parsing behavior. A credential being present means an adapter can be enabled; it does not prove remote service connectivity.

## Application runtime

The root `server.ts` loads `scripts/server-prelude.ts` and calls `startServer()` from `apps/server/main.ts`.

The startup sequence is:

1. Load validated configuration.
2. Initialize the database adapter and verify PostgreSQL schema in production.
3. Construct the shared service container and domain services.
4. Create the Express application.
5. Apply request-ID, Helmet/security-header, proxy, CORS, rate-limit, body parsing, CSRF, and principal-resolution middleware.
6. Register feature routes and the typed `/api/v1` router.
7. Serve Vite middleware in development or static `dist/` files in production.
8. Install graceful SIGTERM/SIGINT shutdown handling and fatal process handlers.

The app factory `createApp()` is designed to be testable and does not itself listen on a port. `startServer()` owns the listener and shutdown lifecycle.

## API organization

Route registration is centralized in `apps/server/routes/index.ts`. The route modules are grouped by concern:

- health and readiness;
- authentication and administration;
- diagnostic console;
- ingestion and discovery;
- syntax and analysis;
- sandbox and decision workflows;
- knowledge and composition;
- packaging and observability;
- evaluation, traceability, and worker operations.

The typed API router is mounted under `/api/v1` and is implemented in `packages/api`. Unknown `/api/*` routes return an RFC 9457-style `application/problem+json` response with a request ID. Health endpoints include liveness and database/schema readiness checks; consult `apps/server/routes/health.routes.ts` for exact paths and response fields.

## Domain package and worker responsibilities

| Area | Main responsibility |
|---|---|
| `packages/contracts` | Shared envelopes, identifiers, epistemic/truth-state types, provenance and observability contracts. |
| `packages/caim` | Canonical artifact model, schemas, manifest and invariants. |
| `packages/auth` | Principal resolution, JWT/session logic, RBAC, grants, CSRF, rate limits and audit. |
| `packages/db` | PostgreSQL adapter, repositories, migration execution and migration-safety checks. |
| `packages/source` | Provider adapters, artifact acquisition, discovery graph and provenance. |
| `packages/syntax` | Language parsing, syntax intelligence and protocol/framework extraction. |
| `workers/static-analysis` | AST-derived CFG, symbol/call graphs, static rules, source/sink/sanitizer taint propagation. |
| `workers/composition` | Manifest parsing, package URL normalization, advisory matching, license/malicious-package checks, SBOM and AI-BOM. |
| `workers/sandbox-orchestrator` | Provider-managed execution, scenarios, network controls, secret sanitization and evasion detection. |
| `workers/decision` | Capability inference, risk, scoring, policy and recommendations. |
| `workers/knowledge` | Chunking, embeddings, retrieval planning, reranking, context assembly and grounded synthesis. |
| `workers/lifecycle` | Differential analysis, modification workspaces, approvals, reanalysis and validation. |
| `workers/evaluation` | Golden-corpus and regression evaluation. |
| `packages/packaging` | Deterministic packaging, manifests, SBOM, signature and shipping verification. |
| `packages/workflow` | Durable jobs, outbox, scheduled workers, telemetry, audit, evaluation and recovery workflows. |

## Data architecture and migrations

The database design uses non-public PostgreSQL schemas for authoritative data, with a curated `api` schema for controlled exposure. Key schema domains include `security`, `core`, `source`, `ontology`, `analysis`, `intel`, `knowledge`, `lifecycle`, and `ops`.

Tenant scope is a separate axis from security classification. Rows derived from a scoped parent inherit that scope; cross-tenant derivations are rejected unless an explicit governed policy permits them. RLS and service authorization are part of the security boundary.

Migrations live in `supabase/migrations/` and are applied in lexical order. See [Supabase database documentation](supabase/README.md), [migration README](supabase/migrations/README.md), and the architecture documents.

**Production database behavior:** `apps/server/infrastructure/db.ts` requires a real PostgreSQL URL in production, verifies database health and migration/schema state, and refuses to start if the production database is unavailable or schema verification fails. The in-memory `pg-mem` fallback is restricted to development/test. Production startup does not run DDL migrations automatically; deploy migrations as a separate controlled step.

## Security model

The repository implements or specifies multiple defensive layers:

- request IDs and hardened HTTP response headers;
- CORS allow-list and bounded request-body sizes;
- rate limiting and CSRF validation;
- principal resolution, role/capability checks and tenant scope;
- PostgreSQL RLS and explicit service scopes;
- secret redaction and fail-closed authorization paths;
- sandbox network controls and secret sanitization;
- append-only, hash-chained audit records with scheduled verification and signed checkpoints;
- artifact provenance, content hashing, package manifests and cryptographic signing.

Read [Audit Log Durability & Integrity Policy](docs/security/audit-policy.md) before changing audit persistence. Security policy claims should be checked against the current implementation and environment-specific certification evidence.

## Tests and verification

The repository uses Vitest across platform, package, worker, script, integration, and E2E test trees. The test suite includes architecture-boundary checks, client bundle isolation, migration and RLS tests, auth and CSRF, provider acquisition, static/dynamic analysis, knowledge grounding, packaging, audit integrity, disaster recovery, and full-pipeline checks.

Recommended local sequence:

```bash
pnpm run lint
pnpm run typecheck
pnpm test
pnpm run test:slow
pnpm run test:e2e
pnpm run release:check
pnpm run build
```

For the complete configured suite use `pnpm run test:all`. Some suites require PostgreSQL, E2B, KMS, object storage, or other external infrastructure. A skipped or unavailable external check must not be reported as passed.

## Generated status, truth ledger, and release evidence

- `docs/implementation/STATUS.generated.md` and `status.generated.json` are generated by `scripts/generate-status.ts`. Do not hand-edit them.
- `docs/implementation/TRUTH_LEDGER.md` records findings and permitted evidence-backed statuses.
- `docs/implementation/BUILD_STATE.json` is a machine-governed build-state artifact; its own comment prohibits hand-editing.
- `docs/certification/` contains receipts for external services and release evidence.
- `scripts/release-check.ts` and related scripts evaluate release gates.

Always regenerate status from the current checkout and inspect the truth ledger and relevant receipts before making a release decision. Generated counts are snapshots, not timeless claims.

## Documentation map

- [Developer guide](docs/DEVELOPER_GUIDE.md)
- [Documentation index](docs/README.md)
- [Architecture V2 index](docs/architecture/v2/INDEX.md)
- [Implementation status](docs/implementation/STATUS.generated.md)
- [Truth ledger](docs/implementation/TRUTH_LEDGER.md)
- [Known gaps](docs/implementation/KNOWN_GAPS.md)
- [Security audit policy](docs/security/audit-policy.md)
- [Database and migrations](supabase/README.md)

## Contributing

1. Read the relevant architecture specification, ADR, and truth-ledger findings.
2. Identify the package or worker that owns the behavior.
3. Preserve public contracts and client/server/worker boundaries.
4. Add tests for normal behavior, failure modes, and security invariants.
5. Run typecheck, relevant tests, and build; run external certification gates when available.
6. Update documentation when setup, environment variables, scripts, route behavior, data contracts, or operational assumptions change.
