# CAIM Developer Guide

This guide is a practical companion to the root README. It focuses on navigating the codebase, running the application, understanding the server and database lifecycle, and validating changes.

## 1. Repository model

CAIM is a TypeScript monorepo. Keep code in the layer that owns its responsibility:

- `apps/web`: user interface and client-side state.
- `apps/server`: HTTP boundary, middleware, route registration and service composition.
- `packages`: reusable contracts and domain services.
- `workers`: analysis and background execution engines.
- `supabase/migrations`: ordered PostgreSQL schema and security changes.
- `scripts`: verification, status generation, build and release utilities.

The Vite build rejects browser imports of worker, packaging, syntax-parser, and Node crypto modules. The browser must call server APIs for privileged work.

## 2. Toolchain

Use the exact versions pinned by the repository:

```bash
corepack enable
pnpm install --frozen-lockfile
```

Node.js 22 or later is required. The root package declares pnpm 9.15.9 as its package manager. Avoid mixing package managers or regenerating the lockfile with a different toolchain.

## 3. Local environment

```bash
cp .env.example .env
```

Set the minimum secrets required by the feature you intend to exercise. For a normal local workflow, start with a Gemini key only if you are using model-backed features. Provider keys for GitHub, Hugging Face, E2B, Supabase, Brave Search, and signing are integration-specific.

The configuration schema is in `packages/config/src/schema.ts`; environment parsing and defaults are in `packages/config/src/loaders.ts`. The config loader handles port precedence, CORS, trusted proxies, request limits, auth secrets, signing configuration, providers, model options, and feature flags.

Never put private keys or service credentials in browser variables. Public config is intentionally sanitized.

## 4. Start and build

```bash
pnpm run dev
```

The root `server.ts` first loads `scripts/server-prelude.ts`, then invokes `startServer()` in `apps/server/main.ts`. In development, the Express app mounts Vite middleware and serves the React SPA.

Production build and start:

```bash
pnpm run build
pnpm start
```

The build generates the Vite client assets and bundles the Node server into `dist/server.cjs`. The server uses static files when configured for production.

## 5. Server request lifecycle

The app factory in `apps/server/index.ts` is intentionally separate from the network listener. It accepts injected dependencies for tests and creates an Express application. The startup module initializes the database and service container, then starts listening.

The middleware order is security-sensitive. It includes request ID validation/generation, Helmet headers, configured proxy trust, CORS, rate limiting, request body limits, CSRF validation, and authenticated principal resolution. Route modules are registered centrally by `apps/server/routes/index.ts`; the typed router is mounted at `/api/v1`.

Unknown API routes return structured problem JSON rather than falling through to the SPA. The error handler includes the request ID for operational correlation.

## 6. Database lifecycle

The database adapter is initialized in `apps/server/infrastructure/db.ts`.

- In production, one of `DATABASE_URL`, `SUPABASE_DB_URL`, or `POSTGRES_URL` must be configured.
- Production requires a successful PostgreSQL health check and schema verification before the server starts.
- Production startup does not apply DDL migrations; apply migrations through the controlled migration workflow first.
- Development/test may try configured PostgreSQL URLs and can fall back to `pg-mem`.
- Do not treat an in-memory run as evidence of production RLS, persistence, backup, or failover behavior.

Migrations are in `supabase/migrations/`. Read the database README and architecture documents before changing schemas or tenant policy.

## 7. Domain ownership

| Concern | Primary location |
|---|---|
| API contracts and router | `packages/api` |
| Auth, roles, grants, CSRF, rate limiting | `packages/auth` |
| CAIM envelope and invariants | `packages/caim`, `packages/contracts` |
| Config and secret boundaries | `packages/config` |
| Persistence and repositories | `packages/db` |
| Source adapters and provenance | `packages/source`, `workers/discovery` |
| Parsing and language intelligence | `packages/syntax`, `workers/semantic` |
| Static rules and taint | `workers/static-analysis` |
| SBOM, AI-BOM and dependency analysis | `workers/composition` |
| Runtime sandbox | `workers/sandbox-orchestrator` |
| Risk and policy | `workers/decision` |
| RAG and grounded synthesis | `workers/knowledge` |
| Lifecycle and validation | `packages/lifecycle`, `workers/lifecycle` |
| Packaging and signing | `packages/packaging` |
| Queues, audit, telemetry, evaluation, DR | `packages/workflow` |
| Web workflows | `apps/web/src/components/views` |
| Engineering diagnostics | `apps/web/src/components/dev` |

## 8. Test strategy

```bash
pnpm run lint
pnpm run typecheck
pnpm test
pnpm run test:slow
pnpm run test:e2e
pnpm run release:check
pnpm run build
```

The default suite excludes the canonical slow suite files unless explicitly selected. Use `pnpm run test:all` to include all configured suites. The slow list includes sandbox, release/DR, performance, cross-tenant RLS, and verification infrastructure checks.

Top-level tests cover HTTP behavior, auth, RLS, audit integrity, migrations, provider acquisition, full-pipeline workflows, and security boundaries. Platform and package tests live alongside their source code.

## 9. Status and truth

Run `pnpm exec tsx scripts/generate-status.ts` to regenerate machine-derived status. Do not edit `STATUS.generated.md`, `status.generated.json`, or the governed build-state JSON by hand.

Read `docs/implementation/TRUTH_LEDGER.md` for evidence-backed findings. A finding marked `EXTERNAL INFRA REQUIRED` cannot be upgraded to pass merely because local tests pass. Check certification receipts for provider-specific evidence and inspect the generation timestamp and Git SHA availability.

## 10. Security and tenancy invariants

- Treat source repositories and uploaded files as untrusted.
- Keep server-only secrets and private signing material out of the client.
- Preserve authentication and capability checks on API routes.
- Keep tenant scope independent from security classification.
- Derive child scope from authoritative parent rows; reject cross-tenant input combinations unless explicitly governed.
- Keep audit records append-only and fail closed for security-critical writes.
- Preserve sandbox network and secret-isolation controls.
- Do not weaken migration, release, or artifact-hygiene gates to make CI green.

## 11. Change checklist

1. Locate the owning package or worker and read its public exports.
2. Read the relevant architecture document and decision records.
3. Add tests for success, failure, and security boundaries.
4. Run typecheck, focused tests, and the relevant slow or external gates.
5. Run the build and artifact-hygiene check.
6. Regenerate status only after the implementation/test state is current.
7. Update docs when developer-facing behavior changes.
