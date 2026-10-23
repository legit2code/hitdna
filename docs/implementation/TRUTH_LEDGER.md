# CAIM Platform Truth Ledger & Audit Findings

> **Authoritative Baseline Reference**: Governed by `00_MASTER_CONSTITUTION.md`.  
> Statuses are strictly evidence-backed. Permitted vocabulary: `EXECUTED — PASS`, `EXECUTED — FAIL`, `STATIC — VERIFIED`, `EXTERNAL INFRA REQUIRED`, `OPEN`.

| Finding ID | Finding Description | Status | Owner Prompt | Evidence |
|---|---|---|---|---|
| **F-01** | Public repository source archive publication (`caim-repository.zip`, `scripts/build-repo-zip.py`) | **EXECUTED — PASS** | R00 | Archive files deleted, `.gitignore` updated, `tests/dist-hygiene.test.ts` passed (9/9 tests pass) |
| **F-02** | Missing real git history, branch protection, and CI status checks on `main` | **EXTERNAL INFRA REQUIRED** | R00 | Repository has no `.git` directory (`GIT_SHA: UNAVAILABLE`); branch protection requires remote Git hosting infrastructure |
| **F-03** | Hardcoded credential literals and unrevoked secrets in history | **EXECUTED — PASS** | R01 | `scripts/secret-scanner.ts` and `.gitleaks.toml` pass across 1,013+ files with 0 findings; demo keys sanitized |
| **F-04** | Synthetic/fallback commit SHAs masking uncommitted modifications | **EXTERNAL INFRA REQUIRED** | R01 | `scripts/generate-status.ts` reports `GIT_SHA: UNAVAILABLE` when `.git` is missing instead of fabricating a synthetic SHA |
| **F-05** | Production runtime fallback to ephemeral in-memory database | **EXTERNAL INFRA REQUIRED** | R02 | Database adapter strictly rejects in-memory fallbacks in production; requires PostgreSQL `DATABASE_URL` (`tests/postgres-adapter-tls.test.ts`) |
| **F-06** | Catalog RLS coverage and two-session non-owner tenant isolation gaps | **EXTERNAL INFRA REQUIRED** | R02 | RLS policies defined across all 33 migrations; multi-tenant tests require live PostgreSQL server |
| **F-07** | Worker stubs (`discovery`, `semantic`, `evaluation`) misreported as complete | **EXECUTED — PASS** | R03 | Workers implemented with authentic logic; verified by `tests/workers-*.test.ts` (11 tests pass) and `tests/workers-guard.test.ts` |
| **F-08** | Unverified container sandbox execution and anti-evasion telemetry | **EXTERNAL INFRA REQUIRED** | R04 | Container sandbox execution in `workers/sandbox-orchestrator/providers/e2b-provider.ts` requires external cloud VM infrastructure |
| **F-09** | Unverified golden corpus evaluation parity and policy zero-regression | **EXECUTED — PASS** | R04 | Live golden corpus evaluator verified by `tests/workers-evaluation.test.ts` and `tests/scheduled-background-workers.test.ts` (5 tests pass) |
| **F-10** | Untested disaster recovery procedures and state reconstruction | **EXTERNAL INFRA REQUIRED** | R05 | DR state reconstruction tests in `tests/dr/` require live Postgres replica and S3 backup targets |
| **F-11** | Unverified composition reachability analysis and AI-BOM claims | **EXECUTED — PASS** | R03 | Dependency reachability and SBOM analysis verified in `src/__tests__/p17_dependency_reachability.test.ts` |
| **F-12** | Diagnostic engineering console endpoints accessible without strict RBAC | **EXECUTED — PASS** | R02 | RBAC enforcement and authorization boundaries verified in `tests/authorization-boundaries.test.ts` |
| **F-13** | Hand-written, unverified status claims in documentation | **EXECUTED — PASS** | R00 | Machine-generated status report via `scripts/generate-status.ts`; verified by `scripts/generate-status.test.ts` (4 tests pass) |
| **F-14** | Build artifact leakage, sourcemap exposure, and bundles over 5 MB | **EXECUTED — PASS** | R00 | Dist hygiene and size budgets verified in `tests/dist-hygiene.test.ts` and `scripts/dist-hygiene.ts`; vendor chunks < 1 MB |
| **F-15** | Static analysis CFG and interprocedural taint propagation gaps | **EXECUTED — PASS** | R03 | AST/CFG/taint flow analysis verified in `src/__tests__/p15_static_analysis.test.ts` and `src/__tests__/p16_taint_analysis.test.ts` |
| **F-16** | Rate limiting and DoS defense degradation under concurrent load | **EXECUTED — PASS** | R02 | Token bucket rate limiting verified in `packages/auth/src/rate-limiter.ts` and `tests/http/` |
| **F-17** | CSRF double-submit token validation and origin checks | **EXECUTED — PASS** | R02 | Double-submit cookie and origin validation verified in `tests/csrf-origin-validation.test.ts` (passes) |
| **F-18** | Outbox pattern transaction atomicity and event queue durability | **EXECUTED — PASS** | R03 | Queue control plane outbox verified in `src/__tests__/p09_workflow_queue_control_plane.test.ts` |
| **F-19** | Monorepo package boundary violations between client and workers | **EXECUTED — PASS** | R01 | Client isolation verified by `dependency-cruiser` and ESLint boundary rules in `tests/architecture/client-isolation.test.ts` and `tests/architecture/boundaries.test.ts` (10 tests pass) |
| **F-20** | Unsigned release receipts and missing cryptographic provenance chains | **STATIC — VERIFIED** | R05 | Package signature verifier contracts verified in `packages/packaging/src/crypto/verifier.ts` and `src/__tests__/packaging.test.ts` |
| **F-21** | Inaccurate monorepo package and worker topology documentation | **STATIC — VERIFIED** | R00 | `README.md` topology aligned to real directory tree; worker statuses corrected |
| **F-22** | Staging and production deployment target placeholder gates | **EXTERNAL INFRA REQUIRED** | R05 | Live deployment targets require external cloud provider provisioning |
| **F-23** | Hardcoded return constants in worker entry points | **EXECUTED — PASS** | P1 | Dynamic pipelines implemented for discovery, semantic, and evaluation; verified by `tests/workers-guard.test.ts` and `tests/workers-dag-integration.test.ts` |
| **F-24** | Client bundle `node:crypto` externalization and circular chunk warning | **EXECUTED — PASS** | P2 | Server crypto decoupled from web; Vite `manualChunks` refactored; verified by clean `npm run build` with zero warnings |
| **F-25** | Flawed status generator statistics and worker classification | **EXECUTED — PASS** | P2 | Recursive multi-file LOC scanning and test referencing implemented in `scripts/generate-status.ts`; verified by `scripts/generate-status.test.ts` |
| **F-26** | Committed archive policy discrepancy (`artifacts/corpus-held-out.tar.gz`) | **STATIC — VERIFIED** | P3 | Explicit narrow exception documented in `SECURITY.md` and cryptographic digest verified in `scripts/dist-hygiene.ts` and `tests/dist-hygiene.test.ts` |
| **F-27** | Personal email contact exposed in public security policy and codeowners | **STATIC — VERIFIED** | P3 | Replaced personal email in `SECURITY.md` and `CODEOWNERS` with `security@caim.internal` and GitHub Private Vulnerability Reporting |
| **F-28** | Demo agent fixture embedding `sk-live-...` token in non-test route | **EXECUTED — PASS** | P3 | Token sanitized to `sk-test-FAKE_MOCK_TOKEN_NEVER_LIVE` in `apps/server/routes/analysis.routes.ts`; secret scanner rule added |
