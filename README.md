# Hit DNA Music Intelligence Platform

> **Architecture Version:** 5.0.0  
> **Pack Version:** 6.0.0  
> **Canonical Manifest Hash:** `1ccc957a962db4c93b5b2a872fb7cddbd4025d938ecdc5de86ca88c17bf5454b`  
> **Active Engine:** `PF-02` — Repository & Tooling Foundation (Phase P01)

Hit DNA Music Intelligence is an evidence-backed music intelligence, empirical Hit DNA analysis, and constrained song construction system governed by the P00 Master Build Constitution.

---

## Canonical Command Surface

| Command | Description |
| :--- | :--- |
| `npm run dev` | Boots local full-stack server (`0.0.0.0:3000`) with Vite development middleware |
| `npm run build` | Compiles client assets (`vite build`) and bundles production Node server (`dist/server.cjs`) |
| `npm start` | Boots production server from `dist/server.cjs` |
| `npm run lint` | Runs strict TypeScript typechecking (`tsc --noEmit`) |
| `npm test` | Runs all unit, integration, and e2e test suites |
| `npm run test:unit` | Runs isolated unit tests |
| `npm run test:integration`| Runs HTTP route and system contract tests against ephemeral listener |
| `npm run test:e2e` | Runs application shell contract tests |
| `npm run check` | Root verification pipeline: runs integrity check, typecheck, tests, and phase verifier |
| `npm run phase:verify P01` | Executes Truth & Integrity verifier and generates `docs/implementation/evidence/P01_RECEIPT.json` |
| `npm run integrity:all` | Runs full suite of deterministic integrity and truth checks |
| `npm run integrity:negative-tests` | Runs negative self-tests verifying drift, contamination, and bad receipts fail |
| `npm run integrity:architecture` | Verifies v5.0.0 66 engines, 670 modules, and manifest hash |
| `npm run integrity:fixtures` | Audits production files for forbidden test fixture contamination |

---

## Module Boundaries

The repository enforces strict module separation across 10 functional boundaries:

- `src/client/`: Application UI shell and console components
- `src/server/`: Express application, routes, and Vite middleware integration
- `src/domain/`: Canonical engine schemas and domain boundaries
- `src/repositories/`: Data access and state persistence abstractions
- `src/services/`: Health, diagnostics, and domain services
- `src/workers/`: Asynchronous job contracts and execution queue stubs
- `src/contracts/`: Source-independent typed API envelopes and schemas
- `src/config/`: Sanitized client/server configuration with secret redaction
- `src/testing/`: Isolated fixtures (`TEST_FIXTURE`), unit, integration, and e2e suites
- `docs/`: Canonical architecture manifest, check matrix, and evidence receipts

---

## Hard Phase Boundaries

Per the P00 Master Build Constitution, domain engines (research ingestion, audio analysis, cohort statistics, artist style profiles, song generation, and admin governance) remain strictly locked until their respective phases.
