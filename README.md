# Agent Lifecycle Intelligence Platform (CAIM V2.0.1)

Controlled Implementation Baseline for Agent Lifecycle Intelligence, Security Analysis, AI-BOM, Sandboxing, and Engine Verification.

## Technology Stack & Environment
- **Runtime**: Node.js >= 22.0.0 (Node 22 LTS)
- **Web Server**: Express 4 (`express ^4.21.2`)
- **Frontend**: React 19 + TypeScript + Vite 6 + Tailwind CSS 4
- **Package Manager**: **`pnpm` is the ONLY supported package manager** (pinned at `9.15.9`). Using `npm`, `yarn`, or `bun` is strictly unsupported.

## Architecture & Monorepo Topology

```text
apps/
  web/                  # React 19 SPA + Tailwind client UI
  server/               # Express 4 API bounded server

packages/
  api/                  # Express API routers and typed endpoint contracts
  auth/                 # PrincipalContext, JWT tokens, RBAC, CSRF, and rate limiting
  caim/                 # Common Artifact Intelligence Model (CAIM V2.0.1) definitions
  config/               # Typed environment configuration and secret boundaries
  contracts/            # Shared Zod schemas, DTOs, and event signatures
  db/                   # PostgreSQL adapter, migration runner, and catalog safety
  lifecycle/            # Non-overwriting lifecycle state machine and validation
  ontology/             # CANE normalization mappings and concept registry
  packaging/            # Cryptographic packaging, attestation, and signing
  source/               # Multi-source acquisition adapters (GitHub, HuggingFace, NPM)
  syntax/               # Multi-language parser registry (TS/JS, Python, Go)
  workflow/             # Outbox queue control plane, DAG coordinator, and DR engine

workers/
  discovery/            # [STUB] Source & Web discovery worker stub (until P6)
  semantic/             # [STUB] AST, grammar, and prompt analysis worker stub (until P6)
  evaluation/           # [STUB] Golden corpus evaluation worker stub (until P6)
  cloudflare-scheduler/ # Cloudflare Worker edge cron scheduler
  composer/             # Composition capability builder
  composition/          # SBOM/AI-BOM dependency reachability worker
  decision/             # Evidence risk and policy decision worker
  knowledge/            # Knowledge RAG and pgvector embedding worker
  lifecycle/            # Differential analysis and lifecycle state worker
  sandbox-orchestrator/ # Isolated execution and anti-evasion worker
  static-analysis/      # Static analysis CFG and interprocedural taint worker
```

## Status & Audit Findings
- Generated Status: [`docs/implementation/STATUS.generated.md`](docs/implementation/STATUS.generated.md)
- Truth Ledger: [`docs/implementation/TRUTH_LEDGER.md`](docs/implementation/TRUTH_LEDGER.md)

## Quick Start & Local Commands

### Prerequisites
- Node.js >= 22.0.0
- pnpm 9.15.9 (`corepack enable && pnpm install`)

### Commands
```bash
# Install dependencies with frozen lockfile
pnpm install --frozen-lockfile

# Run local development server (Express + Vite on port 3000)
pnpm run dev

# Run strict type checking across all modules
pnpm run typecheck

# Run linter
pnpm run lint

# Run fast unit and integration tests
pnpm test

# Run slow test suites (sandbox, DR, performance)
pnpm run test:slow

# Run full test suite across all suites
pnpm run test:all

# Run artifact hygiene check
pnpm exec tsx scripts/dist-hygiene.ts

# Generate authoritative status report
pnpm exec tsx scripts/generate-status.ts

# Run production build
pnpm run build

# Run all checks
pnpm run check
```
