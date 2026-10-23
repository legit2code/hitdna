# Architectural Decision Records (ADRs) & Pending Decisions

*Last Reconciled: 2026-08-24 (Post-P15 Gate)*

| ADR ID | Topic | Status | Authority & Resolution Notes |
|---|---|---|---|
| ADR-001 | Physical Partitioning Strategy | ACCEPTED_DEFERRED | Initial physical partitioning is ACCEPTED_DEFERRED per Invariant #26. Foreign keys and tenant keys preserve partition-readiness without premature physical sub-table partitioning. |
| ADR-002 | Worker Runtime Isolation | LOCKED | Heavy analysis (taint, AST, CFG, dynamic sandbox, vector indexing) is strictly isolated in `workers/` runtime packages/containers; excluded from web SPA bundle. |
| ADR-003 | CAIM Envelope & Canonical ID Format | LOCKED | Standardized on CAIM V2.0.1 canonical envelope with deterministic UUIDs and SHA-256 fingerprint identifiers across all source artifacts (`packages/contracts`, `packages/caim`). |
| ADR-004 | FSM Non-Overwriting Versioning Lifecycle | LOCKED | Implemented append-only immutable AnalysisRuns and AgentVersions. Lifecycle state machine strictly prevents in-place mutation of analyzed artifacts (`packages/lifecycle`, Invariant #21B). |
| ADR-005 | Postgres-Native Queue & Outbox Pattern | LOCKED | Standardized on Postgres-backed atomic transactional outbox and durable leased workflow queue with exponential backoff and DLQ routing (`packages/workflow`). |
| ADR-006 | Diagnostic Engineering Console Architecture | LOCKED | Engineering diagnostic routes mounted under `/dev/*` with strict RBAC (`requireDiagnosticAccess`), tab routing, and JSON inspector drawers (`apps/web/src/components/dev`). |
| ADR-007 | Source Adapters & Quarantine Ingestion | LOCKED | Multi-source adapter framework isolating untrusted remote repositories into staged quarantine classification prior to AST extraction (`packages/source`). |
| ADR-008 | Multi-Language Syntax Parser Registry | LOCKED | Extensible multi-language parser registry supporting TypeScript/JavaScript, Python, and Go with source-span coordinate preservation (`packages/syntax`). |
| ADR-009 | CANE Canonicalization Pipeline | LOCKED | Standardized CANE normalization mappings, concept disambiguation, and version registry bindings (`packages/ontology`). |
| ADR-010 | Static Analysis Deterministic Ruleset & CFG | LOCKED | Implemented AST basic blocks, cyclomatic complexity calculations, interprocedural call graph reachability, and versioned static rule catalog with source span coordinates (`workers/static-analysis`). |
| ADR-011 | Phase Numbering & P10 Sequence History | RECONCILED | P10's functional scope (source discovery adapters and ingestion quarantine) was completed under P11 and P12 following the insertion of the diagnostic console shell at P09A. |
| ADR-012 | Dataflow & Taint Intelligence Engine Architecture | LOCKED | Implemented versioned Source, Sink, and Sanitizer registries with intra-function, interprocedural, and cross-file propagation. Enforced epistemic labeling (`INFERRED_TAINT_FLOW`), non-accusatory flow classifications (`POTENTIAL_*`), confidence scoring, and source-to-sink lineage evidence (`workers/static-analysis/taint`). |
