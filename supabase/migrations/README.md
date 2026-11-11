# Database Migrations

This directory contains the ordered PostgreSQL schema migrations used by CAIM. Files are named with sortable timestamps and phase identifiers; apply them in lexical order using the repository migration tooling.

## Migration responsibilities

The sequence establishes PostgreSQL extensions and schemas, tenant/access scopes, canonical identity and source data, ontology/version registries, analysis foundations, evidence and decision records, knowledge/pgvector, lifecycle and operations, authentication/RLS, audit integrity, and later hardening changes.

## Safe migration practice

1. Review the target migration and its dependencies.
2. Check the architecture and ADRs for locked schema and tenant-scope invariants.
3. Run `pnpm run migrations:safety` and the migration test suites.
4. Apply migrations through a controlled database deployment process.
5. Verify the applied migration head and required tables.
6. Run RLS/catalog and cross-tenant tests against a real PostgreSQL environment where required.

Production application startup verifies schema state and fails closed when required migrations are missing. It does not run DDL migrations automatically.

Do not edit historical migrations that have already been applied in a shared environment. Add a forward migration and corresponding rollback/recovery guidance where applicable.
