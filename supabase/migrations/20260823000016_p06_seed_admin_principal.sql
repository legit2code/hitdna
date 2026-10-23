-- Migration: 20260823000016_p06_seed_admin_principal.sql
-- Purpose: REMOVED INSECURE PASSWORD SEEDING (Security Hardening Refactoring)
-- Document Reference: Architecture V2.0.1 Document 13 (Authentication & Principal Context)
--
-- SECURITY NOTICE:
-- Static password seeding in migrations has been permanently removed from the production migration path.
-- Hardcoded credentials and 'ON CONFLICT (email) DO UPDATE SET hashed_password = ...' clauses are forbidden
-- to prevent migration replays from resetting administrative accounts back to compromised passwords.
--
-- Production administrator bootstrapping is handled exclusively via:
--   1. One-time cryptographically secure random secret generated at deployment and delivered out-of-band
--   2. Out-of-band first-run enrollment flow (/api/auth/bootstrap/enroll)
--   3. External Identity Provider (SSO/OIDC) assertion
--
-- Preserving migration entry for schema_migrations version ledger continuity.
SELECT 1;

