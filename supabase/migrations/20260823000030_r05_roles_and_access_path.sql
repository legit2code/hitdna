-- Migration: 20260823000030_r05_roles_and_access_path.sql
-- Purpose:
--   1. Create authoritative database roles (caim_app, caim_system, caim_migrator) with strictly NOBYPASSRLS and NOSUPERUSER.
--   2. Grant permissions across all application schemas.
--   3. Replace security.is_system_bypass() to test role membership (pg_has_role(current_user, 'caim_system', 'member'))
--      eliminating all GUC-based bypass grants.
--   4. Update security.current_tenant_id() to support bound 'app.tenant_id'.
--   5. Provision security.system_tx_audit ledger for system transaction auditability.

-- 1. Create NOLOGIN, NOSUPERUSER, NOBYPASSRLS Roles
DO $$
BEGIN
  IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'caim_app') THEN
    CREATE ROLE caim_app NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE;
  ELSE
    ALTER ROLE caim_app NOSUPERUSER NOBYPASSRLS;
  END IF;

  IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'caim_system') THEN
    CREATE ROLE caim_system NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE;
  ELSE
    ALTER ROLE caim_system NOSUPERUSER NOBYPASSRLS;
  END IF;

  IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'caim_migrator') THEN
    CREATE ROLE caim_migrator NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE;
  ELSE
    ALTER ROLE caim_migrator NOSUPERUSER NOBYPASSRLS;
  END IF;
END
$$;

-- 2. Schema Permissions for caim_app and caim_system
DO $$
DECLARE
  s text;
  schemas text[] := ARRAY['public', 'security', 'source', 'analysis', 'intel', 'lifecycle', 'core', 'ops', 'audit'];
BEGIN
  FOREACH s IN ARRAY schemas LOOP
    IF EXISTS (SELECT FROM information_schema.schemata WHERE schema_name = s) THEN
      EXECUTE format('GRANT USAGE ON SCHEMA %I TO caim_app, caim_system, caim_migrator', s);
      EXECUTE format('GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA %I TO caim_app, caim_system, caim_migrator', s);
      EXECUTE format('GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA %I TO caim_app, caim_system, caim_migrator', s);
      EXECUTE format('ALTER DEFAULT PRIVILEGES IN SCHEMA %I GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO caim_app, caim_system, caim_migrator', s);
      EXECUTE format('ALTER DEFAULT PRIVILEGES IN SCHEMA %I GRANT USAGE, SELECT ON SEQUENCES TO caim_app, caim_system, caim_migrator', s);
    END IF;
  END LOOP;
END
$$;

-- Allow current user and admin logins to switch roles via SET LOCAL ROLE
GRANT caim_app TO CURRENT_USER;
GRANT caim_system TO CURRENT_USER;
GRANT caim_migrator TO CURRENT_USER;

DO $$
BEGIN
  IF EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'caim_ci_admin') THEN
    GRANT caim_app TO caim_ci_admin;
    GRANT caim_system TO caim_ci_admin;
    GRANT caim_migrator TO caim_ci_admin;
  END IF;
  IF EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'caim_app_user') THEN
    GRANT caim_app TO caim_app_user;
  END IF;
  IF EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'authenticated') THEN
    GRANT caim_app TO authenticated;
  END IF;
END
$$;

-- 3. Replace security.is_system_bypass() with Strict Role-Based Check
-- INVARIANT: No GUC (e.g. app.system_bypass) may ever grant privilege.
-- Only caim_system role membership grants system bypass.
CREATE OR REPLACE FUNCTION security.is_system_bypass()
RETURNS boolean AS $$
BEGIN
  RETURN pg_has_role(current_user, 'caim_system', 'member');
EXCEPTION WHEN OTHERS THEN
  RETURN false;
END;
$$ LANGUAGE plpgsql STABLE;

-- 4. Update security.current_tenant_id() for app.tenant_id with app.current_tenant_id fallback
CREATE OR REPLACE FUNCTION security.current_tenant_id()
RETURNS uuid AS $$
DECLARE
  v_tenant text;
BEGIN
  v_tenant := NULLIF(TRIM(current_setting('app.tenant_id', true)), '');
  IF v_tenant IS NULL THEN
    v_tenant := NULLIF(TRIM(current_setting('app.current_tenant_id', true)), '');
  END IF;
  
  IF v_tenant IS NULL THEN
    RETURN NULL;
  END IF;

  RETURN v_tenant::uuid;
EXCEPTION WHEN OTHERS THEN
  RETURN NULL;
END;
$$ LANGUAGE plpgsql STABLE;

-- 5. System Transaction Audit Ledger
CREATE TABLE IF NOT EXISTS security.system_tx_audit (
  audit_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  actor text NOT NULL,
  reason text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);

GRANT SELECT, INSERT ON security.system_tx_audit TO caim_app, caim_system, caim_migrator;
