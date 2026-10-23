-- Migration: 20260823000002_p03_security_tenants_and_scopes.sql
-- Purpose: Create security tenant spine, access scopes, roles, and classifications
-- Document Reference: Architecture V2.0.1 Document 21 (Tenant Scope & Inheritance) & Document 13 (Security Classification)

-- 1. Security Classifications Table
CREATE TABLE IF NOT EXISTS security.security_classifications (
  security_classification_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  code text UNIQUE NOT NULL,
  rank integer UNIQUE NOT NULL,
  description text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT ck_classification_code CHECK (code IN ('PUBLIC_METADATA', 'INTERNAL', 'SENSITIVE', 'VAULT_RESTRICTED'))
);

-- 2. Tenants Table (SaaS / Customer Tenant Identity, separate from core.organizations)
CREATE TABLE IF NOT EXISTS security.tenants (
  tenant_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_key text UNIQUE NOT NULL,
  display_name text NOT NULL,
  status text NOT NULL DEFAULT 'ACTIVE' CHECK (status IN ('ACTIVE', 'SUSPENDED', 'DECOMMISSIONED')),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NULL
);

CREATE INDEX IF NOT EXISTS idx_tenants_status ON security.tenants(status);

-- 3. Roles Table
CREATE TABLE IF NOT EXISTS security.roles (
  role_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  role_key text UNIQUE NOT NULL,
  description text NOT NULL,
  status text NOT NULL DEFAULT 'ACTIVE' CHECK (status IN ('ACTIVE', 'DEPRECATED')),
  created_at timestamptz NOT NULL DEFAULT now()
);

-- 4. Tenant Memberships Table
CREATE TABLE IF NOT EXISTS security.tenant_memberships (
  tenant_membership_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL REFERENCES security.tenants(tenant_id) ON DELETE CASCADE,
  principal_id text NOT NULL,
  role_id uuid NOT NULL REFERENCES security.roles(role_id),
  status text NOT NULL DEFAULT 'ACTIVE' CHECK (status IN ('ACTIVE', 'SUSPENDED', 'REVOKED')),
  joined_at timestamptz NOT NULL DEFAULT now(),
  revoked_at timestamptz NULL,
  CONSTRAINT uq_tenant_membership_active UNIQUE (tenant_id, principal_id, role_id)
);

CREATE INDEX IF NOT EXISTS idx_tenant_memberships_principal ON security.tenant_memberships(principal_id);
CREATE INDEX IF NOT EXISTS idx_tenant_memberships_tenant ON security.tenant_memberships(tenant_id);

-- 5. Access Scopes Table
-- Enforces:
--   scope_type = 'PLATFORM'     -> tenant_id IS NULL
--   scope_type = 'ORGANIZATION' -> tenant_id IS NOT NULL
-- Exactly one active PLATFORM scope across the platform
-- Each active tenant has exactly one canonical ORGANIZATION scope
CREATE TABLE IF NOT EXISTS security.access_scopes (
  scope_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  scope_type text NOT NULL CHECK (scope_type IN ('PLATFORM', 'ORGANIZATION')),
  tenant_id uuid NULL REFERENCES security.tenants(tenant_id) ON DELETE CASCADE,
  created_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT ck_access_scope_invariants CHECK (
    (scope_type = 'PLATFORM' AND tenant_id IS NULL) OR
    (scope_type = 'ORGANIZATION' AND tenant_id IS NOT NULL)
  )
);

-- Exactly one PLATFORM scope
CREATE UNIQUE INDEX IF NOT EXISTS uq_single_platform_scope ON security.access_scopes ((1)) WHERE (scope_type = 'PLATFORM');

-- Exactly one canonical ORGANIZATION scope per tenant
CREATE UNIQUE INDEX IF NOT EXISTS uq_tenant_organization_scope ON security.access_scopes (tenant_id) WHERE (scope_type = 'ORGANIZATION');

-- 6. User Roles Table (Platform-wide Roles)
CREATE TABLE IF NOT EXISTS security.user_roles (
  user_role_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  principal_id text NOT NULL,
  role_id uuid NOT NULL REFERENCES security.roles(role_id),
  granted_by text NOT NULL,
  granted_at timestamptz NOT NULL DEFAULT now(),
  revoked_at timestamptz NULL,
  CONSTRAINT uq_user_roles_active UNIQUE (principal_id, role_id)
);

CREATE INDEX IF NOT EXISTS idx_user_roles_principal ON security.user_roles(principal_id);

-- 7. Access Grants Table (Granular Capability Scopes)
CREATE TABLE IF NOT EXISTS security.access_grants (
  access_grant_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  principal_id text NOT NULL,
  grant_type text NOT NULL,
  target_scope uuid NULL REFERENCES security.access_scopes(scope_id) ON DELETE CASCADE,
  granted_by text NOT NULL,
  granted_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NULL,
  revoked_at timestamptz NULL
);

CREATE INDEX IF NOT EXISTS idx_access_grants_principal ON security.access_grants(principal_id);
CREATE INDEX IF NOT EXISTS idx_access_grants_scope ON security.access_grants(target_scope);
