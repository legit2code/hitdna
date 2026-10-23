-- Migration: 20260823000015_p06_security_principals_and_users.sql
-- Purpose: Create security.principals table for authenticated identities, password hashing, and session validation
-- Document Reference: Architecture V2.0.1 Document 13 (Authentication & Principal Context) & Document 21 (Tenant Scope)

CREATE TABLE IF NOT EXISTS security.principals (
  principal_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  email text UNIQUE NOT NULL,
  hashed_password text NOT NULL,
  external_identity_provider_id text NULL,
  roles text[] NOT NULL DEFAULT '{"user"}',
  tenant_id uuid NULL REFERENCES security.tenants(tenant_id) ON DELETE SET NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  last_login_at timestamptz NULL
);

CREATE INDEX IF NOT EXISTS idx_principals_email ON security.principals(email);
CREATE INDEX IF NOT EXISTS idx_principals_tenant ON security.principals(tenant_id);

CREATE TABLE IF NOT EXISTS security.refresh_tokens (
  token_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  principal_id uuid NOT NULL REFERENCES security.principals(principal_id) ON DELETE CASCADE,
  token_hash text UNIQUE NOT NULL,
  expires_at timestamptz NOT NULL,
  revoked_at timestamptz NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_refresh_tokens_principal ON security.refresh_tokens(principal_id);
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_hash ON security.refresh_tokens(token_hash);
