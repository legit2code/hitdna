-- Migration: 20260823000029_r04_service_accounts_and_revocations.sql
-- Purpose: Service accounts, token revocation, token versioning, and refresh token families (R04)

-- 1. Token version on principals
ALTER TABLE security.principals
  ADD COLUMN IF NOT EXISTS token_version integer NOT NULL DEFAULT 1;

-- 2. Token revocation blacklist
CREATE TABLE IF NOT EXISTS security.revoked_tokens (
  jti text PRIMARY KEY,
  principal_id text NOT NULL,
  revoked_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL,
  reason text NULL
);

CREATE INDEX IF NOT EXISTS idx_revoked_tokens_principal ON security.revoked_tokens(principal_id);
CREATE INDEX IF NOT EXISTS idx_revoked_tokens_expires ON security.revoked_tokens(expires_at);

-- 3. Refresh token family and reuse detection tracking
ALTER TABLE security.refresh_tokens
  ADD COLUMN IF NOT EXISTS family_id text NULL,
  ADD COLUMN IF NOT EXISTS used_at timestamptz NULL;

UPDATE security.refresh_tokens
  SET family_id = token_id::text
  WHERE family_id IS NULL;

CREATE INDEX IF NOT EXISTS idx_refresh_tokens_family ON security.refresh_tokens(family_id);

-- 4. Service Accounts Registry
CREATE TABLE IF NOT EXISTS security.service_accounts (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name text UNIQUE NOT NULL,
  allowed_tenants jsonb NOT NULL DEFAULT '[]'::jsonb,
  allowed_scopes jsonb NOT NULL DEFAULT '[]'::jsonb,
  credential_hash text NULL,
  public_key text NULL,
  status text NOT NULL DEFAULT 'ACTIVE',
  capabilities jsonb NOT NULL DEFAULT '[]'::jsonb,
  rotated_at timestamptz NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_service_accounts_name ON security.service_accounts(name);
CREATE INDEX IF NOT EXISTS idx_service_accounts_status ON security.service_accounts(status);
