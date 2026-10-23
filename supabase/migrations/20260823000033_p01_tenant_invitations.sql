-- Migration: 20260823000033_p01_tenant_invitations.sql
-- Purpose: Durable DB-backed tenant invitation store with fail-closed RLS and atomic redemption support.
-- Reference: P1 Critical Security Remediation

CREATE TABLE IF NOT EXISTS security.tenant_invitations (
  invitation_id text PRIMARY KEY,
  tenant_id text NOT NULL,
  intended_role text NOT NULL DEFAULT 'user',
  email text,
  expires_at timestamptz NOT NULL,
  used_at timestamptz,
  revoked_at timestamptz,
  created_by text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_tenant_invitations_tenant ON security.tenant_invitations(tenant_id);
CREATE INDEX IF NOT EXISTS idx_tenant_invitations_email ON security.tenant_invitations(email);
CREATE INDEX IF NOT EXISTS idx_tenant_invitations_redemption ON security.tenant_invitations(invitation_id, used_at, revoked_at, expires_at);

-- Register in classification catalog
INSERT INTO security.table_tenant_classifications (table_schema, table_name, classification, description)
VALUES ('security', 'tenant_invitations', 'TENANT_OWNED', 'Durable tenant invitations with single-use atomic redemption')
ON CONFLICT (table_schema, table_name) DO UPDATE 
SET classification = EXCLUDED.classification, description = EXCLUDED.description;

-- Enable and FORCE RLS
ALTER TABLE security.tenant_invitations ENABLE ROW LEVEL SECURITY;
ALTER TABLE security.tenant_invitations FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS tenant_invitations_isolation ON security.tenant_invitations;
CREATE POLICY tenant_invitations_isolation ON security.tenant_invitations
  FOR ALL
  USING (
    security.is_system_bypass()
    OR (
      security.current_tenant_id() IS NOT NULL 
      AND tenant_id = security.current_tenant_id()::text
    )
  )
  WITH CHECK (
    security.is_system_bypass()
    OR (
      security.current_tenant_id() IS NOT NULL 
      AND tenant_id = security.current_tenant_id()::text
    )
  );

GRANT SELECT, INSERT, UPDATE ON TABLE security.tenant_invitations TO caim_app, caim_system;
