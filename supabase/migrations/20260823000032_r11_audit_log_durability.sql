-- Migration: 20260823000032_r11_audit_log_durability.sql
-- Purpose: Durable, append-only, tamper-evident audit log with DB-backed chain head,
--          trigger-enforced mutation prohibition, and hash-chain synchronization.
-- Reference: R11 Audit Log Durability (F-12)

-- 1. Create durable audit chain head tracker table
CREATE TABLE IF NOT EXISTS security.audit_chain_head (
  stream_id text PRIMARY KEY,
  seq bigint NOT NULL DEFAULT 0,
  hash text NOT NULL DEFAULT 'GENESIS_0000000000000000000000000000000000000000000000000000000000000000',
  updated_at timestamptz NOT NULL DEFAULT now()
);

-- Seed initial global stream head
INSERT INTO security.audit_chain_head (stream_id, seq, hash, updated_at)
VALUES ('global', 0, 'GENESIS_0000000000000000000000000000000000000000000000000000000000000000', now())
ON CONFLICT (stream_id) DO NOTHING;

-- 2. Extend security.platform_audit_log with stream_id and hash_algorithm
ALTER TABLE security.platform_audit_log ADD COLUMN IF NOT EXISTS stream_id text NOT NULL DEFAULT 'global';
ALTER TABLE security.platform_audit_log ADD COLUMN IF NOT EXISTS hash_algorithm text NOT NULL DEFAULT 'sha256-rfc8785-v1';

CREATE INDEX IF NOT EXISTS idx_platform_audit_stream_seq ON security.platform_audit_log(stream_id, sequence_number);
CREATE INDEX IF NOT EXISTS idx_platform_audit_hash_algo ON security.platform_audit_log(hash_algorithm);

-- 3. Register audit_chain_head in Table Tenant Classifications Catalog
INSERT INTO security.table_tenant_classifications (table_schema, table_name, classification, description)
VALUES ('security', 'audit_chain_head', 'GLOBAL', 'Chain head tracker for tamper-evident append-only audit streams')
ON CONFLICT (table_schema, table_name) DO UPDATE 
SET classification = EXCLUDED.classification, description = EXCLUDED.description;

-- 4. Enforce RLS on audit_chain_head
ALTER TABLE security.audit_chain_head ENABLE ROW LEVEL SECURITY;
ALTER TABLE security.audit_chain_head FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS audit_chain_head_isolation ON security.audit_chain_head;
CREATE POLICY audit_chain_head_isolation ON security.audit_chain_head
  FOR ALL
  USING (
    security.is_system_bypass()
    OR (
      security.current_tenant_id() IS NOT NULL 
      AND stream_id = 'tenant:' || security.current_tenant_id()::text
    )
    OR stream_id = 'global'
  )
  WITH CHECK (
    security.is_system_bypass()
    OR (
      security.current_tenant_id() IS NOT NULL 
      AND stream_id = 'tenant:' || security.current_tenant_id()::text
    )
    OR stream_id = 'global'
  );

-- 5. Strict Append-Only Permissions Governance
-- Revoke UPDATE, DELETE, TRUNCATE from app roles
REVOKE UPDATE, DELETE, TRUNCATE ON TABLE security.platform_audit_log FROM caim_app, caim_system, PUBLIC;
GRANT SELECT, INSERT ON TABLE security.platform_audit_log TO caim_app, caim_system;

GRANT SELECT, INSERT, UPDATE ON TABLE security.audit_chain_head TO caim_app, caim_system;
REVOKE DELETE, TRUNCATE ON TABLE security.audit_chain_head FROM caim_app, caim_system, PUBLIC;

-- 6. Trigger preventing ANY UPDATE or DELETE on security.platform_audit_log (Fail-Closed)
CREATE OR REPLACE FUNCTION security.prevent_audit_log_mutation()
RETURNS trigger AS $$
BEGIN
  RAISE EXCEPTION 'TAMPER_ATTEMPT: security.platform_audit_log is strictly append-only. UPDATE, DELETE, and TRUNCATE operations are prohibited.';
END;
$$ LANGUAGE plpgsql;

DO $$
BEGIN
  DROP TRIGGER IF EXISTS trg_prevent_audit_log_mutation ON security.platform_audit_log;
  CREATE TRIGGER trg_prevent_audit_log_mutation
  BEFORE UPDATE OR DELETE ON security.platform_audit_log
  FOR EACH ROW EXECUTE FUNCTION security.prevent_audit_log_mutation();
EXCEPTION
  WHEN undefined_table THEN NULL;
END $$;
