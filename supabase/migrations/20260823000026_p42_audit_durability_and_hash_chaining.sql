-- Migration: 20260823000026_p42_audit_durability_and_hash_chaining.sql
-- Purpose: Durable, tamper-evident, fail-secure audit log with hash-chaining, criticality classifications, and tenant RLS isolation
-- Reference: Prompt 3 & Prompt 4 Architecture Hardening

-- 1. Schema Extensions for Tamper-Evident Hash Chaining and Classification
ALTER TABLE security.platform_audit_log ADD COLUMN IF NOT EXISTS tenant_id uuid REFERENCES security.tenants(tenant_id);
ALTER TABLE security.platform_audit_log ADD COLUMN IF NOT EXISTS criticality text NOT NULL DEFAULT 'OPERATIONAL' CHECK (criticality IN ('DIAGNOSTIC', 'OPERATIONAL', 'SECURITY', 'SECURITY_CRITICAL'));
ALTER TABLE security.platform_audit_log ADD COLUMN IF NOT EXISTS classification text NOT NULL DEFAULT 'RESTRICTED';
ALTER TABLE security.platform_audit_log ADD COLUMN IF NOT EXISTS sequence_number bigint NOT NULL DEFAULT 1;
ALTER TABLE security.platform_audit_log ADD COLUMN IF NOT EXISTS previous_hash text NOT NULL DEFAULT 'GENESIS_0000000000000000000000000000000000000000000000000000000000000000';
ALTER TABLE security.platform_audit_log ADD COLUMN IF NOT EXISTS hash text NOT NULL DEFAULT '';

-- 2. Register Table in Tenant Classifications Catalog for Zero-Drift RLS Governance
INSERT INTO security.table_tenant_classifications (table_schema, table_name, classification, description)
VALUES ('security', 'platform_audit_log', 'TENANT_OWNED', 'Append-only tamper-evident platform audit log with cryptographic hash-chaining')
ON CONFLICT (table_schema, table_name) DO UPDATE 
SET classification = EXCLUDED.classification, description = EXCLUDED.description;

-- 3. Enforce Fail-Closed RLS on Audit Log
ALTER TABLE security.platform_audit_log ENABLE ROW LEVEL SECURITY;
ALTER TABLE security.platform_audit_log FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS platform_audit_log_tenant_isolation ON security.platform_audit_log;
CREATE POLICY platform_audit_log_tenant_isolation ON security.platform_audit_log
  FOR ALL
  USING (
    security.is_system_bypass()
    OR (
      security.current_tenant_id() IS NOT NULL 
      AND tenant_id = security.current_tenant_id()
    )
  )
  WITH CHECK (
    security.is_system_bypass()
    OR (
      security.current_tenant_id() IS NOT NULL 
      AND tenant_id = security.current_tenant_id()
    )
  );

-- 4. High-Performance Indexes for Audit Verification & Querying
CREATE INDEX IF NOT EXISTS idx_platform_audit_tenant_seq ON security.platform_audit_log(tenant_id, sequence_number);
CREATE INDEX IF NOT EXISTS idx_platform_audit_criticality ON security.platform_audit_log(criticality);
CREATE INDEX IF NOT EXISTS idx_platform_audit_hash ON security.platform_audit_log(hash);
