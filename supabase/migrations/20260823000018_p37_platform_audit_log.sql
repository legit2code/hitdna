-- Migration: 20260823000018_p37_platform_audit_log.sql
-- Purpose: Unified append-only platform audit log across all analysis, discovery, ingestion, scoring overrides, and composer operations
-- Document Reference: Architecture V2.0.1 Document 13, 17, 18, 29

CREATE TABLE IF NOT EXISTS security.platform_audit_log (
  audit_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  principal_id text NOT NULL,
  action text NOT NULL,
  target_entity_type text NOT NULL,
  target_entity_id text NOT NULL,
  timestamp timestamptz NOT NULL DEFAULT now(),
  outcome text NOT NULL CHECK (outcome IN ('SUCCESS', 'FAILURE', 'DENIED', 'REFUSED', 'ERROR')),
  client_ip text NULL,
  user_agent text NULL,
  correlation_id text NULL,
  details jsonb NOT NULL DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_platform_audit_timestamp ON security.platform_audit_log(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_platform_audit_principal ON security.platform_audit_log(principal_id);
CREATE INDEX IF NOT EXISTS idx_platform_audit_action ON security.platform_audit_log(action);
CREATE INDEX IF NOT EXISTS idx_platform_audit_target ON security.platform_audit_log(target_entity_type, target_entity_id);
