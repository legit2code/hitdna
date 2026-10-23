-- Migration: 20260823000019_p37_rate_limit_buckets.sql
-- Purpose: Shared distributed rate-limiting buckets across multi-instance server deployments
-- Document Reference: Architecture V2.0.1 Document 13, 17, 37

CREATE TABLE IF NOT EXISTS security.rate_limit_buckets (
  bucket_key text PRIMARY KEY,
  count integer NOT NULL DEFAULT 1,
  reset_at bigint NOT NULL,
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_rate_limit_reset_at ON security.rate_limit_buckets(reset_at);
