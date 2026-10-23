-- Migration: 20260823000023_p39_email_verification.sql
-- Purpose: Add email verification flags and verification token columns to security.principals
-- Document Reference: Architecture V2.0.1 Document 13 (Authentication & Identity)

ALTER TABLE security.principals
  ADD COLUMN IF NOT EXISTS email_verified boolean NOT NULL DEFAULT false,
  ADD COLUMN IF NOT EXISTS email_verification_token text NULL,
  ADD COLUMN IF NOT EXISTS email_verification_expires_at timestamptz NULL;

-- Ensure seeded admin / existing principals are marked verified
UPDATE security.principals SET email_verified = true WHERE email_verified = false;

CREATE INDEX IF NOT EXISTS idx_principals_verification_token ON security.principals(email_verification_token);
