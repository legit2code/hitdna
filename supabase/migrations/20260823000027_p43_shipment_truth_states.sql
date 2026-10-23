-- Migration: 20260823000027_p43_shipment_truth_states.sql
-- Purpose: Support all shipping truth states in lifecycle.shipments
-- Reference: Prompt 02 - Shipping Truth States Architecture

DO $$
BEGIN
  -- Drop existing status check constraint if it exists
  IF EXISTS (
    SELECT 1 FROM pg_constraint 
    WHERE conname = 'shipments_status_check' 
    OR conrelid = 'lifecycle.shipments'::regclass AND contype = 'c'
  ) THEN
    ALTER TABLE lifecycle.shipments DROP CONSTRAINT IF EXISTS shipments_status_check;
  END IF;
END $$;

ALTER TABLE lifecycle.shipments 
  DROP CONSTRAINT IF EXISTS shipments_status_check;

ALTER TABLE lifecycle.shipments 
  ADD CONSTRAINT shipments_status_check 
  CHECK (status IN (
    'PENDING', 
    'IN_TRANSIT', 
    'DELIVERED', 
    'FAILED', 
    'NOT_CONFIGURED', 
    'PROVIDER_UNAVAILABLE', 
    'SIMULATED_DELIVERY'
  ));

ALTER TABLE lifecycle.shipments ADD COLUMN IF NOT EXISTS receipt_signature text NULL;
ALTER TABLE lifecycle.shipments ADD COLUMN IF NOT EXISTS truth_state text NULL DEFAULT 'UNKNOWN';
ALTER TABLE lifecycle.shipments ADD COLUMN IF NOT EXISTS error text NULL;
