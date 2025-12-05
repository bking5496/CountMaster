-- Migration: Add unique constraint for FP pallet scans to prevent race condition duplicates
-- Date: 2025-12-05
-- Description: Ensures that within a session, the same batch_number + pallet_number 
--              combination cannot be inserted twice, even during concurrent offline syncs

BEGIN;

-- Create a unique index that only applies to FP scans with pallet numbers
-- This allows RM scans and FP 5-digit manual scans (no pallet) to have duplicates
CREATE UNIQUE INDEX IF NOT EXISTS idx_stock_scans_unique_fp_pallet 
ON stock_scans (session_id, batch_number, pallet_number)
WHERE session_type = 'FP' AND pallet_number IS NOT NULL;

-- Add a comment explaining the constraint
COMMENT ON INDEX idx_stock_scans_unique_fp_pallet IS 
'Prevents duplicate FP pallet scans (same batch+pallet) within a session. 
Handles race conditions when multiple offline devices sync simultaneously.';

COMMIT;
