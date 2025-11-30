-- Migration: Expand batch_number/pallet_number capacity for QR payloads
-- Reason: RM codes like CM155748678 exceed the legacy VARCHAR(5) limit.

BEGIN;

ALTER TABLE IF EXISTS public.stock_scans
    ALTER COLUMN batch_number TYPE text
    USING batch_number::text;

ALTER TABLE IF EXISTS public.stock_scans
    ALTER COLUMN pallet_number TYPE text
    USING pallet_number::text;

COMMIT;
