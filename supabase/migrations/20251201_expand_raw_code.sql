-- Migration: Allow larger QR payloads
-- Raw material codes exceed the legacy VARCHAR(20) limit on stock_scans.raw_code.

BEGIN;

ALTER TABLE IF EXISTS public.stock_scans
    ALTER COLUMN raw_code TYPE text
    USING raw_code::text;

COMMIT;
