-- Migration: Allow decimal quantities for raw materials
-- Change stock_scans.actual_cases from integer to numeric to support kg entries
-- without failing inserts.

BEGIN;

ALTER TABLE IF EXISTS public.stock_scans
    ALTER COLUMN actual_cases TYPE numeric(18,4)
    USING CASE
        WHEN actual_cases IS NULL THEN NULL
        ELSE actual_cases::numeric
    END;

COMMIT;
