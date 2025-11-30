-- Migration: Ensure stock_scans table matches PWA expectations
-- Run in Supabase SQL editor or via supabase migration tooling

BEGIN;

-- Add missing columns
ALTER TABLE IF EXISTS stock_scans
    ADD COLUMN IF NOT EXISTS session_id text,
    ADD COLUMN IF NOT EXISTS session_type text DEFAULT 'FP',
    ADD COLUMN IF NOT EXISTS expiry_date date,
    ADD COLUMN IF NOT EXISTS location text,
    ADD COLUMN IF NOT EXISTS unit_type text DEFAULT 'cases',
    ADD COLUMN IF NOT EXISTS raw_code text,
    ADD COLUMN IF NOT EXISTS cases_on_pallet integer,
    ADD COLUMN IF NOT EXISTS created_by text;

-- Ensure timestamp column exists
ALTER TABLE IF EXISTS stock_scans
    ADD COLUMN IF NOT EXISTS scanned_at timestamptz DEFAULT now();

-- Indexes for performance
CREATE INDEX IF NOT EXISTS idx_stock_scans_session_id ON stock_scans(session_id);
CREATE INDEX IF NOT EXISTS idx_stock_scans_session_type ON stock_scans(session_type);
CREATE INDEX IF NOT EXISTS idx_stock_scans_batch_pallet ON stock_scans(batch_number, pallet_number);

-- Stock takes table (session metadata)
CREATE TABLE IF NOT EXISTS stock_takes (
    id text PRIMARY KEY,
    session_type text NOT NULL,
    session_number integer NOT NULL,
    take_date date NOT NULL,
    status text DEFAULT 'active',
    started_by text,
    started_at timestamptz DEFAULT now(),
    completed_at timestamptz,
    metadata jsonb DEFAULT '{}'::jsonb
);

CREATE INDEX IF NOT EXISTS idx_stock_takes_date_type ON stock_takes(take_date, session_type);

-- RLS policies (adjust to your auth strategy)
ALTER TABLE stock_scans ENABLE ROW LEVEL SECURITY;
ALTER TABLE stock_takes ENABLE ROW LEVEL SECURITY;

DO $$ BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_policies WHERE schemaname = 'public' AND tablename = 'stock_scans' AND policyname = 'Allow all access to stock_scans'
    ) THEN
        CREATE POLICY "Allow all access to stock_scans" ON stock_scans FOR ALL USING (true) WITH CHECK (true);
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM pg_policies WHERE schemaname = 'public' AND tablename = 'stock_takes' AND policyname = 'Allow all access to stock_takes'
    ) THEN
        CREATE POLICY "Allow all access to stock_takes" ON stock_takes FOR ALL USING (true) WITH CHECK (true);
    END IF;
END $$;

COMMIT;
