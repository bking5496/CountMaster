-- Migration: Supabase hardening for Stock Scanner PWA
-- Features: session metadata, heartbeats, lifecycle events, validation, logging, roles

BEGIN;

CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- ==========================================
-- Core stock_scans table additions
-- ==========================================
ALTER TABLE IF EXISTS public.stock_scans
    ADD COLUMN IF NOT EXISTS session_id text,
    ADD COLUMN IF NOT EXISTS session_type text DEFAULT 'FP',
    ADD COLUMN IF NOT EXISTS expiry_date date,
    ADD COLUMN IF NOT EXISTS location text,
    ADD COLUMN IF NOT EXISTS site text,
    ADD COLUMN IF NOT EXISTS aisle text,
    ADD COLUMN IF NOT EXISTS rack text,
    ADD COLUMN IF NOT EXISTS location_zone_id uuid,
    ADD COLUMN IF NOT EXISTS unit_type text DEFAULT 'cases',
    ADD COLUMN IF NOT EXISTS raw_code text,
    ADD COLUMN IF NOT EXISTS cases_on_pallet integer,
    ADD COLUMN IF NOT EXISTS created_by text,
    ADD COLUMN IF NOT EXISTS updated_at timestamptz DEFAULT now();

ALTER TABLE IF EXISTS public.stock_scans
    ADD COLUMN IF NOT EXISTS scanned_at timestamptz DEFAULT now();

DO $$ BEGIN
    IF EXISTS (
        SELECT 1
        FROM information_schema.columns
                WHERE table_schema = 'public'
                    AND table_name = 'stock_scans'
          AND column_name = 'session_id'
    ) THEN
                EXECUTE 'CREATE INDEX IF NOT EXISTS idx_stock_scans_session_id ON public.stock_scans(session_id)';
    END IF;
END $$;

DO $$ BEGIN
    IF EXISTS (
        SELECT 1
        FROM information_schema.columns
                WHERE table_schema = 'public'
                    AND table_name = 'stock_scans'
          AND column_name = 'session_type'
    ) THEN
                EXECUTE 'CREATE INDEX IF NOT EXISTS idx_stock_scans_session_type ON public.stock_scans(session_type)';
    END IF;
END $$;

CREATE INDEX IF NOT EXISTS idx_stock_scans_batch_pallet ON public.stock_scans(batch_number, pallet_number);

DO $$ BEGIN
    IF EXISTS (
        SELECT 1
        FROM information_schema.columns
                WHERE table_schema = 'public'
                    AND table_name = 'stock_scans'
          AND column_name = 'location_zone_id'
    ) THEN
                EXECUTE 'CREATE INDEX IF NOT EXISTS idx_stock_scans_location_zone ON public.stock_scans(location_zone_id)';
    END IF;
END $$;

-- ==========================================
-- Session metadata + lifecycle tables
-- ==========================================
CREATE TABLE IF NOT EXISTS public.stock_takes (
    id text PRIMARY KEY,
    session_type text NOT NULL,
    session_number integer NOT NULL,
    take_date date NOT NULL,
    status text DEFAULT 'active',
    started_by text,
    started_at timestamptz DEFAULT now(),
    paused_at timestamptz,
    resumed_at timestamptz,
    completed_at timestamptz,
    metadata jsonb DEFAULT '{}'::jsonb
);

ALTER TABLE IF EXISTS public.stock_takes
    ADD COLUMN IF NOT EXISTS id text,
    ADD COLUMN IF NOT EXISTS session_type text DEFAULT 'FP',
    ADD COLUMN IF NOT EXISTS session_number integer DEFAULT 1,
    ADD COLUMN IF NOT EXISTS take_date date DEFAULT current_date,
    ADD COLUMN IF NOT EXISTS status text DEFAULT 'active',
    ADD COLUMN IF NOT EXISTS started_by text,
    ADD COLUMN IF NOT EXISTS started_at timestamptz DEFAULT now(),
    ADD COLUMN IF NOT EXISTS paused_at timestamptz,
    ADD COLUMN IF NOT EXISTS resumed_at timestamptz,
    ADD COLUMN IF NOT EXISTS completed_at timestamptz,
    ADD COLUMN IF NOT EXISTS metadata jsonb DEFAULT '{}'::jsonb;

DO $$
BEGIN
    UPDATE public.stock_takes
    SET id = gen_random_uuid()::text
    WHERE id IS NULL;
END $$;

ALTER TABLE IF EXISTS public.stock_takes
    ALTER COLUMN id SET NOT NULL;

ALTER TABLE IF EXISTS public.stock_takes
    ALTER COLUMN id SET DEFAULT gen_random_uuid()::text;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conrelid = 'public.stock_takes'::regclass
          AND conname = 'stock_takes_id_key'
    ) THEN
        ALTER TABLE public.stock_takes
            ADD CONSTRAINT stock_takes_id_key UNIQUE (id);
    END IF;
END $$;

ALTER TABLE IF EXISTS public.stock_takes
    ALTER COLUMN session_type SET NOT NULL;

ALTER TABLE IF EXISTS public.stock_takes
    ALTER COLUMN session_type DROP DEFAULT;

ALTER TABLE IF EXISTS public.stock_takes
    ALTER COLUMN session_number SET NOT NULL;

ALTER TABLE IF EXISTS public.stock_takes
    ALTER COLUMN session_number DROP DEFAULT;

ALTER TABLE IF EXISTS public.stock_takes
    ALTER COLUMN take_date SET NOT NULL;

ALTER TABLE IF EXISTS public.stock_takes
    ALTER COLUMN take_date DROP DEFAULT;

ALTER TABLE IF EXISTS public.stock_takes
    ALTER COLUMN status SET DEFAULT 'active';

CREATE INDEX IF NOT EXISTS idx_stock_takes_date_type ON public.stock_takes(take_date, session_type);

CREATE TABLE IF NOT EXISTS public.session_devices (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    session_id text REFERENCES public.stock_takes(id) ON DELETE CASCADE,
    device_id text NOT NULL,
    user_name text,
    role text DEFAULT 'operator',
    status text DEFAULT 'active',
    last_seen timestamptz DEFAULT now(),
    joined_at timestamptz DEFAULT now(),
    left_at timestamptz,
    UNIQUE(session_id, device_id)
);

DO $$
BEGIN
    WITH ranked AS (
        SELECT id,
               ROW_NUMBER() OVER (PARTITION BY session_id, device_id ORDER BY COALESCE(last_seen, joined_at) DESC, id DESC) AS rn
        FROM public.session_devices
    )
    DELETE FROM public.session_devices
    WHERE id IN (SELECT id FROM ranked WHERE rn > 1);
END $$;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conrelid = 'public.session_devices'::regclass
          AND conname = 'session_devices_session_device_key'
    ) THEN
        ALTER TABLE public.session_devices
            ADD CONSTRAINT session_devices_session_device_key UNIQUE (session_id, device_id);
    END IF;
END $$;

CREATE TABLE IF NOT EXISTS public.session_status_events (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    session_id text REFERENCES public.stock_takes(id) ON DELETE CASCADE,
    previous_status text,
    next_status text NOT NULL,
    reason text,
    actor text,
    actor_device_id text,
    metadata jsonb DEFAULT '{}'::jsonb,
    created_at timestamptz DEFAULT now()
);

-- ==========================================
-- Location hierarchy tables
-- ==========================================
CREATE TABLE IF NOT EXISTS public.location_zones (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    site text NOT NULL,
    aisle text NOT NULL,
    rack text,
    description text,
    metadata jsonb DEFAULT '{}'::jsonb,
    created_at timestamptz DEFAULT now()
);

DO $$ BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'fk_stock_scans_location_zone'
    ) THEN
        ALTER TABLE IF EXISTS public.stock_scans
            ADD CONSTRAINT fk_stock_scans_location_zone
            FOREIGN KEY (location_zone_id) REFERENCES public.location_zones(id);
    END IF;
END $$;

-- ==========================================
-- Audit + logging tables
-- ==========================================
CREATE TABLE IF NOT EXISTS public.scan_audit_logs (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id text,
    action text NOT NULL,
    actor text,
    actor_device_id text,
    previous_data jsonb,
    new_data jsonb,
    created_at timestamptz DEFAULT now()
);

CREATE TABLE IF NOT EXISTS public.event_logs (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    event_type text NOT NULL,
    severity text DEFAULT 'info',
    session_id text,
    device_id text,
    payload jsonb DEFAULT '{}'::jsonb,
    created_at timestamptz DEFAULT now()
);

-- ==========================================
-- Role management + helpers
-- ==========================================
CREATE TABLE IF NOT EXISTS public.app_roles (
    user_id uuid PRIMARY KEY,
    email text,
    role text NOT NULL CHECK (role IN ('operator','supervisor','admin')),
    created_at timestamptz DEFAULT now()
);

CREATE OR REPLACE FUNCTION current_app_role()
RETURNS text
LANGUAGE plpgsql
STABLE
AS $$
DECLARE
    claim text;
    mapped text;
BEGIN
    claim := (auth.jwt()->>'app_role');
    IF claim IS NOT NULL THEN
        RETURN lower(claim);
    END IF;
    IF auth.uid() IS NOT NULL THEN
        SELECT role INTO mapped FROM app_roles WHERE user_id = auth.uid();
        IF mapped IS NOT NULL THEN
            RETURN mapped;
        END IF;
    END IF;
    RETURN 'operator'; -- default for legacy anonymous usage
END;
$$;

-- ==========================================
-- Validation triggers
-- ==========================================
CREATE OR REPLACE FUNCTION validate_stock_scan()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    is_fp boolean := coalesce(NEW.session_type, 'FP') = 'FP';
BEGIN
    IF is_fp THEN
        IF NEW.raw_code IS NULL OR length(NEW.raw_code) <> 13 OR NEW.raw_code !~ '^[0-9]{13}$' THEN
            RAISE EXCEPTION 'FP scans must include 13-digit raw_code';
        END IF;
    ELSE
        IF NEW.expiry_date IS NULL THEN
            RAISE EXCEPTION 'RM scans must include expiry_date';
        END IF;
    END IF;
    IF NEW.site IS NULL AND NEW.location IS NOT NULL THEN
        -- attempt to split legacy location "Site|Aisle|Rack"
        PERFORM 1;
    END IF;
    NEW.updated_at := now();
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_validate_stock_scan ON public.stock_scans;
CREATE TRIGGER trg_validate_stock_scan
BEFORE INSERT OR UPDATE ON public.stock_scans
FOR EACH ROW EXECUTE FUNCTION validate_stock_scan();

CREATE OR REPLACE FUNCTION log_scan_audit()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    INSERT INTO scan_audit_logs (scan_id, action, actor, actor_device_id, previous_data, new_data)
    VALUES (
        coalesce(OLD.id::text, NEW.id::text),
        lower(TG_OP),
        coalesce(auth.jwt()->>'name', auth.jwt()->>'email'),
        auth.jwt()->>'device_id',
        to_jsonb(OLD),
        CASE WHEN TG_OP = 'UPDATE' THEN to_jsonb(NEW) ELSE NULL END
    );
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_scan_audit ON public.stock_scans;
CREATE TRIGGER trg_scan_audit
AFTER UPDATE OR DELETE ON public.stock_scans
FOR EACH ROW EXECUTE FUNCTION log_scan_audit();

-- ==========================================
-- Helper functions
-- ==========================================
CREATE OR REPLACE FUNCTION upsert_session_device(
    p_session_id text,
    p_device_id text,
    p_user_name text,
    p_role text DEFAULT 'operator',
    p_status text DEFAULT 'active'
)
RETURNS session_devices
LANGUAGE plpgsql
AS $$
DECLARE
    result session_devices;
BEGIN
    INSERT INTO session_devices (session_id, device_id, user_name, role, status)
    VALUES (p_session_id, p_device_id, p_user_name, p_role, p_status)
    ON CONFLICT (session_id, device_id)
    DO UPDATE SET
        user_name = excluded.user_name,
        role = excluded.role,
        status = p_status,
        last_seen = now(),
        left_at = CASE WHEN p_status = 'completed' THEN now() ELSE NULL END
    RETURNING * INTO result;
    RETURN result;
END;
$$;

CREATE OR REPLACE FUNCTION log_event(
    p_event_type text,
    p_severity text,
    p_session_id text,
    p_device_id text,
    p_payload jsonb
)
RETURNS event_logs
LANGUAGE plpgsql
AS $$
DECLARE
    result event_logs;
BEGIN
    INSERT INTO event_logs (event_type, severity, session_id, device_id, payload)
    VALUES (p_event_type, coalesce(p_severity, 'info'), p_session_id, p_device_id, coalesce(p_payload, '{}'::jsonb))
    RETURNING * INTO result;
    RETURN result;
END;
$$;

-- ==========================================
-- RLS policies
-- ==========================================
ALTER TABLE public.stock_scans ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.stock_takes ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.session_devices ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.scan_audit_logs ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.event_logs ENABLE ROW LEVEL SECURITY;

-- stock_scans
DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE schemaname = 'public' AND tablename = 'stock_scans' AND policyname = 'stock_scans_select') THEN
        CREATE POLICY stock_scans_select ON public.stock_scans
            FOR SELECT USING (current_app_role() IN ('operator','supervisor','admin'));
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE schemaname = 'public' AND tablename = 'stock_scans' AND policyname = 'stock_scans_insert') THEN
        CREATE POLICY stock_scans_insert ON public.stock_scans
            FOR INSERT WITH CHECK (current_app_role() IN ('operator','supervisor','admin'));
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE schemaname = 'public' AND tablename = 'stock_scans' AND policyname = 'stock_scans_update') THEN
        CREATE POLICY stock_scans_update ON public.stock_scans
            FOR UPDATE USING (current_app_role() IN ('supervisor','admin')) WITH CHECK (current_app_role() IN ('supervisor','admin'));
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE schemaname = 'public' AND tablename = 'stock_scans' AND policyname = 'stock_scans_delete') THEN
        CREATE POLICY stock_scans_delete ON public.stock_scans
            FOR DELETE USING (current_app_role() IN ('supervisor','admin'));
    END IF;
END $$;

-- stock_takes policies
DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE schemaname = 'public' AND tablename = 'stock_takes' AND policyname = 'stock_takes_upsert') THEN
        CREATE POLICY stock_takes_upsert ON public.stock_takes
            FOR ALL USING (current_app_role() IN ('operator','supervisor','admin')) WITH CHECK (current_app_role() IN ('operator','supervisor','admin'));
    END IF;
END $$;

-- session_devices policies
DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE schemaname = 'public' AND tablename = 'session_devices' AND policyname = 'session_devices_rw') THEN
        CREATE POLICY session_devices_rw ON public.session_devices
            FOR ALL USING (current_app_role() IN ('operator','supervisor','admin')) WITH CHECK (current_app_role() IN ('operator','supervisor','admin'));
    END IF;
END $$;

-- audit + event logs read-only for supervisors
DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE schemaname = 'public' AND tablename = 'scan_audit_logs' AND policyname = 'scan_audit_logs_select') THEN
        CREATE POLICY scan_audit_logs_select ON public.scan_audit_logs
            FOR SELECT USING (current_app_role() IN ('supervisor','admin'));
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE schemaname = 'public' AND tablename = 'event_logs' AND policyname = 'event_logs_select') THEN
        CREATE POLICY event_logs_select ON public.event_logs
            FOR SELECT USING (current_app_role() IN ('supervisor','admin'));
    END IF;
END $$;

COMMIT;
