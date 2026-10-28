-- ============================================================================
-- TICKETPILOT SaaS — PRODUCTION POSTGRESQL / SUPABASE MIGRATION (001_initial_schema.sql)
-- Strict Multi-User Isolation (RLS), Integer Cents Monetary Storage,
-- Duplicate-Sale "Needs Action" Safety Enforcement, and Audit Trail.
-- ============================================================================

CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- 1. PROFILES TABLE
CREATE TABLE IF NOT EXISTS public.profiles (
    id UUID PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
    full_name TEXT NOT NULL CHECK (char_length(trim(full_name)) >= 2),
    email TEXT NOT NULL UNIQUE,
    email_verified BOOLEAN NOT NULL DEFAULT FALSE,
    accepted_terms_at TIMESTAMPTZ NOT NULL,
    accepted_privacy_at TIMESTAMPTZ NOT NULL,
    subscription_tier TEXT NOT NULL DEFAULT 'free_launch' CHECK (subscription_tier IN ('free_launch', 'pro_future')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 2. USER PREFERENCES TABLE
CREATE TABLE IF NOT EXISTS public.user_preferences (
    user_id UUID PRIMARY KEY REFERENCES public.profiles(id) ON DELETE CASCADE,
    default_currency TEXT NOT NULL DEFAULT 'USD' CHECK (default_currency IN ('USD', 'EUR', 'GBP', 'CAD', 'AUD', 'EGP')),
    stale_listing_days INTEGER NOT NULL DEFAULT 7 CHECK (stale_listing_days BETWEEN 1 AND 90),
    upcoming_event_Window_days INTEGER NOT NULL DEFAULT 7 CHECK (upcoming_event_window_days BETWEEN 1 AND 60),
    in_app_alerts_enabled BOOLEAN NOT NULL DEFAULT TRUE,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 3. TICKETS INVENTORY TABLE
-- Monetary values stored in integer minor units (cents) + explicit currency to prevent float rounding errors.
CREATE TABLE IF NOT EXISTS public.tickets (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES public.profiles(id) ON DELETE CASCADE,
    event_name TEXT NOT NULL CHECK (char_length(trim(event_name)) >= 2),
    event_datetime TIMESTAMPTZ NOT NULL,
    event_timezone TEXT NOT NULL DEFAULT 'America/New_York',
    venue TEXT NOT NULL CHECK (char_length(trim(venue)) >= 2),
    section TEXT NOT NULL CHECK (char_length(trim(section)) >= 1),
    row_name TEXT NOT NULL CHECK (char_length(trim(row_name)) >= 1),
    seat_range TEXT,
    quantity INTEGER NOT NULL CHECK (quantity > 0 AND quantity <= 1000),
    acquisition_cost_cents BIGINT NOT NULL CHECK (acquisition_cost_cents >= 0),
    currency TEXT NOT NULL CHECK (currency IN ('USD', 'EUR', 'GBP', 'CAD', 'AUD', 'EGP')),
    acquisition_date DATE,
    status TEXT NOT NULL DEFAULT 'Available' CHECK (status IN ('Available', 'Listed', 'Sold', 'Needs Action', 'Archived')),
    notes TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_tickets_user_status ON public.tickets(user_id, status);
CREATE INDEX IF NOT EXISTS idx_tickets_user_event_date ON public.tickets(user_id, event_datetime);

-- 4. EXTERNAL LISTINGS TABLE
CREATE TABLE IF NOT EXISTS public.external_listings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES public.profiles(id) ON DELETE CASCADE,
    ticket_id UUID NOT NULL REFERENCES public.tickets(id) ON DELETE RESTRICT,
    marketplace_name TEXT NOT NULL CHECK (marketplace_name IN ('StubHub', 'Viagogo', 'Ticketmaster Resale', 'SeatGeek', 'Vivid Seats', 'TickPick', 'Other')),
    external_listing_url TEXT,
    marketplace_reference_id TEXT,
    asking_price_cents BIGINT NOT NULL CHECK (asking_price_cents > 0),
    currency TEXT NOT NULL CHECK (currency IN ('USD', 'EUR', 'GBP', 'CAD', 'AUD', 'EGP')),
    status TEXT NOT NULL DEFAULT 'Active' CHECK (status IN ('Active', 'Pending', 'Sold', 'Removed', 'Expired', 'Unknown')),
    last_verified_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    resolution_confirmed_at TIMESTAMPTZ,
    resolution_notes TEXT,
    notes TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_listings_user_ticket ON public.external_listings(user_id, ticket_id);
CREATE INDEX IF NOT EXISTS idx_listings_user_status ON public.external_listings(user_id, status);

-- 5. SALES TABLE
CREATE TABLE IF NOT EXISTS public.sales (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES public.profiles(id) ON DELETE CASCADE,
    ticket_id UUID NOT NULL UNIQUE REFERENCES public.tickets(id) ON DELETE RESTRICT,
    sold_listing_id UUID REFERENCES public.external_listings(id) ON DELETE SET NULL,
    sale_datetime TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    marketplace_name TEXT NOT NULL CHECK (marketplace_name IN ('StubHub', 'Viagogo', 'Ticketmaster Resale', 'SeatGeek', 'Vivid Seats', 'TickPick', 'Direct / Private', 'Other')),
    external_order_id TEXT,
    gross_sale_cents BIGINT NOT NULL CHECK (gross_sale_cents >= 0),
    marketplace_fee_cents BIGINT NOT NULL DEFAULT 0 CHECK (marketplace_fee_cents >= 0),
    other_costs_cents BIGINT NOT NULL DEFAULT 0 CHECK (other_costs_cents >= 0),
    adjustments_cents BIGINT NOT NULL DEFAULT 0,
    net_proceeds_cents BIGINT NOT NULL,
    realized_profit_cents BIGINT NOT NULL,
    currency TEXT NOT NULL CHECK (currency IN ('USD', 'EUR', 'GBP', 'CAD', 'AUD', 'EGP')),
    sale_status TEXT NOT NULL DEFAULT 'Confirmed' CHECK (sale_status IN ('Confirmed', 'Completed', 'Cancelled', 'Disputed')),
    notes TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_sales_user_date ON public.sales(user_id, sale_datetime);

-- 6. PAYOUTS TABLE
CREATE TABLE IF NOT EXISTS public.payouts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES public.profiles(id) ON DELETE CASCADE,
    sale_id UUID NOT NULL UNIQUE REFERENCES public.sales(id) ON DELETE CASCADE,
    marketplace_name TEXT NOT NULL,
    expected_payout_cents BIGINT NOT NULL CHECK (expected_payout_cents >= 0),
    currency TEXT NOT NULL CHECK (currency IN ('USD', 'EUR', 'GBP', 'CAD', 'AUD', 'EGP')),
    expected_payout_date DATE NOT NULL,
    actual_received_cents BIGINT CHECK (actual_received_cents IS NULL OR actual_received_cents >= 0),
    actual_receipt_date DATE,
    payout_status TEXT NOT NULL DEFAULT 'Expected' CHECK (payout_status IN ('Expected', 'Processing', 'Paid', 'Overdue', 'Disputed', 'Cancelled')),
    external_payout_reference TEXT,
    notes TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_payouts_user_status ON public.payouts(user_id, payout_status);

-- 7. ALERTS TABLE
CREATE TABLE IF NOT EXISTS public.alerts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES public.profiles(id) ON DELETE CASCADE,
    related_ticket_id UUID REFERENCES public.tickets(id) ON DELETE CASCADE,
    related_listing_id UUID REFERENCES public.external_listings(id) ON DELETE CASCADE,
    related_payout_id UUID REFERENCES public.payouts(id) ON DELETE CASCADE,
    alert_type TEXT NOT NULL CHECK (alert_type IN ('DUPLICATE_SALE_RISK', 'NEEDS_ACTION', 'STALE_LISTING', 'UPCOMING_EVENT', 'PAYOUT_DUE', 'PAYOUT_OVERDUE', 'SECURITY_EVENT')),
    severity TEXT NOT NULL CHECK (severity IN ('critical', 'warning', 'info')),
    title TEXT NOT NULL,
    message TEXT NOT NULL,
    requires_external_action BOOLEAN NOT NULL DEFAULT FALSE,
    dedup_key TEXT NOT NULL,
    is_read BOOLEAN NOT NULL DEFAULT FALSE,
    is_handled BOOLEAN NOT NULL DEFAULT FALSE,
    handled_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(user_id, dedup_key)
);

-- 8. ACTIVITY LOGS (AUDIT TRAIL)
CREATE TABLE IF NOT EXISTS public.activity_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES public.profiles(id) ON DELETE CASCADE,
    entity_type TEXT NOT NULL,
    entity_id UUID,
    action_type TEXT NOT NULL,
    description TEXT NOT NULL,
    metadata_json JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_activity_logs_user_created ON public.activity_logs(user_id, created_at DESC);

-- ============================================================================
-- ROW LEVEL SECURITY (RLS) POLICIES — STRICT MULTI-USER ISOLATION
-- ============================================================================

ALTER TABLE public.profiles ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.user_preferences ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.tickets ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.external_listings ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.sales ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.payouts ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.alerts ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.activity_logs ENABLE ROW LEVEL SECURITY;

CREATE POLICY profiles_isolation ON public.profiles
    FOR ALL USING (auth.uid() = id) WITH CHECK (auth.uid() = id);

CREATE POLICY preferences_isolation ON public.user_preferences
    FOR ALL USING (auth.uid() = user_id) WITH CHECK (auth.uid() = user_id);

CREATE POLICY tickets_isolation ON public.tickets
    FOR ALL USING (auth.uid() = user_id) WITH CHECK (auth.uid() = user_id);

CREATE POLICY listings_isolation ON public.external_listings
    FOR ALL USING (
        auth.uid() = user_id
        AND EXISTS (SELECT 1 FROM public.tickets t WHERE t.id = ticket_id AND t.user_id = auth.uid())
    )
    WITH CHECK (
        auth.uid() = user_id
        AND EXISTS (SELECT 1 FROM public.tickets t WHERE t.id = ticket_id AND t.user_id = auth.uid())
    );

CREATE POLICY sales_isolation ON public.sales
    FOR ALL USING (
        auth.uid() = user_id
        AND EXISTS (SELECT 1 FROM public.tickets t WHERE t.id = ticket_id AND t.user_id = auth.uid())
    )
    WITH CHECK (
        auth.uid() = user_id
        AND EXISTS (SELECT 1 FROM public.tickets t WHERE t.id = ticket_id AND t.user_id = auth.uid())
    );

CREATE POLICY payouts_isolation ON public.payouts
    FOR ALL USING (
        auth.uid() = user_id
        AND EXISTS (SELECT 1 FROM public.sales s WHERE s.id = sale_id AND s.user_id = auth.uid())
    )
    WITH CHECK (
        auth.uid() = user_id
        AND EXISTS (SELECT 1 FROM public.sales s WHERE s.id = sale_id AND s.user_id = auth.uid())
    );

CREATE POLICY alerts_isolation ON public.alerts
    FOR ALL USING (auth.uid() = user_id) WITH CHECK (auth.uid() = user_id);

CREATE POLICY activity_logs_isolation ON public.activity_logs
    FOR ALL USING (auth.uid() = user_id) WITH CHECK (auth.uid() = user_id);
