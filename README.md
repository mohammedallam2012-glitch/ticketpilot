# TicketPilot SaaS — Complete Architecture, Setup, Security & Zero-Budget Deployment Guide

## 1. Product Boundary & Honest Scope
**TicketPilot** is an inventory, external listing tracker, duplicate-sale safety monitor, and financial accounting tool for independent ticket resellers.
- **What TicketPilot IS**: A relational multi-user system to track owned ticket blocks, log external marketplace listings across StubHub, Viagogo, Ticketmaster Resale, SeatGeek, Vivid Seats, and TickPick, enforce a mandatory **"Needs Action"** manual deactivation workflow when a ticket sells, track expected vs. received payouts, and compute realized profit using integer-cent arithmetic.
- **What TicketPilot is NOT**: TicketPilot is **not** a ticket marketplace, broker, scraper, or payment processor. It does **not** automatically cancel or remove listings on StubHub, Viagogo, or Ticketmaster. When a ticket sells, the user must manually remove remaining active listings on the external marketplaces and confirm each removal inside TicketPilot.

## 2. Zero-Budget ($0) Hosting & Database Commercial Eligibility Audit (Verified October 2026)
Before deploying publicly, review the verified legal and operational constraints of free tiers:
1. **Vercel Hobby Plan ($0/mo)**:
   - **Commercial Restriction**: Vercel's Fair Use Guidelines (updated Sept/Oct 2026) explicitly restrict the Hobby plan to **personal, non-commercial use only**. Any revenue-generating commercial site requires Vercel Pro ($20/mo).
   - **Actionable Recommendation**: Use Vercel Hobby only during free non-commercial beta testing, or deploy commercially at $0 on **Netlify Free** (permits commercial use within 300 credits/month hard cap) or **Cloudflare Pages / Workers Free** (100,000 function invocations/day, 10ms CPU limit per invocation, unlimited static asset bandwidth).
2. **Supabase Free Tier ($0/mo)**:
   - **Quotas & Sleep Behavior**: Includes 500 MB PostgreSQL storage and 50,000 Monthly Active Users (MAUs).
   - **Critical Operational Limitations**:
     - **Inactivity Pause**: Free tier projects automatically pause after **7 days of inactivity**.
     - **Backups**: **0 automated backups** are included on the Free tier (7-day automated backups require Supabase Pro at $25/mo). You must run periodic manual `pg_dump` or CSV exports to back up records on the Free tier.

## 3. Repository Structure
- `supabase/migrations/001_initial_schema.sql`: Complete PostgreSQL schema with `UUID` primary keys, `BIGINT` integer-cent monetary columns, foreign key constraints, indexes, and strict `Row Level Security (RLS)` policies (`auth.uid() = user_id`).
- `src/lib/actions.ts`: Next.js 14 Server Actions enforcing authenticated + email-verified sessions, ownership validation, integer-cent profit calculation, and Duplicate-Sale Safety state transitions.
- `backend/ticketpilot_engine.py`: Self-contained Python/SQLite relational backend engine mirroring the exact PostgreSQL schema and business logic for local execution and automated security testing.
- `tests/test_ticketpilot_suite.py`: Automated verification suite testing authentication, email verification gating, multi-currency lowest asking price, Duplicate-Sale Safety (`Needs Action`), financial calculations, cross-user IDOR isolation, CSV formula injection protection, and reauthenticated account deletion.

## 4. Setup & Local Development Instructions

### Option A: Run the Local Relational Backend & Automated Security Tests
```bash
python3 tests/test_ticketpilot_suite.py
```

### Option B: Connect Next.js 14 to Supabase PostgreSQL
1. Create a free project at `https://supabase.com`.
2. Open the **SQL Editor** in Supabase and run the entire contents of `supabase/migrations/001_initial_schema.sql`.
3. In Supabase **Authentication -> Providers -> Email**, ensure **Confirm email** is enabled so unverified accounts cannot access business data.
4. Copy `.env.example` to `.env.local` and fill in `NEXT_PUBLIC_SUPABASE_URL` and `NEXT_PUBLIC_SUPABASE_ANON_KEY`.
5. Run:
```bash
npm install
npm run dev
```

## 5. Backup, Recovery & Account Deletion Policy
- **Account Deletion**: When a user requests account deletion (after password reauthentication and typing `DELETE MY ACCOUNT`), all active rows in `payouts`, `sales`, `external_listings`, `alerts`, `activity_logs`, `tickets`, `user_preferences`, and `profiles` are immediately purged from the active database.
- **Backup Retention Disclosure**: On the Supabase Free tier, no automated platform backups exist. If upgraded to a plan with automated backups (such as Supabase Pro), encrypted database snapshots expire according to the provider's retention window (typically 7 days).
