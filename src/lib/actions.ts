// ============================================================================
// TICKETPILOT — NEXT.JS 14 SERVER ACTIONS (src/lib/actions.ts)
// Server-side validation, Supabase RLS + explicit ownership verification,
// Duplicate-Sale "Needs Action" state machine, and integer-cent accounting.
// ============================================================================

"use server";

import { createServerClient } from "@supabase/ssr";
import { cookies } from "next/headers";

export type CurrencyCode = "USD" | "EUR" | "GBP" | "CAD" | "AUD" | "EGP";
export type MarketplaceName =
  | "StubHub"
  | "Viagogo"
  | "Ticketmaster Resale"
  | "SeatGeek"
  | "Vivid Seats"
  | "TickPick"
  | "Direct / Private"
  | "Other";

const VALID_CURRENCIES = new Set(["USD", "EUR", "GBP", "CAD", "AUD", "EGP"]);

function getSupabaseServer() {
  const cookieStore = cookies();
  return createServerClient(
    process.env.NEXT_PUBLIC_SUPABASE_URL!,
    process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!,
    {
      cookies: {
        get(name: string) {
          return cookieStore.get(name)?.value;
        },
      },
    }
  );
}

export async function requireVerifiedServerUser() {
  const supabase = getSupabaseServer();
  const {
    data: { user },
    error,
  } = await supabase.auth.getUser();

  if (error || !user) {
    throw new Error("UNAUTHORIZED: Active authenticated session required.");
  }
  if (!user.email_confirmed_at) {
    throw new Error("EMAIL_VERIFICATION_REQUIRED: Please verify your email before accessing business records.");
  }
  return { supabase, user };
}

export function sanitizeCsvCell(value: unknown): string {
  if (value === null || value === undefined) return "";
  const str = String(value);
  if (/^[=+\-@\t\r]/.test(str)) {
    return `'${str}`;
  }
  return str;
}

export async function recordTicketSaleServerAction(input: {
  ticketId: string;
  soldListingId?: string | null;
  marketplaceName: MarketplaceName;
  externalOrderId?: string;
  grossSaleCents: number;
  marketplaceFeeCents: number;
  otherCostsCents?: number;
  adjustmentsCents?: number;
  currency: CurrencyCode;
  expectedPayoutDate: string;
  notes?: string;
}) {
  const { supabase, user } = await requireVerifiedServerUser();

  if (!VALID_CURRENCIES.has(input.currency)) {
    throw new Error("VALIDATION_ERROR: Unsupported currency.");
  }
  if (
    !Number.isInteger(input.grossSaleCents) ||
    input.grossSaleCents < 0 ||
    !Number.isInteger(input.marketplaceFeeCents) ||
    input.marketplaceFeeCents < 0
  ) {
    throw new Error("VALIDATION_ERROR: Monetary amounts must be non-negative integer cents.");
  }

  // 1. Verify ownership of ticket record
  const { data: ticket, error: ticketErr } = await supabase
    .from("tickets")
    .select("*")
    .eq("id", input.ticketId)
    .eq("user_id", user.id)
    .single();

  if (ticketErr || !ticket) {
    throw new Error("AUTHORIZATION_ERROR: Ticket not found or access denied.");
  }
  if (ticket.status === "Sold" || ticket.status === "Needs Action") {
    throw new Error("VALIDATION_ERROR: A sale is already recorded for this ticket.");
  }
  if (ticket.currency !== input.currency) {
    throw new Error(
      `CURRENCY_MISMATCH: Sale currency (${input.currency}) must match ticket acquisition currency (${ticket.currency}).`
    );
  }

  const otherCosts = input.otherCostsCents ?? 0;
  const adjustments = input.adjustmentsCents ?? 0;
  const netProceedsCents = input.grossSaleCents - input.marketplaceFeeCents - otherCosts + adjustments;
  const realizedProfitCents = netProceedsCents - Number(ticket.acquisition_cost_cents);

  // 2. Insert sale record
  const { data: sale, error: saleErr } = await supabase
    .from("sales")
    .insert({
      user_id: user.id,
      ticket_id: ticket.id,
      sold_listing_id: input.soldListingId || null,
      marketplace_name: input.marketplaceName,
      external_order_id: input.externalOrderId || null,
      gross_sale_cents: input.grossSaleCents,
      marketplace_fee_cents: input.marketplaceFeeCents,
      other_costs_cents: otherCosts,
      adjustments_cents: adjustments,
      net_proceeds_cents: netProceedsCents,
      realized_profit_cents: realizedProfitCents,
      currency: input.currency,
      sale_status: "Confirmed",
      notes: input.notes || null,
    })
    .select()
    .single();

  if (saleErr || !sale) {
    throw new Error("DATABASE_ERROR: Could not record sale.");
  }

  // 3. Create Expected Payout record (never counted as received until user confirms receipt)
  await supabase.from("payouts").insert({
    user_id: user.id,
    sale_id: sale.id,
    marketplace_name: input.marketplaceName,
    expected_payout_cents: Math.max(0, netProceedsCents),
    currency: input.currency,
    expected_payout_date: input.expectedPayoutDate,
    payout_status: "Expected",
  });

  if (input.soldListingId) {
    await supabase
      .from("external_listings")
      .update({ status: "Sold", updated_at: new Date().toISOString() })
      .eq("id", input.soldListingId)
      .eq("user_id", user.id);
  }

  // 4. Check for other unresolved external listings on the same ticket
  let unresolvedQuery = supabase
    .from("external_listings")
    .select("*")
    .eq("ticket_id", ticket.id)
    .eq("user_id", user.id)
    .in("status", ["Active", "Pending", "Unknown"]);

  if (input.soldListingId) {
    unresolvedQuery = unresolvedQuery.neq("id", input.soldListingId);
  }

  const { data: unresolvedListings } = await unresolvedQuery;
  const unresolvedCount = unresolvedListings?.length ?? 0;
  const nextTicketStatus = unresolvedCount > 0 ? "Needs Action" : "Sold";

  await supabase
    .from("tickets")
    .update({ status: nextTicketStatus, updated_at: new Date().toISOString() })
    .eq("id", ticket.id)
    .eq("user_id", user.id);

  if (unresolvedCount > 0) {
    await supabase.from("alerts").upsert(
      {
        user_id: user.id,
        related_ticket_id: ticket.id,
        alert_type: "DUPLICATE_SALE_RISK",
        severity: "critical",
        title: `URGENT: Deactivate ${unresolvedCount} External Listing(s) for ${ticket.event_name}`,
        message: `TicketPilot does NOT automatically cancel external listings. Remove each remaining listing on its marketplace and confirm manually.`,
        requires_external_action: true,
        dedup_key: `dup_sale_ticket_${ticket.id}`,
        is_read: false,
        is_handled: false,
      },
      { onConflict: "user_id,dedup_key" }
    );
  }

  return {
    saleId: sale.id,
    ticketStatus: nextTicketStatus,
    netProceedsCents,
    realizedProfitCents,
    unresolvedListings: unresolvedListings ?? [],
  };
}
